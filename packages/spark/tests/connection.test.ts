import { create, toBinary } from "@bufbuild/protobuf";
import { Code, ConnectError, createRouterTransport } from "@connectrpc/connect";
import type { HandlerContext } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { expect, test } from "vite-plus/test";

import { connectOperator, sparkEvents } from "../src/connection/index.ts";
import type { SparkEvent } from "../src/connection/index.ts";
import type { SparkOperatorConfig } from "../src/core/network.ts";
import { SparkRequestError } from "../src/errors/index.ts";
import {
  ChallengeSchema,
  ProtectedChallengeSchema,
  SparkAuthnService,
} from "../src/proto/gen/spark_authn_pb.ts";
import type {
  ProtectedChallenge,
  VerifyChallengeRequest,
} from "../src/proto/gen/spark_authn_pb.ts";
import {
  Network,
  SparkService,
  SubscribeToEventsResponseSchema,
  TransferStatus,
  TransferType,
} from "../src/proto/gen/spark_pb.ts";
import { createTestSigner } from "./support/test-signer.ts";

const OPERATOR: SparkOperatorConfig = {
  id: 0,
  identifier: "0000000000000000000000000000000000000000000000000000000000000001",
  address: "https://op.test",
  identityPublicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(9), true),
};

const noopFetch: typeof globalThis.fetch = async () =>
  Promise.reject(new Error("fetch must not be used with a router transport"));

function fixedRandom(length: number): Uint8Array {
  return new Uint8Array(length).fill(0x80);
}

function makeChallenge(publicKey: Uint8Array): ProtectedChallenge {
  return create(ProtectedChallengeSchema, {
    challenge: create(ChallengeSchema, {
      version: 1,
      timestamp: BigInt(Math.floor(Date.now() / 1000)),
      nonce: new Uint8Array([1, 2, 3]),
      publicKey,
    }),
    serverHmac: new Uint8Array(32).fill(4),
  });
}

type AuthCalls = {
  get_challenge: number;
  verify_challenge: number;
  signaturesVerified: number;
};

/**
 * Fake SO authn service backed by the same digest math as the real SO: it verifies the DER
 * signature over sha256(Challenge) and issues `token-N`.
 */
function authnImpl(
  calls: AuthCalls,
  opts?: {
    expiredOnce?: boolean;
    now?: () => number;
  },
) {
  return {
    get_challenge: (req: { publicKey: Uint8Array }) => {
      calls.get_challenge++;
      return { protectedChallenge: makeChallenge(req.publicKey) };
    },
    verify_challenge: (req: VerifyChallengeRequest) => {
      calls.verify_challenge++;
      if (opts?.expiredOnce && calls.verify_challenge === 1) {
        throw new ConnectError("challenge expired", Code.Internal);
      }
      const challenge = req.protectedChallenge?.challenge;
      if (challenge === undefined) {
        throw new ConnectError("missing challenge", Code.InvalidArgument);
      }
      const digest = sha256(toBinary(ChallengeSchema, challenge));
      if (
        !secp256k1.verify(req.signature, digest, req.publicKey, { format: "der", prehash: false })
      ) {
        throw new ConnectError("bad signature", Code.Unauthenticated);
      }
      calls.signaturesVerified++;
      const nowSec = Math.floor((opts?.now?.() ?? Date.now()) / 1000);
      return {
        sessionToken: `token-${calls.verify_challenge}`,
        expirationTimestamp: BigInt(nowSec + 300),
      };
    },
  };
}

function authHeader(context: HandlerContext): string | null {
  return context.requestHeader.get("authorization");
}

/** Query_nodes impl that rejects calls carrying `token` with Unauthenticated. */
function rejectBearerToken(token: string, counter: { calls: number }) {
  return (_req: unknown, context: HandlerContext) => {
    counter.calls++;
    if (authHeader(context) === `Bearer ${token}`) {
      throw new ConnectError("unauthenticated", Code.Unauthenticated);
    }
    return { nodes: {}, offset: 0n };
  };
}

/** Query_nodes impl that fails `counter.fails` times with Unavailable, then succeeds. */
function failUnavailable(counter: { fails: number }) {
  return () => {
    if (counter.fails > 0) {
      counter.fails--;
      throw new ConnectError("unavailable", Code.Unavailable);
    }
    return { nodes: {}, offset: 0n };
  };
}

/** Subscribe_to_events impl: first subscription yields `connected` then dies; later ones stream. */
function reconnectingEvents(counter: { calls: number }) {
  return async function* (_req: unknown, context: HandlerContext) {
    counter.calls++;
    if (counter.calls === 1) {
      yield create(SubscribeToEventsResponseSchema, {
        event: { case: "connected", value: {} },
      });
      throw new ConnectError("unavailable", Code.Unavailable);
    }
    yield create(SubscribeToEventsResponseSchema, {
      event: {
        case: "receiverTransfer",
        value: {
          transfer: {
            id: "transfer-1",
            senderIdentityPublicKey: new Uint8Array(33).fill(1),
            receiverIdentityPublicKey: new Uint8Array(33).fill(2),
            status: TransferStatus.COMPLETED,
            totalValue: 100n,
            type: TransferType.TRANSFER,
            network: Network.MAINNET,
            leaves: [],
            receivers: [],
            senders: [],
          },
        },
      },
    });
    yield create(SubscribeToEventsResponseSchema, {
      event: { case: "heartbeat", value: {} },
    });
    await new Promise<void>((resolve) => {
      context.signal.addEventListener("abort", () => {
        resolve();
      });
    });
  };
}

function eventType(result: IteratorResult<SparkEvent>): string {
  return result.done === true ? "done" : result.value.type;
}

/** Subscribe_to_events impl: first subscription dies with Unauthenticated, later ones stream. */
function unauthOnceEvents(counter: { calls: number }) {
  return async function* (_req: unknown, context: HandlerContext) {
    counter.calls++;
    if (counter.calls === 1) {
      throw new ConnectError("unauthenticated", Code.Unauthenticated);
    }
    yield create(SubscribeToEventsResponseSchema, {
      event: { case: "connected", value: {} },
    });
    await new Promise<void>((resolve) => {
      context.signal.addEventListener("abort", () => {
        resolve();
      });
    });
  };
}

/** Subscribe_to_events impl: the first two subscriptions close cleanly, then the stream lives. */
function closingThenLiveEvents(counter: { calls: number }) {
  return async function* (_req: unknown, context: HandlerContext) {
    counter.calls++;
    if (counter.calls <= 2) {
      return;
    }
    yield create(SubscribeToEventsResponseSchema, {
      event: { case: "heartbeat", value: {} },
    });
    await new Promise<void>((resolve) => {
      context.signal.addEventListener("abort", () => {
        resolve();
      });
    });
  };
}

/** First subscription yields one event then goes silent; later ones yield a heartbeat. */
function silentThenLiveEvents(counter: { calls: number }) {
  return async function* (_req: unknown, context: HandlerContext) {
    counter.calls++;
    if (counter.calls === 1) {
      yield create(SubscribeToEventsResponseSchema, {
        event: { case: "connected", value: {} },
      });
    }
    if (counter.calls > 1) {
      yield create(SubscribeToEventsResponseSchema, {
        event: { case: "heartbeat", value: {} },
      });
    }
    await new Promise<void>((resolve) => {
      context.signal.addEventListener("abort", () => {
        resolve();
      });
    });
  };
}

function connectTest(
  signer: ReturnType<typeof createTestSigner>,
  routes: Parameters<typeof createRouterTransport>[0],
  extra?: { now?: () => number; sleep?: (ms: number) => Promise<void> },
) {
  return connectOperator(OPERATOR, {
    signer,
    fetch: noopFetch,
    random: fixedRandom,
    transportFactory: (interceptors) =>
      createRouterTransport(routes, { transport: { interceptors: [...interceptors] } }),
    ...extra,
  });
}

test("authenticates lazily once and attaches the bearer token", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const calls: AuthCalls = { get_challenge: 0, verify_challenge: 0, signaturesVerified: 0 };
  const seenAuth: Array<string | null> = [];
  const conn = connectTest(signer, (router) => {
    router.service(SparkAuthnService, authnImpl(calls));
    router.service(SparkService, {
      query_nodes: (_req, context: HandlerContext) => {
        seenAuth.push(authHeader(context));
        return { nodes: {}, offset: 0n };
      },
    });
  });
  const response = await conn.spark.query_nodes({
    source: { case: "ownerIdentityPubkey", value: await signer.identityPublicKey() },
    network: Network.MAINNET,
  });
  expect(response.nodes).toStrictEqual({});
  expect(calls.get_challenge).toBe(1);
  expect(calls.signaturesVerified).toBe(1);
  expect(seenAuth).toStrictEqual(["Bearer token-1"]);
});

test("single-flights concurrent calls onto one authentication", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const calls: AuthCalls = { get_challenge: 0, verify_challenge: 0, signaturesVerified: 0 };
  const conn = connectTest(signer, (router) => {
    router.service(SparkAuthnService, authnImpl(calls));
    router.service(SparkService, {
      query_nodes: () => ({ nodes: {}, offset: 0n }),
    });
  });
  const owner = await signer.identityPublicKey();
  await Promise.all([
    conn.spark.query_nodes({
      source: { case: "ownerIdentityPubkey", value: owner },
      network: Network.MAINNET,
    }),
    conn.spark.query_nodes({
      source: { case: "ownerIdentityPubkey", value: owner },
      network: Network.MAINNET,
    }),
    conn.spark.query_nodes({
      source: { case: "ownerIdentityPubkey", value: owner },
      network: Network.MAINNET,
    }),
  ]);
  expect(calls.get_challenge).toBe(1);
});

test("refreshes an expired session token", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  let nowMs = 1_000_000;
  const calls: AuthCalls = { get_challenge: 0, verify_challenge: 0, signaturesVerified: 0 };
  const conn = connectTest(
    signer,
    (router) => {
      router.service(SparkAuthnService, authnImpl(calls, { now: () => nowMs }));
      router.service(SparkService, {
        query_nodes: () => ({ nodes: {}, offset: 0n }),
      });
    },
    { now: () => nowMs },
  );
  const owner = await signer.identityPublicKey();
  await conn.spark.query_nodes({
    source: { case: "ownerIdentityPubkey", value: owner },
    network: Network.MAINNET,
  });
  expect(calls.get_challenge).toBe(1);
  nowMs += 301_000; // past expiry
  await conn.spark.query_nodes({
    source: { case: "ownerIdentityPubkey", value: owner },
    network: Network.MAINNET,
  });
  expect(calls.get_challenge).toBe(2);
});

test("re-authenticates once on Unauthenticated and retries", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const calls: AuthCalls = { get_challenge: 0, verify_challenge: 0, signaturesVerified: 0 };
  const nodesCalls = { calls: 0 };
  const conn = connectTest(signer, (router) => {
    router.service(SparkAuthnService, authnImpl(calls));
    router.service(SparkService, {
      query_nodes: rejectBearerToken("token-1", nodesCalls),
    });
  });
  const owner = await signer.identityPublicKey();
  await conn.spark.query_nodes({
    source: { case: "ownerIdentityPubkey", value: owner },
    network: Network.MAINNET,
  });
  expect(calls.get_challenge).toBe(2);
  expect(nodesCalls.calls).toBe(2);
});

test("retries an expired challenge during authentication", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const calls: AuthCalls = { get_challenge: 0, verify_challenge: 0, signaturesVerified: 0 };
  const conn = connectTest(signer, (router) => {
    router.service(SparkAuthnService, authnImpl(calls, { expiredOnce: true }));
    router.service(SparkService, {
      query_nodes: () => ({ nodes: {}, offset: 0n }),
    });
  });
  const owner = await signer.identityPublicKey();
  await conn.spark.query_nodes({
    source: { case: "ownerIdentityPubkey", value: owner },
    network: Network.MAINNET,
  });
  expect(calls.verify_challenge).toBe(2);
  expect(calls.signaturesVerified).toBe(1);
});

test("does not retry non-transient failures during authentication", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const calls: AuthCalls = { get_challenge: 0, verify_challenge: 0, signaturesVerified: 0 };
  const conn = connectTest(signer, (router) => {
    router.service(SparkAuthnService, {
      get_challenge: () => {
        calls.get_challenge++;
        throw new ConnectError("bad signature", Code.Internal);
      },
      verify_challenge: () => {
        calls.verify_challenge++;
        return { sessionToken: "tok", expirationTimestamp: 0n };
      },
    });
    router.service(SparkService, {
      query_nodes: () => ({ nodes: {}, offset: 0n }),
    });
  });
  const owner = await signer.identityPublicKey();
  await expect(
    conn.spark.query_nodes({
      source: { case: "ownerIdentityPubkey", value: owner },
      network: Network.MAINNET,
    }),
  ).rejects.toMatchObject({ name: "SparkRequestError", code: "internal" });
  expect(calls.get_challenge).toBe(1);
});

test("retries idempotent reads with backoff but never non-idempotent calls", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const calls: AuthCalls = { get_challenge: 0, verify_challenge: 0, signaturesVerified: 0 };
  const sleeps: number[] = [];
  const queryFails = { fails: 2 };
  let transferCalls = 0;
  const conn = connectTest(
    signer,
    (router) => {
      router.service(SparkAuthnService, authnImpl(calls));
      router.service(SparkService, {
        query_nodes: failUnavailable(queryFails),
        start_transfer_v2: () => {
          transferCalls++;
          throw new ConnectError("unavailable", Code.Unavailable);
        },
      });
    },
    {
      sleep: async (ms) => {
        sleeps.push(ms);
        return Promise.resolve();
      },
    },
  );
  const owner = await signer.identityPublicKey();
  await conn.spark.query_nodes({
    source: { case: "ownerIdentityPubkey", value: owner },
    network: Network.MAINNET,
  });
  expect(sleeps).toHaveLength(2);

  await expect(
    conn.spark.start_transfer_v2({ transferId: "x", ownerIdentityPublicKey: owner }),
  ).rejects.toBeInstanceOf(SparkRequestError);
  expect(transferCalls).toBe(1);
});

test("maps ConnectError to SparkRequestError with code and operator", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const calls: AuthCalls = { get_challenge: 0, verify_challenge: 0, signaturesVerified: 0 };
  const conn = connectTest(signer, (router) => {
    router.service(SparkAuthnService, authnImpl(calls));
    router.service(SparkService, {
      query_nodes: () => {
        throw new ConnectError("denied by policy", Code.PermissionDenied);
      },
    });
  });
  const owner = await signer.identityPublicKey();
  await expect(
    conn.spark.query_nodes({
      source: { case: "ownerIdentityPubkey", value: owner },
      network: Network.MAINNET,
    }),
  ).rejects.toMatchObject({
    name: "SparkRequestError",
    code: "permission_denied",
    operator: OPERATOR.identifier,
    message: "denied by policy",
  });
});

test("event stream maps events, reconnects after failure, and stops on abort", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const calls: AuthCalls = { get_challenge: 0, verify_challenge: 0, signaturesVerified: 0 };
  const sleeps: number[] = [];
  const streamCalls = { calls: 0 };
  const conn = connectTest(
    signer,
    (router) => {
      router.service(SparkAuthnService, authnImpl(calls));
      router.service(SparkService, {
        subscribe_to_events: reconnectingEvents(streamCalls),
        query_nodes: () => ({ nodes: {}, offset: 0n }),
      });
    },
    {
      sleep: async (ms) => {
        sleeps.push(ms);
        return Promise.resolve();
      },
    },
  );
  const abort = new AbortController();
  const iterator = sparkEvents(conn, await signer.identityPublicKey(), abort.signal, {
    sleep: async (ms) => {
      sleeps.push(ms);
      return Promise.resolve();
    },
    random: fixedRandom,
  })[Symbol.asyncIterator]();
  const pull = async () => eventType(await iterator.next());
  const seen = [await pull(), await pull(), await pull()];
  abort.abort();
  seen.push(await pull());
  expect(seen).toStrictEqual(["connected", "transfer", "heartbeat", "done"]);
  expect(streamCalls.calls).toBe(2);
  expect(sleeps).toHaveLength(1);
});

test("a silent stream is abandoned at the idle bound and resubscribed", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const calls: AuthCalls = { get_challenge: 0, verify_challenge: 0, signaturesVerified: 0 };
  const sleeps: number[] = [];
  const streamCalls = { calls: 0 };
  const conn = connectTest(
    signer,
    (router) => {
      router.service(SparkAuthnService, authnImpl(calls));
      router.service(SparkService, {
        subscribe_to_events: silentThenLiveEvents(streamCalls),
      });
    },
    {
      sleep: async (ms) => {
        sleeps.push(ms);
        return Promise.resolve();
      },
    },
  );
  const abort = new AbortController();
  const iterator = sparkEvents(conn, await signer.identityPublicKey(), abort.signal, {
    sleep: async (ms) => {
      sleeps.push(ms);
      return Promise.resolve();
    },
    random: fixedRandom,
    idleTimeoutMs: 20,
  })[Symbol.asyncIterator]();
  const pull = async () => eventType(await iterator.next());
  // After "connected" the stream goes silent; ~20ms later the attempt aborts and the reconnect
  // loop resubscribes — the second subscription's heartbeat is the next event.
  const seen = [await pull(), await pull()];
  abort.abort();
  seen.push(await pull());
  expect(seen).toStrictEqual(["connected", "heartbeat", "done"]);
  expect(streamCalls.calls).toBe(2);
  expect(sleeps).toHaveLength(1);
});

test("mid-stream Unauthenticated invalidates the session and re-authenticates", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const calls: AuthCalls = { get_challenge: 0, verify_challenge: 0, signaturesVerified: 0 };
  const sleeps: number[] = [];
  const streamCalls = { calls: 0 };
  const conn = connectTest(
    signer,
    (router) => {
      router.service(SparkAuthnService, authnImpl(calls));
      router.service(SparkService, {
        subscribe_to_events: unauthOnceEvents(streamCalls),
        query_nodes: () => ({ nodes: {}, offset: 0n }),
      });
    },
    {
      sleep: async (ms) => {
        sleeps.push(ms);
        return Promise.resolve();
      },
    },
  );
  const abort = new AbortController();
  const iterator = sparkEvents(conn, await signer.identityPublicKey(), abort.signal, {
    sleep: async (ms) => {
      sleeps.push(ms);
      return Promise.resolve();
    },
    random: fixedRandom,
  })[Symbol.asyncIterator]();
  const seen = [await iterator.next()];
  abort.abort();
  seen.push(await iterator.next());
  expect(seen.map(eventType)).toStrictEqual(["connected", "done"]);
  expect(streamCalls.calls).toBe(2);
  expect(calls.get_challenge).toBe(2);
  expect(sleeps).toHaveLength(1);
});

test("clean stream closes back off with growing delays before resubscribing", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const calls: AuthCalls = { get_challenge: 0, verify_challenge: 0, signaturesVerified: 0 };
  const sleeps: number[] = [];
  const streamCalls = { calls: 0 };
  const conn = connectTest(
    signer,
    (router) => {
      router.service(SparkAuthnService, authnImpl(calls));
      router.service(SparkService, {
        subscribe_to_events: closingThenLiveEvents(streamCalls),
        query_nodes: () => ({ nodes: {}, offset: 0n }),
      });
    },
    {
      sleep: async (ms) => {
        sleeps.push(ms);
        return Promise.resolve();
      },
    },
  );
  const abort = new AbortController();
  const iterator = sparkEvents(conn, await signer.identityPublicKey(), abort.signal, {
    sleep: async (ms) => {
      sleeps.push(ms);
      return Promise.resolve();
    },
    random: fixedRandom,
  })[Symbol.asyncIterator]();
  const seen = [await iterator.next()];
  abort.abort();
  seen.push(await iterator.next());
  expect(seen.map(eventType)).toStrictEqual(["heartbeat", "done"]);
  expect(streamCalls.calls).toBe(3);
  // Backoff caps double per failure: 1000ms → floor(500+250)=750, then 2000ms → floor(1000+500)=1500.
  expect(sleeps).toStrictEqual([750, 1500]);
});
