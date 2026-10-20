import type { DescService } from "@bufbuild/protobuf";
import { toBinary } from "@bufbuild/protobuf";
import { Code, ConnectError, createClient } from "@connectrpc/connect";
import type { Client, Interceptor, Transport } from "@connectrpc/connect";
import { createGrpcWebTransport } from "@connectrpc/connect-web";

import type { SparkOperatorConfig } from "../core/network.ts";
import { SESSION_EXPIRY_BUFFER_MS } from "../core/session.ts";
import { serverErrorText } from "../core/text.ts";
import { defaultSleep } from "../core/time.ts";
import { uuidv7 } from "../core/uuid.ts";
import { SparkError, SparkRequestError } from "../errors/index.ts";
import { ChallengeSchema, SparkAuthnService } from "../proto/gen/spark_authn_pb.ts";
import type { SubscribeToEventsResponse } from "../proto/gen/spark_pb.ts";
import { SparkService } from "../proto/gen/spark_pb.ts";
import { SparkTokenService } from "../proto/gen/spark_token_pb.ts";
import type { SparkSigner } from "../signer/types.ts";

/**
 * A Spark protocol event delivered by the coordinator's `subscribe_to_events` stream. Plain types;
 * unknown oneof variants are skipped.
 */
export type SparkEvent =
  | { readonly type: "connected" }
  | { readonly type: "heartbeat" }
  | {
      readonly type: "transfer";
      readonly direction: "incoming" | "outgoing";
      readonly transferId: string;
      readonly senderIdentityPublicKey: Uint8Array;
      readonly receiverIdentityPublicKey: Uint8Array;
    }
  | { readonly type: "deposit"; readonly leafId: string }
  | {
      readonly type: "token-transaction";
      readonly transactionHash: Uint8Array;
      readonly tokenIdentifiers: ReadonlyArray<Uint8Array>;
    };

/**
 * A live connection to one signing operator. `spark` and `token` are typed Connect clients; every
 * call on them carries `Authorization: Bearer <session token>` and `X-Client-Env`, retries
 * idempotent reads with backoff, re-authenticates once on `Unauthenticated`, and throws
 * `SparkRequestError`.
 */
export type OperatorConnection = {
  readonly operator: SparkOperatorConfig;
  readonly spark: Client<typeof SparkService>;
  readonly token: Client<typeof SparkTokenService>;
  /** Drops the cached session token; the next call re-authenticates. */
  readonly invalidateSession: () => void;
};

export type ConnectionDeps = {
  readonly signer: SparkSigner;
  readonly fetch: typeof globalThis.fetch;
  /** Required: drives the per-connection session id and retry jitter. */
  readonly random: (length: number) => Uint8Array;
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  /**
   * Test seam: replaces the gRPC-web transport factory (for example wrapping
   * `createRouterTransport`). Called once per operator connection with that operator's config, so a
   * fake can serve different responses per operator. The interceptor chain is always applied, so
   * injected transports get the same auth, retry and error-mapping behavior as the default.
   */
  readonly transportFactory?: (
    interceptors: Interceptor[],
    operator: SparkOperatorConfig,
  ) => Transport;
};

/** Sent as `X-Client-Env`, the header the SOs accept from SDK clients. */
const CLIENT_ENV = "qntx-spark";
const AUTHN_SERVICE = "spark_authn.SparkAuthnService";
const AUTH_MAX_ATTEMPTS = 3;
const RETRY_MAX_ATTEMPTS = 3;
const RETRY_BASE_MS = 1000;
const RETRY_MAX_MS = 10_000;
const EVENT_RECONNECT_BASE_MS = 1000;
const EVENT_RECONNECT_MAX_MS = 60_000;

/** Overall deadline applied to every unary call without an explicit `timeoutMs`. */
const DEFAULT_RPC_TIMEOUT_MS = 60_000;

/**
 * The SO emits a heartbeat event every 5s while a `subscribe_to_events` stream is live (upstream
 * `streamHeartbeatInterval`); three intervals of silence mean the stream died without closing — the
 * attempt aborts and the reconnect loop resubscribes. Upstream applies the same 15s bound
 * unconditionally: even where the heartbeat knob is off, a resubscribe is the cheapest way to
 * notice a dead connection.
 */
const EVENT_IDLE_TIMEOUT_MS = 15_000;

/** Read-only RPCs; only these are eligible for the backoff-retry policy. */
const IDEMPOTENT_METHODS = new Set([
  "query_nodes",
  "query_pending_transfers",
  "query_all_transfers",
  "query_transfers_by_id",
  "query_balance",
  "query_unused_deposit_addresses",
  "query_static_deposit_addresses",
  "query_preimage",
  "query_htlc",
  "query_spark_invoices",
  "query_wallet_setting",
  "query_delegation_grants",
  "get_utxos_for_address",
  "get_utxos_for_identity",
  "get_signing_operator_list",
  "query_token_metadata",
  "query_token_transactions",
  "query_token_outputs",
]);

const RETRYABLE_CODES = new Set([
  Code.Unavailable,
  Code.DeadlineExceeded,
  Code.ResourceExhausted,
  Code.Aborted,
]);

function codeName(code: Code): string {
  const name = Code[code];
  // Connect enum names are PascalCase; the public code vocabulary is the gRPC
  // canonical snake_case form ("Unauthenticated" → "unauthenticated").
  return name === undefined
    ? "unknown"
    : name.replaceAll(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase();
}

function toSparkRequestError(error: unknown, operator: SparkOperatorConfig): SparkRequestError {
  if (error instanceof SparkRequestError) {
    return error;
  }
  if (error instanceof SparkError) {
    return new SparkRequestError(error.message, {
      operator: operator.identifier,
      cause: error,
    });
  }
  if (error instanceof ConnectError) {
    // The Connect runtime wraps non-ConnectError throws (like an auth SparkRequestError from the
    // session path) into Code.Unknown with the original error as the cause; unwrap it.
    if (error.cause instanceof SparkError) {
      return toSparkRequestError(error.cause, operator);
    }
    return new SparkRequestError(serverErrorText(error.rawMessage), {
      code: codeName(error.code),
      operator: operator.identifier,
      cause: error,
    });
  }
  const message = error instanceof Error ? error.message : String(error);
  return new SparkRequestError(message, { operator: operator.identifier, cause: error });
}

function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return typeof value === "object" && value !== null && Symbol.asyncIterator in value;
}

/**
 * Pulls one item, mapping a stream failure to SparkRequestError. Implemented as a manual async
 * iterator wrapper so no `await` sits inside a loop statement.
 */
function mapStreamErrors(
  stream: AsyncIterable<unknown>,
  operator: SparkOperatorConfig,
): AsyncIterable<unknown> {
  const iterator = stream[Symbol.asyncIterator]();
  return {
    [Symbol.asyncIterator]() {
      return {
        next: async (): Promise<IteratorResult<unknown>> => {
          try {
            return await iterator.next();
          } catch (error) {
            throw toSparkRequestError(error, operator);
          }
        },
      };
    },
  };
}

async function mapUnaryResult(result: unknown, operator: SparkOperatorConfig): Promise<unknown> {
  try {
    return await result;
  } catch (error) {
    throw toSparkRequestError(error, operator);
  }
}

/**
 * Errors thrown from inside an interceptor are normalized to `ConnectError`, so SparkRequestError
 * mapping happens here — a proxy over the typed client that maps ConnectError on unary calls and
 * streaming iterations.
 */
function mapClientErrors<S extends DescService>(
  client: Client<S>,
  operator: SparkOperatorConfig,
): Client<S> {
  return new Proxy(client, {
    get(target, prop) {
      const value: unknown = Reflect.get(target, prop);
      if (typeof value !== "function") {
        return value;
      }
      // Not async: streaming RPCs must return their AsyncIterable synchronously.
      return (...args: unknown[]) => {
        let result: unknown;
        try {
          result = Reflect.apply(value, target, args);
        } catch (error) {
          throw toSparkRequestError(error, operator);
        }
        if (result instanceof Promise) {
          return mapUnaryResult(result, operator);
        }
        if (isAsyncIterable(result)) {
          return mapStreamErrors(result, operator);
        }
        return result;
      };
    },
  });
}

function mapResponse(event: SubscribeToEventsResponse["event"]): SparkEvent | undefined {
  switch (event.case) {
    case "connected":
      return { type: "connected" };
    case "heartbeat":
      return { type: "heartbeat" };
    case "receiverTransfer":
    case "senderTransfer": {
      const { transfer } = event.value;
      if (transfer === undefined) {
        return undefined;
      }
      return {
        type: "transfer",
        direction: event.case === "receiverTransfer" ? "incoming" : "outgoing",
        transferId: transfer.id,
        senderIdentityPublicKey: transfer.senderIdentityPublicKey,
        receiverIdentityPublicKey: transfer.receiverIdentityPublicKey,
      };
    }
    case "deposit": {
      const leaf = event.value.deposit;
      if (leaf === undefined) {
        return undefined;
      }
      return { type: "deposit", leafId: leaf.id };
    }
    case "tokenTransaction": {
      const tx = event.value;
      return {
        type: "token-transaction",
        transactionHash: tx.tokenTransactionHash,
        tokenIdentifiers: tx.tokenIdentifiers,
      };
    }
    default:
      return undefined;
  }
}

/**
 * Connects to one signing operator: gRPC-web transport (`useBinaryFormat`), an interceptor chain
 * that attaches the Bearer session token (authenticating lazily, single-flight), re-authenticates
 * once on `Unauthenticated`, retries idempotent reads with exponential backoff, and maps
 * `ConnectError` to `SparkRequestError` at the client boundary.
 */
export function connectOperator(
  operator: SparkOperatorConfig,
  deps: ConnectionDeps,
): OperatorConnection {
  const now = deps.now ?? (() => Date.now());
  const sleep = deps.sleep ?? defaultSleep;
  const sessionId = uuidv7(deps.random, now);

  const interceptor: Interceptor = (next) => async (req) => {
    req.header.set("x-client-env", CLIENT_ENV);
    req.header.set("x-session-id", sessionId);
    if (req.service.typeName === AUTHN_SERVICE) {
      return next(req);
    }
    const call = async (
      attempt: number,
      reauthenticated: boolean,
    ): Promise<Awaited<ReturnType<typeof next>>> => {
      req.header.set("Authorization", `Bearer ${await sessionToken()}`);
      try {
        return await next(req);
      } catch (error) {
        const connErr = error instanceof ConnectError ? error : undefined;
        if (connErr !== undefined && connErr.code === Code.Unauthenticated && !reauthenticated) {
          invalidateSession();
          return call(attempt, true);
        }
        if (
          connErr !== undefined &&
          IDEMPOTENT_METHODS.has(req.method.name) &&
          RETRYABLE_CODES.has(connErr.code) &&
          attempt < RETRY_MAX_ATTEMPTS
        ) {
          await sleep(jittered(attempt, RETRY_BASE_MS, RETRY_MAX_MS));
          return call(attempt + 1, reauthenticated);
        }
        throw error;
      }
    };
    return call(0, false);
  };

  const transportFactory =
    deps.transportFactory ??
    ((interceptors: Interceptor[]): Transport =>
      createGrpcWebTransport({
        baseUrl: operator.address,
        fetch: deps.fetch,
        useBinaryFormat: true,
        defaultTimeoutMs: DEFAULT_RPC_TIMEOUT_MS,
        interceptors,
      }));
  const transport = transportFactory([interceptor], operator);
  const authn = createClient(SparkAuthnService, transport);

  let cached: { readonly token: string; readonly expiresAtMs: number } | undefined;
  let pending: Promise<string> | undefined;

  function invalidateSession(): void {
    cached = undefined;
  }

  /** One get_challenge → sign → verify round trip; retries recurse with a bounded attempt count. */
  async function authenticate(attempt: number): Promise<string> {
    try {
      const identityPublicKey = await deps.signer.identityPublicKey();
      const challengeResponse = await authn.get_challenge(
        { publicKey: identityPublicKey },
        { timeoutMs: 60_000 },
      );
      const { protectedChallenge } = challengeResponse;
      const challenge = protectedChallenge?.challenge;
      if (challenge === undefined) {
        throw new SparkRequestError("auth challenge response missing challenge", {
          operator: operator.identifier,
        });
      }
      const signature = await deps.signer.signIdentity({
        kind: "so-challenge",
        challenge: toBinary(ChallengeSchema, challenge),
      });
      const verified = await authn.verify_challenge(
        { protectedChallenge, signature, publicKey: identityPublicKey },
        { timeoutMs: 60_000 },
      );
      cached = {
        token: verified.sessionToken,
        expiresAtMs: Number(verified.expirationTimestamp) * 1000,
      };
      return verified.sessionToken;
    } catch (error) {
      // Only transient failures retry: an expired challenge (re-issued on the next round trip)
      // and Unavailable with backoff. Internal/Unknown hide real failures like a rejected
      // signature, so they surface immediately.
      const expiredChallenge =
        error instanceof ConnectError && error.rawMessage.includes("challenge expired");
      const unavailable = error instanceof ConnectError && error.code === Code.Unavailable;
      if ((!expiredChallenge && !unavailable) || attempt >= AUTH_MAX_ATTEMPTS - 1) {
        throw toSparkRequestError(error, operator);
      }
      if (unavailable) {
        await sleep(jittered(attempt, RETRY_BASE_MS, RETRY_MAX_MS));
      }
      return authenticate(attempt + 1);
    }
  }

  async function runAuth(): Promise<string> {
    try {
      return await authenticate(0);
    } finally {
      pending = undefined;
    }
  }

  async function sessionToken(): Promise<string> {
    if (cached !== undefined && now() < cached.expiresAtMs - SESSION_EXPIRY_BUFFER_MS) {
      return cached.token;
    }
    pending ??= runAuth();
    return pending;
  }

  function jittered(attempt: number, base: number, max: number): number {
    const cap = Math.min(base * 2 ** attempt, max);
    return Math.floor((cap * (deps.random(1)[0] ?? 0)) / 256);
  }

  return {
    operator,
    spark: mapClientErrors(createClient(SparkService, transport), operator),
    token: mapClientErrors(createClient(SparkTokenService, transport), operator),
    invalidateSession,
  };
}

/**
 * The coordinator's `subscribe_to_events` stream as an `AsyncIterable` of `SparkEvent`s. On stream
 * failure (or a clean close) it re-authenticates when needed and resubscribes with exponential
 * backoff (1s → 60s, jittered) until `signal` aborts. Each attempt carries no overall deadline —
 * `timeoutMs: 0` overrides the transport default — but dies on its own when no message (including
 * the SO's 5s heartbeats) arrives within {@link EVENT_IDLE_TIMEOUT_MS}: the attempt's abort signal
 * ends `next()` and the reconnect loop resubscribes. Implemented as a manual async iterator: every
 * `next()` pulls once, and reconnect/skip paths recurse so no `await` sits in a loop.
 */
export function sparkEvents(
  connection: OperatorConnection,
  identityPublicKey: Uint8Array,
  signal?: AbortSignal,
  deps?: Pick<ConnectionDeps, "sleep" | "random"> & { readonly idleTimeoutMs?: number },
): AsyncIterable<SparkEvent> {
  const sleep = deps?.sleep ?? defaultSleep;
  const idleTimeoutMs = deps?.idleTimeoutMs ?? EVENT_IDLE_TIMEOUT_MS;
  const aborted = () => signal !== undefined && signal.aborted;

  let current: AsyncIterator<SubscribeToEventsResponse> | undefined;
  let failures = 0;
  let idleTimer: ReturnType<typeof setTimeout> | undefined;
  let attemptAbort: AbortController | undefined;
  let onCallerAbort: (() => void) | undefined;

  const clearAttempt = (): void => {
    current = undefined;
    if (idleTimer !== undefined) {
      clearTimeout(idleTimer);
      idleTimer = undefined;
    }
    if (onCallerAbort !== undefined) {
      signal?.removeEventListener("abort", onCallerAbort);
      onCallerAbort = undefined;
    }
    attemptAbort = undefined;
  };

  /** (Re)arms the idle bound; a fired timer aborts only this attempt's stream. */
  const armIdle = (): void => {
    if (idleTimer !== undefined) {
      clearTimeout(idleTimer);
    }
    const timer = setTimeout(() => attemptAbort?.abort(), idleTimeoutMs);
    // Node's Timeout keeps a process alive; a background event stream must not.
    const rawTimer: unknown = timer;
    if (typeof rawTimer === "object" && rawTimer !== null && "unref" in rawTimer) {
      const unref: unknown = rawTimer.unref;
      if (typeof unref === "function") {
        Reflect.apply(unref, rawTimer, []);
      }
    }
    idleTimer = timer;
  };

  /** Backoff-then-resubscribe shared by stream errors and clean closes. */
  const resubscribe = async (): Promise<IteratorResult<SparkEvent>> => {
    clearAttempt();
    const cap = Math.min(EVENT_RECONNECT_BASE_MS * 2 ** failures, EVENT_RECONNECT_MAX_MS);
    failures++;
    const jitter = deps?.random === undefined ? cap / 2 : (cap * (deps.random(1)[0] ?? 0)) / 512;
    await sleep(Math.floor(cap / 2 + jitter));
    return pull();
  };

  const pull = async (): Promise<IteratorResult<SparkEvent>> => {
    if (aborted()) {
      clearAttempt();
      return { done: true, value: undefined };
    }
    try {
      if (current === undefined) {
        attemptAbort = new AbortController();
        onCallerAbort = () => attemptAbort?.abort();
        signal?.addEventListener("abort", onCallerAbort);
        if (signal?.aborted === true) {
          attemptAbort.abort();
        }
        current = connection.spark
          .subscribe_to_events({ identityPublicKey }, { signal: attemptAbort.signal, timeoutMs: 0 })
          [Symbol.asyncIterator]();
        armIdle();
      }
      const item = await current.next();
      // A clean close resubscribes through the same backoff path as a failure: a server that ends
      // streams immediately would otherwise spin the reconnect loop.
      if (item.done === true) {
        return await resubscribe();
      }
      armIdle();
      const event = mapResponse(item.value.event);
      if (event === undefined) {
        return await pull();
      }
      failures = 0;
      return { done: false, value: event };
    } catch (error) {
      if (aborted()) {
        clearAttempt();
        return { done: true, value: undefined };
      }
      // Stream iterations arrive already mapped by mapStreamErrors, so the auth check is on
      // SparkRequestError, not ConnectError.
      if (error instanceof SparkRequestError && error.code === "unauthenticated") {
        connection.invalidateSession();
      }
      return resubscribe();
    }
  };

  return {
    [Symbol.asyncIterator]() {
      return { next: pull };
    },
  };
}
