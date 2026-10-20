import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import {
  lightningAddressDescriptionHash,
  lightningAddressMessageDigest,
} from "../src/core/lightning-address.ts";
import type { LightningAddressStatement } from "../src/core/lightning-address.ts";
import { decodeLnurl } from "../src/lnurl/index.ts";
import {
  createLightningAddressServer,
  createMemoryLightningAddressStore,
} from "../src/server/index.ts";
import type {
  LightningAddressInvoice,
  LightningAddressResult,
  LightningAddressServerClient,
} from "../src/server/index.ts";

const DOMAIN = "example.com";
const NOW_SECS = 1_700_000_000;
const NOW_MS = NOW_SECS * 1000;

const SECRET_A = hexToBytes(`${"0".repeat(62)}01`);
const SECRET_B = hexToBytes(`${"0".repeat(62)}02`);
const PUBKEY_A = secp256k1.getPublicKey(SECRET_A);
const PUBKEY_B = secp256k1.getPublicKey(SECRET_B);
const PUBKEY_HEX_A = bytesToHex(PUBKEY_A);
const PUBKEY_HEX_B = bytesToHex(PUBKEY_B);

const RECEIPT_KEY = "f".repeat(64);

/**
 * The canonical message built verbatim — deliberately NOT the validating core builder, so a body
 * with an invalid username can still carry a well-formed signature.
 */
function rawMessage(statement: LightningAddressStatement): string {
  const fields =
    statement.action === "register"
      ? [
          "breez-lnurl:v2",
          "register",
          statement.domain,
          statement.username,
          lightningAddressDescriptionHash(statement.description),
          String(statement.timestamp),
        ]
      : [
          "breez-lnurl:v2",
          "unregister",
          statement.domain,
          statement.username,
          String(statement.timestamp),
        ];
  return fields.join("\n");
}

/** Signs the message over the LOWERCASED username — what the client helper would produce. */
function sign(statement: LightningAddressStatement, secret: Uint8Array): string {
  const signed: LightningAddressStatement = {
    ...statement,
    username: statement.username.toLowerCase(),
  };
  const digest = lightningAddressMessageDigest(rawMessage(signed));
  return bytesToHex(secp256k1.sign(digest, secret, { format: "der", prehash: false, lowS: true }));
}

function registerBody(
  username: string,
  secret: Uint8Array,
  timestamp = NOW_SECS,
  description = "Pay to me",
): Record<string, unknown> {
  const statement: LightningAddressStatement = {
    kind: "lightning-address",
    action: "register",
    domain: DOMAIN,
    username,
    description,
    timestamp,
  };
  return {
    username,
    signature: sign(statement, secret),
    timestamp,
    description,
  };
}

function unregisterBody(
  username: string,
  secret: Uint8Array,
  timestamp = NOW_SECS,
): Record<string, unknown> {
  const statement: LightningAddressStatement = {
    kind: "lightning-address",
    action: "unregister",
    domain: DOMAIN,
    username,
    timestamp,
  };
  return { username, signature: sign(statement, secret), timestamp };
}

type CreateInvoiceCall = {
  amountSats: number;
  descriptionHash?: Uint8Array;
  receiver?: string | Uint8Array;
  expirySecs?: number;
};

function fakeClient(options?: {
  /** The preimage `receiveStatus` reports for `req-{index + 1}` — its sha256 is the invoice hash. */
  readonly preimages?: ReadonlyArray<Uint8Array | undefined>;
  /** Request ids whose `receiveStatus` read rejects. */
  readonly failFor?: ReadonlyArray<string>;
}): {
  client: LightningAddressServerClient;
  calls: CreateInvoiceCall[];
  statusCalls: string[];
} {
  const calls: CreateInvoiceCall[] = [];
  const statusCalls: string[] = [];
  let counter = 0;
  const client = {
    lightning: {
      createInvoice: async (request: CreateInvoiceCall) => {
        calls.push(request);
        counter += 1;
        const preimage = options?.preimages?.[counter - 1];
        return Promise.resolve({
          id: `req-${counter}`,
          invoice: `lnbcrt-fake-${counter}`,
          // A configured preimage always matches the invoice hash — the real client's
          // receiveStatus only hands back verified preimages.
          paymentHash:
            preimage === undefined ? sha256(utf8ToBytes(`hash-${counter}`)) : sha256(preimage),
          amountSats: request.amountSats,
          expiresAtMs: NOW_MS + 600_000,
        });
      },
      receiveStatus: async (requestId: string) => {
        statusCalls.push(requestId);
        if (options?.failFor?.includes(requestId)) {
          throw new Error(`status read failed for ${requestId}`);
        }
        const index = Number(requestId.slice(4)) - 1;
        const preimage = options?.preimages?.[index];
        return Promise.resolve({
          status: "TRANSFER_COMPLETED",
          ...(preimage === undefined ? {} : { preimage }),
        });
      },
    },
  } as unknown as LightningAddressServerClient;
  return { calls, statusCalls, client };
}

function serverWith(
  client: LightningAddressServerClient,
  zap?: object,
  overrides?: {
    readonly invoiceExpirySecs?: number;
    readonly maxPendingInvoicesPerUser?: number;
    readonly maxPendingInvoices?: number;
    readonly settleBatch?: number;
  },
) {
  const store = createMemoryLightningAddressStore(() => NOW_MS);
  const server = createLightningAddressServer({
    client,
    domain: DOMAIN,
    store,
    minSendableMsat: 1000,
    maxSendableMsat: 10_000_000,
    commentAllowed: 255,
    zap: zap === undefined ? undefined : (zap as never),
    now: () => NOW_MS,
    ...overrides,
  });
  return { server, store };
}

async function statusOf(promise: Promise<LightningAddressResult>): Promise<number> {
  const response = await promise;
  return response.status;
}

async function bodyOf(promise: Promise<LightningAddressResult>): Promise<unknown> {
  const response = await promise;
  return response.body;
}

async function registerAlice(
  server: ReturnType<typeof serverWith>["server"],
  pubkeyHex = PUBKEY_HEX_A,
  secret = SECRET_A,
  name = "alice",
  description = "Pay to me",
): Promise<LightningAddressResult> {
  return server.register(pubkeyHex, registerBody(name, secret, NOW_SECS, description));
}

describe("register", () => {
  test("rejects malformed bodies and fields with 400", async () => {
    const { server } = serverWith(fakeClient().client);
    await expect(statusOf(server.register(PUBKEY_HEX_A, null))).resolves.toBe(400);
    await expect(statusOf(server.register(PUBKEY_HEX_A, { username: "alice" }))).resolves.toBe(400);
    const body = registerBody("alice", SECRET_A);
    await expect(
      statusOf(server.register(PUBKEY_HEX_A, { ...body, timestamp: "now" })),
    ).resolves.toBe(400);
    await expect(statusOf(server.register(PUBKEY_HEX_A, { ...body, signature: 5 }))).resolves.toBe(
      400,
    );
  });

  test("rejects invalid username, long description, bad pubkey and signature", async () => {
    const { server } = serverWith(fakeClient().client);
    await expect(
      statusOf(server.register(PUBKEY_HEX_A, registerBody("has space", SECRET_A))),
    ).resolves.toBe(400);
    await expect(
      statusOf(
        server.register(PUBKEY_HEX_A, registerBody("alice", SECRET_A, NOW_SECS, "d".repeat(513))),
      ),
    ).resolves.toBe(400);
    await expect(
      statusOf(server.register("not-hex", registerBody("alice", SECRET_A))),
    ).resolves.toBe(400);
    await expect(
      statusOf(server.register("ff".repeat(33), registerBody("alice", SECRET_A))),
    ).resolves.toBe(400);
    await expect(
      statusOf(
        server.register(PUBKEY_HEX_A, { ...registerBody("alice", SECRET_A), signature: "zz" }),
      ),
    ).resolves.toBe(400);
  });

  test("rejects a stale timestamp and a signature over different fields", async () => {
    const { server } = serverWith(fakeClient().client);
    await expect(
      statusOf(server.register(PUBKEY_HEX_A, registerBody("alice", SECRET_A, NOW_SECS - 601))),
    ).resolves.toBe(400);
    await expect(
      statusOf(server.register(PUBKEY_HEX_A, registerBody("alice", SECRET_A, NOW_SECS + 601))),
    ).resolves.toBe(400);
    // Signed for "alice" but the body says "bob".
    const body = registerBody("alice", SECRET_A);
    await expect(
      statusOf(server.register(PUBKEY_HEX_A, { ...body, username: "bob" })),
    ).resolves.toBe(400);
    // Signed by B but presented under A's pubkey.
    await expect(
      statusOf(server.register(PUBKEY_HEX_A, registerBody("alice", SECRET_B))),
    ).resolves.toBe(400);
  });

  test("registers and returns the bech32 lnurl and lightning_address", async () => {
    const { server } = serverWith(fakeClient().client);
    const response = await registerAlice(server);
    expect(response.status).toBe(200);
    const body = response.body as { lnurl: string; lightning_address: string };
    expect(body.lightning_address).toBe(`alice@${DOMAIN}`);
    expect(decodeLnurl(body.lnurl)).toBe(`https://${DOMAIN}/lnurlp/alice`);
  });

  test("uppercase usernames register under their lowercase form", async () => {
    const { server } = serverWith(fakeClient().client);
    const response = await server.register(PUBKEY_HEX_A, registerBody("Alice", SECRET_A));
    expect(response.status).toBe(200);
    const body = response.body as { lightning_address: string };
    expect(body.lightning_address).toBe(`alice@${DOMAIN}`);
  });

  test("a replayed statement is 409, a taken name is 409, re-register replaces the name", async () => {
    const { server } = serverWith(fakeClient().client);
    const body = registerBody("alice", SECRET_A);
    await expect(statusOf(server.register(PUBKEY_HEX_A, body))).resolves.toBe(200);
    // Same statement again — claimed.
    await expect(statusOf(server.register(PUBKEY_HEX_A, body))).resolves.toBe(409);
    // Another key claims the same name.
    await expect(
      statusOf(server.register(PUBKEY_HEX_B, registerBody("alice", SECRET_B))),
    ).resolves.toBe(409);
    // A re-registers under a different name: the old name is released.
    await expect(
      statusOf(server.register(PUBKEY_HEX_A, registerBody("alice2", SECRET_A, NOW_SECS + 1))),
    ).resolves.toBe(200);
    await expect(statusOf(server.payRequest("alice"))).resolves.toBe(404);
    await expect(statusOf(server.payRequest("alice2"))).resolves.toBe(200);
    // B can now take the released name.
    await expect(
      statusOf(server.register(PUBKEY_HEX_B, registerBody("alice", SECRET_B, NOW_SECS + 2))),
    ).resolves.toBe(200);
  });
});

describe("unregister", () => {
  test("unregisters the held name; a second identical statement is a replay", async () => {
    const { server } = serverWith(fakeClient().client);
    await registerAlice(server);
    const body = unregisterBody("alice", SECRET_A);
    await expect(statusOf(server.unregister(PUBKEY_HEX_A, body))).resolves.toBe(200);
    await expect(statusOf(server.payRequest("alice"))).resolves.toBe(404);
    // Replaying the same statement is a conflict.
    await expect(statusOf(server.unregister(PUBKEY_HEX_A, body))).resolves.toBe(409);
    // A fresh statement for a key holding nothing is a no-op 200.
    await expect(
      statusOf(server.unregister(PUBKEY_HEX_B, unregisterBody("alice", SECRET_B, NOW_SECS + 1))),
    ).resolves.toBe(200);
  });

  test("rejects a statement naming a different name than held", async () => {
    const { server } = serverWith(fakeClient().client);
    await registerAlice(server);
    await expect(
      statusOf(server.unregister(PUBKEY_HEX_A, unregisterBody("alice2", SECRET_A, NOW_SECS + 1))),
    ).resolves.toBe(400);
    // The name still stands.
    await expect(statusOf(server.payRequest("alice"))).resolves.toBe(200);
  });

  test("rejects stale timestamps, bad keys and bad signatures", async () => {
    const { server } = serverWith(fakeClient().client);
    await expect(
      statusOf(server.unregister(PUBKEY_HEX_A, unregisterBody("alice", SECRET_A, NOW_SECS - 601))),
    ).resolves.toBe(400);
    await expect(
      statusOf(server.unregister("xyz", unregisterBody("alice", SECRET_A))),
    ).resolves.toBe(400);
    await expect(
      statusOf(
        server.unregister(PUBKEY_HEX_A, {
          ...unregisterBody("alice", SECRET_A),
          signature: "zz",
        }),
      ),
    ).resolves.toBe(400);
  });
});

describe("payRequest", () => {
  test("404 for an unknown name; LUD-06 shape without zap", async () => {
    const { server } = serverWith(fakeClient().client);
    await expect(statusOf(server.payRequest("nobody"))).resolves.toBe(404);
    await registerAlice(server);
    const response = await server.payRequest("alice");
    expect(response.status).toBe(200);
    const body = response.body as Record<string, unknown>;
    expect(body["tag"]).toBe("payRequest");
    expect(body["callback"]).toBe(`https://${DOMAIN}/lnurlp/alice/invoice`);
    expect(body["minSendable"]).toBe(1000);
    expect(body["maxSendable"]).toBe(10_000_000);
    expect(body["commentAllowed"]).toBe(255);
    expect(JSON.parse(body["metadata"] as string)).toStrictEqual([
      ["text/plain", "Pay to me"],
      ["text/identifier", `alice@${DOMAIN}`],
    ]);
    expect("allowsNostr" in body).toBe(false);
    expect("nostrPubkey" in body).toBe(false);
  });

  test("advertises nostr fields when zap is configured", async () => {
    const { server } = serverWith(fakeClient().client, {
      receiptPublicKey: RECEIPT_KEY,
      validateRequest: () => undefined,
    });
    await registerAlice(server);
    const body = (await bodyOf(server.payRequest("alice"))) as Record<string, unknown>;
    expect(body["allowsNostr"]).toBe(true);
    expect(body["nostrPubkey"]).toBe(RECEIPT_KEY);
  });
});

describe("invoice", () => {
  test("rejects unknown names, bad amounts, bounds, comments and unsupported zaps", async () => {
    const { server } = serverWith(fakeClient().client);
    await expect(statusOf(server.invoice("nobody", { amount: 1000 }))).resolves.toBe(404);
    await registerAlice(server);
    const error = async (params: Parameters<typeof server.invoice>[1]) => {
      const response = await server.invoice("alice", params);
      expect(response.status).toBe(200);
      return (response.body as { status: string; reason: string }).reason;
    };
    await expect(error({ amount: undefined })).resolves.toBe("missing amount");
    await expect(error({ amount: 1500 })).resolves.toBe("amount must be a whole sat amount");
    await expect(error({ amount: 1000 - 1000 })).resolves.toBe("amount out of bounds");
    await expect(error({ amount: 10_001_000 })).resolves.toBe("amount out of bounds");
    await expect(error({ amount: 1000, comment: "x".repeat(256) })).resolves.toBe(
      "comment too long",
    );
    await expect(error({ amount: 1000, nostr: "{}" })).resolves.toBe("nostr zap not supported");
  });

  test("zap validation errors surface as LNURL errors", async () => {
    const { server } = serverWith(fakeClient().client, {
      receiptPublicKey: RECEIPT_KEY,
      validateRequest: () => {
        throw new Error("zap request is not for this address");
      },
    });
    await registerAlice(server);
    const response = await server.invoice("alice", { amount: 1000, nostr: "{bad}" });
    expect(response.body).toStrictEqual({
      status: "ERROR",
      reason: "zap request is not for this address",
    });
  });

  test("creates the invoice with the payee receiver and the metadata description hash", async () => {
    const { client, calls } = fakeClient();
    const { server, store } = serverWith(client);
    await registerAlice(server);
    const metadata = JSON.stringify([
      ["text/plain", "Pay to me"],
      ["text/identifier", `alice@${DOMAIN}`],
    ]);
    const response = await server.invoice("alice", { amount: 7_000_000, comment: "tip" });
    expect(response.status).toBe(200);
    const body = response.body as { pr: string; routes: unknown[]; verify: string };
    expect(body.pr).toBe("lnbcrt-fake-1");
    expect(body.routes).toStrictEqual([]);
    expect(body.verify).toBe(
      `https://${DOMAIN}/lnurlp/verify/${bytesToHex(sha256(utf8ToBytes("hash-1")))}`,
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]!.amountSats).toBe(7000);
    expect(bytesToHex(calls[0]!.descriptionHash!)).toBe(bytesToHex(sha256(utf8ToBytes(metadata))));
    expect(bytesToHex(calls[0]!.receiver as Uint8Array)).toBe(PUBKEY_HEX_A);
    const record = await store.invoiceByPaymentHash(bytesToHex(sha256(utf8ToBytes("hash-1"))));
    expect(record?.name).toBe("alice");
    expect(record?.comment).toBe("tip");
  });

  test("requests the configured invoice expiry — 3600 by default", async () => {
    const { client, calls } = fakeClient();
    const { server: custom } = serverWith(client, undefined, { invoiceExpirySecs: 600 });
    await registerAlice(custom);
    await custom.invoice("alice", { amount: 1000 });
    const { server: defaults } = serverWith(client);
    await registerAlice(defaults, PUBKEY_HEX_B, SECRET_B, "bob");
    await defaults.invoice("bob", { amount: 1000 });
    expect(calls.map((call) => call.expirySecs)).toStrictEqual([600, 3600]);
  });

  test("rejects invoices past the per-user and global pending caps", async () => {
    const perUser = serverWith(fakeClient().client, undefined, {
      maxPendingInvoicesPerUser: 1,
    });
    await registerAlice(perUser.server);
    await perUser.server.invoice("alice", { amount: 1000 }); // fills the quota
    const second = await perUser.server.invoice("alice", { amount: 2000 });
    expect(second.body).toStrictEqual({ status: "ERROR", reason: "too many pending invoices" });

    // The same row also fills a global cap of 1 — even for another payee.
    const global = serverWith(fakeClient().client, undefined, { maxPendingInvoices: 1 });
    await registerAlice(global.server);
    await global.server.invoice("alice", { amount: 1000 });
    await global.server.register(PUBKEY_HEX_B, registerBody("bob", SECRET_B, NOW_SECS + 1));
    const other = await global.server.invoice("bob", { amount: 1000 });
    expect(other.body).toStrictEqual({ status: "ERROR", reason: "too many pending invoices" });
    // Expired rows never count toward the cap — the error is alice's pending invoice alone.
    await global.store.putInvoice({
      paymentHash: "dd".repeat(32),
      requestId: "req-old",
      name: "bob",
      pubkeyHex: PUBKEY_HEX_B,
      invoice: "lnbcrt-old",
      expiresAtMs: NOW_MS - 1,
    } satisfies LightningAddressInvoice);
    // Settling alice's invoice frees the quota.
    const settled = await global.store.settleInvoice(
      bytesToHex(sha256(utf8ToBytes("hash-1"))),
      "cc".repeat(32),
    );
    expect(settled).toBeDefined();
    const freed = await global.server.invoice("bob", { amount: 1000 });
    expect((freed.body as { status?: string }).status).not.toBe("ERROR");
    expect((freed.body as { pr?: string }).pr).toBeDefined();
  });

  test("a nostr zap request replaces the metadata in the description hash", async () => {
    const { client, calls } = fakeClient();
    const nostr = `{"kind":9734,"content":"zap"}`;
    const { server, store } = serverWith(client, {
      receiptPublicKey: RECEIPT_KEY,
      validateRequest: () => undefined,
    });
    await registerAlice(server);
    const response = await server.invoice("alice", { amount: 1000, nostr });
    expect(response.status).toBe(200);
    expect(bytesToHex(calls[0]!.descriptionHash!)).toBe(bytesToHex(sha256(utf8ToBytes(nostr))));
    const record = await store.invoiceByPaymentHash(bytesToHex(sha256(utf8ToBytes("hash-1"))));
    expect(record?.zapRequest).toBe(nostr);
  });
});

describe("verify + settlePending", () => {
  test("verify reports unsettled and settled invoices; unknown is an error", async () => {
    const preimage = hexToBytes("ab".repeat(32));
    const { client } = fakeClient({ preimages: [preimage] });
    const { server } = serverWith(client);
    await registerAlice(server);
    await server.invoice("alice", { amount: 1000 });
    const hash = bytesToHex(sha256(preimage));

    const unknown = await server.verify("00".repeat(32));
    expect(unknown.body).toStrictEqual({ status: "ERROR", reason: "Not found" });

    const pending = await bodyOf(server.verify(hash));
    expect(pending).toStrictEqual({
      status: "OK",
      settled: false,
      pr: "lnbcrt-fake-1",
    });

    const settled = await server.settlePending();
    expect(settled).toHaveLength(1);
    expect(settled[0]!.preimageHex).toBe(bytesToHex(preimage));

    const done = await bodyOf(server.verify(hash));
    const record = done as Record<string, unknown>;
    expect(record["settled"]).toBe(true);
    expect(record["preimage"]).toBe(bytesToHex(preimage));
    expect(record["pr"]).toBe("lnbcrt-fake-1");
  });

  test("settlePending only settles invoices with a verified preimage and skips expired", async () => {
    const { client, statusCalls } = fakeClient(); // no preimage → nothing settles
    const { server, store } = serverWith(client);
    await registerAlice(server);
    await server.invoice("alice", { amount: 1000 });
    await store.putInvoice({
      paymentHash: "11".repeat(32),
      requestId: "expired",
      name: "alice",
      pubkeyHex: PUBKEY_HEX_A,
      invoice: "lnbcrt-old",
      expiresAtMs: NOW_MS - 1, // already expired — never polled
    } satisfies LightningAddressInvoice);

    await expect(server.settlePending()).resolves.toHaveLength(0);
    expect(statusCalls).toStrictEqual(["req-1"]);

    const record = await store.invoiceByPaymentHash(bytesToHex(sha256(utf8ToBytes("hash-1"))));
    expect(record?.preimageHex).toBeUndefined();
  });

  test("a failing status read stays pending without aborting the round", async () => {
    const preimage = hexToBytes("ab".repeat(32));
    const { client } = fakeClient({ preimages: [preimage], failFor: ["req-2"] });
    const { server, store } = serverWith(client);
    await registerAlice(server);
    await server.invoice("alice", { amount: 1000 }); // req-1
    await server.invoice("alice", { amount: 2000 }); // req-2 — its status read throws

    const settled = await server.settlePending();
    expect(settled).toHaveLength(1);
    expect(settled[0]!.paymentHash).toBe(bytesToHex(sha256(preimage)));

    // req-2 stays pending — the next round retries it.
    const pending = await store.pendingInvoices(NOW_MS, 10);
    expect(pending.map((i) => i.requestId)).toStrictEqual(["req-2"]);
  });

  test("settlePending bounds a round and rotates least-recently-checked first", async () => {
    const { client, statusCalls } = fakeClient(); // nothing settles
    const { server } = serverWith(client, undefined, { settleBatch: 2 });
    await registerAlice(server);
    await server.invoice("alice", { amount: 1000 }); // req-1
    await server.invoice("alice", { amount: 2000 }); // req-2
    await server.invoice("alice", { amount: 3000 }); // req-3

    // Round 1: insertion order — every record is unchecked.
    await server.settlePending();
    expect(statusCalls).toStrictEqual(["req-1", "req-2"]);
    // Round 2: the never-checked req-3 goes first, then the oldest check.
    await server.settlePending();
    expect(statusCalls).toStrictEqual(["req-1", "req-2", "req-3", "req-1"]);
  });

  test("verify lowercases the hash and rejects malformed input", async () => {
    const { server } = serverWith(fakeClient().client);
    await registerAlice(server);
    await server.invoice("alice", { amount: 1000 });
    const hash = bytesToHex(sha256(utf8ToBytes("hash-1")));

    const upper = await server.verify(hash.toUpperCase());
    expect((upper.body as Record<string, unknown>)["status"]).toBe("OK");

    await expect(bodyOf(server.verify("not-a-hash"))).resolves.toStrictEqual({
      status: "ERROR",
      reason: "Not found",
    });
    await expect(bodyOf(server.verify("12".repeat(40)))).resolves.toStrictEqual({
      status: "ERROR",
      reason: "Not found",
    });
  });
});

describe("memory store", () => {
  function invoice(overrides: Partial<LightningAddressInvoice> = {}): LightningAddressInvoice {
    return {
      paymentHash: "ab".repeat(32),
      requestId: "req-1",
      name: "alice",
      pubkeyHex: PUBKEY_HEX_A,
      invoice: "lnbcrt1...",
      expiresAtMs: NOW_MS + 60_000,
      ...overrides,
    };
  }

  test("countPendingInvoices scopes by pubkey and ignores settled and expired rows", async () => {
    const store = createMemoryLightningAddressStore();
    await store.putInvoice(invoice());
    await store.putInvoice(
      invoice({ paymentHash: "11".repeat(32), requestId: "req-2", pubkeyHex: PUBKEY_HEX_B }),
    );
    await store.putInvoice(
      invoice({ paymentHash: "22".repeat(32), requestId: "req-3", expiresAtMs: NOW_MS - 1 }),
    );
    await store.putInvoice(
      invoice({ paymentHash: "33".repeat(32), requestId: "req-4", preimageHex: "cc".repeat(32) }),
    );
    await expect(store.countPendingInvoices(NOW_MS)).resolves.toBe(2);
    await expect(store.countPendingInvoices(NOW_MS, PUBKEY_HEX_A)).resolves.toBe(1);
    await expect(store.countPendingInvoices(NOW_MS, PUBKEY_HEX_B)).resolves.toBe(1);
  });

  test("pendingInvoices caps the batch and rotates least-recently-checked first", async () => {
    const store = createMemoryLightningAddressStore();
    await store.putInvoice(invoice({ requestId: "req-1" }));
    await store.putInvoice(
      invoice({ paymentHash: "11".repeat(32), requestId: "req-2", expiresAtMs: NOW_MS + 120_000 }),
    );
    await store.putInvoice(
      invoice({ paymentHash: "22".repeat(32), requestId: "req-3", expiresAtMs: NOW_MS + 180_000 }),
    );
    const first = await store.pendingInvoices(NOW_MS, 2);
    expect(first.map((i) => i.requestId)).toStrictEqual(["req-1", "req-2"]);
    await store.markChecked("ab".repeat(32), NOW_MS + 1);
    await store.markChecked("11".repeat(32), NOW_MS + 2);
    const next = await store.pendingInvoices(NOW_MS + 2, 2);
    expect(next.map((i) => i.requestId)).toStrictEqual(["req-3", "req-1"]);
  });

  test("pruneInvoices drops expired unsettled rows and settled rows past retention", async () => {
    const store = createMemoryLightningAddressStore();
    const retention = 30 * 24 * 3600 * 1000;
    await store.putInvoice(invoice({ requestId: "req-1", expiresAtMs: NOW_MS - 1 })); // expired
    await store.putInvoice(
      invoice({
        paymentHash: "11".repeat(32),
        requestId: "req-2",
        expiresAtMs: NOW_MS - retention - 1,
        preimageHex: "cc".repeat(32),
      }),
    ); // settled long ago
    await store.putInvoice(
      invoice({
        paymentHash: "22".repeat(32),
        requestId: "req-3",
        expiresAtMs: NOW_MS - 1,
        preimageHex: "cc".repeat(32),
      }),
    ); // settled, inside retention
    await store.putInvoice(
      invoice({ paymentHash: "33".repeat(32), requestId: "req-4", expiresAtMs: NOW_MS + 60_000 }),
    ); // live
    await expect(store.pruneInvoices(NOW_MS, retention)).resolves.toBe(2);
    await expect(store.invoiceByPaymentHash("ab".repeat(32))).resolves.toBeUndefined();
    await expect(store.invoiceByPaymentHash("11".repeat(32))).resolves.toBeUndefined();
    await expect(store.invoiceByPaymentHash("22".repeat(32))).resolves.toBeDefined();
    await expect(store.invoiceByPaymentHash("33".repeat(32))).resolves.toBeDefined();
  });

  test("claimStatement prunes expired claims — a statement may be re-signed and reused", async () => {
    let now = 1000;
    const store = createMemoryLightningAddressStore(() => now);
    await expect(store.claimStatement("s1", 2000)).resolves.toBe(true);
    await expect(store.claimStatement("s1", 2000)).resolves.toBe(false);
    now = 2500;
    await expect(store.claimStatement("s1", 4000)).resolves.toBe(true);
    await expect(store.claimStatement("s1", 4000)).resolves.toBe(false);
  });
});
