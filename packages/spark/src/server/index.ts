import { secp256k1 } from "@noble/curves/secp256k1.js";
import { equalBytes } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import type { SparkClient } from "../client/index.ts";
import {
  LIGHTNING_ADDRESS_MAX_DESCRIPTION_LENGTH,
  LIGHTNING_ADDRESS_USERNAME_PATTERN,
  LIGHTNING_ADDRESS_VALIDITY_SECS,
  checkLightningAddressDomain,
  lightningAddressMessageDigest,
  lightningAddressRegisterMessage,
  lightningAddressStatementHash,
  lightningAddressTimestampFresh,
  lightningAddressUnregisterMessage,
} from "../core/lightning-address.ts";
import { serverErrorText } from "../core/text.ts";
import { SparkInputError } from "../errors/index.ts";
import { isJsonObject } from "../lnurl/http.ts";
import { encodeLnurl } from "../lnurl/index.ts";
import type { LightningAddressInvoice, LightningAddressStore } from "./store.ts";

export { createMemoryLightningAddressStore } from "./store.ts";
export type {
  LightningAddressInvoice,
  LightningAddressStore,
  LightningAddressUser,
} from "./store.ts";

// A framework-agnostic Lightning Address server (LUD-06/LUD-12/LUD-21, NIP-57
// zap hooks) over a Breez-style signed-statement registration protocol —
// ported from Breez crates/breez-sdk/lnurl/src/routes.rs @956ff90. HTTP
// binding is the app's: every handler returns `{ status, body }`.

export type LightningAddressResult = {
  readonly status: number;
  readonly body: unknown;
};

/** NIP-57 zap support: the receipt key plus the app's own zap-request validation. */
export type LightningAddressZapConfig = {
  /** The receipt signer's 32-byte x-only public key, lowercase hex — the `nostrPubkey` payers see. */
  readonly receiptPublicKey: string;
  /** Validates a raw zap-request event JSON for `amountMsat`; throwing rejects the invoice. */
  readonly validateRequest: (json: string, amountMsat: number) => void;
};

/** The wallet the server creates invoices through — a `SparkClient` or its lightning slice. */
export type LightningAddressServerClient = Pick<SparkClient, "lightning">;

export type LightningAddressServer = {
  /** `POST /lnurlpay/{pubkey}` — signed statement claims a name. */
  readonly register: (pubkeyHex: string, body: unknown) => Promise<LightningAddressResult>;
  /** `DELETE /lnurlpay/{pubkey}` — signed statement gives the held name up. */
  readonly unregister: (pubkeyHex: string, body: unknown) => Promise<LightningAddressResult>;
  /** `GET /.well-known/lnurlp/{name}` (or `/lnurlp/{name}`) — the LUD-06 payRequest. */
  readonly payRequest: (name: string) => Promise<LightningAddressResult>;
  /** `GET /lnurlp/{name}/invoice?amount=&comment=&nostr=` — the LUD-06 callback. */
  readonly invoice: (
    name: string,
    params: { readonly amount: unknown; readonly comment?: string; readonly nostr?: string },
  ) => Promise<LightningAddressResult>;
  /** `GET /lnurlp/verify/{paymentHash}` — LUD-21 payment status. */
  readonly verify: (paymentHashHex: string) => Promise<LightningAddressResult>;
  /**
   * Polls `client.lightning.receiveStatus` for a bounded batch of pending invoices —
   * least-recently-checked first — and settles the ones whose verified preimage arrived. Returns
   * the records settled this round so the app can publish zap receipts or webhooks.
   */
  readonly settlePending: () => Promise<ReadonlyArray<LightningAddressInvoice>>;
};

function result(status: number, body: unknown): LightningAddressResult {
  return { status, body };
}

/** LUD convention: business errors ride a 200 with the `{"status": "ERROR"}` envelope. */
function lnurlError(reason: string): LightningAddressResult {
  return result(200, { status: "ERROR", reason });
}

/** `settlePending` polls at most this many invoice statuses in parallel. */
const SETTLE_CONCURRENCY = 8;

const DEFAULT_INVOICE_EXPIRY_SECS = 3600;
const DEFAULT_MAX_PENDING_PER_USER = 100;
const DEFAULT_MAX_PENDING = 10_000;
const DEFAULT_SETTLE_BATCH = 200;

function positiveInt(value: number | undefined, fallback: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 1) {
    throw new SparkInputError(`lightning address server: ${name} must be a positive integer`);
  }
  return resolved;
}

function asStringField(body: Record<string, unknown>, field: string): string {
  const value = body[field];
  if (typeof value !== "string") {
    throw new SparkInputError(`${field} is not a string`);
  }
  return value;
}

function asTimestampField(body: Record<string, unknown>): number {
  const value = body["timestamp"];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new SparkInputError("timestamp is not a non-negative integer");
  }
  return value;
}

function parseKeyAndSignature(
  pubkeyHex: string,
  signatureHex: string,
): { pubkey: Uint8Array; pubkeyHex: string; signature: Uint8Array } | LightningAddressResult {
  let pubkey: ReturnType<typeof secp256k1.Point.fromBytes>;
  try {
    pubkey = secp256k1.Point.fromBytes(hexToBytes(pubkeyHex));
  } catch {
    return result(400, "invalid pubkey");
  }
  let signature: Uint8Array;
  try {
    signature = secp256k1.Signature.fromBytes(hexToBytes(signatureHex), "der").toBytes("der");
  } catch {
    return result(400, "invalid signature");
  }
  return { pubkey: pubkey.toBytes(true), pubkeyHex: bytesToHex(pubkey.toBytes(true)), signature };
}

function verifyStatement(pubkey: Uint8Array, signature: Uint8Array, message: string): boolean {
  try {
    return secp256k1.verify(signature, lightningAddressMessageDigest(message), pubkey, {
      format: "der",
      prehash: false,
    });
  } catch {
    return false;
  }
}

/**
 * Creates the Lightning Address handlers for one `domain`. The registration LNURL handed out is the
 * LUD-01 bech32 encoding of `https://{domain}/lnurlp/{name}` (not the `lnurlp://` LUD-17 scheme) —
 * every LUD-16 wallet resolves the bare address without scheme support.
 */
export function createLightningAddressServer(options: {
  readonly client: LightningAddressServerClient;
  /** The served hostname — validated, lowercased, and signed into every registration message. */
  readonly domain: string;
  readonly store: LightningAddressStore;
  readonly minSendableMsat: number;
  readonly maxSendableMsat: number;
  /** Longest payer comment accepted (LUD-12 `commentAllowed`). */
  readonly commentAllowed: number;
  /** BOLT-11 expiry requested for every issued invoice; default {@link DEFAULT_INVOICE_EXPIRY_SECS}. */
  readonly invoiceExpirySecs?: number;
  /**
   * Pending (unsettled, unexpired) invoices one payee may hold — an unauthenticated callback is a
   * write, so without a cap a name's quota is a free database row each. Default 100.
   */
  readonly maxPendingInvoicesPerUser?: number;
  /** Pending invoices the whole server holds; default 10_000. */
  readonly maxPendingInvoices?: number;
  /**
   * Invoices status-checked per `settlePending` round, least-recently-checked first so a backlog
   * rotates fairly instead of starving the tail. Default {@link DEFAULT_SETTLE_BATCH}.
   */
  readonly settleBatch?: number;
  readonly zap?: LightningAddressZapConfig | undefined;
  readonly now?: (() => number) | undefined;
}): LightningAddressServer {
  const domain = options.domain.toLowerCase();
  checkLightningAddressDomain(domain);
  if (
    !Number.isSafeInteger(options.minSendableMsat) ||
    options.minSendableMsat < 1 ||
    !Number.isSafeInteger(options.maxSendableMsat) ||
    options.maxSendableMsat < options.minSendableMsat
  ) {
    throw new SparkInputError("lightning address server: invalid sendable bounds");
  }
  if (!Number.isSafeInteger(options.commentAllowed) || options.commentAllowed < 0) {
    throw new SparkInputError("lightning address server: invalid commentAllowed");
  }
  if (options.zap !== undefined && !/^[0-9a-f]{64}$/u.test(options.zap.receiptPublicKey)) {
    throw new SparkInputError(
      "lightning address server: zap.receiptPublicKey must be 32-byte lowercase hex",
    );
  }
  const { client, store } = options;
  const { zap } = options;
  const invoiceExpirySecs = positiveInt(
    options.invoiceExpirySecs,
    DEFAULT_INVOICE_EXPIRY_SECS,
    "invoiceExpirySecs",
  );
  const maxPendingPerUser = positiveInt(
    options.maxPendingInvoicesPerUser,
    DEFAULT_MAX_PENDING_PER_USER,
    "maxPendingInvoicesPerUser",
  );
  const maxPending = positiveInt(
    options.maxPendingInvoices,
    DEFAULT_MAX_PENDING,
    "maxPendingInvoices",
  );
  const settleBatch = positiveInt(options.settleBatch, DEFAULT_SETTLE_BATCH, "settleBatch");
  const now = options.now ?? (() => Date.now());
  const nowSecs = (): number => Math.floor(now() / 1000);

  function metadataOf(user: { name: string; description: string }): string {
    return JSON.stringify([
      ["text/plain", user.description],
      ["text/identifier", `${user.name}@${domain}`],
    ]);
  }

  /**
   * Claims the signed statement before anything else — replay protection burns the signature
   * unconditionally, so a registration that then loses a name race still consumes its statement and
   * the caller must sign a fresh one (its timestamp window has moved on anyway).
   */
  async function claimAndStore(
    pubkeyHex: string,
    message: string,
    timestamp: number,
    user: { name: string; pubkeyHex: string; description: string } | undefined,
  ): Promise<LightningAddressResult | undefined> {
    const statementHash = lightningAddressStatementHash(pubkeyHex, message);
    const claimed = await store.claimStatement(
      statementHash,
      (timestamp + LIGHTNING_ADDRESS_VALIDITY_SECS) * 1000,
    );
    if (!claimed) {
      return result(409, "signature has already been used");
    }
    if (user !== undefined && !(await store.putUser(user))) {
      return result(409, "name already taken");
    }
    return undefined;
  }

  async function register(pubkeyHex: string, body: unknown): Promise<LightningAddressResult> {
    if (!isJsonObject(body)) {
      return result(400, "invalid request body");
    }
    let parsed: { username: string; signature: string; timestamp: number; description: string };
    try {
      parsed = {
        username: asStringField(body, "username").toLowerCase(),
        signature: asStringField(body, "signature"),
        timestamp: asTimestampField(body),
        description: asStringField(body, "description"),
      };
    } catch {
      return result(400, "invalid request body");
    }
    if (!LIGHTNING_ADDRESS_USERNAME_PATTERN.test(parsed.username)) {
      return result(400, "invalid username");
    }
    if (parsed.description.length > LIGHTNING_ADDRESS_MAX_DESCRIPTION_LENGTH) {
      return result(400, "description too long");
    }
    const key = parseKeyAndSignature(pubkeyHex, parsed.signature);
    if ("status" in key) {
      return key;
    }
    if (!lightningAddressTimestampFresh(parsed.timestamp, nowSecs())) {
      return result(400, "invalid timestamp");
    }
    const message = lightningAddressRegisterMessage(
      domain,
      parsed.username,
      parsed.description,
      parsed.timestamp,
    );
    if (!verifyStatement(key.pubkey, key.signature, message)) {
      return result(400, `invalid signature for domain '${domain}'`);
    }
    const failure = await claimAndStore(key.pubkeyHex, message, parsed.timestamp, {
      name: parsed.username,
      pubkeyHex: key.pubkeyHex,
      description: parsed.description,
    });
    if (failure !== undefined) {
      return failure;
    }
    // The bech32 LNURL of the pay endpoint — the LUD-17-free form every client resolves.
    const lnurl = encodeLnurl(`https://${domain}/lnurlp/${parsed.username}`);
    return result(200, { lnurl, lightning_address: `${parsed.username}@${domain}` });
  }

  async function unregister(pubkeyHex: string, body: unknown): Promise<LightningAddressResult> {
    if (!isJsonObject(body)) {
      return result(400, "invalid request body");
    }
    let parsed: { username: string; signature: string; timestamp: number };
    try {
      parsed = {
        username: asStringField(body, "username").toLowerCase(),
        signature: asStringField(body, "signature"),
        timestamp: asTimestampField(body),
      };
    } catch {
      return result(400, "invalid request body");
    }
    if (!LIGHTNING_ADDRESS_USERNAME_PATTERN.test(parsed.username)) {
      return result(400, "invalid username");
    }
    const key = parseKeyAndSignature(pubkeyHex, parsed.signature);
    if ("status" in key) {
      return key;
    }
    if (!lightningAddressTimestampFresh(parsed.timestamp, nowSecs())) {
      return result(400, "invalid timestamp");
    }
    const message = lightningAddressUnregisterMessage(domain, parsed.username, parsed.timestamp);
    if (!verifyStatement(key.pubkey, key.signature, message)) {
      return result(400, `invalid signature for domain '${domain}'`);
    }
    const failure = await claimAndStore(key.pubkeyHex, message, parsed.timestamp, undefined);
    if (failure !== undefined) {
      return failure;
    }
    const held = await store.userByPublicKey(key.pubkeyHex);
    if (held === undefined) {
      return result(200, "");
    }
    if (held.name !== parsed.username) {
      return result(400, "username does not match the registered name");
    }
    if (!(await store.deleteUser(key.pubkeyHex, parsed.username))) {
      return result(400, "username does not match the registered name");
    }
    return result(200, "");
  }

  async function payRequest(name: string): Promise<LightningAddressResult> {
    const user = await store.userByName(name.toLowerCase());
    if (user === undefined) {
      return result(404, "");
    }
    return result(200, {
      tag: "payRequest",
      callback: `https://${domain}/lnurlp/${user.name}/invoice`,
      minSendable: options.minSendableMsat,
      maxSendable: options.maxSendableMsat,
      metadata: metadataOf(user),
      commentAllowed: options.commentAllowed,
      ...(zap === undefined ? {} : { allowsNostr: true, nostrPubkey: zap.receiptPublicKey }),
    });
  }

  async function invoice(
    name: string,
    params: { readonly amount: unknown; readonly comment?: string; readonly nostr?: string },
  ): Promise<LightningAddressResult> {
    const user = await store.userByName(name.toLowerCase());
    if (user === undefined) {
      return result(404, "");
    }
    if (typeof params.amount !== "number" || !Number.isSafeInteger(params.amount)) {
      return lnurlError("missing amount");
    }
    if (params.amount % 1000 !== 0) {
      return lnurlError("amount must be a whole sat amount");
    }
    if (params.amount < options.minSendableMsat || params.amount > options.maxSendableMsat) {
      return lnurlError("amount out of bounds");
    }
    if (params.comment !== undefined && params.comment.length > options.commentAllowed) {
      return lnurlError("comment too long");
    }
    if (params.nostr !== undefined) {
      if (zap === undefined) {
        return lnurlError("nostr zap not supported");
      }
      try {
        zap.validateRequest(params.nostr, params.amount);
      } catch (error) {
        return lnurlError(serverErrorText(error instanceof Error ? error.message : String(error)));
      }
    }
    if (
      (await store.countPendingInvoices(now(), user.pubkeyHex)) >= maxPendingPerUser ||
      (await store.countPendingInvoices(now())) >= maxPending
    ) {
      return lnurlError("too many pending invoices");
    }
    // NIP-57: the invoice commits to the zap request alone; otherwise to the metadata.
    const descriptionHash = sha256(utf8ToBytes(params.nostr ?? metadataOf(user)));
    let created;
    try {
      created = await client.lightning.createInvoice({
        amountSats: params.amount / 1000,
        descriptionHash,
        receiver: hexToBytes(user.pubkeyHex),
        expirySecs: invoiceExpirySecs,
      });
    } catch {
      return lnurlError("failed to create invoice");
    }
    const paymentHash = bytesToHex(created.paymentHash);
    await store.putInvoice({
      paymentHash,
      requestId: created.id,
      name: user.name,
      pubkeyHex: user.pubkeyHex,
      invoice: created.invoice,
      expiresAtMs: created.expiresAtMs,
      ...(params.nostr === undefined ? {} : { zapRequest: params.nostr }),
      ...(params.comment === undefined ? {} : { comment: params.comment }),
    });
    return result(200, {
      pr: created.invoice,
      routes: [],
      verify: `https://${domain}/lnurlp/verify/${paymentHash}`,
    });
  }

  async function verify(paymentHashHex: string): Promise<LightningAddressResult> {
    const hash = paymentHashHex.toLowerCase();
    const record = /^[0-9a-f]{64}$/u.test(hash)
      ? await store.invoiceByPaymentHash(hash)
      : undefined;
    if (record === undefined) {
      return lnurlError("Not found");
    }
    return result(200, {
      status: "OK",
      settled: record.preimageHex !== undefined,
      ...(record.preimageHex === undefined ? {} : { preimage: record.preimageHex }),
      pr: record.invoice,
    });
  }

  async function settleOne(
    record: LightningAddressInvoice,
  ): Promise<LightningAddressInvoice | undefined> {
    try {
      const status = await client.lightning.receiveStatus(record.requestId);
      const { preimage } = status;
      if (preimage === undefined) {
        return undefined;
      }
      if (!equalBytes(sha256(preimage), hexToBytes(record.paymentHash))) {
        return undefined;
      }
      return await store.settleInvoice(record.paymentHash, bytesToHex(preimage));
    } catch {
      // A failed read (or a failed store write) leaves the invoice pending for the next round.
      return undefined;
    } finally {
      // Fairness bookkeeping only — a failed mark just degrades the check order.
      await store.markChecked(record.paymentHash, now()).catch(() => undefined);
    }
  }

  async function settlePending(): Promise<ReadonlyArray<LightningAddressInvoice>> {
    const pending = await store.pendingInvoices(now(), settleBatch);
    const settled: LightningAddressInvoice[] = [];
    for (let start = 0; start < pending.length; start += SETTLE_CONCURRENCY) {
      const chunk = pending.slice(start, start + SETTLE_CONCURRENCY);
      // oxlint-disable-next-line no-await-in-loop -- chunks are sequential to bound concurrency
      const results = await Promise.all(chunk.map(settleOne));
      settled.push(
        ...results.filter((invoice): invoice is LightningAddressInvoice => invoice !== undefined),
      );
    }
    return settled;
  }

  return { register, unregister, payRequest, invoice, verify, settlePending };
}
