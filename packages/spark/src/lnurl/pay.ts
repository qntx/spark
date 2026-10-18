import { equalBytes } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { decodeBolt11 } from "../core/bolt11.ts";
import type { Bolt11Invoice } from "../core/bolt11.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SparkInputError, SparkRequestError } from "../errors/index.ts";
import { checkLnurlUrl } from "./codec.ts";
import { lnurlGetJson } from "./http.ts";
import type { JsonObject } from "./http.ts";
import { parseSuccessAction } from "./success-action.ts";
import type { LnurlSuccessAction } from "./success-action.ts";
import { parseLnurlUrl, withQuery } from "./url.ts";

// LUD-06 payRequest, with LUD-12 comments and NIP-57 (LUD-16 appendix) zaps.

function fail(message: string): never {
  throw new SparkInputError(`lnurl payRequest: ${message}`);
}

export type LnurlPayRequest = {
  readonly tag: "payRequest";
  /** Second-callback URL from the service. */
  readonly callback: string;
  readonly minSendableMsat: number;
  readonly maxSendableMsat: number;
  /** Raw metadata JSON string — hashed verbatim into the invoice's `h` field. */
  readonly metadata: string;
  /** The metadata's single `text/plain` entry (LUD-06, mandatory). */
  readonly description: string;
  /** Max comment characters the service accepts (LUD-12); 0 = unsupported. */
  readonly commentAllowed: number;
  /** NIP-57 zaps: the service accepts a signed `nostr` zap-request event. */
  readonly allowsNostr: boolean;
  /** 32-byte x-only nostr pubkey; present exactly when `allowsNostr`. */
  readonly nostrPubkey?: Uint8Array | undefined;
};

function asString(body: JsonObject, field: string): string {
  const { [field]: value } = body;
  if (typeof value !== "string") {
    fail(`${field} is not a string`);
  }
  return value;
}

function asMsat(body: JsonObject, field: string): number {
  const { [field]: value } = body;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail(`${field} is not a non-negative integer`);
  }
  return value;
}

/** LUD-06: every metadata entry is an array whose first item is the mime-like type. */
function asEntry(value: unknown): [string, unknown] {
  if (!Array.isArray(value) || value.length < 2 || typeof value[0] !== "string") {
    fail("metadata entries must be [type, value] arrays");
  }
  return [value[0], value[1]];
}

/** The metadata array's single mandatory `text/plain` string (LUD-06 step 3). */
function parseDescription(metadata: string): string {
  let entries: unknown;
  try {
    entries = JSON.parse(metadata);
  } catch (error) {
    throw new SparkInputError("lnurl payRequest: metadata is not valid JSON", { cause: error });
  }
  if (!Array.isArray(entries)) {
    fail("metadata is not an array");
  }
  let description: string | undefined;
  for (const raw of entries) {
    const [mime, content] = asEntry(raw);
    if (mime !== "text/plain") {
      continue;
    }
    if (typeof content !== "string") {
      fail("metadata text/plain value is not a string");
    }
    if (description !== undefined) {
      fail("metadata has more than one text/plain entry");
    }
    description = content;
  }
  if (description === undefined) {
    fail("metadata lacks a text/plain entry");
  }
  return description;
}

export function parseLnurlPayRequest(body: JsonObject): LnurlPayRequest {
  if (body["tag"] !== "payRequest") {
    fail("tag is not payRequest");
  }
  const callback = asString(body, "callback");
  try {
    checkLnurlUrl(callback);
  } catch (error) {
    throw new SparkInputError(
      "lnurl payRequest: callback must be a valid https or .onion http url",
      { cause: error },
    );
  }
  const minSendableMsat = asMsat(body, "minSendable");
  const maxSendableMsat = asMsat(body, "maxSendable");
  if (minSendableMsat === 0) {
    fail("minSendable is less than 1");
  }
  if (minSendableMsat > maxSendableMsat) {
    fail("minSendable exceeds maxSendable");
  }
  const metadata = asString(body, "metadata");
  const description = parseDescription(metadata);

  const commentAllowedRaw = body["commentAllowed"];
  let commentAllowed = 0;
  if (commentAllowedRaw !== undefined) {
    if (
      typeof commentAllowedRaw !== "number" ||
      !Number.isSafeInteger(commentAllowedRaw) ||
      commentAllowedRaw < 0
    ) {
      fail("commentAllowed is not a non-negative integer");
    }
    commentAllowed = commentAllowedRaw;
  }

  const allowsNostr = body["allowsNostr"] === true;
  let nostrPubkey: Uint8Array | undefined;
  if (allowsNostr) {
    const pubkey = body["nostrPubkey"];
    if (typeof pubkey !== "string" || !/^[0-9a-fA-F]{64}$/.test(pubkey)) {
      fail("allowsNostr without a 32-byte hex nostrPubkey");
    }
    nostrPubkey = hexToBytes(pubkey);
  }

  return {
    tag: "payRequest",
    callback,
    minSendableMsat,
    maxSendableMsat,
    metadata,
    description,
    commentAllowed,
    allowsNostr,
    nostrPubkey,
  };
}

export type LnurlInvoice = {
  /** The service's BOLT-11 payment request string. */
  readonly invoice: string;
  readonly decoded: Bolt11Invoice;
  readonly successAction?: LnurlSuccessAction | undefined;
};

/**
 * LUD-06 second callback: requests the invoice for `amountMsat`, then verifies it against the
 * request — exact amount, invoice network, and a `h` description-hash over the raw metadata (or
 * over the zap-request event alone for a nostr zap, NIP-57).
 */
export async function requestInvoice(
  request: LnurlPayRequest,
  options: {
    readonly fetch: typeof globalThis.fetch;
    readonly network: SparkNetwork;
    readonly amountMsat: number;
    readonly comment?: string;
    readonly zapRequest?: string;
  },
): Promise<LnurlInvoice> {
  const { amountMsat, comment, zapRequest } = options;
  if (
    !Number.isSafeInteger(amountMsat) ||
    amountMsat < request.minSendableMsat ||
    amountMsat > request.maxSendableMsat
  ) {
    fail("amount is outside the sendable bounds");
  }
  if (comment !== undefined) {
    if (request.commentAllowed === 0) {
      fail("comment: the service does not accept comments");
    }
    if (comment.length > request.commentAllowed) {
      fail("comment exceeds commentAllowed");
    }
  }
  if (zapRequest !== undefined && !request.allowsNostr) {
    fail("zapRequest: the service does not allow nostr zaps");
  }

  const params: Array<[string, string]> = [["amount", String(amountMsat)]];
  if (comment !== undefined) {
    params.push(["comment", comment]);
  }
  if (zapRequest !== undefined) {
    params.push(["nostr", zapRequest]);
  }

  const body = await lnurlGetJson(withQuery(request.callback, params), options.fetch);
  const { pr } = body;
  if (typeof pr !== "string") {
    fail("response pr is not a string");
  }
  const successAction =
    body["successAction"] === undefined
      ? undefined
      : parseSuccessAction(body["successAction"], parseLnurlUrl(request.callback).host);

  let decoded: Bolt11Invoice;
  try {
    decoded = decodeBolt11(pr);
  } catch (error) {
    throw new SparkRequestError("lnurl response: pr is not a valid BOLT-11 invoice", {
      code: "unexpected_response",
      cause: error,
    });
  }
  if (decoded.amountMsat !== BigInt(amountMsat)) {
    fail("invoice amount does not match the requested amount");
  }
  if (decoded.network !== options.network) {
    fail("invoice is for a different network");
  }
  if (decoded.descriptionHash === undefined) {
    fail("invoice lacks a description hash");
  }
  const expected = sha256(utf8ToBytes(zapRequest ?? request.metadata));
  if (!equalBytes(decoded.descriptionHash, expected)) {
    fail("invoice description hash does not match the metadata");
  }
  return { invoice: pr, decoded, successAction };
}
