import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { SparkInputError, SparkRequestError } from "../errors/index.ts";
import { lnurlGetJson } from "./http.ts";
import { formatLnurlUrl, parseLnurlUrl, queryParams, withQuery } from "./url.ts";
import type { LnurlUrlParts } from "./url.ts";

// LUD-04 (lnurl/luds 04.md): an LNURL whose query already carries
// `tag=login&k1=<64 hex>` is an auth challenge — the wallet must not GET it;
// it signs k1 with the domain's LUD-05 linking key and GETs the same URL with
// `sig=<hex DER>` and `key=<hex compressed pubkey>` appended.
// Upstream reference: breez-spark-sdk crates/breez-sdk/common/src/lnurl/
// auth.rs (validate_request, perform_lnurl_auth) @956ff90.

const K1_PATTERN = /^[0-9a-f]{64}$/;

function asAction(value: string): LnurlAuthAction | undefined {
  switch (value) {
    case "register":
    case "login":
    case "link":
    case "auth":
      return value;
    default:
      return undefined;
  }
}

export type LnurlAuthAction = "register" | "login" | "link" | "auth";

export type LnurlAuthRequest = {
  readonly tag: "login";
  /** The full service URL to GET in the second step, normalized. */
  readonly url: string;
  /** The 32-byte challenge, lowercase hex. */
  readonly k1: string;
  readonly action?: LnurlAuthAction | undefined;
  /** The service's lowercase hostname — shown to the user on login. */
  readonly domain: string;
};

/**
 * Parses an LNURL-auth URL (the decoded form of a `lnurl1…` string or a bare https/onion URL).
 * Requires `tag=login` and a 64-hex `k1` query parameter; `action` must be one of the LUD-04 enum
 * values when present.
 */
export function parseLnurlAuth(url: string): LnurlAuthRequest {
  let parts: LnurlUrlParts;
  try {
    parts = parseLnurlUrl(url);
  } catch (error) {
    throw new SparkInputError("lnurl auth: not a URL", { cause: error });
  }
  const params = queryParams(parts.query);
  if (params.get("tag") !== "login") {
    throw new SparkInputError("lnurl auth: expected tag=login");
  }
  const k1 = params.get("k1")?.toLowerCase();
  if (k1 === undefined || !K1_PATTERN.test(k1)) {
    throw new SparkInputError("lnurl auth: k1 must be 64 hex characters");
  }
  const actionText = params.get("action");
  const action = actionText === undefined ? undefined : asAction(actionText);
  if (actionText !== undefined && action === undefined) {
    throw new SparkInputError("lnurl auth: unsupported action");
  }
  return {
    tag: "login",
    url: formatLnurlUrl(parts),
    k1,
    ...(action === undefined ? {} : { action }),
    domain: parts.host,
  };
}

/**
 * The signing shape the auth flow needs — a structural subset of `LnurlAuthSigner` (the lnurl layer
 * must not import the signer implementation).
 */
export type LnurlAuthSigning = {
  readonly sign: (request: {
    readonly domain: string;
    readonly k1: Uint8Array;
  }) => Promise<{ readonly linkingKey: Uint8Array; readonly signature: Uint8Array }>;
};

/**
 * LUD-04 step 3: signs the `k1` challenge with the domain's linking key and GETs the service URL
 * with `sig` and `key` appended. The k1 challenge and the signature never appear in error
 * messages.
 */
export async function submitLnurlAuth(
  request: LnurlAuthRequest,
  options: { readonly fetch: typeof globalThis.fetch; readonly signer: LnurlAuthSigning },
): Promise<void> {
  const { linkingKey, signature } = await options.signer.sign({
    domain: request.domain,
    k1: hexToBytes(request.k1),
  });
  const body = await lnurlGetJson(
    withQuery(request.url, [
      ["sig", bytesToHex(signature)],
      ["key", bytesToHex(linkingKey)],
    ]),
    options.fetch,
  );
  if (body["status"] !== "OK") {
    throw new SparkRequestError("lnurl auth response: status is not OK", {
      code: "unexpected_response",
    });
  }
}
