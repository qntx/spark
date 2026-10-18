import { SparkInputError } from "../errors/index.ts";
import { parseLnurlAuth } from "./auth.ts";
import type { LnurlAuthRequest } from "./auth.ts";
import { checkLnurlUrl, decodeLnurl, lightningAddressUrl } from "./codec.ts";
import { lnurlGetJson } from "./http.ts";
import { parseLnurlPayRequest } from "./pay.ts";
import type { LnurlPayRequest } from "./pay.ts";
import { parseLnurlUrl, queryParams } from "./url.ts";
import { parseLnurlWithdrawRequest } from "./withdraw.ts";
import type { LnurlWithdrawRequest } from "./withdraw.ts";

export type LnurlResolved = LnurlPayRequest | LnurlWithdrawRequest | LnurlAuthRequest;

/**
 * Resolves an `lnurl1…` string, a lightning address (`user@domain`, LUD-16) or a bare https/onion
 * URL into a typed LNURL service request. A `tag=login` query is a LUD-04 auth challenge carried
 * inside the LNURL itself and returns without fetching; otherwise the endpoint is fetched and only
 * the interactive `payRequest` (LUD-06) and `withdrawRequest` (LUD-03) tags are supported.
 */
export async function resolveLnurl(
  input: string,
  options: { readonly fetch: typeof globalThis.fetch },
): Promise<LnurlResolved> {
  const url = resolveUrl(input);
  if (queryParams(parseLnurlUrl(url).query).get("tag") === "login") {
    return parseLnurlAuth(url);
  }
  const body = await lnurlGetJson(url, options.fetch);
  switch (body["tag"]) {
    case "payRequest":
      return parseLnurlPayRequest(body);
    case "withdrawRequest":
      return parseLnurlWithdrawRequest(body);
    default:
      throw new SparkInputError(`lnurl: unsupported tag ${JSON.stringify(body["tag"] ?? null)}`);
  }
}

function resolveUrl(input: string): string {
  const lower = input.toLowerCase();
  if (lower.startsWith("lnurl1") || lower.startsWith("lightning:")) {
    return decodeLnurl(input);
  }
  if (input.includes("@")) {
    return lightningAddressUrl(input);
  }
  let url: string;
  try {
    checkLnurlUrl(input);
    url = input;
  } catch (error) {
    throw new SparkInputError("lnurl: not an lnurl, lightning address, or URL", {
      cause: error,
    });
  }
  return url;
}
