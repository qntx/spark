import { utf8ToBytes } from "@noble/hashes/utils.js";
import { bech32 } from "@scure/base";

import { SparkInputError } from "../errors/index.ts";
import { formatLnurlUrl, parseLnurlUrl } from "./url.ts";

// LUD-01 base encoding: bech32 (NOT bech32m) with the hrp "lnurl" and the
// BIP-0173 length limit removed — real LNURLs far exceed 90 characters.

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

function fail(message: string, options?: ErrorOptions): never {
  throw new SparkInputError(`lnurl: ${message}`, options);
}

/** LUD-01 §HTTPS or Onion: clearnet https, or http only for a `.onion` host. */
export function checkLnurlUrl(url: string): void {
  const parts = parseLnurlUrl(url);
  if (parts.scheme === "https") {
    return;
  }
  if (parts.scheme === "http" && parts.host.endsWith(".onion")) {
    return;
  }
  fail("url must be https, or http to an .onion host");
}

/**
 * Decodes a bech32 `lnurl1…` string into the normalized URL it wraps (LUD-01). Accepts upper- or
 * lowercase (never mixed) and an optional `lightning:` scheme prefix.
 */
export function decodeLnurl(text: string): string {
  const raw = text.toLowerCase().startsWith("lightning:") ? text.slice("lightning:".length) : text;
  if (/[a-z]/.test(raw) && /[A-Z]/.test(raw)) {
    fail("mixed case");
  }
  let decoded;
  try {
    decoded = bech32.decodeToBytes(raw.toLowerCase(), false);
  } catch (error) {
    throw new SparkInputError("lnurl: invalid bech32", { cause: error });
  }
  if (decoded.prefix !== "lnurl") {
    fail("prefix: expected 'lnurl'");
  }
  let url: string;
  try {
    url = UTF8_DECODER.decode(decoded.bytes);
  } catch (error) {
    throw new SparkInputError("lnurl: payload is not UTF-8", { cause: error });
  }
  checkLnurlUrl(url);
  return formatLnurlUrl(parseLnurlUrl(url));
}

/** Bech32-encodes an https/onion URL into a lowercase `lnurl1…` string (LUD-01). */
export function encodeLnurl(url: string): string {
  checkLnurlUrl(url);
  return bech32.encode(
    "lnurl",
    bech32.toWords(utf8ToBytes(formatLnurlUrl(parseLnurlUrl(url)))),
    false,
  );
}

const USERNAME_PATTERN = /^[a-z0-9._+-]+$/;

/**
 * LUD-16 `<username>@<domain>` → the well-known pay endpoint. `@<domain>` resolves to the default
 * identifier `_`. An `.onion` domain yields http, a clearnet domain https. Usernames are lowercased
 * and must match `a-z0-9-_.` plus `+` for service tags; ports, userinfo and paths are rejected.
 */
export function lightningAddressUrl(address: string): string {
  const lower = address.toLowerCase();
  const at = lower.lastIndexOf("@");
  if (at === -1) {
    fail("lightning address: expected <username>@<domain>");
  }
  const username = lower.slice(0, at) || "_";
  const domain = lower.slice(at + 1);
  if (!USERNAME_PATTERN.test(username)) {
    fail("lightning address: invalid username");
  }
  if (domain === "") {
    fail("lightning address: missing domain");
  }
  let host: string;
  try {
    const parts = parseLnurlUrl(`https://${domain}`);
    if (parts.port !== undefined || parts.path !== "/") {
      fail("lightning address: domain must be a bare hostname");
    }
    ({ host } = parts);
  } catch (error) {
    throw new SparkInputError("lnurl: lightning address: invalid domain", { cause: error });
  }
  const scheme = host.endsWith(".onion") ? "http" : "https";
  return `${scheme}://${host}/.well-known/lnurlp/${username}`;
}
