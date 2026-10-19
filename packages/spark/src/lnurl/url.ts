import { SparkInputError } from "../errors/index.ts";

// A strict URL parser for the LNURL layer. The WHATWG `URL` global cannot be
// used: React Native's polyfill (Libraries/Blob/URL.js) is a regex
// approximation that does not validate input and whose `searchParams`
// mutations never reach `href`, which would silently drop `amount`, `comment`
// and `nostr` from payRequest callbacks. Only the https/http + DNS/IPv4 shape
// LNURLs need is accepted — no userinfo, no IPv6 literals, no fragments kept.

export type LnurlUrlParts = {
  readonly scheme: "https" | "http";
  /** Lowercase hostname (DNS labels or IPv4 dotted quad). */
  readonly host: string;
  readonly port?: number | undefined;
  /** Always starts with `/`; `/` when absent. */
  readonly path: string;
  /** Without the leading `?`; "" when absent. Fragments are dropped. */
  readonly query: string;
};

function fail(message: string): never {
  throw new SparkInputError(`lnurl: ${message}`);
}

const URL_PATTERN = /^([a-zA-Z]+):\/\/([^/?#]*)(\/[^?#]*)?(?:\?([^#]*))?(?:#.*)?$/;
const HOST_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const STRICT_IPV4_LABEL = /^(0|[1-9][0-9]{0,2})$/;
// URLs containing control characters or whitespace are rejected outright.
// oxlint-disable-next-line no-control-regex -- control characters must be rejected
const FORBIDDEN = /[\u0000-\u0020\u007F]/;

function checkHost(authority: string): { host: string; port?: number } {
  if (authority.includes("@")) {
    fail("url must not contain userinfo");
  }
  let host = authority;
  let port: number | undefined;
  const colon = authority.lastIndexOf(":");
  if (colon !== -1) {
    host = authority.slice(0, colon);
    const portText = authority.slice(colon + 1);
    if (!/^[0-9]+$/.test(portText)) {
      fail("url has an invalid port");
    }
    port = Number(portText);
    if (port < 1 || port > 65_535) {
      fail("url port is out of range");
    }
  }
  const lower = host.toLowerCase();
  if (lower.length === 0) {
    fail("url has no host");
  }
  if (lower.length > 253) {
    fail("url host is too long");
  }
  const labels = lower.split(".");
  for (const label of labels) {
    if (!HOST_LABEL.test(label)) {
      fail("url host has an invalid label");
    }
  }
  checkIpv4(labels);
  return port === undefined ? { host: lower } : { host: lower, port };
}

// A label the WHATWG URL parser reads as an IPv4 number: decimal digits, a
// `0x`/`0X` hex value, or a `0`-prefixed octal value.
function isWhatwgIpv4Number(label: string): boolean {
  if (/^0[xX]/.test(label)) {
    return /^0[xX][0-9a-f]*$/.test(label);
  }
  if (label.startsWith("0") && label.length > 1) {
    return /^0[0-7]+$/.test(label);
  }
  return /^[0-9]+$/.test(label);
}

// Node's WHATWG URL parser treats the host as IPv4 whenever the last label is an
// IPv4 number; every other label must then parse as a number too (otherwise it
// stays a DNS name). This parser only knows the canonical dotted quad, so
// non-canonical IPv4 forms — `127.1`, `0x7f.0.0.1`, `2130706433`, `10.0x0.1`,
// `01.2.3.4` — must be rejected rather than passed to fetch for reinterpretation.
function checkIpv4(labels: ReadonlyArray<string>): void {
  const last = labels.at(-1) ?? "";
  if (!isWhatwgIpv4Number(last) || !labels.every(isWhatwgIpv4Number)) {
    return;
  }
  if (labels.length !== 4) {
    fail("url host has a non-canonical IPv4 form");
  }
  for (const label of labels) {
    if (!STRICT_IPV4_LABEL.test(label) || Number(label) > 255) {
      fail("url host has a non-canonical IPv4 form");
    }
  }
}

/**
 * Parses `text` into strict parts. Accepts `https`/`http` schemes only, a DNS hostname or IPv4
 * literal, an optional port, and a path/query; a `#fragment` is accepted and dropped. Everything
 * else throws {@link SparkInputError}.
 */
export function parseLnurlUrl(text: string): LnurlUrlParts {
  if (FORBIDDEN.test(text)) {
    fail("url contains whitespace or control characters");
  }
  const match = URL_PATTERN.exec(text);
  if (match === null) {
    fail("not a URL");
  }
  const schemeText = (match[1] ?? "").toLowerCase();
  if (schemeText !== "https" && schemeText !== "http") {
    fail("url scheme must be https or http");
  }
  const { host, port } = checkHost(match[2] ?? "");
  const path = match[3] ?? "/";
  const query = match[4] ?? "";
  return port === undefined
    ? { scheme: schemeText, host, path, query }
    : { scheme: schemeText, host, port, path, query };
}

/** `scheme://host[:port]path[?query]` — the canonical string form. */
export function formatLnurlUrl(parts: LnurlUrlParts): string {
  const port = parts.port === undefined ? "" : `:${parts.port}`;
  const query = parts.query === "" ? "" : `?${parts.query}`;
  return `${parts.scheme}://${parts.host}${port}${parts.path}${query}`;
}

function decodeQueryComponent(text: string): string {
  // application/x-www-form-urlencoded: '+' decodes to a space.
  const spaced = text.replaceAll("+", " ");
  try {
    return decodeURIComponent(spaced);
  } catch (error) {
    throw new SparkInputError("lnurl url: malformed query escape", { cause: error });
  }
}

/**
 * Parses a `application/x-www-form-urlencoded` query string (without the leading `?`) into a
 * name→value map. Bare `name` pairs (no `=`) decode to ""; the last duplicate wins.
 */
export function queryParams(query: string): Map<string, string> {
  const params = new Map<string, string>();
  if (query === "") {
    return params;
  }
  for (const pair of query.split("&")) {
    const eq = pair.indexOf("=");
    const name = eq === -1 ? pair : pair.slice(0, eq);
    const value = eq === -1 ? "" : pair.slice(eq + 1);
    params.set(decodeQueryComponent(name), decodeQueryComponent(value));
  }
  return params;
}

/**
 * Appends `encodeURIComponent`-encoded `name=value` pairs to a URL's query, preserving existing
 * pairs and dropping any fragment.
 */
export function withQuery(url: string, params: ReadonlyArray<readonly [string, string]>): string {
  const parts = parseLnurlUrl(url);
  const encoded = params.map(
    ([name, value]) => `${encodeURIComponent(name)}=${encodeURIComponent(value)}`,
  );
  const query = parts.query === "" ? encoded.join("&") : `${parts.query}&${encoded.join("&")}`;
  return formatLnurlUrl({ ...parts, query });
}
