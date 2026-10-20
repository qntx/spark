import { utf8ToBytes } from "@noble/hashes/utils.js";

import { serverErrorText } from "../core/text.ts";
import { SparkRequestError } from "../errors/index.ts";

export type JsonObject = Record<string, unknown>;

export function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** LNURL responses are small JSON documents; a larger body is a hostile or broken endpoint. */
export const MAX_LNURL_RESPONSE_BYTES: number = 256 * 1024;

/** Whole-round-trip bound for every LNURL request — request and body read. */
export const LNURL_REQUEST_TIMEOUT_MS = 30_000;

function timedOut(): SparkRequestError {
  return new SparkRequestError("lnurl request timed out", { code: "deadline_exceeded" });
}

function tooLarge(): SparkRequestError {
  return new SparkRequestError("lnurl response: body exceeds 256 KiB", {
    code: "unexpected_response",
  });
}

/**
 * Rejects before reading when a truthful `Content-Length` already exceeds the bound. A missing (or
 * lying) header cannot be trusted, so the caller still reads the body once and re-checks it against
 * the same bound afterwards.
 */
function checkContentLength(response: Response): void {
  const declared = Number(response.headers.get("content-length") ?? "");
  if (Number.isSafeInteger(declared) && declared > MAX_LNURL_RESPONSE_BYTES) {
    throw tooLarge();
  }
}

function checkBodySize(text: string): void {
  if (utf8ToBytes(text).length > MAX_LNURL_RESPONSE_BYTES) {
    throw tooLarge();
  }
}

/**
 * One GET against an LNURL endpoint with the injected fetch. HTTP failures and the protocol-level
 * `{"status": "ERROR", "reason"}` envelope map onto the SSP client's error vocabulary; error
 * messages never echo request URLs — withdraw callbacks carry the ephemeral `k1`, which authorizes
 * a payout.
 */
export async function lnurlGetJson(
  url: string,
  fetch: typeof globalThis.fetch,
): Promise<JsonObject> {
  // AbortController + setTimeout is the Hermes-safe way to bound the whole round trip —
  // request and body read — without an injected timer.
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), LNURL_REQUEST_TIMEOUT_MS);
  try {
    let response: Response;
    try {
      response = await fetch(url, { signal: timeout.signal });
    } catch (error) {
      if (timeout.signal.aborted) {
        throw timedOut();
      }
      throw new SparkRequestError("lnurl request failed", { cause: error });
    }
    if (!response.ok) {
      throw new SparkRequestError(`lnurl request failed with status ${response.status}`, {
        code: `http_${response.status}`,
      });
    }
    checkContentLength(response);
    let text: string;
    try {
      // Without a trustworthy Content-Length the body is still read once, then size-checked.
      text = await response.text();
    } catch (error) {
      if (timeout.signal.aborted) {
        throw timedOut();
      }
      throw new SparkRequestError("lnurl request failed", { cause: error });
    }
    checkBodySize(text);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (error) {
      throw new SparkRequestError("lnurl response: body is not valid JSON", {
        code: "unexpected_response",
        cause: error,
      });
    }
    if (!isJsonObject(parsed)) {
      throw new SparkRequestError("lnurl response: body is not an object", {
        code: "unexpected_response",
      });
    }
    if (parsed["status"] === "ERROR") {
      const { reason } = parsed;
      throw new SparkRequestError(
        `lnurl error: ${typeof reason === "string" ? serverErrorText(reason) : "no reason given"}`,
        { code: "lnurl_error" },
      );
    }
    return parsed;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * One JSON request with a body (POST/DELETE) against an LNURL endpoint. Same error vocabulary as
 * {@link lnurlGetJson}; a 2xx response with an empty body returns `undefined`, and request bodies
 * never echo into error messages — the server's response text is sanitized before it is embedded.
 */
export async function lnurlSendJson(
  url: string,
  fetch: typeof globalThis.fetch,
  options: {
    readonly method: string;
    readonly body: JsonObject;
    /** Whole-round-trip bound; defaults to {@link LNURL_REQUEST_TIMEOUT_MS}. */
    readonly timeoutMs?: number;
  },
): Promise<JsonObject | undefined> {
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), options.timeoutMs ?? LNURL_REQUEST_TIMEOUT_MS);
  try {
    let response: Response;
    try {
      response = await fetch(url, {
        method: options.method,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(options.body),
        signal: timeout.signal,
      });
    } catch (error) {
      if (timeout.signal.aborted) {
        throw timedOut();
      }
      throw new SparkRequestError("lnurl request failed", { cause: error });
    }
    checkContentLength(response);
    const text = await response.text().catch(() => "");
    if (timeout.signal.aborted) {
      throw timedOut();
    }
    checkBodySize(text);
    if (!response.ok) {
      const detail = serverErrorText(text);
      throw new SparkRequestError(
        `lnurl request failed with status ${response.status}${detail === "" ? "" : `: ${detail}`}`,
        { code: `http_${response.status}` },
      );
    }
    if (text === "") {
      return undefined;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (error) {
      throw new SparkRequestError("lnurl response: body is not valid JSON", {
        code: "unexpected_response",
        cause: error,
      });
    }
    if (!isJsonObject(parsed)) {
      throw new SparkRequestError("lnurl response: body is not an object", {
        code: "unexpected_response",
      });
    }
    if (parsed["status"] === "ERROR") {
      const { reason } = parsed;
      throw new SparkRequestError(
        `lnurl error: ${typeof reason === "string" ? serverErrorText(reason) : "no reason given"}`,
        { code: "lnurl_error" },
      );
    }
    return parsed;
  } finally {
    clearTimeout(timer);
  }
}
