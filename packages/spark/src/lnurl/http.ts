import { serverErrorText } from "../core/text.ts";
import { SparkRequestError } from "../errors/index.ts";

export type JsonObject = Record<string, unknown>;

export function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
  let response: Response;
  try {
    response = await fetch(url);
  } catch (error) {
    throw new SparkRequestError("lnurl request failed", { cause: error });
  }
  if (!response.ok) {
    throw new SparkRequestError(`lnurl request failed with status ${response.status}`, {
      code: `http_${response.status}`,
    });
  }
  let parsed: unknown;
  try {
    parsed = await response.json();
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
}
