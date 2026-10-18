import { SparkInputError, SparkRequestError } from "../errors/index.ts";
import { checkLnurlUrl } from "./codec.ts";
import { lnurlGetJson } from "./http.ts";
import type { JsonObject } from "./http.ts";
import { withQuery } from "./url.ts";

// LUD-03 withdrawRequest.

function fail(message: string): never {
  throw new SparkInputError(`lnurl withdrawRequest: ${message}`);
}

export type LnurlWithdrawRequest = {
  readonly tag: "withdrawRequest";
  /** Second-callback URL accepting `k1` and `pr` query params. */
  readonly callback: string;
  /** Ephemeral service challenge echoed back verbatim on the callback. */
  readonly k1: string;
  readonly defaultDescription: string;
  readonly minWithdrawableMsat: number;
  readonly maxWithdrawableMsat: number;
};

function asString(body: JsonObject, field: string, required: boolean): string {
  const { [field]: value } = body;
  if (typeof value !== "string") {
    if (!required && value === undefined) {
      return "";
    }
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

export function parseLnurlWithdrawRequest(body: JsonObject): LnurlWithdrawRequest {
  if (body["tag"] !== "withdrawRequest") {
    fail("tag is not withdrawRequest");
  }
  const callback = asString(body, "callback", true);
  try {
    checkLnurlUrl(callback);
  } catch (error) {
    throw new SparkInputError(
      "lnurl withdrawRequest: callback must be a valid https or .onion http url",
      { cause: error },
    );
  }
  const k1 = asString(body, "k1", true);
  if (k1 === "") {
    fail("k1 is empty");
  }
  const minWithdrawableMsat = asMsat(body, "minWithdrawable");
  const maxWithdrawableMsat = asMsat(body, "maxWithdrawable");
  if (minWithdrawableMsat > maxWithdrawableMsat) {
    fail("minWithdrawable exceeds maxWithdrawable");
  }
  return {
    tag: "withdrawRequest",
    callback,
    k1,
    defaultDescription: asString(body, "defaultDescription", false),
    minWithdrawableMsat,
    maxWithdrawableMsat,
  };
}

/**
 * LUD-03 step 5: submits the wallet's BOLT-11 `invoice` for payment. The service pays
 * asynchronously; a `{"status": "OK"}` body means it accepted — errors surface as
 * `SparkRequestError` (`lnurl_error` / `http_*`).
 */
export async function submitWithdraw(
  request: LnurlWithdrawRequest,
  options: { readonly fetch: typeof globalThis.fetch; readonly invoice: string },
): Promise<void> {
  const body = await lnurlGetJson(
    withQuery(request.callback, [
      ["k1", request.k1],
      ["pr", options.invoice],
    ]),
    options.fetch,
  );
  if (body["status"] !== "OK") {
    throw new SparkRequestError("lnurl withdraw response: status is not OK", {
      code: "unexpected_response",
    });
  }
}
