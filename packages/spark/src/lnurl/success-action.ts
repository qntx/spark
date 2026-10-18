import { SparkInputError } from "../errors/index.ts";
import { isJsonObject } from "./http.ts";
import type { JsonObject } from "./http.ts";
import { parseLnurlUrl } from "./url.ts";

// LUD-09 successAction parsing; `aes` is LUD-10.

function fail(message: string): never {
  throw new SparkInputError(`lnurl successAction: ${message}`);
}

export type LnurlSuccessAction =
  | { readonly tag: "message"; readonly message: string }
  | { readonly tag: "url"; readonly description: string; readonly url: string }
  /**
   * LUD-10 `aes`: ciphertext/iv are base64 and stay encrypted here — decryption needs the payment
   * preimage, available only after the lightning send settles.
   */
  | {
      readonly tag: "aes";
      readonly description: string;
      readonly ciphertext: string;
      readonly iv: string;
    };

function asString(action: JsonObject, field: string): string {
  const { [field]: value } = action;
  if (typeof value !== "string") {
    fail(`${field} is not a string`);
  }
  return value;
}

/**
 * Parses a `successAction` object (LUD-09). `callbackHost` is the payRequest callback's hostname:
 * `url` actions must stay on that domain. Unknown tags are rejected — a wallet that cannot show the
 * action must not proceed (LUD-09).
 */
export function parseSuccessAction(value: unknown, callbackHost: string): LnurlSuccessAction {
  if (!isJsonObject(value)) {
    fail("not an object");
  }
  switch (value["tag"]) {
    case "message": {
      const message = asString(value, "message");
      if (message.length > 144) {
        fail("message exceeds 144 characters");
      }
      return { tag: "message", message };
    }
    case "url": {
      const description = asString(value, "description");
      if (description.length > 144) {
        fail("description exceeds 144 characters");
      }
      const url = asString(value, "url");
      let host: string;
      try {
        ({ host } = parseLnurlUrl(url));
      } catch (error) {
        throw new SparkInputError("lnurl successAction: url is not a URL", { cause: error });
      }
      if (host !== callbackHost) {
        fail("url domain does not match the callback domain");
      }
      return { tag: "url", description, url };
    }
    case "aes":
      return {
        tag: "aes",
        description: asString(value, "description"),
        ciphertext: asString(value, "ciphertext"),
        iv: asString(value, "iv"),
      };
    default:
      return fail("unknown tag");
  }
}
