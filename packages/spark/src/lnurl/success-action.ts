import { cbc } from "@noble/ciphers/aes.js";
import { base64 } from "@scure/base";

import { SparkInputError } from "../errors/index.ts";
import { isJsonObject } from "./http.ts";
import type { JsonObject } from "./http.ts";
import { parseLnurlUrl } from "./url.ts";

// LUD-09 successAction parsing; `aes` is LUD-10.

/** LUD-10 caps the base64-decoded ciphertext at 4 KiB. */
const AES_CIPHERTEXT_MAX_BYTES = 4 * 1024;

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

/**
 * LUD-10: decrypts an `aes` successAction with the payment preimage — AES-256-CBC, the preimage is
 * the key, `iv` is base64 of 16 bytes, `ciphertext` base64 of at most 4 KiB, PKCS#7 padding, UTF-8
 * plaintext.
 */
export function decryptSuccessAction(
  action: Extract<LnurlSuccessAction, { readonly tag: "aes" }>,
  preimage: Uint8Array,
): string {
  if (preimage.length !== 32) {
    fail("preimage must be 32 bytes");
  }
  let iv: Uint8Array;
  let ciphertext: Uint8Array;
  try {
    iv = base64.decode(action.iv);
    ciphertext = base64.decode(action.ciphertext);
  } catch (error) {
    throw new SparkInputError("lnurl successAction: aes fields are not base64", {
      cause: error,
    });
  }
  if (iv.length !== 16) {
    fail("iv is not 16 bytes");
  }
  if (ciphertext.length === 0 || ciphertext.length > AES_CIPHERTEXT_MAX_BYTES) {
    fail("ciphertext exceeds 4 KiB");
  }
  let plaintext: Uint8Array;
  try {
    plaintext = cbc(preimage, iv).decrypt(ciphertext);
  } catch (error) {
    throw new SparkInputError("lnurl successAction: aes decryption failed", { cause: error });
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  } catch (error) {
    throw new SparkInputError("lnurl successAction: aes plaintext is not UTF-8", {
      cause: error,
    });
  }
}
