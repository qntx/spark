import { bytesToHex } from "@noble/hashes/utils.js";

import type { LightningAddressStatement } from "../core/lightning-address.ts";
import { SparkRequestError } from "../errors/index.ts";
import { checkLnurlUrl } from "./codec.ts";
import { lnurlSendJson } from "./http.ts";
import { formatLnurlUrl, parseLnurlUrl } from "./url.ts";

// Registering and unregistering a Lightning Address on a Breez-style LNURL
// server: `POST/DELETE {serverUrl}/lnurlpay/{pubkey}` with a signed
// `breez-lnurl:v2` statement (core/lightning-address.ts). Upstream reference:
// Breez crates/breez-sdk/lnurl/src/routes.rs (register, unregister) @956ff90.

/**
 * The signing shape the registration helpers need — a structural subset of `SparkSigner` (the lnurl
 * layer must not import the signer implementation).
 */
export type LightningAddressSigning = {
  readonly identityPublicKey: () => Promise<Uint8Array>;
  readonly signIdentity: (statement: LightningAddressStatement) => Promise<Uint8Array>;
};

export type RegisterLightningAddressBody = {
  readonly username: string;
  readonly signature: string;
  readonly timestamp: number;
  readonly description: string;
};

export type UnregisterLightningAddressBody = {
  readonly username: string;
  readonly signature: string;
  readonly timestamp: number;
};

export type LightningAddressRegistration = {
  readonly lnurl: string;
  readonly lightningAddress: string;
};

/**
 * Builds the register request body the signed statement commits to — lowercased domain and
 * username, fresh timestamp — and signs it. Split from {@link registerLightningAddress} so the same
 * bytes can be handed to a server handler in tests without HTTP.
 */
export async function lightningAddressRegisterBody(options: {
  readonly domain: string;
  readonly username: string;
  readonly description: string;
  readonly signer: LightningAddressSigning;
  readonly now?: (() => number) | undefined;
}): Promise<{ readonly pubkeyHex: string; readonly body: RegisterLightningAddressBody }> {
  const statement: LightningAddressStatement = {
    kind: "lightning-address",
    action: "register",
    domain: options.domain.toLowerCase(),
    username: options.username.toLowerCase(),
    description: options.description,
    timestamp: Math.floor((options.now ?? Date.now)() / 1000),
  };
  const signature = await options.signer.signIdentity(statement);
  const pubkeyHex = bytesToHex(await options.signer.identityPublicKey());
  return {
    pubkeyHex,
    body: {
      username: statement.username,
      signature: bytesToHex(signature),
      timestamp: statement.timestamp,
      description: options.description,
    },
  };
}

/** The unregister counterpart of {@link lightningAddressRegisterBody}. */
export async function lightningAddressUnregisterBody(options: {
  readonly domain: string;
  readonly username: string;
  readonly signer: LightningAddressSigning;
  readonly now?: (() => number) | undefined;
}): Promise<{ readonly pubkeyHex: string; readonly body: UnregisterLightningAddressBody }> {
  const statement: LightningAddressStatement = {
    kind: "lightning-address",
    action: "unregister",
    domain: options.domain.toLowerCase(),
    username: options.username.toLowerCase(),
    timestamp: Math.floor((options.now ?? Date.now)() / 1000),
  };
  const signature = await options.signer.signIdentity(statement);
  const pubkeyHex = bytesToHex(await options.signer.identityPublicKey());
  return {
    pubkeyHex,
    body: {
      username: statement.username,
      signature: bytesToHex(signature),
      timestamp: statement.timestamp,
    },
  };
}

function lnurlpayUrl(serverUrl: string, pubkeyHex: string): string {
  checkLnurlUrl(serverUrl);
  const base = formatLnurlUrl(parseLnurlUrl(serverUrl));
  return `${base.endsWith("/") ? base.slice(0, -1) : base}/lnurlpay/${pubkeyHex}`;
}

/**
 * Claims `username` on the Lightning Address server at `serverUrl`: signs the register statement
 * and POSTs it to `/lnurlpay/{pubkey}`. `serverUrl` must be https or an `.onion` http URL.
 */
export async function registerLightningAddress(options: {
  readonly fetch: typeof globalThis.fetch;
  readonly serverUrl: string;
  readonly domain: string;
  readonly username: string;
  readonly description: string;
  readonly signer: LightningAddressSigning;
  readonly now?: (() => number) | undefined;
}): Promise<LightningAddressRegistration> {
  const { pubkeyHex, body } = await lightningAddressRegisterBody(options);
  const response = await lnurlSendJson(lnurlpayUrl(options.serverUrl, pubkeyHex), options.fetch, {
    method: "POST",
    body,
  });
  const lnurl = response?.["lnurl"];
  const lightningAddress = response?.["lightning_address"];
  if (typeof lnurl !== "string" || typeof lightningAddress !== "string") {
    throw new SparkRequestError("lnurl register response: missing lnurl or lightning_address", {
      code: "unexpected_response",
    });
  }
  return { lnurl, lightningAddress };
}

/**
 * Gives up `username` on the server: signs the unregister statement and DELETEs
 * `/lnurlpay/{pubkey}`.
 */
export async function unregisterLightningAddress(options: {
  readonly fetch: typeof globalThis.fetch;
  readonly serverUrl: string;
  readonly domain: string;
  readonly username: string;
  readonly signer: LightningAddressSigning;
  readonly now?: (() => number) | undefined;
}): Promise<void> {
  const { pubkeyHex, body } = await lightningAddressUnregisterBody(options);
  await lnurlSendJson(lnurlpayUrl(options.serverUrl, pubkeyHex), options.fetch, {
    method: "DELETE",
    body,
  });
}
