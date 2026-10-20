import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { SparkInputError } from "../errors/index.ts";

// Canonical messages the identity key signs to authorize a Lightning Address
// server request, ported from Breez crates/breez-sdk/lnurl-models/src/
// signed_message.rs @956ff90 — both sides build the exact same bytes, so the
// golden vectors in vectors/lightning-address.json are the wire spec.
//
// A message names the version, the route, the domain it applies to, and the
// request it authorizes, joined by LF. Field order is fixed and messages are
// only ever compared, never parsed, so the sole hazard is two field tuples
// colliding: the domain and username rules below forbid LF, the description
// enters hashed, and the timestamp is digits.

const VERSION = "breez-lnurl:v2";

/**
 * How far a statement's `timestamp` may sit from the verifier's clock, in either direction, in
 * seconds. The server refuses a message outside this window; it also sets how long a spent
 * statement's claim is retained.
 */
export const LIGHTNING_ADDRESS_VALIDITY_SECS = 600;

/** Longest description a registration may carry (the server rejects longer). */
export const LIGHTNING_ADDRESS_MAX_DESCRIPTION_LENGTH = 512;

/**
 * LUD-16 strict username rule: lowercase alphanumerics plus `-`, `_`, `.` and `+`, 1–64 characters.
 * Callers lowercase before validating — uppercase is an error, never silently folded.
 */
// oxlint-disable-next-line no-inferrable-types -- isolatedDeclarations requires it
export const LIGHTNING_ADDRESS_USERNAME_PATTERN: RegExp = /^[a-z0-9\-_.+]{1,64}$/u;

const HOST_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/u;

/** The statement shape `SparkSigner.signIdentity` accepts for Lightning Address requests. */
export type LightningAddressStatement =
  | {
      readonly kind: "lightning-address";
      readonly action: "register";
      readonly domain: string;
      readonly username: string;
      readonly description: string;
      readonly timestamp: number;
    }
  | {
      readonly kind: "lightning-address";
      readonly action: "unregister";
      readonly domain: string;
      readonly username: string;
      readonly timestamp: number;
    };

function fail(message: string): never {
  throw new SparkInputError(`lightning address: ${message}`);
}

/** A registration name: LUD-16 local-part, already lowercase. */
export function checkLightningAddressUsername(username: string): void {
  if (!LIGHTNING_ADDRESS_USERNAME_PATTERN.test(username)) {
    fail("invalid username");
  }
}

/**
 * The domain a message binds to: non-empty lowercase host labels. The check must forbid LF — an LF
 * in the domain would let one tuple read as another.
 */
export function checkLightningAddressDomain(domain: string): void {
  if (domain.length === 0 || domain.length > 253) {
    fail("invalid domain");
  }
  for (const label of domain.split(".")) {
    if (!HOST_LABEL.test(label)) {
      fail("invalid domain");
    }
  }
}

function checkTimestamp(timestamp: number): void {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    fail("invalid timestamp");
  }
}

/** `sha256` of the exact description bytes, lowercase hex — the description enters hashed. */
export function lightningAddressDescriptionHash(description: string): string {
  return bytesToHex(sha256(utf8ToBytes(description)));
}

/**
 * `POST /lnurlpay/{pubkey}`: the message claiming `username` on `domain`, fields joined by LF:
 * `breez-lnurl:v2` ‖ `register` ‖ domain ‖ username ‖ sha256(description) ‖ timestamp.
 */
export function lightningAddressRegisterMessage(
  domain: string,
  username: string,
  description: string,
  timestamp: number,
): string {
  checkLightningAddressDomain(domain);
  checkLightningAddressUsername(username);
  checkTimestamp(timestamp);
  return [
    VERSION,
    "register",
    domain,
    username,
    lightningAddressDescriptionHash(description),
    String(timestamp),
  ].join("\n");
}

/**
 * `DELETE /lnurlpay/{pubkey}`: the message giving up `username` on `domain`: `breez-lnurl:v2` ‖
 * `unregister` ‖ domain ‖ username ‖ timestamp.
 */
export function lightningAddressUnregisterMessage(
  domain: string,
  username: string,
  timestamp: number,
): string {
  checkLightningAddressDomain(domain);
  checkLightningAddressUsername(username);
  checkTimestamp(timestamp);
  return [VERSION, "unregister", domain, username, String(timestamp)].join("\n");
}

/** Builds the canonical message a {@link LightningAddressStatement} signs, after validation. */
export function lightningAddressMessage(statement: LightningAddressStatement): string {
  if (statement.action === "register") {
    return lightningAddressRegisterMessage(
      statement.domain,
      statement.username,
      statement.description,
      statement.timestamp,
    );
  }
  return lightningAddressUnregisterMessage(
    statement.domain,
    statement.username,
    statement.timestamp,
  );
}

/** `sha256(message)` — the digest the identity key signs and the server verifies. */
export function lightningAddressMessageDigest(message: string): Uint8Array {
  return sha256(utf8ToBytes(message));
}

/**
 * The replay-protection claim key: `sha256(pubkeyHex ‖ 0x00 ‖ message)`. The pubkey is the
 * lowercase compressed-hex string; the 0x00 separator keeps the pubkey/message boundary unambiguous
 * (Breez `statement_hash`).
 */
export function lightningAddressStatementHash(pubkeyHex: string, message: string): string {
  return bytesToHex(
    sha256(concatBytes(utf8ToBytes(pubkeyHex), Uint8Array.of(0), utf8ToBytes(message))),
  );
}

/**
 * Whether a statement `timestamp` (seconds) is inside the accept window around `nowSecs`, bounded
 * symmetrically so a device whose clock runs fast still works.
 */
export function lightningAddressTimestampFresh(timestamp: number, nowSecs: number): boolean {
  return (
    Number.isSafeInteger(timestamp) &&
    timestamp >= 0 &&
    Math.abs(timestamp - nowSecs) <= LIGHTNING_ADDRESS_VALIDITY_SECS
  );
}
