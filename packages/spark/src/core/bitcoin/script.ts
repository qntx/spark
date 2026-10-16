import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { Address, NETWORK, OutScript, p2tr, p2wpkh, TEST_NETWORK } from "@scure/btc-signer";
import type { BTC_NETWORK } from "@scure/btc-signer/utils.js";

import { SparkInputError } from "../../errors/index.ts";
import type { SparkNetwork } from "../network.ts";

// Taproot key tweaks, P2TR/P2WPKH scripts and addresses, and the ephemeral
// anchor output. Upstream references: signer/spark-frost/src/transaction.rs
// and sdks/js/packages/spark-sdk/src/utils/bitcoin.ts (buildonspark/spark@0b3a32a).

/** Ephemeral anchor (P2A): OP_TRUE, push 2 bytes, 0x4e73 — value 0 sats. */
export const EPHEMERAL_ANCHOR_SCRIPT: Uint8Array = new Uint8Array([0x51, 0x02, 0x4e, 0x73]);

export type BitcoinOutput = {
  readonly script: Uint8Array;
  readonly amountSats: number;
};

/** Maps a {@link SparkNetwork} onto btc-signer network parameters (`bc` / `bcrt`). */
export function btcNetwork(network: SparkNetwork): BTC_NETWORK {
  return network === "mainnet" ? NETWORK : { ...TEST_NETWORK, bech32: "bcrt" };
}

function assertCompressedPublicKey(publicKey: Uint8Array, field: string): void {
  if (publicKey.length !== 33) {
    throw new SparkInputError(`${field}: must be a 33-byte compressed public key`);
  }
  try {
    secp256k1.Point.fromBytes(publicKey);
  } catch (error) {
    throw new SparkInputError(`${field}: not a valid secp256k1 point`, { cause: error });
  }
}

/** The x-only (32-byte) form of a compressed public key, validated on-curve. */
export function xOnlyPublicKey(publicKey: Uint8Array): Uint8Array {
  assertCompressedPublicKey(publicKey, "publicKey");
  return secp256k1.Point.fromBytes(publicKey).toBytes(true).subarray(1);
}

/**
 * BIP-341 key tweak with no script tree: `Q = lift_x(P) + tagged_hash("TapTweak", P) * G`. Returns
 * the tweaked key as 33-byte compressed bytes.
 */
export function computeTaprootKeyNoScript(xOnlyKey: Uint8Array): Uint8Array {
  if (xOnlyKey.length !== 32) {
    throw new SparkInputError("xOnlyKey: must be a 32-byte x-only public key");
  }
  const tweakHash = schnorr.utils.taggedHash("TapTweak", xOnlyKey);
  const tweak = BigInt(`0x${bytesToHex(tweakHash)}`);
  try {
    return schnorr.utils
      .lift_x(BigInt(`0x${bytesToHex(xOnlyKey)}`))
      .add(secp256k1.Point.BASE.multiply(tweak))
      .toBytes(true);
  } catch (error) {
    throw new SparkInputError("xOnlyKey: cannot derive a taproot key", { cause: error });
  }
}

/** P2TR scriptPubKey for a 33-byte compressed public key (key-path only). */
export function p2trScriptFromPublicKey(publicKey: Uint8Array, network: SparkNetwork): Uint8Array {
  const { script } = p2tr(xOnlyPublicKey(publicKey), undefined, btcNetwork(network));
  if (script === undefined) {
    throw new SparkInputError("publicKey: cannot derive a P2TR script");
  }
  return script;
}

/** Bech32m P2TR address for a 33-byte compressed public key. */
export function p2trAddressFromPublicKey(publicKey: Uint8Array, network: SparkNetwork): string {
  const { address } = p2tr(xOnlyPublicKey(publicKey), undefined, btcNetwork(network));
  if (address === undefined) {
    throw new SparkInputError("publicKey: cannot derive a P2TR address");
  }
  return address;
}

/** Re-encodes a P2TR scriptPubKey (34 bytes, `5120…`) as a bech32m address. */
export function p2trAddressFromScript(pkScript: Uint8Array, network: SparkNetwork): string {
  if (pkScript.length !== 34 || pkScript[0] !== 0x51 || pkScript[1] !== 0x20) {
    throw new SparkInputError("pkScript: must be a 34-byte P2TR script (0x5120…)");
  }
  try {
    return Address(btcNetwork(network)).encode(OutScript.decode(pkScript));
  } catch (error) {
    throw new SparkInputError("pkScript: not a decodable output script", { cause: error });
  }
}

/** Bech32 P2WPKH address for a 33-byte compressed public key. */
export function p2wpkhAddressFromPublicKey(publicKey: Uint8Array, network: SparkNetwork): string {
  assertCompressedPublicKey(publicKey, "publicKey");
  const { address } = p2wpkh(publicKey, btcNetwork(network));
  if (address === undefined) {
    throw new SparkInputError("publicKey: cannot derive a P2WPKH address");
  }
  return address;
}

/** Zero-value ephemeral anchor output appended to CPFP transactions. */
export function ephemeralAnchorOutput(): BitcoinOutput {
  return { script: EPHEMERAL_ANCHOR_SCRIPT, amountSats: 0 };
}
