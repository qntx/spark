import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

import { SparkInputError } from "../../errors/index.ts";
import { requireLength } from "../assert.ts";
import { uint32be, uint64be } from "../bytes.ts";
import { INVOICE_VERSION } from "../invoice.ts";
import type { SparkInvoiceFields } from "../invoice.ts";
import type { SparkNetwork } from "../network.ts";
import { uuidToBytes } from "../uuid.ts";

// Upstream references: sdks/js/packages/spark-sdk/src/utils/invoice-hashing.ts
// and signer/spark-token-primitives/src/invoice.rs (buildonspark/spark@0b3a32a).
// HashSparkInvoiceV1 is a field-wise SHA-256 construction (not protohash):
// each field is hashed individually and the 32-byte digests are concatenated
// in a fixed order, then hashed once more.

const PUBLIC_KEY_LENGTH = 33;
const TOKEN_IDENTIFIER_LENGTH = 32;
const MAX_TOKEN_AMOUNT_BYTES = 16;

function networkMagic(network: SparkNetwork): number {
  if (network === "mainnet") {
    return 0xd9b4bef9;
  }
  if (network === "regtest") {
    return 0xdab5bffa;
  }
  throw new SparkInputError("invoice network: must be 'mainnet' or 'regtest'");
}

function hashNetworkMagic(network: SparkNetwork): Uint8Array {
  return sha256(sha256(uint32be(networkMagic(network))));
}

/**
 * The deterministic digest a Spark invoice signature covers: SHA-256 over the per-field hashes of
 * version, id, network magic, receiver public key, the payment discriminator and contents, memo,
 * sender public key and expiry seconds. Fields are optional at the protobuf level but have fixed
 * defaults here (zero-filled keys, zero amounts, empty memo).
 */
export function hashSparkInvoice(
  invoice: SparkInvoiceFields,
  receiverPublicKey: Uint8Array,
  network: SparkNetwork,
): Uint8Array {
  if (invoice.version !== INVOICE_VERSION) {
    throw new SparkInputError(`invoice.version: must be ${INVOICE_VERSION}`);
  }
  requireLength(receiverPublicKey, PUBLIC_KEY_LENGTH, "receiver public key");

  const allHashes: Uint8Array[] = [
    sha256(uint32be(invoice.version)),
    sha256(uuidToBytes(invoice.id)),
    hashNetworkMagic(network),
    sha256(receiverPublicKey),
  ];

  const { payment } = invoice;
  if (payment === undefined) {
    throw new SparkInputError("invoice.payment: missing payment type");
  }
  switch (payment.type) {
    case "tokens": {
      allHashes.push(sha256(new Uint8Array([1])));
      const { tokenIdentifier } = payment;
      if (tokenIdentifier === undefined || tokenIdentifier.length === 0) {
        allHashes.push(sha256(new Uint8Array(TOKEN_IDENTIFIER_LENGTH)));
      } else {
        if (tokenIdentifier.length !== TOKEN_IDENTIFIER_LENGTH) {
          throw new SparkInputError("invoice token identifier must be exactly 32 bytes");
        }
        allHashes.push(sha256(tokenIdentifier));
      }
      const { amount } = payment;
      if (amount !== undefined && amount.length > MAX_TOKEN_AMOUNT_BYTES) {
        throw new SparkInputError("invoice token amount exceeds 16 bytes");
      }
      allHashes.push(sha256(amount ?? new Uint8Array()));
      break;
    }
    case "sats": {
      allHashes.push(sha256(new Uint8Array([2])));
      const sats = payment.amount;
      if (sats !== undefined && (!Number.isSafeInteger(sats) || sats < 0)) {
        throw new SparkInputError("invoice sats amount must be a non-negative safe integer");
      }
      allHashes.push(sha256(uint64be(BigInt(sats ?? 0))));
      break;
    }
  }

  allHashes.push(sha256(invoice.memo === undefined ? new Uint8Array() : utf8ToBytes(invoice.memo)));

  const { senderPublicKey } = invoice;
  if (senderPublicKey === undefined || senderPublicKey.length === 0) {
    allHashes.push(sha256(new Uint8Array(PUBLIC_KEY_LENGTH)));
  } else {
    if (senderPublicKey.length !== PUBLIC_KEY_LENGTH) {
      throw new SparkInputError("invoice sender public key must be exactly 33 bytes");
    }
    allHashes.push(sha256(senderPublicKey));
  }

  let expirySeconds = 0n;
  if (invoice.expiresAt !== undefined) {
    const seconds = Math.floor(invoice.expiresAt / 1000);
    if (seconds > 0) {
      expirySeconds = BigInt(seconds);
    }
  }
  allHashes.push(sha256(uint64be(expirySeconds)));

  const finalHasher = sha256.create();
  for (const hash of allHashes) {
    finalHasher.update(hash);
  }
  return finalHasher.digest();
}
