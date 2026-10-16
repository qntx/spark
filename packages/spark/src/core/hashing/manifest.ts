import { fromBinary, toBinary } from "@bufbuild/protobuf";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { bech32, bech32m } from "@scure/base";

import { SparkInputError } from "../../errors/index.ts";
import type { ManifestAmount, TransferManifest } from "../../proto/gen/spark_pb.ts";
import { TransferManifestSchema } from "../../proto/gen/spark_pb.ts";
import { compareBytes } from "../bytes.ts";
import { newHasher } from "./hashstructure.ts";
import { hashProto } from "./protohash.ts";

// Upstream references: signer/spark-token-primitives/src/transfer_manifest.rs
// and quote_envelope.rs (buildonspark/spark@0b3a32a). The TypeScript SDK
// delegates these digests to the Rust crate through bindings; this module is a
// pure-TS port of the same construction, byte-identical per the vectors in
// spark/testdata/{transfer_manifest_hash,quote_envelope}_cases.json.

const TRANSFER_MANIFEST_TAG = ["spark", "transfer", "manifest"] as const;
const QUOTE_TAG = ["spark", "quote", "v1"] as const;
const RECEIVE_ATTESTOR_TARGET_TAG = ["spark", "quote", "target", "receive", "attestor", "v1"];
const SEND_TARGET_TAG = ["spark", "quote", "target", "send", "v1"];
const COOP_EXIT_TARGET_TAG = ["spark", "quote", "target", "coop_exit", "v1"];
const STATIC_DEPOSIT_TARGET_TAG = ["spark", "quote", "target", "static_deposit", "v1"];

const DIGEST_LENGTH = 32;
const COMPRESSED_KEY_LENGTH = 33;
const SUPPORTED_MANIFEST_VERSION = 1;
// Protobuf Timestamp upper bound (9999-12-31T23:59:59Z); negative epochs are
// rejected because JS remainder math would derive negative nanos.
const MAX_TIMESTAMP_SECONDS = 253_402_300_799n;
const MAX_MANIFEST_AMOUNT_SATS = 2_100_000_000_000_000n;
const NANOS_PER_MILLI = 1_000_000;

/** Which flow a quote was issued for; 1-based so 0 stays an unset sentinel. */
export const QuoteReason = {
  RECEIVE: 1,
  SEND: 2,
  COOP_EXIT: 3,
  STATIC_DEPOSIT: 4,
} as const;
export type QuoteReason = (typeof QuoteReason)[keyof typeof QuoteReason];

export const QuoteRole = {
  ISSUER: 1,
  ATTESTOR: 2,
} as const;
export type QuoteRole = (typeof QuoteRole)[keyof typeof QuoteRole];

function notHashable(message: string): SparkInputError {
  return new SparkInputError(`transfer manifest not hashable: ${message}`);
}

// spark.Network values: UNSPECIFIED=0, MAINNET=1, REGTEST=2, TESTNET=3, SIGNET=4.
function isKnownNetwork(network: number): boolean {
  return Number.isInteger(network) && network >= 1 && network <= 4;
}

// spark.FeeSource values: UNSPECIFIED=0, PARTNER_MARKUP=1, BASE=2, NETWORK=3.
function isKnownFeeSource(source: number): boolean {
  return Number.isInteger(source) && source >= 0 && source <= 3;
}

// spark.FeeRole values: UNSPECIFIED=0, AFFILIATE=1, PARTNER=2, LS=3.
function isKnownFeeRole(role: number): boolean {
  return Number.isInteger(role) && role >= 0 && role <= 3;
}

function amountSortKey(amount: ManifestAmount | undefined): readonly [number, bigint] {
  if (amount === undefined) {
    return [0, 0n];
  }
  switch (amount.amount.case) {
    case "sats":
      return [1, amount.amount.value];
    case "bps":
      return [2, BigInt(amount.amount.value)];
    default:
      return [0, 0n];
  }
}

function compareAmounts(a: ManifestAmount | undefined, b: ManifestAmount | undefined): number {
  const [ka, va] = amountSortKey(a);
  const [kb, vb] = amountSortKey(b);
  if (ka !== kb) {
    return ka - kb;
  }
  return va < vb ? -1 : va > vb ? 1 : 0;
}

function validateAmount(amount: ManifestAmount | undefined, context: string): void {
  const [kind, value] = amountSortKey(amount);
  if (kind === 0) {
    throw notHashable(`${context}: amount must be set`);
  }
  if (value === 0n) {
    throw notHashable(`${context}: amount must be non-zero (zero is omitted from the hash)`);
  }
  if (value < 0n) {
    throw notHashable(`${context}: amount must be non-negative`);
  }
  if (kind === 1 && value > MAX_MANIFEST_AMOUNT_SATS) {
    throw notHashable(`${context}: sats amount exceeds ${MAX_MANIFEST_AMOUNT_SATS}`);
  }
  if (kind === 2 && amount?.amount.case === "bps") {
    const bps = amount.amount.value;
    if (!Number.isSafeInteger(bps) || bps < 0 || bps > 0xffffffff) {
      throw notHashable(`${context}: bps exceeds uint32 range`);
    }
  }
}

function validateTimestamp(ts: Timestamp | undefined, field: string): void {
  if (ts === undefined) {
    return;
  }
  if (!Number.isSafeInteger(ts.nanos)) {
    throw notHashable(`${field}: nanos must be an integer`);
  }
  if (ts.seconds < 0n || ts.seconds > MAX_TIMESTAMP_SECONDS) {
    throw notHashable(`${field}: seconds out of range [0, ${MAX_TIMESTAMP_SECONDS}]`);
  }
  if (ts.nanos < 0 || ts.nanos >= 1_000_000_000) {
    throw notHashable(`${field}: nanos out of range [0, 1e9)`);
  }
  // Objecthash implementations disagree on present-but-zero message fields:
  // this implementation's default-skipping gate omits a present epoch
  // timestamp entirely while the Go port hashes it as list[0,0] — reject
  // rather than sign a digest implementations disagree on.
  if (ts.seconds === 0n && ts.nanos < NANOS_PER_MILLI) {
    throw notHashable(`${field}: timestamp must not floor to the epoch`);
  }
}

function validateForHashing(manifest: TransferManifest): void {
  if (manifest.version !== SUPPORTED_MANIFEST_VERSION) {
    throw notHashable(
      `unsupported manifest version ${manifest.version} (supported: ${SUPPORTED_MANIFEST_VERSION})`,
    );
  }
  if (manifest.transferId.length === 0) {
    throw notHashable("transfer_id must be set");
  }
  if (!isKnownNetwork(manifest.network)) {
    throw notHashable("network must be a known value");
  }
  validateTimestamp(manifest.transferExpiryTime, "transfer_expiry_time");
  validateTimestamp(manifest.quoteExpiryTime, "quote_expiry_time");
  if (manifest.edges.length === 0) {
    throw notHashable("edges must be non-empty");
  }
  for (const [i, edge] of manifest.edges.entries()) {
    if (edge.senderIdentityPublicKey.length === 0) {
      throw notHashable(`edges[${i}]: sender_identity_public_key must be set`);
    }
    if (edge.receiverIdentityPublicKey.length === 0) {
      throw notHashable(`edges[${i}]: receiver_identity_public_key must be set`);
    }
    validateAmount(edge.amount, `edges[${i}]`);
  }
  for (const [i, fee] of manifest.fees.entries()) {
    if (!isKnownFeeSource(fee.source) || fee.source === 0) {
      throw notHashable(`fees[${i}]: source must be a known non-zero value`);
    }
    if (!isKnownFeeRole(fee.role)) {
      throw notHashable(`fees[${i}]: role must be a known value`);
    }
    // FEE_SOURCE_PARTNER_MARKUP
    if (fee.source === 1 && fee.role === 0) {
      throw notHashable(`fees[${i}]: role must be set for partner markup fees`);
    }
    if (fee.receiverIdentityPublicKey.length !== COMPRESSED_KEY_LENGTH) {
      throw notHashable(
        `fees[${i}]: receiver_identity_public_key must be ${COMPRESSED_KEY_LENGTH} bytes`,
      );
    }
    validateAmount(fee.amount, `fees[${i}]`);
  }
}

function floorTimestamp(ts: Timestamp): Timestamp {
  return {
    $typeName: "google.protobuf.Timestamp",
    seconds: ts.seconds,
    nanos: Math.floor(ts.nanos / NANOS_PER_MILLI) * NANOS_PER_MILLI,
  };
}

function canonicalize(manifest: TransferManifest): TransferManifest {
  const edges = [...manifest.edges].sort((a, b) => {
    const sender = compareBytes(a.senderIdentityPublicKey, b.senderIdentityPublicKey);
    if (sender !== 0) {
      return sender;
    }
    const receiver = compareBytes(a.receiverIdentityPublicKey, b.receiverIdentityPublicKey);
    if (receiver !== 0) {
      return receiver;
    }
    return compareAmounts(a.amount, b.amount);
  });
  const fees = [...manifest.fees].sort((a, b) => {
    if (a.source !== b.source) {
      return a.source - b.source;
    }
    if (a.role !== b.role) {
      return a.role - b.role;
    }
    const receiver = compareBytes(a.receiverIdentityPublicKey, b.receiverIdentityPublicKey);
    if (receiver !== 0) {
      return receiver;
    }
    return compareAmounts(a.amount, b.amount);
  });
  return {
    ...manifest,
    edges,
    fees,
    transferExpiryTime: manifest.transferExpiryTime
      ? floorTimestamp(manifest.transferExpiryTime)
      : undefined,
    quoteExpiryTime: manifest.quoteExpiryTime
      ? floorTimestamp(manifest.quoteExpiryTime)
      : undefined,
  };
}

/**
 * The signed digest for a `TransferManifest`: tagged_hash(["spark","transfer","manifest"],
 * protohash(canonicalize(manifest))) Validation is fail-closed because protohash silently omits
 * unset fields: an unset version, network, pubkey, or amount would vanish from the digest.
 */
export function hashSerializedTransferManifest(manifestBytes: Uint8Array): Uint8Array {
  let manifest: TransferManifest;
  try {
    manifest = fromBinary(TransferManifestSchema, manifestBytes);
  } catch (error) {
    throw new SparkInputError("failed to decode TransferManifest", { cause: error });
  }
  validateForHashing(manifest);
  const objectHash = hashProto(TransferManifestSchema, canonicalize(manifest));
  return newHasher(TRANSFER_MANIFEST_TAG).addBytes(objectHash).hash();
}

/** Same digest, starting from a message object instead of wire bytes. */
export function hashTransferManifest(manifest: TransferManifest): Uint8Array {
  return hashSerializedTransferManifest(toBinary(TransferManifestSchema, manifest));
}

function require32Bytes(name: string, value: Uint8Array): void {
  if (value.length !== DIGEST_LENGTH) {
    throw new SparkInputError(`${name} must be 32 bytes`);
  }
}

/** Binds a receive attestation to the invoice's payment hash. */
export function receiveAttestorTarget(paymentHash: Uint8Array): Uint8Array {
  require32Bytes("payment_hash", paymentHash);
  return newHasher(RECEIVE_ATTESTOR_TARGET_TAG).addBytes(paymentHash).hash();
}

export function sendTarget(paymentHash: Uint8Array): Uint8Array {
  require32Bytes("payment_hash", paymentHash);
  return newHasher(SEND_TARGET_TAG).addBytes(paymentHash).hash();
}

/**
 * Segwit addresses are case-insensitive (BIP-173), so a valid one is lowercased before hashing;
 * anything else is bound exactly as given, like `bech32::segwit::decode` upstream.
 */
function canonicalWithdrawalAddress(address: string): string {
  if (isSegwitAddress(address)) {
    return address.toLowerCase();
  }
  return address;
}

function isBech32Encoded(address: string): address is `${string}1${string}` {
  return address.includes("1");
}

function isSegwitAddress(address: string): boolean {
  for (const encoding of [bech32, bech32m] as const) {
    try {
      if (!isBech32Encoded(address)) {
        continue;
      }
      const { words } = encoding.decode(address);
      const [version] = words;
      if (version === undefined || version > 16) {
        continue;
      }
      const program = encoding.fromWords(words.slice(1));
      if (program.length < 2 || program.length > 40) {
        continue;
      }
      // v0 programs are 20 or 32 bytes and must use bech32; v1+ use bech32m.
      if (version === 0) {
        if (encoding === bech32 && (program.length === 20 || program.length === 32)) {
          return true;
        }
        continue;
      }
      if (encoding === bech32m) {
        return true;
      }
    } catch {
      continue;
    }
  }
  return false;
}

export function coopExitTarget(withdrawalAddress: string, leafSetHash: Uint8Array): Uint8Array {
  if (withdrawalAddress.length === 0) {
    throw new SparkInputError("coop exit target: withdrawal_address must be non-empty");
  }
  require32Bytes("leaf_set_hash", leafSetHash);
  return newHasher(COOP_EXIT_TARGET_TAG)
    .addString(canonicalWithdrawalAddress(withdrawalAddress))
    .addBytes(leafSetHash)
    .hash();
}

export function staticDepositTarget(txid: Uint8Array, vout: number): Uint8Array {
  require32Bytes("txid", txid);
  if (!Number.isSafeInteger(vout) || vout < 0 || vout > 0xffffffff) {
    throw new SparkInputError("static deposit target: vout must be a uint32");
  }
  return newHasher(STATIC_DEPOSIT_TARGET_TAG).addBytes(txid).addUint64(vout).hash();
}

/**
 * The digest every party to a fee quote signs: tagged_hash(["spark","quote","v1"], network,
 * manifest_hash, reason, role, target) `network` is the spark proto `Network` value (1..4), not the
 * SDK-local network name. `target` is opaque here — an issuer legitimately has none — but an
 * attestor must bind one.
 */
export function quoteEnvelopeDigest({
  network,
  manifestHash,
  reason,
  role,
  target,
}: {
  readonly network: number;
  readonly manifestHash: Uint8Array;
  readonly reason: number;
  readonly role: number;
  readonly target: Uint8Array;
}): Uint8Array {
  require32Bytes("manifest_hash", manifestHash);
  if (!isKnownNetwork(network)) {
    throw new SparkInputError(`quote envelope digest: unsupported network ${network}`);
  }
  if (!Number.isInteger(reason) || reason < 1 || reason > 4) {
    throw new SparkInputError(`quote envelope digest: unsupported quote reason ${reason}`);
  }
  if (role !== QuoteRole.ISSUER && role !== QuoteRole.ATTESTOR) {
    throw new SparkInputError(`quote envelope digest: unsupported quote role ${role}`);
  }
  if (role === QuoteRole.ATTESTOR && target.length === 0) {
    throw new SparkInputError("quote envelope digest: attestor target must be non-empty");
  }
  return newHasher(QUOTE_TAG)
    .addUint64(network)
    .addBytes(manifestHash)
    .addUint64(reason)
    .addUint64(role)
    .addBytes(target)
    .hash();
}
