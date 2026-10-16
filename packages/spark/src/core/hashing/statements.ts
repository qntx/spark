import { toBinary } from "@bufbuild/protobuf";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

import { SparkInputError } from "../../errors/index.ts";
import { ChallengeSchema } from "../../proto/gen/spark_authn_pb.ts";
import type { Challenge } from "../../proto/gen/spark_authn_pb.ts";
import { HashVariant } from "../../proto/gen/spark_pb.ts";
import type { TransferPackage } from "../../proto/gen/spark_pb.ts";
import type { SparkNetwork } from "../network.ts";
import { uuidFromBytes, uuidToBytes } from "../uuid.ts";
import { newHasher } from "./hashstructure.ts";

// Upstream references: sdks/js/packages/spark-sdk/src/utils/{transfer_package,
// proof}.ts, spark-wallet/spark-wallet.ts (static deposit + instant claim +
// watchtower statements), services/transfer.ts (per-leaf send digest), and the
// Go counterparts in spark/common/{transfer_package,proof}.go and
// spark/so/handler (buildonspark/spark@0b3a32a).

function concat(parts: ReadonlyArray<Uint8Array>): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function transferIdBytes(transferId: string): Uint8Array {
  return uuidToBytes(transferId);
}

/**
 * The transfer-package digest the sender signs: the HASH_VARIANT_V2 tagged hashstructure digest
 * over the transfer id and the key-tweak map. The SDK only ever produces V2 packages, so any other
 * variant — and any package carrying a `delegationIntent` (Spark Pull) — is rejected.
 */
export function transferPackageDigest(
  transferId: string,
  transferPackage: TransferPackage,
): Uint8Array {
  if (transferPackage.hashVariant !== HashVariant.V2) {
    throw new SparkInputError("transfer package: only hash variant HASH_VARIANT_V2 is supported");
  }
  if (transferPackage.delegationIntent !== undefined) {
    throw new SparkInputError("transfer package: delegation intent is not supported");
  }
  return newHasher(["spark", "transfer", "signing payload"])
    .addBytes(transferIdBytes(transferId))
    .addMapStringToBytes(transferPackage.keyTweakPackage)
    .hash();
}

/** The claim-package digest: tagged hasher over the transfer id and tweak map. */
export function claimPackageDigest(
  transferId: string,
  keyTweakPackage: Readonly<Record<string, Uint8Array>>,
): Uint8Array {
  return newHasher(["spark", "claim", "signing payload"])
    .addBytes(transferIdBytes(transferId))
    .addMapStringToBytes(keyTweakPackage)
    .hash();
}

/** Sha256(utf8(leafId) ‖ utf8(transferId) ‖ secretCipher) — the per-leaf send signature digest. */
export function sendLeafSigningDigest(
  leafId: string,
  transferId: string,
  secretCipher: Uint8Array,
): Uint8Array {
  return sha256(concat([utf8ToBytes(leafId), utf8ToBytes(transferId), secretCipher]));
}

/** Deposit-address proof of possession, signed with the identity key at address generation. */
export function proofOfPossessionDigest(
  userPublicKey: Uint8Array,
  operatorPublicKey: Uint8Array,
  depositAddress: string,
): Uint8Array {
  return newHasher(["spark", "deposit", "proof_of_possession"])
    .addBytes(userPublicKey)
    .addBytes(operatorPublicKey)
    .addBytes(utf8ToBytes(depositAddress))
    .hash();
}

export type StaticDepositRequestType = "fixed" | "maxFee" | "refund";

const STATIC_DEPOSIT_REQUEST_TYPE: Record<StaticDepositRequestType, number> = {
  fixed: 0,
  maxFee: 1,
  refund: 2,
};

export type StaticDepositStatement = {
  readonly transactionId: string;
  readonly outputIndex: number;
  readonly network: SparkNetwork;
  readonly requestType: StaticDepositRequestType;
  readonly creditAmountSats: number;
  readonly payload: Uint8Array;
};

/**
 * The static-deposit user statement digest: SHA-256 over the concatenation "claim_static_deposit" ‖
 * network ‖ txid(hex text) ‖ vout(u32 LE) ‖ requestType(u8) ‖ creditAmount(u64 LE) ‖ payload where
 * payload is the SSP signature for claims/max-fee and the refund spend transaction's sighash for
 * refunds. Network is the lowercase network name ("mainnet"/"regtest"). This is the only form the
 * SDK signs (spark-wallet.ts `getStaticDepositSigningPayload` + sha256).
 */
export function staticDepositStatementDigest({
  transactionId,
  outputIndex,
  network,
  requestType,
  creditAmountSats,
  payload,
}: StaticDepositStatement): Uint8Array {
  if (!Number.isSafeInteger(outputIndex) || outputIndex < 0 || outputIndex > 0xffffffff) {
    throw new SparkInputError("static deposit statement: output index must be a uint32");
  }
  if (!Number.isSafeInteger(creditAmountSats) || creditAmountSats < 0) {
    throw new SparkInputError("static deposit statement: credit amount must be a safe integer");
  }
  const requestTypeValue = STATIC_DEPOSIT_REQUEST_TYPE[requestType];

  const outputIndexBytes = new Uint8Array(4);
  new DataView(outputIndexBytes.buffer).setUint32(0, outputIndex, true);
  const creditAmountBytes = new Uint8Array(8);
  new DataView(creditAmountBytes.buffer).setBigUint64(0, BigInt(creditAmountSats), true);

  return sha256(
    concat([
      utf8ToBytes("claim_static_deposit"),
      utf8ToBytes(network),
      utf8ToBytes(transactionId),
      outputIndexBytes,
      new Uint8Array([requestTypeValue]),
      creditAmountBytes,
      payload,
    ]),
  );
}

/**
 * The 0-confirmation instant static deposit statement digest: a tagged hashstructure digest
 * (requestType 3 = Instant) over the claim terms.
 */
export function instantStaticDepositStatementDigest({
  network,
  creditAmountSats,
  secondaryCreditAmountSats,
  destinationAddress,
  satsValue,
  sspSignature,
}: {
  readonly network: SparkNetwork;
  readonly creditAmountSats: number;
  readonly secondaryCreditAmountSats: number;
  readonly destinationAddress: string;
  readonly satsValue: number;
  readonly sspSignature: Uint8Array;
}): Uint8Array {
  return newHasher(["spark", "claim_instant_static_deposit"])
    .addString(network)
    .addUint8(3) // requestType = Instant
    .addUint64(creditAmountSats)
    .addUint64(secondaryCreditAmountSats)
    .addString(destinationAddress)
    .addUint64(satsValue)
    .addBytes(sspSignature)
    .hash();
}

const NETWORK_STATEMENT_NAME: Record<SparkNetwork, string> = {
  mainnet: "MAINNET",
  regtest: "REGTEST",
};

/**
 * The watchtower recovery statement digest: sha256("recover_watchtower_exited_leaf" ‖ NETWORK ‖
 * leafId ‖ recoveryTxSighash) where NETWORK is the upper-case proto network name
 * ("MAINNET"/"REGTEST") — unlike the lowercase, Bitcoin-style names the static deposit statements
 * use.
 */
export function watchtowerRecoveryStatementDigest(
  network: SparkNetwork,
  leafId: string,
  recoveryTxSighash: Uint8Array,
): Uint8Array {
  return sha256(
    concat([
      utf8ToBytes("recover_watchtower_exited_leaf"),
      utf8ToBytes(NETWORK_STATEMENT_NAME[network]),
      // uuid.String() in Go: lowercase canonical form.
      utf8ToBytes(uuidFromBytes(uuidToBytes(leafId))),
      recoveryTxSighash,
    ]),
  );
}

/** Sha256 over the serialized spark_authn.Challenge — the digest the session signature covers. */
export function authnChallengeDigest(challenge: Challenge): Uint8Array {
  return sha256(toBinary(ChallengeSchema, challenge));
}
