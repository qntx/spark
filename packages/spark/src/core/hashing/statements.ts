import { toBinary, fromBinary } from "@bufbuild/protobuf";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { base64urlnopad } from "@scure/base";

import { SparkInputError } from "../../errors/index.ts";
import { ChallengeSchema } from "../../proto/gen/spark_authn_pb.ts";
import type { Challenge } from "../../proto/gen/spark_authn_pb.ts";
import { HashVariant } from "../../proto/gen/spark_pb.ts";
import type { TransferPackage } from "../../proto/gen/spark_pb.ts";
import { ProtectedChallengeSchema } from "../../proto/gen/ssp_authn_pb.ts";
import type { SparkNetwork } from "../network.ts";
import { uuidFromBytes, uuidToBytes } from "../uuid.ts";
import { newHasher } from "./hashstructure.ts";

// Upstream references: sdks/js/packages/spark-sdk/src/utils/{transfer_package,
// proof}.ts, spark-wallet/spark-wallet.ts (static deposit + watchtower
// statements), services/transfer.ts (per-leaf send digest), and the
// Go counterparts in spark/common/{transfer_package,proof}.go and
// spark/so/handler (buildonspark/spark@0b3a32a).

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
    .addBytes(uuidToBytes(transferId))
    .addMapStringToBytes(transferPackage.keyTweakPackage)
    .hash();
}

/** The claim-package digest: tagged hasher over the transfer id and tweak map. */
export function claimPackageDigest(
  transferId: string,
  keyTweakPackage: Readonly<Record<string, Uint8Array>>,
): Uint8Array {
  return newHasher(["spark", "claim", "signing payload"])
    .addBytes(uuidToBytes(transferId))
    .addMapStringToBytes(keyTweakPackage)
    .hash();
}

/** Sha256(utf8(leafId) ‖ utf8(transferId) ‖ secretCipher) — the per-leaf send signature digest. */
export function sendLeafSigningDigest(
  leafId: string,
  transferId: string,
  secretCipher: Uint8Array,
): Uint8Array {
  return sha256(concatBytes(utf8ToBytes(leafId), utf8ToBytes(transferId), secretCipher));
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
 * payload is the raw SSP signature bytes for claims/max-fee and the raw sighash of the refund spend
 * transaction for refunds. Network is the lowercase network name ("mainnet"/"regtest"). This is the
 * only form the SDK signs (spark-wallet.ts `getStaticDepositSigningPayload` + sha256).
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
    concatBytes(
      utf8ToBytes("claim_static_deposit"),
      utf8ToBytes(network),
      utf8ToBytes(transactionId),
      outputIndexBytes,
      new Uint8Array([requestTypeValue]),
      creditAmountBytes,
      payload,
    ),
  );
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
    concatBytes(
      utf8ToBytes("recover_watchtower_exited_leaf"),
      utf8ToBytes(NETWORK_STATEMENT_NAME[network]),
      // uuid.String() in Go: lowercase canonical form.
      utf8ToBytes(uuidFromBytes(uuidToBytes(leafId))),
      recoveryTxSighash,
    ),
  );
}

/**
 * Sha256 over the base64-decoded SSP protected challenge — the digest the SSP session signature
 * covers (upstream graphql/client.ts `authenticate`). The SSP emits unpadded base64url; like Node's
 * base64 decoder the standard-alphabet characters and padding are normalized away before decoding
 * with the URL-safe, unpadded variant.
 *
 * The decoded bytes are server-chosen input to the identity key — a signature over this digest
 * verifies anywhere a raw sha256 digest is signed — so they are accepted only as an
 * `ssp_authn.ProtectedChallenge` whose `challenge.public_key` is `identityPublicKey` (either key
 * encoding). Unknown fields are tolerated; the bytes are signed verbatim. Ported from
 * breez-spark-sdk `crates/spark/src/ssp/challenge.rs` @956ff90.
 */
export function sspChallengeDigest(
  protectedChallenge: string,
  identityPublicKey: Uint8Array,
): Uint8Array {
  let decoded: Uint8Array;
  try {
    const normalized = protectedChallenge
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
    decoded = base64urlnopad.decode(normalized);
  } catch {
    throw new SparkInputError("ssp challenge: protected challenge is not valid base64");
  }
  let protectedMsg;
  try {
    protectedMsg = fromBinary(ProtectedChallengeSchema, decoded);
  } catch {
    throw new SparkInputError("ssp challenge: not a ssp_authn.ProtectedChallenge");
  }
  const { challenge } = protectedMsg;
  if (challenge === undefined) {
    throw new SparkInputError("ssp challenge: missing challenge");
  }
  if (challenge.publicKey.length === 0) {
    throw new SparkInputError("ssp challenge: missing public key");
  }
  let issuedTo: ReturnType<typeof secp256k1.Point.fromBytes>;
  let identity: ReturnType<typeof secp256k1.Point.fromBytes>;
  try {
    issuedTo = secp256k1.Point.fromBytes(challenge.publicKey);
    identity = secp256k1.Point.fromBytes(identityPublicKey);
  } catch {
    throw new SparkInputError("ssp challenge: malformed public key");
  }
  if (!issuedTo.equals(identity)) {
    throw new SparkInputError("ssp challenge: challenge is issued to a different public key");
  }
  return sha256(decoded);
}

/** Sha256 over the serialized spark_authn.Challenge — the digest the session signature covers. */
export function authnChallengeDigest(challenge: Challenge): Uint8Array {
  return sha256(toBinary(ChallengeSchema, challenge));
}
