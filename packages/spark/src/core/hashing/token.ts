import { sha256 } from "@noble/hashes/sha2.js";

import { SparkInputError } from "../../errors/index.ts";
import type {
  FinalTokenOutput,
  FinalTokenTransaction,
  PartialTokenOutput,
  PartialTokenTransaction,
  TokenOutput,
  TokenTransaction,
} from "../../proto/gen/spark_token_pb.ts";
import {
  FinalTokenTransactionSchema,
  PartialTokenTransactionSchema,
} from "../../proto/gen/spark_token_pb.ts";
import { hashProto } from "./protohash.ts";

// Upstream references: spark/so/utils/token_transaction.go (HashTokenTransactionV3)
// and spark/so/protoconverter/token_transaction.go (ConvertV2TxShapeTo{Partial,Final})
// plus signer/spark-token-primitives/src/token_transaction/hash.rs
// (buildonspark/spark@0b3a32a). The digest is protoreflecthash over the V3
// PartialTokenTransaction / FinalTokenTransaction protos — NOT over the unified
// TokenTransaction the request carries. (The upstream TS SDK's
// `hashTokenTransactionV3` protohashes TokenTransaction directly; it is dead
// code there — `hashTokenTransaction` only dispatches versions 1 and 2 — and
// cannot match the Go/Go-pinned testdata digests, whose field numbering is
// Partial/Final's.)

function toPartialOutput(output: TokenOutput): PartialTokenOutput {
  return {
    $typeName: "spark_token.PartialTokenOutput",
    ownerPublicKey: output.ownerPublicKey,
    withdrawBondSats: output.withdrawBondSats ?? 0n,
    withdrawRelativeBlockLocktime: output.withdrawRelativeBlockLocktime ?? 0n,
    tokenIdentifier: output.tokenIdentifier ?? new Uint8Array(),
    tokenAmount: output.tokenAmount,
  };
}

function tokenMetadata(tx: TokenTransaction) {
  return {
    $typeName: "spark_token.TokenTransactionMetadata" as const,
    sparkOperatorIdentityPublicKeys: tx.sparkOperatorIdentityPublicKeys,
    network: tx.network,
    clientCreatedTimestamp: tx.clientCreatedTimestamp,
    validityDurationSeconds: tx.validityDurationSeconds ?? 0n,
    invoiceAttachments: tx.invoiceAttachments,
  };
}

/** Mirrors `ConvertV2TxShapeToPartial`: drops every SO-filled field. */
function convertV2TxShapeToPartial(tx: TokenTransaction): PartialTokenTransaction {
  const partial: PartialTokenTransaction = {
    $typeName: "spark_token.PartialTokenTransaction",
    version: tx.version,
    tokenTransactionMetadata: tokenMetadata(tx),
    tokenInputs: { case: undefined },
    partialTokenOutputs: tx.tokenOutputs.map(toPartialOutput),
    executeBefore: tx.executeBefore,
  };
  switch (tx.tokenInputs.case) {
    case "mintInput":
      partial.tokenInputs = {
        case: "mintInput",
        value: {
          $typeName: "spark_token.TokenMintInput",
          issuerPublicKey: tx.tokenInputs.value.issuerPublicKey,
          tokenIdentifier: tx.tokenInputs.value.tokenIdentifier,
        },
      };
      break;
    case "transferInput":
      partial.tokenInputs = {
        case: "transferInput",
        value: {
          $typeName: "spark_token.TokenTransferInput",
          outputsToSpend: tx.tokenInputs.value.outputsToSpend,
        },
      };
      break;
    case "createInput":
      partial.tokenInputs = {
        case: "createInput",
        value: {
          ...tx.tokenInputs.value,
          creationEntityPublicKey: undefined,
        },
      };
      break;
    default:
      // Unknown or missing input: upstream returns the partial as-is.
      break;
  }
  return partial;
}

/** Mirrors `ConvertV2TxShapeToFinal`: keeps the full output shape, wrapped. */
function convertV2TxShapeToFinal(tx: TokenTransaction): FinalTokenTransaction {
  const inputs = tx.tokenInputs;
  if (inputs.case === undefined) {
    throw new SparkInputError("token transaction token_inputs: missing or unknown case");
  }
  const outputs: FinalTokenOutput[] = tx.tokenOutputs.map((output) => ({
    $typeName: "spark_token.FinalTokenOutput",
    partialTokenOutput: toPartialOutput(output),
    revocationCommitment: output.revocationCommitment ?? new Uint8Array(),
  }));
  return {
    $typeName: "spark_token.FinalTokenTransaction",
    version: tx.version,
    tokenTransactionMetadata: tokenMetadata(tx),
    tokenInputs: inputs,
    finalTokenOutputs: outputs,
    executeBefore: tx.executeBefore,
  };
}

/**
 * The V3 token transaction hash. `partialHash` signs the pre-finalization shape
 * (`PartialTokenTransaction`: no expiry time, no SO-filled output fields); otherwise the hash is
 * over `FinalTokenTransaction`.
 */
export function hashTokenTransactionV3(
  tokenTransaction: TokenTransaction,
  partialHash = false,
): Uint8Array {
  if (tokenTransaction === undefined || tokenTransaction === null) {
    throw new SparkInputError("token transaction cannot be nil");
  }
  if (partialHash) {
    return hashProto(PartialTokenTransactionSchema, convertV2TxShapeToPartial(tokenTransaction));
  }
  return hashProto(FinalTokenTransactionSchema, convertV2TxShapeToFinal(tokenTransaction));
}

/** Protoreflecthash of `spark_token.PartialTokenTransaction` — what owners sign V3 inputs over. */
export function hashPartialTokenTransaction(
  partialTokenTransaction: PartialTokenTransaction,
): Uint8Array {
  if (partialTokenTransaction === undefined || partialTokenTransaction === null) {
    throw new SparkInputError("partial token transaction cannot be nil");
  }
  return hashProto(PartialTokenTransactionSchema, partialTokenTransaction);
}

/** Protoreflecthash of `spark_token.FinalTokenTransaction`. */
export function hashFinalTokenTransaction(
  finalTokenTransaction: FinalTokenTransaction,
): Uint8Array {
  if (finalTokenTransaction === undefined || finalTokenTransaction === null) {
    throw new SparkInputError("final token transaction cannot be nil");
  }
  return hashProto(FinalTokenTransactionSchema, finalTokenTransaction);
}

/**
 * Sha256(sha256(finalTokenTransactionHash) ‖ sha256(operatorIdentityPublicKey)). The per-operator
 * payload a token owner signs for each input.
 */
export function hashOperatorSpecificTokenTransactionSignablePayload(payload: {
  readonly finalTokenTransactionHash?: Uint8Array;
  readonly operatorIdentityPublicKey?: Uint8Array;
}): Uint8Array {
  const allHashes: Uint8Array[] = [];

  const finalHash = payload.finalTokenTransactionHash;
  if (finalHash !== undefined && finalHash.length > 0) {
    if (finalHash.length !== 32) {
      throw new SparkInputError("final token transaction hash must be 32 bytes");
    }
    allHashes.push(sha256(finalHash));
  }

  const operatorKey = payload.operatorIdentityPublicKey;
  if (operatorKey === undefined || operatorKey.length === 0) {
    throw new SparkInputError("operator identity public key must be non-empty");
  }
  allHashes.push(sha256(operatorKey));

  const concatenated = new Uint8Array(allHashes.reduce((sum, h) => sum + h.length, 0));
  let offset = 0;
  for (const h of allHashes) {
    concatenated.set(h, offset);
    offset += h.length;
  }
  return sha256(concatenated);
}
