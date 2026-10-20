import { bytesToNumberBE } from "@noble/curves/utils.js";

import type { SparkNetwork } from "../core/network.ts";
import { encodeTokenIdentifier } from "../core/token-identifier.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import type { OutputWithPreviousTransactionData } from "../proto/gen/spark_token_pb.ts";
import { TokenOutputStatus } from "../proto/gen/spark_token_pb.ts";

const TOKEN_IDENTIFIER_LENGTH = 32;
const TOKEN_AMOUNT_LENGTH = 16;
const PREV_TX_HASH_LENGTH = 32;
const PUBLIC_KEY_LENGTH = 33;

/**
 * Mapped `query_token_outputs` status. `"unknown"` marks an enum value this SDK does not recognize
 * — it must never be spendable; an unset status field stays absent instead.
 */
export type SparkTokenOutputStatus = "available" | "pending-outbound" | "unknown";

/** One owned token output, keyed by its previous transaction location. */
export type SparkTokenOutput = {
  readonly id: string;
  /** Raw 32-byte token identifier (bech32m-encode for display). */
  readonly tokenIdentifier: Uint8Array;
  /** Decoded 128-bit amount. */
  readonly amount: bigint;
  readonly prevTransactionHash: Uint8Array;
  readonly prevTransactionVout: number;
  readonly ownerPublicKey: Uint8Array;
  readonly status?: SparkTokenOutputStatus;
};

/** Aggregate balance for one token identifier, display-ready. */
export type SparkTokenBalance = {
  /** Bech32m `btkn`/`btknrt` token identifier. */
  readonly tokenIdentifier: string;
  readonly amount: bigint;
  readonly outputCount: number;
};

function mapOutputStatus(
  status: TokenOutputStatus | undefined,
): SparkTokenOutputStatus | undefined {
  switch (status) {
    case TokenOutputStatus.AVAILABLE:
      return "available";
    case TokenOutputStatus.PENDING_OUTBOUND:
      return "pending-outbound";
    case TokenOutputStatus.UNSPECIFIED:
    case undefined:
      return undefined;
    default:
      return "unknown";
  }
}

/** Maps a `query_token_outputs` row; throws on malformed SO data. */
export function mapTokenOutput(row: OutputWithPreviousTransactionData): SparkTokenOutput {
  const { output } = row;
  if (output === undefined) {
    throw new SparkError("token output: missing output message");
  }
  const status = mapOutputStatus(output.status);
  const { tokenIdentifier } = output;
  if (tokenIdentifier === undefined || tokenIdentifier.length !== TOKEN_IDENTIFIER_LENGTH) {
    throw new SparkError("token output: missing or malformed token identifier");
  }
  if (output.tokenAmount.length !== TOKEN_AMOUNT_LENGTH) {
    throw new SparkError("token output: token amount is not 16 bytes");
  }
  if (output.id === undefined || output.id === "") {
    throw new SparkError("token output: missing id");
  }
  if (row.previousTransactionHash.length !== PREV_TX_HASH_LENGTH) {
    throw new SparkError("token output: previous transaction hash is not 32 bytes");
  }
  if (output.ownerPublicKey.length !== PUBLIC_KEY_LENGTH) {
    throw new SparkError("token output: owner public key is not 33 bytes");
  }
  return {
    id: output.id,
    tokenIdentifier,
    amount: bytesToNumberBE(output.tokenAmount),
    prevTransactionHash: row.previousTransactionHash,
    prevTransactionVout: row.previousTransactionVout,
    ownerPublicKey: output.ownerPublicKey,
    ...(status === undefined ? {} : { status }),
  };
}

/** Sums spendable outputs into per-identifier balances; only `"available"` outputs count. */
export function tokenBalances(
  outputs: ReadonlyArray<SparkTokenOutput>,
  network: SparkNetwork,
): SparkTokenBalance[] {
  const totals = new Map<string, SparkTokenBalance>();
  for (const output of outputs) {
    if (output.status !== "available") {
      continue;
    }
    const identifier = encodeTokenIdentifier(output.tokenIdentifier, network);
    const existing = totals.get(identifier);
    if (existing === undefined) {
      totals.set(identifier, {
        tokenIdentifier: identifier,
        amount: output.amount,
        outputCount: 1,
      });
    } else {
      totals.set(identifier, {
        tokenIdentifier: identifier,
        amount: existing.amount + output.amount,
        outputCount: existing.outputCount + 1,
      });
    }
  }
  return [...totals.values()];
}

/** Amount must be a non-negative 128-bit integer. */
export function assertTokenAmount(amount: bigint): void {
  if (amount <= 0n) {
    throw new SparkInputError("token amount must be greater than 0");
  }
  if (amount >= 1n << 128n) {
    throw new SparkInputError("token amount exceeds uint128");
  }
}
