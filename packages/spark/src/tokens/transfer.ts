import { create, toBinary } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import type { CallOptions, Client } from "@connectrpc/connect";
import { equalBytes, numberToBytesBE } from "@noble/curves/utils.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { compareBytes } from "../core/bytes.ts";
import { hashFinalTokenTransaction } from "../core/hashing/token.ts";
import { sparkNetworkProto } from "../core/network.ts";
import type { SparkNetwork, SparkOperatorConfig } from "../core/network.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import type {
  FinalTokenTransaction,
  PartialTokenOutput,
  PartialTokenTransaction,
  SignatureWithIndex,
  SparkTokenService,
} from "../proto/gen/spark_token_pb.ts";
import {
  PartialTokenOutputSchema,
  PartialTokenTransactionSchema,
  SignatureWithIndexSchema,
  TokenTransactionMetadataSchema,
} from "../proto/gen/spark_token_pb.ts";
import type { SparkSigner } from "../signer/types.ts";
import { assertTokenAmount } from "./model.ts";
import type { SparkTokenOutput } from "./model.ts";

// Upstream references: sdks/js/packages/spark-sdk/src/services/tokens/
// token-transactions.ts (buildonspark/spark@0b3a32a) — selectTokenOutputs
// (SMALL_FIRST), constructPartialTransferTokenTransaction and
// broadcastTokenTransactionV3Detailed.

/** Upstream cap on inputs per token transaction (`MAX_TOKEN_OUTPUTS_TX`). */
const MAX_TOKEN_OUTPUTS_TX = 500;
const TOKEN_AMOUNT_LENGTH = 16;
const TOKEN_VERSION = 3;

export type TokenNetworkParams = {
  readonly withdrawBondSats: number;
  readonly withdrawRelativeBlockLocktime: number;
  readonly validityDurationSeconds: number;
};

/**
 * Small-first selection, ported from upstream `selectTokenOutputs`: exact match first, then the
 * smallest prefix of sorted outputs reaching `amount`, swapping in larger outputs when the cap is
 * hit. Throws {@link SparkInputError} when funds are insufficient.
 */
export function selectTokenOutputs(
  outputs: ReadonlyArray<SparkTokenOutput>,
  amount: bigint,
): SparkTokenOutput[] {
  assertTokenAmount(amount);
  const available = outputs.filter((output) => output.status !== "pending-outbound");
  const total = available.reduce((sum, output) => sum + output.amount, 0n);
  if (total < amount) {
    throw new SparkInputError("insufficient token amount");
  }

  const exact = available.find((output) => output.amount === amount);
  if (exact !== undefined) {
    return [exact];
  }

  const sorted = [...available].sort((a, b) =>
    a.amount < b.amount ? -1 : a.amount > b.amount ? 1 : 0,
  );
  let sum = 0n;
  let count = 0;
  for (const output of sorted) {
    sum += output.amount;
    count += 1;
    if (sum >= amount) {
      return sorted.slice(0, count);
    }
    if (count >= MAX_TOKEN_OUTPUTS_TX) {
      break;
    }
  }

  // The smallest MAX did not reach the target: swap smallest selections for the largest
  // remaining outputs.
  const small = sorted.slice(0, MAX_TOKEN_OUTPUTS_TX);
  const large = sorted.slice(MAX_TOKEN_OUTPUTS_TX).reverse();
  const selected = [...small];
  let selectedSum = small.reduce((acc, output) => acc + output.amount, 0n);
  let largeIndex = 0;
  while (selectedSum < amount && largeIndex < large.length) {
    const smallest = selected.shift();
    const largest = large[largeIndex];
    if (smallest === undefined || largest === undefined) {
      break;
    }
    selected.push(largest);
    selectedSum = selectedSum - smallest.amount + largest.amount;
    largeIndex += 1;
  }
  if (selectedSum < amount) {
    throw new SparkInputError("insufficient token amount within the output cap");
  }
  return selected;
}

function sortedOperatorKeys(operators: ReadonlyArray<SparkOperatorConfig>): Uint8Array[] {
  // Byte-wise ascending order, matching upstream collectOperatorIdentityPublicKeys.
  return [...operators].map((operator) => operator.identityPublicKey).sort(compareBytes);
}

function partialOutput(
  ownerPublicKey: Uint8Array,
  tokenIdentifier: Uint8Array,
  amount: bigint,
  tokens: TokenNetworkParams,
): PartialTokenOutput {
  return create(PartialTokenOutputSchema, {
    ownerPublicKey,
    withdrawBondSats: BigInt(tokens.withdrawBondSats),
    withdrawRelativeBlockLocktime: BigInt(tokens.withdrawRelativeBlockLocktime),
    tokenIdentifier,
    tokenAmount: numberToBytesBE(amount, TOKEN_AMOUNT_LENGTH),
  });
}

/**
 * Builds the V3 `PartialTokenTransaction` for a transfer (upstream
 * `constructPartialTransferTokenTransaction`): inputs sorted by previous vout, receiver outputs
 * first, change back to the sender when selected inputs exceed the requested amount, metadata from
 * the network config. No invoice attachments.
 */
export function buildTransferPartial(options: {
  readonly selectedOutputs: ReadonlyArray<SparkTokenOutput>;
  readonly receiverPublicKey: Uint8Array;
  readonly tokenIdentifier: Uint8Array;
  readonly amount: bigint;
  readonly senderPublicKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly operators: ReadonlyArray<SparkOperatorConfig>;
  readonly tokens: TokenNetworkParams;
  readonly now: () => number;
}): PartialTokenTransaction {
  const inputs = [...options.selectedOutputs].sort(
    (a, b) => a.prevTransactionVout - b.prevTransactionVout,
  );
  let available = 0n;
  for (const output of inputs) {
    if (!equalBytes(output.tokenIdentifier, options.tokenIdentifier)) {
      throw new SparkInputError("selected outputs span multiple token identifiers");
    }
    available += output.amount;
  }
  if (available < options.amount) {
    throw new SparkInputError("selected outputs do not cover the requested amount");
  }

  const partialTokenOutputs = [
    partialOutput(
      options.receiverPublicKey,
      options.tokenIdentifier,
      options.amount,
      options.tokens,
    ),
  ];
  if (available > options.amount) {
    partialTokenOutputs.push(
      partialOutput(
        options.senderPublicKey,
        options.tokenIdentifier,
        available - options.amount,
        options.tokens,
      ),
    );
  }

  return create(PartialTokenTransactionSchema, {
    version: TOKEN_VERSION,
    tokenTransactionMetadata: create(TokenTransactionMetadataSchema, {
      network: sparkNetworkProto(options.network),
      sparkOperatorIdentityPublicKeys: sortedOperatorKeys(options.operators),
      validityDurationSeconds: BigInt(options.tokens.validityDurationSeconds),
      clientCreatedTimestamp: timestampFromMs(options.now()),
      invoiceAttachments: [],
    }),
    tokenInputs: {
      case: "transferInput",
      value: {
        outputsToSpend: inputs.map((output) => ({
          prevTokenTransactionHash: output.prevTransactionHash,
          prevTokenTransactionVout: output.prevTransactionVout,
        })),
      },
    },
    partialTokenOutputs,
  });
}

function signatureCount(partial: PartialTokenTransaction): number {
  // The SO requires exactly one owner signature per input index: every spent output for a
  // transfer, index 0 for mint/create (spark/so/handler/tokens/
  // internal_prepare_token_handler.go, validateTransferOwnerSignatures).
  if (partial.tokenInputs.case === "transferInput") {
    return partial.tokenInputs.value.outputsToSpend.length;
  }
  if (partial.tokenInputs.case === "mintInput" || partial.tokenInputs.case === "createInput") {
    return 1;
  }
  throw new SparkInputError("token transaction inputs: missing or unknown case");
}

function sameOutputs(final: FinalTokenTransaction, partial: PartialTokenTransaction): boolean {
  if (final.finalTokenOutputs.length !== partial.partialTokenOutputs.length) {
    return false;
  }
  return partial.partialTokenOutputs.every((expected, index) => {
    const actual = final.finalTokenOutputs[index]?.partialTokenOutput;
    return (
      actual !== undefined &&
      equalBytes(actual.ownerPublicKey, expected.ownerPublicKey) &&
      equalBytes(actual.tokenIdentifier, expected.tokenIdentifier) &&
      equalBytes(actual.tokenAmount, expected.tokenAmount) &&
      actual.withdrawBondSats === expected.withdrawBondSats &&
      actual.withdrawRelativeBlockLocktime === expected.withdrawRelativeBlockLocktime
    );
  });
}

function sameInputs(final: FinalTokenTransaction, partial: PartialTokenTransaction): boolean {
  if (partial.tokenInputs.case === "transferInput" && final.tokenInputs.case === "transferInput") {
    const expected = partial.tokenInputs.value.outputsToSpend;
    const actual = final.tokenInputs.value.outputsToSpend;
    return (
      expected.length === actual.length &&
      expected.every((input, index) => {
        const actualInput = actual[index];
        return (
          actualInput !== undefined &&
          equalBytes(input.prevTokenTransactionHash, actualInput.prevTokenTransactionHash) &&
          input.prevTokenTransactionVout === actualInput.prevTokenTransactionVout
        );
      })
    );
  }
  return final.tokenInputs.case === partial.tokenInputs.case;
}

/**
 * `broadcast_transaction` — signs the partial transaction's hash once per input index with the
 * identity key (BIP-340), submits it to the coordinator, and verifies the returned final
 * transaction carries the same inputs, outputs (order, owner, identifier, amount, withdraw
 * bond/locktime), network, operator set, and validity duration. Returns the hex
 * `hashFinalTokenTransaction` plus the raw token identifier the SO returns on create transactions.
 */
export async function broadcastPartialTokenTransaction(options: {
  readonly token: Client<typeof SparkTokenService>;
  readonly signer: SparkSigner;
  readonly partial: PartialTokenTransaction;
  readonly network: SparkNetwork;
  readonly operators: ReadonlyArray<SparkOperatorConfig>;
  readonly tokens: TokenNetworkParams;
  readonly call?: CallOptions;
}): Promise<{ transactionHash: string; tokenIdentifier?: Uint8Array }> {
  const { partial } = options;
  const metadata = partial.tokenTransactionMetadata;
  if (metadata === undefined) {
    throw new SparkInputError("token transaction: missing metadata");
  }

  const bytes = toBinary(PartialTokenTransactionSchema, partial);
  const signature = await options.signer.signIdentity({
    kind: "token-transaction",
    partialTransaction: bytes,
  });
  // Every input index signs the same digest with the same identity key, so one
  // signature serves each index the SO expects (all inputs are identity-owned).
  const ownerSignatures: SignatureWithIndex[] = [];
  for (let index = 0; index < signatureCount(partial); index += 1) {
    ownerSignatures.push(create(SignatureWithIndexSchema, { signature, inputIndex: index }));
  }

  const response = await options.token.broadcast_transaction(
    {
      identityPublicKey: await options.signer.identityPublicKey(),
      partialTokenTransaction: partial,
      tokenTransactionOwnerSignatures: ownerSignatures,
    },
    options.call,
  );

  const final = response.finalTokenTransaction;
  if (final === undefined) {
    throw new SparkError("broadcast_transaction: response missing final token transaction");
  }
  const finalMetadata = final.tokenTransactionMetadata;
  if (
    final.version !== partial.version ||
    !sameInputs(final, partial) ||
    !sameOutputs(final, partial) ||
    finalMetadata === undefined ||
    finalMetadata.network !== metadata.network ||
    finalMetadata.validityDurationSeconds !== metadata.validityDurationSeconds ||
    finalMetadata.sparkOperatorIdentityPublicKeys.length !==
      metadata.sparkOperatorIdentityPublicKeys.length ||
    !metadata.sparkOperatorIdentityPublicKeys.every((key, index) =>
      equalBytes(key, finalMetadata.sparkOperatorIdentityPublicKeys[index] ?? new Uint8Array()),
    )
  ) {
    throw new SparkError(
      `broadcast_transaction: final transaction ${bytesToHex(
        hashFinalTokenTransaction(final),
      )} does not match the submitted partial`,
    );
  }
  return {
    transactionHash: bytesToHex(hashFinalTokenTransaction(final)),
    ...(response.tokenIdentifier === undefined
      ? {}
      : { tokenIdentifier: response.tokenIdentifier }),
  };
}
