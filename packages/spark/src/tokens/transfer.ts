import { create, toBinary } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import type { CallOptions, Client } from "@connectrpc/connect";
import { equalBytes, numberToBytesBE } from "@noble/curves/utils.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { compareBytes } from "../core/bytes.ts";
import { hashFinalTokenTransaction, hashTokenTransactionV3 } from "../core/hashing/token.ts";
import { sparkNetworkProto } from "../core/network.ts";
import type { SparkNetwork, SparkOperatorConfig } from "../core/network.ts";
import { SparkError, SparkInputError, SparkRequestError } from "../errors/index.ts";
import { Order } from "../proto/gen/spark_pb.ts";
import type {
  BroadcastTransactionResponse,
  FinalTokenTransaction,
  PartialTokenOutput,
  PartialTokenTransaction,
  SignatureWithIndex,
  SparkTokenService,
  TokenOutputToSpend,
  TokenTransaction,
} from "../proto/gen/spark_token_pb.ts";
import {
  TokenTransactionStatus,
  InvoiceAttachmentSchema,
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
export const MAX_TOKEN_OUTPUTS_TX = 500;
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
  const available = outputs.filter((output) => output.status === "available");
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
 * the network config. Invoice attachments are attached sorted by plain string order, matching
 * upstream sortInvoiceAttachments.
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
  /** Invoice address strings this transfer pays; attached sorted by plain string order. */
  readonly invoiceAttachments?: ReadonlyArray<string>;
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
      invoiceAttachments: [...(options.invoiceAttachments ?? [])]
        .sort()
        .map((sparkInvoice) => create(InvoiceAttachmentSchema, { sparkInvoice })),
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

function sameInvoiceAttachments(
  final: FinalTokenTransaction,
  partial: PartialTokenTransaction,
): boolean {
  const expected = (partial.tokenTransactionMetadata?.invoiceAttachments ?? []).map(
    (attachment) => attachment.sparkInvoice,
  );
  const actual = (final.tokenTransactionMetadata?.invoiceAttachments ?? []).map(
    (attachment) => attachment.sparkInvoice,
  );
  return (
    expected.length === actual.length &&
    expected.every((invoice, index) => invoice === actual[index])
  );
}

/**
 * Errors the SO raises only when the broadcast cannot have committed. Everything else — transport
 * failures, deadlines, `aborted` preemption races, malformed responses — may follow a server-side
 * commit and is recovered by re-broadcast + probe.
 */
const DEFINITIVE_BROADCAST_CODES: ReadonlySet<string> = new Set([
  "invalid_argument",
  "failed_precondition",
  "already_exists",
  "not_found",
  "unauthenticated",
  "permission_denied",
  "out_of_range",
  "unimplemented",
]);

function isDefinitiveBroadcastRejection(error: unknown): boolean {
  return error instanceof SparkRequestError && DEFINITIVE_BROADCAST_CODES.has(error.code ?? "");
}

function assertFinalMatchesPartial(
  final: FinalTokenTransaction | undefined,
  partial: PartialTokenTransaction,
): asserts final is FinalTokenTransaction {
  if (final === undefined) {
    throw new SparkError("broadcast_transaction: response missing final token transaction");
  }
  const metadata = partial.tokenTransactionMetadata;
  const finalMetadata = final.tokenTransactionMetadata;
  if (
    final.version !== partial.version ||
    !sameInputs(final, partial) ||
    !sameOutputs(final, partial) ||
    !sameInvoiceAttachments(final, partial) ||
    metadata === undefined ||
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
}

/** Multiset equality over (prev hash, vout) — order-insensitive. */
function sameInputSet(
  actual: ReadonlyArray<TokenOutputToSpend>,
  expected: ReadonlyArray<TokenOutputToSpend>,
): boolean {
  if (actual.length !== expected.length) {
    return false;
  }
  const remaining = [...actual];
  for (const input of expected) {
    const index = remaining.findIndex(
      (candidate) =>
        equalBytes(candidate.prevTokenTransactionHash, input.prevTokenTransactionHash) &&
        candidate.prevTokenTransactionVout === input.prevTokenTransactionVout,
    );
    if (index === -1) {
      return false;
    }
    remaining.splice(index, 1);
  }
  return true;
}

/** `sameOutputs` over the V2 `TokenOutput` shape a committed transaction carries. */
function sameV2Outputs(tx: TokenTransaction, partial: PartialTokenTransaction): boolean {
  if (tx.tokenOutputs.length !== partial.partialTokenOutputs.length) {
    return false;
  }
  return partial.partialTokenOutputs.every((expected, index) => {
    const actual = tx.tokenOutputs[index];
    return (
      actual !== undefined &&
      equalBytes(actual.ownerPublicKey, expected.ownerPublicKey) &&
      equalBytes(actual.tokenIdentifier ?? new Uint8Array(), expected.tokenIdentifier) &&
      equalBytes(actual.tokenAmount, expected.tokenAmount) &&
      (actual.withdrawBondSats ?? 0n) === expected.withdrawBondSats &&
      (actual.withdrawRelativeBlockLocktime ?? 0n) === expected.withdrawRelativeBlockLocktime
    );
  });
}

/**
 * `query_token_transactions` probe for a broadcast whose response may have been lost: the
 * output-ids filter returns transactions that spent OR created the given outputs, so candidates
 * must be live (non-cancelled) transfers whose input set equals the partial's. A live match with
 * different outputs means an unknown transaction consumed the inputs — fail loudly rather than let
 * a retry double-pay.
 */
async function probeCommittedTransfer(options: {
  readonly token: Client<typeof SparkTokenService>;
  readonly partial: PartialTokenTransaction;
  readonly inputOutputIds: ReadonlyArray<string>;
  readonly call?: CallOptions;
}): Promise<{ transactionHash: string } | undefined> {
  const inputs = options.partial.tokenInputs;
  if (inputs.case !== "transferInput") {
    return undefined;
  }
  const expectedInputs = inputs.value.outputsToSpend;
  const response = await options.token.query_token_transactions(
    {
      queryType: {
        case: "byFilters",
        value: { outputIds: [...options.inputOutputIds] },
      },
      outputIds: [],
      ownerPublicKeys: [],
      issuerPublicKeys: [],
      tokenIdentifiers: [],
      tokenTransactionHashes: [],
      order: Order.DESCENDING,
      limit: 128n,
      offset: 0n,
    },
    options.call,
  );
  for (const row of response.tokenTransactionsWithStatus) {
    if (
      row.status === TokenTransactionStatus.TOKEN_TRANSACTION_STARTED_CANCELLED ||
      row.status === TokenTransactionStatus.TOKEN_TRANSACTION_SIGNED_CANCELLED
    ) {
      continue;
    }
    const tx = row.tokenTransaction;
    if (tx === undefined || tx.tokenInputs.case !== "transferInput") {
      continue;
    }
    const actualInputs = tx.tokenInputs.value.outputsToSpend;
    const spendsOurs = actualInputs.some((actual) =>
      expectedInputs.some(
        (expected) =>
          equalBytes(expected.prevTokenTransactionHash, actual.prevTokenTransactionHash) &&
          expected.prevTokenTransactionVout === actual.prevTokenTransactionVout,
      ),
    );
    if (!spendsOurs) {
      continue;
    }
    const hash =
      row.tokenTransactionHash.length > 0
        ? bytesToHex(row.tokenTransactionHash)
        : bytesToHex(hashTokenTransactionV3(tx));
    if (sameInputSet(actualInputs, expectedInputs) && sameV2Outputs(tx, options.partial)) {
      return { transactionHash: hash };
    }
    throw new SparkError(
      `broadcast_transaction: inputs were consumed by a different token transaction ${hash}`,
    );
  }
  return undefined;
}

/**
 * `broadcast_transaction` — signs the partial transaction's hash once per input index with the
 * identity key (BIP-340), submits it to the coordinator, and verifies the returned final
 * transaction carries the same inputs, outputs (order, owner, identifier, amount, withdraw
 * bond/locktime), invoice attachments, network, operator set, and validity duration. Returns the
 * hex `hashFinalTokenTransaction` plus the raw token identifier the SO returns on create
 * transactions.
 *
 * When `inputOutputIds` carries the ids of the spent outputs (`SparkTokenOutput.id`) a
 * non-definitive broadcast failure recovers instead of losing the transaction: the identical
 * partial is re-broadcast once — the SO dedups by partial-transaction hash
 * (`handleExistingTransaction`, spark/so/handler/tokens/broadcast_token_handler.go) — and if that
 * also fails, `query_token_transactions` is probed for a committed transaction spending exactly
 * those inputs. Matching receiver/change outputs return the committed hash; a live transaction
 * spending them with different outputs throws. When neither resolves the failure the thrown
 * {@link SparkRequestError} names the input output ids — check `tokens.outputs()` before retrying,
 * because a fresh call would select different outputs and pay twice.
 */
export async function broadcastPartialTokenTransaction(options: {
  readonly token: Client<typeof SparkTokenService>;
  readonly signer: SparkSigner;
  readonly partial: PartialTokenTransaction;
  readonly network: SparkNetwork;
  readonly operators: ReadonlyArray<SparkOperatorConfig>;
  readonly tokens: TokenNetworkParams;
  readonly call?: CallOptions;
  /** Output ids of the spent inputs; enables lost-response recovery (transfers only). */
  readonly inputOutputIds?: ReadonlyArray<string>;
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

  const request = {
    identityPublicKey: await options.signer.identityPublicKey(),
    partialTokenTransaction: partial,
    tokenTransactionOwnerSignatures: ownerSignatures,
  };
  const attempt = async (): Promise<{
    response: BroadcastTransactionResponse;
    final: FinalTokenTransaction;
  }> => {
    const response = await options.token.broadcast_transaction(request, options.call);
    const final = response.finalTokenTransaction;
    assertFinalMatchesPartial(final, partial);
    return { response, final };
  };

  let committed: { response: BroadcastTransactionResponse; final: FinalTokenTransaction };
  try {
    committed = await attempt();
  } catch (error) {
    const { inputOutputIds } = options;
    if (
      inputOutputIds === undefined ||
      partial.tokenInputs.case !== "transferInput" ||
      isDefinitiveBroadcastRejection(error)
    ) {
      throw error;
    }
    try {
      committed = await attempt();
    } catch (retryError) {
      if (isDefinitiveBroadcastRejection(retryError)) {
        throw retryError;
      }
      let recovered: { transactionHash: string } | undefined;
      try {
        recovered = await probeCommittedTransfer({
          token: options.token,
          partial,
          inputOutputIds,
          ...(options.call === undefined ? {} : { call: options.call }),
        });
      } catch (probeError) {
        // A failed query tells us nothing — fall through to the error that carries the input
        // output ids. The probe's own verdict (inputs consumed by a different transaction) is a
        // SparkError and must still propagate.
        if (!(probeError instanceof SparkRequestError)) {
          throw probeError;
        }
        recovered = undefined;
      }
      if (recovered !== undefined) {
        return recovered;
      }
      const requestOptions: ErrorOptions & { code?: string; operator?: string } = {
        cause: error,
      };
      if (error instanceof SparkRequestError) {
        if (error.code !== undefined) {
          requestOptions.code = error.code;
        }
        if (error.operator !== undefined) {
          requestOptions.operator = error.operator;
        }
      }
      throw new SparkRequestError(
        `broadcast_transaction may have committed; check tokens.outputs() for input output ids ${inputOutputIds.join(
          ",",
        )} before retrying`,
        requestOptions,
      );
    }
  }

  return {
    transactionHash: bytesToHex(hashFinalTokenTransaction(committed.final)),
    ...(committed.response.tokenIdentifier === undefined
      ? {}
      : { tokenIdentifier: committed.response.tokenIdentifier }),
  };
}
