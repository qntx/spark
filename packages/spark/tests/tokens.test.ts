import { create } from "@bufbuild/protobuf";
import type { MessageInitShape } from "@bufbuild/protobuf";
import type { Client } from "@connectrpc/connect";
import { createRouterTransport } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { createSparkClientWith } from "../src/client/index.ts";
import { encodeSparkAddress } from "../src/core/address.ts";
import { hashFinalTokenTransaction } from "../src/core/hashing/token.ts";
import type { SparkOperatorConfig } from "../src/core/network.ts";
import {
  SparkError,
  SparkInputError,
  SparkRequestError,
  SparkTokenBroadcastError,
} from "../src/errors/index.ts";
import {
  ChallengeSchema,
  ProtectedChallengeSchema,
  SparkAuthnService,
} from "../src/proto/gen/spark_authn_pb.ts";
import { Network, PageResponseSchema } from "../src/proto/gen/spark_pb.ts";
import {
  CommitStatus,
  QueryTokenOutputsResponseSchema,
  SparkTokenService,
  TokenOutputStatus,
  TokenTransactionStatus,
} from "../src/proto/gen/spark_token_pb.ts";
import type {
  BroadcastTransactionResponse,
  FinalTokenTransaction,
  PartialTokenOutput,
  PartialTokenTransaction,
  QueryTokenOutputsResponse,
  TokenOutput,
  TokenTransaction,
  TokenTransactionWithStatus,
  BroadcastTransactionRequestSchema,
  BroadcastTransactionRequest,
} from "../src/proto/gen/spark_token_pb.ts";
import {
  buildTransferPartial,
  broadcastPartialTokenTransaction,
  MAX_TOKEN_OUTPUTS_TX,
  selectTokenOutputs,
  transferWithInputIds,
} from "../src/tokens/index.ts";
import type { SparkTokenOutput, TokenNetworkParams } from "../src/tokens/index.ts";
import { createTestSigner } from "./support/test-signer.ts";

type BroadcastTxInit = MessageInitShape<typeof BroadcastTransactionRequestSchema>;

function required<T>(value: T | undefined, name: string): T {
  if (value === undefined) {
    throw new Error(`expected ${name}`);
  }
  return value;
}

function byteCompare(a: Uint8Array, b: Uint8Array): number {
  const shared = Math.min(a.length, b.length);
  for (let i = 0; i < shared; i += 1) {
    if (a[i] !== b[i]) {
      return (a[i] ?? 0) - (b[i] ?? 0);
    }
  }
  return a.length - b.length;
}

function ownerSignatureEntries(request: BroadcastTxInit | undefined) {
  return request?.tokenTransactionOwnerSignatures ?? [];
}

function spentOutputs(partial: PartialTokenTransaction) {
  if (partial.tokenInputs.case !== "transferInput") {
    throw new Error("expected a transfer input");
  }
  return partial.tokenInputs.value.outputsToSpend;
}

const COORDINATOR_ID = "0000000000000000000000000000000000000000000000000000000000000001";
const OPERATORS: ReadonlyArray<SparkOperatorConfig> = [
  {
    id: 0,
    identifier: COORDINATOR_ID,
    address: "https://op0.test",
    identityPublicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(9), true),
  },
  {
    id: 1,
    identifier: "0000000000000000000000000000000000000000000000000000000000000002",
    address: "https://op1.test",
    identityPublicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(8), true),
  },
  {
    id: 2,
    identifier: "0000000000000000000000000000000000000000000000000000000000000003",
    address: "https://op2.test",
    identityPublicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(7), true),
  },
];

const TOKENS: TokenNetworkParams = {
  withdrawBondSats: 10_000,
  withdrawRelativeBlockLocktime: 1000,
  validityDurationSeconds: 180,
};

const TOKEN_ID = hexToBytes("ab".repeat(32));
const OTHER_TOKEN_ID = hexToBytes("cd".repeat(32));
const OWNER = secp256k1.getPublicKey(new Uint8Array(32).fill(3), true);
const RECEIVER = secp256k1.getPublicKey(new Uint8Array(32).fill(4), true);

function makeOutput(
  id: string,
  amount: bigint,
  overrides?: {
    tokenIdentifier?: Uint8Array;
    prevVout?: number;
    status?: "available" | "pending-outbound" | "unknown";
  },
): SparkTokenOutput {
  return {
    id,
    tokenIdentifier: overrides?.tokenIdentifier ?? TOKEN_ID,
    amount,
    prevTransactionHash: hexToBytes("ee".repeat(32)),
    prevTransactionVout: overrides?.prevVout ?? 0,
    ownerPublicKey: OWNER,
    status: overrides?.status ?? "available",
  };
}

describe("selectTokenOutputs", () => {
  test("returns the single exact match", () => {
    const outputs = [makeOutput("a", 30n), makeOutput("b", 50n), makeOutput("c", 90n)];
    expect(selectTokenOutputs(outputs, 50n).map((o) => o.id)).toStrictEqual(["b"]);
  });

  test("accumulates smallest-first until the amount is covered", () => {
    const outputs = [makeOutput("a", 90n), makeOutput("b", 30n), makeOutput("c", 50n)];
    expect(selectTokenOutputs(outputs, 60n).map((o) => o.id)).toStrictEqual(["b", "c"]);
  });

  test("skips pending-outbound and unknown outputs", () => {
    const outputs = [
      makeOutput("a", 50n),
      makeOutput("b", 50n, { status: "pending-outbound" }),
      // An enum value the SDK does not recognize must never be spendable.
      makeOutput("c", 50n, { status: "unknown" }),
    ];
    expect(() => selectTokenOutputs(outputs, 80n)).toThrow(SparkInputError);
    expect(selectTokenOutputs(outputs, 50n).map((o) => o.id)).toStrictEqual(["a"]);
  });

  test("rejects zero and insufficient amounts", () => {
    const outputs = [makeOutput("a", 10n)];
    expect(() => selectTokenOutputs(outputs, 0n)).toThrow(SparkInputError);
    expect(() => selectTokenOutputs(outputs, 11n)).toThrow(SparkInputError);
    expect(() => selectTokenOutputs(outputs, 1n << 128n)).toThrow(SparkInputError);
  });
});

function makeTransferPartial(options?: {
  inputs?: SparkTokenOutput[];
  amount?: bigint;
}): PartialTokenTransaction {
  return buildTransferPartial({
    selectedOutputs: options?.inputs ?? [makeOutput("a", 100n)],
    receiverPublicKey: RECEIVER,
    tokenIdentifier: TOKEN_ID,
    amount: options?.amount ?? 40n,
    senderPublicKey: OWNER,
    network: "regtest",
    operators: OPERATORS,
    tokens: TOKENS,
    now: () => 1_700_000_123_456,
  });
}

describe("buildTransferPartial", () => {
  const partial = makeTransferPartial();

  test("builds a V3 partial with the network metadata and sorted operator keys", () => {
    expect(partial.version).toBe(3);
    const metadata = partial.tokenTransactionMetadata;
    expect(metadata?.network).toBe(Network.REGTEST);
    expect(metadata?.validityDurationSeconds).toBe(180n);
    expect(metadata?.invoiceAttachments).toHaveLength(0);
    const sorted = [...OPERATORS].map((o) => o.identityPublicKey).toSorted(byteCompare);
    expect(metadata?.sparkOperatorIdentityPublicKeys.map(bytesToHex)).toStrictEqual(
      sorted.map(bytesToHex),
    );
    expect(metadata?.clientCreatedTimestamp?.seconds).toBe(1_700_000_123n);
    expect(metadata?.clientCreatedTimestamp?.nanos).toBe(456_000_000);
  });

  test("receiver output first, change output back to sender", () => {
    const [receiverOut, changeOut] = partial.partialTokenOutputs;
    expect(receiverOut?.ownerPublicKey).toStrictEqual(RECEIVER);
    expect(receiverOut?.tokenIdentifier).toStrictEqual(TOKEN_ID);
    expect(receiverOut?.tokenAmount).toStrictEqual(numberToBytesBE(40n, 16));
    expect(receiverOut?.withdrawBondSats).toBe(10_000n);
    expect(receiverOut?.withdrawRelativeBlockLocktime).toBe(1000n);
    expect(changeOut?.ownerPublicKey).toStrictEqual(OWNER);
    expect(changeOut?.tokenAmount).toStrictEqual(numberToBytesBE(60n, 16));
  });

  test("exact spends produce no change output", () => {
    const exact = makeTransferPartial({ amount: 100n });
    expect(exact.partialTokenOutputs).toHaveLength(1);
  });

  test("inputs are sorted by previous vout", () => {
    const inputs = [
      makeOutput("high", 10n, { prevVout: 5 }),
      makeOutput("low", 10n, { prevVout: 1 }),
    ];
    const built = makeTransferPartial({ inputs, amount: 15n });
    const spent = spentOutputs(built);
    expect(spent.map((o) => o.prevTokenTransactionVout)).toStrictEqual([1, 5]);
  });

  test("rejects mixed token identifiers and underfunded selections", () => {
    expect(() =>
      makeTransferPartial({
        inputs: [makeOutput("a", 50n), makeOutput("b", 50n, { tokenIdentifier: OTHER_TOKEN_ID })],
        amount: 60n,
      }),
    ).toThrow(SparkInputError);
    expect(() => makeTransferPartial({ amount: 101n })).toThrow(SparkInputError);
  });
});

/** Builds the final transaction the SO would return for `partial` (echo + SO fields). */
function finalFor(
  partial: PartialTokenTransaction,
  mutate?: (output: PartialTokenOutput) => PartialTokenOutput,
): FinalTokenTransaction {
  return {
    $typeName: "spark_token.FinalTokenTransaction",
    version: partial.version,
    tokenTransactionMetadata: partial.tokenTransactionMetadata,
    tokenInputs: partial.tokenInputs,
    finalTokenOutputs: partial.partialTokenOutputs.map((output) => ({
      $typeName: "spark_token.FinalTokenOutput" as const,
      partialTokenOutput: mutate === undefined ? output : mutate(output),
      revocationCommitment: new Uint8Array(33).fill(2),
    })),
  };
}

function fakeTokenClient(
  broadcast: (req: BroadcastTxInit) => BroadcastTransactionResponse,
): Client<typeof SparkTokenService> {
  return {
    broadcast_transaction: async (req) => {
      await Promise.resolve();
      return broadcast(req);
    },
  } as Client<typeof SparkTokenService>;
}

describe("broadcastPartialTokenTransaction", () => {
  const partial = makeTransferPartial();
  const signer = createTestSigner(new Uint8Array(32).fill(7));

  test("signs once per input index and returns the final hash", async () => {
    const inputs = [makeOutput("a", 10n), makeOutput("b", 30n), makeOutput("c", 60n)];
    const built = makeTransferPartial({ inputs, amount: 50n });
    const final = finalFor(built);
    const expectedHash = bytesToHex(hashFinalTokenTransaction(final));
    let seenRequest: BroadcastTxInit | undefined;
    const token = fakeTokenClient((req) => {
      seenRequest = req;
      return {
        commitStatus: CommitStatus.COMMIT_FINALIZED,
        $typeName: "spark_token.BroadcastTransactionResponse",
        finalTokenTransaction: final,
      };
    });
    const { transactionHash: hash } = await broadcastPartialTokenTransaction({
      token,
      signer,
      partial: built,
      network: "regtest",
      operators: OPERATORS,
      tokens: TOKENS,
    });
    expect(hash).toBe(expectedHash);
    const signatures = ownerSignatureEntries(seenRequest);
    expect(signatures.map((s) => s.inputIndex)).toStrictEqual([0, 1, 2]);
    for (const entry of signatures) {
      expect(entry.signature).toHaveLength(64);
      expect(entry.signature).toStrictEqual(signatures[0]!.signature);
    }
    expect(seenRequest?.identityPublicKey).toStrictEqual(await signer.identityPublicKey());
  });

  test("rejects a final transaction whose outputs do not match the partial", async () => {
    const tampered = finalFor(partial, (output) => ({
      ...output,
      tokenAmount: numberToBytesBE(1n, 16),
    }));
    const token = fakeTokenClient(() => ({
      $typeName: "spark_token.BroadcastTransactionResponse",
      commitStatus: CommitStatus.COMMIT_FINALIZED,
      finalTokenTransaction: tampered,
    }));
    await expect(
      broadcastPartialTokenTransaction({
        token,
        signer,
        partial,
        network: "regtest",
        operators: OPERATORS,
        tokens: TOKENS,
      }),
    ).rejects.toThrow(SparkError);
  });

  test("rejects a missing final transaction", async () => {
    const token = fakeTokenClient(() => ({
      $typeName: "spark_token.BroadcastTransactionResponse",
      commitStatus: CommitStatus.COMMIT_FINALIZED,
    }));
    await expect(
      broadcastPartialTokenTransaction({
        token,
        signer,
        partial,
        network: "regtest",
        operators: OPERATORS,
        tokens: TOKENS,
      }),
    ).rejects.toThrow(SparkError);
  });

  test("rejects a final transaction on the wrong network", async () => {
    const wrong: FinalTokenTransaction = {
      ...finalFor(partial),
      tokenTransactionMetadata: {
        ...partial.tokenTransactionMetadata!,
        network: Network.MAINNET,
      },
    };
    const token = fakeTokenClient(() => ({
      $typeName: "spark_token.BroadcastTransactionResponse",
      commitStatus: CommitStatus.COMMIT_FINALIZED,
      finalTokenTransaction: wrong,
    }));
    await expect(
      broadcastPartialTokenTransaction({
        token,
        signer,
        partial,
        network: "regtest",
        operators: OPERATORS,
        tokens: TOKENS,
      }),
    ).rejects.toThrow(SparkError);
  });
});

/** Builds the V2-shape committed transaction `query_token_transactions` would return. */
function v2TxFor(
  partial: PartialTokenTransaction,
  mutate?: (output: PartialTokenOutput) => PartialTokenOutput,
): TokenTransaction {
  const metadata = required(partial.tokenTransactionMetadata, "metadata");
  return {
    $typeName: "spark_token.TokenTransaction",
    version: partial.version,
    tokenInputs: partial.tokenInputs,
    tokenOutputs: partial.partialTokenOutputs.map((output) => {
      const resolved = mutate === undefined ? output : mutate(output);
      const tokenOutput: TokenOutput = {
        $typeName: "spark_token.TokenOutput",
        ownerPublicKey: resolved.ownerPublicKey,
        tokenIdentifier: resolved.tokenIdentifier,
        tokenAmount: resolved.tokenAmount,
        withdrawBondSats: resolved.withdrawBondSats,
        withdrawRelativeBlockLocktime: resolved.withdrawRelativeBlockLocktime,
      };
      return tokenOutput;
    }),
    sparkOperatorIdentityPublicKeys: metadata.sparkOperatorIdentityPublicKeys,
    network: metadata.network,
    clientCreatedTimestamp: metadata.clientCreatedTimestamp,
    validityDurationSeconds: metadata.validityDurationSeconds,
    invoiceAttachments: metadata.invoiceAttachments,
  };
}

function statusRow(
  tx: TokenTransaction,
  status: (typeof TokenTransactionStatus)[keyof typeof TokenTransactionStatus],
  hash: Uint8Array,
): TokenTransactionWithStatus {
  return {
    $typeName: "spark_token.TokenTransactionWithStatus",
    tokenTransaction: tx,
    status,
    tokenTransactionHash: hash,
  };
}

function recoverableTokenClient(handlers: {
  readonly broadcasts: ReadonlyArray<() => BroadcastTransactionResponse>;
  readonly rows?: ReadonlyArray<TokenTransactionWithStatus>;
  readonly queryError?: SparkRequestError;
}): {
  client: Client<typeof SparkTokenService>;
  broadcastCalls: () => number;
  queryCalls: () => number;
} {
  let broadcastCalls = 0;
  let queryCalls = 0;
  const client = {
    broadcast_transaction: async () => {
      await Promise.resolve();
      const behavior =
        handlers.broadcasts[Math.min(broadcastCalls, handlers.broadcasts.length - 1)];
      broadcastCalls += 1;
      return required(behavior, "broadcast behavior")();
    },
    query_token_transactions: async (req: { limit: bigint; offset: bigint }) => {
      await Promise.resolve();
      queryCalls += 1;
      if (handlers.queryError !== undefined) {
        throw handlers.queryError;
      }
      const rows = handlers.rows ?? [];
      const limit = Number(req.limit);
      const offset = Number(req.offset);
      const page = rows.slice(offset, offset + limit);
      return {
        $typeName: "spark_token.QueryTokenTransactionsResponse",
        tokenTransactionsWithStatus: [...page],
        offset: page.length === limit ? BigInt(offset + page.length) : -1n,
      };
    },
  } as unknown as Client<typeof SparkTokenService>;
  return { client, broadcastCalls: () => broadcastCalls, queryCalls: () => queryCalls };
}

const LOST = () => {
  throw new SparkRequestError("connection lost mid-response", { code: "unavailable" });
};

describe("broadcastPartialTokenTransaction recovery", () => {
  const inputs = [makeOutput("out-1", 60n), makeOutput("out-2", 40n)];
  const partial = makeTransferPartial({ inputs, amount: 70n });
  const inputIds = inputs.map((output) => output.id);
  const committedHash = hexToBytes("11".repeat(32));
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const broadcastOptions = {
    signer,
    partial,
    network: "regtest" as const,
    operators: OPERATORS,
    tokens: TOKENS,
    inputOutputIds: inputIds,
  };

  test("retries the identical partial once and returns on success", async () => {
    const final = finalFor(partial);
    const { client, broadcastCalls, queryCalls } = recoverableTokenClient({
      broadcasts: [
        LOST,
        () => ({
          $typeName: "spark_token.BroadcastTransactionResponse",
          commitStatus: CommitStatus.COMMIT_FINALIZED,
          finalTokenTransaction: final,
        }),
      ],
    });
    const { transactionHash } = await broadcastPartialTokenTransaction({
      token: client,
      ...broadcastOptions,
    });
    expect(transactionHash).toBe(bytesToHex(hashFinalTokenTransaction(final)));
    expect(broadcastCalls()).toBe(2);
    expect(queryCalls()).toBe(0);
  });

  test("lost response: probe finds the committed transaction and returns its hash", async () => {
    const { client, broadcastCalls, queryCalls } = recoverableTokenClient({
      broadcasts: [LOST],
      rows: [
        // The output-ids filter also returns the mint that created the input — it must be skipped.
        statusRow(
          {
            $typeName: "spark_token.TokenTransaction",
            version: 3,
            tokenInputs: {
              case: "mintInput",
              value: {
                $typeName: "spark_token.TokenMintInput",
                issuerPublicKey: OWNER,
                tokenIdentifier: TOKEN_ID,
              },
            },
            tokenOutputs: [],
            sparkOperatorIdentityPublicKeys: [],
            network: Network.REGTEST,
            invoiceAttachments: [],
          },
          TokenTransactionStatus.TOKEN_TRANSACTION_FINALIZED,
          hexToBytes("22".repeat(32)),
        ),
        statusRow(
          v2TxFor(partial),
          TokenTransactionStatus.TOKEN_TRANSACTION_FINALIZED,
          committedHash,
        ),
      ],
    });
    const { transactionHash } = await broadcastPartialTokenTransaction({
      token: client,
      ...broadcastOptions,
    });
    expect(transactionHash).toBe(bytesToHex(committedHash));
    expect(broadcastCalls()).toBe(2);
    expect(queryCalls()).toBe(1);
  });

  test("probe finding a different transaction over the same inputs throws", async () => {
    const foreign = v2TxFor(partial, (output) => ({
      ...output,
      tokenAmount: numberToBytesBE(1n, 16),
    }));
    const { client } = recoverableTokenClient({
      broadcasts: [LOST],
      rows: [statusRow(foreign, TokenTransactionStatus.TOKEN_TRANSACTION_FINALIZED, committedHash)],
    });
    await expect(
      broadcastPartialTokenTransaction({ token: client, ...broadcastOptions }),
    ).rejects.toThrow(/consumed by a different token transaction/);
  });

  test("lost response with no committed transaction throws naming the input ids", async () => {
    const { client } = recoverableTokenClient({ broadcasts: [LOST], rows: [] });
    const failure = await broadcastPartialTokenTransaction({
      token: client,
      ...broadcastOptions,
    }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(SparkTokenBroadcastError);
    expect((failure as SparkTokenBroadcastError).inputOutputIds).toStrictEqual(["out-1", "out-2"]);
    expect((failure as Error).message).toContain("out-1");
    expect((failure as Error).message).toContain("out-2");
  });

  test("a failed probe still names the input output ids", async () => {
    const { client } = recoverableTokenClient({
      broadcasts: [LOST],
      queryError: new SparkRequestError("still down", { code: "unavailable" }),
    });
    const failure = await broadcastPartialTokenTransaction({
      token: client,
      ...broadcastOptions,
    }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(SparkRequestError);
    expect((failure as Error).message).toContain("out-1");
  });

  test("a cancelled transaction over the inputs does not count as committed", async () => {
    const { client } = recoverableTokenClient({
      broadcasts: [LOST],
      rows: [
        statusRow(
          v2TxFor(partial),
          TokenTransactionStatus.TOKEN_TRANSACTION_SIGNED_CANCELLED,
          committedHash,
        ),
      ],
    });
    await expect(
      broadcastPartialTokenTransaction({ token: client, ...broadcastOptions }),
    ).rejects.toThrow(SparkRequestError);
  });

  test("a matching transaction that has not finalized fails instead of reporting success", async () => {
    const assertPending = async (
      status: (typeof TokenTransactionStatus)[keyof typeof TokenTransactionStatus],
    ): Promise<void> => {
      const { client } = recoverableTokenClient({
        broadcasts: [LOST],
        rows: [statusRow(v2TxFor(partial), status, committedHash)],
      });
      const failure = await broadcastPartialTokenTransaction({
        token: client,
        ...broadcastOptions,
      }).catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(SparkTokenBroadcastError);
      expect((failure as SparkTokenBroadcastError).inputOutputIds).toStrictEqual([
        "out-1",
        "out-2",
      ]);
      expect((failure as Error).message).toContain("still in progress");
      expect((failure as Error).message).toContain(bytesToHex(committedHash));
      expect((failure as Error).message).toContain("out-1");
    };
    await assertPending(TokenTransactionStatus.TOKEN_TRANSACTION_STARTED);
    await assertPending(TokenTransactionStatus.TOKEN_TRANSACTION_SIGNED);
    await assertPending(TokenTransactionStatus.TOKEN_TRANSACTION_REVEALED);
    await assertPending(TokenTransactionStatus.TOKEN_TRANSACTION_UNKNOWN);
  });

  test("a matching row without a transaction hash reports the in-progress tx as pending", async () => {
    const { client } = recoverableTokenClient({
      broadcasts: [LOST],
      rows: [
        statusRow(
          v2TxFor(partial),
          TokenTransactionStatus.TOKEN_TRANSACTION_STARTED,
          new Uint8Array(0),
        ),
      ],
    });
    const failure = await broadcastPartialTokenTransaction({
      token: client,
      ...broadcastOptions,
    }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(SparkRequestError);
    expect((failure as Error).message).toContain("pending");
    expect((failure as Error).message).toContain("still in progress");
  });

  test("definitive rejections are rethrown without retry or probe", async () => {
    const rejected = () => {
      throw new SparkRequestError("invalid signature", { code: "invalid_argument" });
    };
    const { client, broadcastCalls, queryCalls } = recoverableTokenClient({
      broadcasts: [rejected],
      rows: [
        statusRow(
          v2TxFor(partial),
          TokenTransactionStatus.TOKEN_TRANSACTION_FINALIZED,
          committedHash,
        ),
      ],
    });
    await expect(
      broadcastPartialTokenTransaction({ token: client, ...broadcastOptions }),
    ).rejects.toThrow("invalid signature");
    expect(broadcastCalls()).toBe(1);
    expect(queryCalls()).toBe(0);
  });

  test("without input output ids a failure propagates without recovery", async () => {
    const { client, broadcastCalls, queryCalls } = recoverableTokenClient({
      broadcasts: [LOST],
      rows: [
        statusRow(
          v2TxFor(partial),
          TokenTransactionStatus.TOKEN_TRANSACTION_FINALIZED,
          committedHash,
        ),
      ],
    });
    await expect(
      broadcastPartialTokenTransaction({
        token: client,
        signer,
        partial,
        network: "regtest",
        operators: OPERATORS,
        tokens: TOKENS,
      }),
    ).rejects.toThrow("connection lost mid-response");
    expect(broadcastCalls()).toBe(1);
    expect(queryCalls()).toBe(0);
  });
});

/** The transaction that created an output id — vout is its index in `tokenOutputs`. */
function creatorRow(
  id: string,
  vout: number,
  amount: bigint,
  overrides?: {
    readonly owner?: Uint8Array;
    readonly tokenIdentifier?: Uint8Array;
    readonly hash?: Uint8Array;
  },
): TokenTransactionWithStatus {
  const tokenOutputs: TokenOutput[] = [];
  for (let index = 0; index <= vout; index += 1) {
    tokenOutputs.push({
      $typeName: "spark_token.TokenOutput",
      ownerPublicKey: OWNER,
      tokenIdentifier: TOKEN_ID,
      tokenAmount: numberToBytesBE(1n, 16),
      withdrawBondSats: 10_000n,
      withdrawRelativeBlockLocktime: 1000n,
    });
  }
  tokenOutputs[vout] = {
    $typeName: "spark_token.TokenOutput",
    id,
    ownerPublicKey: overrides?.owner ?? OWNER,
    tokenIdentifier: overrides?.tokenIdentifier ?? TOKEN_ID,
    tokenAmount: numberToBytesBE(amount, 16),
    withdrawBondSats: 10_000n,
    withdrawRelativeBlockLocktime: 1000n,
  };
  return statusRow(
    {
      $typeName: "spark_token.TokenTransaction",
      version: 3,
      tokenInputs: {
        case: "mintInput",
        value: {
          $typeName: "spark_token.TokenMintInput",
          issuerPublicKey: OWNER,
          tokenIdentifier: TOKEN_ID,
        },
      },
      tokenOutputs,
      sparkOperatorIdentityPublicKeys: [],
      network: Network.REGTEST,
      invoiceAttachments: [],
    },
    TokenTransactionStatus.TOKEN_TRANSACTION_FINALIZED,
    overrides?.hash ?? hexToBytes("ee".repeat(32)),
  );
}

describe("transferWithInputIds", () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const HASH_1 = hexToBytes("ee".repeat(32));
  const HASH_2 = hexToBytes("dd".repeat(32));
  const creators = [
    creatorRow("out-1", 1, 60n, { hash: HASH_1 }),
    creatorRow("out-2", 0, 40n, { hash: HASH_2 }),
  ];
  const inputIds = ["out-1", "out-2"];
  const committedHash = hexToBytes("11".repeat(32));
  // The partial the retry rebuilds: receiver 70 of 100, 30 change back to the sender.
  const resolved: SparkTokenOutput[] = [
    {
      id: "out-1",
      tokenIdentifier: TOKEN_ID,
      amount: 60n,
      prevTransactionHash: HASH_1,
      prevTransactionVout: 1,
      ownerPublicKey: OWNER,
      status: "available",
    },
    {
      id: "out-2",
      tokenIdentifier: TOKEN_ID,
      amount: 40n,
      prevTransactionHash: HASH_2,
      prevTransactionVout: 0,
      ownerPublicKey: OWNER,
      status: "available",
    },
  ];
  const expectedPartial = makeTransferPartial({ inputs: resolved, amount: 70n });

  function retryClient(handlers: {
    readonly rows?: ReadonlyArray<TokenTransactionWithStatus>;
    readonly broadcast?: (req: BroadcastTransactionRequest) => BroadcastTransactionResponse;
  }) {
    let broadcastCalls = 0;
    const requests: BroadcastTransactionRequest[] = [];
    let queryCalls = 0;
    const client = {
      broadcast_transaction: async (req: BroadcastTransactionRequest) => {
        await Promise.resolve();
        broadcastCalls += 1;
        requests.push(req);
        return required(handlers.broadcast, "broadcast handler")(req);
      },
      query_token_transactions: async (req: { limit: bigint; offset: bigint }) => {
        await Promise.resolve();
        queryCalls += 1;
        const rows = handlers.rows ?? [];
        const limit = Number(req.limit);
        const offset = Number(req.offset);
        const page = rows.slice(offset, offset + limit);
        return {
          $typeName: "spark_token.QueryTokenTransactionsResponse",
          tokenTransactionsWithStatus: [...page],
          offset: page.length === limit ? BigInt(offset + page.length) : -1n,
        };
      },
    } as unknown as Client<typeof SparkTokenService>;
    return {
      client,
      broadcastCalls: () => broadcastCalls,
      queryCalls: () => queryCalls,
      requests: () => requests,
    };
  }

  const retryOptions = {
    signer,
    network: "regtest" as const,
    operators: OPERATORS,
    tokens: TOKENS,
    now: () => 1_700_000_999_000,
    tokenIdentifier: TOKEN_ID,
    receiverPublicKey: RECEIVER,
    senderPublicKey: OWNER,
    inputOutputIds: inputIds,
    amount: 70n,
  };

  test("returns the committed hash without broadcasting when the same transaction finalized", async () => {
    const { client, broadcastCalls } = retryClient({
      rows: [
        ...creators,
        statusRow(
          v2TxFor(expectedPartial),
          TokenTransactionStatus.TOKEN_TRANSACTION_FINALIZED,
          committedHash,
        ),
      ],
    });
    const result = await transferWithInputIds({ token: client, ...retryOptions });
    expect(result.transactionHash).toBe(bytesToHex(committedHash));
    expect(broadcastCalls()).toBe(0);
  });

  test("resolves creators and the spender spread over more than one page", async () => {
    const fillers = Array.from({ length: 100 }, (_, i) =>
      creatorRow(`filler-${i}`, 0, 1n, {
        hash: hexToBytes((i % 256).toString(16).padStart(2, "0").repeat(32)),
      }),
    );
    const { client, broadcastCalls, queryCalls } = retryClient({
      rows: [
        ...fillers,
        ...creators,
        statusRow(
          v2TxFor(expectedPartial),
          TokenTransactionStatus.TOKEN_TRANSACTION_FINALIZED,
          committedHash,
        ),
      ],
    });
    const result = await transferWithInputIds({ token: client, ...retryOptions });
    expect(queryCalls()).toBe(2);
    expect(result.transactionHash).toBe(bytesToHex(committedHash));
    expect(broadcastCalls()).toBe(0);
  });

  test("broadcasts exactly the remembered inputs when nothing committed", async () => {
    const { client, broadcastCalls, requests } = retryClient({
      rows: creators,
      broadcast: (req) => ({
        $typeName: "spark_token.BroadcastTransactionResponse",
        commitStatus: CommitStatus.COMMIT_FINALIZED,
        finalTokenTransaction: finalFor(required(req.partialTokenTransaction, "broadcast partial")),
      }),
    });
    const result = await transferWithInputIds({ token: client, ...retryOptions });
    expect(broadcastCalls()).toBe(1);
    const sent = required(requests()[0], "broadcast request");
    const partialReq = required(sent.partialTokenTransaction, "broadcast partial");
    // Sorted by vout: out-2 (vout 0) before out-1 (vout 1).
    expect(
      spentOutputs(partialReq).map((output) => ({
        hash: bytesToHex(output.prevTokenTransactionHash),
        vout: output.prevTokenTransactionVout,
      })),
    ).toStrictEqual([
      { hash: bytesToHex(HASH_2), vout: 0 },
      { hash: bytesToHex(HASH_1), vout: 1 },
    ]);
    expect(result.transactionHash).toBe(
      bytesToHex(hashFinalTokenTransaction(finalFor(partialReq))),
    );
  });

  test("a still-in-progress transaction over the inputs rethrows with the same ids", async () => {
    const { client, broadcastCalls } = retryClient({
      rows: [
        ...creators,
        statusRow(
          v2TxFor(expectedPartial),
          TokenTransactionStatus.TOKEN_TRANSACTION_SIGNED,
          committedHash,
        ),
      ],
    });
    const failure = await transferWithInputIds({ token: client, ...retryOptions }).catch(
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(SparkTokenBroadcastError);
    expect((failure as SparkTokenBroadcastError).inputOutputIds).toStrictEqual(inputIds);
    expect(broadcastCalls()).toBe(0);
  });

  test("a committed transaction with different outputs over the same inputs throws", async () => {
    const foreign = v2TxFor(expectedPartial, (output) => ({
      ...output,
      tokenAmount: numberToBytesBE(1n, 16),
    }));
    const { client } = retryClient({
      rows: [
        ...creators,
        statusRow(foreign, TokenTransactionStatus.TOKEN_TRANSACTION_FINALIZED, committedHash),
      ],
    });
    await expect(transferWithInputIds({ token: client, ...retryOptions })).rejects.toThrow(
      /consumed by a different token transaction/,
    );
  });

  test("unknown, foreign, and wrong-identifier inputs throw SparkInputError", async () => {
    const { client } = retryClient({
      rows: [creatorRow("out-1", 0, 60n)],
      broadcast: () => {
        throw new Error("unreachable");
      },
    });
    await expect(
      transferWithInputIds({ token: client, ...retryOptions, inputOutputIds: ["out-9"] }),
    ).rejects.toThrow(SparkInputError);
    await expect(
      transferWithInputIds({ token: client, ...retryOptions, inputOutputIds: ["out-1", "out-9"] }),
    ).rejects.toThrow(/out-9/);

    const foreign = retryClient({
      rows: [creatorRow("out-3", 0, 60n, { owner: RECEIVER })],
    });
    await expect(
      transferWithInputIds({ token: foreign.client, ...retryOptions, inputOutputIds: ["out-3"] }),
    ).rejects.toThrow(/not owned by this identity/);

    const wrongToken = retryClient({
      rows: [creatorRow("out-4", 0, 60n, { tokenIdentifier: OTHER_TOKEN_ID })],
    });
    await expect(
      transferWithInputIds({
        token: wrongToken.client,
        ...retryOptions,
        inputOutputIds: ["out-4"],
      }),
    ).rejects.toThrow(/different token identifier/);
  });
});

describe("client.tokens", () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const owner = secp256k1.getPublicKey(new Uint8Array(32).fill(7), true);
  const identifier = "btknrt18aaxwtn6q4smnlv8td08x5xxz0mx49c60suectq6d9p2gljtjmuq7f86q9";
  const rawIdentifier = hexToBytes(
    "3f7a672e7a0561b9fd875b5e7350c613f66a971a7c399c2c1a6942a47e4b96f8",
  );

  function tokenRow(
    id: string,
    amount: bigint,
    tokenIdentifier = rawIdentifier,
    status: TokenOutputStatus = TokenOutputStatus.AVAILABLE,
  ) {
    return {
      $typeName: "spark_token.OutputWithPreviousTransactionData" as const,
      output: {
        $typeName: "spark_token.TokenOutput" as const,
        id,
        ownerPublicKey: owner,
        tokenIdentifier,
        tokenAmount: numberToBytesBE(amount, 16),
        status,
      },
      previousTransactionHash: hexToBytes("ee".repeat(32)),
      previousTransactionVout: 0,
    };
  }

  function clientWith(impl: {
    query?: (req: { tokenIdentifiers: Uint8Array[] }) => QueryTokenOutputsResponse;
    broadcast?: (
      req: BroadcastTransactionRequest,
    ) => BroadcastTransactionResponse | Promise<BroadcastTransactionResponse>;
    transactions?: () => {
      readonly tokenTransactionsWithStatus: ReadonlyArray<TokenTransactionWithStatus>;
    };
  }) {
    return createSparkClientWith(
      {
        network: "regtest",
        signer,
        fetch: async () => {
          await Promise.resolve();
          return new Response("not found", { status: 404 });
        },
        random: (length) => new Uint8Array(length).fill(1),
        sleep: async () => Promise.resolve(),
        operators: OPERATORS,
      },
      {
        transportFactory: (interceptors) =>
          createRouterTransport(
            (router) => {
              router.service(SparkAuthnService, {
                get_challenge: (req) => ({
                  protectedChallenge: create(ProtectedChallengeSchema, {
                    challenge: create(ChallengeSchema, {
                      version: 1,
                      timestamp: BigInt(Math.floor(Date.now() / 1000)),
                      nonce: new Uint8Array(4),
                      publicKey: req.publicKey,
                    }),
                    serverHmac: new Uint8Array(4),
                  }),
                }),
                verify_challenge: () => ({
                  sessionToken: "so-tok",
                  expirationTimestamp: BigInt(Math.floor(Date.now() / 1000) + 600),
                }),
              });
              router.service(SparkTokenService, {
                query_token_outputs: (req) =>
                  impl.query?.(req) ?? {
                    $typeName: "spark_token.QueryTokenOutputsResponse",
                    outputsWithPreviousTransactionData: [],
                  },
                broadcast_transaction: (
                  req,
                ): BroadcastTransactionResponse | Promise<BroadcastTransactionResponse> =>
                  impl.broadcast?.(req) ?? {
                    $typeName: "spark_token.BroadcastTransactionResponse",
                    commitStatus: CommitStatus.COMMIT_FINALIZED,
                  },
                query_token_transactions: () => ({
                  $typeName: "spark_token.QueryTokenTransactionsResponse",
                  tokenTransactionsWithStatus: [
                    ...(impl.transactions?.().tokenTransactionsWithStatus ?? []),
                  ],
                  offset: -1n,
                }),
              });
            },
            { transport: { interceptors: [...interceptors] } },
          ),
      },
    );
  }

  test("outputs maps and filters by decoded identifier", async () => {
    let queried: Uint8Array[] | undefined;
    const client = clientWith({
      query: (req) => {
        queried = req.tokenIdentifiers;
        return {
          $typeName: "spark_token.QueryTokenOutputsResponse",
          outputsWithPreviousTransactionData: [tokenRow("o1", 30n)],
        };
      },
    });
    const outputs = await client.tokens.outputs({ tokenIdentifier: identifier });
    expect(queried?.map(bytesToHex)).toStrictEqual([bytesToHex(rawIdentifier)]);
    expect(outputs).toHaveLength(1);
    expect(outputs[0]?.amount).toBe(30n);
    expect(outputs[0]?.tokenIdentifier).toStrictEqual(rawIdentifier);
    client.close();
  });

  test("balances aggregates per identifier", async () => {
    const client = clientWith({
      query: () => ({
        $typeName: "spark_token.QueryTokenOutputsResponse",
        outputsWithPreviousTransactionData: [
          tokenRow("o1", 30n),
          tokenRow("o2", 20n),
          tokenRow("o3", 5n, OTHER_TOKEN_ID),
        ],
      }),
    });
    const balances = await client.tokens.balances();
    const main = balances.find((b) => b.tokenIdentifier === identifier);
    expect(main?.amount).toBe(50n);
    expect(main?.outputCount).toBe(2);
    expect(balances).toHaveLength(2);
    client.close();
  });

  test("balances exclude pending-outbound outputs", async () => {
    const client = clientWith({
      query: () => ({
        $typeName: "spark_token.QueryTokenOutputsResponse",
        outputsWithPreviousTransactionData: [
          tokenRow("o1", 30n),
          tokenRow("o2", 20n, rawIdentifier, TokenOutputStatus.PENDING_OUTBOUND),
        ],
      }),
    });
    const balances = await client.tokens.balances();
    const outputs = await client.tokens.outputs({ tokenIdentifier: identifier });
    expect(outputs).toHaveLength(2);
    expect(balances).toHaveLength(1);
    expect(balances[0]?.amount).toBe(30n);
    expect(balances[0]?.outputCount).toBe(1);
    client.close();
  });

  test("outputs with an unrecognized status are listed but never spendable", async () => {
    const client = clientWith({
      query: () => ({
        $typeName: "spark_token.QueryTokenOutputsResponse",
        outputsWithPreviousTransactionData: [
          tokenRow("o1", 30n),
          // An enum value this SDK does not know must not count toward balances or selection.
          tokenRow("o2", 20n, rawIdentifier, 99 as TokenOutputStatus),
          tokenRow("o3", 5n, rawIdentifier, TokenOutputStatus.UNSPECIFIED),
        ],
      }),
    });
    const outputs = await client.tokens.outputs({ tokenIdentifier: identifier });
    expect(outputs).toHaveLength(3);
    expect(outputs[1]?.status).toBe("unknown");
    const balances = await client.tokens.balances();
    expect(balances).toHaveLength(1);
    expect(balances[0]?.amount).toBe(30n);
    expect(balances[0]?.outputCount).toBe(1);
    client.close();
  });

  test("outputs rejects rows with malformed fields", async () => {
    const cases: Array<{ name: string; row: Record<string, unknown>; message: string }> = [
      {
        name: "empty id",
        row: { ...tokenRow("o1", 30n), output: { ...tokenRow("o1", 30n).output, id: "" } },
        message: "token output: missing id",
      },
      {
        name: "short previous transaction hash",
        row: { ...tokenRow("o1", 30n), previousTransactionHash: new Uint8Array(31) },
        message: "token output: previous transaction hash is not 32 bytes",
      },
      {
        name: "short owner public key",
        row: {
          ...tokenRow("o1", 30n),
          output: { ...tokenRow("o1", 30n).output, ownerPublicKey: new Uint8Array(32) },
        },
        message: "token output: owner public key is not 33 bytes",
      },
    ];
    for (const testCase of cases) {
      const client = clientWith({
        query: () =>
          create(QueryTokenOutputsResponseSchema, {
            outputsWithPreviousTransactionData: [testCase.row as ReturnType<typeof tokenRow>],
          }),
      });
      // oxlint-disable-next-line no-await-in-loop -- each case needs its own client
      await expect(client.tokens.outputs({ tokenIdentifier: identifier })).rejects.toThrow(
        testCase.message,
      );
      client.close();
    }
  });

  test("outputs page through an advancing cursor", async () => {
    const cursors: string[] = [];
    const client = clientWith({
      query: (req) => {
        const { cursor } = (req as unknown as { pageRequest: { cursor: string } }).pageRequest;
        cursors.push(cursor);
        // Appending "1" advances the cursor; on the last page nextCursor is ignored anyway.
        const last = cursor === "11";
        return create(QueryTokenOutputsResponseSchema, {
          outputsWithPreviousTransactionData: [tokenRow(`o-${cursor}`, 1n)],
          pageResponse: create(PageResponseSchema, {
            hasNextPage: !last,
            nextCursor: `${cursor}1`,
          }),
        });
      },
    });
    const outputs = await client.tokens.outputs({ tokenIdentifier: identifier });
    expect(outputs).toHaveLength(3);
    expect(cursors).toStrictEqual(["", "1", "11"]);
    client.close();
  });

  test("outputs throws on a non-advancing cursor", async () => {
    const client = clientWith({
      query: () =>
        create(QueryTokenOutputsResponseSchema, {
          outputsWithPreviousTransactionData: [tokenRow("o1", 1n)],
          pageResponse: create(PageResponseSchema, {
            hasNextPage: true,
            nextCursor: "",
          }),
        }),
    });
    await expect(client.tokens.outputs({ tokenIdentifier: identifier })).rejects.toThrow(
      "non-advancing cursor",
    );
    client.close();
  });

  test("outputs throws when the coordinator never stops paging", async () => {
    let pages = 0;
    const client = clientWith({
      query: (req) => {
        pages += 1;
        const { cursor } = (req as unknown as { pageRequest: { cursor: string } }).pageRequest;
        return create(QueryTokenOutputsResponseSchema, {
          outputsWithPreviousTransactionData: [tokenRow(`o-${pages}`, 1n)],
          pageResponse: create(PageResponseSchema, {
            hasNextPage: true,
            nextCursor: `${cursor}1`,
          }),
        });
      },
    });
    await expect(client.tokens.outputs({ tokenIdentifier: identifier })).rejects.toThrow(
      "did not stop returning full pages",
    );
    expect(pages).toBe(1000);
    client.close();
  });

  test("transfer selects outputs, broadcasts, and returns the final hash", async () => {
    const client = clientWith({
      query: () => ({
        $typeName: "spark_token.QueryTokenOutputsResponse",
        outputsWithPreviousTransactionData: [tokenRow("o1", 30n), tokenRow("o2", 20n)],
      }),
      broadcast: (req) => ({
        $typeName: "spark_token.BroadcastTransactionResponse",
        commitStatus: CommitStatus.COMMIT_FINALIZED,
        finalTokenTransaction: finalFor(req.partialTokenTransaction!),
      }),
    });
    const hash = await client.tokens.transfer({
      tokenIdentifier: identifier,
      amount: 40n,
      receiver: encodeSparkAddress({ network: "regtest", identityPublicKey: RECEIVER }),
    });
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    client.close();
  });

  test("two concurrent transfers never select the same output", async () => {
    // Distinct prev-transaction vouts so each row is identifiable in broadcast inputs.
    const rows = [0, 1, 2, 3].map((vout) => ({
      ...tokenRow(`o${vout}`, 30n),
      previousTransactionVout: vout,
    }));
    const spent = new Set<string>();
    const broadcastInputs: string[][] = [];
    let inFlight = 0;
    let maxInFlight = 0;
    const client = clientWith({
      query: () => ({
        $typeName: "spark_token.QueryTokenOutputsResponse",
        outputsWithPreviousTransactionData: rows.filter(
          (row) => !spent.has(String(row.previousTransactionVout)),
        ),
      }),
      broadcast: async (req) => {
        const partial = req.partialTokenTransaction!;
        const inputs = spentOutputs(partial).map((output) =>
          String(output.prevTokenTransactionVout),
        );
        broadcastInputs.push(inputs);
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise<void>((resolve) => {
          setTimeout(resolve, 15);
        });
        inFlight -= 1;
        for (const id of inputs) {
          spent.add(id);
        }
        return {
          $typeName: "spark_token.BroadcastTransactionResponse",
          commitStatus: CommitStatus.COMMIT_FINALIZED,
          finalTokenTransaction: finalFor(partial),
        };
      },
    });
    const receiver = encodeSparkAddress({ network: "regtest", identityPublicKey: RECEIVER });
    const hashes = await Promise.all([
      client.tokens.transfer({ tokenIdentifier: identifier, amount: 40n, receiver }),
      client.tokens.transfer({ tokenIdentifier: identifier, amount: 40n, receiver }),
    ]);
    expect(hashes.every((hash) => /^[0-9a-f]{64}$/.test(hash))).toBe(true);
    // Serialized under the token lock: no overlapping broadcasts and disjoint inputs.
    expect(maxInFlight).toBe(1);
    expect(broadcastInputs).toHaveLength(2);
    expect(new Set(broadcastInputs.flat()).size).toBe(4);
    client.close();
  });

  test("transfer rejects a token identifier for the wrong network", async () => {
    const client = clientWith({});
    await expect(
      client.tokens.transfer({
        tokenIdentifier: "btkn18aaxwtn6q4smnlv8td08x5xxz0mx49c60suectq6d9p2gljtjmuqahuvew",
        amount: 1n,
        receiver: RECEIVER,
      }),
    ).rejects.toThrow(SparkInputError);
    client.close();
  });

  test("consolidate merges the outputs into a single self-owned output", async () => {
    let broadcastRequest: BroadcastTransactionRequest | undefined;
    const client = clientWith({
      query: () => ({
        $typeName: "spark_token.QueryTokenOutputsResponse",
        outputsWithPreviousTransactionData: [tokenRow("o1", 30n), tokenRow("o2", 20n)],
      }),
      broadcast: (req) => {
        broadcastRequest = req;
        return {
          $typeName: "spark_token.BroadcastTransactionResponse",
          commitStatus: CommitStatus.COMMIT_FINALIZED,
          finalTokenTransaction: finalFor(req.partialTokenTransaction!),
        };
      },
    });
    const result = await client.tokens.consolidate({ tokenIdentifier: identifier });
    expect(result?.transactionHash).toMatch(/^[0-9a-f]{64}$/);
    const partial = required(broadcastRequest, "broadcast request").partialTokenTransaction;
    expect(spentOutputs(required(partial, "partial"))).toHaveLength(2);
    const outputs = required(partial, "partial").partialTokenOutputs;
    expect(outputs).toHaveLength(1);
    expect(bytesToHex(required(outputs[0], "output").ownerPublicKey)).toBe(bytesToHex(owner));
    expect(required(outputs[0], "output").tokenAmount).toStrictEqual(numberToBytesBE(50n, 16));
    client.close();
  });

  test("consolidate returns undefined with one or fewer available outputs", async () => {
    let broadcasts = 0;
    const client = clientWith({
      query: () => ({
        $typeName: "spark_token.QueryTokenOutputsResponse",
        outputsWithPreviousTransactionData: [
          tokenRow("o1", 30n),
          tokenRow("o2", 20n, rawIdentifier, TokenOutputStatus.PENDING_OUTBOUND),
        ],
      }),
      broadcast: () => {
        broadcasts += 1;
        return {
          $typeName: "spark_token.BroadcastTransactionResponse",
          commitStatus: CommitStatus.COMMIT_FINALIZED,
        };
      },
    });
    await expect(
      client.tokens.consolidate({ tokenIdentifier: identifier }),
    ).resolves.toBeUndefined();
    expect(broadcasts).toBe(0);
    client.close();
  });

  test("consolidate caps the inputs at MAX_TOKEN_OUTPUTS_TX", async () => {
    let broadcastRequest: BroadcastTransactionRequest | undefined;
    const rows = Array.from({ length: MAX_TOKEN_OUTPUTS_TX + 2 }, (_, index) =>
      tokenRow(`o${index}`, 1n),
    );
    const client = clientWith({
      query: () => ({
        $typeName: "spark_token.QueryTokenOutputsResponse",
        outputsWithPreviousTransactionData: rows,
      }),
      broadcast: (req) => {
        broadcastRequest = req;
        return {
          $typeName: "spark_token.BroadcastTransactionResponse",
          commitStatus: CommitStatus.COMMIT_FINALIZED,
          finalTokenTransaction: finalFor(req.partialTokenTransaction!),
        };
      },
    });
    const result = await client.tokens.consolidate({ tokenIdentifier: identifier });
    expect(result?.transactionHash).toMatch(/^[0-9a-f]{64}$/);
    const partial = required(
      required(broadcastRequest, "broadcast").partialTokenTransaction,
      "partial",
    );
    expect(spentOutputs(partial)).toHaveLength(MAX_TOKEN_OUTPUTS_TX);
    expect(required(partial.partialTokenOutputs[0], "output").tokenAmount).toStrictEqual(
      numberToBytesBE(BigInt(MAX_TOKEN_OUTPUTS_TX), 16),
    );
    client.close();
  });

  test("two concurrent consolidates are serialized under the token lock", async () => {
    const rows = [tokenRow("o1", 30n), tokenRow("o2", 20n)];
    const spent = new Set<string>();
    let inFlight = 0;
    let maxInFlight = 0;
    const client = clientWith({
      query: () => ({
        $typeName: "spark_token.QueryTokenOutputsResponse",
        outputsWithPreviousTransactionData: rows.filter((row) => !spent.has(row.output.id)),
      }),
      broadcast: async (req) => {
        spentOutputs(req.partialTokenTransaction!);
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise<void>((resolve) => {
          setTimeout(resolve, 15);
        });
        inFlight -= 1;
        for (const row of rows) {
          spent.add(row.output.id);
        }
        return {
          $typeName: "spark_token.BroadcastTransactionResponse",
          commitStatus: CommitStatus.COMMIT_FINALIZED,
          finalTokenTransaction: finalFor(req.partialTokenTransaction!),
        };
      },
    });
    const [first, second] = await Promise.all([
      client.tokens.consolidate({ tokenIdentifier: identifier }),
      client.tokens.consolidate({ tokenIdentifier: identifier }),
    ]);
    expect(maxInFlight).toBe(1);
    // The second run finds the outputs spent and has nothing to merge.
    expect([first, second].filter((result) => result !== undefined)).toHaveLength(1);
    client.close();
  });

  test("transfer with inputOutputIds returns the committed hash without broadcasting", async () => {
    const creators = [
      creatorRow("out-1", 0, 60n, {
        owner,
        tokenIdentifier: rawIdentifier,
        hash: hexToBytes("ee".repeat(32)),
      }),
      creatorRow("out-2", 0, 40n, {
        owner,
        tokenIdentifier: rawIdentifier,
        hash: hexToBytes("dd".repeat(32)),
      }),
    ];
    const resolved: SparkTokenOutput[] = [
      {
        id: "out-1",
        tokenIdentifier: rawIdentifier,
        amount: 60n,
        prevTransactionHash: hexToBytes("ee".repeat(32)),
        prevTransactionVout: 0,
        ownerPublicKey: owner,
        status: "available",
      },
      {
        id: "out-2",
        tokenIdentifier: rawIdentifier,
        amount: 40n,
        prevTransactionHash: hexToBytes("dd".repeat(32)),
        prevTransactionVout: 0,
        ownerPublicKey: owner,
        status: "available",
      },
    ];
    const expectedPartial = buildTransferPartial({
      selectedOutputs: resolved,
      receiverPublicKey: RECEIVER,
      tokenIdentifier: rawIdentifier,
      amount: 70n,
      senderPublicKey: owner,
      network: "regtest",
      operators: OPERATORS,
      tokens: TOKENS,
      now: () => 0,
    });
    const committedHash = hexToBytes("11".repeat(32));
    const client = clientWith({
      transactions: () => ({
        tokenTransactionsWithStatus: [
          ...creators,
          statusRow(
            v2TxFor(expectedPartial),
            TokenTransactionStatus.TOKEN_TRANSACTION_FINALIZED,
            committedHash,
          ),
        ],
      }),
    });
    const hash = await client.tokens.transfer({
      tokenIdentifier: identifier,
      amount: 70n,
      receiver: RECEIVER,
      inputOutputIds: ["out-1", "out-2"],
    });
    expect(hash).toBe(bytesToHex(committedHash));
    client.close();
  });
});
