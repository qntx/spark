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
import { SparkError, SparkInputError } from "../src/errors/index.ts";
import {
  ChallengeSchema,
  ProtectedChallengeSchema,
  SparkAuthnService,
} from "../src/proto/gen/spark_authn_pb.ts";
import { Network } from "../src/proto/gen/spark_pb.ts";
import {
  CommitStatus,
  SparkTokenService,
  TokenOutputStatus,
} from "../src/proto/gen/spark_token_pb.ts";
import type {
  BroadcastTransactionResponse,
  FinalTokenTransaction,
  PartialTokenOutput,
  PartialTokenTransaction,
  QueryTokenOutputsResponse,
  BroadcastTransactionRequestSchema,
  BroadcastTransactionRequest,
} from "../src/proto/gen/spark_token_pb.ts";
import {
  buildTransferPartial,
  broadcastPartialTokenTransaction,
  selectTokenOutputs,
} from "../src/tokens/index.ts";
import type { SparkTokenOutput, TokenNetworkParams } from "../src/tokens/index.ts";
import { createTestSigner } from "./support/test-signer.ts";

type BroadcastTxInit = MessageInitShape<typeof BroadcastTransactionRequestSchema>;

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
    status?: "available" | "pending-outbound";
  },
): SparkTokenOutput {
  return {
    id,
    tokenIdentifier: overrides?.tokenIdentifier ?? TOKEN_ID,
    amount,
    prevTransactionHash: hexToBytes("ee".repeat(32)),
    prevTransactionVout: overrides?.prevVout ?? 0,
    ownerPublicKey: OWNER,
    ...(overrides?.status === undefined ? {} : { status: overrides.status }),
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

  test("skips pending-outbound outputs", () => {
    const outputs = [makeOutput("a", 50n), makeOutput("b", 50n, { status: "pending-outbound" })];
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
});
