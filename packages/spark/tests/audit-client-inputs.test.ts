import { create, toBinary } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { createClient, createRouterTransport } from "@connectrpc/connect";
import type { ConnectRouter } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { numberToBytesBE, numberToVarBytesBE } from "@noble/curves/utils.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { describe, expect, test } from "vite-plus/test";

import { createSparkClientWith } from "../src/client/index.ts";
import { encodeSparkAddress } from "../src/core/address.ts";
import { sparkNetworkConfig } from "../src/core/network.ts";
import type { SparkOperatorConfig } from "../src/core/network.ts";
import { SparkInputError } from "../src/errors/index.ts";
import { createMemorySparkStore } from "../src/exit/store.ts";
import { payLightningInvoice } from "../src/lightning/index.ts";
import {
  ChallengeSchema,
  ProtectedChallengeSchema,
  SparkAuthnService,
} from "../src/proto/gen/spark_authn_pb.ts";
import {
  Network,
  QueryTransfersResponseSchema,
  SparkService,
  TransferReceiverStatus,
  TransferSchema,
  TransferStatus,
  TransferType,
  TreeNodeSchema,
} from "../src/proto/gen/spark_pb.ts";
import {
  QueryTokenOutputsResponseSchema,
  SparkTokenService,
  TokenTransactionStatus,
} from "../src/proto/gen/spark_token_pb.ts";
import type {
  PartialTokenOutput,
  PartialTokenTransaction,
  TokenOutput,
  TokenTransaction,
  TokenTransactionWithStatus,
} from "../src/proto/gen/spark_token_pb.ts";
import { ProtectedChallengeSchema as SspProtectedChallengeSchema } from "../src/proto/gen/ssp_authn_pb.ts";
import { createSspClient } from "../src/ssp/index.ts";
import type { SspClient } from "../src/ssp/index.ts";
import { buildTransferPartial } from "../src/tokens/index.ts";
import type { SparkTokenOutput } from "../src/tokens/index.ts";
import type { SparkLeaf } from "../src/tree/index.ts";
import { encodeTestBolt11 } from "./support/bolt11.ts";
import { createTestSigner } from "./support/test-signer.ts";

// Round-9 external audit, group C. PoCs d4 and d5 run reversed: the bypassed fee gate now
// rejects at entry, and one malformed pending-transfer row can no longer starve the valid
// transfers behind it. The other tests pin the new invoices.pay retry handles (L-02) and the
// SSP read-only retry policy (I-12).

const NOW_MS = 1_700_000_000_000;

function required<T>(value: T | undefined, name: string): T {
  if (value === undefined) {
    throw new Error(`${name} was not captured`);
  }
  return value;
}

describe("d4: lightning.pay validates maxFeeSats before any SSP call", () => {
  const OPERATORS: ReadonlyArray<SparkOperatorConfig> = [
    new Uint8Array(32).fill(9),
    new Uint8Array(32).fill(8),
    new Uint8Array(32).fill(3),
  ].map((secret, id) => ({
    id,
    identifier: `${"0".repeat(62)}0${id + 1}`,
    address: `https://op${id}.test`,
    identityPublicKey: secp256k1.getPublicKey(secret, true),
  }));
  const SSP_IDENTITY = secp256k1.getPublicKey(new Uint8Array(32).fill(21), true);
  const PAYMENT_HASH = new Uint8Array(32).fill(4);
  const FEE_QUOTE = 1_000_000;

  const deadSpark = createClient(SparkService, {
    unary: async () => Promise.reject(new Error("unexpected spark call")),
    stream: async () => Promise.reject(new Error("unexpected spark stream")),
  });

  function countingSsp(): { ssp: SspClient; feeEstimateCalls: () => number } {
    let feeEstimateCalls = 0;
    const unstubbed = async () => Promise.reject(new Error("unstubbed ssp call"));
    return {
      ssp: {
        swapFeeEstimate: unstubbed,
        requestSwap: unstubbed,
        requestLightningReceive: unstubbed,
        requestLightningSend: unstubbed,
        lightningSendFeeEstimate: async () => {
          feeEstimateCalls += 1;
          await Promise.resolve();
          return FEE_QUOTE;
        },
        lightningSendRequest: unstubbed,
        lightningReceiveRequest: unstubbed,
        coopExitFeeQuote: unstubbed,
        requestCoopExit: unstubbed,
        completeCoopExit: unstubbed,
        coopExitRequest: unstubbed,
        staticDepositQuote: unstubbed,
        claimStaticDeposit: unstubbed,
      },
      feeEstimateCalls: () => feeEstimateCalls,
    };
  }

  const INVOICE = encodeTestBolt11({
    secretKey: new Uint8Array(32).fill(66),
    network: "regtest",
    paymentHash: PAYMENT_HASH,
    amountMsat: 1_000_000n,
    timestamp: Math.floor(NOW_MS / 1000) - 60,
  });

  function depsWith(spendAmounts: number[]): {
    deps: Parameters<typeof payLightningInvoice>[0];
    feeEstimateCalls: () => number;
  } {
    const { ssp, feeEstimateCalls } = countingSsp();
    return {
      deps: {
        spark: deadSpark,
        operatorSparks: [],
        ssp,
        sspIdentityPublicKey: SSP_IDENTITY,
        signer: createTestSigner(new Uint8Array(32).fill(7)),
        network: "regtest",
        operators: OPERATORS,
        threshold: 2,
        random: (length) => new Uint8Array(length).fill(1),
        now: () => NOW_MS,
        spendLeaves: async <T>(
          amountSats: number,
          _use: (leaves: ReadonlyArray<SparkLeaf>) => Promise<T>,
        ): Promise<T> => {
          spendAmounts.push(amountSats);
          return Promise.reject(new Error("PAST-FEE-GATE"));
        },
        deleteExitChains: async () => Promise.resolve(),
      },
      feeEstimateCalls,
    };
  }

  test("maxFeeSats NaN rejects before the fee estimate or leaf selection", async () => {
    const spendAmounts: number[] = [];
    const { deps, feeEstimateCalls } = depsWith(spendAmounts);
    await expect(
      payLightningInvoice(deps, { invoice: INVOICE, maxFeeSats: Number.NaN }),
    ).rejects.toThrow(SparkInputError);
    expect(feeEstimateCalls()).toBe(0);
    expect(spendAmounts).toStrictEqual([]);
  });

  test("a cast-undefined maxFeeSats rejects identically", async () => {
    const spendAmounts: number[] = [];
    const { deps, feeEstimateCalls } = depsWith(spendAmounts);
    await expect(
      payLightningInvoice(deps, {
        invoice: INVOICE,
        maxFeeSats: undefined as unknown as number,
      }),
    ).rejects.toThrow(SparkInputError);
    expect(feeEstimateCalls()).toBe(0);
    expect(spendAmounts).toStrictEqual([]);
  });

  test("a valid maxFeeSats still rejects an excessive quote", async () => {
    const spendAmounts: number[] = [];
    const { deps, feeEstimateCalls } = depsWith(spendAmounts);
    await expect(payLightningInvoice(deps, { invoice: INVOICE, maxFeeSats: 100 })).rejects.toThrow(
      `fee estimate ${FEE_QUOTE} exceeds maxFeeSats 100`,
    );
    expect(feeEstimateCalls()).toBe(1);
    expect(spendAmounts).toStrictEqual([]);
  });
});

describe("d5: one malformed pending row cannot starve valid transfers", () => {
  const OPERATORS = sparkNetworkConfig("regtest").operators;

  function transferProto(options: { id: string; totalValue: bigint; receiver: Uint8Array }) {
    return {
      id: options.id,
      senderIdentityPublicKey: new Uint8Array(33).fill(3),
      receiverIdentityPublicKey: options.receiver,
      status: TransferStatus.SENDER_KEY_TWEAKED,
      totalValue: options.totalValue,
      expiryTime: timestampFromMs(1_700_000_600_000),
      createdTime: timestampFromMs(1_700_000_000_000),
      updatedTime: timestampFromMs(1_700_000_000_000),
      type: TransferType.TRANSFER,
      network: Network.REGTEST,
      leaves: [
        {
          leaf: create(TreeNodeSchema, {
            id: `pl-${options.id}`,
            treeId: "tree",
            value: options.totalValue > 100_000n ? 100_000n : options.totalValue,
            nodeTx: new Uint8Array([1, 2]),
            refundTx: new Uint8Array([3, 4]),
            vout: 0,
            verifyingPublicKey: new Uint8Array(33).fill(5),
            ownerIdentityPublicKey: new Uint8Array(33).fill(6),
            ownerSigningPublicKey: new Uint8Array(33).fill(6),
            signingKeyshare: {
              ownerIdentifiers: OPERATORS.map((op) => op.identifier),
              threshold: 2,
              publicKey: new Uint8Array(33).fill(7),
              publicShares: {},
            },
            status: "AVAILABLE",
            network: Network.REGTEST,
          }),
          transferReceiverId: "r-1",
        },
      ],
      receivers: [
        {
          id: "r-1",
          identityPublicKey: options.receiver,
          amountSats: options.totalValue > 100_000n ? 100_000n : options.totalValue,
          status: TransferReceiverStatus.KEY_TWEAKED,
        },
      ],
      senders: [],
    };
  }

  function clientWithPoisonedPending(signer: ReturnType<typeof createTestSigner>) {
    const claimCalls: string[] = [];
    const client = createSparkClientWith(
      {
        network: "regtest",
        signer,
        fetch: async () => Promise.reject(new Error("unexpected fetch")),
        random: (length) => new Uint8Array(length).fill(1),
        store: createMemorySparkStore(),
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
              router.service(SparkService, {
                query_pending_transfers: async () => {
                  const pubkey = await signer.identityPublicKey();
                  return create(QueryTransfersResponseSchema, {
                    transfers: [
                      transferProto({ id: "t-valid", totalValue: 4321n, receiver: pubkey }),
                      // 2^60 sats — far above MAX_SATS; mapTransfer rejects this row alone.
                      transferProto({ id: "t-poison", totalValue: 1n << 60n, receiver: pubkey }),
                    ],
                    offset: -1n,
                  });
                },
                claim_transfer: () => {
                  claimCalls.push("claim_transfer");
                  return {};
                },
              });
            },
            { transport: { interceptors: [...interceptors] } },
          ),
      },
    );
    return { client, claimCalls };
  }

  test("pending() returns the mappable transfer", async () => {
    const signer = createTestSigner(new Uint8Array(32).fill(7));
    const { client } = clientWithPoisonedPending(signer);
    const pending = await client.transfers.pending();
    expect(pending.map((transfer) => transfer.id)).toStrictEqual(["t-valid"]);
    client.close();
  });

  test("claimPending claims what it can and reports the malformed row", async () => {
    const signer = createTestSigner(new Uint8Array(32).fill(7));
    const { client } = clientWithPoisonedPending(signer);
    // Before the fix this rejected with the poisoned row's mapping error and never reached
    // the valid transfer. Now the call resolves: the malformed row is one failure entry and
    // the valid transfer ran through the per-transfer claim path (which then fails on this
    // fixture's unimplemented signer internals — still reported, still isolated).
    const claimed = await client.transfers.claimPending();
    expect(claimed.failures.map((failure) => failure.transferId).toSorted()).toStrictEqual([
      "t-poison",
      "t-valid",
    ]);
    const poisoned = required(
      claimed.failures.find((failure) => failure.transferId === "t-poison"),
      "t-poison failure",
    );
    expect((poisoned.error as Error).message).toContain("transfer total value");
    client.close();
  });
});

describe("invoices.pay idempotency handles", () => {
  const TRANSFER_ID = "01989abc-def0-7abc-89ab-cdef01234567";
  const TOKEN_ID = hexToBytes("ab".repeat(32));
  const HASH_1 = hexToBytes("ee".repeat(32));
  const HASH_2 = hexToBytes("dd".repeat(32));
  const COMMITTED_HASH = hexToBytes("11".repeat(32));

  function authnStub(router: ConnectRouter) {
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
  }

  function satsInvoice(receiver: Uint8Array, amountSats: number): string {
    return encodeSparkAddress({
      network: "regtest",
      identityPublicKey: receiver,
      invoice: {
        version: 1,
        id: TRANSFER_ID,
        payment: { type: "sats", amount: amountSats },
      },
    });
  }

  test("a sats invoice retry with transferId recovers the committed transfer", async () => {
    const payer = createTestSigner(new Uint8Array(32).fill(7));
    const payerPubkey = await payer.identityPublicKey();
    const receiver = secp256k1.getPublicKey(new Uint8Array(32).fill(22), true);
    const invoice = satsInvoice(receiver, 100_000);
    const committed = create(TransferSchema, {
      id: TRANSFER_ID,
      senderIdentityPublicKey: payerPubkey,
      receiverIdentityPublicKey: receiver,
      status: TransferStatus.SENDER_INITIATED,
      type: TransferType.TRANSFER,
      network: Network.REGTEST,
      totalValue: 100_000n,
      receivers: [
        {
          id: "r-1",
          identityPublicKey: receiver,
          amountSats: 100_000n,
          status: TransferReceiverStatus.INITIATED,
        },
      ],
    });
    let nodeQueries = 0;
    const client = createSparkClientWith(
      {
        network: "regtest",
        signer: payer,
        fetch: async () => Promise.reject(new Error("unexpected fetch")),
        random: (length) => new Uint8Array(length).fill(1),
        store: createMemorySparkStore(),
      },
      {
        transportFactory: (interceptors) =>
          createRouterTransport(
            (router) => {
              authnStub(router);
              router.service(SparkService, {
                query_nodes: () => {
                  nodeQueries += 1;
                  return {};
                },
                query_transfers_by_id: () =>
                  create(QueryTransfersResponseSchema, { transfers: [committed] }),
                start_transfer_v2: () => {
                  throw new Error("start_transfer_v2 must not run when the probe hits");
                },
              });
            },
            { transport: { interceptors: [...interceptors] } },
          ),
      },
    );
    const paid = await client.invoices.pay(invoice, { transferId: TRANSFER_ID });
    expect(paid).toMatchObject({ id: TRANSFER_ID });
    // The probe hit short-circuits before leaf selection — query_nodes never ran.
    expect(nodeQueries).toBe(0);
    client.close();
  });

  function creatorRow(
    id: string,
    vout: number,
    amount: bigint,
    owner: Uint8Array,
    hash: Uint8Array,
  ): TokenTransactionWithStatus {
    const tokenOutputs: TokenOutput[] = [];
    for (let index = 0; index <= vout; index += 1) {
      tokenOutputs.push({
        $typeName: "spark_token.TokenOutput",
        ownerPublicKey: owner,
        tokenIdentifier: TOKEN_ID,
        tokenAmount: numberToBytesBE(1n, 16),
        withdrawBondSats: 10_000n,
        withdrawRelativeBlockLocktime: 1000n,
      });
    }
    tokenOutputs[vout] = {
      $typeName: "spark_token.TokenOutput",
      id,
      ownerPublicKey: owner,
      tokenIdentifier: TOKEN_ID,
      tokenAmount: numberToBytesBE(amount, 16),
      withdrawBondSats: 10_000n,
      withdrawRelativeBlockLocktime: 1000n,
    };
    return {
      $typeName: "spark_token.TokenTransactionWithStatus",
      tokenTransaction: {
        $typeName: "spark_token.TokenTransaction",
        version: 3,
        tokenInputs: {
          case: "mintInput",
          value: {
            $typeName: "spark_token.TokenMintInput",
            issuerPublicKey: owner,
            tokenIdentifier: TOKEN_ID,
          },
        },
        tokenOutputs,
        sparkOperatorIdentityPublicKeys: [],
        network: Network.REGTEST,
        invoiceAttachments: [],
      },
      status: TokenTransactionStatus.TOKEN_TRANSACTION_FINALIZED,
      tokenTransactionHash: hash,
    };
  }

  function v2TxFor(partial: PartialTokenTransaction): TokenTransaction {
    const metadata = partial.tokenTransactionMetadata;
    if (metadata === undefined) {
      throw new Error("partial metadata missing");
    }
    return {
      $typeName: "spark_token.TokenTransaction",
      version: partial.version,
      tokenInputs: partial.tokenInputs,
      tokenOutputs: partial.partialTokenOutputs.map((output: PartialTokenOutput) => {
        const tokenOutput: TokenOutput = {
          $typeName: "spark_token.TokenOutput",
          ownerPublicKey: output.ownerPublicKey,
          tokenIdentifier: output.tokenIdentifier,
          tokenAmount: output.tokenAmount,
          withdrawBondSats: output.withdrawBondSats,
          withdrawRelativeBlockLocktime: output.withdrawRelativeBlockLocktime,
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

  test("a token invoice retry with inputOutputIds recovers the committed hash", async () => {
    const payer = createTestSigner(new Uint8Array(32).fill(7));
    const payerPubkey = await payer.identityPublicKey();
    const receiverPubkey = secp256k1.getPublicKey(new Uint8Array(32).fill(22), true);
    const invoice = encodeSparkAddress({
      network: "regtest",
      identityPublicKey: receiverPubkey,
      invoice: {
        version: 1,
        id: TRANSFER_ID,
        payment: {
          type: "tokens",
          tokenIdentifier: TOKEN_ID,
          amount: numberToVarBytesBE(40n),
        },
      },
    });
    const resolved: SparkTokenOutput[] = [
      {
        id: "out-1",
        tokenIdentifier: TOKEN_ID,
        amount: 60n,
        prevTransactionHash: HASH_1,
        prevTransactionVout: 1,
        ownerPublicKey: payerPubkey,
        status: "available",
      },
      {
        id: "out-2",
        tokenIdentifier: TOKEN_ID,
        amount: 40n,
        prevTransactionHash: HASH_2,
        prevTransactionVout: 0,
        ownerPublicKey: payerPubkey,
        status: "available",
      },
    ];
    const regtest = sparkNetworkConfig("regtest");
    const expectedPartial = buildTransferPartial({
      selectedOutputs: resolved,
      receiverPublicKey: receiverPubkey,
      tokenIdentifier: TOKEN_ID,
      amount: 40n,
      senderPublicKey: payerPubkey,
      network: "regtest",
      operators: regtest.operators,
      tokens: regtest.tokens,
      now: () => NOW_MS,
      invoiceAttachments: [invoice],
    });
    let broadcastCalls = 0;
    const client = createSparkClientWith(
      {
        network: "regtest",
        signer: payer,
        fetch: async () => Promise.reject(new Error("unexpected fetch")),
        random: (length) => new Uint8Array(length).fill(1),
        store: createMemorySparkStore(),
        now: () => NOW_MS,
      },
      {
        transportFactory: (interceptors) =>
          createRouterTransport(
            (router) => {
              authnStub(router);
              router.service(SparkService, {});
              router.service(SparkTokenService, {
                query_token_outputs: () =>
                  create(QueryTokenOutputsResponseSchema, {
                    outputsWithPreviousTransactionData: [],
                  }),
                query_token_transactions: () => ({
                  $typeName: "spark_token.QueryTokenTransactionsResponse" as const,
                  tokenTransactionsWithStatus: [
                    creatorRow("out-1", 1, 60n, payerPubkey, HASH_1),
                    creatorRow("out-2", 0, 40n, payerPubkey, HASH_2),
                    {
                      $typeName: "spark_token.TokenTransactionWithStatus" as const,
                      tokenTransaction: v2TxFor(expectedPartial),
                      status: TokenTransactionStatus.TOKEN_TRANSACTION_FINALIZED,
                      tokenTransactionHash: COMMITTED_HASH,
                    },
                  ],
                  offset: -1n,
                }),
                broadcast_transaction: () => {
                  broadcastCalls += 1;
                  throw new Error("broadcast must not run when the committed row matches");
                },
              });
            },
            { transport: { interceptors: [...interceptors] } },
          ),
      },
    );
    const hash = await client.invoices.pay(invoice, { inputOutputIds: ["out-1", "out-2"] });
    expect(hash).toBe(bytesToHex(COMMITTED_HASH));
    expect(broadcastCalls).toBe(0);
    client.close();
  });
});

describe("ssp read-only retries (I-12)", () => {
  const SSP_OPTS = { baseUrl: "https://ssp.test", graphqlPath: "graphql/spark/2025-03-19" };
  const SIGNER = createTestSigner(new Uint8Array(32).fill(7));
  const SWAP_INPUT = {
    adaptorPublicKey: new Uint8Array(33).fill(2),
    totalAmountSats: 150,
    targetAmountsSats: [100],
    feeSats: 0,
    userLeaves: [
      {
        leafId: "leaf-1",
        rawUnsignedRefundTransaction: new Uint8Array([1, 2, 3]),
        adaptorAddedSignature: new Uint8Array(64).fill(4),
      },
    ],
    userOutboundTransferId: "01955cc1-0000-7000-8000-000000000001",
  };

  function feeEstimateResponse(): Response {
    return Response.json({
      data: {
        leaves_swap_fee_estimate: {
          leaves_swap_fee_estimate_output_fee_estimate: {
            currency_amount_original_value: 250,
            currency_amount_original_unit: "SATOSHI",
          },
        },
      },
    });
  }

  function retrySsp(
    operationName: string,
    behaviors: ReadonlyArray<(init: RequestInit | undefined) => Promise<Response>>,
  ): { fetchImpl: typeof globalThis.fetch; attempts: () => number } {
    let attempts = 0;
    const fetchImpl: typeof globalThis.fetch = async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as { operationName: string };
      if (body.operationName === "GetChallenge") {
        return Response.json({
          data: {
            get_challenge: {
              get_challenge_output_protected_challenge: base64.encode(
                toBinary(SspProtectedChallengeSchema, {
                  $typeName: "ssp_authn.ProtectedChallenge",
                  version: 1,
                  challenge: {
                    $typeName: "ssp_authn.Challenge",
                    version: 1,
                    timestamp: 1_786_974_052n,
                    nonce: new Uint8Array(32).fill(9),
                    publicKey: await SIGNER.identityPublicKey(),
                  },
                  serverHmac: new Uint8Array(32).fill(7),
                }),
              ),
            },
          },
        });
      }
      if (body.operationName === "VerifyChallenge") {
        return Response.json({
          data: {
            verify_challenge: {
              verify_challenge_output_session_token: "ssp-token-1",
              verify_challenge_output_valid_until: "2030-01-01T00:00:00Z",
            },
          },
        });
      }
      if (body.operationName === operationName) {
        attempts += 1;
        const behavior = required(
          behaviors[Math.min(attempts - 1, behaviors.length - 1)],
          "ssp behavior",
        );
        return behavior(init);
      }
      return new Response("unexpected operation", { status: 404 });
    };
    return { fetchImpl, attempts: () => attempts };
  }

  const DOWN = async () => Promise.reject(new TypeError("down"));
  const HUNG = async (init: RequestInit | undefined) =>
    new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => {
        reject(new Error("aborted"));
      });
    });
  const OK_ESTIMATE = async () => Promise.resolve(feeEstimateResponse());
  const SERVER_500 = async () => Promise.resolve(new Response("broken", { status: 500 }));

  test("a read-only query retries transport failures with backoff", async () => {
    const { fetchImpl, attempts } = retrySsp("LeavesSwapFeeEstimate", [DOWN, DOWN, OK_ESTIMATE]);
    const sleeps: number[] = [];
    const client = createSspClient({
      ...SSP_OPTS,
      signer: SIGNER,
      fetch: fetchImpl,
      sleep: async (ms) => {
        sleeps.push(ms);
        await Promise.resolve();
      },
    });
    await expect(client.swapFeeEstimate(100_000)).resolves.toBe(250);
    expect(attempts()).toBe(3);
    expect(sleeps).toStrictEqual([1000, 2000]);
  });

  test("a read-only query stops after three transport failures", async () => {
    const { fetchImpl, attempts } = retrySsp("LeavesSwapFeeEstimate", [DOWN]);
    const client = createSspClient({
      ...SSP_OPTS,
      signer: SIGNER,
      fetch: fetchImpl,
      sleep: async () => Promise.resolve(),
    });
    await expect(client.swapFeeEstimate(100_000)).rejects.toThrow("ssp request failed");
    expect(attempts()).toBe(3);
  });

  test("a timed-out read retries", async () => {
    const { fetchImpl, attempts } = retrySsp("LeavesSwapFeeEstimate", [HUNG, OK_ESTIMATE]);
    const client = createSspClient({
      ...SSP_OPTS,
      signer: SIGNER,
      fetch: fetchImpl,
      requestTimeoutMs: 20,
      sleep: async () => Promise.resolve(),
    });
    await expect(client.swapFeeEstimate(100_000)).resolves.toBe(250);
    expect(attempts()).toBe(2);
  });

  test("a server error does not retry a read", async () => {
    const { fetchImpl, attempts } = retrySsp("LeavesSwapFeeEstimate", [SERVER_500]);
    const client = createSspClient({
      ...SSP_OPTS,
      signer: SIGNER,
      fetch: fetchImpl,
      sleep: async () => Promise.resolve(),
    });
    await expect(client.swapFeeEstimate(100_000)).rejects.toThrow("status 500");
    expect(attempts()).toBe(1);
  });

  test("mutations never retry", async () => {
    const { fetchImpl, attempts } = retrySsp("RequestSwap", [DOWN]);
    const client = createSspClient({
      ...SSP_OPTS,
      signer: SIGNER,
      fetch: fetchImpl,
      sleep: async () => Promise.resolve(),
    });
    await expect(client.requestSwap(SWAP_INPUT)).rejects.toThrow("ssp request failed");
    expect(attempts()).toBe(1);
  });
});
