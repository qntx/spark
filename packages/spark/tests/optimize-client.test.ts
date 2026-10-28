import { create } from "@bufbuild/protobuf";
import { createClient, createRouterTransport } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, test } from "vite-plus/test";

import type { ClientContext } from "../src/client/context.ts";
import { optimizeLeaves } from "../src/client/optimize.ts";
import { createCurrentTimelockRefundTxs } from "../src/core/bitcoin/index.ts";
import { sendLeafSigningDigest } from "../src/core/hashing/statements.ts";
import { createMutex } from "../src/core/mutex.ts";
import { sparkNetworkConfig } from "../src/core/network.ts";
import { SparkInputError } from "../src/errors/index.ts";
import { createMemorySparkStore } from "../src/exit/store.ts";
import {
  ClaimTransferResponseSchema,
  GetSigningCommitmentsResponseSchema,
  InitiateSwapPrimaryTransferResponseSchema,
  LeafRefundTxSigningResultSchema,
  Network,
  QueryTransfersResponseSchema,
  SigningKeyshareSchema,
  SigningResultSchema,
  SparkService,
  TransferLeafSchema,
  TransferSchema,
  TransferStatus,
  TransferType,
  TreeNodeSchema,
  TreeNodeStatus,
} from "../src/proto/gen/spark_pb.ts";
import type {
  ClaimTransferRequest,
  GetSigningCommitmentsRequest,
  InitiateSwapPrimaryTransferRequest,
  Transfer,
  TransferLeaf,
} from "../src/proto/gen/spark_pb.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import type { SparkSigner } from "../src/signer/index.ts";
import type { SspClient, SspSwapRequest } from "../src/ssp/index.ts";
import type { SparkLeaf } from "../src/tree/index.ts";
import { loadWasmBackend } from "./support/backend.ts";
import {
  commitmentGroup,
  fabricateLeaf,
  fixedRandom,
  hashedRandom,
  OPERATORS,
  operatorCommitments,
  required,
  SHARE_PUB,
  THRESHOLD,
  verifyingKeyFor,
} from "./support/fakes.ts";

const SSP_SECRET = new Uint8Array(32).fill(21);
const SSP_IDENTITY = secp256k1.getPublicKey(SSP_SECRET, true);
const NOW_MS = 1_700_000_000_000;

const sorted = (values: ReadonlyArray<number>): number[] => values.toSorted((a, b) => a - b);

/** A wallet leaf with a per-leaf signing key, as `syncLeaves` would map it. */
async function walletLeaf(
  signer: SparkSigner,
  leafId: string,
  valueSats: bigint,
  identity: Uint8Array,
  refundSequence?: number,
): Promise<SparkLeaf> {
  const [key] = await signer.publicKeys([{ type: "leaf", leafId }]);
  return fabricateLeaf({
    leafId,
    signingPublicKey: required(key, "leaf public key"),
    ownerIdentityPublicKey: identity,
    valueSats,
    ...(refundSequence === undefined ? {} : { refundSequence }),
  }).leaf;
}

function signingResult(leafId: string, verifyingKey: Uint8Array) {
  return create(LeafRefundTxSigningResultSchema, {
    leafId,
    verifyingKey,
    refundTxSigningResult: create(SigningResultSchema, {
      signatureShares: Object.fromEntries(
        OPERATORS.map((op) => [op.identifier, new Uint8Array(32).fill(1)]),
      ),
      signingNonceCommitments: operatorCommitments(),
      publicKeys: Object.fromEntries(
        OPERATORS.map((op) => [op.identifier, new Uint8Array(33).fill(2)]),
      ),
    }),
  });
}

/** One inbound swap leaf: sealed to `receiverIdentity`, sender-signed by the SSP key. */
async function sspInboundLeaf(
  leafId: string,
  valueSats: bigint,
  receiverIdentity: Uint8Array,
  inboundId: string,
): Promise<TransferLeaf> {
  const receivedSecret = sha256(new TextEncoder().encode(leafId));
  const receivedPublicKey = secp256k1.getPublicKey(receivedSecret, true);
  const crypto = await loadWasmBackend();
  const secretCipher = crypto.eciesEncrypt(
    receiverIdentity,
    receivedSecret,
    new Uint8Array(32).fill(6),
  );
  const fabricated = fabricateLeaf({
    leafId,
    signingPublicKey: receivedPublicKey,
    ownerIdentityPublicKey: receiverIdentity,
    valueSats,
  });
  const { nodeTx } = fabricated;
  const verifyingKey = fabricated.leaf.verifyingPublicKey;
  const intermediateRefundTx = createCurrentTimelockRefundTxs({
    nodeTx,
    sequence: 1900,
    receivingPublicKey: receivedPublicKey,
    network: "regtest",
  }).cpfpRefund.txBytes;
  const digest = sendLeafSigningDigest(leafId, inboundId, secretCipher);
  const signature = secp256k1.sign(digest, SSP_SECRET, { prehash: false, lowS: true });
  return create(TransferLeafSchema, {
    leaf: create(TreeNodeSchema, {
      id: leafId,
      treeId: `tree-${leafId}`,
      value: valueSats,
      nodeTx,
      refundTx: intermediateRefundTx,
      vout: 0,
      verifyingPublicKey: verifyingKey,
      ownerIdentityPublicKey: receiverIdentity,
      ownerSigningPublicKey: receivedPublicKey,
      signingKeyshare: {
        ownerIdentifiers: OPERATORS.map((op) => op.identifier),
        threshold: THRESHOLD,
        publicKey: SHARE_PUB,
        publicShares: {},
      },
      status: "AVAILABLE",
      network: Network.REGTEST,
      treenodeStatus: TreeNodeStatus.AVAILABLE,
    }),
    secretCipher,
    sig: { case: "signature" as const, value: signature },
    intermediateRefundTx,
  });
}

/** The SSP's counter transfer to us: SSP sender, leaves sealed to our identity. */
async function sspInboundTransfer(
  receiverIdentity: Uint8Array,
  inboundId: string,
  targets: ReadonlyArray<number>,
): Promise<Transfer> {
  const transferLeaves = await Promise.all(
    targets.map(async (value, i) =>
      sspInboundLeaf(`swap-leaf-${inboundId}-${i}`, BigInt(value), receiverIdentity, inboundId),
    ),
  );
  let totalValue = 0n;
  for (const value of targets) {
    totalValue += BigInt(value);
  }
  return create(TransferSchema, {
    id: inboundId,
    senderIdentityPublicKey: SSP_IDENTITY,
    receiverIdentityPublicKey: receiverIdentity,
    status: TransferStatus.SENDER_KEY_TWEAKED,
    type: TransferType.COUNTER_SWAP_V3,
    network: Network.REGTEST,
    totalValue,
    leaves: transferLeaves,
  });
}

async function claimedLeaf(signer: SparkSigner, leaf: TransferLeaf): Promise<TransferLeaf> {
  const inner = required(leaf.leaf, "leaf");
  const newKeys = await signer.publicKeys([{ type: "leaf", leafId: inner.id }]);
  const newKey = required(newKeys[0], "claim leaf key");
  return create(TransferLeafSchema, {
    ...leaf,
    leaf: create(TreeNodeSchema, {
      ...inner,
      verifyingPublicKey: verifyingKeyFor(newKey),
      ownerSigningPublicKey: newKey,
      signingKeyshare: create(SigningKeyshareSchema, {
        ownerIdentifiers: OPERATORS.map((op) => op.identifier),
        threshold: THRESHOLD,
        publicKey: SHARE_PUB,
        publicShares: {},
      }),
    }),
  });
}

type SwapEvent =
  | { readonly kind: "initiate"; readonly leafIds: string[] }
  | { readonly kind: "claim"; readonly transferId: string };

const alternatingKind = (index: number): SwapEvent["kind"] =>
  index % 2 === 0 ? "initiate" : "claim";

const initiates = (
  events: ReadonlyArray<SwapEvent>,
): Array<Extract<SwapEvent, { kind: "initiate" }>> =>
  events.filter(
    (event): event is Extract<SwapEvent, { kind: "initiate" }> => event.kind === "initiate",
  );

/**
 * A client context whose `syncLeaves` serves the mutable `wallet` array and whose fake SO/SSP run
 * real `swapLeaves` rounds: each swap consumes the initiated leaf ids once `storeChainsFor` lands
 * the claimed leaves — exactly what the next sync would observe on a real SO. `churnedWalletValues`
 * replaces the wallet wholesale after the first swap lands, simulating external churn.
 */
async function swapContext(options?: {
  walletValues?: number[];
  churnedWalletValues?: number[];
  onSwapClaimed?: (swapsCompleted: number) => void;
}) {
  const signer = createSparkSigner({
    crypto: await loadWasmBackend(),
    accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
    network: "regtest",
    random: fixedRandom(),
  });
  const identity = await signer.identityPublicKey();
  let wallet: SparkLeaf[] = await Promise.all(
    (options?.walletValues ?? []).map(async (value, i) =>
      walletLeaf(signer, `wallet-leaf-${i}`, BigInt(value), identity),
    ),
  );
  let churned: SparkLeaf[] | undefined =
    options?.churnedWalletValues === undefined
      ? undefined
      : await Promise.all(
          options.churnedWalletValues.map(async (value, i) =>
            walletLeaf(signer, `churned-leaf-${i}`, BigInt(value), identity),
          ),
        );

  const events: SwapEvent[] = [];
  const swapRequests: SspSwapRequest[] = [];
  const inboundTargets = new Map<string, number[]>();
  const inbounds = new Map<string, Transfer>();
  let lastConsumed: string[] = [];
  let inboundCounter = 0;
  let swapsCompleted = 0;

  const ssp: SspClient = {
    swapFeeEstimate: async () => Promise.resolve(0),
    requestSwap: async (request) => {
      swapRequests.push(request);
      const inboundId = `01989abc-def0-7abc-89ab-${String(inboundCounter).padStart(12, "0")}`;
      inboundCounter += 1;
      inboundTargets.set(inboundId, [...request.targetAmountsSats]);
      return Promise.resolve({ status: "SUCCEEDED", inboundTransferId: inboundId, feeSats: 0 });
    },
    transfers: async () => Promise.resolve([]),
    requestLightningReceive: async () =>
      Promise.reject(new Error("requestLightningReceive not stubbed")),
    requestLightningSend: async () => Promise.reject(new Error("requestLightningSend not stubbed")),
    lightningSendFeeEstimate: async () =>
      Promise.reject(new Error("lightningSendFeeEstimate not stubbed")),
    lightningSendRequest: async () => Promise.reject(new Error("lightningSendRequest not stubbed")),
    lightningReceiveRequest: async () =>
      Promise.reject(new Error("lightningReceiveRequest not stubbed")),
    coopExitFeeQuote: async () => Promise.reject(new Error("coopExitFeeQuote not stubbed")),
    requestCoopExit: async () => Promise.reject(new Error("requestCoopExit not stubbed")),
    completeCoopExit: async () => Promise.reject(new Error("completeCoopExit not stubbed")),
    coopExitRequest: async () => Promise.reject(new Error("coopExitRequest not stubbed")),
    staticDepositQuote: async () => Promise.reject(new Error("staticDepositQuote not stubbed")),
    claimStaticDeposit: async () => Promise.reject(new Error("claimStaticDeposit not stubbed")),
  };

  const transport = createRouterTransport((router) => {
    router.service(SparkService, {
      get_signing_commitments: (req: GetSigningCommitmentsRequest) =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(
            3 * (req.nodeIds.length > 0 ? req.nodeIds.length : req.nodeIdCount),
          ),
        }),
      initiate_swap_primary_transfer: (req: InitiateSwapPrimaryTransferRequest) => {
        const transfer = required(req.transfer, "swap request transfer");
        const leafIds =
          transfer.transferPackage?.leavesToSend.map((job) => required(job.leafId, "job leafId")) ??
          [];
        lastConsumed = leafIds;
        events.push({ kind: "initiate", leafIds });
        return create(InitiateSwapPrimaryTransferResponseSchema, {
          transfer: create(TransferSchema, {
            id: transfer.transferId,
            senderIdentityPublicKey: transfer.ownerIdentityPublicKey,
            receiverIdentityPublicKey: transfer.receiverIdentityPublicKey,
            status: TransferStatus.SENDER_INITIATED,
            type: TransferType.PRIMARY_SWAP_V3,
            network: Network.REGTEST,
          }),
          signingResults: leafIds.map((leafId) =>
            signingResult(
              leafId,
              required(
                wallet.find((l) => l.id === leafId),
                `leaf ${leafId}`,
              ).verifyingPublicKey,
            ),
          ),
        });
      },
      query_transfers_by_id: async (req: unknown) => {
        const ids = (req as { transferIds: string[] }).transferIds;
        const transfers = await Promise.all(
          ids.map(async (id) => {
            const cached = inbounds.get(id);
            const inbound =
              cached ??
              (await sspInboundTransfer(identity, id, required(inboundTargets.get(id), "targets")));
            inbounds.set(id, inbound);
            return inbound;
          }),
        );
        return create(QueryTransfersResponseSchema, { transfers });
      },
      claim_transfer: async (req: ClaimTransferRequest) => {
        events.push({ kind: "claim", transferId: req.transferId });
        const inbound = required(inbounds.get(req.transferId), "inbound transfer");
        return create(ClaimTransferResponseSchema, {
          transfer: create(TransferSchema, {
            id: req.transferId,
            status: TransferStatus.COMPLETED,
            type: TransferType.COUNTER_SWAP_V3,
            network: Network.REGTEST,
            leaves: await Promise.all(
              inbound.leaves.map(async (leaf) => claimedLeaf(signer, leaf)),
            ),
          }),
        });
      },
    });
  });
  const spark = createClient(SparkService, transport);
  const store = createMemorySparkStore();
  const regtest = sparkNetworkConfig("regtest");
  const context: ClientContext = {
    coordinatorConnection: {
      operator: required(OPERATORS[0], "coordinator operator"),
      spark,
      token: undefined as never,
      invalidateSession: () => {},
    },
    otherConnections: [],
    signer,
    network: "regtest",
    config: {
      ...regtest,
      operators: OPERATORS,
      threshold: THRESHOLD,
      ssp: { ...regtest.ssp, identityPublicKey: SSP_IDENTITY },
    },
    operators: OPERATORS,
    store,
    random: hashedRandom("optimize-test-context"),
    now: () => NOW_MS,
    sleep: async () => Promise.resolve(),
    transferCoordinator: {
      spark,
      signer,
      network: "regtest",
      operators: OPERATORS,
      threshold: THRESHOLD,
    },
    depositCoordinator: {
      spark,
      signer,
      network: "regtest",
      operators: OPERATORS,
      coordinatorIdentifier: required(OPERATORS[0], "coordinator").identifier,
    },
    sspClient: ssp,
    leafLock: createMutex(),
    tokenLock: createMutex(),
    storeChainsFor: async (leaves) => {
      const consumed = new Set(lastConsumed);
      wallet = churned ?? [...wallet.filter((leaf) => !consumed.has(leaf.id)), ...leaves];
      churned = undefined;
      swapsCompleted += 1;
      options?.onSwapClaimed?.(swapsCompleted);
      await Promise.resolve();
      return [];
    },
    syncLeaves: async () => Promise.resolve([...wallet]),
    leaves: async () => Promise.resolve([...wallet]),
    receiverIdentityKey: () => {
      throw new Error("receiverIdentityKey not stubbed");
    },
    tokenIdentifierForNetwork: () => {
      throw new Error("tokenIdentifierForNetwork not stubbed");
    },
  };
  return { context, signer, store, events, swapRequests, wallet: () => wallet };
}

describe("client.optimizeLeaves", () => {
  test("does nothing when the wallet is already optimal", async () => {
    const { context, events } = await swapContext({ walletValues: [1, 1, 2, 4] });
    const result = await optimizeLeaves(context);
    expect(result).toStrictEqual({ swaps: 0, leavesBefore: 4, leavesAfter: 4 });
    expect(events).toHaveLength(0);
  }, 60_000);

  test("does nothing for an empty wallet", async () => {
    const { context, events } = await swapContext({ walletValues: [] });
    const result = await optimizeLeaves(context, { multiplicity: 0 });
    expect(result).toStrictEqual({ swaps: 0, leavesBefore: 0, leavesAfter: 0 });
    expect(events).toHaveLength(0);
  }, 60_000);

  test("rejects invalid options before touching the SO", async () => {
    const { context, events } = await swapContext({ walletValues: [8] });
    await expect(optimizeLeaves(context, { multiplicity: -1 })).rejects.toThrow(SparkInputError);
    await expect(optimizeLeaves(context, { multiplicity: 6 })).rejects.toThrow(SparkInputError);
    await expect(optimizeLeaves(context, { maxLeavesPerSwap: 0 })).rejects.toThrow(SparkInputError);
    expect(events).toHaveLength(0);
  }, 60_000);

  test("consolidates dust into one leaf, one swap per locked round", async () => {
    const walletValues = Array.from({ length: 64 }, () => 1);
    const { context, store, events, wallet } = await swapContext({ walletValues });
    const initialLeaves = wallet();
    await store.putExitChains(
      initialLeaves.map((leaf) => ({
        leafId: leaf.id,
        nodes: [{ nodeId: `${leaf.id}-root`, nodeTx: leaf.nodeTx }],
        refundTx: leaf.refundTx,
      })),
    );

    const result = await optimizeLeaves(context, { multiplicity: 0, maxLeavesPerSwap: 8 });
    // 8 rounds of 8x[1]->[8], then one [8x8]->[64]: 9 swaps, 64 leaves down to 1.
    expect(result).toStrictEqual({ swaps: 9, leavesBefore: 64, leavesAfter: 1 });
    expect(wallet()).toHaveLength(1);
    expect(wallet()[0]?.valueSats).toBe(64);

    // Swaps ran strictly one at a time: every initiate is claimed before the next initiate.
    expect(events.map((e) => e.kind)).toStrictEqual(
      Array.from({ length: 18 }, (_, i) => alternatingKind(i)),
    );
    for (const event of initiates(events)) {
      expect(event.leafIds.length).toBeLessThanOrEqual(8);
    }
    // Every input exit chain was deleted; only consumed ids were seeded.
    await expect(store.exitChains()).resolves.toHaveLength(0);
  }, 60_000);

  test("maps planned values onto concrete leaves in plan order", async () => {
    // The plan sorts inputs ascending: sixteen 1-sat leaves then the 64-sat leaf.
    const walletValues = [...Array.from({ length: 16 }, () => 1), 64];
    const { context, events, swapRequests } = await swapContext({ walletValues });
    const result = await optimizeLeaves(context, { multiplicity: 0 });
    expect(result).toStrictEqual({ swaps: 1, leavesBefore: 17, leavesAfter: 2 });
    const initiate = required(
      events.find((e) => e.kind === "initiate"),
      "initiate event",
    );
    expect(initiate.leafIds).toStrictEqual([
      ...Array.from({ length: 16 }, (_, i) => `wallet-leaf-${i}`),
      "wallet-leaf-16",
    ]);
    expect(required(swapRequests[0], "swap request").targetAmountsSats).toStrictEqual([16, 64]);
  }, 60_000);

  test("reshapes a single leaf for multiplicity 1 and conserves balance", async () => {
    const { context, swapRequests, wallet } = await swapContext({ walletValues: [100] });
    const result = await optimizeLeaves(context, { multiplicity: 1 });
    expect(result).toStrictEqual({ swaps: 1, leavesBefore: 1, leavesAfter: 9 });
    expect(required(swapRequests[0], "swap request").targetAmountsSats).toStrictEqual([
      1, 1, 2, 4, 4, 8, 16, 32, 32,
    ]);
    expect(sorted(wallet().map((leaf) => leaf.valueSats))).toStrictEqual([
      1, 1, 2, 4, 4, 8, 16, 32, 32,
    ]);
    expect(wallet().reduce((sum, leaf) => sum + leaf.valueSats, 0)).toBe(100);
  }, 60_000);

  test("aborts between swaps", async () => {
    const controller = new AbortController();
    const { context, events } = await swapContext({
      walletValues: Array.from({ length: 64 }, () => 1),
      onSwapClaimed: () => controller.abort(),
    });
    const result = await optimizeLeaves(context, {
      multiplicity: 0,
      maxLeavesPerSwap: 8,
      signal: controller.signal,
    });
    expect(result.swaps).toBe(1);
    expect(result.leavesBefore).toBe(64);
    expect(result.leavesAfter).toBe(57);
    expect(events.filter((e) => e.kind === "initiate")).toHaveLength(1);
  }, 60_000);

  test("replans when the leaf set changed between rounds", async () => {
    // After the first swap lands, the wallet is replaced wholesale (external churn); the next
    // round must plan against the fresh set, not the stale plan.
    const walletValues = Array.from({ length: 64 }, () => 1);
    const { context, events, wallet } = await swapContext({
      walletValues,
      churnedWalletValues: Array.from({ length: 32 }, () => 2),
    });
    const result = await optimizeLeaves(context, { multiplicity: 0, maxLeavesPerSwap: 8 });
    // swap 1 from the stale plan lands; swaps 2+ of that plan cannot map onto the churned set, so
    // the next iteration replans: four [2x8]->[16] swaps plus the [16x4]->[64] finisher.
    expect(result.swaps).toBe(6);
    const initiated = events.filter((e) => e.kind === "initiate");
    expect(initiated[0]?.leafIds).toStrictEqual(
      Array.from({ length: 8 }, (_, i) => `wallet-leaf-${i}`),
    );
    expect(initiated[1]?.leafIds).toStrictEqual(
      Array.from({ length: 8 }, (_, i) => `churned-leaf-${i}`),
    );
    expect(wallet().map((leaf) => leaf.valueSats)).toStrictEqual([64]);
  }, 60_000);
});
