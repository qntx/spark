import { create } from "@bufbuild/protobuf";
import { createClient, createRouterTransport } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import { createSparkClientWith } from "../src/client/index.ts";
import {
  p2trScriptFromPublicKey,
  txId,
  createCurrentTimelockRefundTxs,
} from "../src/core/bitcoin/index.ts";
import { sendLeafSigningDigest } from "../src/core/hashing/statements.ts";
import { sparkNetworkConfig } from "../src/core/network.ts";
import { createMemorySparkStore } from "../src/exit/store.ts";
import {
  ChallengeSchema,
  ProtectedChallengeSchema,
  SparkAuthnService,
} from "../src/proto/gen/spark_authn_pb.ts";
import {
  ClaimTransferResponseSchema,
  GetSigningCommitmentsResponseSchema,
  InitiateSwapPrimaryTransferResponseSchema,
  LeafRefundTxSigningResultSchema,
  Network,
  QueryNodesResponseSchema,
  QueryTransfersResponseSchema,
  RequestedSigningCommitmentsSchema,
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
import type { QueryNodesRequest, TransferLeaf, TreeNode } from "../src/proto/gen/spark_pb.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import type { SparkSigner } from "../src/signer/index.ts";
import type { SspClient, SspSwapRequest } from "../src/ssp/index.ts";
import { mapTransfer, swapLeaves } from "../src/transfer/index.ts";
import { malformedLeafTx, mapTreeNode } from "../src/tree/index.ts";
import type { SparkLeaf } from "../src/tree/index.ts";
import { loadWasmBackend } from "./support/backend.ts";
import { required } from "./support/fakes.ts";
import { createTestSigner } from "./support/test-signer.ts";

// Regression coverage for external-audit H-01 and H-02 (PoCs d1 and d3, reversed):
// exit chains must be built only from nodes every operator serves identically, and a leaf's
// valueSats must equal its nodeTx output 0 amount everywhere the leaf can be spent or counted.

const OPERATORS = sparkNetworkConfig("regtest").operators;
const THRESHOLD = 2;
const COORDINATOR = OPERATORS[0]!.identifier;
const SHARE_PUB = secp256k1.getPublicKey(new Uint8Array(32).fill(11), true);

const LEAF_ID = "leaf-1";
const LEAF_SECRET = new Uint8Array(32).fill(42);
const LEAF_PUBLIC = secp256k1.getPublicKey(LEAF_SECRET, true);
const VERIFYING_KEY = secp256k1.Point.fromBytes(LEAF_PUBLIC)
  .add(secp256k1.Point.fromBytes(SHARE_PUB))
  .toBytes(true);

function fakeTxid(label: number): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = (label + i) % 256;
  }
  return out;
}

function txSpending(
  prevTxid: Uint8Array,
  sequence: number,
  payKey: Uint8Array = SHARE_PUB,
  amount = 1000n,
): Uint8Array {
  const tx = new Transaction({ allowUnknownOutputs: true });
  tx.addInput({ txid: prevTxid, index: 0, sequence });
  tx.addOutput({ script: p2trScriptFromPublicKey(payKey, "regtest"), amount });
  return tx.toBytes(true);
}

// Root R -> mid P -> leaf L, transaction links real so the exit-chain verifier accepts them.
const ROOT_NODE_TX = txSpending(fakeTxid(0x30), 0);
const MID_NODE_TX = txSpending(hexToBytes(txId(ROOT_NODE_TX)), 0);
const LEAF_NODE_TX = txSpending(hexToBytes(txId(MID_NODE_TX)), 0);
const LEAF_REFUND_TX = txSpending(hexToBytes(txId(LEAF_NODE_TX)), 2000, LEAF_PUBLIC);

function nodeProto(options: {
  id: string;
  nodeTx: Uint8Array;
  refundTx?: Uint8Array;
  parent?: string;
}): TreeNode {
  return create(TreeNodeSchema, {
    id: options.id,
    treeId: `tree-${options.id}`,
    value: 1000n,
    nodeTx: options.nodeTx,
    refundTx: options.refundTx ?? new Uint8Array(0),
    vout: 0,
    verifyingPublicKey: VERIFYING_KEY,
    ownerIdentityPublicKey: new Uint8Array(33).fill(6),
    ownerSigningPublicKey: new Uint8Array(33).fill(6),
    signingKeyshare: {
      ownerIdentifiers: OPERATORS.map((op) => op.identifier),
      threshold: THRESHOLD,
      publicKey: SHARE_PUB,
      publicShares: {},
    },
    status: "AVAILABLE",
    network: Network.REGTEST,
    treenodeStatus: TreeNodeStatus.AVAILABLE,
    ...(options.parent === undefined ? {} : { parentNodeId: options.parent }),
  });
}

const ROOT = nodeProto({ id: "root", nodeTx: ROOT_NODE_TX });
const MID = nodeProto({ id: "mid", nodeTx: MID_NODE_TX, parent: "root" });
const leafWithParent = () =>
  nodeProto({ id: LEAF_ID, nodeTx: LEAF_NODE_TX, refundTx: LEAF_REFUND_TX, parent: "mid" });
const leafOrphaned = () =>
  nodeProto({ id: LEAF_ID, nodeTx: LEAF_NODE_TX, refundTx: LEAF_REFUND_TX });

function authn(router: { service: (a: never, b: never) => void }) {
  router.service(
    SparkAuthnService as never,
    {
      get_challenge: (req: { publicKey: Uint8Array }) => ({
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
    } as never,
  );
}

function makeChainClient(
  store: ReturnType<typeof createMemorySparkStore>,
  state: {
    /** When true the coordinator serves the leaf with no parentNodeId. */
    coordinatorDropsParent?: boolean;
    /** Per-operator ancestor overrides, keyed by operator identifier. */
    ancestorNodeTx?: Record<string, Uint8Array>;
  },
) {
  const signer = createTestSigner(new Uint8Array(32).fill(7), new Map([[LEAF_ID, LEAF_PUBLIC]]));
  const coordNodes = (): Record<string, TreeNode> => ({
    [LEAF_ID]: state.coordinatorDropsParent === true ? leafOrphaned() : leafWithParent(),
    mid: MID,
    root: ROOT,
  });
  const sparkImplFor = (identifier: string) => ({
    query_nodes: (req: QueryNodesRequest) => {
      if (identifier === COORDINATOR) {
        if (req.source.case === "nodeIds") {
          return { nodes: coordNodes(), offset: 0n };
        }
        const leaf = state.coordinatorDropsParent === true ? leafOrphaned() : leafWithParent();
        return { nodes: { [LEAF_ID]: leaf }, offset: -1n };
      }
      const midOverride = state.ancestorNodeTx?.[identifier];
      const mid =
        midOverride === undefined
          ? MID
          : nodeProto({ id: "mid", nodeTx: midOverride, parent: "root" });
      if (req.source.case === "nodeIds") {
        return { nodes: { [LEAF_ID]: leafWithParent(), mid, root: ROOT }, offset: 0n };
      }
      return { nodes: { [LEAF_ID]: leafWithParent() }, offset: -1n };
    },
  });
  return createSparkClientWith(
    {
      network: "regtest",
      signer,
      fetch: async () => Promise.reject(new Error("unexpected fetch")),
      random: (length) => new Uint8Array(length).fill(1),
      sleep: async () => Promise.resolve(),
      store,
    },
    {
      transportFactory: (interceptors, operator) =>
        createRouterTransport(
          (router) => {
            authn(router);
            router.service(SparkService, sparkImplFor(operator.identifier));
          },
          { transport: { interceptors: [...interceptors] } },
        ),
    },
  );
}

describe("H-01: coordinator-only exit chain data", () => {
  test("a leaf whose coordinator row blanks parentNodeId is quarantined, stored chain survives", async () => {
    const store = createMemorySparkStore();
    const state: { coordinatorDropsParent: boolean } = { coordinatorDropsParent: false };
    const client = makeChainClient(store, state);

    // Round 1: everyone agrees on the full chain root -> mid -> leaf-1.
    const leaves = await client.leaves();
    expect(leaves.map((leaf) => leaf.id)).toStrictEqual([LEAF_ID]);
    const stored = await store.exitChains();
    const good = stored.find((chain) => chain.leafId === LEAF_ID);
    expect(good?.nodes.map((node) => node.nodeId)).toStrictEqual(["root", "mid", LEAF_ID]);
    const offline = await client.withdrawals.offlineExitTransactions([LEAF_ID]);
    expect(offline.map((t) => t.kind)).toStrictEqual(["node", "node", "node", "refund"]);

    // Round 2: the coordinator serves the same leaf with parentNodeId cleared; the honest
    // operators still report "mid". The leaf must leave the spendable set and the verified
    // 3-node chain must stay stored untouched.
    state.coordinatorDropsParent = true;
    const leaves2 = await client.leaves();
    expect(leaves2).toStrictEqual([]);

    const storedAgain = await store.exitChains();
    const kept = storedAgain.find((chain) => chain.leafId === LEAF_ID);
    expect(kept?.nodes.map((node) => node.nodeId)).toStrictEqual(["root", "mid", LEAF_ID]);
    const backup = await client.withdrawals.offlineExitTransactions([LEAF_ID]);
    expect(backup.map((t) => `${t.nodeId}:${t.kind}`)).toStrictEqual([
      "root:node",
      "mid:node",
      `${LEAF_ID}:node`,
      `${LEAF_ID}:refund`,
    ]);
  });

  test("unilateralExit throws naming the leaf and the differing field, stored chain intact", async () => {
    const store = createMemorySparkStore();
    const state: { coordinatorDropsParent: boolean } = { coordinatorDropsParent: false };
    const client = makeChainClient(store, state);

    await client.leaves();
    const storedBefore = await store.exitChains();
    expect(storedBefore.find((chain) => chain.leafId === LEAF_ID)?.nodes).toHaveLength(3);

    // The live unilateral-exit query answers leaf-1 with no parent on the coordinator; the
    // honest operators still serve the real parent — the call must refuse to build or store
    // anything from that data.
    state.coordinatorDropsParent = true;
    await expect(client.withdrawals.unilateralExit([LEAF_ID])).rejects.toThrow(
      `unilateral exit: leaf ${LEAF_ID} node ${LEAF_ID} parentNodeId differs across operators`,
    );
    const storedAfter = await store.exitChains();
    expect(storedAfter.find((chain) => chain.leafId === LEAF_ID)?.nodes).toHaveLength(3);
    const backup = await client.withdrawals.offlineExitTransactions([LEAF_ID]);
    expect(backup).toHaveLength(4);
  });

  test("one operator serving a different ancestor nodeTx rejects the leaf at sync", async () => {
    const store = createMemorySparkStore();
    const attacker = OPERATORS[1]!.identifier;
    const foreignMid = txSpending(fakeTxid(0x99), 0);
    const client = makeChainClient(store, {
      ancestorNodeTx: { [attacker]: foreignMid },
    });

    // The coordinator's chain is internally consistent, but one operator serves a different
    // mid.nodeTx — nothing from that chain may be stored and the leaf must be quarantined.
    await expect(client.leaves()).resolves.toStrictEqual([]);
    await expect(store.exitChains()).resolves.toStrictEqual([]);
  });
});

describe("H-02: leaf valueSats bound to nodeTx output 0", () => {
  function mislabeledLeafProto(options: {
    label: bigint;
    pays: bigint;
    verifyingKey: Uint8Array;
    ownerIdentity: Uint8Array;
    leafKey?: Uint8Array;
    id?: string;
  }): TreeNode {
    const nodeTx = txSpending(fakeTxid(0x40), 0, options.verifyingKey, options.pays);
    const refundTx = txSpending(
      hexToBytes(txId(nodeTx)),
      2000,
      options.leafKey ?? options.ownerIdentity,
    );
    return create(TreeNodeSchema, {
      id: options.id ?? "leaf-mislabeled",
      treeId: "tree-1",
      value: options.label,
      nodeTx,
      refundTx,
      vout: 0,
      verifyingPublicKey: options.verifyingKey,
      ownerIdentityPublicKey: options.ownerIdentity,
      ownerSigningPublicKey: options.leafKey ?? options.ownerIdentity,
      signingKeyshare: {
        ownerIdentifiers: OPERATORS.map((op) => op.identifier),
        threshold: THRESHOLD,
        publicKey: SHARE_PUB,
        publicShares: {},
      },
      status: "AVAILABLE",
      network: Network.REGTEST,
      treenodeStatus: TreeNodeStatus.AVAILABLE,
    });
  }

  test("malformedLeafTx rejects a value label the nodeTx output does not back", () => {
    const leaf = mapTreeNode(
      mislabeledLeafProto({
        label: 1000n,
        pays: 9000n,
        verifyingKey: VERIFYING_KEY,
        ownerIdentity: secp256k1.Point.BASE.toBytes(true),
      }),
    );
    expect(leaf.valueSats).toBe(1000);
    expect(malformedLeafTx(leaf)).toBe("node tx output 0 does not pay the leaf's value");
  });

  test("a mislabeled leaf never reaches selection: send aborts before any signing", async () => {
    const crypto = await loadWasmBackend();
    const signer = createSparkSigner({
      crypto,
      accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
      network: "regtest",
      random: (length) => randomBytes(length),
    });
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: "leaf-mislabeled" }]);
    const verifyingKey = secp256k1.Point.fromBytes(leafKey!)
      .add(secp256k1.Point.fromBytes(SHARE_PUB))
      .toBytes(true);
    const proto = mislabeledLeafProto({
      label: 1000n,
      pays: 9000n,
      verifyingKey,
      ownerIdentity: identity,
      leafKey: leafKey!,
    });

    const calls: string[] = [];
    const client = createSparkClientWith(
      {
        network: "regtest",
        signer,
        fetch: async () => Promise.reject(new Error("unexpected fetch")),
        random: (length) => randomBytes(length),
        store: createMemorySparkStore(),
      },
      {
        transportFactory: (interceptors) =>
          createRouterTransport(
            (router) => {
              authn(router);
              router.service(SparkService, {
                query_nodes: () => ({ nodes: { "leaf-mislabeled": proto }, offset: -1n }),
                get_signing_commitments: () => {
                  calls.push("get_signing_commitments");
                  return create(GetSigningCommitmentsResponseSchema, {});
                },
                start_transfer_v2: () => {
                  calls.push("start_transfer_v2");
                  return create(TransferSchema, {});
                },
              } as never);
            },
            { transport: { interceptors: [...interceptors] } },
          ),
      },
    );

    // The label says 1000 but the chain pays 9000 — the leaf must not even be listed.
    await expect(client.leaves()).resolves.toStrictEqual([]);
    await expect(client.balance()).resolves.toBe(0);
    const receiver = secp256k1.getPublicKey(new Uint8Array(32).fill(77), true);
    await expect(client.transfers.send({ receiver, amountSats: 1000 })).rejects.toThrow(/balance/);
    expect(calls).toStrictEqual([]);
    signer.dispose();
  }, 60_000);
});

const INBOUND_ID = "01989abc-def0-7000-8000-00000000000a";
const SWAP_LEAF_ID = "01989abc-def0-7abc-89ab-0000000000bb";
const SSP_SECRET = new Uint8Array(32).fill(55);
const SSP_IDENTITY = secp256k1.getPublicKey(SSP_SECRET, true);

/** One inbound leaf sealed to `identity` and sender-signed by the SSP key. */
async function sspInboundLeaf(options: {
  leafId: string;
  label: bigint;
  pays: bigint;
  identity: Uint8Array;
  transferId?: string;
  nodeTx?: Uint8Array;
  parent?: string;
}) {
  const receivedSecret = sha256(new TextEncoder().encode(options.leafId));
  const receivedPublicKey = secp256k1.getPublicKey(receivedSecret, true);
  const crypto = await loadWasmBackend();
  const secretCipher = crypto.eciesEncrypt(
    options.identity,
    receivedSecret,
    new Uint8Array(32).fill(6),
  );
  const verifyingKey = secp256k1.Point.fromBytes(receivedPublicKey)
    .add(secp256k1.Point.fromBytes(SHARE_PUB))
    .toBytes(true);
  const nodeTx = options.nodeTx ?? txSpending(fakeTxid(0x50), 0, verifyingKey, options.pays);
  const intermediateRefundTx = createCurrentTimelockRefundTxs({
    nodeTx,
    sequence: 1900,
    receivingPublicKey: receivedPublicKey,
    network: "regtest",
  }).cpfpRefund.txBytes;
  const digest = sendLeafSigningDigest(
    options.leafId,
    options.transferId ?? INBOUND_ID,
    secretCipher,
  );
  const signature = secp256k1.sign(digest, SSP_SECRET, { prehash: false, lowS: true });
  return create(TransferLeafSchema, {
    leaf: create(TreeNodeSchema, {
      id: options.leafId,
      treeId: `tree-${options.leafId}`,
      value: options.label,
      nodeTx,
      refundTx: intermediateRefundTx,
      vout: 0,
      verifyingPublicKey: verifyingKey,
      ownerIdentityPublicKey: options.identity,
      ownerSigningPublicKey: receivedPublicKey,
      signingKeyshare: create(SigningKeyshareSchema, {
        ownerIdentifiers: OPERATORS.map((op) => op.identifier),
        threshold: THRESHOLD,
        publicKey: SHARE_PUB,
        publicShares: {},
      }),
      status: "AVAILABLE",
      network: Network.REGTEST,
      treenodeStatus: TreeNodeStatus.AVAILABLE,
      ...(options.parent === undefined ? {} : { parentNodeId: options.parent }),
    }),
    secretCipher,
    sig: { case: "signature" as const, value: signature },
    intermediateRefundTx,
  });
}

function commitmentGroup(count: number) {
  return Array.from({ length: count }, () =>
    create(RequestedSigningCommitmentsSchema, {
      signingNonceCommitments: Object.fromEntries(
        OPERATORS.map((op, i) => [
          op.identifier,
          {
            hiding: secp256k1.Point.BASE.toBytes(true),
            binding: secp256k1.Point.BASE.multiply(BigInt(i + 2)).toBytes(true),
          },
        ]),
      ),
    }),
  );
}

function inputLeaf(signerLeafKey: Uint8Array, identity: Uint8Array): SparkLeaf {
  const verifyingKey = secp256k1.Point.fromBytes(signerLeafKey)
    .add(secp256k1.Point.fromBytes(SHARE_PUB))
    .toBytes(true);
  const nodeTx = txSpending(fakeTxid(0x60), 0, verifyingKey, 100_000n);
  return {
    id: "input-leaf",
    treeId: "tree-input-leaf",
    valueSats: 100_000,
    status: "AVAILABLE",
    nodeTx,
    refundTx: createCurrentTimelockRefundTxs({
      nodeTx,
      sequence: 2000,
      receivingPublicKey: signerLeafKey,
      network: "regtest",
    }).cpfpRefund.txBytes,
    verifyingPublicKey: verifyingKey,
    ownerIdentityPublicKey: identity,
    ownerSigningPublicKey: signerLeafKey,
    signingKeyshare: {
      ownerIdentifiers: OPERATORS.map((op) => op.identifier),
      threshold: THRESHOLD,
      publicKey: SHARE_PUB,
    },
    vout: 0,
  };
}

describe("H-02: swap claims from coordinator-only data", () => {
  test("a claimed swap leaf whose label its nodeTx does not back aborts the swap", async () => {
    const crypto = await loadWasmBackend();
    const signer = createSparkSigner({
      crypto,
      accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
      network: "regtest",
      random: (length) => randomBytes(length),
    });
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: "input-leaf" }]);
    const input = inputLeaf(leafKey!, identity);

    // The inbound leaf is well-formed; the coordinator's claim response labels it 100_000
    // while the same nodeTx only pays 90_000.
    const inboundLeaf = await sspInboundLeaf({
      leafId: SWAP_LEAF_ID,
      label: 100_000n,
      pays: 100_000n,
      identity,
    });
    const inbound = create(TransferSchema, {
      id: INBOUND_ID,
      senderIdentityPublicKey: SSP_IDENTITY,
      receiverIdentityPublicKey: identity,
      status: TransferStatus.SENDER_KEY_TWEAKED,
      type: TransferType.COUNTER_SWAP_V3,
      network: Network.REGTEST,
      totalValue: 100_000n,
      leaves: [inboundLeaf],
    });
    const claimedInner = required(inboundLeaf.leaf, "inbound leaf node");
    const mislabeledNodeTx = txSpending(
      fakeTxid(0x50),
      0,
      claimedInner.verifyingPublicKey,
      90_000n,
    );
    const [newKey] = await signer.publicKeys([{ type: "leaf", leafId: SWAP_LEAF_ID }]);
    const claimedLeaf = create(TransferLeafSchema, {
      ...inboundLeaf,
      leaf: create(TreeNodeSchema, {
        ...claimedInner,
        value: 100_000n,
        nodeTx: mislabeledNodeTx,
        refundTx: createCurrentTimelockRefundTxs({
          nodeTx: mislabeledNodeTx,
          sequence: 1900,
          receivingPublicKey: newKey!,
          network: "regtest",
        }).cpfpRefund.txBytes,
        verifyingPublicKey: secp256k1.Point.fromBytes(newKey!)
          .add(secp256k1.Point.fromBytes(SHARE_PUB))
          .toBytes(true),
        ownerSigningPublicKey: newKey!,
      }),
    });

    const aggregateCalls: unknown[] = [];
    const wrapped: SparkSigner = {
      ...signer,
      aggregateFrost: async (jobs) => {
        aggregateCalls.push(jobs);
        return Promise.resolve(jobs.map(() => new Uint8Array(64).fill(0x42)));
      },
    };
    const sspRequests: SspSwapRequest[] = [];
    const ssp: SspClient = {
      swapFeeEstimate: async () => Promise.resolve(0),
      requestSwap: async (request) => {
        sspRequests.push(request);
        return Promise.resolve({
          status: "SUCCEEDED",
          inboundTransferId: INBOUND_ID,
          feeSats: 0,
        });
      },
      requestLightningReceive: async () => Promise.reject(new Error("not stubbed")),
      requestLightningSend: async () => Promise.reject(new Error("not stubbed")),
      lightningSendFeeEstimate: async () => Promise.reject(new Error("not stubbed")),
      lightningSendRequest: async () => Promise.reject(new Error("not stubbed")),
      lightningReceiveRequest: async () => Promise.reject(new Error("not stubbed")),
      coopExitFeeQuote: async () => Promise.reject(new Error("not stubbed")),
      requestCoopExit: async () => Promise.reject(new Error("not stubbed")),
      completeCoopExit: async () => Promise.reject(new Error("not stubbed")),
      coopExitRequest: async () => Promise.reject(new Error("not stubbed")),
      staticDepositQuote: async () => Promise.reject(new Error("not stubbed")),
      claimStaticDeposit: async () => Promise.reject(new Error("not stubbed")),
    };
    const transport = createRouterTransport((router) => {
      router.service(SparkService, {
        get_signing_commitments: () =>
          create(GetSigningCommitmentsResponseSchema, {
            signingCommitments: commitmentGroup(3),
          }),
        initiate_swap_primary_transfer: (req: {
          transfer?: {
            transferId: string;
            ownerIdentityPublicKey: Uint8Array;
            receiverIdentityPublicKey: Uint8Array;
          };
        }) =>
          create(InitiateSwapPrimaryTransferResponseSchema, {
            transfer: create(TransferSchema, {
              id: req.transfer!.transferId,
              senderIdentityPublicKey: req.transfer!.ownerIdentityPublicKey,
              receiverIdentityPublicKey: req.transfer!.receiverIdentityPublicKey,
              status: TransferStatus.SENDER_INITIATED,
              type: TransferType.PRIMARY_SWAP_V3,
              network: Network.REGTEST,
              totalValue: BigInt(input.valueSats),
            }),
            signingResults: [
              create(LeafRefundTxSigningResultSchema, {
                leafId: input.id,
                verifyingKey: input.verifyingPublicKey,
                refundTxSigningResult: create(SigningResultSchema, {
                  signatureShares: Object.fromEntries(
                    OPERATORS.map((op) => [op.identifier, new Uint8Array(32).fill(1)]),
                  ),
                  signingNonceCommitments: Object.fromEntries(
                    OPERATORS.map((op, i) => [
                      op.identifier,
                      {
                        hiding: secp256k1.Point.BASE.toBytes(true),
                        binding: secp256k1.Point.BASE.multiply(BigInt(i + 2)).toBytes(true),
                      },
                    ]),
                  ),
                  publicKeys: Object.fromEntries(
                    OPERATORS.map((op) => [op.identifier, new Uint8Array(33).fill(2)]),
                  ),
                }),
              }),
            ],
          }),
        query_transfers_by_id: () => create(QueryTransfersResponseSchema, { transfers: [inbound] }),
        claim_transfer: () =>
          create(ClaimTransferResponseSchema, {
            transfer: create(TransferSchema, {
              id: INBOUND_ID,
              status: TransferStatus.COMPLETED,
              type: TransferType.COUNTER_SWAP_V3,
              network: Network.REGTEST,
              leaves: [claimedLeaf],
            }),
          }),
        query_nodes: () => create(QueryNodesResponseSchema, { nodes: {}, offset: -1n }),
      } as never);
    });
    const spark = createClient(SparkService, transport);

    await expect(
      swapLeaves({
        spark,
        signer: wrapped,
        network: "regtest",
        operators: OPERATORS,
        threshold: THRESHOLD,
        ssp,
        sspIdentityPublicKey: SSP_IDENTITY,
        transferId: "01989abc-def0-7000-8000-000000000001",
        leaves: [input],
        targetAmountsSats: [100_000],
        random: (length) => new Uint8Array(length).fill(3),
      }),
    ).rejects.toThrow(/claimed 0 sats but expected 100000/);
    expect(sspRequests).toHaveLength(1);
    signer.dispose();
  }, 60_000);
});

const CLAIM_TRANSFER_ID = "01989abc-def0-7000-8000-00000000000c";

/**
 * The leaf a real `claim_transfer` response carries for this fixture: same node id and nodeTx as
 * the pending row, but finalized under the receiver's `LEAF{leafId}` key and parented at "mid".
 */
function claimedLeafProto(newKey: Uint8Array, identity: Uint8Array, orphan = false): TreeNode {
  return create(TreeNodeSchema, {
    id: LEAF_ID,
    treeId: `tree-${LEAF_ID}`,
    value: 1000n,
    nodeTx: LEAF_NODE_TX,
    refundTx: createCurrentTimelockRefundTxs({
      nodeTx: LEAF_NODE_TX,
      sequence: 1900,
      receivingPublicKey: newKey,
      network: "regtest",
    }).cpfpRefund.txBytes,
    vout: 0,
    verifyingPublicKey: secp256k1.Point.fromBytes(newKey)
      .add(secp256k1.Point.fromBytes(SHARE_PUB))
      .toBytes(true),
    ownerIdentityPublicKey: identity,
    ownerSigningPublicKey: newKey,
    signingKeyshare: create(SigningKeyshareSchema, {
      ownerIdentifiers: OPERATORS.map((op) => op.identifier),
      threshold: THRESHOLD,
      publicKey: SHARE_PUB,
      publicShares: {},
    }),
    status: "AVAILABLE",
    network: Network.REGTEST,
    treenodeStatus: TreeNodeStatus.AVAILABLE,
    ...(orphan ? {} : { parentNodeId: "mid" }),
  });
}

/**
 * A client whose per-operator `query_nodes` serves `mid`/`root` plus whatever `leafFor` hands back
 * for LEAF_ID — `includeParents` is honored so a nodeIds query sees each node's ancestors — and
 * whose coordinator additionally answers the claim ceremony (`get_signing_commitments` +
 * `claim_transfer` returning `claimed`).
 */
function makeClaimClient(
  store: ReturnType<typeof createMemorySparkStore>,
  signer: SparkSigner,
  leafFor: (identifier: string) => TreeNode | undefined,
  claimed: TransferLeaf,
) {
  const allFor = (identifier: string): Array<[string, TreeNode]> => {
    const leaf = leafFor(identifier);
    const out: Array<[string, TreeNode]> = [
      ["mid", MID],
      ["root", ROOT],
    ];
    if (leaf !== undefined) {
      out.push([LEAF_ID, leaf]);
    }
    return out;
  };
  const sparkImplFor = (identifier: string) => ({
    query_nodes: (req: QueryNodesRequest) => {
      const all = new Map(allFor(identifier));
      if (req.source.case !== "nodeIds") {
        return create(QueryNodesResponseSchema, {
          nodes: Object.fromEntries(all),
          offset: -1n,
        });
      }
      const served = new Map<string, TreeNode>();
      const add = (id: string): void => {
        const node = all.get(id);
        if (node === undefined || served.has(id)) {
          return;
        }
        served.set(id, node);
        if (req.includeParents && node.parentNodeId !== undefined && node.parentNodeId !== "") {
          add(node.parentNodeId);
        }
      };
      for (const id of req.source.value.nodeIds) {
        add(id);
      }
      return create(QueryNodesResponseSchema, {
        nodes: Object.fromEntries(served),
        offset: 0n,
      });
    },
    get_signing_commitments: () =>
      create(GetSigningCommitmentsResponseSchema, {
        signingCommitments: commitmentGroup(3),
      }),
    claim_transfer: (req: { transferId: string }) =>
      create(ClaimTransferResponseSchema, {
        transfer: create(TransferSchema, {
          id: req.transferId,
          status: TransferStatus.COMPLETED,
          type: TransferType.TRANSFER,
          network: Network.REGTEST,
          leaves: [claimed],
        }),
      }),
  });
  return createSparkClientWith(
    {
      network: "regtest",
      signer,
      fetch: async () => Promise.reject(new Error("unexpected fetch")),
      random: (length) => new Uint8Array(length).fill(1),
      sleep: async () => Promise.resolve(),
      store,
    },
    {
      transportFactory: (interceptors, operator) =>
        createRouterTransport(
          (router) => {
            authn(router);
            router.service(SparkService, sparkImplFor(operator.identifier));
          },
          { transport: { interceptors: [...interceptors] } },
        ),
    },
  );
}

describe("H-01: caller rows on the claim path get no exemption", () => {
  async function claimFixture(state: { coordinatorOrphans?: boolean; dropOn?: string }) {
    const crypto = await loadWasmBackend();
    const signer = createSparkSigner({
      crypto,
      accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
      network: "regtest",
      random: (length) => randomBytes(length),
    });
    const identity = await signer.identityPublicKey();
    const [newKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const inbound = await sspInboundLeaf({
      leafId: LEAF_ID,
      label: 1000n,
      pays: 1000n,
      identity,
      transferId: CLAIM_TRANSFER_ID,
      nodeTx: LEAF_NODE_TX,
      parent: "mid",
    });
    const claimedLeaf = claimedLeafProto(required(newKey, "leaf key"), identity);
    const claimed = create(TransferLeafSchema, { ...inbound, leaf: claimedLeaf });
    const pending = create(TransferSchema, {
      id: CLAIM_TRANSFER_ID,
      senderIdentityPublicKey: SSP_IDENTITY,
      receiverIdentityPublicKey: identity,
      status: TransferStatus.SENDER_KEY_TWEAKED,
      type: TransferType.TRANSFER,
      network: Network.REGTEST,
      totalValue: 1000n,
      leaves: [inbound],
    });
    const store = createMemorySparkStore();
    const client = makeClaimClient(
      store,
      signer,
      (identifier) => {
        if (identifier === state.dropOn) {
          return undefined;
        }
        if (identifier === COORDINATOR && state.coordinatorOrphans === true) {
          return claimedLeafProto(required(newKey, "leaf key"), identity, true);
        }
        return claimedLeaf;
      },
      claimed,
    );
    return { client, store, signer, pending, newKey: required(newKey, "leaf key"), identity };
  }

  test("a claimed leaf whose coordinator row blanks parentNodeId stores no chain; next sync does", async () => {
    const state = { coordinatorOrphans: true };
    const { client, store, signer, pending } = await claimFixture(state);

    // The claim itself succeeds — the rejection only withholds the unverified chain.
    const claimed = await client.transfers.claim(mapTransfer(pending));
    expect(claimed.map((leaf) => leaf.id)).toStrictEqual([LEAF_ID]);
    await expect(store.exitChains()).resolves.toStrictEqual([]);

    // Once the coordinator's row agrees with the other operators the next sync stores the chain.
    state.coordinatorOrphans = false;
    const leaves = await client.leaves();
    expect(leaves.map((leaf) => leaf.id)).toStrictEqual([LEAF_ID]);
    const stored = await store.exitChains();
    expect(
      stored.find((chain) => chain.leafId === LEAF_ID)?.nodes.map((n) => n.nodeId),
    ).toStrictEqual(["root", "mid", LEAF_ID]);
    signer.dispose();
  }, 60_000);

  test("a claimed leaf one operator does not index yet is rejected; the claim still returns it", async () => {
    const lagging = OPERATORS[2]!.identifier;
    const state: { dropOn?: string } = { dropOn: lagging };
    const { client, store, signer, pending } = await claimFixture(state);

    const claimed = await client.transfers.claim(mapTransfer(pending));
    expect(claimed.map((leaf) => leaf.id)).toStrictEqual([LEAF_ID]);
    await expect(store.exitChains()).resolves.toStrictEqual([]);

    // The operator catches up; the following sync stores the chain.
    delete state.dropOn;
    const leaves = await client.leaves();
    expect(leaves.map((leaf) => leaf.id)).toStrictEqual([LEAF_ID]);
    const stored = await store.exitChains();
    expect(
      stored.find((chain) => chain.leafId === LEAF_ID)?.nodes.map((n) => n.nodeId),
    ).toStrictEqual(["root", "mid", LEAF_ID]);
    signer.dispose();
  }, 60_000);
});
