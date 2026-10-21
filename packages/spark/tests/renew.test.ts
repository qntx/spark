import { create } from "@bufbuild/protobuf";
import { createRouterTransport, createClient } from "@connectrpc/connect";
import type { Client, HandlerContext } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import { createSparkClientWith } from "../src/client/index.ts";
import {
  createInitialTimelockRefundTxs,
  createZeroTimelockNodeTx,
  p2trScriptFromPublicKey,
  txId,
} from "../src/core/bitcoin/index.ts";
import type { SparkOperatorConfig } from "../src/core/network.ts";
import { createMemorySparkStore } from "../src/exit/store.ts";
import {
  ChallengeSchema,
  ProtectedChallengeSchema,
  SparkAuthnService,
} from "../src/proto/gen/spark_authn_pb.ts";
import {
  GetSigningCommitmentsResponseSchema,
  Network,
  QueryNodesResponseSchema,
  RenewLeafResponseSchema,
  RequestedSigningCommitmentsSchema,
  SparkService,
  StartTransferResponseSchema,
  TransferSchema,
  TransferStatus,
  TransferType,
  TreeNodeSchema,
  TreeNodeStatus,
} from "../src/proto/gen/spark_pb.ts";
import type {
  GetSigningCommitmentsRequest,
  QueryNodesRequest,
  RenewLeafRequest,
  RenewNodeTimelockSigningJob,
  RenewNodeZeroTimelockSigningJob,
  StartTransferRequest,
} from "../src/proto/gen/spark_pb.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import type { SparkSigner, SigningTarget } from "../src/signer/index.ts";
import type { SparkLeaf } from "../src/tree/index.ts";
import { renewLeaf, renewalKind } from "../src/tree/renew.ts";
import { loadWasmBackend } from "./support/backend.ts";

const OPERATOR_SECRETS = [
  new Uint8Array(32).fill(9),
  new Uint8Array(32).fill(8),
  new Uint8Array(32).fill(3),
];
const OPERATORS: ReadonlyArray<SparkOperatorConfig> = OPERATOR_SECRETS.map((secret, id) => ({
  id,
  identifier: `${"0".repeat(62)}0${id + 1}`,
  address: `https://op${id}.test`,
  identityPublicKey: secp256k1.getPublicKey(secret, true),
}));
const THRESHOLD = 2;
const LEAF_ID = "01989abc-def0-7abc-89ab-cdef01234567";
const PARENT_ID = "01989abc-def0-7abc-89ab-00000000beef";
const SHARE_SECRET = 0x5ea5n;
const SHARE_PUB = secp256k1.Point.BASE.multiply(SHARE_SECRET).toBytes(true);

function fixedRandom(): (length: number) => Uint8Array {
  let counter = 0;
  return (length) => {
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      counter = (counter + 1) % 251;
      out[i] = counter;
    }
    return out;
  };
}

async function testSigner(): Promise<SparkSigner> {
  return createSparkSigner({
    crypto: await loadWasmBackend(),
    accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
    network: "regtest",
    random: fixedRandom(),
  });
}

function verifyingKeyFor(signingPublicKey: Uint8Array): Uint8Array {
  return secp256k1.Point.BASE.multiply(SHARE_SECRET)
    .add(secp256k1.Point.fromBytes(signingPublicKey))
    .toBytes(true);
}

function required<T>(value: T | undefined | null): T {
  if (value === undefined || value === null) {
    throw new Error("required value missing");
  }
  return value;
}

function inputSequence(txBytes: Uint8Array): number {
  const { sequence } = Transaction.fromRaw(txBytes, { allowUnknownOutputs: true }).getInput(0);
  if (sequence === undefined) {
    throw new Error("test fixture tx has no sequence");
  }
  return sequence;
}

/** A synthetic single-input single-output tx with the given input sequence. */
function txWithSequence(
  sequence: number,
  scriptKey: Uint8Array,
  amountSats: bigint,
  prevTxid: Uint8Array = new Uint8Array(32).fill(7),
): Uint8Array {
  const tx = new Transaction({ allowUnknownOutputs: true });
  tx.addInput({ txid: prevTxid, index: 0, sequence });
  tx.addOutput({ script: p2trScriptFromPublicKey(scriptKey, "regtest"), amount: amountSats });
  return tx.toBytes(true);
}

function txidBytes(tx: Uint8Array): Uint8Array {
  const bytes = hexToBytes(txId(tx));
  return bytes;
}

function fabricateLeaf(options: {
  nodeSequence: number;
  refundSequence: number;
  signingPublicKey: Uint8Array;
  ownerIdentityPublicKey: Uint8Array;
  parentNodeId?: string;
}): SparkLeaf {
  const verifyingKey = verifyingKeyFor(options.signingPublicKey);
  // A leaf with a parent spends the parent node tx; the deterministic parent
  // fixture builds it as fabricateParent(verifyingKey) below.
  const prevTxid =
    options.parentNodeId === undefined
      ? new Uint8Array(32).fill(7)
      : txidBytes(txWithSequence(0, verifyingKey, 100_000n));
  const nodeTx = txWithSequence(options.nodeSequence, verifyingKey, 100_000n, prevTxid);
  // The refund must spend the node tx output 0 and pay the leaf's own signing key — the
  // exit-chain checks verify both.
  const refundTx = txWithSequence(
    options.refundSequence,
    options.signingPublicKey,
    100_000n,
    txidBytes(nodeTx),
  );
  return {
    id: LEAF_ID,
    treeId: `tree-${LEAF_ID}`,
    valueSats: 100_000,
    status: "AVAILABLE",
    nodeTx,
    refundTx,
    verifyingPublicKey: verifyingKey,
    ownerIdentityPublicKey: options.ownerIdentityPublicKey,
    ownerSigningPublicKey: options.signingPublicKey,
    signingKeyshare: {
      ownerIdentifiers: OPERATORS.map((op) => op.identifier),
      threshold: THRESHOLD,
      publicKey: SHARE_PUB,
    },
    vout: 0,
    ...(options.parentNodeId === undefined ? {} : { parentNodeId: options.parentNodeId }),
  };
}

function fabricateParent(verifyingKey: Uint8Array) {
  return create(TreeNodeSchema, {
    id: PARENT_ID,
    treeId: `tree-${LEAF_ID}`,
    value: 100_000n,
    nodeTx: txWithSequence(0, verifyingKey, 100_000n),
    refundTx: new Uint8Array(4),
    vout: 0,
    verifyingPublicKey: verifyingKey,
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
  });
}

type SparkImpl = Partial<{
  query_nodes: (req: QueryNodesRequest) => unknown;
  get_signing_commitments: (req: GetSigningCommitmentsRequest) => unknown;
  renew_leaf: (req: RenewLeafRequest, ctx: HandlerContext) => unknown;
  start_transfer_v2: (req: StartTransferRequest) => unknown;
}>;

function makeSparkClient(sparkImpl: SparkImpl): Client<typeof SparkService> {
  const transport = createRouterTransport(
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
      router.service(SparkService, sparkImpl as never);
    },
    { transport: {} },
  );
  return createClient(SparkService, transport);
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

function signingJobValue(req: RenewLeafRequest | undefined, want: string) {
  const jobs = required(req).signingJobs;
  if (jobs.case !== want) {
    throw new Error(`expected ${want}, got ${jobs.case}`);
  }
  return jobs.value;
}

function leafNode(leaf: SparkLeaf) {
  return create(TreeNodeSchema, {
    id: leaf.id,
    treeId: leaf.treeId,
    value: BigInt(leaf.valueSats),
    nodeTx: leaf.nodeTx,
    refundTx: leaf.refundTx,
    vout: leaf.vout,
    verifyingPublicKey: leaf.verifyingPublicKey,
    ownerIdentityPublicKey: leaf.ownerIdentityPublicKey,
    ownerSigningPublicKey: leaf.ownerSigningPublicKey,
    signingKeyshare: {
      ownerIdentifiers: OPERATORS.map((op) => op.identifier),
      threshold: THRESHOLD,
      publicKey: leaf.signingKeyshare.publicKey,
      publicShares: {},
    },
    status: "AVAILABLE",
    network: Network.REGTEST,
    treenodeStatus: TreeNodeStatus.AVAILABLE,
  });
}

function makeWalletClient(signer: SparkSigner, sparkImpl: SparkImpl) {
  return createSparkClientWith(
    {
      network: "regtest",
      signer,
      fetch: async () => Promise.reject(new Error("no fetch")),
      random: fixedRandom(),
      operators: OPERATORS,
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
            router.service(SparkService, sparkImpl as never);
          },
          { transport: { interceptors: [...interceptors] } },
        ),
    },
  );
}

function renewZeroResponse(req: RenewLeafRequest, base: ReturnType<typeof leafNode>) {
  const jobs = req.signingJobs;
  if (jobs.case !== "renewNodeZeroTimelockSigningJob") {
    throw new Error(`unexpected renew job case ${jobs.case}`);
  }
  const renewed = create(TreeNodeSchema, {
    ...base,
    nodeTx: required(jobs.value.nodeTxSigningJob).rawTx,
    refundTx: required(jobs.value.refundTxSigningJob).rawTx,
  });
  return create(RenewLeafResponseSchema, {
    renewResult: { case: "renewNodeZeroTimelockResult", value: { node: renewed } },
  });
}

function renewedNodeResponse(renewKind: "zero" | "node" | "refund") {
  const scriptKey = secp256k1.Point.BASE.toBytes(true);
  const nodeTx = txWithSequence(0, scriptKey, 100_000n);
  const node = create(TreeNodeSchema, {
    id: LEAF_ID,
    treeId: `tree-${LEAF_ID}`,
    value: 100_000n,
    nodeTx,
    refundTx: txWithSequence(0x200, scriptKey, 99_000n, txidBytes(nodeTx)),
    vout: 0,
    verifyingPublicKey: new Uint8Array(33).fill(5),
    ownerIdentityPublicKey: new Uint8Array(33).fill(6),
    ownerSigningPublicKey: new Uint8Array(33).fill(6),
    signingKeyshare: {
      ownerIdentifiers: OPERATORS.map((op) => op.identifier),
      threshold: THRESHOLD,
      publicKey: new Uint8Array(33).fill(7),
      publicShares: {},
    },
    status: "AVAILABLE",
    network: Network.REGTEST,
    treenodeStatus: TreeNodeStatus.AVAILABLE,
  });
  if (renewKind === "zero") {
    return create(RenewLeafResponseSchema, {
      renewResult: { case: "renewNodeZeroTimelockResult", value: { node } },
    });
  }
  if (renewKind === "node") {
    return create(RenewLeafResponseSchema, {
      renewResult: { case: "renewNodeTimelockResult", value: { splitNode: node, node } },
    });
  }
  return create(RenewLeafResponseSchema, {
    renewResult: { case: "renewRefundTimelockResult", value: { node } },
  });
}

describe("renewalKind", () => {
  const owner = new Uint8Array(33).fill(6);
  const key = secp256k1.getPublicKey(new Uint8Array(32).fill(1), true);
  const classify = (nodeSequence: number, refundSequence: number) =>
    renewalKind(
      fabricateLeaf({
        nodeSequence,
        refundSequence,
        signingPublicKey: key,
        ownerIdentityPublicKey: owner,
      }),
    );

  test("is undefined while the refund timelock is healthy", () => {
    expect(classify(0, 2000)).toBeUndefined();
    expect(classify(0, 200)).toBeUndefined();
  });

  test("classifies the stale refund timelock boundary at 199", () => {
    expect(classify(0, 199)).toBe("zero-timelock");
    expect(classify(300, 199)).toBe("refund");
    expect(classify(199, 199)).toBe("node");
  });

  test("classifies node timelock boundaries", () => {
    expect(classify(0, 100)).toBe("zero-timelock");
    expect(classify(200, 100)).toBe("refund");
    expect(classify(199, 100)).toBe("node");
    expect(classify(100, 100)).toBe("node");
  });
});

describe("renewLeaf", () => {
  async function setup(nodeSequence: number, refundSequence: number, withParent: boolean) {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    if (leafKey === undefined) {
      throw new Error("leaf key missing");
    }
    const leaf = fabricateLeaf({
      nodeSequence,
      refundSequence,
      signingPublicKey: leafKey,
      ownerIdentityPublicKey: identity,
      ...(withParent ? { parentNodeId: PARENT_ID } : {}),
    });
    return { signer, leaf, leafKey };
  }

  test("zero-timelock: four jobs on the renewNodeZeroTimelock wire case", async () => {
    const { signer, leaf, leafKey } = await setup(0, 100, false);
    const targets: SigningTarget[] = [];
    const recording: SparkSigner = {
      ...signer,
      signFrost: async (jobs) => {
        for (const job of jobs) {
          targets.push(job.target);
        }
        return signer.signFrost(jobs);
      },
    };

    let commitmentsReq: GetSigningCommitmentsRequest | undefined;
    let renewReq: RenewLeafRequest | undefined;
    let idempotencyKey: string | null = null;
    let queryNodesCalls = 0;
    const spark = makeSparkClient({
      query_nodes: () => {
        queryNodesCalls += 1;
        return create(QueryNodesResponseSchema, { nodes: {}, offset: 0n });
      },
      get_signing_commitments: (req) => {
        commitmentsReq = req;
        return create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(4),
        });
      },
      renew_leaf: (req, ctx) => {
        renewReq = req;
        idempotencyKey = ctx.requestHeader.get("x-idempotency-key");
        return renewedNodeResponse("zero");
      },
    });

    const renewed = await renewLeaf({ spark, signer: recording, network: "regtest", leaf });
    expect(renewed.id).toBe(LEAF_ID);
    expect(queryNodesCalls).toBe(0);

    expect(commitmentsReq?.nodeIds).toStrictEqual([LEAF_ID]);
    expect(commitmentsReq?.count).toBe(4);
    expect(idempotencyKey).toBe(txId(leaf.refundTx));

    const value = signingJobValue(
      renewReq,
      "renewNodeZeroTimelockSigningJob",
    ) as RenewNodeZeroTimelockSigningJob;
    const expected = createZeroTimelockNodeTx(leaf.nodeTx, "regtest");
    const refunds = createInitialTimelockRefundTxs({
      nodeTx: expected.cpfp.txBytes,
      directNodeTx: expected.direct.txBytes,
      receivingPublicKey: leafKey,
      network: "regtest",
    });
    expect(bytesToHex(required(value.nodeTxSigningJob).rawTx)).toBe(
      bytesToHex(expected.cpfp.txBytes),
    );
    expect(bytesToHex(required(value.directNodeTxSigningJob).rawTx)).toBe(
      bytesToHex(expected.direct.txBytes),
    );
    expect(bytesToHex(required(value.refundTxSigningJob).rawTx)).toBe(
      bytesToHex(refunds.cpfpRefund.txBytes),
    );
    expect(bytesToHex(required(value.directFromCpfpRefundTxSigningJob).rawTx)).toBe(
      bytesToHex(refunds.directFromCpfpRefund.txBytes),
    );

    // Sequences: renewed node 0, its direct 50, refunds at the initial 2000 / 2050.
    expect(targets.map((t) => inputSequence(t.transaction))).toStrictEqual([0, 50, 2000, 2050]);
    const leafOutput = Transaction.fromRaw(leaf.nodeTx, {
      allowUnknownOutputs: true,
    }).getOutput(0);
    const nodeOutput = Transaction.fromRaw(expected.cpfp.txBytes, {
      allowUnknownOutputs: true,
    }).getOutput(0);
    const expectedPrevouts = [leafOutput, leafOutput, nodeOutput, nodeOutput];
    for (const [index, target] of targets.entries()) {
      const expectedPrevout = required(expectedPrevouts[index]);
      expect(target.prevouts[0]?.script).toStrictEqual(expectedPrevout.script);
      expect(target.prevouts[0]?.amount).toBe(Number(expectedPrevout.amount));
    }
    signer.dispose();
  });

  test("refund: five jobs, decremented node and fresh refunds", async () => {
    const { signer, leaf } = await setup(300, 100, true);
    const targets: SigningTarget[] = [];
    const recording: SparkSigner = {
      ...signer,
      signFrost: async (jobs) => {
        for (const job of jobs) {
          targets.push(job.target);
        }
        return signer.signFrost(jobs);
      },
    };

    let commitmentsReq: GetSigningCommitmentsRequest | undefined;
    let renewReq: RenewLeafRequest | undefined;
    let nodesReq: QueryNodesRequest | undefined;
    const spark = makeSparkClient({
      query_nodes: (req) => {
        nodesReq = req;
        return create(QueryNodesResponseSchema, {
          nodes: { [PARENT_ID]: fabricateParent(leaf.verifyingPublicKey) },
          offset: 0n,
        });
      },
      get_signing_commitments: (req) => {
        commitmentsReq = req;
        return create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(5),
        });
      },
      renew_leaf: (req) => {
        renewReq = req;
        return renewedNodeResponse("refund");
      },
    });

    await renewLeaf({ spark, signer: recording, network: "regtest", leaf });
    expect(commitmentsReq?.nodeIds).toStrictEqual([LEAF_ID]);
    expect(commitmentsReq?.count).toBe(5);
    expect(nodesReq?.source).toStrictEqual({
      case: "nodeIds",
      value: { nodeIds: [PARENT_ID], $typeName: "spark.TreeNodeIds" },
    });

    expect(renewReq?.signingJobs.case).toBe("renewRefundTimelockSigningJob");
    // Job order: node, directNode, cpfp, direct, directFromCpfp.
    expect(targets.map((t) => inputSequence(t.transaction))).toStrictEqual([
      200, 250, 2000, 2050, 2050,
    ]);
    signer.dispose();
  });

  test("node: seven jobs with a zero-timelock split then a fresh node", async () => {
    const { signer, leaf } = await setup(100, 100, true);
    const targets: SigningTarget[] = [];
    const recording: SparkSigner = {
      ...signer,
      signFrost: async (jobs) => {
        for (const job of jobs) {
          targets.push(job.target);
        }
        return signer.signFrost(jobs);
      },
    };

    let commitmentsReq: GetSigningCommitmentsRequest | undefined;
    let renewReq: RenewLeafRequest | undefined;
    const spark = makeSparkClient({
      query_nodes: () =>
        create(QueryNodesResponseSchema, {
          nodes: { [PARENT_ID]: fabricateParent(leaf.verifyingPublicKey) },
          offset: 0n,
        }),
      get_signing_commitments: (req) => {
        commitmentsReq = req;
        return create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(7),
        });
      },
      renew_leaf: (req) => {
        renewReq = req;
        return renewedNodeResponse("node");
      },
    });

    await renewLeaf({ spark, signer: recording, network: "regtest", leaf });
    expect(commitmentsReq?.count).toBe(7);

    const value = signingJobValue(
      renewReq,
      "renewNodeTimelockSigningJob",
    ) as RenewNodeTimelockSigningJob;
    // Job order: split, directSplit, node, directNode, cpfp, direct, directFromCpfp.
    expect(targets.map((t) => inputSequence(t.transaction))).toStrictEqual([
      0, 50, 2000, 2050, 2000, 2050, 2050,
    ]);
    expect(value.splitNodeTxSigningJob).toBeDefined();
    expect(value.splitNodeDirectTxSigningJob).toBeDefined();
    signer.dispose();
  });

  test("rejects a leaf that does not need renewal", async () => {
    const { signer, leaf } = await setup(0, 2000, false);
    const spark = makeSparkClient({});
    await expect(renewLeaf({ spark, signer, network: "regtest", leaf })).rejects.toThrow(
      "does not need renewal",
    );
    signer.dispose();
  });

  test("rejects a wrong renew_result case", async () => {
    const { signer, leaf } = await setup(0, 100, false);
    const spark = makeSparkClient({
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(4),
        }),
      renew_leaf: () => renewedNodeResponse("refund"),
    });
    await expect(renewLeaf({ spark, signer, network: "regtest", leaf })).rejects.toThrow(
      "expected renewNodeZeroTimelockResult",
    );
    signer.dispose();
  });

  test("rejects a missing parent node", async () => {
    const { signer, leaf } = await setup(300, 100, true);
    const spark = makeSparkClient({
      query_nodes: () => create(QueryNodesResponseSchema, { nodes: {}, offset: 0n }),
    });
    await expect(renewLeaf({ spark, signer, network: "regtest", leaf })).rejects.toThrow(
      "parent node",
    );
    signer.dispose();
  });
});

describe("transfers.send renewal", () => {
  test("renews a stale leaf before starting the transfer", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const leaf = fabricateLeaf({
      nodeSequence: 0,
      refundSequence: 100,
      signingPublicKey: required(leafKey),
      ownerIdentityPublicKey: identity,
    });
    const node = leafNode(leaf);
    const receiverIdentity = secp256k1.getPublicKey(new Uint8Array(32).fill(4), true);

    const events: string[] = [];
    let startReq: StartTransferRequest | undefined;
    const client = makeWalletClient(signer, {
      query_nodes: () =>
        create(QueryNodesResponseSchema, { nodes: { [leaf.id]: node }, offset: -1n }),
      get_signing_commitments: (req) =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(req.count),
        }),
      renew_leaf: (req) => {
        events.push("renew");
        return renewZeroResponse(req, node);
      },
      start_transfer_v2: (req) => {
        events.push("send");
        startReq = req;
        return create(StartTransferResponseSchema, {
          transfer: create(TransferSchema, {
            id: req.transferId,
            senderIdentityPublicKey: req.ownerIdentityPublicKey,
            receiverIdentityPublicKey: req.receiverIdentityPublicKey,
            status: TransferStatus.SENDER_INITIATED,
            type: TransferType.TRANSFER,
            network: Network.REGTEST,
            totalValue: 100_000n,
          }),
        });
      },
    });

    await client.transfers.send({ receiver: receiverIdentity, amountSats: 100_000 });
    expect(events).toStrictEqual(["renew", "send"]);

    // The sent refund is decremented from the renewed 2000-timelock refund.
    const cpfpJob = required(startReq?.transferPackage?.leavesToSend[0]);
    expect(inputSequence(cpfpJob.rawTx)).toBe(1900);
    signer.dispose();
  });
});
