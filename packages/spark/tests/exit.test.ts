import { create } from "@bufbuild/protobuf";
import { createClient, createRouterTransport } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import { p2trScriptFromPublicKey, txId } from "../src/core/bitcoin/index.ts";
import { SparkError, SparkInputError } from "../src/errors/index.ts";
import { exitChain, unilateralExitTransactions } from "../src/exit/unilateral.ts";
import {
  Network,
  QueryNodesResponseSchema,
  SparkService,
  TreeNodeSchema,
  TreeNodeStatus,
} from "../src/proto/gen/spark_pb.ts";
import type { SparkLeaf } from "../src/tree/index.ts";

const OPERATORS = ["id0001", "id0002"];
const KEY = secp256k1.Point.BASE.multiply(5n).toBytes(true);

/** Asymmetric fake display-order txid derived from a label byte. */
function fakeTxid(label: number): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = (label + i) % 256;
  }
  return out;
}

function txSpending(prevTxid: Uint8Array, sequence: number): Uint8Array {
  const tx = new Transaction({ allowUnknownOutputs: true });
  tx.addInput({ txid: prevTxid, index: 0, sequence });
  tx.addOutput({ script: p2trScriptFromPublicKey(KEY, "regtest"), amount: 100_000n });
  return tx.toBytes(true);
}

function leafNode(options: {
  readonly id: string;
  readonly parent?: string;
  readonly nodeSequence?: number;
  readonly refundSequence?: number;
  readonly hasRefund?: boolean;
}): SparkLeaf {
  const nodeTx = txSpending(fakeTxid(0x11), options.nodeSequence ?? 0);
  return {
    id: options.id,
    treeId: `tree-${options.id}`,
    valueSats: 100_000,
    status: "AVAILABLE",
    nodeTx,
    // btc-signer keeps input txids in display order.
    refundTx:
      options.hasRefund === false
        ? new Uint8Array(0)
        : txSpending(hexToBytes(txId(nodeTx)), options.refundSequence ?? 500),
    verifyingPublicKey: KEY,
    ownerIdentityPublicKey: new Uint8Array(33).fill(6),
    ownerSigningPublicKey: new Uint8Array(33).fill(6),
    signingKeyshare: { ownerIdentifiers: OPERATORS, threshold: 1, publicKey: KEY },
    vout: 0,
    ...(options.parent === undefined ? {} : { parentNodeId: options.parent }),
  };
}

function treeNodeProto(leaf: SparkLeaf) {
  return create(TreeNodeSchema, {
    id: leaf.id,
    treeId: leaf.treeId,
    value: 100_000n,
    nodeTx: leaf.nodeTx,
    refundTx: leaf.refundTx,
    vout: leaf.vout,
    verifyingPublicKey: leaf.verifyingPublicKey,
    ownerIdentityPublicKey: leaf.ownerIdentityPublicKey,
    ownerSigningPublicKey: leaf.ownerSigningPublicKey,
    signingKeyshare: {
      ownerIdentifiers: OPERATORS,
      threshold: 1,
      publicKey: leaf.signingKeyshare.publicKey,
      publicShares: {},
    },
    status: leaf.status,
    network: Network.REGTEST,
    treenodeStatus: TreeNodeStatus.AVAILABLE,
    ...(leaf.parentNodeId === undefined ? {} : { parentNodeId: leaf.parentNodeId }),
  });
}

function required<T>(value: T | undefined): T {
  if (value === undefined) {
    throw new Error("required value missing");
  }
  return value;
}

function sparkReturning(leaves: ReadonlyArray<SparkLeaf>) {
  const nodes: Record<string, ReturnType<typeof treeNodeProto>> = {};
  for (const leaf of leaves) {
    nodes[leaf.id] = treeNodeProto(leaf);
  }
  const transport = createRouterTransport((router) => {
    router.service(SparkService, {
      query_nodes: () => create(QueryNodesResponseSchema, { nodes, offset: 0n }),
    });
  });
  return createClient(SparkService, transport);
}

describe("exitChain", () => {
  test("walks leaf to root regardless of status and reverses to root-first", () => {
    const root = leafNode({ id: "root" });
    const mid = leafNode({ id: "mid", parent: "root" });
    const leaf = leafNode({ id: "leaf", parent: "mid" });
    const burnt = { ...mid, status: "LOST" };
    const nodes = new Map([
      ["root", root],
      ["mid", burnt],
      ["leaf", leaf],
    ]);
    expect(exitChain("leaf", nodes).map((node) => node.id)).toStrictEqual(["root", "mid", "leaf"]);
  });

  test("root-only chain for a deposit leaf", () => {
    const root = leafNode({ id: "root" });
    expect(exitChain("root", new Map([["root", root]])).map((n) => n.id)).toStrictEqual(["root"]);
  });

  test("guards cycles", () => {
    const a = leafNode({ id: "a", parent: "b" });
    const b = leafNode({ id: "b", parent: "a" });
    expect(() =>
      exitChain(
        "a",
        new Map([
          ["a", a],
          ["b", b],
        ]),
      ),
    ).toThrow(SparkError);
  });

  test("names a missing parent", () => {
    const leaf = leafNode({ id: "leaf", parent: "ghost" });
    expect(() => exitChain("leaf", new Map([["leaf", leaf]]))).toThrow(/ghost/);
  });

  test("throws when the requested id is absent", () => {
    expect(() => exitChain("nope", new Map())).toThrow(SparkError);
  });
});

describe("unilateralExitTransactions", () => {
  const ROOT = leafNode({ id: "root" });
  const MID = leafNode({ id: "mid", parent: "root", nodeSequence: 2000 });
  const LEAF_A = leafNode({
    id: "leaf-a",
    parent: "mid",
    nodeSequence: 1900,
    refundSequence: 2000,
  });
  const LEAF_B = leafNode({
    id: "leaf-b",
    parent: "mid",
    nodeSequence: 1800,
    refundSequence: 1900,
  });
  const ALL = [ROOT, MID, LEAF_A, LEAF_B];

  test("emits root-to-leaf chains, dedupes shared ancestors, refund right after its leaf", async () => {
    const spark = sparkReturning(ALL);
    const out = await unilateralExitTransactions({
      spark,
      network: "regtest",
      leafIds: ["leaf-a", "leaf-b"],
    });
    expect(out.map((tx) => `${tx.nodeId}:${tx.kind}`)).toStrictEqual([
      "root:node",
      "mid:node",
      "leaf-a:node",
      "leaf-a:refund",
      "leaf-b:node",
      "leaf-b:refund",
    ]);
  });

  test("reports txids, parentTxid and relative timelocks", async () => {
    const spark = sparkReturning(ALL);
    const [out] = [
      await unilateralExitTransactions({ spark, network: "regtest", leafIds: ["leaf-b"] }),
    ];
    const [rootTx, midTx, leafTx, refundTx] = out;
    const root = required(rootTx);
    const mid = required(midTx);
    const leaf = required(leafTx);
    const refund = required(refundTx);
    expect(root.txid).toBe(txId(ROOT.nodeTx));
    expect(root.relativeTimelock).toBe(0);
    expect(mid.relativeTimelock).toBe(2000);
    expect(leaf.txid).toBe(txId(LEAF_B.nodeTx));
    expect(leaf.parentTxid).toBe(bytesToHex(fakeTxid(0x11)));
    expect(leaf.relativeTimelock).toBe(1800);
    expect(refund.txid).toBe(txId(LEAF_B.refundTx));
    expect(refund.parentTxid).toBe(txId(LEAF_B.nodeTx));
    expect(refund.relativeTimelock).toBe(1900);
  });

  test("queries with nodeIds, includeParents and empty statuses", async () => {
    let captured: unknown;
    const transport = createRouterTransport((router) => {
      router.service(SparkService, {
        query_nodes: (req: { source: unknown; includeParents: boolean; statuses: unknown[] }) => {
          captured = {
            source: req.source,
            includeParents: req.includeParents,
            statuses: req.statuses,
          };
          return create(QueryNodesResponseSchema, { nodes: {}, offset: 0n });
        },
      });
    });
    const spark = createClient(SparkService, transport);
    await expect(
      unilateralExitTransactions({ spark, network: "regtest", leafIds: ["leaf-a"] }),
    ).rejects.toThrow(SparkInputError);
    const req = captured as {
      source: { case: string; value: { nodeIds: string[] } };
      includeParents: boolean;
      statuses: unknown[];
    };
    expect(req.source.case).toBe("nodeIds");
    expect(req.source.value.nodeIds).toStrictEqual(["leaf-a"]);
    expect(req.includeParents).toBe(true);
    expect(req.statuses).toStrictEqual([]);
  });

  test("rejects a requested id the query does not return", async () => {
    const spark = sparkReturning(ALL);
    await expect(
      unilateralExitTransactions({ spark, network: "regtest", leafIds: ["stranger"] }),
    ).rejects.toThrow(SparkInputError);
  });

  test("rejects a requested node that is not a leaf", async () => {
    const noRefund = leafNode({ id: "node-only", hasRefund: false });
    const spark = sparkReturning([noRefund]);
    await expect(
      unilateralExitTransactions({ spark, network: "regtest", leafIds: ["node-only"] }),
    ).rejects.toThrow(/not a leaf/);
  });

  test("fails when a parent is missing from the query result", async () => {
    const spark = sparkReturning([LEAF_A]);
    await expect(
      unilateralExitTransactions({ spark, network: "regtest", leafIds: ["leaf-a"] }),
    ).rejects.toThrow(/mid/);
  });

  test("empty input makes no call", async () => {
    let calls = 0;
    const transport = createRouterTransport((router) => {
      router.service(SparkService, {
        query_nodes: () => {
          calls += 1;
          return create(QueryNodesResponseSchema, { nodes: {}, offset: 0n });
        },
      });
    });
    const spark = createClient(SparkService, transport);
    await expect(
      unilateralExitTransactions({ spark, network: "regtest", leafIds: [] }),
    ).resolves.toStrictEqual([]);
    expect(calls).toBe(0);
  });
});
