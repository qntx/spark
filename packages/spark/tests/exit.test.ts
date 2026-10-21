import { create } from "@bufbuild/protobuf";
import { createClient, createRouterTransport } from "@connectrpc/connect";
import type { Transport } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import { p2trScriptFromPublicKey, txId } from "../src/core/bitcoin/index.ts";
import { SparkError, SparkInputError } from "../src/errors/index.ts";
import {
  buildExitChains,
  exitChain,
  exitTransactions,
  queryExitChains,
  unilateralExitTransactions,
} from "../src/exit/unilateral.ts";
import {
  Network,
  QueryNodesResponseSchema,
  SparkService,
  TreeNodeSchema,
  TreeNodeStatus,
} from "../src/proto/gen/spark_pb.ts";
import type { QueryNodesRequest } from "../src/proto/gen/spark_pb.ts";
import type { SparkLeafKey, SparkSigner } from "../src/signer/types.ts";
import type { SparkLeaf } from "../src/tree/index.ts";

const OPERATORS = ["id0001", "id0002"];
const KEY = secp256k1.Point.BASE.multiply(5n).toBytes(true);
const OTHER_KEY = secp256k1.Point.BASE.multiply(7n).toBytes(true);

const REFUND_SCRIPT = p2trScriptFromPublicKey(KEY, "regtest");

/** Leaf id → the key-path script the signer's own `LEAF{id}` key pays. */
function refundScripts(...leafIds: ReadonlyArray<string>): ReadonlyMap<string, Uint8Array> {
  return new Map(leafIds.map((leafId) => [leafId, REFUND_SCRIPT]));
}

/** Signer stub: `publicKeys` answers KEY for every leaf — the owner of the fixture refunds. */
const SIGNER = {
  // oxlint-disable-next-line require-await -- the SparkSigner shape is async; nothing awaits here
  publicKeys: async (keys: ReadonlyArray<SparkLeafKey>) => keys.map(() => KEY),
} as unknown as SparkSigner;

/** Asymmetric fake display-order txid derived from a label byte. */
function fakeTxid(label: number): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = (label + i) % 256;
  }
  return out;
}

function txSpending(prevTxid: Uint8Array, sequence: number, payKey: Uint8Array = KEY): Uint8Array {
  const tx = new Transaction({ allowUnknownOutputs: true });
  tx.addInput({ txid: prevTxid, index: 0, sequence });
  tx.addOutput({ script: p2trScriptFromPublicKey(payKey, "regtest"), amount: 100_000n });
  return tx.toBytes(true);
}

function leafNode(options: {
  readonly id: string;
  readonly parent?: string;
  /** The parent node's tx; the child spends its output 0 (the node's `vout`). */
  readonly parentTx?: Uint8Array;
  readonly nodeSequence?: number;
  readonly refundSequence?: number;
  readonly hasRefund?: boolean;
  /** Prebuilt txs (e.g. shared across many fake nodes) — skips construction. */
  readonly nodeTx?: Uint8Array;
  readonly refundTx?: Uint8Array;
}): SparkLeaf {
  const nodeTx =
    options.nodeTx ??
    txSpending(
      options.parentTx === undefined ? fakeTxid(0x11) : hexToBytes(txId(options.parentTx)),
      options.nodeSequence ?? 0,
    );
  return {
    id: options.id,
    treeId: `tree-${options.id}`,
    valueSats: 100_000,
    status: "AVAILABLE",
    nodeTx,
    // btc-signer keeps input txids in display order.
    refundTx:
      options.refundTx ??
      (options.hasRefund === false
        ? new Uint8Array(0)
        : txSpending(hexToBytes(txId(nodeTx)), options.refundSequence ?? 500)),
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

/** Narrows a query_nodes request to its nodeIds source, failing the test on any other case. */
function nodeIdsFrom(req: QueryNodesRequest): ReadonlyArray<string> {
  if (req.source.case !== "nodeIds") {
    throw new Error(`unexpected query_nodes source: ${req.source.case}`);
  }
  return req.source.value.nodeIds;
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

const ROOT = leafNode({ id: "root" });
const MID = leafNode({ id: "mid", parent: "root", parentTx: ROOT.nodeTx, nodeSequence: 2000 });
const LEAF_A = leafNode({
  id: "leaf-a",
  parent: "mid",
  parentTx: MID.nodeTx,
  nodeSequence: 1900,
  refundSequence: 2000,
});
const LEAF_B = leafNode({
  id: "leaf-b",
  parent: "mid",
  parentTx: MID.nodeTx,
  nodeSequence: 1800,
  refundSequence: 1900,
});
const ALL = [ROOT, MID, LEAF_A, LEAF_B];
const ALL_MAP = new Map(ALL.map((leaf) => [leaf.id, leaf]));

describe("exitTransactions", () => {
  test("emits root-to-leaf chains, dedupes shared ancestors, refund right after its leaf", () => {
    const out = exitTransactions(
      buildExitChains(["leaf-a", "leaf-b"], ALL_MAP, refundScripts("leaf-a", "leaf-b")),
    );
    expect(out.map((tx) => `${tx.nodeId}:${tx.kind}`)).toStrictEqual([
      "root:node",
      "mid:node",
      "leaf-a:node",
      "leaf-a:refund",
      "leaf-b:node",
      "leaf-b:refund",
    ]);
  });

  test("reports txids, parentTxid and relative timelocks", () => {
    const out = exitTransactions(buildExitChains(["leaf-b"], ALL_MAP, refundScripts("leaf-b")));
    const [rootTx, midTx, leafTx, refundTx] = out;
    const root = required(rootTx);
    const mid = required(midTx);
    const leaf = required(leafTx);
    const refund = required(refundTx);
    expect(root.txid).toBe(txId(ROOT.nodeTx));
    expect(root.relativeTimelock).toBe(0);
    expect(mid.relativeTimelock).toBe(2000);
    expect(leaf.txid).toBe(txId(LEAF_B.nodeTx));
    expect(leaf.parentTxid).toBe(txId(MID.nodeTx));
    expect(leaf.relativeTimelock).toBe(1800);
    expect(refund.txid).toBe(txId(LEAF_B.refundTx));
    expect(refund.parentTxid).toBe(txId(LEAF_B.nodeTx));
    expect(refund.relativeTimelock).toBe(1900);
  });
});

describe("buildExitChains linkage", () => {
  test("rejects a child that does not spend its parent's node tx", () => {
    const parent = leafNode({ id: "p" });
    const child = leafNode({ id: "c", parent: "p" });
    const nodes = new Map([
      ["p", parent],
      ["c", child],
    ]);
    expect(() => buildExitChains(["c"], nodes, refundScripts("c"))).toThrow(
      /does not spend its parent output/,
    );
  });

  test("rejects a child spending the parent at the wrong vout", () => {
    const parent = leafNode({ id: "p" });
    // The leaf claims vout 3 but its node tx actually spends output 0.
    const child = {
      ...leafNode({ id: "c", parent: "p", parentTx: parent.nodeTx }),
      vout: 3,
    };
    const nodes = new Map([
      ["p", parent],
      ["c", child],
    ]);
    expect(() => buildExitChains(["c"], nodes, refundScripts("c"))).toThrow(/vout 3/);
  });

  test("rejects a leaf refund that does not spend the leaf node tx", () => {
    const leaf = {
      ...LEAF_A,
      refundTx: txSpending(fakeTxid(0x22), 500),
    };
    const nodes = new Map([...ALL_MAP, ["leaf-a", leaf]]);
    expect(() => buildExitChains(["leaf-a"], nodes, refundScripts("leaf-a"))).toThrow(
      /refund tx of leaf leaf-a does not spend/,
    );
  });

  test("rejects a direct-from-CPFP refund that does not spend the leaf node tx", () => {
    const directFromCpfpRefundTx = txSpending(fakeTxid(0x22), 300);
    const leaf = { ...LEAF_A, directFromCpfpRefundTx };
    const nodes = new Map([...ALL_MAP, ["leaf-a", leaf]]);
    expect(() => buildExitChains(["leaf-a"], nodes, refundScripts("leaf-a"))).toThrow(
      /direct-from-CPFP refund tx of leaf leaf-a does not spend/,
    );
  });

  test("rejects a direct refund that does not spend the leaf direct tx", () => {
    const directTx = txSpending(fakeTxid(0x33), 100);
    const directRefundTx = txSpending(fakeTxid(0x44), 100);
    const leaf = { ...LEAF_A, directTx, directRefundTx };
    const nodes = new Map([...ALL_MAP, ["leaf-a", leaf]]);
    expect(() => buildExitChains(["leaf-a"], nodes, refundScripts("leaf-a"))).toThrow(
      /direct refund tx of leaf leaf-a does not spend/,
    );
  });

  test("rejects a leaf with a direct refund but no direct tx", () => {
    const leaf = { ...LEAF_A, directRefundTx: txSpending(fakeTxid(0x44), 100) };
    const nodes = new Map([...ALL_MAP, ["leaf-a", leaf]]);
    expect(() => buildExitChains(["leaf-a"], nodes, refundScripts("leaf-a"))).toThrow(
      /direct refund but no direct tx/,
    );
  });
});

describe("buildExitChains memoization", () => {
  test("verifies a shared ancestor's link once per call", () => {
    const root = leafNode({ id: "root" });
    const mid = leafNode({ id: "mid", parent: "root", parentTx: root.nodeTx });
    // 2000 leaves share mid and reuse identical linked tx bytes: without the
    // per-call caches this re-parses and re-hashes mid's tx once per leaf.
    const sharedNodeTx = txSpending(hexToBytes(txId(mid.nodeTx)), 100);
    const sharedRefundTx = txSpending(hexToBytes(txId(sharedNodeTx)), 500);
    const nodes = new Map<string, SparkLeaf>([
      ["root", root],
      ["mid", mid],
    ]);
    const leafIds: string[] = [];
    for (let i = 0; i < 2000; i++) {
      const id = `leaf-${i}`;
      leafIds.push(id);
      nodes.set(
        id,
        leafNode({ id, parent: "mid", nodeTx: sharedNodeTx, refundTx: sharedRefundTx }),
      );
    }
    const started = performance.now();
    const chains = buildExitChains(leafIds, nodes, refundScripts(...leafIds));
    const elapsed = performance.now() - started;
    expect(chains).toHaveLength(2000);
    expect(chains[0]?.nodes.map((node) => node.nodeId)).toStrictEqual(["root", "mid", "leaf-0"]);
    expect(elapsed).toBeLessThan(2000);
  });
});

describe("buildExitChains refund destination", () => {
  test("rejects a refund that does not pay the leaf's key-path script", () => {
    const leaf = {
      ...LEAF_A,
      refundTx: txSpending(hexToBytes(txId(LEAF_A.nodeTx)), 500, OTHER_KEY),
    };
    const nodes = new Map([...ALL_MAP, ["leaf-a", leaf]]);
    expect(() => buildExitChains(["leaf-a"], nodes, refundScripts("leaf-a"))).toThrow(
      /refund tx of leaf leaf-a does not pay/,
    );
  });

  test("rejects a direct-from-CPFP refund paying another key", () => {
    const leaf = {
      ...LEAF_A,
      directFromCpfpRefundTx: txSpending(hexToBytes(txId(LEAF_A.nodeTx)), 300, OTHER_KEY),
    };
    const nodes = new Map([...ALL_MAP, ["leaf-a", leaf]]);
    expect(() => buildExitChains(["leaf-a"], nodes, refundScripts("leaf-a"))).toThrow(
      /direct-from-CPFP refund tx of leaf leaf-a does not pay/,
    );
  });

  test("rejects a direct refund paying another key", () => {
    const directTx = txSpending(fakeTxid(0x33), 100);
    const leaf = {
      ...LEAF_A,
      directTx,
      directRefundTx: txSpending(hexToBytes(txId(directTx)), 100, OTHER_KEY),
    };
    const nodes = new Map([...ALL_MAP, ["leaf-a", leaf]]);
    expect(() => buildExitChains(["leaf-a"], nodes, refundScripts("leaf-a"))).toThrow(
      /direct refund tx of leaf leaf-a does not pay/,
    );
  });

  test("rejects a leaf missing from the expected-script map", () => {
    expect(() => buildExitChains(["leaf-a"], ALL_MAP, new Map())).toThrow(
      /no expected refund script for leaf leaf-a/,
    );
  });
});

describe("unilateralExitTransactions", () => {
  test("queries with nodeIds, includeParents and empty statuses", async () => {
    let captured: unknown;
    const transport = createRouterTransport((router) => {
      router.service(SparkService, {
        query_nodes: (req: QueryNodesRequest) => {
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
      unilateralExitTransactions({
        spark,
        network: "regtest",
        signer: SIGNER,
        leafIds: ["leaf-a"],
      }),
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
      unilateralExitTransactions({
        spark,
        network: "regtest",
        signer: SIGNER,
        leafIds: ["stranger"],
      }),
    ).rejects.toThrow(SparkInputError);
  });

  test("rejects a requested node that is not a leaf", async () => {
    const noRefund = leafNode({ id: "node-only", hasRefund: false });
    const spark = sparkReturning([noRefund]);
    await expect(
      unilateralExitTransactions({
        spark,
        network: "regtest",
        signer: SIGNER,
        leafIds: ["node-only"],
      }),
    ).rejects.toThrow(/not a leaf/);
  });

  test("fails when a parent is missing from the query result", async () => {
    const spark = sparkReturning([LEAF_A]);
    await expect(
      unilateralExitTransactions({
        spark,
        network: "regtest",
        signer: SIGNER,
        leafIds: ["leaf-a"],
      }),
    ).rejects.toThrow(/mid/);
  });

  test("rejects a leaf whose served refund pays a different key", async () => {
    // A leaf we do not own: the SO serves a structurally valid chain whose refund pays a
    // stranger's key — the client must refuse rather than return or store it.
    const foreign = {
      ...LEAF_A,
      id: "foreign",
      refundTx: txSpending(hexToBytes(txId(LEAF_A.nodeTx)), 1900, OTHER_KEY),
    };
    const spark = sparkReturning([...ALL, foreign]);
    await expect(
      unilateralExitTransactions({
        spark,
        network: "regtest",
        signer: SIGNER,
        leafIds: ["foreign"],
      }),
    ).rejects.toThrow(/refund tx of leaf foreign does not pay/);
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
      unilateralExitTransactions({ spark, network: "regtest", signer: SIGNER, leafIds: [] }),
    ).resolves.toStrictEqual({ transactions: [], chains: [] });
    expect(calls).toBe(0);
  });
});

describe("queryExitChains", () => {
  test("root leaves need no RPC", async () => {
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
    const { chains } = await queryExitChains({
      spark,
      network: "regtest",
      signer: SIGNER,
      leaves: [ROOT],
    });
    expect(calls).toBe(0);
    expect(chains.map((chain) => chain.leafId)).toStrictEqual(["root"]);
    expect(chains[0]?.nodes.map((node) => node.nodeId)).toStrictEqual(["root"]);
  });

  test("fetches missing ancestors once per 1000 parent ids", async () => {
    const parentIds: string[] = [];
    for (let i = 0; i < 1001; i++) {
      parentIds.push(`p${i}`);
    }
    // One linked parent/leaf/refund tx set shared by every node — this test covers
    // ancestor-id chunking, so per-node tx construction is wasted work.
    const parentTx = txSpending(fakeTxid(0x11), 0);
    const leafTx = txSpending(hexToBytes(txId(parentTx)), 0);
    const leafRefundTx = txSpending(hexToBytes(txId(leafTx)), 500);
    const parentProtos = new Map(
      parentIds.map((id) => [
        id,
        treeNodeProto(leafNode({ id, nodeTx: parentTx, refundTx: leafRefundTx })),
      ]),
    );
    const leaves = parentIds.map((parent) =>
      leafNode({
        id: `leaf-${parent}`,
        parent,
        nodeTx: leafTx,
        refundTx: leafRefundTx,
      }),
    );
    // Respond with the parents only for the requested chunk, through a direct
    // transport that skips the serialization round-trip.
    const calls: Array<ReadonlyArray<string>> = [];
    const transport = {
      unary: async (
        _method: unknown,
        _signal: unknown,
        _timeoutMs: unknown,
        _header: unknown,
        input: unknown,
      ) => {
        const chunk = nodeIdsFrom(input as QueryNodesRequest);
        calls.push(chunk);
        const nodes: Record<string, ReturnType<typeof treeNodeProto>> = {};
        for (const id of chunk) {
          nodes[id] = required(parentProtos.get(id));
        }
        return Promise.resolve({
          stream: false,
          service: SparkService,
          method: SparkService.method.query_nodes,
          header: new Headers(),
          trailer: new Headers(),
          message: create(QueryNodesResponseSchema, { nodes, offset: 0n }),
        });
      },
      stream: async () => Promise.reject(new Error("unimplemented")),
    } as unknown as Transport;
    const spark = createClient(SparkService, transport);
    const { chains } = await queryExitChains({ spark, network: "regtest", signer: SIGNER, leaves });
    expect(calls.map((chunk) => chunk.length)).toStrictEqual([1000, 1]);
    expect(chains).toHaveLength(1001);
  }, 60_000);

  test("the given leaf wins over a node returned for its id", async () => {
    const grandparent = leafNode({ id: "gp" });
    const parent = leafNode({ id: "p", parent: "gp", parentTx: grandparent.nodeTx });
    const leaf = leafNode({ id: "leaf", parent: "p", parentTx: parent.nodeTx });
    const staleLeaf = { ...leaf, refundTx: leafNode({ id: "x", parentTx: leaf.nodeTx }).refundTx };
    const transport = createRouterTransport((router) => {
      router.service(SparkService, {
        query_nodes: () =>
          create(QueryNodesResponseSchema, {
            nodes: {
              p: treeNodeProto(parent),
              gp: treeNodeProto(grandparent),
              leaf: treeNodeProto(staleLeaf),
            },
            offset: 0n,
          }),
      });
    });
    const spark = createClient(SparkService, transport);
    const { chains } = await queryExitChains({
      spark,
      network: "regtest",
      signer: SIGNER,
      leaves: [leaf],
    });
    const [chain] = chains;
    expect(chain?.nodes.map((node) => node.nodeId)).toStrictEqual(["gp", "p", "leaf"]);
    expect(chain?.refundTx).toStrictEqual(leaf.refundTx);
  });

  test("a parent missing from the query result rejects only that leaf", async () => {
    const leaf = leafNode({ id: "leaf", parent: "ghost" });
    const transport = createRouterTransport((router) => {
      router.service(SparkService, {
        query_nodes: () => create(QueryNodesResponseSchema, { nodes: {}, offset: 0n }),
      });
    });
    const spark = createClient(SparkService, transport);
    const { chains, rejected } = await queryExitChains({
      spark,
      network: "regtest",
      signer: SIGNER,
      leaves: [leaf],
    });
    expect(chains).toHaveLength(0);
    expect(rejected).toHaveLength(1);
    expect(rejected[0]?.leafId).toBe("leaf");
    expect(rejected[0]?.error.message).toMatch(/ghost/);
  });
});
