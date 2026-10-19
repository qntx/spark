import { create } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { expect, test } from "vite-plus/test";

import { Network, TreeNodeSchema, TreeNodeStatus } from "../src/proto/gen/spark_pb.ts";
import type { TreeNode } from "../src/proto/gen/spark_pb.ts";
import { mapTreeNode, selectExact, selectLeaves } from "../src/tree/index.ts";

function makeNode(overrides: object): TreeNode {
  return create(TreeNodeSchema, {
    id: "leaf-1",
    treeId: "tree-1",
    value: 500n,
    status: "AVAILABLE",
    nodeTx: new Uint8Array([1]),
    refundTx: new Uint8Array([2]),
    vout: 1,
    verifyingPublicKey: new Uint8Array(33).fill(5),
    ownerIdentityPublicKey: new Uint8Array(33).fill(6),
    ownerSigningPublicKey: new Uint8Array(33).fill(6),
    signingKeyshare: {
      ownerIdentifiers: ["op-0", "op-1"],
      threshold: 2,
      publicKey: new Uint8Array(33).fill(7),
      publicShares: {},
    },
    network: Network.MAINNET,
    treenodeStatus: TreeNodeStatus.AVAILABLE,
    createdTime: timestampFromMs(1_700_000_000_000),
    updatedTime: timestampFromMs(1_700_000_000_000),
    ...overrides,
  });
}

test("mapTreeNode carries every optional field when present", () => {
  const leaf = mapTreeNode(
    makeNode({
      parentNodeId: "parent-1",
      directTx: new Uint8Array([10]),
      directRefundTx: new Uint8Array([11]),
      directFromCpfpRefundTx: new Uint8Array([12]),
    }),
  );
  expect(leaf.parentNodeId).toBe("parent-1");
  expect(leaf.directTx).toStrictEqual(new Uint8Array([10]));
  expect(leaf.directRefundTx).toStrictEqual(new Uint8Array([11]));
  expect(leaf.directFromCpfpRefundTx).toStrictEqual(new Uint8Array([12]));
});

test("mapTreeNode drops empty optional fields", () => {
  const leaf = mapTreeNode(makeNode({}));
  expect(leaf.parentNodeId).toBeUndefined();
  expect(leaf.directTx).toBeUndefined();
  expect(leaf.directRefundTx).toBeUndefined();
  expect(leaf.directFromCpfpRefundTx).toBeUndefined();
});

function selectLeaf(id: string, valueSats: number, status = "AVAILABLE") {
  return mapTreeNode(makeNode({ id, value: BigInt(valueSats), status }));
}

test("selectExact prefers a single exact leaf", () => {
  const leaves = [selectLeaf("a", 100), selectLeaf("b", 200), selectLeaf("c", 300)];
  const selected = selectExact(leaves, 200);
  expect(selected?.map((leaf) => leaf.id)).toStrictEqual(["b"]);
});

test("selectExact falls back to the descending greedy pass", () => {
  const leaves = [selectLeaf("a", 64), selectLeaf("b", 32), selectLeaf("c", 4)];
  const selected = selectExact(leaves, 36);
  expect(selected?.map((leaf) => leaf.id)).toStrictEqual(["b", "c"]);
});

test("selectExact pass 2 retried on power-of-two leaves only", () => {
  const leaves = [selectLeaf("a", 3), selectLeaf("b", 2), selectLeaf("c", 2)];
  const selected = selectExact(leaves, 4);
  expect(selected?.map((leaf) => leaf.id)).toStrictEqual(["b", "c"]);
});

test("selectExact ignores non-AVAILABLE leaves", () => {
  const leaves = [selectLeaf("a", 100, "CREATING"), selectLeaf("b", 50)];
  expect(selectExact(leaves, 100)).toBeUndefined();
  expect(selectExact(leaves, 50)?.map((leaf) => leaf.id)).toStrictEqual(["b"]);
});

test("selectLeaves returns exact selections unchanged", () => {
  const leaves = [selectLeaf("a", 8), selectLeaf("b", 8)];
  const selection = selectLeaves(leaves, 16);
  expect(selection.kind).toBe("exact");
  expect(selection.leaves.map((leaf) => leaf.id)).toStrictEqual(["a", "b"]);
});

test("selectLeaves picks the smallest single leaf covering the amount", () => {
  const leaves = [selectLeaf("a", 10), selectLeaf("b", 64), selectLeaf("c", 100)];
  const selection = selectLeaves(leaves, 40);
  expect(selection).toStrictEqual({ kind: "swap", leaves: [leaves[1]] });
});

test("selectLeaves accumulates descending when no single leaf covers the amount", () => {
  const leaves = [selectLeaf("a", 20), selectLeaf("b", 15)];
  const selection = selectLeaves(leaves, 25);
  expect(selection.kind).toBe("swap");
  expect(selection.leaves.map((leaf) => leaf.id)).toStrictEqual(["a", "b"]);
});

test("selectLeaves rejects an insufficient AVAILABLE balance", () => {
  const leaves = [selectLeaf("a", 10), selectLeaf("b", 5, "CREATING")];
  expect(() => selectLeaves(leaves, 20)).toThrow(/insufficient balance/);
});

test("selectLeaves rejects non-positive amounts", () => {
  const leaves = [selectLeaf("a", 10)];
  expect(() => selectLeaves(leaves, 0)).toThrow(/positive safe integer/);
  expect(() => selectLeaves(leaves, -5)).toThrow(/positive safe integer/);
  expect(() => selectLeaves(leaves, 1.5)).toThrow(/positive safe integer/);
});
