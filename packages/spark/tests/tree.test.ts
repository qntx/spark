import { create } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { expect, test } from "vite-plus/test";

import { Network, TreeNodeSchema, TreeNodeStatus } from "../src/proto/gen/spark_pb.ts";
import type { TreeNode } from "../src/proto/gen/spark_pb.ts";
import { mapTreeNode } from "../src/tree/index.ts";

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
