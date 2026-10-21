import { create } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { expect, test } from "vite-plus/test";

import { p2trScriptFromPublicKey, txId } from "../src/core/bitcoin/index.ts";
import { Network, TreeNodeSchema, TreeNodeStatus } from "../src/proto/gen/spark_pb.ts";
import type { TreeNode } from "../src/proto/gen/spark_pb.ts";
import {
  malformedLeafTx,
  mapTreeNode,
  operatorsDisagree,
  ownsLeaf,
  selectExact,
  selectExactMany,
  selectLeaves,
} from "../src/tree/index.ts";
import type { SparkLeaf } from "../src/tree/index.ts";

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

test("selectExactMany assigns disjoint groups, smallest amount first", () => {
  // 10 has no single leaf: greedy descending takes 8 then 2, so the ascending pass must leave
  // a fitting pair — processing 10 first would consume both 8-sat leaves and starve the 8.
  const leaves = [
    selectLeaf("a", 8),
    selectLeaf("b", 8),
    selectLeaf("c", 16),
    selectLeaf("d", 8),
    selectLeaf("e", 2),
  ];
  const groups = selectExactMany(leaves, [8, 10]);
  expect(groups?.map((group) => group.map((leaf) => leaf.id))).toStrictEqual([["a"], ["b", "e"]]);
});

test("selectExactMany returns groups in the order amounts listed them", () => {
  const leaves = [selectLeaf("a", 2), selectLeaf("b", 3)];
  const groups = selectExactMany(leaves, [3, 2]);
  expect(groups?.map((group) => group.map((leaf) => leaf.id))).toStrictEqual([["b"], ["a"]]);
});

test("selectExactMany fails when any amount cannot be matched exactly", () => {
  const leaves = [selectLeaf("a", 8), selectLeaf("b", 8)];
  expect(selectExactMany(leaves, [8, 9])).toBeUndefined();
  // Overlapping need: only one 8-sat leaf exists.
  expect(selectExactMany(leaves, [8])).toBeDefined();
  expect(selectExactMany([selectLeaf("a", 8)], [8, 8])).toBeUndefined();
});

test("selectLeaves returns exact selections unchanged", () => {
  const leaves = [selectLeaf("a", 8), selectLeaf("b", 8)];
  const selection = selectLeaves(leaves, [16]);
  expect(selection).toStrictEqual({ kind: "exact", groups: [[leaves[0], leaves[1]]] });
});

test("selectLeaves picks the smallest single leaf covering the amount", () => {
  const leaves = [selectLeaf("a", 10), selectLeaf("b", 64), selectLeaf("c", 100)];
  const selection = selectLeaves(leaves, [40]);
  expect(selection).toStrictEqual({ kind: "swap", leaves: [leaves[1]] });
});

test("selectLeaves accumulates descending when no single leaf covers the amount", () => {
  const leaves = [selectLeaf("a", 20), selectLeaf("b", 15)];
  const selection = selectLeaves(leaves, [25]);
  expect(selection).toStrictEqual({
    kind: "swap",
    leaves: [leaves[0], leaves[1]],
  });
});

test("selectLeaves swaps for the total when only some amounts match exactly", () => {
  // 7 matches exactly, 30 does not — the whole set falls back to one swap covering 37.
  const leaves = [selectLeaf("a", 7), selectLeaf("b", 40)];
  const selection = selectLeaves(leaves, [7, 30]);
  expect(selection).toStrictEqual({ kind: "swap", leaves: [leaves[1]] });
});

test("selectLeaves rejects an insufficient AVAILABLE balance", () => {
  const leaves = [selectLeaf("a", 10), selectLeaf("b", 5, "CREATING")];
  expect(() => selectLeaves(leaves, [20])).toThrow(/insufficient balance/);
});

test("selectLeaves rejects non-positive amounts", () => {
  const leaves = [selectLeaf("a", 10)];
  expect(() => selectLeaves(leaves, [0])).toThrow(/positive safe integer/);
  expect(() => selectLeaves(leaves, [-5])).toThrow(/positive safe integer/);
  expect(() => selectLeaves(leaves, [1.5])).toThrow(/positive safe integer/);
});

test("selectLeaves rejects an empty amounts list", () => {
  expect(() => selectLeaves([selectLeaf("a", 10)], [])).toThrow(/must not be empty/);
});

const VERIFY_KEY = secp256k1.getPublicKey(new Uint8Array(32).fill(9), true);

function txSpending(prevTxid: Uint8Array): Uint8Array {
  const tx = new Transaction({ allowUnknownOutputs: true });
  tx.addInput({ txid: prevTxid, index: 0, sequence: 0x200 });
  tx.addOutput({ script: p2trScriptFromPublicKey(VERIFY_KEY, "mainnet"), amount: 1000n });
  return tx.toBytes(true);
}

function verifyLeaf(overrides: Partial<SparkLeaf> = {}): SparkLeaf {
  const nodeTx = txSpending(new Uint8Array(32).fill(1));
  const refundTx = txSpending(hexToBytes(txId(nodeTx)));
  const leaf = mapTreeNode(
    makeNode({
      nodeTx,
      refundTx,
      verifyingPublicKey: VERIFY_KEY,
      signingKeyshare: {
        ownerIdentifiers: ["op-0", "op-1"],
        threshold: 2,
        publicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(7), true),
        publicShares: {},
      },
    }),
  );
  return { ...leaf, ...overrides };
}

test("malformedLeafTx accepts a well-formed leaf", () => {
  expect(malformedLeafTx(verifyLeaf())).toBeUndefined();
});

test("malformedLeafTx names each defect", () => {
  // A 0-input transaction cannot round-trip scure's parser, so it lands on the parse defect.
  const noInputs = new Transaction({ allowUnknownOutputs: true });
  noInputs.addOutput({ script: p2trScriptFromPublicKey(VERIFY_KEY, "mainnet"), amount: 1000n });
  expect(malformedLeafTx(verifyLeaf({ nodeTx: noInputs.toBytes(true) }))).toBe(
    "node tx fails to parse",
  );

  const noOutputs = new Transaction({ allowUnknownOutputs: true });
  noOutputs.addInput({ txid: new Uint8Array(32).fill(2), index: 0, sequence: 0x200 });
  expect(malformedLeafTx(verifyLeaf({ refundTx: noOutputs.toBytes(true) }))).toBe(
    "refund tx has no outputs",
  );

  expect(malformedLeafTx(verifyLeaf({ nodeTx: new Uint8Array([0xaa]) }))).toBe(
    "node tx fails to parse",
  );
});

test("operatorsDisagree compares the fields a spend commits to", () => {
  const leaf = verifyLeaf();
  expect(operatorsDisagree(leaf, verifyLeaf())).toBe(false);
  expect(operatorsDisagree(leaf, verifyLeaf({ valueSats: 999 }))).toBe(true);
  expect(operatorsDisagree(leaf, verifyLeaf({ status: "CREATING" }))).toBe(true);
  expect(operatorsDisagree(leaf, verifyLeaf({ vout: 2 }))).toBe(true);
  expect(
    operatorsDisagree(
      leaf,
      verifyLeaf({ verifyingPublicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(10), true) }),
    ),
  ).toBe(true);
  expect(
    operatorsDisagree(leaf, verifyLeaf({ nodeTx: txSpending(new Uint8Array(32).fill(9)) })),
  ).toBe(true);
  expect(
    operatorsDisagree(
      leaf,
      verifyLeaf({
        signingKeyshare: {
          ...leaf.signingKeyshare,
          publicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(8), true),
        },
      }),
    ),
  ).toBe(true);
});

test("operatorsDisagree compares the direct refund variants too", () => {
  const directTx = txSpending(new Uint8Array(32).fill(3));
  const directRefundTx = txSpending(new Uint8Array(32).fill(4));
  const directFromCpfpRefundTx = txSpending(new Uint8Array(32).fill(5));
  const leaf = verifyLeaf({ directTx, directRefundTx, directFromCpfpRefundTx });
  expect(
    operatorsDisagree(leaf, verifyLeaf({ directTx, directRefundTx, directFromCpfpRefundTx })),
  ).toBe(false);
  // Absent on one side and present on the other is a real disagreement: mapTreeNode already
  // normalized empty bytes to undefined.
  expect(operatorsDisagree(leaf, verifyLeaf({ directTx }))).toBe(true);
  expect(operatorsDisagree(verifyLeaf({ directTx }), leaf)).toBe(true);
  expect(
    operatorsDisagree(
      leaf,
      verifyLeaf({
        directTx,
        directRefundTx: txSpending(new Uint8Array(32).fill(6)),
        directFromCpfpRefundTx,
      }),
    ),
  ).toBe(true);
  expect(
    operatorsDisagree(
      leaf,
      verifyLeaf({
        directTx,
        directRefundTx,
        directFromCpfpRefundTx: txSpending(new Uint8Array(32).fill(7)),
      }),
    ),
  ).toBe(true);
});

test("ownsLeaf checks our key plus the share reaches the verifying key", () => {
  const ourSecret = new Uint8Array(32).fill(3);
  const shareSecret = new Uint8Array(32).fill(4);
  const verifying = secp256k1.Point.fromBytes(secp256k1.getPublicKey(ourSecret, true))
    .add(secp256k1.Point.fromBytes(secp256k1.getPublicKey(shareSecret, true)))
    .toBytes(true);
  const leaf = verifyLeaf({
    verifyingPublicKey: verifying,
    signingKeyshare: {
      ownerIdentifiers: ["op-0", "op-1"],
      threshold: 2,
      publicKey: secp256k1.getPublicKey(shareSecret, true),
    },
  });
  expect(ownsLeaf(leaf, secp256k1.getPublicKey(ourSecret, true))).toBe(true);
  expect(ownsLeaf(leaf, secp256k1.getPublicKey(new Uint8Array(32).fill(5), true))).toBe(false);
  expect(ownsLeaf(leaf, new Uint8Array(33))).toBe(false);
});
