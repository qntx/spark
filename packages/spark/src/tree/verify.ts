import { secp256k1 } from "@noble/curves/secp256k1.js";
import { equalBytes } from "@noble/curves/utils.js";

import { parseTransaction } from "../core/bitcoin/sighash.ts";
import type { SparkLeaf } from "./index.ts";

// Leaf verification ported from breez-spark-sdk crates/spark/src/tree/service.rs @956ff90
// (`malformed_tx`, `operators_disagree`, `retain_owned`): the coordinator is a server and can lie,
// so a leaf enters the spendable pool only when it is well-formed, provably held under a key this
// wallet derives, and reported identically by every operator.

/**
 * Names the first of the leaf's defects — an unparseable, input-less or output-less transaction, or
 * a value label the node tx does not back — or undefined when the leaf is well-formed.
 *
 * A leaf's `valueSats` must equal what its node tx output 0 pays: that is the output the leaf's
 * refunds spend and the amount the upstream SO takes as the leaf's value (`renew_leaf_handler.go`
 * uses `TxOut[0].Value`). Internal tree nodes have one output per child, so this is a leaf-only
 * invariant — callers apply it only to leaves. A label the transaction does not back lets a
 * coordinator make the wallet pay a larger real output for a smaller declared amount, so an unbound
 * value is disqualifying wherever the leaf came from.
 */
export function malformedLeafTx(leaf: SparkLeaf): string | undefined {
  const candidates: ReadonlyArray<readonly [string, Uint8Array | undefined]> = [
    ["node tx", leaf.nodeTx],
    ["refund tx", leaf.refundTx.length === 0 ? undefined : leaf.refundTx],
    ["direct tx", leaf.directTx],
    ["direct refund tx", leaf.directRefundTx],
    ["direct from cpfp refund tx", leaf.directFromCpfpRefundTx],
  ];
  let nodeTx;
  for (const [name, bytes] of candidates) {
    if (bytes === undefined) {
      continue;
    }
    let tx;
    try {
      tx = parseTransaction(bytes);
    } catch {
      return `${name} fails to parse`;
    }
    if (tx.inputsLength === 0 && tx.outputsLength === 0) {
      return `${name} has no inputs and no outputs`;
    }
    if (tx.inputsLength === 0) {
      return `${name} has no inputs`;
    }
    if (tx.outputsLength === 0) {
      return `${name} has no outputs`;
    }
    if (name === "node tx") {
      nodeTx = tx;
    }
  }
  if (nodeTx !== undefined) {
    const { amount } = nodeTx.getOutput(0);
    if (amount === undefined || amount !== BigInt(leaf.valueSats)) {
      return "node tx output 0 does not pay the leaf's value";
    }
  }
  return undefined;
}

/**
 * Whether the coordinator's copy of a leaf and another operator's copy describe different leaves.
 * Compares every field a spend commits to: `valueSats` is the amount the wallet pays or exits the
 * leaf for, `verifyingPublicKey` is the key signing must reach, and `vout` locates the leaf in
 * `nodeTx` — a coordinator reporting any of them differently is as disqualifying as a different
 * transaction. `parentNodeId` and `treeId` decide which exit chain the leaf belongs to — a
 * coordinator that blanks or retargets them would truncate or swap the stored unilateral-exit
 * chain, so a differing link is a disagreement like any other.
 */
export function operatorsDisagree(coordinator: SparkLeaf, operator: SparkLeaf): boolean {
  return (
    operator.status !== coordinator.status ||
    operator.valueSats !== coordinator.valueSats ||
    operator.vout !== coordinator.vout ||
    operator.treeId !== coordinator.treeId ||
    operator.parentNodeId !== coordinator.parentNodeId ||
    !equalBytes(operator.verifyingPublicKey, coordinator.verifyingPublicKey) ||
    !equalBytes(operator.signingKeyshare.publicKey, coordinator.signingKeyshare.publicKey) ||
    !equalBytes(operator.nodeTx, coordinator.nodeTx) ||
    !equalBytes(operator.refundTx, coordinator.refundTx) ||
    !sameOptionalBytes(operator.directTx, coordinator.directTx) ||
    !sameOptionalBytes(operator.directRefundTx, coordinator.directRefundTx) ||
    !sameOptionalBytes(operator.directFromCpfpRefundTx, coordinator.directFromCpfpRefundTx)
  );
}

/**
 * `mapTreeNode` normalizes absent `direct*` fields to undefined, so undefined-versus-bytes is a
 * genuine disagreement, not an encoding artifact.
 */
function sameOptionalBytes(a: Uint8Array | undefined, b: Uint8Array | undefined): boolean {
  return a === b || (a !== undefined && b !== undefined && equalBytes(a, b));
}

/** Every mapped field two rows for the same leaf id must share to count as one report. */
export function sameLeafRow(a: SparkLeaf, b: SparkLeaf): boolean {
  return (
    a.id === b.id &&
    a.treeId === b.treeId &&
    a.valueSats === b.valueSats &&
    a.status === b.status &&
    a.vout === b.vout &&
    a.parentNodeId === b.parentNodeId &&
    a.signingKeyshare.threshold === b.signingKeyshare.threshold &&
    equalBytes(a.signingKeyshare.publicKey, b.signingKeyshare.publicKey) &&
    a.signingKeyshare.ownerIdentifiers.length === b.signingKeyshare.ownerIdentifiers.length &&
    a.signingKeyshare.ownerIdentifiers.every(
      (identifier, i) => identifier === b.signingKeyshare.ownerIdentifiers[i],
    ) &&
    equalBytes(a.nodeTx, b.nodeTx) &&
    equalBytes(a.refundTx, b.refundTx) &&
    equalBytes(a.verifyingPublicKey, b.verifyingPublicKey) &&
    equalBytes(a.ownerIdentityPublicKey, b.ownerIdentityPublicKey) &&
    equalBytes(a.ownerSigningPublicKey, b.ownerSigningPublicKey) &&
    sameOptionalBytes(a.directTx, b.directTx) &&
    sameOptionalBytes(a.directRefundTx, b.directRefundTx) &&
    sameOptionalBytes(a.directFromCpfpRefundTx, b.directFromCpfpRefundTx)
  );
}

/**
 * Groups served leaf rows by id. Identical copies collapse to one row — honest paging over a
 * mutating set can repeat a row. Two DIFFERENT rows for one id quarantine it: a coordinator can
 * serve conflicting copies under different map keys to smuggle one row past the agreement checks,
 * so a conflicted id is never spendable, never counted and never a deletion witness.
 */
export function dedupeLeafRows(leaves: ReadonlyArray<SparkLeaf>): {
  readonly unique: SparkLeaf[];
  readonly conflicted: string[];
} {
  const byId = new Map<string, SparkLeaf[]>();
  for (const leaf of leaves) {
    const rows = byId.get(leaf.id);
    if (rows === undefined) {
      byId.set(leaf.id, [leaf]);
    } else {
      rows.push(leaf);
    }
  }
  const unique: SparkLeaf[] = [];
  const conflicted: string[] = [];
  for (const [id, rows] of byId) {
    const [first] = rows;
    if (first !== undefined && rows.every((row) => sameLeafRow(first, row))) {
      unique.push(first);
    } else {
      conflicted.push(id);
    }
  }
  return { unique, conflicted };
}

/**
 * Whether `leafPublicKey` — the wallet's `LEAF{leafId}` key — plus the operators' signing share
 * reaches the leaf's verifying key. The wallet can sign for the leaf only when it does; malformed
 * key material means not owned.
 */
export function ownsLeaf(leaf: SparkLeaf, leafPublicKey: Uint8Array): boolean {
  try {
    const ours = secp256k1.Point.fromBytes(leafPublicKey);
    const share = secp256k1.Point.fromBytes(leaf.signingKeyshare.publicKey);
    const verifying = secp256k1.Point.fromBytes(leaf.verifyingPublicKey);
    return ours.add(share).equals(verifying);
  } catch {
    return false;
  }
}
