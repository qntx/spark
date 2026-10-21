import { secp256k1 } from "@noble/curves/secp256k1.js";
import { equalBytes } from "@noble/curves/utils.js";

import { parseTransaction } from "../core/bitcoin/sighash.ts";
import type { SparkLeaf } from "./index.ts";

// Leaf verification ported from breez-spark-sdk crates/spark/src/tree/service.rs @956ff90
// (`malformed_tx`, `operators_disagree`, `retain_owned`): the coordinator is a server and can lie,
// so a leaf enters the spendable pool only when it is well-formed, provably held under a key this
// wallet derives, and reported identically by every operator.

/**
 * Names the first of the leaf's transactions that is unusable — unparseable, input-less or
 * output-less — or undefined when every present transaction is well-formed.
 */
export function malformedLeafTx(leaf: SparkLeaf): string | undefined {
  const candidates: ReadonlyArray<readonly [string, Uint8Array | undefined]> = [
    ["node tx", leaf.nodeTx],
    ["refund tx", leaf.refundTx.length === 0 ? undefined : leaf.refundTx],
    ["direct tx", leaf.directTx],
    ["direct refund tx", leaf.directRefundTx],
    ["direct from cpfp refund tx", leaf.directFromCpfpRefundTx],
  ];
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
  }
  return undefined;
}

/**
 * Whether the coordinator's copy of a leaf and another operator's copy describe different leaves.
 * Compares every field a spend commits to: `valueSats` is the amount the wallet pays or exits the
 * leaf for, `verifyingPublicKey` is the key signing must reach, and `vout` locates the leaf in
 * `nodeTx` — a coordinator reporting any of them differently is as disqualifying as a different
 * transaction.
 */
export function operatorsDisagree(coordinator: SparkLeaf, operator: SparkLeaf): boolean {
  return (
    operator.status !== coordinator.status ||
    operator.valueSats !== coordinator.valueSats ||
    operator.vout !== coordinator.vout ||
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
