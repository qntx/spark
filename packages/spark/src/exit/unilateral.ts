import type { CallOptions, Client } from "@connectrpc/connect";
import { bytesToHex } from "@noble/hashes/utils.js";

import { getTimelockFromSequence, parseTransaction, txId } from "../core/bitcoin/index.ts";
import { sparkNetworkProto } from "../core/network.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import type { SparkService } from "../proto/gen/spark_pb.ts";
import { mapTreeNode } from "../tree/index.ts";
import type { SparkLeaf } from "../tree/index.ts";

// Unilateral exit: the Spark tree's pre-signed transactions are already signed by
// the operator quorum — the owner only needs to broadcast them. Every tx is a
// zero-fee v3 (TRUC) transaction with a P2A anchor; the caller fee-bumps each via
// a CPFP child built with `buildCpfpChild` and submits them as packages.

/** A pre-signed exit transaction plus the context needed to broadcast it. */
export type ExitTransaction = {
  /** The tree node this transaction belongs to (the leaf's id for refunds). */
  readonly nodeId: string;
  readonly kind: "node" | "refund";
  /** Zero-fee v3 transaction with a P2A anchor output. */
  readonly transaction: Uint8Array;
  /** Display-order txid. */
  readonly txid: string;
  /** Display-order txid spent by input 0 (the deposit tx for a root node tx). */
  readonly parentTxid: string;
  /** BIP-68 blocks the input must wait after its parent confirms. */
  readonly relativeTimelock: number;
};

/**
 * Walks `leafId`'s ancestor chain root-first, following `parentNodeId` regardless of node status
 * (an ancestor in any status still holds the output the child spends — Breez
 * `walk_unilateral_exit_chain`). Missing entries and cycles are `SparkError`s naming the offending
 * id.
 */
export function exitChain(leafId: string, nodes: ReadonlyMap<string, SparkLeaf>): SparkLeaf[] {
  const start = nodes.get(leafId);
  if (start === undefined) {
    throw new SparkError(`exitChain: node ${leafId} not found`);
  }
  const chain: SparkLeaf[] = [];
  const visited = new Set<string>();
  let current = start;
  for (;;) {
    if (visited.has(current.id)) {
      throw new SparkError(`exitChain: parent cycle at node ${current.id}`);
    }
    visited.add(current.id);
    chain.push(current);
    const parentId = current.parentNodeId;
    if (parentId === undefined) {
      break;
    }
    const parent = nodes.get(parentId);
    if (parent === undefined) {
      throw new SparkError(`exitChain: parent node ${parentId} of ${current.id} not found`);
    }
    current = parent;
  }
  return chain.reverse();
}

function exitTransaction(
  nodeId: string,
  kind: "node" | "refund",
  txBytes: Uint8Array,
): ExitTransaction {
  const tx = parseTransaction(txBytes);
  const input = tx.getInput(0);
  if (input.txid === undefined || input.sequence === undefined) {
    throw new SparkError(`exitChain: ${kind} tx of node ${nodeId} has no input 0`);
  }
  return {
    nodeId,
    kind,
    transaction: txBytes,
    txid: txId(txBytes),
    // btc-signer keeps input txids in display order.
    parentTxid: bytesToHex(input.txid),
    relativeTimelock: getTimelockFromSequence(input.sequence),
  };
}

/**
 * One `query_nodes` (with parents) for the requested leaves, then every leaf's exit chain root→leaf
 * followed by that leaf's refund. Ancestor node txs shared between leaves appear once, at first
 * use. A requested id that the query does not return or that carries no refund is a
 * `SparkInputError`.
 */
export async function unilateralExitTransactions(options: {
  readonly spark: Client<typeof SparkService>;
  readonly network: SparkNetwork;
  readonly leafIds: ReadonlyArray<string>;
  readonly call?: CallOptions;
}): Promise<ReadonlyArray<ExitTransaction>> {
  const { spark, network, leafIds } = options;
  if (leafIds.length === 0) {
    return [];
  }
  const response = await spark.query_nodes(
    {
      source: { case: "nodeIds", value: { nodeIds: [...leafIds] } },
      includeParents: true,
      limit: 0n,
      offset: 0n,
      network: sparkNetworkProto(network),
      statuses: [],
    },
    options.call,
  );
  const nodes = new Map<string, SparkLeaf>(
    Object.values(response.nodes).map((node) => {
      const leaf = mapTreeNode(node);
      return [leaf.id, leaf];
    }),
  );

  const out: ExitTransaction[] = [];
  const emitted = new Set<string>();
  for (const leafId of leafIds) {
    const requested = nodes.get(leafId);
    if (requested === undefined) {
      throw new SparkInputError(`unilateral exit: leaf ${leafId} not found`);
    }
    if (requested.refundTx.length === 0) {
      throw new SparkInputError(`unilateral exit: node ${leafId} is not a leaf (no refund tx)`);
    }
    for (const node of exitChain(leafId, nodes)) {
      if (!emitted.has(node.id)) {
        emitted.add(node.id);
        out.push(exitTransaction(node.id, "node", node.nodeTx));
      }
    }
    out.push(exitTransaction(leafId, "refund", requested.refundTx));
  }
  return out;
}
