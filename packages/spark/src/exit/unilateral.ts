import type { CallOptions, Client } from "@connectrpc/connect";
import { bytesToHex } from "@noble/hashes/utils.js";

import { getTimelockFromSequence, parseTransaction, txId } from "../core/bitcoin/index.ts";
import { sparkNetworkProto } from "../core/network.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import type { SparkService } from "../proto/gen/spark_pb.ts";
import { mapTreeNode } from "../tree/index.ts";
import type { SparkLeaf } from "../tree/index.ts";
import type { SparkExitChain } from "./store.ts";

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

/** SO query_nodes caps `nodeIds` at DefaultMaxQueryNodesByID. */
const MAX_QUERY_NODE_IDS = 1000;

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

function optionalBytes(value: Uint8Array | undefined): Uint8Array | undefined {
  return value === undefined || value.length === 0 ? undefined : value;
}

/** The outpoint input 0 spends: display-order parent txid and output index. */
function input0Spends(txBytes: Uint8Array, what: string): { txid: string; vout: number } {
  const input = parseTransaction(txBytes).getInput(0);
  if (input.txid === undefined || input.index === undefined) {
    throw new SparkError(`unilateral exit: ${what} has no input 0 outpoint`);
  }
  // btc-signer keeps input txids in display order.
  return { txid: bytesToHex(input.txid), vout: input.index };
}

/**
 * Fails closed on a transaction that does not spend the expected outpoint — a coordinator-supplied
 * chain whose transactions do not chain together can never be broadcast.
 */
function requireSpends(
  txBytes: Uint8Array,
  parentTxBytes: Uint8Array,
  vout: number,
  what: string,
): void {
  const spent = input0Spends(txBytes, what);
  if (spent.txid !== txId(parentTxBytes) || spent.vout !== vout) {
    throw new SparkError(`unilateral exit: ${what} does not spend its parent output`);
  }
}

/**
 * Builds each requested leaf's storable exit chain from a node map. A requested id the map does not
 * hold is a `SparkInputError`, as is a node carrying no refund (not a leaf).
 */
export function buildExitChains(
  leafIds: ReadonlyArray<string>,
  nodes: ReadonlyMap<string, SparkLeaf>,
): SparkExitChain[] {
  const chains: SparkExitChain[] = [];
  for (const leafId of leafIds) {
    const requested = nodes.get(leafId);
    if (requested === undefined) {
      throw new SparkInputError(`unilateral exit: leaf ${leafId} not found`);
    }
    if (requested.refundTx.length === 0) {
      throw new SparkInputError(`unilateral exit: node ${leafId} is not a leaf (no refund tx)`);
    }
    const directRefundTx = optionalBytes(requested.directRefundTx);
    const directFromCpfpRefundTx = optionalBytes(requested.directFromCpfpRefundTx);
    // Verify the chain really chains: each node's input 0 spends the parent node's tx at the
    // output `node.vout` names (Breez tree/mod.rs: "the vout to spend the previous
    // transaction"), and the leaf's refunds spend the leaf transactions themselves.
    const chain = exitChain(leafId, nodes);
    for (const [i, node] of chain.entries()) {
      const parent = chain[i - 1];
      if (parent === undefined) {
        continue;
      }
      requireSpends(
        node.nodeTx,
        parent.nodeTx,
        node.vout,
        `node tx of ${node.id} (parent ${parent.id}, vout ${node.vout})`,
      );
    }
    requireSpends(requested.refundTx, requested.nodeTx, 0, `refund tx of leaf ${leafId}`);
    if (directFromCpfpRefundTx !== undefined) {
      requireSpends(
        directFromCpfpRefundTx,
        requested.nodeTx,
        0,
        `direct-from-CPFP refund tx of leaf ${leafId}`,
      );
    }
    if (directRefundTx !== undefined) {
      const directTx = optionalBytes(requested.directTx);
      if (directTx === undefined) {
        throw new SparkError(
          `unilateral exit: leaf ${leafId} has a direct refund but no direct tx`,
        );
      }
      requireSpends(directRefundTx, directTx, 0, `direct refund tx of leaf ${leafId}`);
    }
    const chainNodes: Array<{
      nodeId: string;
      nodeTx: Uint8Array;
      directTx?: Uint8Array;
    }> = [];
    for (const node of chain) {
      const directTx = optionalBytes(node.directTx);
      chainNodes.push({
        nodeId: node.id,
        nodeTx: node.nodeTx,
        ...(directTx === undefined ? {} : { directTx }),
      });
    }
    chains.push({
      leafId,
      nodes: chainNodes,
      refundTx: requested.refundTx,
      ...(directRefundTx === undefined ? {} : { directRefundTx }),
      ...(directFromCpfpRefundTx === undefined ? {} : { directFromCpfpRefundTx }),
    });
  }
  return chains;
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
 * Flattens stored chains into broadcast order: for each leaf's chain root→leaf, ancestor node txs
 * deduplicated by node id at first use, then that leaf's refund right after its leaf node tx.
 */
export function exitTransactions(chains: ReadonlyArray<SparkExitChain>): ExitTransaction[] {
  const out: ExitTransaction[] = [];
  const emitted = new Set<string>();
  for (const chain of chains) {
    for (const node of chain.nodes) {
      if (!emitted.has(node.nodeId)) {
        emitted.add(node.nodeId);
        out.push(exitTransaction(node.nodeId, "node", node.nodeTx));
      }
    }
    out.push(exitTransaction(chain.leafId, "refund", chain.refundTx));
  }
  return out;
}

/**
 * Builds exit chains for leaves already in hand. Fetches only the ancestors the caller lacks
 * (parentNodeIds not among the given leaves) with `includeParents`, in `nodeIds` chunks of 1000 —
 * those ancestors existed before the claim/deposit, so looking them up by id does not depend on the
 * just-written leaf being indexed. Given leaf objects win over returned nodes for their own id.
 */
export async function queryExitChains(options: {
  readonly spark: Client<typeof SparkService>;
  readonly network: SparkNetwork;
  readonly leaves: ReadonlyArray<SparkLeaf>;
  readonly call?: CallOptions;
}): Promise<SparkExitChain[]> {
  const { spark, network, leaves } = options;
  const known = new Map<string, SparkLeaf>(leaves.map((leaf) => [leaf.id, leaf]));
  const wanted = new Set<string>();
  for (const leaf of leaves) {
    if (leaf.parentNodeId !== undefined && !known.has(leaf.parentNodeId)) {
      wanted.add(leaf.parentNodeId);
    }
  }
  if (wanted.size === 0) {
    return buildExitChains(
      leaves.map((leaf) => leaf.id),
      known,
    );
  }
  const ids = [...wanted];
  for (let i = 0; i < ids.length; i += MAX_QUERY_NODE_IDS) {
    // oxlint-disable-next-line no-await-in-loop -- ancestor chunks are sequential by design
    const response = await spark.query_nodes(
      {
        source: {
          case: "nodeIds",
          value: { nodeIds: ids.slice(i, i + MAX_QUERY_NODE_IDS) },
        },
        includeParents: true,
        limit: 0n,
        offset: 0n,
        network: sparkNetworkProto(network),
        statuses: [],
      },
      options.call,
    );
    for (const node of Object.values(response.nodes)) {
      const mapped = mapTreeNode(node);
      if (!known.has(mapped.id)) {
        known.set(mapped.id, mapped);
      }
    }
  }
  return buildExitChains(
    leaves.map((leaf) => leaf.id),
    known,
  );
}

/**
 * One `query_nodes` (with parents) for the requested leaves' ids, then the exit chains and their
 * broadcast-flattened transactions. A requested id that the query does not return or that carries
 * no refund is a `SparkInputError`.
 */
export async function unilateralExitTransactions(options: {
  readonly spark: Client<typeof SparkService>;
  readonly network: SparkNetwork;
  readonly leafIds: ReadonlyArray<string>;
  readonly call?: CallOptions;
}): Promise<{
  readonly transactions: ReadonlyArray<ExitTransaction>;
  readonly chains: ReadonlyArray<SparkExitChain>;
}> {
  const { spark, network, leafIds } = options;
  if (leafIds.length === 0) {
    return { transactions: [], chains: [] };
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
  const chains = buildExitChains(leafIds, nodes);
  return { transactions: exitTransactions(chains), chains };
}
