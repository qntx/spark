import type { CallOptions, Client } from "@connectrpc/connect";
import { equalBytes } from "@noble/curves/utils.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import {
  getTimelockFromSequence,
  p2trScriptFromPublicKey,
  parseTransaction,
  txId,
} from "../core/bitcoin/index.ts";
import { sparkNetworkProto } from "../core/network.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import type { SparkService } from "../proto/gen/spark_pb.ts";
import type { SparkSigner } from "../signer/types.ts";
import { mapTreeNode } from "../tree/index.ts";
import type { SparkLeaf } from "../tree/index.ts";
import { batchedPublicKeys } from "../tree/signing.ts";
import type { SparkExitChain } from "./store.ts";

// Unilateral exit: the Spark tree's pre-signed transactions are already signed by
// the operator quorum — the owner only needs to broadcast them. Every tx is a
// zero-fee v3 (TRUC) transaction with a P2A anchor; the caller fee-bumps each via
// a CPFP child built with `buildCpfpChild` and submits them as packages.

// Every pre-signed transaction carries a hard deadline. Once its parent has
// confirmed and the transaction's own relative timelock has passed, it must
// confirm within DIRECT_TIMELOCK_OFFSET blocks or the SO watchtower may publish
// the self-fee "direct" variant it holds — a same-outpoint transaction whose
// witness never leaves the SO. What that means per transaction kind:
//   - an intermediate node's node tx: the direct node tx cuts off the child's
//     pre-signed package; every descendant leaf is marked WATCHTOWER_EXITED —
//     recover it with `withdrawals.recoverWatchtowerExit` while the SO is
//     online.
//   - a leaf's node tx: keep each exit package confirming promptly so the
//     leaf's own chain stays ahead of the deadline.
//   - a refund tx: the watchtower publishes `direct_from_cpfp_refund_tx`, whose
//     output still pays the leaf's key-path script — sweep it with
//     `withdrawals.sweepRefund`.
// TRUC admits only one unconfirmed ancestor, so the CPFP path can advance just
// one level per confirmation; pick fee rates that land each package well inside
// the DIRECT_TIMELOCK_OFFSET window.

/**
 * A pre-signed exit transaction plus the context needed to broadcast it. Broadcasting is
 * deadline-bound: once `parentTxid` confirms and `relativeTimelock` blocks pass, this must confirm
 * within DIRECT_TIMELOCK_OFFSET blocks or the SO watchtower replaces it with the direct variant
 * (see the module doc).
 */
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

type Outpoint = { txid: string; vout: number };

/** Per-`buildExitChains` memoization keyed by transaction bytes identity. */
type LinkageCache = {
  readonly txids: Map<Uint8Array, string>;
  readonly input0: Map<Uint8Array, Outpoint>;
  readonly output0: Map<Uint8Array, Uint8Array>;
  readonly verifiedLinks: Set<string>;
};

function cachedTxId(txBytes: Uint8Array, cache: LinkageCache): string {
  let cached = cache.txids.get(txBytes);
  if (cached === undefined) {
    cached = txId(txBytes);
    cache.txids.set(txBytes, cached);
  }
  return cached;
}

/** The outpoint input 0 spends: display-order parent txid and output index. */
function input0Spends(txBytes: Uint8Array, what: string, cache: LinkageCache): Outpoint {
  const cached = cache.input0.get(txBytes);
  if (cached !== undefined) {
    return cached;
  }
  const input = parseTransaction(txBytes).getInput(0);
  if (input.txid === undefined || input.index === undefined) {
    throw new SparkError(`unilateral exit: ${what} has no input 0 outpoint`);
  }
  // btc-signer keeps input txids in display order.
  const outpoint = { txid: bytesToHex(input.txid), vout: input.index };
  cache.input0.set(txBytes, outpoint);
  return outpoint;
}

/**
 * Fails closed on a transaction that does not spend the expected outpoint — a coordinator-supplied
 * chain whose transactions do not chain together can never be broadcast.
 */
function requireSpends(
  txBytes: Uint8Array,
  expected: Outpoint,
  what: string,
  cache: LinkageCache,
): void {
  const spent = input0Spends(txBytes, what, cache);
  if (spent.txid !== expected.txid || spent.vout !== expected.vout) {
    throw new SparkError(`unilateral exit: ${what} does not spend its parent output`);
  }
}

/** The script output 0 pays, parsed and memoized once per transaction. */
function output0Script(txBytes: Uint8Array, what: string, cache: LinkageCache): Uint8Array {
  const cached = cache.output0.get(txBytes);
  if (cached !== undefined) {
    return cached;
  }
  const tx = parseTransaction(txBytes);
  if (tx.outputsLength === 0) {
    throw new SparkError(`unilateral exit: ${what} has no outputs`);
  }
  const { script } = tx.getOutput(0);
  if (script === undefined) {
    throw new SparkError(`unilateral exit: ${what} output 0 has no script`);
  }
  cache.output0.set(txBytes, script);
  return script;
}

/**
 * Fails closed on a transaction whose output 0 does not pay `expectedScript` — a served refund that
 * looks structurally valid but pays another key would spend the exit to a stranger.
 */
function requirePaysScript(
  txBytes: Uint8Array,
  expectedScript: Uint8Array,
  what: string,
  cache: LinkageCache,
): void {
  if (!equalBytes(output0Script(txBytes, what, cache), expectedScript)) {
    throw new SparkError(`unilateral exit: ${what} does not pay the leaf's key-path script`);
  }
}

/**
 * Builds each requested leaf's storable exit chain from a node map. A requested id the map does not
 * hold is a `SparkInputError`, as is a node carrying no refund (not a leaf). Every refund must also
 * pay the caller-supplied `refundScripts` entry — derived from the signer's own leaf key, never the
 * node — so a served refund paying a stranger fails closed.
 */
export function buildExitChains(
  leafIds: ReadonlyArray<string>,
  nodes: ReadonlyMap<string, SparkLeaf>,
  refundScripts: ReadonlyMap<string, Uint8Array>,
): SparkExitChain[] {
  const cache = newLinkageCache();
  return leafIds.map((leafId) => buildLeafExitChain(leafId, nodes, refundScripts, cache));
}

function newLinkageCache(): LinkageCache {
  // Leaves share ancestors; each node→parent link is verified once and each
  // transaction is parsed and hashed once per call.
  return {
    txids: new Map(),
    input0: new Map(),
    output0: new Map(),
    verifiedLinks: new Set(),
  };
}

/**
 * One leaf's verified exit chain, sharing `cache` across siblings so shared ancestors link once.
 * Throws the same `SparkInputError`/`SparkError` `buildExitChains` raises for that leaf.
 */
function buildLeafExitChain(
  leafId: string,
  nodes: ReadonlyMap<string, SparkLeaf>,
  refundScripts: ReadonlyMap<string, Uint8Array>,
  cache: LinkageCache,
): SparkExitChain {
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
    if (parent === undefined || cache.verifiedLinks.has(node.id)) {
      continue;
    }
    requireSpends(
      node.nodeTx,
      { txid: cachedTxId(parent.nodeTx, cache), vout: node.vout },
      `node tx of ${node.id} (parent ${parent.id}, vout ${node.vout})`,
      cache,
    );
    cache.verifiedLinks.add(node.id);
  }
  const leafNodeTxid = cachedTxId(requested.nodeTx, cache);
  requireSpends(
    requested.refundTx,
    { txid: leafNodeTxid, vout: 0 },
    `refund tx of leaf ${leafId}`,
    cache,
  );
  if (directFromCpfpRefundTx !== undefined) {
    requireSpends(
      directFromCpfpRefundTx,
      { txid: leafNodeTxid, vout: 0 },
      `direct-from-CPFP refund tx of leaf ${leafId}`,
      cache,
    );
  }
  if (directRefundTx !== undefined) {
    const directTx = optionalBytes(requested.directTx);
    if (directTx === undefined) {
      throw new SparkError(`unilateral exit: leaf ${leafId} has a direct refund but no direct tx`);
    }
    requireSpends(
      directRefundTx,
      { txid: cachedTxId(directTx, cache), vout: 0 },
      `direct refund tx of leaf ${leafId}`,
      cache,
    );
  }
  // Structure alone is not enough — every refund must pay this leaf's own key-path script.
  const expectedRefundScript = refundScripts.get(leafId);
  if (expectedRefundScript === undefined) {
    throw new SparkError(`unilateral exit: no expected refund script for leaf ${leafId}`);
  }
  requirePaysScript(requested.refundTx, expectedRefundScript, `refund tx of leaf ${leafId}`, cache);
  if (directFromCpfpRefundTx !== undefined) {
    requirePaysScript(
      directFromCpfpRefundTx,
      expectedRefundScript,
      `direct-from-CPFP refund tx of leaf ${leafId}`,
      cache,
    );
  }
  if (directRefundTx !== undefined) {
    requirePaysScript(
      directRefundTx,
      expectedRefundScript,
      `direct refund tx of leaf ${leafId}`,
      cache,
    );
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
  return {
    leafId,
    nodes: chainNodes,
    refundTx: requested.refundTx,
    ...(directRefundTx === undefined ? {} : { directRefundTx }),
    ...(directFromCpfpRefundTx === undefined ? {} : { directFromCpfpRefundTx }),
  };
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
 * Broadcast strictly in this order — each transaction's deadline is its parent's confirmation
 * height plus its own relative timelock plus DIRECT_TIMELOCK_OFFSET, so a stalled package endangers
 * every transaction below it.
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
 * The key-path script every refund of `leafIds` must pay: P2TR of the signer's own `LEAF{leafId}`
 * public key — the key this client signs those refunds with — never a key the SO reports.
 */
async function leafRefundScripts(
  signer: SparkSigner,
  leafIds: ReadonlyArray<string>,
  network: SparkNetwork,
): Promise<ReadonlyMap<string, Uint8Array>> {
  const keys = await batchedPublicKeys(
    signer,
    leafIds.map((leafId) => ({ type: "leaf", leafId })),
  );
  const scripts = new Map<string, Uint8Array>();
  for (const [i, leafId] of leafIds.entries()) {
    const key = keys[i];
    if (key === undefined) {
      throw new SparkError("unilateral exit: signer returned fewer public keys than requested");
    }
    scripts.set(leafId, p2trScriptFromPublicKey(key, network));
  }
  return scripts;
}

/**
 * Builds exit chains for leaves already in hand. Fetches only the ancestors the caller lacks
 * (parentNodeIds not among the given leaves) with `includeParents`, in `nodeIds` chunks of 1000 —
 * those ancestors existed before the claim/deposit, so looking them up by id does not depend on the
 * just-written leaf being indexed. Given leaf objects win over returned nodes for their own id.
 * Each refund must pay the signer's own `LEAF{id}` key-path script — a foreign leaf fails rather
 * than storing a stranger's chain.
 */
export async function queryExitChains(options: {
  readonly spark: Client<typeof SparkService>;
  readonly network: SparkNetwork;
  readonly signer: SparkSigner;
  readonly leaves: ReadonlyArray<SparkLeaf>;
  readonly call?: CallOptions;
}): Promise<{
  readonly chains: SparkExitChain[];
  /** Leaves whose chain failed verification — the caller quarantines them, it does not throw. */
  readonly rejected: ReadonlyArray<{ readonly leafId: string; readonly error: SparkError }>;
}> {
  const { spark, network, signer, leaves } = options;
  const refundScripts = await leafRefundScripts(
    signer,
    leaves.map((leaf) => leaf.id),
    network,
  );
  const known = new Map<string, SparkLeaf>(leaves.map((leaf) => [leaf.id, leaf]));
  const wanted = new Set<string>();
  for (const leaf of leaves) {
    if (leaf.parentNodeId !== undefined && !known.has(leaf.parentNodeId)) {
      wanted.add(leaf.parentNodeId);
    }
  }
  if (wanted.size === 0) {
    return collectExitChains(
      leaves.map((leaf) => leaf.id),
      known,
      refundScripts,
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
  return collectExitChains(
    leaves.map((leaf) => leaf.id),
    known,
    refundScripts,
  );
}

/**
 * `buildExitChains` for every leaf, collecting per-leaf failures rather than throwing on the first:
 * one leaf with a chain that fails verification must not block the valid chains — the sync
 * quarantines it like an operator-disagreeing leaf.
 */
function collectExitChains(
  leafIds: ReadonlyArray<string>,
  nodes: ReadonlyMap<string, SparkLeaf>,
  refundScripts: ReadonlyMap<string, Uint8Array>,
): {
  chains: SparkExitChain[];
  rejected: Array<{ leafId: string; error: SparkError }>;
} {
  const cache = newLinkageCache();
  const chains: SparkExitChain[] = [];
  const rejected: Array<{ leafId: string; error: SparkError }> = [];
  for (const leafId of leafIds) {
    try {
      chains.push(buildLeafExitChain(leafId, nodes, refundScripts, cache));
    } catch (error) {
      rejected.push({
        leafId,
        error:
          error instanceof SparkError
            ? error
            : new SparkError(`unilateral exit: leaf ${leafId} chain build failed`, {
                cause: error,
              }),
      });
    }
  }
  return { chains, rejected };
}

/**
 * One `query_nodes` (with parents) for the requested leaves' ids, then the exit chains and their
 * broadcast-flattened transactions. A requested id that the query does not return or that carries
 * no refund is a `SparkInputError`. Each refund must pay the signer's own `LEAF{id}` key-path
 * script, so a foreign leaf id fails rather than returning a stranger's chain. The returned
 * transactions are owner-broadcastable; the direct variants stored alongside them in the chains are
 * witness-stripped templates and are not.
 */
export async function unilateralExitTransactions(options: {
  readonly spark: Client<typeof SparkService>;
  readonly network: SparkNetwork;
  readonly signer: SparkSigner;
  readonly leafIds: ReadonlyArray<string>;
  readonly call?: CallOptions;
}): Promise<{
  readonly transactions: ReadonlyArray<ExitTransaction>;
  readonly chains: ReadonlyArray<SparkExitChain>;
}> {
  const { spark, network, signer, leafIds } = options;
  if (leafIds.length === 0) {
    return { transactions: [], chains: [] };
  }
  const refundScripts = await leafRefundScripts(signer, leafIds, network);
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
  const chains = buildExitChains(leafIds, nodes, refundScripts);
  return { transactions: exitTransactions(chains), chains };
}
