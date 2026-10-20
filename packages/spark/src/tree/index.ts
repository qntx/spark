import type { Client, CallOptions } from "@connectrpc/connect";

import { u64ToSats } from "../core/assert.ts";
import { sparkNetworkProto } from "../core/network.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import { TreeNodeStatus } from "../proto/gen/spark_pb.ts";
import type { SparkService, TreeNode } from "../proto/gen/spark_pb.ts";

export type SparkLeaf = {
  readonly id: string;
  readonly treeId: string;
  readonly valueSats: number;
  readonly status: string;
  readonly nodeTx: Uint8Array;
  readonly refundTx: Uint8Array;
  readonly directTx?: Uint8Array;
  readonly directRefundTx?: Uint8Array;
  readonly directFromCpfpRefundTx?: Uint8Array;
  readonly verifyingPublicKey: Uint8Array;
  readonly ownerIdentityPublicKey: Uint8Array;
  readonly ownerSigningPublicKey: Uint8Array;
  readonly signingKeyshare: {
    readonly ownerIdentifiers: ReadonlyArray<string>;
    readonly threshold: number;
    readonly publicKey: Uint8Array;
  };
  readonly vout: number;
  readonly parentNodeId?: string;
};

const LEAF_PAGE_SIZE = 50;

/**
 * Hard bound on coordinator-driven pagination: a hostile SO can keep returning full pages forever,
 * and these callers run inside the leaf/token lock, so the loop must terminate.
 */
const MAX_PAGES = 1000;

function optionalBytes(value: Uint8Array): Uint8Array | undefined {
  return value.length === 0 ? undefined : value;
}

export function mapTreeNode(node: TreeNode): SparkLeaf {
  const keyshare = node.signingKeyshare;
  if (keyshare === undefined) {
    throw new SparkInputError("leaf missing signing keyshare");
  }
  const leaf: SparkLeaf = {
    id: node.id,
    treeId: node.treeId,
    valueSats: u64ToSats(node.value, "leaf value"),
    status: node.status,
    nodeTx: node.nodeTx,
    refundTx: node.refundTx,
    verifyingPublicKey: node.verifyingPublicKey,
    ownerIdentityPublicKey: node.ownerIdentityPublicKey,
    ownerSigningPublicKey: node.ownerSigningPublicKey,
    signingKeyshare: {
      ownerIdentifiers: keyshare.ownerIdentifiers,
      threshold: keyshare.threshold,
      publicKey: keyshare.publicKey,
    },
    vout: node.vout,
    ...(node.parentNodeId === undefined || node.parentNodeId === ""
      ? {}
      : { parentNodeId: node.parentNodeId }),
  };
  const directTx = optionalBytes(node.directTx);
  const directRefundTx = optionalBytes(node.directRefundTx);
  const directFromCpfpRefundTx = optionalBytes(node.directFromCpfpRefundTx);
  return {
    ...leaf,
    ...(directTx === undefined ? {} : { directTx }),
    ...(directRefundTx === undefined ? {} : { directRefundTx }),
    ...(directFromCpfpRefundTx === undefined ? {} : { directFromCpfpRefundTx }),
  };
}

/**
 * Pages through `query_nodes` for the owner's nodes in `statuses` — the same source filter and
 * short-page termination the upstream leaf-manager uses, in batches of 50. `includeParents`
 * additionally returns the matched nodes' ancestors (needed by the watchtower-exit listing, whose
 * recoverable output lives on a parent's direct tx). The SO-supplied offset must strictly advance
 * on every full page and the walk is bounded — endless or rewinding pages throw.
 */
export async function queryOwnerNodes(options: {
  readonly spark: Client<typeof SparkService>;
  readonly ownerIdentityPublicKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly statuses: ReadonlyArray<TreeNodeStatus>;
  readonly includeParents: boolean;
  readonly call?: CallOptions;
}): Promise<TreeNode[]> {
  const nodes: TreeNode[] = [];
  let offset = 0;
  for (let pageIndex = 0; pageIndex < MAX_PAGES; pageIndex++) {
    // oxlint-disable-next-line no-await-in-loop -- pages are sequential by definition
    const response = await options.spark.query_nodes(
      {
        source: {
          case: "ownerIdentityPubkey",
          value: options.ownerIdentityPublicKey,
        },
        includeParents: options.includeParents,
        limit: BigInt(LEAF_PAGE_SIZE),
        offset: BigInt(offset),
        network: sparkNetworkProto(options.network),
        statuses: [...options.statuses],
      },
      options.call,
    );
    const page = Object.values(response.nodes);
    nodes.push(...page);
    if (page.length < LEAF_PAGE_SIZE) {
      return nodes;
    }
    const nextOffset = Number(response.offset);
    if (!Number.isSafeInteger(nextOffset) || nextOffset <= offset) {
      throw new SparkError("query nodes: coordinator returned a non-advancing offset");
    }
    offset = nextOffset;
  }
  throw new SparkError("query nodes: coordinator did not stop returning full pages");
}

/** Pages through `query_nodes` for the owner's `AVAILABLE` leaves via {@link queryOwnerNodes}. */
export async function queryLeaves(options: {
  readonly spark: Client<typeof SparkService>;
  readonly ownerIdentityPublicKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly call?: CallOptions;
}): Promise<SparkLeaf[]> {
  const nodes = await queryOwnerNodes({
    ...options,
    statuses: [TreeNodeStatus.AVAILABLE],
    includeParents: false,
  });
  return nodes.filter((node) => node.status === "AVAILABLE").map((node) => mapTreeNode(node));
}

export function leavesBalance(leaves: ReadonlyArray<SparkLeaf>): number {
  let total = 0;
  for (const leaf of leaves) {
    if (leaf.status === "AVAILABLE") {
      total += leaf.valueSats;
    }
  }
  return total;
}

export { selectExact, selectExactMany, selectLeaves } from "./select.ts";
export type { LeafSelection } from "./select.ts";
export { malformedLeafTx, operatorsDisagree, ownsLeaf } from "./verify.ts";
export {
  assertOptimizationOptions,
  DEFAULT_MAX_LEAVES_PER_SWAP,
  greedyLeaves,
  MAX_PLANNING_ITERATIONS,
  maximizeUnilateralExit,
  minimizeTransferSwap,
  optimize,
  shouldOptimize,
  swapMinimizingLeaves,
} from "./optimize.ts";
export type { OptimizationSwap } from "./optimize.ts";
