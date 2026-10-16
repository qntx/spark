import type { Client, CallOptions } from "@connectrpc/connect";

import { sparkNetworkProto } from "../core/network.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SparkInputError } from "../errors/index.ts";
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

function optionalBytes(value: Uint8Array): Uint8Array | undefined {
  return value.length === 0 ? undefined : value;
}

function checkedSats(value: bigint, field: string): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new SparkInputError(`leaf ${field} out of range`);
  }
  return Number(value);
}

export function mapTreeNode(node: TreeNode): SparkLeaf {
  const keyshare = node.signingKeyshare;
  if (keyshare === undefined) {
    throw new SparkInputError("leaf missing signing keyshare");
  }
  const leaf: SparkLeaf = {
    id: node.id,
    treeId: node.treeId,
    valueSats: checkedSats(node.value, "value"),
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
  };
  const directTx = optionalBytes(node.directTx);
  if (directTx !== undefined) {
    return { ...leaf, directTx };
  }
  return leaf;
}

/**
 * Pages through `query_nodes` for the owner's `AVAILABLE` leaves — the same source/status filter
 * the upstream leaf-manager uses (`include_parents=false`, batches of 50 until a short page).
 */
export async function queryLeaves(options: {
  readonly spark: Client<typeof SparkService>;
  readonly ownerIdentityPublicKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly call?: CallOptions;
}): Promise<SparkLeaf[]> {
  const fetchPage = async (offset: number): Promise<SparkLeaf[]> => {
    const response = await options.spark.query_nodes(
      {
        source: {
          case: "ownerIdentityPubkey",
          value: options.ownerIdentityPublicKey,
        },
        includeParents: false,
        limit: BigInt(LEAF_PAGE_SIZE),
        offset: BigInt(offset),
        network: sparkNetworkProto(options.network),
        statuses: [TreeNodeStatus.AVAILABLE],
      },
      options.call,
    );
    const page = Object.values(response.nodes)
      .filter((node) => node.status === "AVAILABLE")
      .map((node) => mapTreeNode(node));
    if (Object.keys(response.nodes).length < LEAF_PAGE_SIZE) {
      return page;
    }
    const rest = await fetchPage(Number(response.offset));
    return [...page, ...rest];
  };
  return fetchPage(0);
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
