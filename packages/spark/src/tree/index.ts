import type { Client, CallOptions } from "@connectrpc/connect";

import { u64ToSats } from "../core/assert.ts";
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
