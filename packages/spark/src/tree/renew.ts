import { create } from "@bufbuild/protobuf";
import type { CallOptions, Client } from "@connectrpc/connect";

import { u64ToSats } from "../core/assert.ts";
import type { NodeTxPair } from "../core/bitcoin/index.ts";
import {
  createDecrementedTimelockNodeTx,
  createInitialTimelockNodeTx,
  createInitialTimelockRefundTxs,
  createZeroTimelockNodeTx,
  doesTxnNeedRenewed,
  isZeroTimelock,
  parseTransaction,
  txId,
} from "../core/bitcoin/index.ts";
import { sparkNetworkProto } from "../core/network.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import {
  RenewNodeTimelockSigningJobSchema,
  RenewNodeZeroTimelockSigningJobSchema,
  RenewRefundTimelockSigningJobSchema,
} from "../proto/gen/spark_pb.ts";
import type {
  RenewLeafRequest,
  SparkService,
  UserSignedTxSigningJob,
} from "../proto/gen/spark_pb.ts";
import type { SparkLeafKey, SparkSigner } from "../signer/types.ts";
import { mapTreeNode } from "./index.ts";
import type { SparkLeaf } from "./index.ts";
import { signUserJobs } from "./signing.ts";
import type { UserSigningSpec } from "./signing.ts";

// Leaf timelock renewal (upstream leaf-manager `checkRenewLeaves` classification plus the
// `renewNodeTxn`/`renewRefundTxn`/`renewZeroTimelockNodeTxn` job builders, buildonspark/spark
// @0b3a32a). The user signs every renewed transaction with the leaf's LEAF{leafId} key; the SO
// returns the updated node.

function inputSequence(txBytes: Uint8Array, context: string): number {
  const { sequence } = parseTransaction(txBytes).getInput(0);
  if (sequence === undefined) {
    throw new SparkInputError(`${context}: input 0 has no sequence`);
  }
  return sequence;
}

function txOutput(
  txBytes: Uint8Array,
  context: string,
): { readonly script: Uint8Array; readonly amount: number } {
  const output = parseTransaction(txBytes).getOutput(0);
  if (output.script === undefined || output.amount === undefined) {
    throw new SparkError(`${context}: transaction has no output 0`);
  }
  return { script: output.script, amount: u64ToSats(output.amount, `${context} output`) };
}

/**
 * Which renewal path a leaf needs: `zero-timelock` when the node tx timelock is already 0, `node`
 * when it is itself below the renewal threshold, `refund` when only the refund tx is stale, and
 * undefined when the refund timelock is still healthy (`doesTxnNeedRenewed`).
 */
export function renewalKind(leaf: SparkLeaf): "refund" | "node" | "zero-timelock" | undefined {
  const refundSequence = inputSequence(leaf.refundTx, `leaf ${leaf.id} refund tx`);
  if (!doesTxnNeedRenewed(refundSequence)) {
    return undefined;
  }
  const nodeSequence = inputSequence(leaf.nodeTx, `leaf ${leaf.id} node tx`);
  if (isZeroTimelock(nodeSequence)) {
    return "zero-timelock";
  }
  return doesTxnNeedRenewed(nodeSequence) ? "node" : "refund";
}

/**
 * `renew_leaf` — re-signs a leaf's node and refund transactions at fresh timelocks against the SO.
 * Job order, prevouts and the wire field each job lands in mirror upstream
 * `createRenew*SigningJobs` exactly; commitment index `i` pairs with job `i`.
 */
export async function renewLeaf(options: {
  readonly spark: Client<typeof SparkService>;
  readonly signer: SparkSigner;
  readonly network: SparkNetwork;
  readonly leaf: SparkLeaf;
  readonly call?: CallOptions;
}): Promise<SparkLeaf> {
  const { spark, signer, network, leaf } = options;
  const kind = renewalKind(leaf);
  if (kind === undefined) {
    throw new SparkInputError(`renewLeaf: leaf ${leaf.id} does not need renewal`);
  }
  const key: SparkLeafKey = { type: "leaf", leafId: leaf.id };
  const [signingPublicKey] = await signer.publicKeys([key]);
  if (signingPublicKey === undefined) {
    throw new SparkError("renewLeaf: signer returned no leaf public key");
  }

  type RenewJobName =
    | "split"
    | "directSplit"
    | "node"
    | "directNode"
    | "cpfp"
    | "direct"
    | "directFromCpfp";
  const jobs: Array<{
    readonly name: RenewJobName;
    readonly txBytes: Uint8Array;
    readonly prevout: { readonly script: Uint8Array; readonly amount: number };
  }> = [];
  const push = (
    name: RenewJobName,
    txBytes: Uint8Array,
    prevout: { readonly script: Uint8Array; readonly amount: number },
  ): void => {
    jobs.push({ name, txBytes, prevout });
  };

  // Zero-timelock renewal signs only the CPFP refunds (mirrors upstream, which
  // sends no direct refund job there); refund and node renewals sign all three.
  const refundsOver = (
    nodeTx: Uint8Array,
    directNodeTx: Uint8Array,
    includeDirect: boolean,
  ): void => {
    const refunds = createInitialTimelockRefundTxs({
      nodeTx,
      directNodeTx,
      receivingPublicKey: signingPublicKey,
      network,
    });
    const nodeOut = txOutput(nodeTx, "renewed node tx");
    push("cpfp", refunds.cpfpRefund.txBytes, nodeOut);
    if (includeDirect && refunds.directRefund !== undefined) {
      push("direct", refunds.directRefund.txBytes, txOutput(directNodeTx, "direct node tx"));
    }
    push("directFromCpfp", refunds.directFromCpfpRefund.txBytes, nodeOut);
  };

  if (kind === "zero-timelock") {
    const node = createZeroTimelockNodeTx(leaf.nodeTx, network);
    const leafOut = txOutput(leaf.nodeTx, `leaf ${leaf.id} node tx`);
    push("node", node.cpfp.txBytes, leafOut);
    push("directNode", node.direct.txBytes, leafOut);
    refundsOver(node.cpfp.txBytes, node.direct.txBytes, false);
  } else {
    if (leaf.parentNodeId === undefined) {
      throw new SparkError(`renewLeaf: leaf ${leaf.id} has no parent node`);
    }
    const parentResponse = await spark.query_nodes(
      {
        source: { case: "nodeIds", value: { nodeIds: [leaf.parentNodeId] } },
        includeParents: false,
        limit: 1n,
        offset: 0n,
        network: sparkNetworkProto(network),
        statuses: [],
      },
      options.call,
    );
    const parent = parentResponse.nodes[leaf.parentNodeId];
    if (parent === undefined) {
      throw new SparkError(`renewLeaf: parent node ${leaf.parentNodeId} not found`);
    }
    const parentOut = txOutput(parent.nodeTx, `parent node ${leaf.parentNodeId} tx`);
    let nodePair: NodeTxPair;
    let nodePrevout = parentOut;
    if (kind === "refund") {
      nodePair = createDecrementedTimelockNodeTx(parent.nodeTx, leaf.nodeTx, network);
    } else {
      const split = createZeroTimelockNodeTx(parent.nodeTx, network);
      push("split", split.cpfp.txBytes, parentOut);
      push("directSplit", split.direct.txBytes, parentOut);
      nodePrevout = txOutput(split.cpfp.txBytes, "split node tx");
      nodePair = createInitialTimelockNodeTx(split.cpfp.txBytes, network);
    }
    push("node", nodePair.cpfp.txBytes, nodePrevout);
    push("directNode", nodePair.direct.txBytes, nodePrevout);
    refundsOver(nodePair.cpfp.txBytes, nodePair.direct.txBytes, true);
  }

  const commitmentsResponse = await spark.get_signing_commitments(
    { nodeIds: [leaf.id], count: jobs.length },
    options.call,
  );
  const soCommitments = commitmentsResponse.signingCommitments;
  if (soCommitments.length !== jobs.length) {
    throw new SparkError(
      `renewLeaf: expected ${jobs.length} signing commitments, got ${soCommitments.length}`,
    );
  }

  const specs: UserSigningSpec[] = jobs.map((job, index) => {
    const commitments = soCommitments[index];
    if (commitments === undefined) {
      throw new SparkError("renewLeaf: signing commitment bookkeeping failure");
    }
    return {
      leafId: leaf.id,
      key,
      signingPublicKey,
      verifyingKey: leaf.verifyingPublicKey,
      target: { transaction: job.txBytes, inputIndex: 0, prevouts: [job.prevout] },
      commitments,
    };
  });
  const signed = await signUserJobs(signer, specs);
  const at = (name: RenewJobName): UserSignedTxSigningJob => {
    const index = jobs.findIndex((job) => job.name === name);
    const job = index === -1 ? undefined : signed[index];
    if (job === undefined) {
      throw new SparkError(`renewLeaf: missing signed job ${name}`);
    }
    return job;
  };

  const signingJobs: RenewLeafRequest["signingJobs"] =
    kind === "zero-timelock"
      ? {
          case: "renewNodeZeroTimelockSigningJob",
          value: create(RenewNodeZeroTimelockSigningJobSchema, {
            nodeTxSigningJob: at("node"),
            refundTxSigningJob: at("cpfp"),
            directNodeTxSigningJob: at("directNode"),
            directFromCpfpRefundTxSigningJob: at("directFromCpfp"),
          }),
        }
      : kind === "refund"
        ? {
            case: "renewRefundTimelockSigningJob",
            value: create(RenewRefundTimelockSigningJobSchema, {
              nodeTxSigningJob: at("node"),
              refundTxSigningJob: at("cpfp"),
              directNodeTxSigningJob: at("directNode"),
              directRefundTxSigningJob: at("direct"),
              directFromCpfpRefundTxSigningJob: at("directFromCpfp"),
            }),
          }
        : {
            case: "renewNodeTimelockSigningJob",
            value: create(RenewNodeTimelockSigningJobSchema, {
              splitNodeTxSigningJob: at("split"),
              splitNodeDirectTxSigningJob: at("directSplit"),
              nodeTxSigningJob: at("node"),
              directNodeTxSigningJob: at("directNode"),
              refundTxSigningJob: at("cpfp"),
              directRefundTxSigningJob: at("direct"),
              directFromCpfpRefundTxSigningJob: at("directFromCpfp"),
            }),
          };

  const response = await spark.renew_leaf(
    { leafId: leaf.id, signingJobs },
    {
      ...options.call,
      headers: { "x-idempotency-key": txId(leaf.refundTx) },
    },
  );
  const result = response.renewResult;
  const expectedCase =
    kind === "refund"
      ? "renewRefundTimelockResult"
      : kind === "node"
        ? "renewNodeTimelockResult"
        : "renewNodeZeroTimelockResult";
  if (result.case !== expectedCase || result.value.node === undefined) {
    throw new SparkError(
      `renewLeaf: coordinator returned ${result.case ?? "no result"}, expected ${expectedCase}`,
    );
  }
  return mapTreeNode(result.value.node);
}
