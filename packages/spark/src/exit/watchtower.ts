import { create } from "@bufbuild/protobuf";
import type { CallOptions, Client } from "@connectrpc/connect";
import { equalBytes } from "@noble/curves/utils.js";

import { u64ToSats } from "../core/assert.ts";
import {
  buildKeySpendSweep,
  finalizeKeySpend,
  p2trScriptFromPublicKey,
  parseTransaction,
  taprootKeySpendSighash,
  txId,
  verifyFinalizedTaprootSignature,
} from "../core/bitcoin/index.ts";
import { sparkNetworkProto } from "../core/network.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import { SigningJobSchema, TreeNodeStatus } from "../proto/gen/spark_pb.ts";
import type { SparkService, TreeNode } from "../proto/gen/spark_pb.ts";
import type { SparkSigner } from "../signer/types.ts";
import { queryOwnerNodes } from "../tree/index.ts";
import { cosignSingleJob } from "../tree/signing.ts";

export type WatchtowerExitedLeaf = {
  readonly leafId: string;
  readonly status: "WATCHTOWER_EXITED" | "WATCHTOWER_EXIT_RECOVERED";
  readonly valueSats: number;
  /** The confirmed ancestor output the leaf can still spend, when one resolves locally. */
  readonly recovery?: {
    readonly txid: string;
    readonly outputIndex: number;
    readonly valueSats: number;
  };
};

const WATCHTOWER_STATUSES: ReadonlyArray<TreeNodeStatus> = [
  TreeNodeStatus.WATCHTOWER_EXITED,
  TreeNodeStatus.WATCHTOWER_EXIT_RECOVERED,
];

/**
 * The leaf and its ancestors, nearest generation first — the order is load bearing: each renewal
 * generation's direct tx spends the one above and pays the same key, so successive watchtower
 * broadcasts leave several of them ON_CHAIN at once with only the nearest one's output still
 * unspent. Consumed-as-visited, so a parent cycle cannot spin. (upstream spark-wallet.ts
 * `generationsFromLeaf`)
 */
function generationsFromLeaf(leaf: TreeNode, nodes: ReadonlyArray<TreeNode>): TreeNode[] {
  const remaining = new Map(nodes.map((node) => [node.id, node]));
  const generations: TreeNode[] = [];
  for (let node: TreeNode | undefined = leaf; node !== undefined;) {
    generations.push(node);
    remaining.delete(node.id);
    node =
      node.parentNodeId === undefined || node.parentNodeId === ""
        ? undefined
        : remaining.get(node.parentNodeId);
  }
  return generations;
}

function findOutputPayingScript(
  transaction: ReturnType<typeof parseTransaction>,
  script: Uint8Array,
): number | undefined {
  for (let i = 0; i < transaction.outputsLength; i++) {
    const outputScript = transaction.getOutput(i).script;
    if (outputScript !== undefined && equalBytes(outputScript, script)) {
      return i;
    }
  }
  return undefined;
}

/**
 * Finds the confirmed on-chain output a watchtower-exited leaf can still spend — the one paying
 * P2TR(leaf.verifyingPublicKey), which renewal copies forward unchanged. `nodes` is the leaf and
 * its ancestors as `query_nodes` returns them with `includeParents`. Without `recoveryTxid` only
 * ON_CHAIN generations qualify — the gate the SE applies in `findRecoverySourceNode`, which also
 * excludes the leaf's own direct tx (it conflict-spends the very output being recovered). An
 * explicit `outputIndex` is re-checked against the leaf script. Returns undefined rather than
 * throwing: an unresolvable leaf is still worth listing. (upstream spark-wallet.ts
 * `resolveRecoverableOutput`)
 */
export function resolveRecoverableOutput(
  leaf: TreeNode,
  nodes: ReadonlyArray<TreeNode>,
  network: SparkNetwork,
  recoveryTxid?: string,
  outputIndex?: number,
): { txid: string; outputIndex: number; valueSats: number; prevTx: Uint8Array } | undefined {
  const leafScript = p2trScriptFromPublicKey(leaf.verifyingPublicKey, network);
  for (const node of generationsFromLeaf(leaf, nodes)) {
    if (node.directTx.length === 0) {
      continue;
    }
    // An explicitly named transaction is taken at its word: the SE re-checks the status itself,
    // and trusting the caller keeps a stale local chain view from blocking a recovery.
    if (recoveryTxid === undefined && node.treenodeStatus !== TreeNodeStatus.ON_CHAIN) {
      continue;
    }
    const tx = parseTransaction(node.directTx);
    const txid = txId(node.directTx);
    if (recoveryTxid !== undefined && txid !== recoveryTxid) {
      continue;
    }
    const index = outputIndex ?? findOutputPayingScript(tx, leafScript);
    // Fully bounded: a negative or fractional override lands on this check instead of throwing
    // out of getOutput.
    if (
      index === undefined ||
      !Number.isSafeInteger(index) ||
      index < 0 ||
      index >= tx.outputsLength
    ) {
      continue;
    }
    const output = tx.getOutput(index);
    if (output.amount === undefined || output.script === undefined) {
      continue;
    }
    // Re-checked rather than trusted from the search above: an explicit outputIndex skips that
    // search entirely, and the operator makes the same comparison.
    if (!equalBytes(output.script, leafScript)) {
      continue;
    }
    const valueSats = Number(output.amount);
    if (!Number.isSafeInteger(valueSats)) {
      continue;
    }
    return { txid, outputIndex: index, valueSats, prevTx: node.directTx };
  }
  return undefined;
}

/**
 * Lists the owner's watchtower-exited leaves and the recoverable output each still holds. Only a
 * leaf carries a refund tx — excluding the renewal split nodes that keep a stale owner key — and
 * the owner key must be ours. Already-recovered leaves stay listed: the SE never sees the
 * broadcast, so check the chain, not this list, for whether a recovery landed. (upstream
 * leaf-manager `queryWatchtowerExitedNodes` + `getWatchtowerExitedLeaves`)
 */
export async function queryWatchtowerExitedLeaves(options: {
  readonly spark: Client<typeof SparkService>;
  readonly identityPublicKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly call?: CallOptions;
}): Promise<ReadonlyArray<WatchtowerExitedLeaf>> {
  const { spark, identityPublicKey, network } = options;
  const nodes = await queryOwnerNodes({
    spark,
    ownerIdentityPublicKey: identityPublicKey,
    network,
    statuses: WATCHTOWER_STATUSES,
    includeParents: true,
    ...(options.call === undefined ? {} : { call: options.call }),
  });
  return nodes
    .filter(
      (node) =>
        node.refundTx.length > 0 && equalBytes(node.ownerIdentityPublicKey, identityPublicKey),
    )
    .map((leaf) => {
      const recovery = resolveRecoverableOutput(leaf, nodes, network);
      const entry: {
        -readonly [K in keyof WatchtowerExitedLeaf]: WatchtowerExitedLeaf[K];
      } = {
        leafId: leaf.id,
        status:
          leaf.treenodeStatus === TreeNodeStatus.WATCHTOWER_EXIT_RECOVERED
            ? "WATCHTOWER_EXIT_RECOVERED"
            : "WATCHTOWER_EXITED",
        valueSats: u64ToSats(leaf.value, "leaf value"),
      };
      if (recovery !== undefined) {
        entry.recovery = {
          txid: recovery.txid,
          outputIndex: recovery.outputIndex,
          valueSats: recovery.valueSats,
        };
      }
      return entry;
    });
}

/**
 * Co-signs a transaction spending the on-chain output a watchtower exit stranded under `leafId` and
 * returns it signed, NOT broadcast — broadcast is the caller's job (`sendrawtransaction`, which the
 * SE never sees). The leaf is retired server-side in the same operation; re-calling is allowed to
 * raise the fee since every recovery spends the same output. `recoveryTxid`/`outputIndex` name the
 * source outpoint explicitly; without them the nearest ON_CHAIN ancestor's output paying the leaf's
 * key is used.
 */
export async function recoverWatchtowerExit(
  options: {
    readonly spark: Client<typeof SparkService>;
    readonly signer: SparkSigner;
    readonly network: SparkNetwork;
    readonly call?: CallOptions;
  },
  request: {
    readonly leafId: string;
    readonly destinationScript: Uint8Array;
    readonly feeRateSatPerVbyte: number;
    readonly recoveryTxid?: string;
    readonly outputIndex?: number;
  },
): Promise<{ readonly transaction: Uint8Array; readonly txid: string }> {
  const { spark, signer, network } = options;
  const { leafId } = request;

  // The ancestor chain carries the transaction being spent, so the wallet needs no explorer.
  const nodesResponse = await spark.query_nodes(
    {
      source: { case: "nodeIds", value: { nodeIds: [leafId] } },
      includeParents: true,
      network: sparkNetworkProto(network),
    },
    options.call,
  );
  const leaf = nodesResponse.nodes[leafId];
  if (leaf === undefined) {
    throw new SparkInputError(`recoverWatchtowerExit: leaf ${leafId} not found`);
  }
  const identityPublicKey = await signer.identityPublicKey();
  if (!equalBytes(leaf.ownerIdentityPublicKey, identityPublicKey)) {
    throw new SparkInputError(`recoverWatchtowerExit: leaf ${leafId} is not ours`);
  }
  if (
    leaf.treenodeStatus !== TreeNodeStatus.WATCHTOWER_EXITED &&
    leaf.treenodeStatus !== TreeNodeStatus.WATCHTOWER_EXIT_RECOVERED
  ) {
    throw new SparkInputError(
      `recoverWatchtowerExit: leaf ${leafId} is ${leaf.status}, expected a watchtower-exited status`,
    );
  }
  const recoverable = resolveRecoverableOutput(
    leaf,
    Object.values(nodesResponse.nodes),
    network,
    request.recoveryTxid,
    request.outputIndex,
  );
  if (recoverable === undefined) {
    throw new SparkInputError(
      request.recoveryTxid === undefined
        ? "recoverWatchtowerExit: no confirmed ancestor transaction of this leaf holds a recoverable output"
        : "recoverWatchtowerExit: recoveryTxid is not an ancestor transaction of this leaf paying its key",
    );
  }

  const sweep = buildKeySpendSweep({
    prevTx: recoverable.prevTx,
    vout: recoverable.outputIndex,
    destinationScript: request.destinationScript,
    feeRateSatPerVbyte: request.feeRateSatPerVbyte,
  });
  const key = { type: "leaf", leafId } as const;
  const [signingPublicKey] = await signer.publicKeys([key]);
  if (signingPublicKey === undefined) {
    throw new SparkError(`recoverWatchtowerExit: signer returned no key for leaf ${leafId}`);
  }
  if (!equalBytes(signingPublicKey, leaf.ownerSigningPublicKey)) {
    throw new SparkError(
      `recoverWatchtowerExit: signer key does not match leaf ${leafId}'s owner signing key`,
    );
  }
  const [commitment] = await signer.newCommitments(1);
  if (commitment === undefined) {
    throw new SparkError("recoverWatchtowerExit: signer returned no signing commitment");
  }
  // Authorises this exact transaction: the operator-internal channel carries no session, and the
  // sighash inside the statement stops an earlier authorisation being replayed onto a new tx.
  const userSignature = await signer.signIdentity({
    kind: "watchtower-recovery",
    network,
    leafId,
    target: sweep.target,
  });

  const response = await spark.recover_watchtower_exited_leaf(
    {
      leafId,
      recoveryTxSigningJob: create(SigningJobSchema, {
        signingPublicKey,
        rawTx: sweep.transaction,
        signingNonceCommitment: commitment,
      }),
      userSignature,
    },
    options.call,
  );
  const result = response.recoveryTxSigningResult;
  const { verifyingKey } = response;
  if (result === undefined) {
    throw new SparkError("recoverWatchtowerExit: coordinator returned no signing result");
  }
  if (!equalBytes(verifyingKey, leaf.verifyingPublicKey)) {
    throw new SparkError("recoverWatchtowerExit: coordinator returned an unexpected verifying key");
  }
  const leafScript = p2trScriptFromPublicKey(leaf.verifyingPublicKey, network);
  if (!equalBytes(p2trScriptFromPublicKey(verifyingKey, network), leafScript)) {
    throw new SparkError("recoverWatchtowerExit: verifying key does not bind the recovered output");
  }

  const signature = await cosignSingleJob(signer, {
    key,
    target: sweep.target,
    verifyingKey,
    commitment,
    result,
    context: "recoverWatchtowerExit",
  });
  const signed = finalizeKeySpend(sweep.transaction, signature);
  if (
    !verifyFinalizedTaprootSignature(signed, taprootKeySpendSighash(sweep.target), verifyingKey, 0)
  ) {
    throw new SparkError("recoverWatchtowerExit: the aggregated signature does not verify");
  }
  return { transaction: signed, txid: txId(signed) };
}
