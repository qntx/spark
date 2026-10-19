import { u64ToSats } from "../core/assert.ts";
import { parseTransaction } from "../core/bitcoin/index.ts";
import type { RefundTxTrio } from "../core/bitcoin/index.ts";
import { SparkError } from "../errors/index.ts";
import type { RequestedSigningCommitments, UserSignedTxSigningJob } from "../proto/gen/spark_pb.ts";
import type { SparkSigner } from "../signer/types.ts";
import type { SparkLeaf } from "../tree/index.ts";
import { signUserJobs } from "../tree/signing.ts";
import type { UserSigningSpec } from "../tree/signing.ts";

/** One refund signing spec: the leaf it covers, its SO commitments and the signing target. */
type RefundJobSpec = UserSigningSpec & { readonly leafId: string };

/** Per-leaf input to {@link refundJobGroups}: the leaf, its current refund tx and its signer key. */
export type RefundJobLeaf = {
  readonly leaf: SparkLeaf;
  readonly refundTx: Uint8Array;
  readonly signingPublicKey: Uint8Array;
};

function prevout(
  txBytes: Uint8Array,
  vout: number,
  context: string,
): { readonly script: Uint8Array; readonly amount: number } {
  const output = parseTransaction(txBytes).getOutput(vout);
  if (output.script === undefined || output.amount === undefined) {
    throw new SparkError(`${context}: transaction has no output ${vout}`);
  }
  return { script: output.script, amount: u64ToSats(output.amount, `${context} output`) };
}

function refundTxSequence(refundTxBytes: Uint8Array, context: string): number {
  const { sequence } = parseTransaction(refundTxBytes).getInput(0);
  if (sequence === undefined) {
    throw new SparkError(`${context}: refund tx input has no sequence`);
  }
  return sequence;
}

/**
 * Builds the three refund signing-job groups (CPFP, direct, direct-from-CPFP) for `leaves`,
 * mirroring upstream `signRefundsCore`: the CPFP and direct-from-CPFP refunds spend the node tx
 * output 0, the direct refund spends the direct node tx output 0 and exists only when the leaf
 * carries a direct tx. `signingCommitments` must hold exactly `3 * leaves.length` entries, sliced
 * per group (CPFP first, then direct, then direct-from-CPFP).
 *
 * `buildRefunds` constructs the leaf's refund trio from its current refund sequence — plain
 * timelock refunds for sends, swaps and claims, HTLC refunds for Lightning sends.
 */
export function refundJobGroups(
  leaves: ReadonlyArray<RefundJobLeaf>,
  buildRefunds: (entry: RefundJobLeaf, sequence: number) => RefundTxTrio,
  signingCommitments: ReadonlyArray<RequestedSigningCommitments>,
  context: string,
): {
  cpfp: RefundJobSpec[];
  direct: RefundJobSpec[];
  directFromCpfp: RefundJobSpec[];
} {
  const count = leaves.length;
  if (signingCommitments.length !== 3 * count) {
    throw new SparkError(
      `${context}: expected ${3 * count} signing commitments, got ${signingCommitments.length}`,
    );
  }
  const cpfp: RefundJobSpec[] = [];
  const direct: RefundJobSpec[] = [];
  const directFromCpfp: RefundJobSpec[] = [];
  for (const [i, entry] of leaves.entries()) {
    const nodeOutput = prevout(entry.leaf.nodeTx, 0, `${context} leaf ${entry.leaf.id} node tx`);
    const refunds = buildRefunds(entry, refundTxSequence(entry.refundTx, context));
    const commitments = signingCommitments[i];
    const directCommitment = signingCommitments[count + i];
    const directFromCpfpCommitment = signingCommitments[2 * count + i];
    if (
      commitments === undefined ||
      directCommitment === undefined ||
      directFromCpfpCommitment === undefined
    ) {
      throw new SparkError(`${context}: signing commitment bookkeeping failure`);
    }
    cpfp.push({
      leafId: entry.leaf.id,
      key: { type: "leaf", leafId: entry.leaf.id },
      signingPublicKey: entry.signingPublicKey,
      verifyingKey: entry.leaf.verifyingPublicKey,
      target: {
        transaction: refunds.cpfpRefund.txBytes,
        inputIndex: 0,
        prevouts: [nodeOutput],
      },
      commitments,
    });
    if (refunds.directRefund !== undefined) {
      const directOutput = prevout(
        entry.leaf.directTx ?? new Uint8Array(),
        0,
        `${context} leaf ${entry.leaf.id} direct node tx`,
      );
      direct.push({
        leafId: entry.leaf.id,
        key: { type: "leaf", leafId: entry.leaf.id },
        signingPublicKey: entry.signingPublicKey,
        verifyingKey: entry.leaf.verifyingPublicKey,
        target: {
          transaction: refunds.directRefund.txBytes,
          inputIndex: 0,
          prevouts: [directOutput],
        },
        commitments: directCommitment,
      });
    }
    directFromCpfp.push({
      leafId: entry.leaf.id,
      key: { type: "leaf", leafId: entry.leaf.id },
      signingPublicKey: entry.signingPublicKey,
      verifyingKey: entry.leaf.verifyingPublicKey,
      target: {
        transaction: refunds.directFromCpfpRefund.txBytes,
        inputIndex: 0,
        prevouts: [nodeOutput],
      },
      commitments: directFromCpfpCommitment,
    });
  }
  return { cpfp, direct, directFromCpfp };
}

/** One batched `signFrost` over all specs; returns the wire `UserSignedTxSigningJob`s per group. */
export async function signRefundJobs(
  signer: SparkSigner,
  groups: { cpfp: RefundJobSpec[]; direct: RefundJobSpec[]; directFromCpfp: RefundJobSpec[] },
): Promise<{
  cpfp: UserSignedTxSigningJob[];
  direct: UserSignedTxSigningJob[];
  directFromCpfp: UserSignedTxSigningJob[];
}> {
  const jobs = await signUserJobs(signer, [
    ...groups.cpfp,
    ...groups.direct,
    ...groups.directFromCpfp,
  ]);
  return {
    cpfp: jobs.slice(0, groups.cpfp.length),
    direct: jobs.slice(groups.cpfp.length, groups.cpfp.length + groups.direct.length),
    directFromCpfp: jobs.slice(groups.cpfp.length + groups.direct.length),
  };
}
