import { create } from "@bufbuild/protobuf";

import { SparkError } from "../errors/index.ts";
import { UserSignedTxSigningJobSchema } from "../proto/gen/spark_pb.ts";
import type { RequestedSigningCommitments, UserSignedTxSigningJob } from "../proto/gen/spark_pb.ts";
import type { OperatorCommitment, SigningTarget, SparkKey, SparkSigner } from "../signer/types.ts";

/**
 * One user-side FROST signing job for an SO request: the key inside the signer, the wire
 * `signingPublicKey`, the aggregate `verifyingKey`, the sighash `target` (its `transaction` becomes
 * the job's `rawTx`) and the per-operator commitments the SO issued for the job. `leafId` is set on
 * transfer/claim/renew jobs and absent on deposit jobs.
 */
export type UserSigningSpec = {
  readonly leafId?: string;
  readonly key: SparkKey;
  readonly signingPublicKey: Uint8Array;
  readonly verifyingKey: Uint8Array;
  readonly target: SigningTarget;
  readonly commitments: RequestedSigningCommitments;
  /** 33-byte adaptor point, when the job's signature must verify under an adaptor (leaves swap). */
  readonly adaptorPublicKey?: Uint8Array;
};

function operatorCommitments(
  commitments: RequestedSigningCommitments,
): ReadonlyArray<OperatorCommitment> {
  return Object.entries(commitments.signingNonceCommitments).map(([identifier, commitment]) => ({
    identifier,
    commitment,
  }));
}

/**
 * Signs every spec in one `newCommitments`/`signFrost` round — user commitment at index `i` signs
 * spec `i` — and returns the wire `UserSignedTxSigningJob`s in the same order.
 */
export async function signUserJobs(
  signer: SparkSigner,
  specs: ReadonlyArray<UserSigningSpec>,
): Promise<UserSignedTxSigningJob[]> {
  const commitments = await signer.newCommitments(specs.length);
  if (commitments.length !== specs.length) {
    throw new SparkError("signUserJobs: signer returned fewer commitments than requested");
  }
  const shares = await signer.signFrost(
    specs.map((spec, index) => {
      const commitment = commitments[index];
      if (commitment === undefined) {
        throw new SparkError("signUserJobs: commitment bookkeeping failure");
      }
      return {
        key: spec.key,
        target: spec.target,
        verifyingKey: spec.verifyingKey,
        commitment,
        operatorCommitments: operatorCommitments(spec.commitments),
        ...(spec.adaptorPublicKey === undefined ? {} : { adaptorPublicKey: spec.adaptorPublicKey }),
      };
    }),
  );
  if (shares.length !== specs.length) {
    throw new SparkError("signUserJobs: signer returned fewer shares than requested");
  }
  return specs.map((spec, index) => {
    const commitment = commitments[index];
    const share = shares[index];
    if (commitment === undefined || share === undefined) {
      throw new SparkError("signUserJobs: signing job bookkeeping failure");
    }
    return create(UserSignedTxSigningJobSchema, {
      ...(spec.leafId === undefined ? {} : { leafId: spec.leafId }),
      signingPublicKey: spec.signingPublicKey,
      rawTx: spec.target.transaction,
      signingNonceCommitment: commitment,
      userSignature: share,
      signingCommitments: { signingCommitments: spec.commitments.signingNonceCommitments },
    });
  });
}
