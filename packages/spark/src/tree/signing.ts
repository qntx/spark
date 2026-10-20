import { create } from "@bufbuild/protobuf";

import { SparkError } from "../errors/index.ts";
import { UserSignedTxSigningJobSchema } from "../proto/gen/spark_pb.ts";
import type {
  RequestedSigningCommitments,
  SigningResult,
  UserSignedTxSigningJob,
} from "../proto/gen/spark_pb.ts";
import type {
  OperatorCommitment,
  SigningCommitment,
  SigningTarget,
  SparkKey,
  SparkSigner,
} from "../signer/types.ts";

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

/**
 * Completes one SO co-signing round for a caller-built job: `signFrost` the user's share over the
 * SO's `SigningResult` commitments, then `aggregateFrost` all shares into the 64-byte signature the
 * spend's witness carries. `commitment` is the user's `newCommitments(1)` nonce sent on the
 * request; `result` is the returned `SigningResult`. Shared by the static-deposit refund and the
 * watchtower-exit recovery, which both finish a single key-path input this way.
 */
export async function cosignSingleJob(
  signer: SparkSigner,
  job: {
    readonly key: SparkKey;
    readonly target: SigningTarget;
    readonly verifyingKey: Uint8Array;
    readonly commitment: SigningCommitment;
    readonly result: SigningResult;
    /** Error-message prefix, e.g. `"refundStatic"`. */
    readonly context: string;
  },
): Promise<Uint8Array> {
  const { key, target, verifyingKey, commitment, result, context } = job;
  const operatorCommitments = Object.entries(result.signingNonceCommitments).map(
    ([identifier, commitment]) => ({ identifier, commitment }),
  );
  const [signatureShare] = await signer.signFrost([
    { key, target, verifyingKey, commitment, operatorCommitments },
  ]);
  if (signatureShare === undefined) {
    throw new SparkError(`${context}: signer returned no signature share`);
  }
  const [signature] = await signer.aggregateFrost([
    {
      key,
      target,
      verifyingKey,
      commitment,
      signatureShare,
      operators: Object.keys(result.signatureShares).map((identifier) => {
        const operatorCommitment = result.signingNonceCommitments[identifier];
        const share = result.signatureShares[identifier];
        const publicKey = result.publicKeys[identifier];
        if (operatorCommitment === undefined || share === undefined || publicKey === undefined) {
          throw new SparkError(`${context}: missing operator ${identifier} signing data`);
        }
        return { identifier, commitment: operatorCommitment, signatureShare: share, publicKey };
      }),
    },
  ]);
  if (signature === undefined) {
    throw new SparkError(`${context}: signer returned no aggregate signature`);
  }
  return signature;
}
