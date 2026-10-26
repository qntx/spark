import { create } from "@bufbuild/protobuf";

import { SparkError } from "../errors/index.ts";
import { UserSignedTxSigningJobSchema } from "../proto/gen/spark_pb.ts";
import type {
  RequestedSigningCommitments,
  SigningResult,
  UserSignedTxSigningJob,
} from "../proto/gen/spark_pb.ts";
import type {
  FrostAggregateJob,
  OperatorCommitment,
  SigningCommitment,
  SigningTarget,
  SparkKey,
  SparkLeafKey,
  SparkSigner,
} from "../signer/types.ts";

/**
 * The signer's per-call job limit (signer/backend.ts `MAX_JOBS` — services only hold the
 * `SparkSigner` type, so the client-side constant lives here). Signer calls whose input scales with
 * leaf count must chunk through the helpers below; a unit test keeps this equal to `MAX_JOBS`.
 */
export const SIGNER_BATCH_LIMIT = 256;

function chunks<T>(items: ReadonlyArray<T>, size: number): T[][] {
  const result: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    result.push(items.slice(i, i + size));
  }
  return result;
}

/** `signer.publicKeys` over any number of keys, at most `SIGNER_BATCH_LIMIT` per call. */
export async function batchedPublicKeys(
  signer: SparkSigner,
  keys: ReadonlyArray<SparkLeafKey>,
): Promise<Uint8Array[]> {
  const parts = await Promise.all(
    chunks([...keys], SIGNER_BATCH_LIMIT).map(async (chunk) => signer.publicKeys(chunk)),
  );
  return parts.flat();
}

/** `signer.receivedPublicKeys` over any number of ciphers, chunked like `batchedPublicKeys`. */
export async function batchedReceivedPublicKeys(
  signer: SparkSigner,
  secretCiphers: ReadonlyArray<Uint8Array>,
): Promise<Uint8Array[]> {
  const parts = await Promise.all(
    chunks([...secretCiphers], SIGNER_BATCH_LIMIT).map(async (chunk) =>
      signer.receivedPublicKeys(chunk),
    ),
  );
  return parts.flat();
}

/** `signer.aggregateFrost` over any number of jobs, chunked like `batchedPublicKeys`. */
export async function batchedAggregateFrost(
  signer: SparkSigner,
  jobs: ReadonlyArray<FrostAggregateJob>,
): Promise<Uint8Array[]> {
  const parts = await Promise.all(
    chunks([...jobs], SIGNER_BATCH_LIMIT).map(async (chunk) => signer.aggregateFrost(chunk)),
  );
  return parts.flat();
}

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
  /** Connector-refund proof pair — see `FrostSignJob.exit`. */
  readonly exit?: {
    readonly connectorTx: Uint8Array;
    readonly exitTx: Uint8Array;
  };
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
 * Signs every spec in `newCommitments`/`signFrost` rounds of at most `SIGNER_BATCH_LIMIT` — user
 * commitment at index `i` signs spec `i` — and returns the wire `UserSignedTxSigningJob`s in the
 * same order. Chunks are sequential so outstanding nonces never exceed the limit; a leaf needs
 * three refund jobs, so a 1000-leaf transfer still fits the signer's per-call cap.
 */
export async function signUserJobs(
  signer: SparkSigner,
  specs: ReadonlyArray<UserSigningSpec>,
): Promise<UserSignedTxSigningJob[]> {
  const jobs: UserSignedTxSigningJob[] = [];
  for (const chunk of chunks([...specs], SIGNER_BATCH_LIMIT)) {
    // oxlint-disable-next-line no-await-in-loop -- chunks are sequential to bound outstanding nonces
    const commitments = await signer.newCommitments(chunk.length);
    if (commitments.length !== chunk.length) {
      throw new SparkError("signUserJobs: signer returned fewer commitments than requested");
    }
    // oxlint-disable-next-line no-await-in-loop -- chunks are sequential to bound outstanding nonces
    const shares = await signer.signFrost(
      chunk.map((spec, index) => {
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
          ...(spec.adaptorPublicKey === undefined
            ? {}
            : { adaptorPublicKey: spec.adaptorPublicKey }),
          ...(spec.exit === undefined ? {} : { exit: spec.exit }),
        };
      }),
    );
    if (shares.length !== chunk.length) {
      throw new SparkError("signUserJobs: signer returned fewer shares than requested");
    }
    for (const [index, spec] of chunk.entries()) {
      const commitment = commitments[index];
      const share = shares[index];
      if (commitment === undefined || share === undefined) {
        throw new SparkError("signUserJobs: signing job bookkeeping failure");
      }
      jobs.push(
        create(UserSignedTxSigningJobSchema, {
          ...(spec.leafId === undefined ? {} : { leafId: spec.leafId }),
          signingPublicKey: spec.signingPublicKey,
          rawTx: spec.target.transaction,
          signingNonceCommitment: commitment,
          userSignature: share,
          signingCommitments: { signingCommitments: spec.commitments.signingNonceCommitments },
        }),
      );
    }
  }
  return jobs;
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
