import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { secp256k1 } from "@noble/curves/secp256k1.js";

import { taprootKeySpendSighash } from "../core/bitcoin/sighash.ts";
import type { SparkCrypto } from "../crypto/index.ts";
import { SparkCryptoError } from "../errors/index.ts";
import {
  FrostAggregateJobSchema,
  FrostAggregateRequestSchema,
  FrostAggregateResponseSchema,
  FrostSignJobSchema,
  FrostSignRequestSchema,
  FrostSignResponseSchema,
} from "../proto/gen/qntx_spark_ffi_pb.ts";
import { backendCall, checkBatch, identifierBytes } from "./backend.ts";
import type { SignerKeys } from "./keys.ts";
import type { NonceStore } from "./nonces.ts";
import type { FrostAggregateJob, FrostSignJob } from "./types.ts";

/**
 * User-side FROST signature shares, one 32-byte share per job in order. Each job's commitment nonce
 * is removed from the store before the backend call — reuse fails even after an error. Resolved
 * private keys and consumed nonces are wiped.
 */
export function frostSignJobs(
  crypto: SparkCrypto,
  jobs: ReadonlyArray<FrostSignJob>,
  keys: SignerKeys,
  nonces: NonceStore,
): ReadonlyArray<Uint8Array> {
  checkBatch(jobs.length, "signFrost");
  if (jobs.length === 0) {
    return [];
  }
  const secretKeys: Uint8Array[] = [];
  const consumedNonces: Uint8Array[] = [];
  try {
    const request = create(FrostSignRequestSchema, { jobs: [] });
    for (const job of jobs) {
      const nonce = nonces.take(job.commitment);
      consumedNonces.push(nonce);
      const secretKey = keys.resolve(job.key);
      secretKeys.push(secretKey);
      request.jobs.push(
        create(FrostSignJobSchema, {
          message: taprootKeySpendSighash(job.target),
          secretKey,
          verifyingKey: job.verifyingKey,
          nonce,
          userCommitment: { hiding: job.commitment.hiding, binding: job.commitment.binding },
          operatorCommitments: job.operatorCommitments.map((operator) => ({
            identifier: identifierBytes(operator.identifier),
            commitment: {
              hiding: operator.commitment.hiding,
              binding: operator.commitment.binding,
            },
          })),
          adaptorPublicKey: job.adaptorPublicKey ?? new Uint8Array(),
        }),
      );
    }
    const requestBytes = toBinary(FrostSignRequestSchema, request);
    let responseBytes: Uint8Array;
    try {
      responseBytes = backendCall(() => crypto.frostSign(requestBytes));
    } finally {
      requestBytes.fill(0);
    }
    const response = fromBinary(FrostSignResponseSchema, responseBytes);
    if (response.signatureShares.length !== jobs.length) {
      throw new SparkCryptoError(8);
    }
    return response.signatureShares;
  } finally {
    for (const key of secretKeys) {
      key.fill(0);
    }
    for (const nonce of consumedNonces) {
      nonce.fill(0);
    }
  }
}

/**
 * Aggregated 64-byte FROST (Schnorr) signatures, one per job in order. The user verifying share is
 * derived from the resolved private key.
 */
export function frostAggregateJobs(
  crypto: SparkCrypto,
  jobs: ReadonlyArray<FrostAggregateJob>,
  keys: SignerKeys,
): ReadonlyArray<Uint8Array> {
  checkBatch(jobs.length, "aggregateFrost");
  if (jobs.length === 0) {
    return [];
  }
  const secretKeys: Uint8Array[] = [];
  try {
    const request = create(FrostAggregateRequestSchema, { jobs: [] });
    for (const job of jobs) {
      const secretKey = keys.resolve(job.key);
      secretKeys.push(secretKey);
      request.jobs.push(
        create(FrostAggregateJobSchema, {
          message: taprootKeySpendSighash(job.target),
          verifyingKey: job.verifyingKey,
          userCommitment: {
            hiding: job.commitment.hiding,
            binding: job.commitment.binding,
          },
          userPublicKey: secp256k1.getPublicKey(secretKey, true),
          userSignatureShare: job.signatureShare,
          operators: job.operators.map((operator) => ({
            identifier: identifierBytes(operator.identifier),
            commitment: {
              hiding: operator.commitment.hiding,
              binding: operator.commitment.binding,
            },
            signatureShare: operator.signatureShare,
            publicKey: operator.publicKey,
          })),
          adaptorPublicKey: job.adaptorPublicKey ?? new Uint8Array(),
        }),
      );
    }
    const responseBytes = backendCall(() =>
      crypto.frostAggregate(toBinary(FrostAggregateRequestSchema, request)),
    );
    const response = fromBinary(FrostAggregateResponseSchema, responseBytes);
    if (response.signatures.length !== jobs.length) {
      throw new SparkCryptoError(8);
    }
    return response.signatures;
  } finally {
    for (const key of secretKeys) {
      key.fill(0);
    }
  }
}
