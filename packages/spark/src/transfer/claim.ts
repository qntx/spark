import { create, toBinary } from "@bufbuild/protobuf";
import type { CallOptions, Client } from "@connectrpc/connect";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { equalBytes } from "@noble/curves/utils.js";

import { createCurrentTimelockRefundTxs } from "../core/bitcoin/index.ts";
import { sendLeafSigningDigest } from "../core/hashing/statements.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SparkError, SparkInputError, SparkRequestError } from "../errors/index.ts";
import { SignatureScheme } from "../proto/gen/common_pb.ts";
import { ClaimPackageSchema, HashVariant } from "../proto/gen/spark_pb.ts";
import type { ClaimTransferResponse, SparkService, TransferLeaf } from "../proto/gen/spark_pb.ts";
import { mapTreeNode } from "../tree/index.ts";
import type { SparkLeaf } from "../tree/index.ts";
import { CLAIMABLE_TRANSFER_STATUSES, mapTransfer } from "./model.ts";
import type { SparkTransfer, SparkTransferLeaf, TransferCoordinator } from "./model.ts";
import { queryTransfersByIds } from "./query.ts";
import { refundJobGroups, signRefundJobs } from "./refunds.ts";

/**
 * Verifies one pending leaf's sender signature: a legacy bare ECDSA signature (compact or DER) or a
 * scheme-tagged `common.Signature` (DER ECDSA or BIP-340 over the x-only sender key). Ported from
 * upstream `verifyTypedSignature`; anything unrecognized fails closed.
 */
function verifyLeafSignature(
  digest: Uint8Array,
  senderPublicKey: Uint8Array,
  sig: SparkTransferLeaf["sig"],
): boolean {
  if (digest.length !== 32 || senderPublicKey.length !== 33) {
    return false;
  }
  try {
    if (sig?.case === "typedSignature") {
      if (sig.value.signature.length === 0) {
        return false;
      }
      if (sig.value.scheme === SignatureScheme.ECDSA) {
        return secp256k1.verify(sig.value.signature, digest, senderPublicKey, {
          format: "der",
          prehash: false,
        });
      }
      if (sig.value.scheme === SignatureScheme.SCHNORR) {
        const [prefix] = senderPublicKey;
        if (prefix !== 0x02 && prefix !== 0x03) {
          return false;
        }
        return schnorr.verify(sig.value.signature, digest, senderPublicKey.subarray(1));
      }
      return false;
    }
    if (sig?.case === "signature") {
      return secp256k1.verify(sig.value, digest, senderPublicKey, { prehash: false });
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Whether the caller's own receiver leg is complete (upstream `isReceiverLegComplete`): the
 * whole-transfer status flips to COMPLETED only once every receiver claims, so multi-receiver
 * claimants key off their own receiver edge, with the whole status as a safety net.
 */
function isReceiverLegComplete(transfer: SparkTransfer, self: Uint8Array): boolean {
  const wholeComplete = transfer.status === "COMPLETED";
  if (transfer.receivers.length <= 1) {
    return wholeComplete;
  }
  const own = transfer.receivers.find((receiver) => equalBytes(receiver.identityPublicKey, self));
  return own !== undefined && (own.status === "COMPLETED" || wholeComplete);
}

/**
 * Maps wire transfer leaves down to this receiver's SparkLeaves — claim responses may carry every
 * receiver's leaves, and only `receiverId`'s edge (when set) becomes ours.
 */
function receiverLeaves(
  leaves: ReadonlyArray<TransferLeaf>,
  receiverId: string | undefined,
): SparkLeaf[] {
  const out: SparkLeaf[] = [];
  for (const leaf of leaves) {
    if (
      leaf.leaf !== undefined &&
      (receiverId === undefined || leaf.transferReceiverId === receiverId)
    ) {
      out.push(mapTreeNode(leaf.leaf));
    }
  }
  return out;
}

/**
 * `claim_transfer` answered `already_exists`: the operators finished this claim without us seeing
 * the response (lost response or retried call). Re-query and return this receiver's leaves when its
 * leg completed; rethrow the original error otherwise.
 */
async function recoverCompletedClaim(options: {
  readonly spark: Client<typeof SparkService>;
  readonly network: SparkNetwork;
  readonly transferId: string;
  readonly self: Uint8Array;
  readonly receiverId: string | undefined;
  readonly error: SparkRequestError;
  readonly call?: CallOptions;
}): Promise<SparkLeaf[]> {
  const { error } = options;
  const [found] = await queryTransfersByIds({
    spark: options.spark,
    transferIds: [options.transferId],
    network: options.network,
    ...(options.call === undefined ? {} : { call: options.call }),
  });
  if (found === undefined || !isReceiverLegComplete(mapTransfer(found), options.self)) {
    throw error;
  }
  return receiverLeaves(found.leaves, options.receiverId);
}

/**
 * `claim_transfer` — receiver claim. Verifies the sender's per-leaf signature over
 * `sendLeafSigningDigest` and that each `secret_cipher` decrypts (inside the signer) to the key
 * whose public key the leaf was tweaked to, re-signs the refund transactions at their current
 * timelock with the derived `LEAF{leafId}` keys, then submits the `ClaimPackage`.
 */
export async function claimTransfer(
  options: TransferCoordinator & {
    readonly transfer: SparkTransfer;
    readonly call?: CallOptions;
  },
): Promise<SparkLeaf[]> {
  const { spark, signer, network, operators, threshold } = options;
  const { transfer } = options;
  if (!CLAIMABLE_TRANSFER_STATUSES.includes(transfer.status)) {
    throw new SparkInputError(`claimTransfer: transfer status ${transfer.status} is not claimable`);
  }
  if (transfer.leaves.length === 0) {
    throw new SparkInputError("claimTransfer: transfer has no leaves");
  }

  // Multi-receiver transfers carry every receiver's leaves; claim only our receiver edge
  // (upstream `scopeTransferLeavesToReceiver`). Single-receiver and legacy transfers must
  // name this identity — fail closed.
  const self = await signer.identityPublicKey();
  let claimLeaves = transfer.leaves;
  let receiverId: string | undefined;
  if (transfer.receivers.length > 1) {
    const own = transfer.receivers.find((receiver) => equalBytes(receiver.identityPublicKey, self));
    if (own === undefined || own.id === "") {
      throw new SparkInputError("claimTransfer: not a receiver of this multi-receiver transfer");
    }
    claimLeaves = transfer.leaves.filter((leaf) => leaf.transferReceiverId === own.id);
    if (claimLeaves.length === 0) {
      throw new SparkInputError("claimTransfer: no leaves assigned to this receiver edge");
    }
    receiverId = own.id;
  } else {
    const receiverKey =
      transfer.receivers[0]?.identityPublicKey ?? transfer.receiverIdentityPublicKey;
    if (!equalBytes(receiverKey, self)) {
      throw new SparkInputError("claimTransfer: transfer is not addressed to this identity");
    }
  }

  for (const leaf of claimLeaves) {
    const digest = sendLeafSigningDigest(leaf.leaf.id, transfer.id, leaf.secretCipher);
    if (!verifyLeafSignature(digest, transfer.senderIdentityPublicKey, leaf.sig)) {
      throw new SparkInputError(
        `claimTransfer: sender signature verification failed for leaf ${leaf.leaf.id}`,
      );
    }
  }

  const receivedKeys = await signer.receivedPublicKeys(
    claimLeaves.map((leaf) => leaf.secretCipher),
  );
  for (const [i, leaf] of claimLeaves.entries()) {
    const received = receivedKeys[i];
    if (received === undefined) {
      throw new SparkError("claimTransfer: signer returned fewer public keys than requested");
    }
    if (!equalBytes(received, leaf.leaf.ownerSigningPublicKey)) {
      throw new SparkInputError(
        `claimTransfer: secret_cipher does not decrypt to the signing key of leaf ${leaf.leaf.id}`,
      );
    }
  }

  const prepared = await signer.prepareClaim({
    transferId: transfer.id,
    leaves: claimLeaves.map((leaf) => ({
      leafId: leaf.leaf.id,
      secretCipher: leaf.secretCipher,
    })),
    operators,
    threshold,
  });

  const signingCommitments = await spark.get_signing_commitments(
    {
      nodeIdCount: claimLeaves.length,
      count: 3,
    },
    options.call,
  );

  const newLeafKeys = await signer.publicKeys(
    claimLeaves.map((leaf) => ({ type: "leaf", leafId: leaf.leaf.id })),
  );

  const groups = refundJobGroups(
    claimLeaves.map((leaf, i) => {
      const signingPublicKey = newLeafKeys[i];
      if (signingPublicKey === undefined) {
        throw new SparkError("claimTransfer: signer returned fewer public keys than requested");
      }
      return {
        leaf: {
          ...leaf.leaf,
          refundTx: leaf.intermediateRefundTx,
          directRefundTx: leaf.intermediateDirectRefundTx,
          directFromCpfpRefundTx: leaf.intermediateDirectFromCpfpRefundTx,
        },
        refundTx: leaf.intermediateRefundTx,
        signingPublicKey,
        receivingPublicKey: signingPublicKey,
      };
    }),
    createCurrentTimelockRefundTxs,
    signingCommitments.signingCommitments,
    network,
    "claimTransfer",
  );

  const jobs = await signRefundJobs(signer, groups);

  const claimPackage = create(ClaimPackageSchema, {
    leavesToClaim: jobs.cpfp,
    keyTweakPackage: prepared.operatorPackages,
    userSignature: new Uint8Array(),
    directLeavesToClaim: jobs.direct,
    directFromCpfpLeavesToClaim: jobs.directFromCpfp,
    hashVariant: HashVariant.V2,
  });
  claimPackage.userSignature = await signer.signIdentity({
    kind: "claim-package",
    transferId: transfer.id,
    package: toBinary(ClaimPackageSchema, claimPackage),
  });

  let response: ClaimTransferResponse;
  try {
    response = await spark.claim_transfer(
      {
        transferId: transfer.id,
        ownerIdentityPublicKey: self,
        claimPackage,
      },
      options.call,
    );
  } catch (error) {
    // The operators may have already finished this claim (e.g. a lost response or a
    // retried call). Re-query and return this receiver's leaves if its leg completed.
    if (!(error instanceof SparkRequestError) || error.code !== "already_exists") {
      throw error;
    }
    return recoverCompletedClaim({
      spark,
      network,
      transferId: transfer.id,
      self,
      receiverId,
      error,
      ...(options.call === undefined ? {} : { call: options.call }),
    });
  }
  if (response.transfer === undefined) {
    throw new SparkError("claimTransfer: coordinator returned no transfer");
  }
  return receiverLeaves(response.transfer.leaves, receiverId);
}
