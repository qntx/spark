import { create, toBinary } from "@bufbuild/protobuf";
import type { CallOptions } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { equalBytes } from "@noble/curves/utils.js";

import { createDecrementedTimelockRefundTxs } from "../core/bitcoin/index.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import {
  AdaptorPublicKeyPackageSchema,
  HashVariant,
  TransferPackageSchema,
} from "../proto/gen/spark_pb.ts";
import type { SspClient } from "../ssp/index.ts";
import { selectExact } from "../tree/index.ts";
import type { SparkLeaf } from "../tree/index.ts";
import { signUserJobs } from "../tree/signing.ts";
import { claimTransfer } from "./claim.ts";
import type { TransferCoordinator } from "./model.ts";
import { mapTransfer } from "./model.ts";
import { queryTransfersByIds } from "./query.ts";
import { refundJobGroups } from "./refunds.ts";

/**
 * `initiate_swap_primary_transfer` (swap v3) + `request_swap` — exchanges `leaves` with the SSP for
 * fresh leaves at `targetAmountsSats`, claimed via the counter transfer the SSP starts.
 *
 * Flow (mirrors upstream `sendSwapTransfer` + Breez swap v3): the sender key-tweaks each leaf
 * toward the SSP identity, signs only the CPFP refund jobs under an adaptor point, and submits the
 * primary transfer without `expiryTime` — for a v3 primary swap the SO assigns the expiry itself
 * and holds the key tweaks until the counter transfer. The adaptor-added signatures go to the SSP
 * in `request_swap`; the SSP then starts the counter transfer this function claims.
 */
export async function swapLeaves(
  options: TransferCoordinator & {
    readonly ssp: SspClient;
    readonly sspIdentityPublicKey: Uint8Array;
    readonly transferId: string;
    readonly leaves: ReadonlyArray<SparkLeaf>;
    readonly targetAmountsSats: ReadonlyArray<number>;
    readonly random: (length: number) => Uint8Array;
    readonly call?: CallOptions;
  },
): Promise<SparkLeaf[]> {
  const { spark, signer, network, operators, threshold } = options;
  if (options.leaves.length === 0) {
    throw new SparkInputError("swapLeaves: leaves must not be empty");
  }
  if (options.targetAmountsSats.length === 0) {
    throw new SparkInputError("swapLeaves: targetAmountsSats must not be empty");
  }
  let totalSats = 0;
  for (const leaf of options.leaves) {
    totalSats += leaf.valueSats;
  }
  let targetTotal = 0;
  for (const target of options.targetAmountsSats) {
    if (!Number.isSafeInteger(target) || target <= 0) {
      throw new SparkInputError("swapLeaves: targetAmountsSats must be positive safe integers");
    }
    targetTotal += target;
  }
  if (targetTotal > totalSats) {
    throw new SparkInputError(
      `swapLeaves: target amounts ${targetTotal} exceed leaves value ${totalSats}`,
    );
  }

  const prepared = await signer.prepareTransfer({
    transferId: options.transferId,
    receiverIdentityPublicKey: options.sspIdentityPublicKey,
    leaves: options.leaves.map((leaf) => ({
      leafId: leaf.id,
      key: { type: "leaf", leafId: leaf.id },
    })),
    operators,
    threshold,
  });

  const signingCommitments = await spark.get_signing_commitments(
    {
      nodeIds: options.leaves.map((leaf) => leaf.id),
      count: 3,
    },
    options.call,
  );

  const signingPublicKeys = await signer.publicKeys(
    options.leaves.map((leaf) => ({ type: "leaf", leafId: leaf.id })),
  );

  const groups = refundJobGroups(
    options.leaves.map((leaf, i) => {
      const signingPublicKey = signingPublicKeys[i];
      if (signingPublicKey === undefined) {
        throw new SparkError("swapLeaves: signer returned fewer public keys than requested");
      }
      return { leaf, refundTx: leaf.refundTx, signingPublicKey };
    }),
    (entry, sequence) =>
      createDecrementedTimelockRefundTxs({
        nodeTx: entry.leaf.nodeTx,
        directNodeTx: entry.leaf.directTx,
        sequence,
        receivingPublicKey: options.sspIdentityPublicKey,
        network,
      }),
    signingCommitments.signingCommitments,
    "swapLeaves",
  );

  // The adaptor secret is discarded immediately — no party needs it (upstream and Breez discard it
  // too) — so it is not wallet key material and is generated outside the signer.
  const adaptorSecret = secp256k1.utils.randomSecretKey(options.random(48));
  const adaptorPublicKey = secp256k1.getPublicKey(adaptorSecret, true);
  adaptorSecret.fill(0);

  const cpfpJobs = await signUserJobs(
    signer,
    groups.cpfp.map((spec) => ({ ...spec, adaptorPublicKey })),
  );

  const transferPackage = create(TransferPackageSchema, {
    leavesToSend: cpfpJobs,
    keyTweakPackage: prepared.operatorPackages,
    userSignature: new Uint8Array(),
    directLeavesToSend: [],
    directFromCpfpLeavesToSend: [],
    hashVariant: HashVariant.V2,
  });
  transferPackage.userSignature = await signer.signIdentity({
    kind: "transfer-package",
    transferId: options.transferId,
    package: toBinary(TransferPackageSchema, transferPackage),
  });

  const response = await spark.initiate_swap_primary_transfer(
    {
      transfer: {
        transferId: options.transferId,
        ownerIdentityPublicKey: await signer.identityPublicKey(),
        receiverIdentityPublicKey: options.sspIdentityPublicKey,
        transferPackage,
      },
      adaptorPublicKeys: create(AdaptorPublicKeyPackageSchema, { adaptorPublicKey }),
    },
    options.call,
  );
  if (response.transfer === undefined) {
    throw new SparkError("swapLeaves: coordinator returned no transfer");
  }

  const jobByLeafId = new Map<string, (typeof cpfpJobs)[number]>();
  for (const job of cpfpJobs) {
    if (job.leafId === undefined) {
      throw new SparkError("swapLeaves: signing job bookkeeping failure");
    }
    jobByLeafId.set(job.leafId, job);
  }
  const specByLeafId = new Map(groups.cpfp.map((spec) => [spec.leafId, spec]));
  const leafByLeafId = new Map(options.leaves.map((leaf) => [leaf.id, leaf]));
  if (response.signingResults.length !== options.leaves.length) {
    throw new SparkError(
      `swapLeaves: expected ${options.leaves.length} signing results, got ${response.signingResults.length}`,
    );
  }

  const aggregateJobs = response.signingResults.map((result) => {
    const leaf = leafByLeafId.get(result.leafId);
    const spec = specByLeafId.get(result.leafId);
    const job = jobByLeafId.get(result.leafId);
    if (leaf === undefined || spec === undefined || job === undefined) {
      throw new SparkError(`swapLeaves: signing result for unknown leaf ${result.leafId}`);
    }
    const userCommitment = job.signingNonceCommitment;
    if (userCommitment === undefined) {
      throw new SparkError("swapLeaves: signing job bookkeeping failure");
    }
    const refundResult = result.refundTxSigningResult;
    if (refundResult === undefined) {
      throw new SparkError(`swapLeaves: leaf ${result.leafId} has no refund signing result`);
    }
    if (!equalBytes(result.verifyingKey, leaf.verifyingPublicKey)) {
      throw new SparkError(`swapLeaves: leaf ${result.leafId} verifying key mismatch`);
    }
    return {
      key: { type: "leaf", leafId: leaf.id } as const,
      target: spec.target,
      verifyingKey: result.verifyingKey,
      commitment: userCommitment,
      signatureShare: job.userSignature,
      operators: Object.keys(refundResult.signatureShares).map((identifier) => {
        const commitment = refundResult.signingNonceCommitments[identifier];
        const signatureShare = refundResult.signatureShares[identifier];
        const publicKey = refundResult.publicKeys[identifier];
        if (commitment === undefined || signatureShare === undefined || publicKey === undefined) {
          throw new SparkError(
            `swapLeaves: leaf ${result.leafId} is missing operator ${identifier} signing data`,
          );
        }
        return { identifier, commitment, signatureShare, publicKey };
      }),
      adaptorPublicKey,
    };
  });
  const adaptorAddedSignatures = await signer.aggregateFrost(aggregateJobs);
  if (adaptorAddedSignatures.length !== response.signingResults.length) {
    throw new SparkError("swapLeaves: signer returned fewer adaptor signatures than requested");
  }

  const userLeaves = response.signingResults.map((result, index) => {
    const spec = specByLeafId.get(result.leafId);
    const adaptorAddedSignature = adaptorAddedSignatures[index];
    if (spec === undefined || adaptorAddedSignature === undefined) {
      throw new SparkError("swapLeaves: adaptor signature bookkeeping failure");
    }
    return {
      leafId: result.leafId,
      rawUnsignedRefundTransaction: spec.target.transaction,
      adaptorAddedSignature,
    };
  });
  const requestedFeeSats = 0;
  const swapResult = await options.ssp.requestSwap({
    adaptorPublicKey,
    totalAmountSats: totalSats,
    targetAmountsSats: options.targetAmountsSats,
    feeSats: requestedFeeSats,
    userLeaves,
    userOutboundTransferId: options.transferId,
  });

  const [inbound] = await queryTransfersByIds({
    spark,
    transferIds: [swapResult.inboundTransferId],
    network,
    ...(options.call === undefined ? {} : { call: options.call }),
  });
  if (inbound === undefined) {
    throw new SparkError("swapLeaves: inbound transfer not found");
  }
  const inboundTransfer = mapTransfer(inbound);
  if (!equalBytes(inboundTransfer.senderIdentityPublicKey, options.sspIdentityPublicKey)) {
    throw new SparkError("swapLeaves: inbound transfer sender is not the SSP");
  }
  const claimed = await claimTransfer({
    spark,
    signer,
    network,
    operators,
    threshold,
    transfer: inboundTransfer,
    ...(options.call === undefined ? {} : { call: options.call }),
  });

  // Validate against the fee WE requested — an SSP-declared fee that differs means the swap did
  // not execute on the terms we offered, even though the inbound leaves are already ours.
  if (swapResult.feeSats !== requestedFeeSats) {
    throw new SparkError(
      `swapLeaves: SSP declared a fee of ${swapResult.feeSats} sats but we requested ` +
        `${requestedFeeSats}; the swap leaves are already ours`,
    );
  }
  let claimedTotal = 0;
  for (const leaf of claimed) {
    claimedTotal += leaf.valueSats;
  }
  if (claimedTotal !== totalSats - requestedFeeSats) {
    throw new SparkError(
      `swapLeaves: claimed ${claimedTotal} sats but expected ${totalSats - requestedFeeSats} ` +
        `(inputs ${totalSats} minus fee ${requestedFeeSats}); the swap leaves are already ours`,
    );
  }
  let remaining = claimed;
  for (const target of options.targetAmountsSats) {
    const exact = selectExact(remaining, target);
    if (exact === undefined) {
      throw new SparkError(
        `swapLeaves: claimed leaves cannot cover target amount ${target} sats exactly; ` +
          "the swap leaves are already ours",
      );
    }
    const used = new Set(exact.map((leaf) => leaf.id));
    remaining = remaining.filter((leaf) => !used.has(leaf.id));
  }
  return claimed;
}
