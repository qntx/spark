import { create, toBinary } from "@bufbuild/protobuf";
import type { CallOptions } from "@connectrpc/connect";

import { createDecrementedTimelockRefundTxs } from "../core/bitcoin/index.ts";
import type { RefundTxTrio } from "../core/bitcoin/index.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import { HashVariant, TransferPackageSchema } from "../proto/gen/spark_pb.ts";
import type { TransferPackage } from "../proto/gen/spark_pb.ts";
import type { SparkLeaf } from "../tree/index.ts";
import { mapTransfer } from "./model.ts";
import type { SparkTransfer, TransferCoordinator } from "./model.ts";
import { refundJobGroups, signRefundJobs } from "./refunds.ts";
import type { RefundJobLeaf } from "./refunds.ts";

/**
 * The signed `TransferPackage` for a send-style transfer: every leaf gets a fresh recipient key
 * inside the signer (`prepareTransfer`), the refund transactions per leaf are built by
 * `buildRefunds` and signed in one `signFrost` batch, and the package carries the identity-key
 * signature over the V2 signing payload. Sends and swaps use decremented-timelock refunds;
 * Lightning sends inject HTLC refunds instead.
 */
export async function prepareTransferPackage(
  options: TransferCoordinator & {
    readonly transferId: string;
    readonly leaves: ReadonlyArray<SparkLeaf>;
    readonly receiverIdentityPublicKey: Uint8Array;
    readonly buildRefunds: (
      entry: RefundJobLeaf,
      sequence: number,
    ) => {
      refunds: RefundTxTrio;
      extraPrevout?: { readonly script: Uint8Array; readonly amount: number };
    };
    readonly call?: CallOptions;
  },
): Promise<TransferPackage> {
  const { spark, signer, operators, threshold } = options;
  if (options.leaves.length === 0) {
    throw new SparkInputError("prepareTransferPackage: leaves must not be empty");
  }

  const prepared = await signer.prepareTransfer({
    transferId: options.transferId,
    receiverIdentityPublicKey: options.receiverIdentityPublicKey,
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
        throw new SparkError(
          "prepareTransferPackage: signer returned fewer public keys than requested",
        );
      }
      return { leaf, refundTx: leaf.refundTx, signingPublicKey };
    }),
    options.buildRefunds,
    signingCommitments.signingCommitments,
    "prepareTransferPackage",
  );

  const jobs = await signRefundJobs(signer, groups);

  const transferPackage = create(TransferPackageSchema, {
    leavesToSend: jobs.cpfp,
    keyTweakPackage: prepared.operatorPackages,
    userSignature: new Uint8Array(),
    directLeavesToSend: jobs.direct,
    directFromCpfpLeavesToSend: jobs.directFromCpfp,
    hashVariant: HashVariant.V2,
  });
  transferPackage.userSignature = await signer.signIdentity({
    kind: "transfer-package",
    transferId: options.transferId,
    package: toBinary(TransferPackageSchema, transferPackage),
  });
  return transferPackage;
}

/**
 * `start_transfer_v2` — single-receiver send. Refund transactions are rebuilt one timelock interval
 * below each leaf's current refund sequence.
 */
export async function sendTransfer(
  options: TransferCoordinator & {
    readonly transferId: string;
    readonly leaves: ReadonlyArray<SparkLeaf>;
    readonly receiverIdentityPublicKey: Uint8Array;
    /** The invoice address string this transfer pays, forwarded to `start_transfer_v2`. */
    readonly sparkInvoice?: string;
    readonly call?: CallOptions;
  },
): Promise<SparkTransfer> {
  const { spark, signer, network } = options;

  const transferPackage = await prepareTransferPackage({
    ...options,
    buildRefunds: (entry, sequence) => ({
      refunds: createDecrementedTimelockRefundTxs({
        nodeTx: entry.leaf.nodeTx,
        directNodeTx: entry.leaf.directTx,
        sequence,
        receivingPublicKey: options.receiverIdentityPublicKey,
        network,
      }),
    }),
  });

  const response = await spark.start_transfer_v2(
    {
      transferId: options.transferId,
      ownerIdentityPublicKey: await signer.identityPublicKey(),
      receiverIdentityPublicKey: options.receiverIdentityPublicKey,
      transferPackage,
      sparkInvoice: options.sparkInvoice ?? "",
    },
    options.call,
  );
  if (response.transfer === undefined) {
    throw new SparkError("sendTransfer: coordinator returned no transfer");
  }
  return mapTransfer(response.transfer);
}
