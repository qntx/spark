import { create, toBinary } from "@bufbuild/protobuf";
import type { CallOptions } from "@connectrpc/connect";
import { equalBytes } from "@noble/curves/utils.js";

import { createDecrementedTimelockRefundTxs } from "../core/bitcoin/index.ts";
import type { RefundTxTrio } from "../core/bitcoin/index.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import {
  HashVariant,
  SenderTransferPackageSchema,
  TransferPackageSchema,
} from "../proto/gen/spark_pb.ts";
import type { TransferPackage } from "../proto/gen/spark_pb.ts";
import type { SparkLeaf } from "../tree/index.ts";
import { mapTransfer } from "./model.ts";
import type { SparkTransfer, TransferCoordinator } from "./model.ts";
import { refundJobGroups, signRefundJobs } from "./refunds.ts";
import type { RefundJobLeaf } from "./refunds.ts";

/** One leaf of a send-style package: the leaf and the receiver its secret cipher seals to. */
export type SendLeafInput = {
  readonly leaf: SparkLeaf;
  /** 33-byte compressed identity public key this leaf's secret cipher is sealed to. */
  readonly receiverIdentityPublicKey: Uint8Array;
};

/**
 * The signed `TransferPackage` for a send-style transfer: every leaf gets a fresh recipient key
 * inside the signer (`prepareTransfer`), sealed to that leaf's own receiver; the refund
 * transactions per leaf are built by `buildRefunds` and signed in one `signFrost` batch, and the
 * package carries the identity-key signature over the V2 signing payload. Sends and swaps use
 * decremented-timelock refunds; Lightning sends inject HTLC refunds instead.
 */
export async function prepareTransferPackage(
  options: TransferCoordinator & {
    readonly transferId: string;
    readonly leaves: ReadonlyArray<SendLeafInput>;
    readonly buildRefunds: (
      entry: SendLeafInput & RefundJobLeaf,
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
    leaves: options.leaves.map((leaf) => ({
      leafId: leaf.leaf.id,
      key: { type: "leaf", leafId: leaf.leaf.id },
      receiverIdentityPublicKey: leaf.receiverIdentityPublicKey,
    })),
    operators,
    threshold,
  });

  const signingCommitments = await spark.get_signing_commitments(
    {
      nodeIds: options.leaves.map((leaf) => leaf.leaf.id),
      count: 3,
    },
    options.call,
  );

  const signingPublicKeys = await signer.publicKeys(
    options.leaves.map((leaf) => ({ type: "leaf", leafId: leaf.leaf.id })),
  );

  const groups = refundJobGroups(
    options.leaves.map((leaf, i) => {
      const signingPublicKey = signingPublicKeys[i];
      if (signingPublicKey === undefined) {
        throw new SparkError(
          "prepareTransferPackage: signer returned fewer public keys than requested",
        );
      }
      return {
        leaf: leaf.leaf,
        refundTx: leaf.leaf.refundTx,
        signingPublicKey,
        receiverIdentityPublicKey: leaf.receiverIdentityPublicKey,
      };
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

/** One receiver's share of a send: the receiver's identity key and the leaves paying it. */
export type SendAllocation = {
  readonly receiverIdentityPublicKey: Uint8Array;
  readonly leaves: ReadonlyArray<SparkLeaf>;
};

/**
 * `start_transfer_v2`/`start_transfer_v3` — a send of `allocations`. Refund transactions are
 * rebuilt one timelock interval below each leaf's current refund sequence, paying each leaf's own
 * receiver. Exactly one allocation goes through V2 (which may carry a Spark invoice); several
 * receivers require V3, where the sender package maps every leaf id to its receiver key.
 */
export async function sendTransfer(
  options: TransferCoordinator & {
    readonly transferId: string;
    readonly allocations: ReadonlyArray<SendAllocation>;
    /** The invoice address string this transfer pays — single-allocation (V2) sends only. */
    readonly sparkInvoice?: string;
    readonly call?: CallOptions;
  },
): Promise<SparkTransfer> {
  const { spark, signer, network } = options;
  if (options.allocations.length === 0) {
    throw new SparkInputError("sendTransfer: allocations must not be empty");
  }
  if (options.allocations.length > 1 && options.sparkInvoice !== undefined) {
    throw new SparkInputError("sendTransfer: a multi-receiver transfer cannot carry an invoice");
  }
  const receiverKeys: Uint8Array[] = [];
  const leafIds = new Set<string>();
  const leaves: SendLeafInput[] = [];
  for (const allocation of options.allocations) {
    if (allocation.leaves.length === 0) {
      throw new SparkInputError("sendTransfer: allocation leaves must not be empty");
    }
    if (receiverKeys.some((key) => equalBytes(key, allocation.receiverIdentityPublicKey))) {
      throw new SparkInputError("sendTransfer: duplicate receiver identity public key");
    }
    receiverKeys.push(allocation.receiverIdentityPublicKey);
    for (const leaf of allocation.leaves) {
      if (leafIds.has(leaf.id)) {
        throw new SparkInputError(`sendTransfer: leaf ${leaf.id} appears twice`);
      }
      leafIds.add(leaf.id);
      leaves.push({
        leaf,
        receiverIdentityPublicKey: allocation.receiverIdentityPublicKey,
      });
    }
  }

  const transferPackage = await prepareTransferPackage({
    ...options,
    leaves,
    buildRefunds: (entry, sequence) => ({
      refunds: createDecrementedTimelockRefundTxs({
        nodeTx: entry.leaf.nodeTx,
        directNodeTx: entry.leaf.directTx,
        sequence,
        receivingPublicKey: entry.receiverIdentityPublicKey,
        network,
      }),
    }),
  });

  const ownerIdentityPublicKey = await signer.identityPublicKey();
  const [first] = options.allocations;
  const response =
    options.allocations.length === 1 && first !== undefined
      ? await spark.start_transfer_v2(
          {
            transferId: options.transferId,
            ownerIdentityPublicKey,
            receiverIdentityPublicKey: first.receiverIdentityPublicKey,
            transferPackage,
            sparkInvoice: options.sparkInvoice ?? "",
          },
          options.call,
        )
      : await spark.start_transfer_v3(
          {
            transferId: options.transferId,
            senderPackages: [
              create(SenderTransferPackageSchema, {
                ownerIdentityPublicKey,
                transferPackage,
                receiverIdentityPublicKeys: Object.fromEntries(
                  leaves.map((leaf) => [leaf.leaf.id, leaf.receiverIdentityPublicKey]),
                ),
              }),
            ],
          },
          options.call,
        );
  if (response.transfer === undefined) {
    throw new SparkError("sendTransfer: coordinator returned no transfer");
  }
  return mapTransfer(response.transfer);
}
