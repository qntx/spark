import { timestampDate } from "@bufbuild/protobuf/wkt";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import type { Client } from "@connectrpc/connect";

import { u64ToSats } from "../core/assert.ts";
import { sparkNetworkFromProto } from "../core/network.ts";
import type { SparkNetwork, SparkOperatorConfig } from "../core/network.ts";
import { protoEnumName } from "../core/proto-enum.ts";
import type { Signature } from "../proto/gen/common_pb.ts";
import { TransferReceiverStatus, TransferStatus, TransferType } from "../proto/gen/spark_pb.ts";
import type { SparkService, Transfer, TransferLeaf } from "../proto/gen/spark_pb.ts";
import type { SparkSigner } from "../signer/types.ts";
import { mapTreeNode } from "../tree/index.ts";
import type { SparkLeaf } from "../tree/index.ts";

export type SparkTransferLeaf = {
  readonly leaf: SparkLeaf;
  /** ECIES(receiver identity) ciphertext sealing the leaf key the sender generated. */
  readonly secretCipher: Uint8Array;
  /** Sender's per-leaf authorization: legacy bare signature or scheme-tagged `common.Signature`. */
  readonly sig:
    | { readonly case: "signature"; readonly value: Uint8Array }
    | { readonly case: "typedSignature"; readonly value: Signature }
    | undefined;
  /** Receiver-edge id that owns this leaf on multi-receiver transfers ("" when unset). */
  readonly transferReceiverId: string;
  /** Receiver-side refund txs captured at send time; they are the leaf's current refund state. */
  readonly intermediateRefundTx: Uint8Array;
  readonly intermediateDirectRefundTx: Uint8Array;
  readonly intermediateDirectFromCpfpRefundTx: Uint8Array;
};

export type SparkTransferReceiver = {
  readonly id: string;
  readonly identityPublicKey: Uint8Array;
  /** Sats this receiver edge carries (0 on single-receiver transfers that leave it unset). */
  readonly amountSats: number;
  readonly status: string;
};

export type SparkTransfer = {
  readonly id: string;
  readonly senderIdentityPublicKey: Uint8Array;
  readonly receiverIdentityPublicKey: Uint8Array;
  readonly receivers: ReadonlyArray<SparkTransferReceiver>;
  readonly status: string;
  readonly type: string;
  readonly network: SparkNetwork;
  readonly totalValueSats: number;
  readonly expiryTimeMs?: number;
  readonly createdTimeMs?: number;
  readonly updatedTimeMs?: number;
  readonly sparkInvoice?: string;
  readonly leaves: ReadonlyArray<SparkTransferLeaf>;
};

/**
 * Whole-transfer statuses a receiver can claim on (mirrors upstream
 * `partitionClaimablePendingTransfers`).
 */
export const CLAIMABLE_TRANSFER_STATUSES: ReadonlyArray<string> = [
  "SENDER_KEY_TWEAKED",
  "RECEIVER_KEY_TWEAK_LOCKED",
  "RECEIVER_KEY_TWEAK_APPLIED",
  "RECEIVER_KEY_TWEAKED",
  "RECEIVER_REFUND_SIGNED",
];

function millis(timestamp: Timestamp | undefined): number | undefined {
  if (timestamp === undefined) {
    return undefined;
  }
  return timestampDate(timestamp).getTime();
}

function mapTransferLeaf(leaf: TransferLeaf): SparkTransferLeaf | undefined {
  if (leaf.leaf === undefined) {
    return undefined;
  }
  return {
    leaf: mapTreeNode(leaf.leaf),
    secretCipher: leaf.secretCipher,
    sig:
      leaf.sig.case === "signature"
        ? { case: "signature", value: leaf.sig.value }
        : leaf.sig.case === "typedSignature"
          ? { case: "typedSignature", value: leaf.sig.value }
          : undefined,
    transferReceiverId: leaf.transferReceiverId,
    intermediateRefundTx: leaf.intermediateRefundTx,
    intermediateDirectRefundTx: leaf.intermediateDirectRefundTx,
    intermediateDirectFromCpfpRefundTx: leaf.intermediateDirectFromCpfpRefundTx,
  };
}

export function mapTransfer(transfer: Transfer): SparkTransfer {
  const leaves: SparkTransferLeaf[] = [];
  for (const leaf of transfer.leaves) {
    const mapped = mapTransferLeaf(leaf);
    if (mapped !== undefined) {
      leaves.push(mapped);
    }
  }
  const out: SparkTransfer = {
    id: transfer.id,
    senderIdentityPublicKey: transfer.senderIdentityPublicKey,
    receiverIdentityPublicKey: transfer.receiverIdentityPublicKey,
    receivers: transfer.receivers.map((receiver) => ({
      id: receiver.id,
      identityPublicKey: receiver.identityPublicKey,
      amountSats: u64ToSats(receiver.amountSats, "transfer receiver amount"),
      status: protoEnumName(TransferReceiverStatus, receiver.status),
    })),
    status: protoEnumName(TransferStatus, transfer.status),
    type: protoEnumName(TransferType, transfer.type),
    network: sparkNetworkFromProto(transfer.network),
    totalValueSats: u64ToSats(transfer.totalValue, "transfer total value"),
    leaves,
  };
  const expiry = millis(transfer.expiryTime);
  const created = millis(transfer.createdTime);
  const updated = millis(transfer.updatedTime);
  return {
    ...out,
    ...(expiry === undefined ? {} : { expiryTimeMs: expiry }),
    ...(created === undefined ? {} : { createdTimeMs: created }),
    ...(updated === undefined ? {} : { updatedTimeMs: updated }),
    ...(transfer.sparkInvoice === "" ? {} : { sparkInvoice: transfer.sparkInvoice }),
  };
}

/** Coordinator context shared by the transfer RPCs (the coordinator fans out to the other SOs). */
export type TransferCoordinator = {
  readonly spark: Client<typeof SparkService>;
  readonly signer: SparkSigner;
  readonly network: SparkNetwork;
  /** Every signing operator, coordinator included. */
  readonly operators: ReadonlyArray<SparkOperatorConfig>;
  readonly threshold: number;
};
