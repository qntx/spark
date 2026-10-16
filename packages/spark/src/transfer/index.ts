import { timestampDate } from "@bufbuild/protobuf/wkt";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import type { CallOptions, Client } from "@connectrpc/connect";

import { sparkNetworkFromProto, sparkNetworkProto } from "../core/network.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SparkInputError } from "../errors/index.ts";
import { TransferStatus, TransferType } from "../proto/gen/spark_pb.ts";
import type { SparkService, Transfer, TransferLeaf } from "../proto/gen/spark_pb.ts";
import { mapTreeNode } from "../tree/index.ts";
import type { SparkLeaf } from "../tree/index.ts";

export type SparkTransferLeaf = {
  readonly leaf: SparkLeaf;
};

export type SparkTransfer = {
  readonly id: string;
  readonly senderIdentityPublicKey: Uint8Array;
  readonly receiverIdentityPublicKey: Uint8Array;
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

function enumName(table: Record<string, number>, value: number): string {
  for (const [name, v] of Object.entries(table)) {
    if (v === value) {
      return name;
    }
  }
  return String(value);
}

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
  return { leaf: mapTreeNode(leaf.leaf) };
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
    status: enumName(TransferStatus, transfer.status),
    type: enumName(TransferType, transfer.type),
    network: sparkNetworkFromProto(transfer.network),
    totalValueSats: checkedValue(transfer.totalValue),
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

function checkedValue(value: bigint): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new SparkInputError("transfer total value out of range");
  }
  return Number(value);
}

/** `query_pending_transfers` — transfers awaiting this identity as receiver. */
export async function queryPendingTransfers(options: {
  readonly spark: Client<typeof SparkService>;
  readonly identityPublicKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly call?: CallOptions;
}): Promise<SparkTransfer[]> {
  const response = await options.spark.query_pending_transfers(
    {
      participant: {
        case: "receiverIdentityPublicKey",
        value: options.identityPublicKey,
      },
      network: sparkNetworkProto(options.network),
    },
    options.call,
  );
  return response.transfers.map(mapTransfer);
}

/** `query_all_transfers` — transfers where the identity is sender or receiver. */
export async function queryAllTransfers(options: {
  readonly spark: Client<typeof SparkService>;
  readonly identityPublicKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly limit?: number;
  readonly offset?: number;
  readonly call?: CallOptions;
}): Promise<SparkTransfer[]> {
  const response = await options.spark.query_all_transfers(
    {
      participant: {
        case: "senderOrReceiverIdentityPublicKey",
        value: options.identityPublicKey,
      },
      network: sparkNetworkProto(options.network),
      limit: BigInt(options.limit ?? 100),
      offset: BigInt(options.offset ?? 0),
    },
    options.call,
  );
  return response.transfers.map(mapTransfer);
}
