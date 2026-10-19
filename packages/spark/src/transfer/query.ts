import type { CallOptions, Client } from "@connectrpc/connect";

import { sparkNetworkProto } from "../core/network.ts";
import type { SparkNetwork } from "../core/network.ts";
import type { SparkService, Transfer } from "../proto/gen/spark_pb.ts";
import { mapTransfer } from "./model.ts";
import type { SparkTransfer } from "./model.ts";

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

/** `query_transfers_by_id` — the raw transfers for the given ids (order may differ). */
export async function queryTransfersByIds(options: {
  readonly spark: Client<typeof SparkService>;
  readonly transferIds: ReadonlyArray<string>;
  readonly network: SparkNetwork;
  readonly call?: CallOptions;
}): Promise<Transfer[]> {
  const response = await options.spark.query_transfers_by_id(
    { transferIds: [...options.transferIds], network: sparkNetworkProto(options.network) },
    options.call,
  );
  return response.transfers;
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
