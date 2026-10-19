import type { CallOptions, Client } from "@connectrpc/connect";
import { equalBytes } from "@noble/curves/utils.js";

import { sparkNetworkProto } from "../core/network.ts";
import type { SparkNetwork } from "../core/network.ts";
import { protoEnumName } from "../core/proto-enum.ts";
import { SparkError } from "../errors/index.ts";
import type { SparkService, Transfer } from "../proto/gen/spark_pb.ts";
import { TransferType } from "../proto/gen/spark_pb.ts";
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

/**
 * The transfer a committed outbound swap/exit left behind, looked up after a lost response. The
 * probe only diagnoses the original failure, so its own error maps to undefined — the caller
 * rethrows the original. Only a transfer of the expected type between the expected parties is a
 * usable recovery: anything else means ours never committed.
 */
export async function queryCommittedTransfer(options: {
  readonly spark: Client<typeof SparkService>;
  readonly network: SparkNetwork;
  readonly transferId: string;
  readonly type: TransferType;
  readonly senderIdentityPublicKey: Uint8Array;
  readonly receiverIdentityPublicKey: Uint8Array;
  readonly call?: CallOptions;
}): Promise<SparkTransfer | undefined> {
  let transfers: Transfer[];
  try {
    transfers = await queryTransfersByIds({
      spark: options.spark,
      transferIds: [options.transferId],
      network: options.network,
      ...(options.call === undefined ? {} : { call: options.call }),
    });
  } catch {
    return undefined;
  }
  const transfer = transfers.find(
    (candidate) =>
      candidate.type === options.type &&
      equalBytes(candidate.senderIdentityPublicKey, options.senderIdentityPublicKey) &&
      equalBytes(candidate.receiverIdentityPublicKey, options.receiverIdentityPublicKey),
  );
  return transfer === undefined ? undefined : mapTransfer(transfer);
}

/**
 * The committed transfer must be exactly the one we signed for — our leaves to the expected
 * receiver under the expected type. On a recovered response in particular, continuing with a
 * transfer to another receiver would commit our leaves to terms we never agreed to.
 */
export function assertCommittedTransfer(
  transfer: SparkTransfer,
  expected: {
    readonly type: TransferType;
    readonly senderIdentityPublicKey: Uint8Array;
    readonly receiverIdentityPublicKey: Uint8Array;
  },
  context: string,
): void {
  if (
    transfer.type !== protoEnumName(TransferType, expected.type) ||
    !equalBytes(transfer.senderIdentityPublicKey, expected.senderIdentityPublicKey) ||
    !equalBytes(transfer.receiverIdentityPublicKey, expected.receiverIdentityPublicKey)
  ) {
    throw new SparkError(`${context}: committed transfer is not ours to the expected receiver`);
  }
}
