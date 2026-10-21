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

/**
 * Terminal statuses a transfer can never come back from: RETURNED means the send refunded to the
 * sender, EXPIRED means it timed out unclaimed. A probe that finds one must surface it — the id is
 * burned, and matching it as committed would report a failed payment as successful.
 */
const TERMINAL_TRANSFER_STATUSES: ReadonlySet<string> = new Set(["RETURNED", "EXPIRED"]);

/** The SO caps `query_pending_transfers` pages at 100 (upstream maxTransferPageSize). */
const PENDING_PAGE_SIZE = 100;
const PENDING_MAX_PAGES = 1000;

/**
 * The result of {@link queryPendingTransfers}: the rows that mapped cleanly plus, isolated per row,
 * the ones the coordinator returned but {@link mapTransfer} rejected. A malformed row must never
 * throw over the whole page — that would let one poisoned transfer starve every valid transfer
 * behind it.
 */
export type PendingTransfersQuery = {
  readonly transfers: SparkTransfer[];
  /** One entry per unmappable row, keyed by the row's raw transfer id. */
  readonly unmappable: ReadonlyArray<{ readonly transferId: string; readonly error: unknown }>;
};

/**
 * `query_pending_transfers` — transfers awaiting this identity as receiver. Pages the whole set:
 * the SO caps a page at 100 and reports `-1` on the last page, so a full page must carry a strictly
 * advancing offset; the walk is bounded like `queryOwnerNodes`. Each row maps on its own.
 */
export async function queryPendingTransfers(options: {
  readonly spark: Client<typeof SparkService>;
  readonly identityPublicKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly call?: CallOptions;
}): Promise<PendingTransfersQuery> {
  const transfers: SparkTransfer[] = [];
  const unmappable: Array<{ transferId: string; error: unknown }> = [];
  let offset = 0;
  for (let pageIndex = 0; pageIndex < PENDING_MAX_PAGES; pageIndex++) {
    // oxlint-disable-next-line no-await-in-loop -- pages are sequential by definition
    const response = await options.spark.query_pending_transfers(
      {
        participant: {
          case: "receiverIdentityPublicKey",
          value: options.identityPublicKey,
        },
        network: sparkNetworkProto(options.network),
        limit: BigInt(PENDING_PAGE_SIZE),
        offset: BigInt(offset),
      },
      options.call,
    );
    for (const row of response.transfers) {
      try {
        transfers.push(mapTransfer(row));
      } catch (error) {
        unmappable.push({ transferId: row.id, error });
      }
    }
    // The SO reports the end explicitly: offset is -1 unless the page was full, so a short page
    // is not the stop condition — if the SO's cap ever dropped below PENDING_PAGE_SIZE a length
    // test would silently drop pending transfers.
    const nextOffset = Number(response.offset);
    if (nextOffset < 0) {
      return { transfers, unmappable };
    }
    if (!Number.isSafeInteger(nextOffset) || nextOffset <= offset) {
      throw new SparkError("query pending transfers: coordinator returned a non-advancing offset");
    }
    offset = nextOffset;
  }
  throw new SparkError("query pending transfers: coordinator did not stop returning full pages");
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

/** The terms a recovered or probed transfer must carry to be the one we signed for. */
export type CommittedTransferExpectation = {
  /**
   * The id this call committed the transfer under — an echoed transfer under another id is not
   * ours.
   */
  readonly transferId: string;
  readonly type: TransferType;
  readonly senderIdentityPublicKey: Uint8Array;
  /** Every receiver identity key this transfer must pay, as a set. */
  readonly receiverIdentityPublicKeys: ReadonlyArray<Uint8Array>;
  /**
   * Sends only: the requested amount per receiver identity key. On multi-receiver transfers each
   * edge's `amountSats` must equal its requested amount (a single edge may leave it unset — the
   * total binds it); `totalValueSats` must equal their sum either way.
   */
  readonly receiverAmountsSats?: ReadonlyArray<{
    readonly receiverIdentityPublicKey: Uint8Array;
    readonly amountSats: number;
  }>;
};

/**
 * Whether `transfer` is exactly the one we signed for: our id, same type, our sender key, and the
 * expected receiver set. A populated `receivers` list must carry exactly the expected identity keys
 * (and, when `receiverAmountsSats` is given, exactly the requested per-receiver amounts); an empty
 * `receivers` list can only satisfy a single expected receiver via `receiverIdentityPublicKey`. A
 * terminal (RETURNED/EXPIRED) transfer can never be the committed one.
 */
function matchesCommittedTransfer(
  transfer: SparkTransfer,
  expected: CommittedTransferExpectation,
): boolean {
  if (
    transfer.id !== expected.transferId ||
    TERMINAL_TRANSFER_STATUSES.has(transfer.status) ||
    transfer.type !== protoEnumName(TransferType, expected.type) ||
    !equalBytes(transfer.senderIdentityPublicKey, expected.senderIdentityPublicKey)
  ) {
    return false;
  }
  if (transfer.receivers.length === 0) {
    const [only] = expected.receiverIdentityPublicKeys;
    if (
      expected.receiverIdentityPublicKeys.length !== 1 ||
      only === undefined ||
      !equalBytes(transfer.receiverIdentityPublicKey, only)
    ) {
      return false;
    }
  } else {
    // Set equality: no duplicate edges, and every expected receiver key appears exactly once.
    if (transfer.receivers.length !== expected.receiverIdentityPublicKeys.length) {
      return false;
    }
    const seen: Uint8Array[] = [];
    for (const receiver of transfer.receivers) {
      if (seen.some((key) => equalBytes(key, receiver.identityPublicKey))) {
        return false;
      }
      if (
        !expected.receiverIdentityPublicKeys.some((key) =>
          equalBytes(key, receiver.identityPublicKey),
        )
      ) {
        return false;
      }
      seen.push(receiver.identityPublicKey);
      // A single-receiver edge may leave amountSats unset (0); its terms are bound by
      // totalValueSats below. Per-edge amounts are only meaningful on multi-receiver transfers.
      if (transfer.receivers.length > 1) {
        const amount = expected.receiverAmountsSats?.find((entry) =>
          equalBytes(entry.receiverIdentityPublicKey, receiver.identityPublicKey),
        );
        if (amount !== undefined && receiver.amountSats !== amount.amountSats) {
          return false;
        }
      }
    }
  }
  if (expected.receiverAmountsSats !== undefined) {
    let total = 0;
    for (const entry of expected.receiverAmountsSats) {
      total += entry.amountSats;
    }
    if (transfer.totalValueSats !== total) {
      return false;
    }
  }
  return true;
}

/**
 * The transfer a committed outbound swap/exit/send left behind, looked up after a lost response.
 * The probe only diagnoses the original failure, so its own error maps to undefined — the caller
 * rethrows the original. Only a transfer matching the expectation is a usable recovery: anything
 * else means ours never committed.
 */
export async function queryCommittedTransfer(
  options: {
    readonly spark: Client<typeof SparkService>;
    readonly network: SparkNetwork;
    readonly transferId: string;
    readonly call?: CallOptions;
  } & CommittedTransferExpectation,
): Promise<SparkTransfer | undefined> {
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
  const transfer = transfers
    .filter((candidate) => candidate.id === options.transferId)
    .map(mapTransfer)
    .find((mapped) => matchesCommittedTransfer(mapped, options));
  return transfer;
}

/**
 * A transfer carrying `transferId`, whatever its terms — for the probe-before-send path, where a
 * present-but-mismatched transfer is a distinct outcome (the caller supplied a reused id) rather
 * than the "not committed" one. Query errors map to undefined: a failed probe is not proof of
 * absence, it just means the normal send path runs.
 */
export async function queryTransferById(options: {
  readonly spark: Client<typeof SparkService>;
  readonly network: SparkNetwork;
  readonly transferId: string;
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
  const transfer = transfers.find((candidate) => candidate.id === options.transferId);
  return transfer === undefined ? undefined : mapTransfer(transfer);
}

/**
 * A probed transfer in a terminal state is a distinct failure from a mismatch: the id can never
 * commit under any terms, so the only remedy is a fresh one. Call before
 * {@link assertCommittedTransfer} on probe-first paths.
 */
export function assertLiveTransfer(transfer: SparkTransfer): void {
  if (TERMINAL_TRANSFER_STATUSES.has(transfer.status)) {
    throw new SparkError(
      `transfer ${transfer.id} was ${transfer.status}; retry with a new transferId`,
    );
  }
}

/**
 * The committed transfer must be exactly the one we signed for — our leaves to the expected
 * receivers under the expected type, in a committed status. On a recovered response in particular,
 * continuing with a transfer to other receivers would commit our leaves to terms we never agreed
 * to.
 */
export function assertCommittedTransfer(
  transfer: SparkTransfer,
  expected: CommittedTransferExpectation,
  context: string,
): void {
  if (!matchesCommittedTransfer(transfer, expected)) {
    throw new SparkError(`${context}: committed transfer is not ours to the expected receivers`);
  }
}
