import { equalBytes } from "@noble/curves/utils.js";

import { connectOperator, sparkEvents } from "../connection/index.ts";
import type { ConnectionDeps, OperatorConnection, SparkEvent } from "../connection/index.ts";
import { decodeSparkAddress, verifySparkAddressSignature } from "../core/address.ts";
import {
  buildKeySpendSweep,
  finalizeKeySpend,
  p2trScriptFromPublicKey,
  parseTransaction,
} from "../core/bitcoin/index.ts";
import { sparkNetworkConfig } from "../core/network.ts";
import type { SparkNetwork, SparkNetworkConfig, SparkOperatorConfig } from "../core/network.ts";
import { uuidv7 } from "../core/uuid.ts";
import {
  claimDeposit,
  generateDepositAddress,
  queryUnusedDepositAddresses,
} from "../deposit/index.ts";
import type { DepositCoordinator, UnusedDepositAddress } from "../deposit/index.ts";
import { SparkInputError } from "../errors/index.ts";
import { unilateralExitTransactions } from "../exit/unilateral.ts";
import type { ExitTransaction } from "../exit/unilateral.ts";
import type { SparkSigner } from "../signer/types.ts";
import { createSspClient } from "../ssp/index.ts";
import {
  claimTransfer,
  CLAIMABLE_TRANSFER_STATUSES,
  queryAllTransfers,
  queryPendingTransfers,
  selectLeavesExact,
  sendTransfer,
} from "../transfer/index.ts";
import type { SparkTransfer, TransferCoordinator } from "../transfer/index.ts";
import { leavesBalance, queryLeaves } from "../tree/index.ts";
import type { SparkLeaf } from "../tree/index.ts";
import { renewLeaf, renewalKind } from "../tree/renew.ts";

export type SparkClient = {
  /** The 33-byte compressed secp256k1 identity public key. */
  readonly identityPublicKey: () => Promise<Uint8Array>;
  /** Sum of the owner's `AVAILABLE` leaf values, in sats. */
  readonly balance: () => Promise<number>;
  /** The owner's `AVAILABLE` leaves from the coordinator's `query_nodes`. */
  readonly leaves: () => Promise<ReadonlyArray<SparkLeaf>>;
  readonly transfers: {
    /** Transfers awaiting this identity as receiver. */
    readonly pending: () => Promise<ReadonlyArray<SparkTransfer>>;
    /** All transfers where the identity is sender or receiver. */
    readonly list: (options?: {
      readonly limit?: number;
      readonly offset?: number;
    }) => Promise<ReadonlyArray<SparkTransfer>>;
    /**
     * Sends exactly `amountSats` to `receiver` (a `spark1…`/`sparkrt1…` address string or a 33-byte
     * identity public key) via `start_transfer_v2`. Selects AVAILABLE leaves summing exactly to the
     * amount — leaf swaps arrive with S8, so other amounts are rejected for now.
     */
    readonly send: (sendOptions: {
      readonly receiver: string | Uint8Array;
      readonly amountSats: number;
    }) => Promise<SparkTransfer>;
    /** Verifies and claims a pending transfer addressed to this identity; returns the new leaves. */
    readonly claim: (transfer: SparkTransfer) => Promise<ReadonlyArray<SparkLeaf>>;
    /** Claims every pending incoming transfer; returns all new leaves. */
    readonly claimPending: () => Promise<ReadonlyArray<SparkLeaf>>;
  };
  /** SSP leaves-swap fee quote in sats. */
  readonly swapFeeEstimate: (amountSats: number) => Promise<number>;
  readonly deposits: {
    /** Fresh single-use deposit address with a verified proof-of-possession. */
    readonly newAddress: () => Promise<string>;
    /** Deposit addresses the SO still considers unused. */
    readonly unused: () => Promise<ReadonlyArray<UnusedDepositAddress>>;
    /**
     * Claims an on-chain deposit paying to one of the unused addresses. When the transaction has
     * multiple matching outputs `vout` selects which one.
     */
    readonly claim: (options: {
      readonly transaction: Uint8Array;
      readonly vout?: number;
    }) => Promise<SparkLeaf>;
  };
  readonly withdrawals: {
    /** Pre-signed exit transactions for the given leaves, root first (see ExitTransaction). */
    readonly unilateralExit: (
      leafIds: ReadonlyArray<string>,
    ) => Promise<ReadonlyArray<ExitTransaction>>;
    /**
     * Signed key-path sweep of a confirmed refund output (any of the leaf's refund variants, output 0)
     * to `destinationScript`.
     */
    readonly sweepRefund: (options: {
      readonly leafId: string;
      readonly refundTx: Uint8Array;
      readonly destinationScript: Uint8Array;
      readonly feeRateSatPerVbyte: number;
    }) => Promise<Uint8Array>;
  };
  /** Coordinator `subscribe_to_events`; reconnects until `signal` aborts or `close()` runs. */
  readonly events: (signal?: AbortSignal) => AsyncIterable<SparkEvent>;
  /** Aborts all outstanding event streams (including caller-signaled ones). */
  readonly close: () => void;
};

export type SparkClientOptions = {
  readonly network: SparkNetwork;
  readonly signer: SparkSigner;
  readonly fetch: typeof globalThis.fetch;
  readonly random?: (length: number) => Uint8Array;
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly operators?: ReadonlyArray<SparkOperatorConfig>;
  readonly ssp?: SparkNetworkConfig["ssp"];
};

/** Internal seams for tests; not part of the public options surface. */
export type SparkClientSeams = {
  readonly transportFactory?: ConnectionDeps["transportFactory"];
};

export function createSparkClient(options: SparkClientOptions): SparkClient {
  return createSparkClientWith(options, {});
}

export function createSparkClientWith(
  options: SparkClientOptions,
  seams: SparkClientSeams,
): SparkClient {
  const config = sparkNetworkConfig(options.network);
  const operators = options.operators ?? config.operators;
  const ssp = options.ssp ?? config.ssp;
  const random =
    options.random ??
    ((length: number) => {
      const { crypto } = globalThis;
      if (crypto === undefined) {
        throw new SparkInputError("no randomness source: pass options.random");
      }
      return crypto.getRandomValues(new Uint8Array(length));
    });
  const abort = new AbortController();

  const deps: ConnectionDeps = {
    signer: options.signer,
    fetch: options.fetch,
    random,
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.sleep === undefined ? {} : { sleep: options.sleep }),
    ...(seams.transportFactory === undefined ? {} : { transportFactory: seams.transportFactory }),
  };

  const coordinator = operators.find((operator) => operator.identifier === config.coordinator);
  if (coordinator === undefined) {
    throw new SparkInputError(`coordinator ${config.coordinator} is not in the operator set`);
  }
  const coordinatorConnection: OperatorConnection = connectOperator(coordinator, deps);

  const depositCoordinator: DepositCoordinator = {
    spark: coordinatorConnection.spark,
    signer: options.signer,
    network: options.network,
    operators,
    coordinatorIdentifier: config.coordinator,
  };

  const transferCoordinator: TransferCoordinator = {
    spark: coordinatorConnection.spark,
    signer: options.signer,
    network: options.network,
    operators,
    threshold: config.threshold,
  };

  const sspClient = createSspClient({
    baseUrl: ssp.baseUrl,
    graphqlPath: ssp.graphqlPath,
    signer: options.signer,
    fetch: options.fetch,
    ...(options.now === undefined ? {} : { now: options.now }),
  });

  const leaves = async (): Promise<ReadonlyArray<SparkLeaf>> =>
    queryLeaves({
      spark: coordinatorConnection.spark,
      ownerIdentityPublicKey: await options.signer.identityPublicKey(),
      network: options.network,
    });

  /** Resolves a spark address string or raw identity public key to the receiver's identity key. */
  const receiverIdentityKey = (receiver: string | Uint8Array): Uint8Array => {
    if (typeof receiver !== "string") {
      if (receiver.length !== 33) {
        throw new SparkInputError("send: receiver identity public key must be 33 bytes");
      }
      return receiver;
    }
    const address = decodeSparkAddress(receiver);
    if (address.network !== options.network) {
      throw new SparkInputError(`send: receiver address is for ${address.network}`);
    }
    if (address.invoice !== undefined) {
      throw new SparkInputError("send: invoice-carrying addresses are not supported yet");
    }
    if (
      address.signature !== undefined &&
      address.signature.length > 0 &&
      !verifySparkAddressSignature(address)
    ) {
      throw new SparkInputError("send: receiver address signature is invalid");
    }
    return address.identityPublicKey;
  };

  /**
   * Events against the coordinator. The caller's signal and the client's close() are linked into a
   * per-stream AbortController via listeners (no AbortSignal.any — Hermes support is uncertain);
   * listeners are dropped when the stream ends.
   */
  const events = (callerSignal?: AbortSignal): AsyncIterable<SparkEvent> => {
    const controller = new AbortController();
    const stop = (): void => {
      controller.abort();
    };
    abort.signal.addEventListener("abort", stop, { once: true });
    callerSignal?.addEventListener("abort", stop, { once: true });
    // Abort listeners don't fire retroactively — a signal that is already aborted (or a client
    // closed before events() ran) must abort the stream controller directly.
    if (abort.signal.aborted || callerSignal?.aborted === true) {
      stop();
    }
    const inner = eventsWithKey(controller.signal)[Symbol.asyncIterator]();
    const cleanup = (): void => {
      abort.signal.removeEventListener("abort", stop);
      callerSignal?.removeEventListener("abort", stop);
    };
    return {
      [Symbol.asyncIterator]() {
        return {
          next: async (): Promise<IteratorResult<SparkEvent>> => {
            try {
              const item = await inner.next();
              if (item.done === true) {
                cleanup();
              }
              return item;
            } catch (error) {
              cleanup();
              throw error;
            }
          },
        };
      },
    };
  };

  async function* eventsWithKey(signal: AbortSignal): AsyncIterable<SparkEvent> {
    const key = await options.signer.identityPublicKey();
    yield* sparkEvents(coordinatorConnection, key, signal, {
      ...(options.sleep === undefined ? {} : { sleep: options.sleep }),
      random,
    });
  }

  return {
    identityPublicKey: async () => options.signer.identityPublicKey(),
    balance: async () => leavesBalance(await leaves()),
    leaves,
    transfers: {
      pending: async () =>
        queryPendingTransfers({
          spark: coordinatorConnection.spark,
          identityPublicKey: await options.signer.identityPublicKey(),
          network: options.network,
        }),
      list: async (listOptions) =>
        queryAllTransfers({
          spark: coordinatorConnection.spark,
          identityPublicKey: await options.signer.identityPublicKey(),
          network: options.network,
          ...(listOptions?.limit === undefined ? {} : { limit: listOptions.limit }),
          ...(listOptions?.offset === undefined ? {} : { offset: listOptions.offset }),
        }),
      send: async (sendOptions) => {
        const receiver = receiverIdentityKey(sendOptions.receiver);
        const selected = selectLeavesExact(await leaves(), sendOptions.amountSats);
        // Renew any leaf whose refund timelock is spent before handing it to the receiver.
        const sendLeaves: SparkLeaf[] = [];
        for (const leaf of selected) {
          if (renewalKind(leaf) === undefined) {
            sendLeaves.push(leaf);
            continue;
          }
          // oxlint-disable-next-line no-await-in-loop -- renewals must complete in order before send
          const renewed = await renewLeaf({
            spark: coordinatorConnection.spark,
            signer: options.signer,
            network: options.network,
            leaf,
          });
          sendLeaves.push(renewed);
        }
        return sendTransfer({
          ...transferCoordinator,
          transferId: uuidv7(random, options.now),
          leaves: sendLeaves,
          receiverIdentityPublicKey: receiver,
        });
      },
      claim: async (transfer) => claimTransfer({ ...transferCoordinator, transfer }),
      claimPending: async () => {
        const pending = await queryPendingTransfers({
          spark: coordinatorConnection.spark,
          identityPublicKey: await options.signer.identityPublicKey(),
          network: options.network,
        });
        const claimed: SparkLeaf[] = [];
        for (const transfer of pending) {
          if (!CLAIMABLE_TRANSFER_STATUSES.includes(transfer.status)) {
            continue;
          }
          // oxlint-disable-next-line no-await-in-loop -- claims run strictly in order; each consumes signer nonces
          claimed.push(...(await claimTransfer({ ...transferCoordinator, transfer })));
        }
        return claimed;
      },
    },
    swapFeeEstimate: async (amountSats) => sspClient.swapFeeEstimate(amountSats),
    deposits: {
      newAddress: async () =>
        generateDepositAddress({
          ...depositCoordinator,
          leafId: uuidv7(random, options.now),
        }),
      unused: async () => queryUnusedDepositAddresses(depositCoordinator),
      claim: async (claimOptions) =>
        claimDeposit({
          ...depositCoordinator,
          transaction: claimOptions.transaction,
          ...(claimOptions.vout === undefined ? {} : { vout: claimOptions.vout }),
        }),
    },
    withdrawals: {
      unilateralExit: async (leafIds) =>
        unilateralExitTransactions({
          spark: coordinatorConnection.spark,
          network: options.network,
          leafIds,
        }),
      sweepRefund: async ({ leafId, refundTx, destinationScript, feeRateSatPerVbyte }) => {
        const key = { type: "leaf" as const, leafId };
        const [publicKey] = await options.signer.publicKeys([key]);
        if (publicKey === undefined) {
          throw new SparkInputError(`sweepRefund: no public key for leaf ${leafId}`);
        }
        const output = parseTransaction(refundTx).getOutput(0);
        if (
          output.script === undefined ||
          !equalBytes(output.script, p2trScriptFromPublicKey(publicKey, options.network))
        ) {
          throw new SparkInputError(
            `sweepRefund: refund tx output 0 does not pay leaf ${leafId}'s key-path script`,
          );
        }
        const sweep = buildKeySpendSweep({
          prevTx: refundTx,
          vout: 0,
          destinationScript,
          feeRateSatPerVbyte,
        });
        const signature = await options.signer.signKeySpend(key, sweep.target);
        return finalizeKeySpend(sweep.transaction, signature);
      },
    },
    events,
    close() {
      abort.abort();
    },
  };
}
