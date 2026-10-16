import { connectOperator, sparkEvents } from "../connection/index.ts";
import type { ConnectionDeps, OperatorConnection, SparkEvent } from "../connection/index.ts";
import { sparkNetworkConfig } from "../core/network.ts";
import type { SparkNetwork, SparkNetworkConfig, SparkOperatorConfig } from "../core/network.ts";
import { SparkInputError } from "../errors/index.ts";
import type { SparkSigner } from "../signer/types.ts";
import { createSspClient } from "../ssp/index.ts";
import { queryAllTransfers, queryPendingTransfers } from "../transfer/index.ts";
import type { SparkTransfer } from "../transfer/index.ts";
import { leavesBalance, queryLeaves } from "../tree/index.ts";
import type { SparkLeaf } from "../tree/index.ts";

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
  };
  /** SSP leaves-swap fee quote in sats. */
  readonly swapFeeEstimate: (amountSats: number) => Promise<number>;
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
    },
    swapFeeEstimate: async (amountSats) => sspClient.swapFeeEstimate(amountSats),
    events,
    close() {
      abort.abort();
    },
  };
}
