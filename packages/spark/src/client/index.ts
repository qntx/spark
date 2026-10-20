import { connectOperator, sparkEvents } from "../connection/index.ts";
import type { ConnectionDeps, OperatorConnection, SparkEvent } from "../connection/index.ts";
import { sparkNetworkConfig } from "../core/network.ts";
import type { SparkNetwork, SparkNetworkConfig, SparkOperatorConfig } from "../core/network.ts";
import type { UnusedDepositAddress } from "../deposit/index.ts";
import type { StaticDepositRefund, StaticDepositUtxo } from "../deposit/static.ts";
import { SparkInputError } from "../errors/index.ts";
import type {
  CooperativeExitQuote,
  CooperativeExitResult,
  CooperativeExitSpeed,
  CooperativeExitStatus,
} from "../exit/coop.ts";
import { createMemorySparkStore } from "../exit/store.ts";
import type { SparkStore } from "../exit/store.ts";
import type { ExitTransaction } from "../exit/unilateral.ts";
import type {
  LightningInvoice,
  LightningPayment,
  LightningReceiveStatus,
  LightningSendStatus,
  LightningSendStatusRequest,
} from "../lightning/index.ts";
import type { SparkSigner } from "../signer/types.ts";
import { createSspClient } from "../ssp/index.ts";
import type { SparkTokenBalance, SparkTokenOutput } from "../tokens/index.ts";
import type { SparkTransfer } from "../transfer/index.ts";
import { leavesBalance } from "../tree/index.ts";
import type { SparkLeaf } from "../tree/index.ts";
import { createClientContext } from "./context.ts";
import { createDeposits } from "./deposits.ts";
import type { StaticDepositClaimResult } from "./deposits.ts";
import { createInvoices } from "./invoices.ts";
import { createLightning } from "./lightning.ts";
import { createTokens } from "./tokens.ts";
import { createTransfers } from "./transfers.ts";
import { createWithdrawals } from "./withdrawals.ts";

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
     * identity public key) via `start_transfer_v2` — selecting exact leaves, or swapping with the
     * SSP first when no exact combination exists. Pass the same `transferId` to retry a call whose
     * response was lost.
     */
    readonly send: (sendOptions: {
      readonly receiver: string | Uint8Array;
      readonly amountSats: number;
      readonly transferId?: string;
    }) => Promise<SparkTransfer>;
    /**
     * Sends to several receivers in one `start_transfer_v3` — one exact leaf group per entry, or a
     * single SSP swap minting every amount. `receiver` accepts the same shapes as `send` (invoice
     * addresses are rejected); duplicate receivers are rejected. `transferId` has the same retry
     * semantics as `send`.
     */
    readonly sendMany: (sendOptions: {
      readonly receivers: ReadonlyArray<{
        readonly receiver: string | Uint8Array;
        readonly amountSats: number;
      }>;
      readonly transferId?: string;
    }) => Promise<SparkTransfer>;
    /** Verifies and claims a pending transfer addressed to this identity; returns the new leaves. */
    readonly claim: (transfer: SparkTransfer) => Promise<ReadonlyArray<SparkLeaf>>;
    /** Claims every pending incoming transfer; returns all new leaves. */
    readonly claimPending: () => Promise<ReadonlyArray<SparkLeaf>>;
  };
  readonly tokens: {
    /** Token outputs owned by this identity, optionally narrowed to one bech32m identifier. */
    readonly outputs: (options?: {
      readonly tokenIdentifier?: string;
    }) => Promise<ReadonlyArray<SparkTokenOutput>>;
    /** Per-identifier aggregate balances. */
    readonly balances: () => Promise<ReadonlyArray<SparkTokenBalance>>;
    /**
     * Sends exactly `amount` of the bech32m token to `receiver` (a spark address string or a
     * 33-byte identity public key) via `broadcast_transaction`; returns the hex final transaction
     * hash. Change returns to the sender.
     */
    readonly transfer: (transferOptions: {
      readonly tokenIdentifier: string;
      readonly amount: bigint;
      readonly receiver: string | Uint8Array;
    }) => Promise<string>;
  };
  readonly invoices: {
    /**
     * Creates a signed sats invoice address for this identity. `amountSats` omitted means the payer
     * picks the amount.
     */
    readonly createSats: (options?: {
      readonly amountSats?: number;
      readonly memo?: string;
      readonly senderPublicKey?: Uint8Array;
      readonly expiresAtMs?: number;
    }) => Promise<string>;
    /**
     * Creates a signed token invoice address for this identity. `tokenIdentifier` is the bech32m
     * identifier; omit it (with `amount`) for any-token invoices.
     */
    readonly createTokens: (options?: {
      readonly tokenIdentifier?: string;
      readonly amount?: bigint;
      readonly memo?: string;
      readonly senderPublicKey?: Uint8Array;
      readonly expiresAtMs?: number;
    }) => Promise<string>;
    /**
     * Pays a Spark invoice address. `amount` is required for open invoices and must equal a fixed
     * invoice amount when set. Resolves to the `SparkTransfer` for sats invoices or the hex final
     * token transaction hash for token invoices.
     */
    readonly pay: (
      invoice: string,
      options?: { readonly amount?: number | bigint },
    ) => Promise<SparkTransfer | string>;
    /** Coordinator `query_spark_invoices` statuses for the given invoice address strings. */
    readonly status: (
      invoices: ReadonlyArray<string>,
    ) => Promise<ReadonlyArray<SparkInvoiceStatus>>;
  };
  /** SSP leaves-swap fee quote in sats. */
  readonly swapFeeEstimate: (amountSats: number) => Promise<number>;
  readonly lightning: {
    /**
     * Asks the SSP for a BOLT-11 invoice paying this identity. `amountSats` of 0 requests an
     * amountless invoice; `includeSparkAddress` embeds a Spark fallback address payers can settle
     * directly. The returned invoice is verified field-by-field before it is handed out.
     */
    readonly createInvoice: (options: {
      readonly amountSats: number;
      readonly memo?: string;
      readonly descriptionHash?: Uint8Array;
      readonly expirySecs?: number;
      readonly includeSparkAddress?: boolean;
    }) => Promise<LightningInvoice>;
    /**
     * Pays a BOLT-11 invoice via a preimage swap with the SSP. `amountSats` is required for
     * zero-amount invoices and rejected otherwise; `transferId` makes a retry resume the same
     * transfer instead of paying twice.
     */
    readonly pay: (options: {
      readonly invoice: string;
      readonly maxFeeSats: number;
      readonly amountSats?: number;
      readonly transferId?: string;
    }) => Promise<LightningPayment>;
    /**
     * `user_request` status of a send; `preimage` appears once the SSP settled it. Pass the
     * `LightningPayment` from `pay` — the request's invoice and preimage are verified against its
     * payment hash, not the hash the SSP reports.
     */
    readonly sendStatus: (request: LightningSendStatusRequest) => Promise<LightningSendStatus>;
    /** `user_request` status of a receive, with the inbound transfer id once present. */
    readonly receiveStatus: (requestId: string) => Promise<LightningReceiveStatus>;
  };
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
    /**
     * Claims several confirmed UTXOs paying the SAME single-use address into one leaf — the only
     * way to claim more than one UTXO, since a single-use address is consumed by a claim. At most
     * 11 outputs; `vout` is resolved by unique match when omitted.
     */
    readonly claimMany: (options: {
      readonly outputs: ReadonlyArray<{
        readonly transaction: Uint8Array;
        readonly vout?: number;
      }>;
    }) => Promise<SparkLeaf>;
    /** The identity's reusable static deposit address — the same address on every call. */
    readonly staticAddress: () => Promise<string>;
    /** Confirmed, unclaimed UTXOs paying the static deposit address. */
    readonly staticUtxos: () => Promise<ReadonlyArray<StaticDepositUtxo>>;
    /**
     * Claims a static-deposit UTXO through the SSP: quotes the credit, rejects fees over
     * `maxFeeSats`, then claims the SSP's inbound transfer. `rawTx` supplies the deposit
     * transaction when the SO's utxo listing does not return it.
     */
    readonly claimStatic: (options: {
      readonly txid: string;
      readonly vout: number;
      readonly maxFeeSats: number;
      readonly rawTx?: Uint8Array;
    }) => Promise<StaticDepositClaimResult>;
    /**
     * Signs a version-3 refund spending a static-deposit UTXO to `destinationAddress` at
     * `feeRateSatPerVbyte` (fee floored at 194 sats; output must clear dust). The signed
     * transaction is returned unbroadcast.
     */
    readonly refundStatic: (options: {
      readonly txid: string;
      readonly vout: number;
      readonly destinationAddress: string;
      readonly feeRateSatPerVbyte: number;
      readonly rawTx?: Uint8Array;
    }) => Promise<StaticDepositRefund>;
  };
  readonly withdrawals: {
    /** Pre-signed exit transactions for the given leaves, root first (see ExitTransaction). */
    readonly unilateralExit: (
      leafIds: ReadonlyArray<string>,
    ) => Promise<ReadonlyArray<ExitTransaction>>;
    /**
     * The SSP's per-speed cooperative-exit fees for `address`. `amountSats` selects exactly that
     * much to exit (swapping if needed); omitting it quotes for the whole balance.
     */
    readonly quoteCooperativeExit: (options: {
      readonly address: string;
      readonly amountSats?: number;
    }) => Promise<CooperativeExitQuote>;
    /**
     * Cooperatively exits leaves to `address`, deducting `speed`'s quoted fee from the payout.
     * `amountSats` exits exactly that much; omitting it exits the whole balance. Pass the same
     * `transferId` to retry a call whose response was lost.
     */
    readonly cooperativeExit: (options: {
      readonly address: string;
      readonly speed: CooperativeExitSpeed;
      readonly maxFeeSats: number;
      readonly amountSats?: number;
      readonly transferId?: string;
    }) => Promise<CooperativeExitResult>;
    /** The SSP's status for a cooperative-exit request id. */
    readonly cooperativeExitStatus: (requestId: string) => Promise<CooperativeExitStatus>;
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

/** One entry of `query_spark_invoices`: the invoice string, its status name, and the payment. */
export type SparkInvoiceStatus = {
  readonly invoice: string;
  /** `InvoiceStatus` enum name, e.g. `"PENDING"`, `"FINALIZED"`. */
  readonly status: string;
  /** Hex transfer id when a sats transfer paid the invoice. */
  readonly satsTransferId?: string | undefined;
  /** Hex `hashFinalTokenTransaction` when a token transfer paid the invoice. */
  readonly tokenTransactionHash?: string | undefined;
};

export type SparkClientOptions = {
  readonly network: SparkNetwork;
  readonly signer: SparkSigner;
  readonly fetch: typeof globalThis.fetch;
  /** Exit-chain persistence; defaults to an in-memory store. */
  readonly store?: SparkStore;
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

/**
 * Builds a Spark client over one operator set. All spend paths are concurrency-safe within one
 * client instance — sends, swaps, lightning payments, exits and claims serialize leaf selection and
 * exit-chain bookkeeping on an internal lock, and token transfers likewise — but several client
 * instances or devices on one identity are not coordinated: the SO rejects the conflicting spend.
 */
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
  const store = options.store ?? createMemorySparkStore();
  const now = options.now ?? (() => Date.now());

  const deps: ConnectionDeps = {
    signer: options.signer,
    fetch: options.fetch,
    random,
    now,
    ...(options.sleep === undefined ? {} : { sleep: options.sleep }),
    ...(seams.transportFactory === undefined ? {} : { transportFactory: seams.transportFactory }),
  };

  const coordinator = operators.find((operator) => operator.identifier === config.coordinator);
  if (coordinator === undefined) {
    throw new SparkInputError(`coordinator ${config.coordinator} is not in the operator set`);
  }
  const coordinatorConnection: OperatorConnection = connectOperator(coordinator, deps);
  // Cross-checks (leaf agreement in leaves()) need a connection per operator; the coordinator
  // stays the only one used for writes.
  const otherConnections = operators
    .filter((operator) => operator !== coordinator)
    .map((operator) => connectOperator(operator, deps));

  const context = createClientContext({
    coordinatorConnection,
    otherConnections,
    signer: options.signer,
    network: options.network,
    config: { ...config, ssp },
    operators,
    store,
    random,
    now,
    depositCoordinator: {
      spark: coordinatorConnection.spark,
      signer: options.signer,
      network: options.network,
      operators,
      coordinatorIdentifier: config.coordinator,
    },
    transferCoordinator: {
      spark: coordinatorConnection.spark,
      signer: options.signer,
      network: options.network,
      operators,
      threshold: config.threshold,
    },
    ...(options.sleep === undefined ? {} : { sleep: options.sleep }),
    sspClient: createSspClient({
      baseUrl: ssp.baseUrl,
      graphqlPath: ssp.graphqlPath,
      signer: options.signer,
      fetch: options.fetch,
      now,
    }),
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
    balance: async () => leavesBalance(await context.leaves()),
    leaves: context.leaves,
    transfers: createTransfers(context),
    tokens: createTokens(context),
    invoices: createInvoices(context),
    swapFeeEstimate: async (amountSats) => context.sspClient.swapFeeEstimate(amountSats),
    lightning: createLightning(context),
    deposits: createDeposits(context),
    withdrawals: createWithdrawals(context),
    events,
    close() {
      abort.abort();
    },
  };
}
