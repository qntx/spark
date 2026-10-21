import type { SparkNetwork } from "../core/network.ts";
import type { SparkSigner } from "../signer/types.ts";

export type SspClient = {
  /** `leaves_swap_fee_estimate` — the sats fee the SSP quotes for swapping `amountSats`. */
  readonly swapFeeEstimate: (amountSats: number) => Promise<number>;
  /** `request_swap` — submits the adaptor-signed leaves swap; resolves to the inbound transfer. */
  readonly requestSwap: (request: SspSwapRequest) => Promise<SspSwapResult>;
  /** `request_lightning_receive` — asks the SSP to issue a BOLT-11 invoice for `paymentHash`. */
  readonly requestLightningReceive: (
    request: SspLightningReceiveRequest,
  ) => Promise<SspLightningReceiveResult>;
  /** `request_lightning_send` — asks the SSP to pay `encodedInvoice` over Lightning. */
  readonly requestLightningSend: (
    request: SspLightningSendRequest,
  ) => Promise<SspLightningSendResult>;
  /** `lightning_send_fee_estimate` — the sats fee the SSP quotes for paying the invoice. */
  readonly lightningSendFeeEstimate: (
    encodedInvoice: string,
    amountSats?: number,
  ) => Promise<number>;
  /** `user_request` — status of a lightning send request by id. */
  readonly lightningSendRequest: (id: string) => Promise<SspLightningSendResult>;
  /** `user_request` — status of a lightning receive request by id. */
  readonly lightningReceiveRequest: (id: string) => Promise<SspLightningReceiveResult>;
  /** `coop_exit_fee_quote` — per-speed exit fees (user fee + L1 broadcast fee) for the leaves. */
  readonly coopExitFeeQuote: (
    leafIds: ReadonlyArray<string>,
    address: string,
  ) => Promise<SspCoopExitFeeQuote>;
  /** `request_coop_exit` — creates the payout + connector transactions for the exit. */
  readonly requestCoopExit: (request: SspCoopExitRequest) => Promise<SspCoopExitResult>;
  /** `complete_coop_exit` — asks the SSP to broadcast the payout once the transfer committed. */
  readonly completeCoopExit: (request: {
    readonly coopExitRequestId: string;
    readonly userOutboundTransferExternalId: string;
  }) => Promise<SspCoopExitStatus>;
  /** `user_request` — status of a cooperative-exit request by id. */
  readonly coopExitRequest: (id: string) => Promise<SspCoopExitStatus>;
  /**
   * `static_deposit_quote` — the sats the SSP credits for claiming the UTXO, plus its quote
   * signature.
   */
  readonly staticDepositQuote: (request: {
    readonly transactionId: string;
    readonly outputIndex: number;
    readonly network: SparkNetwork;
  }) => Promise<SspStaticDepositQuote>;
  /** `claim_static_deposit` — FIXED-amount claim authorized by the static-deposit secret key. */
  readonly claimStaticDeposit: (
    request: SspClaimStaticDepositRequest,
  ) => Promise<SspClaimStaticDepositResult>;
};

/** One swapped-out leaf: the unsigned CPFP refund tx and its adaptor-completed signature. */
export type SspSwapLeaf = {
  readonly leafId: string;
  readonly rawUnsignedRefundTransaction: Uint8Array;
  readonly adaptorAddedSignature: Uint8Array;
};

export type SspSwapRequest = {
  readonly adaptorPublicKey: Uint8Array;
  readonly totalAmountSats: number;
  readonly targetAmountsSats: ReadonlyArray<number>;
  readonly feeSats: number;
  readonly userLeaves: ReadonlyArray<SspSwapLeaf>;
  readonly userOutboundTransferId: string;
};

export type SspSwapResult = {
  readonly status: string;
  readonly inboundTransferId: string;
  readonly feeSats: number;
};

export type SspLightningReceiveRequest = {
  readonly network: SparkNetwork;
  readonly amountSats: number;
  readonly paymentHash: Uint8Array;
  readonly expirySecs: number;
  readonly receiverIdentityPublicKey: Uint8Array;
  readonly memo?: string;
  readonly descriptionHash?: Uint8Array;
  readonly includeSparkAddress?: boolean;
};

export type SspLightningReceiveResult = {
  readonly id: string;
  readonly status: string;
  /** The encoded BOLT-11 invoice the SSP issued. */
  readonly invoice: string;
  /** `transfer_spark_id` of the preimage-swap transfer, once the payment arrived. */
  readonly transferId?: string;
  readonly paymentPreimage?: Uint8Array;
};

export type SspLightningSendRequest = {
  readonly encodedInvoice: string;
  /** Amount for amountless invoices; must be absent for fixed-amount ones. */
  readonly amountSats?: number;
  /** The preimage-swap transfer id — the SSP's idempotency key for this send. */
  readonly userOutboundTransferExternalId: string;
};

export type SspLightningSendResult = {
  readonly id: string;
  readonly status: string;
  readonly encodedInvoice: string;
  readonly feeSats: number;
  readonly transferId?: string;
  readonly paymentPreimage?: Uint8Array;
};

/** Speed tier accepted by `request_coop_exit` (upstream `ExitSpeed`). */
export type SspCoopExitSpeed = "FAST" | "MEDIUM" | "SLOW";

export type SspCoopExitFeeQuote = {
  readonly id: string;
  readonly expiresAtMs: number;
  /** `user_fee + l1_broadcast_fee` per speed, in sats. */
  readonly fees: { readonly fast: number; readonly medium: number; readonly slow: number };
};

export type SspCoopExitRequest = {
  readonly leafIds: ReadonlyArray<string>;
  readonly withdrawalAddress: string;
  readonly exitSpeed: SspCoopExitSpeed;
  /** Fee deducted from the withdrawal (`withdraw_all`); the only mode we support. */
  readonly withdrawAll: true;
  /** The outbound transfer id — the SSP's idempotency key for this exit. */
  readonly userOutboundTransferExternalId: string;
};

export type SspCoopExitResult = {
  readonly id: string;
  readonly status: string;
  readonly rawCoopExitTransaction: Uint8Array;
  /** Display-order hex, exactly as the SSP returns it. */
  readonly coopExitTxid: string;
  readonly rawConnectorTransaction: Uint8Array;
};

export type SspCoopExitStatus = {
  readonly id: string;
  readonly status: string;
  readonly transferId?: string;
  /** The SSP-built payout transaction, when the request record carries it. */
  readonly rawCoopExitTransaction?: Uint8Array;
};

export type SspStaticDepositQuote = {
  readonly creditAmountSats: number;
  /** The SSP's quote signature — echoed back as `quote_signature` on the claim. */
  readonly signature: string;
};

export type SspClaimStaticDepositRequest = {
  readonly transactionId: string;
  readonly outputIndex: number;
  readonly network: SparkNetwork;
  readonly creditAmountSats: number;
  /** Hex of the static-deposit secret key ECIES-sealed to the SSP identity public key. */
  readonly encryptedSecretKey: string;
  /** Hex-encoded DER identity signature over the `static-deposit-claim` statement. */
  readonly signature: string;
  /** The quote signature `static_deposit_quote` returned. */
  readonly quoteSignature: string;
};

export type SspClaimStaticDepositResult = {
  /** The SSP → wallet transfer id, once the claim created it. */
  readonly transferId?: string;
};

export type SspDeps = {
  readonly signer: SparkSigner;
  readonly fetch: typeof globalThis.fetch;
  readonly now?: () => number;
};
