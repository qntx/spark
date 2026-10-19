import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";

import type { SparkNetwork } from "../core/network.ts";
import { SESSION_EXPIRY_BUFFER_MS } from "../core/session.ts";
import { serverErrorText } from "../core/text.ts";
import { SparkInputError, SparkRequestError } from "../errors/index.ts";
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
};

export type SspDeps = {
  readonly signer: SparkSigner;
  readonly fetch: typeof globalThis.fetch;
  readonly now?: () => number;
};

// Query documents copied verbatim (selections, aliases, operation names) from upstream
// sdks/js/packages/spark-sdk/src/graphql (buildonspark/spark@0b3a32a).
const GET_CHALLENGE = `
mutation GetChallenge($public_key: PublicKey!) {
  get_challenge(input: { public_key: $public_key }) {
    ...GetChallengeOutputFragment
  }
}

fragment GetChallengeOutputFragment on GetChallengeOutput {
  __typename
  get_challenge_output_protected_challenge: protected_challenge
}`;

const VERIFY_CHALLENGE = `
mutation VerifyChallenge(
  $protected_challenge: String!
  $signature: String!
  $identity_public_key: PublicKey!
  $provider: Provider
) {
  verify_challenge(
    input: {
      protected_challenge: $protected_challenge
      signature: $signature
      identity_public_key: $identity_public_key
      provider: $provider
    }
  ) {
    ...VerifyChallengeOutputFragment
  }
}

fragment VerifyChallengeOutputFragment on VerifyChallengeOutput {
  __typename
  verify_challenge_output_valid_until: valid_until
  verify_challenge_output_session_token: session_token
}`;

const LEAVES_SWAP_FEE_ESTIMATE = `
query LeavesSwapFeeEstimate($total_amount_sats: Int!) {
  leaves_swap_fee_estimate(input: { total_amount_sats: $total_amount_sats }) {
    ...LeavesSwapFeeEstimateOutputFragment
  }
}

fragment LeavesSwapFeeEstimateOutputFragment on LeavesSwapFeeEstimateOutput {
  __typename
  leaves_swap_fee_estimate_output_fee_estimate: fee_estimate {
    __typename
    currency_amount_original_value: original_value
    currency_amount_original_unit: original_unit
  }
}`;

/**
 * Terminal failure/failing values of the SSP's `SparkLeavesSwapRequestStatus`. The upstream JS enum
 * stops at FAILED/EXPIRED; the live schema's values come from Breez's graphql/models.rs.
 */
const SWAP_FAILED = new Set([
  "INBOUND_TRANSFER_VERIFYING_FAILED",
  "OUTBOUND_TRANSFER_SENDING_FAILED",
  "OUTBOUND_TRANSFER_COMPLETING_FAILED",
  "INBOUND_TRANSFER_CLAIMING_FAILED",
  "REQUEST_FAILING_FROM_VERIFYING_SCHEDULED",
  "REQUEST_FAILING_FROM_SENDING_SCHEDULED",
  "REQUEST_FAILING_FROM_VERIFYING_FAILED",
  "REQUEST_FAILING_FROM_SENDING_FAILED",
  "EXPIRED",
  "FAILED",
]);

const REQUEST_SWAP = `
mutation RequestSwap(
  $adaptor_pubkey: PublicKey!
  $total_amount_sats: Long!
  $target_amount_sats: [Long!]!
  $fee_sats: Long!
  $user_leaves: [UserLeafInput!]!
  $user_outbound_transfer_external_id: UUID!
) {
  request_swap(input: {
    adaptor_pubkey: $adaptor_pubkey
    total_amount_sats: $total_amount_sats
    target_amount_sats: $target_amount_sats
    fee_sats: $fee_sats
    user_leaves: $user_leaves
    user_outbound_transfer_external_id: $user_outbound_transfer_external_id
  }) {
    request {
      ...LeavesSwapRequestFragment
    }
  }
}

fragment LeavesSwapRequestFragment on LeavesSwapRequest {
    __typename
    leaves_swap_request_id: id
    leaves_swap_request_created_at: created_at
    leaves_swap_request_updated_at: updated_at
    leaves_swap_request_network: network
    leaves_swap_request_status: status
    leaves_swap_request_total_amount: total_amount {
        __typename
        currency_amount_original_value: original_value
        currency_amount_original_unit: original_unit
    }
    leaves_swap_request_target_amount: target_amount {
        __typename
        currency_amount_original_value: original_value
        currency_amount_original_unit: original_unit
    }
    leaves_swap_request_fee: fee {
        __typename
        currency_amount_original_value: original_value
        currency_amount_original_unit: original_unit
    }
    leaves_swap_request_inbound_transfer: inbound_transfer {
        __typename
        transfer_total_amount: total_amount {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        transfer_spark_id: spark_id
        transfer_user_request: user_request {
            id
        }
    }
    leaves_swap_request_outbound_transfer: outbound_transfer {
        __typename
        transfer_total_amount: total_amount {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        transfer_spark_id: spark_id
        transfer_user_request: user_request {
            id
        }
    }
    leaves_swap_request_expires_at: expires_at
    leaves_swap_request_swap_leaves: swap_leaves {
        __typename
        swap_leaf_leaf_id: leaf_id
        swap_leaf_raw_unsigned_refund_transaction: raw_unsigned_refund_transaction
        swap_leaf_adaptor_signed_signature: adaptor_signed_signature
        swap_leaf_direct_raw_unsigned_refund_transaction: direct_raw_unsigned_refund_transaction
        swap_leaf_direct_adaptor_signed_signature: direct_adaptor_signed_signature
        swap_leaf_direct_from_cpfp_raw_unsigned_refund_transaction: direct_from_cpfp_raw_unsigned_refund_transaction
        swap_leaf_direct_from_cpfp_adaptor_signed_signature: direct_from_cpfp_adaptor_signed_signature
    }
}`;

// Upstream builds this document to gate the `committed_quote` variant; we never send it, so this is
// `requestLightningReceiveDocument(false)` unrolled.
const REQUEST_LIGHTNING_RECEIVE = `
mutation RequestLightningReceive(
    $network: BitcoinNetwork!
    $amount_sats: Long!
    $payment_hash: Hash32!
    $expiry_secs: Int
    $memo: String
    $include_spark_address: Boolean
    $receiver_identity_pubkey: PublicKey
    $description_hash: Hash32
    $spark_invoice: String
  ) {
    request_lightning_receive(
      input: {
        network: $network
        amount_sats: $amount_sats
        payment_hash: $payment_hash
        expiry_secs: $expiry_secs
        memo: $memo
        include_spark_address: $include_spark_address
        receiver_identity_pubkey: $receiver_identity_pubkey
        description_hash: $description_hash
        spark_invoice: $spark_invoice
      }
    ) {
      request {
        ...LightningReceiveRequestFragment
      }
    }
  }

fragment LightningReceiveRequestFragment on LightningReceiveRequest {
    __typename
    lightning_receive_request_id: id
    lightning_receive_request_created_at: created_at
    lightning_receive_request_updated_at: updated_at
    lightning_receive_request_network: network
    lightning_receive_request_invoice: invoice {
        __typename
        invoice_encoded_invoice: encoded_invoice
        invoice_bitcoin_network: bitcoin_network
        invoice_payment_hash: payment_hash
        invoice_amount: amount {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        invoice_created_at: created_at
        invoice_expires_at: expires_at
        invoice_memo: memo
    }
    lightning_receive_request_status: status
    lightning_receive_request_transfer: transfer {
        __typename
        transfer_total_amount: total_amount {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        transfer_spark_id: spark_id
        transfer_user_request: user_request {
            id
        }
    }
    lightning_receive_request_payment_preimage: payment_preimage
    lightning_receive_request_receiver_identity_public_key: receiver_identity_public_key
}`;

const REQUEST_LIGHTNING_SEND = `
mutation RequestLightningSend(
    $encoded_invoice: String!
    $idempotency_key: String
    $amount_sats: Long
    $user_outbound_transfer_external_id: UUID
  ) {
    request_lightning_send(input: {
      encoded_invoice: $encoded_invoice
      idempotency_key: $idempotency_key
      amount_sats: $amount_sats
      user_outbound_transfer_external_id: $user_outbound_transfer_external_id
    }) {
      request {
        ...LightningSendRequestFragment
      }
    }
  }

fragment LightningSendRequestFragment on LightningSendRequest {
    __typename
    lightning_send_request_id: id
    lightning_send_request_created_at: created_at
    lightning_send_request_updated_at: updated_at
    lightning_send_request_network: network
    lightning_send_request_encoded_invoice: encoded_invoice
    lightning_send_request_fee: fee {
        __typename
        currency_amount_original_value: original_value
        currency_amount_original_unit: original_unit
    }
    lightning_send_request_idempotency_key: idempotency_key
    lightning_send_request_status: status
    lightning_send_request_transfer: transfer {
        __typename
        transfer_total_amount: total_amount {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        transfer_spark_id: spark_id
        transfer_user_request: user_request {
            id
        }
    }
    lightning_send_request_payment_preimage: payment_preimage
}`;

const LIGHTNING_SEND_FEE_ESTIMATE = `
query LightningSendFeeEstimate(
    $encoded_invoice: String!
    $amount_sats: Long
  ) {
    lightning_send_fee_estimate(
      input: {
        encoded_invoice: $encoded_invoice
        amount_sats: $amount_sats
      }
    ) {
      ...LightningSendFeeEstimateOutputFragment
    }
  }

fragment LightningSendFeeEstimateOutputFragment on LightningSendFeeEstimateOutput {
    __typename
    lightning_send_fee_estimate_output_fee_estimate: fee_estimate {
        __typename
        currency_amount_original_value: original_value
        currency_amount_original_unit: original_unit
    }
}`;

const COOP_EXIT_FEE_QUOTE = `
query CoopExitFeeQuote($leaf_external_ids: [UUID!]!, $withdrawal_address: String!) {
  coop_exit_fee_quote(input: {
    leaf_external_ids: $leaf_external_ids
    withdrawal_address: $withdrawal_address
  }) {
    ...CoopExitFeeQuoteOutputFragment
  }
}

fragment CoopExitFeeQuoteOutputFragment on CoopExitFeeQuoteOutput {
    __typename
    coop_exit_fee_quote_quote: quote {
        __typename
        coop_exit_fee_quote_id: id
        coop_exit_fee_quote_created_at: created_at
        coop_exit_fee_quote_updated_at: updated_at
        coop_exit_fee_quote_network: network
        coop_exit_fee_quote_user_fee_fast: user_fee_fast {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        coop_exit_fee_quote_user_fee_medium: user_fee_medium {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        coop_exit_fee_quote_user_fee_slow: user_fee_slow {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        coop_exit_fee_quote_l1_broadcast_fee_fast: l1_broadcast_fee_fast {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        coop_exit_fee_quote_l1_broadcast_fee_medium: l1_broadcast_fee_medium {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        coop_exit_fee_quote_l1_broadcast_fee_slow: l1_broadcast_fee_slow {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        coop_exit_fee_quote_expires_at: expires_at
    }
}`;

const REQUEST_COOP_EXIT = `
mutation RequestCoopExit(
  $leaf_external_ids: [UUID!]!
  $withdrawal_address: String!
  $idempotency_key: String
  $exit_speed: ExitSpeed!
  $withdraw_all: Boolean
  $fee_leaf_external_ids: [UUID!]
  $fee_quote_id: ID
  $user_outbound_transfer_external_id: UUID
) {
  request_coop_exit(input: {
    leaf_external_ids: $leaf_external_ids
    withdrawal_address: $withdrawal_address
    idempotency_key: $idempotency_key
    exit_speed: $exit_speed
    withdraw_all: $withdraw_all
    fee_leaf_external_ids: $fee_leaf_external_ids
    fee_quote_id: $fee_quote_id
    user_outbound_transfer_external_id: $user_outbound_transfer_external_id
  }) {
    request {
      ...CoopExitRequestFragment
    }
  }
}

fragment CoopExitRequestFragment on CoopExitRequest {
    __typename
    coop_exit_request_id: id
    coop_exit_request_created_at: created_at
    coop_exit_request_updated_at: updated_at
    coop_exit_request_network: network
    coop_exit_request_fee: fee {
        __typename
        currency_amount_original_value: original_value
        currency_amount_original_unit: original_unit
    }
    coop_exit_request_l1_broadcast_fee: l1_broadcast_fee {
        __typename
        currency_amount_original_value: original_value
        currency_amount_original_unit: original_unit
    }
    coop_exit_request_fee_quote: fee_quote {
        id
    }
    coop_exit_request_exit_speed: exit_speed
    coop_exit_request_status: status
    coop_exit_request_expires_at: expires_at
    coop_exit_request_raw_connector_transaction: raw_connector_transaction
    coop_exit_request_raw_coop_exit_transaction: raw_coop_exit_transaction
    coop_exit_request_coop_exit_txid: coop_exit_txid
    coop_exit_request_transfer: transfer {
        __typename
        transfer_total_amount: total_amount {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        transfer_spark_id: spark_id
        transfer_user_request: user_request {
            id
        }
    }
}`;

const COMPLETE_COOP_EXIT = `
mutation CompleteCoopExit(
  $user_outbound_transfer_external_id: UUID!
  $coop_exit_request_id: ID
) {
  complete_coop_exit(input: {
    user_outbound_transfer_external_id: $user_outbound_transfer_external_id
    coop_exit_request_id: $coop_exit_request_id
  }) {
    request {
      ...CoopExitRequestFragment
    }
  }
}

fragment CoopExitRequestFragment on CoopExitRequest {
    __typename
    coop_exit_request_id: id
    coop_exit_request_created_at: created_at
    coop_exit_request_updated_at: updated_at
    coop_exit_request_network: network
    coop_exit_request_fee: fee {
        __typename
        currency_amount_original_value: original_value
        currency_amount_original_unit: original_unit
    }
    coop_exit_request_l1_broadcast_fee: l1_broadcast_fee {
        __typename
        currency_amount_original_value: original_value
        currency_amount_original_unit: original_unit
    }
    coop_exit_request_fee_quote: fee_quote {
        id
    }
    coop_exit_request_exit_speed: exit_speed
    coop_exit_request_status: status
    coop_exit_request_expires_at: expires_at
    coop_exit_request_raw_connector_transaction: raw_connector_transaction
    coop_exit_request_raw_coop_exit_transaction: raw_coop_exit_transaction
    coop_exit_request_coop_exit_txid: coop_exit_txid
    coop_exit_request_transfer: transfer {
        __typename
        transfer_total_amount: total_amount {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        transfer_spark_id: spark_id
        transfer_user_request: user_request {
            id
        }
    }
}`;

// Upstream's UserRequest query — the document its `getLightningReceiveRequest`/
// `getLightningSendRequest` use — copied verbatim including the other request-type fragments.
const USER_REQUEST = `
query UserRequest($request_id: ID!) {
  user_request(request_id: $request_id) {
    ...UserRequestFragment
  }
}

fragment UserRequestFragment on UserRequest {
    __typename
    ... on ClaimStaticDeposit {
        __typename
        claim_static_deposit_id: id
        claim_static_deposit_created_at: created_at
        claim_static_deposit_updated_at: updated_at
        claim_static_deposit_network: network
        claim_static_deposit_credit_amount: credit_amount {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        claim_static_deposit_max_fee: max_fee {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        claim_static_deposit_status: status
        claim_static_deposit_transaction_id: transaction_id
        claim_static_deposit_output_index: output_index
        claim_static_deposit_bitcoin_network: bitcoin_network
        claim_static_deposit_transfer_spark_id: transfer_spark_id
    }
    ... on CoopExitRequest {
        __typename
        coop_exit_request_id: id
        coop_exit_request_created_at: created_at
        coop_exit_request_updated_at: updated_at
        coop_exit_request_network: network
        coop_exit_request_fee: fee {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        coop_exit_request_l1_broadcast_fee: l1_broadcast_fee {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        coop_exit_request_fee_quote: fee_quote {
            id
        }
        coop_exit_request_exit_speed: exit_speed
        coop_exit_request_status: status
        coop_exit_request_expires_at: expires_at
        coop_exit_request_raw_connector_transaction: raw_connector_transaction
        coop_exit_request_raw_coop_exit_transaction: raw_coop_exit_transaction
        coop_exit_request_coop_exit_txid: coop_exit_txid
        coop_exit_request_transfer: transfer {
            __typename
            transfer_total_amount: total_amount {
                __typename
                currency_amount_original_value: original_value
                currency_amount_original_unit: original_unit
            }
            transfer_spark_id: spark_id
            transfer_user_request: user_request {
                id
            }
        }
    }
    ... on LeavesSwapRequest {
        __typename
        leaves_swap_request_id: id
        leaves_swap_request_created_at: created_at
        leaves_swap_request_updated_at: updated_at
        leaves_swap_request_network: network
        leaves_swap_request_status: status
        leaves_swap_request_total_amount: total_amount {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        leaves_swap_request_target_amount: target_amount {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        leaves_swap_request_fee: fee {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        leaves_swap_request_inbound_transfer: inbound_transfer {
            __typename
            transfer_total_amount: total_amount {
                __typename
                currency_amount_original_value: original_value
                currency_amount_original_unit: original_unit
            }
            transfer_spark_id: spark_id
            transfer_user_request: user_request {
                id
            }
        }
        leaves_swap_request_outbound_transfer: outbound_transfer {
            __typename
            transfer_total_amount: total_amount {
                __typename
                currency_amount_original_value: original_value
                currency_amount_original_unit: original_unit
            }
            transfer_spark_id: spark_id
            transfer_user_request: user_request {
                id
            }
        }
        leaves_swap_request_expires_at: expires_at
        leaves_swap_request_swap_leaves: swap_leaves {
            __typename
            swap_leaf_leaf_id: leaf_id
            swap_leaf_raw_unsigned_refund_transaction: raw_unsigned_refund_transaction
            swap_leaf_adaptor_signed_signature: adaptor_signed_signature
            swap_leaf_direct_raw_unsigned_refund_transaction: direct_raw_unsigned_refund_transaction
            swap_leaf_direct_adaptor_signed_signature: direct_adaptor_signed_signature
            swap_leaf_direct_from_cpfp_raw_unsigned_refund_transaction: direct_from_cpfp_raw_unsigned_refund_transaction
            swap_leaf_direct_from_cpfp_adaptor_signed_signature: direct_from_cpfp_adaptor_signed_signature
        }
    }
    ... on LightningReceiveRequest {
        __typename
        lightning_receive_request_id: id
        lightning_receive_request_created_at: created_at
        lightning_receive_request_updated_at: updated_at
        lightning_receive_request_network: network
        lightning_receive_request_invoice: invoice {
            __typename
            invoice_encoded_invoice: encoded_invoice
            invoice_bitcoin_network: bitcoin_network
            invoice_payment_hash: payment_hash
            invoice_amount: amount {
                __typename
                currency_amount_original_value: original_value
                currency_amount_original_unit: original_unit
            }
            invoice_created_at: created_at
            invoice_expires_at: expires_at
            invoice_memo: memo
        }
        lightning_receive_request_status: status
        lightning_receive_request_transfer: transfer {
            __typename
            transfer_total_amount: total_amount {
                __typename
                currency_amount_original_value: original_value
                currency_amount_original_unit: original_unit
            }
            transfer_spark_id: spark_id
            transfer_user_request: user_request {
                id
            }
        }
        lightning_receive_request_payment_preimage: payment_preimage
        lightning_receive_request_receiver_identity_public_key: receiver_identity_public_key
    }
    ... on LightningSendRequest {
        __typename
        lightning_send_request_id: id
        lightning_send_request_created_at: created_at
        lightning_send_request_updated_at: updated_at
        lightning_send_request_network: network
        lightning_send_request_encoded_invoice: encoded_invoice
        lightning_send_request_fee: fee {
            __typename
            currency_amount_original_value: original_value
            currency_amount_original_unit: original_unit
        }
        lightning_send_request_idempotency_key: idempotency_key
        lightning_send_request_status: status
        lightning_send_request_transfer: transfer {
            __typename
            transfer_total_amount: total_amount {
                __typename
                currency_amount_original_value: original_value
                currency_amount_original_unit: original_unit
            }
            transfer_spark_id: spark_id
            transfer_user_request: user_request {
                id
            }
        }
        lightning_send_request_payment_preimage: payment_preimage
    }
}`;

type JsonObject = Record<string, unknown>;

/** A malformed SSP response is a server fault, not caller input. */
function unexpectedResponse(field: string, rule: string): SparkRequestError {
  return new SparkRequestError(`ssp response: ${field} ${rule}`, {
    code: "unexpected_response",
  });
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asObject(value: unknown, field: string): JsonObject {
  if (!isJsonObject(value)) {
    throw unexpectedResponse(field, "is not an object");
  }
  return value;
}

function asString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw unexpectedResponse(field, "is not a string");
  }
  return value;
}

function asSats(value: unknown, field: string): number {
  // Only plain decimal strings and numbers: Number() would also accept "0x10", " 5 ", "1e3".
  const n =
    typeof value === "number"
      ? value
      : typeof value === "string" && /^[0-9]+$/.test(value)
        ? Number(value)
        : undefined;
  if (n === undefined || !Number.isSafeInteger(n) || n < 0) {
    throw unexpectedResponse(field, "is not a non-negative integer");
  }
  return n;
}

/** CurrencyAmount in SATOSHI → sats; any other unit is an unexpected response. */
function currencyAmountSats(value: unknown, field: string): number {
  const amount = asObject(value, field);
  const unit = asString(
    amount["currency_amount_original_unit"],
    `${field}.currency_amount_original_unit`,
  );
  if (unit !== "SATOSHI") {
    throw unexpectedResponse(`${field}.currency_amount_original_unit`, "is not SATOSHI");
  }
  return asSats(
    amount["currency_amount_original_value"],
    `${field}.currency_amount_original_value`,
  );
}

/** Fee CurrencyAmount → sats: SATOSHI as-is, MILLISATOSHI rounded up, else unexpected (upstream). */
function feeAmountSats(value: unknown, field: string): number {
  const amount = asObject(value, field);
  const unit = asString(
    amount["currency_amount_original_unit"],
    `${field}.currency_amount_original_unit`,
  );
  const valueSats = asSats(
    amount["currency_amount_original_value"],
    `${field}.currency_amount_original_value`,
  );
  switch (unit) {
    case "SATOSHI":
      return valueSats;
    case "MILLISATOSHI":
      return Math.ceil(valueSats / 1000);
    default:
      throw unexpectedResponse(`${field}.currency_amount_original_unit`, `is ${unit}`);
  }
}

/** Hex-encoded 32-byte preimage → bytes; absent when the request has no preimage yet. */
function optionalPreimage(value: unknown, field: string): Uint8Array | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  let preimage: Uint8Array;
  try {
    preimage = hexToBytes(asString(value, field));
  } catch {
    throw unexpectedResponse(field, "is not a 32-byte hex preimage");
  }
  if (preimage.length !== 32) {
    throw unexpectedResponse(field, "is not a 32-byte hex preimage");
  }
  return preimage;
}

/** `transfer_spark_id` inside an optional transfer object. */
function optionalTransferId(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  return asString(asObject(value, field)["transfer_spark_id"], `${field}.transfer_spark_id`);
}

function asHexBytes(value: unknown, field: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(asString(value, field));
  } catch {
    throw unexpectedResponse(field, "is not valid hex");
  }
  return bytes;
}

/** Display-order txid hex, exactly 32 bytes. */
function asTxidHex(value: unknown, field: string): string {
  const txid = asString(value, field);
  try {
    if (hexToBytes(txid).length !== 32) {
      throw new Error("wrong length");
    }
  } catch {
    throw unexpectedResponse(field, "is not a 32-byte hex txid");
  }
  return txid;
}

function parseLightningReceive(request: JsonObject, field: string): SspLightningReceiveResult {
  const invoice = asObject(
    request["lightning_receive_request_invoice"],
    `${field}.lightning_receive_request_invoice`,
  );
  const transferId = optionalTransferId(
    request["lightning_receive_request_transfer"],
    `${field}.lightning_receive_request_transfer`,
  );
  const paymentPreimage = optionalPreimage(
    request["lightning_receive_request_payment_preimage"],
    `${field}.lightning_receive_request_payment_preimage`,
  );
  return {
    id: asString(request["lightning_receive_request_id"], `${field}.lightning_receive_request_id`),
    status: asString(
      request["lightning_receive_request_status"],
      `${field}.lightning_receive_request_status`,
    ),
    invoice: asString(invoice["invoice_encoded_invoice"], `${field}.invoice_encoded_invoice`),
    ...(transferId === undefined ? {} : { transferId }),
    ...(paymentPreimage === undefined ? {} : { paymentPreimage }),
  };
}

function parseLightningSend(request: JsonObject, field: string): SspLightningSendResult {
  const transferId = optionalTransferId(
    request["lightning_send_request_transfer"],
    `${field}.lightning_send_request_transfer`,
  );
  const paymentPreimage = optionalPreimage(
    request["lightning_send_request_payment_preimage"],
    `${field}.lightning_send_request_payment_preimage`,
  );
  return {
    id: asString(request["lightning_send_request_id"], `${field}.lightning_send_request_id`),
    status: asString(
      request["lightning_send_request_status"],
      `${field}.lightning_send_request_status`,
    ),
    encodedInvoice: asString(
      request["lightning_send_request_encoded_invoice"],
      `${field}.lightning_send_request_encoded_invoice`,
    ),
    feeSats: feeAmountSats(
      request["lightning_send_request_fee"],
      `${field}.lightning_send_request_fee`,
    ),
    ...(transferId === undefined ? {} : { transferId }),
    ...(paymentPreimage === undefined ? {} : { paymentPreimage }),
  };
}

function parseCoopExitQuote(quote: JsonObject, field: string): SspCoopExitFeeQuote {
  const fees = (speed: string): number => {
    const userFee = currencyAmountSats(
      quote[`coop_exit_fee_quote_user_fee_${speed}`],
      `${field}.coop_exit_fee_quote_user_fee_${speed}`,
    );
    const l1Fee = currencyAmountSats(
      quote[`coop_exit_fee_quote_l1_broadcast_fee_${speed}`],
      `${field}.coop_exit_fee_quote_l1_broadcast_fee_${speed}`,
    );
    return userFee + l1Fee;
  };
  const expiresAtMs = Date.parse(
    asString(quote["coop_exit_fee_quote_expires_at"], `${field}.coop_exit_fee_quote_expires_at`),
  );
  if (Number.isNaN(expiresAtMs)) {
    throw unexpectedResponse(`${field}.coop_exit_fee_quote_expires_at`, "is not a parseable date");
  }
  return {
    id: asString(quote["coop_exit_fee_quote_id"], `${field}.coop_exit_fee_quote_id`),
    expiresAtMs,
    fees: { fast: fees("fast"), medium: fees("medium"), slow: fees("slow") },
  };
}

/** The CoopExitRequest fields every parse needs: id, status and the optional transfer link. */
function parseCoopExitStatus(request: JsonObject, field: string): SspCoopExitStatus {
  const transferId = optionalTransferId(
    request["coop_exit_request_transfer"],
    `${field}.coop_exit_request_transfer`,
  );
  return {
    id: asString(request["coop_exit_request_id"], `${field}.coop_exit_request_id`),
    status: asString(request["coop_exit_request_status"], `${field}.coop_exit_request_status`),
    ...(transferId === undefined ? {} : { transferId }),
  };
}

/** Request_coop_exit additionally returns the payout + connector transactions to validate. */
function parseCoopExitResult(request: JsonObject, field: string): SspCoopExitResult {
  return {
    ...parseCoopExitStatus(request, field),
    rawCoopExitTransaction: asHexBytes(
      request["coop_exit_request_raw_coop_exit_transaction"],
      `${field}.coop_exit_request_raw_coop_exit_transaction`,
    ),
    coopExitTxid: asTxidHex(
      request["coop_exit_request_coop_exit_txid"],
      `${field}.coop_exit_request_coop_exit_txid`,
    ),
    rawConnectorTransaction: asHexBytes(
      request["coop_exit_request_raw_connector_transaction"],
      `${field}.coop_exit_request_raw_connector_transaction`,
    ),
  };
}

/**
 * Minimal GraphQL-over-POST client for the SSP. Authenticates with GetChallenge → `signIdentity`
 * (`ssp-challenge`) → VerifyChallenge, sends `Authorization: Bearer <session token>`, and
 * re-authenticates once on a 401. Only the queries this stage needs are supported.
 */
export function createSspClient(options: {
  readonly baseUrl: string;
  readonly graphqlPath: string;
  readonly signer: SparkSigner;
  readonly fetch: typeof globalThis.fetch;
  readonly now?: () => number;
}): SspClient {
  const now = options.now ?? (() => Date.now());
  const endpoint = `${options.baseUrl.replace(/\/+$/, "")}/${options.graphqlPath.replace(/^\/+/, "")}`;

  let sessionToken: string | undefined;
  let validUntilMs = 0;
  let pendingAuth: Promise<void> | undefined;

  async function post(
    operationName: string,
    query: string,
    variables: JsonObject,
    authed: boolean,
  ): Promise<JsonObject> {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (authed && sessionToken !== undefined) {
      headers["Authorization"] = `Bearer ${sessionToken}`;
    }
    let response: Response;
    try {
      response = await options.fetch(endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify({ operationName, query, variables }),
      });
    } catch (error) {
      throw new SparkRequestError("ssp request failed", { cause: error });
    }
    if (response.status === 401) {
      throw new SparkRequestError("ssp request unauthorized", {
        code: "unauthenticated",
      });
    }
    if (response.status !== 200) {
      throw new SparkRequestError(`ssp request failed with status ${response.status}`, {
        code: `http_${response.status}`,
      });
    }
    let parsed: unknown;
    try {
      parsed = await response.json();
    } catch (error) {
      throw new SparkRequestError("ssp response: body is not valid JSON", {
        code: "unexpected_response",
        cause: error,
      });
    }
    const body = asObject(parsed, "body");
    const { errors } = body;
    if (Array.isArray(errors) && errors.length > 0) {
      const first = asObject(errors[0], "errors[0]");
      const { extensions } = first;
      const code =
        typeof extensions === "object" && extensions !== null
          ? asObject(extensions, "extensions")["code"]
          : undefined;
      throw new SparkRequestError(
        `ssp error: ${serverErrorText(asString(first["message"], "errors[0].message"))}`,
        typeof code === "string" ? { code: code.toLowerCase() } : {},
      );
    }
    return asObject(body["data"], "data");
  }

  async function authenticate(): Promise<void> {
    const identityPublicKey = bytesToHex(await options.signer.identityPublicKey());
    const challengeData = await post(
      "GetChallenge",
      GET_CHALLENGE,
      { public_key: identityPublicKey },
      false,
    );
    const challengeOutput = asObject(challengeData["get_challenge"], "get_challenge");
    const protectedChallenge = asString(
      challengeOutput["get_challenge_output_protected_challenge"],
      "get_challenge_output_protected_challenge",
    );
    const signature = await options.signer.signIdentity({
      kind: "ssp-challenge",
      protectedChallenge,
    });
    const verifyData = await post(
      "VerifyChallenge",
      VERIFY_CHALLENGE,
      {
        protected_challenge: protectedChallenge,
        signature: base64.encode(signature),
        identity_public_key: identityPublicKey,
      },
      false,
    );
    const verifyOutput = asObject(verifyData["verify_challenge"], "verify_challenge");
    sessionToken = asString(
      verifyOutput["verify_challenge_output_session_token"],
      "verify_challenge_output_session_token",
    );
    const validUntil = Date.parse(
      asString(
        verifyOutput["verify_challenge_output_valid_until"],
        "verify_challenge_output_valid_until",
      ),
    );
    if (Number.isNaN(validUntil)) {
      throw unexpectedResponse("verify_challenge_output_valid_until", "is not a parseable date");
    }
    validUntilMs = validUntil;
  }

  async function ensureAuth(): Promise<void> {
    if (sessionToken !== undefined && now() < validUntilMs - SESSION_EXPIRY_BUFFER_MS) {
      return;
    }
    pendingAuth ??= (async () => {
      try {
        await authenticate();
      } finally {
        pendingAuth = undefined;
      }
    })();
    await pendingAuth;
  }

  async function authedPost(
    operationName: string,
    query: string,
    variables: JsonObject,
  ): Promise<JsonObject> {
    await ensureAuth();
    try {
      return await post(operationName, query, variables, true);
    } catch (error) {
      if (error instanceof SparkRequestError && error.code === "unauthenticated") {
        sessionToken = undefined;
        await ensureAuth();
        return post(operationName, query, variables, true);
      }
      throw error;
    }
  }

  return {
    async swapFeeEstimate(amountSats: number): Promise<number> {
      if (!Number.isSafeInteger(amountSats) || amountSats <= 0) {
        throw new SparkInputError("amount sats must be a positive integer");
      }
      const data = await authedPost("LeavesSwapFeeEstimate", LEAVES_SWAP_FEE_ESTIMATE, {
        total_amount_sats: amountSats,
      });
      const output = asObject(data["leaves_swap_fee_estimate"], "leaves_swap_fee_estimate");
      return currencyAmountSats(
        output["leaves_swap_fee_estimate_output_fee_estimate"],
        "leaves_swap_fee_estimate_output_fee_estimate",
      );
    },

    async requestSwap(request: SspSwapRequest): Promise<SspSwapResult> {
      const data = await authedPost("RequestSwap", REQUEST_SWAP, {
        adaptor_pubkey: bytesToHex(request.adaptorPublicKey),
        total_amount_sats: request.totalAmountSats,
        target_amount_sats: [...request.targetAmountsSats],
        fee_sats: request.feeSats,
        user_leaves: request.userLeaves.map((leaf) => ({
          leaf_id: leaf.leafId,
          raw_unsigned_refund_transaction: bytesToHex(leaf.rawUnsignedRefundTransaction),
          adaptor_added_signature: bytesToHex(leaf.adaptorAddedSignature),
        })),
        user_outbound_transfer_external_id: request.userOutboundTransferId,
      });
      const output = asObject(data["request_swap"], "request_swap");
      const swapRequest = asObject(output["request"], "request_swap.request");
      const status = asString(
        swapRequest["leaves_swap_request_status"],
        "leaves_swap_request_status",
      );
      const swapLeaves = swapRequest["leaves_swap_request_swap_leaves"];
      if (!Array.isArray(swapLeaves) || swapLeaves.length === 0) {
        throw unexpectedResponse("leaves_swap_request_swap_leaves", "is missing or empty");
      }
      // Terminal failure/failing states of the live SparkLeavesSwapRequestStatus enum —
      // the upstream JS list is stale; Breez models.rs carries the current values.
      if (SWAP_FAILED.has(status)) {
        throw new SparkRequestError(`ssp leaves swap ${status.toLowerCase()}`, {
          code: "swap_failed",
        });
      }
      const inbound = asObject(
        swapRequest["leaves_swap_request_inbound_transfer"],
        "leaves_swap_request_inbound_transfer",
      );
      const inboundTransferId = asString(inbound["transfer_spark_id"], "transfer_spark_id");
      const feeSats = currencyAmountSats(
        swapRequest["leaves_swap_request_fee"],
        "leaves_swap_request_fee",
      );
      return { status, inboundTransferId, feeSats };
    },

    async requestLightningReceive(
      request: SspLightningReceiveRequest,
    ): Promise<SspLightningReceiveResult> {
      if (!Number.isSafeInteger(request.amountSats) || request.amountSats < 0) {
        throw new SparkInputError("amount sats must be a non-negative integer");
      }
      if (!Number.isSafeInteger(request.expirySecs) || request.expirySecs <= 0) {
        throw new SparkInputError("expiry secs must be a positive integer");
      }
      const data = await authedPost("RequestLightningReceive", REQUEST_LIGHTNING_RECEIVE, {
        network: request.network === "mainnet" ? "MAINNET" : "REGTEST",
        amount_sats: request.amountSats,
        payment_hash: bytesToHex(request.paymentHash),
        expiry_secs: request.expirySecs,
        memo: request.memo,
        include_spark_address: request.includeSparkAddress,
        receiver_identity_pubkey: bytesToHex(request.receiverIdentityPublicKey),
        description_hash:
          request.descriptionHash === undefined ? undefined : bytesToHex(request.descriptionHash),
        spark_invoice: undefined,
      });
      const output = asObject(data["request_lightning_receive"], "request_lightning_receive");
      return parseLightningReceive(
        asObject(output["request"], "request_lightning_receive.request"),
        "request_lightning_receive.request",
      );
    },

    async requestLightningSend(request: SspLightningSendRequest): Promise<SspLightningSendResult> {
      const data = await authedPost("RequestLightningSend", REQUEST_LIGHTNING_SEND, {
        encoded_invoice: request.encodedInvoice,
        amount_sats: request.amountSats,
        // The transfer id keys the request; the SSP refuses `idempotency_key` alongside it.
        idempotency_key: undefined,
        user_outbound_transfer_external_id: request.userOutboundTransferExternalId,
      });
      const output = asObject(data["request_lightning_send"], "request_lightning_send");
      return parseLightningSend(
        asObject(output["request"], "request_lightning_send.request"),
        "request_lightning_send.request",
      );
    },

    async lightningSendFeeEstimate(encodedInvoice: string, amountSats?: number): Promise<number> {
      const data = await authedPost("LightningSendFeeEstimate", LIGHTNING_SEND_FEE_ESTIMATE, {
        encoded_invoice: encodedInvoice,
        amount_sats: amountSats,
      });
      const output = asObject(data["lightning_send_fee_estimate"], "lightning_send_fee_estimate");
      return feeAmountSats(
        output["lightning_send_fee_estimate_output_fee_estimate"],
        "lightning_send_fee_estimate_output_fee_estimate",
      );
    },

    async lightningSendRequest(id: string): Promise<SspLightningSendResult> {
      const data = await authedPost("UserRequest", USER_REQUEST, { request_id: id });
      const userRequest = data["user_request"];
      if (userRequest === undefined || userRequest === null) {
        throw unexpectedResponse("user_request", "is missing");
      }
      const request = asObject(userRequest, "user_request");
      if (request["__typename"] !== "LightningSendRequest") {
        throw unexpectedResponse("user_request.__typename", `is ${String(request["__typename"])}`);
      }
      return parseLightningSend(request, "user_request");
    },

    async lightningReceiveRequest(id: string): Promise<SspLightningReceiveResult> {
      const data = await authedPost("UserRequest", USER_REQUEST, { request_id: id });
      const userRequest = data["user_request"];
      if (userRequest === undefined || userRequest === null) {
        throw unexpectedResponse("user_request", "is missing");
      }
      const request = asObject(userRequest, "user_request");
      if (request["__typename"] !== "LightningReceiveRequest") {
        throw unexpectedResponse("user_request.__typename", `is ${String(request["__typename"])}`);
      }
      return parseLightningReceive(request, "user_request");
    },

    async coopExitFeeQuote(
      leafIds: ReadonlyArray<string>,
      address: string,
    ): Promise<SspCoopExitFeeQuote> {
      const data = await authedPost("CoopExitFeeQuote", COOP_EXIT_FEE_QUOTE, {
        leaf_external_ids: [...leafIds],
        withdrawal_address: address,
      });
      const output = asObject(data["coop_exit_fee_quote"], "coop_exit_fee_quote");
      return parseCoopExitQuote(
        asObject(output["coop_exit_fee_quote_quote"], "coop_exit_fee_quote.quote"),
        "coop_exit_fee_quote.quote",
      );
    },

    async requestCoopExit(request: SspCoopExitRequest): Promise<SspCoopExitResult> {
      if (request.leafIds.length === 0) {
        throw new SparkInputError("requestCoopExit: leaf ids must not be empty");
      }
      const data = await authedPost("RequestCoopExit", REQUEST_COOP_EXIT, {
        leaf_external_ids: [...request.leafIds],
        withdrawal_address: request.withdrawalAddress,
        exit_speed: request.exitSpeed,
        withdraw_all: request.withdrawAll,
        user_outbound_transfer_external_id: request.userOutboundTransferExternalId,
        // Fee-deduction mode only: no fee leaves, quote id or idempotency key.
        idempotency_key: undefined,
        fee_leaf_external_ids: undefined,
        fee_quote_id: undefined,
      });
      const output = asObject(data["request_coop_exit"], "request_coop_exit");
      return parseCoopExitResult(
        asObject(output["request"], "request_coop_exit.request"),
        "request_coop_exit.request",
      );
    },

    async completeCoopExit(request: {
      coopExitRequestId: string;
      userOutboundTransferExternalId: string;
    }): Promise<SspCoopExitStatus> {
      const data = await authedPost("CompleteCoopExit", COMPLETE_COOP_EXIT, {
        coop_exit_request_id: request.coopExitRequestId,
        user_outbound_transfer_external_id: request.userOutboundTransferExternalId,
      });
      const output = asObject(data["complete_coop_exit"], "complete_coop_exit");
      return parseCoopExitStatus(
        asObject(output["request"], "complete_coop_exit.request"),
        "complete_coop_exit.request",
      );
    },

    async coopExitRequest(id: string): Promise<SspCoopExitStatus> {
      const data = await authedPost("UserRequest", USER_REQUEST, { request_id: id });
      const userRequest = data["user_request"];
      if (userRequest === undefined || userRequest === null) {
        throw unexpectedResponse("user_request", "is missing");
      }
      const request = asObject(userRequest, "user_request");
      if (request["__typename"] !== "CoopExitRequest") {
        throw unexpectedResponse("user_request.__typename", `is ${String(request["__typename"])}`);
      }
      return parseCoopExitStatus(request, "user_request");
    },
  };
}
