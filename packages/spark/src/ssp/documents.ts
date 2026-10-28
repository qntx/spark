// Query documents copied verbatim (selections, aliases, operation names) from upstream
// sdks/js/packages/spark-sdk/src/graphql (buildonspark/spark@0b3a32a).
export const GET_CHALLENGE = `
mutation GetChallenge($public_key: PublicKey!) {
  get_challenge(input: { public_key: $public_key }) {
    ...GetChallengeOutputFragment
  }
}

fragment GetChallengeOutputFragment on GetChallengeOutput {
  __typename
  get_challenge_output_protected_challenge: protected_challenge
}`;

export const VERIFY_CHALLENGE = `
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

export const LEAVES_SWAP_FEE_ESTIMATE = `
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
export const SWAP_FAILED: ReadonlySet<string> = new Set([
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

export const REQUEST_SWAP = `
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
export const REQUEST_LIGHTNING_RECEIVE = `
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

export const REQUEST_LIGHTNING_SEND = `
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

export const LIGHTNING_SEND_FEE_ESTIMATE = `
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

export const COOP_EXIT_FEE_QUOTE = `
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

export const REQUEST_COOP_EXIT = `
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

export const COMPLETE_COOP_EXIT = `
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

export const STATIC_DEPOSIT_QUOTE = `
  query StaticDepositQuote(
    $transaction_id: String!
    $output_index: Int!
    $network: BitcoinNetwork!
  ) {
    static_deposit_quote(
      input: {
        transaction_id: $transaction_id,
        output_index: $output_index,
        network: $network
      }
    ) {
      ...StaticDepositQuoteOutputFragment
    }
  }

fragment StaticDepositQuoteOutputFragment on StaticDepositQuoteOutput {
    __typename
    static_deposit_quote_output_transaction_id: transaction_id
    static_deposit_quote_output_output_index: output_index
    static_deposit_quote_output_network: network
    static_deposit_quote_output_credit_amount_sats: credit_amount_sats
    static_deposit_quote_output_signature: signature
}`;

// Upstream JS's document sends deposit_secret_key in cleartext; the Lightspark schema
// (ClaimStaticDepositInput — via breez-spark-sdk's crates/spark/schema/spark.graphql) accepts
// encrypted_deposit_secret_key, the key ECIES-sealed to the SSP identity, and deprecates
// request_type. This document sends neither — the raw key never leaves the signer.
export const CLAIM_STATIC_DEPOSIT = `
  mutation ClaimStaticDeposit(
    $transaction_id: String!
    $output_index: Int!
    $network: BitcoinNetwork!
    $credit_amount_sats: Long
    $encrypted_deposit_secret_key: String!
    $signature: String!
    $quote_signature: String!
  ) {
    claim_static_deposit(input: {
      transaction_id: $transaction_id
      output_index: $output_index
      network: $network
      credit_amount_sats: $credit_amount_sats
      max_fee_sats: null
      encrypted_deposit_secret_key: $encrypted_deposit_secret_key
      signature: $signature
      quote_signature: $quote_signature
    }) {
      ...ClaimStaticDepositOutputFragment
    }
  }

fragment ClaimStaticDepositOutputFragment on ClaimStaticDepositOutput {
    __typename
    claim_static_deposit_output_transfer_id: transfer_id
}`;

// Upstream's UserRequest query — the document its `getLightningReceiveRequest`/
// `getLightningSendRequest` use — copied verbatim including the other request-type fragments.
export const USER_REQUEST = `
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

// Query documents copied verbatim (selections, aliases, operation names) from upstream
// sdks/js/packages/spark-sdk/src/graphql/queries/Transfers.ts (buildonspark/spark@0b3a32a),
// trimmed to the fields we parse — the fragments keep their upstream aliasing.
export const TRANSFERS = `
query Transfers($transfer_spark_ids: [UUID!]!) {
  transfers(transfer_spark_ids: $transfer_spark_ids) {
    ...TransferFragment
    transfer_user_request: user_request {
      ...UserRequestFragment
    }
  }
}

fragment TransferFragment on Transfer {
  __typename
  transfer_spark_id: spark_id
}

fragment CurrencyAmountFragment on CurrencyAmount {
  __typename
  currency_amount_original_value: original_value
  currency_amount_original_unit: original_unit
}

fragment TransferSparkIdFragment on Transfer {
  __typename
  transfer_spark_id: spark_id
}

fragment UserRequestFragment on UserRequest {
  __typename
  ... on ClaimStaticDeposit {
    claim_static_deposit_id: id
    claim_static_deposit_deposit_amount: deposit_amount {
      ...CurrencyAmountFragment
    }
    claim_static_deposit_credit_amount: credit_amount {
      ...CurrencyAmountFragment
    }
    claim_static_deposit_max_fee: max_fee {
      ...CurrencyAmountFragment
    }
    claim_static_deposit_status: status
    claim_static_deposit_transaction_id: transaction_id
    claim_static_deposit_output_index: output_index
    claim_static_deposit_transfer_spark_id: transfer_spark_id
  }
  ... on CoopExitRequest {
    coop_exit_request_id: id
    coop_exit_request_fee: fee {
      ...CurrencyAmountFragment
    }
    coop_exit_request_l1_broadcast_fee: l1_broadcast_fee {
      ...CurrencyAmountFragment
    }
    coop_exit_request_status: status
    coop_exit_request_coop_exit_txid: coop_exit_txid
    coop_exit_request_transfer: transfer {
      ...TransferSparkIdFragment
    }
  }
  ... on LeavesSwapRequest {
    leaves_swap_request_id: id
    leaves_swap_request_status: status
  }
  ... on LightningReceiveRequest {
    lightning_receive_request_id: id
    lightning_receive_request_invoice: invoice {
      __typename
      invoice_encoded_invoice: encoded_invoice
      invoice_payment_hash: payment_hash
    }
    lightning_receive_request_status: status
    lightning_receive_request_transfer: transfer {
      ...TransferSparkIdFragment
    }
    lightning_receive_request_payment_preimage: payment_preimage
  }
  ... on LightningSendRequest {
    lightning_send_request_id: id
    lightning_send_request_encoded_invoice: encoded_invoice
    lightning_send_request_fee: fee {
      ...CurrencyAmountFragment
    }
    lightning_send_request_status: status
    lightning_send_request_transfer: transfer {
      ...TransferSparkIdFragment
    }
    lightning_send_request_payment_preimage: payment_preimage
  }
}`;
