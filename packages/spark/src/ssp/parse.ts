import { hexToBytes } from "@noble/hashes/utils.js";

import { SparkRequestError } from "../errors/index.ts";
import type {
  SspCoopExitFeeQuote,
  SspCoopExitResult,
  SspCoopExitStatus,
  SspLightningReceiveResult,
  SspLightningSendResult,
  SspTransferResult,
  SspUserRequest,
} from "./types.ts";

export type JsonObject = Record<string, unknown>;

/** A malformed SSP response is a server fault, not caller input. */
export function unexpectedResponse(field: string, rule: string): SparkRequestError {
  return new SparkRequestError(`ssp response: ${field} ${rule}`, {
    code: "unexpected_response",
  });
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asObject(value: unknown, field: string): JsonObject {
  if (!isJsonObject(value)) {
    throw unexpectedResponse(field, "is not an object");
  }
  return value;
}

export function asString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw unexpectedResponse(field, "is not a string");
  }
  return value;
}

export function asSats(value: unknown, field: string): number {
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

/** A GraphQL Int field used as an array/output index — a number, not a decimal string. */
export function asIndex(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw unexpectedResponse(field, "is not a non-negative integer");
  }
  return value;
}

/** CurrencyAmount in SATOSHI → sats; any other unit is an unexpected response. */
export function currencyAmountSats(value: unknown, field: string): number {
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
export function feeAmountSats(value: unknown, field: string): number {
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

/** Optional hex-encoded field → bytes; absent or null becomes undefined. */
function optionalHexBytes(value: unknown, field: string): Uint8Array | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  return asHexBytes(value, field);
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
  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(txid);
  } catch {
    throw unexpectedResponse(field, "is not a 32-byte hex txid");
  }
  if (bytes.length !== 32) {
    throw unexpectedResponse(field, "is not a 32-byte hex txid");
  }
  return txid;
}

export function parseLightningReceive(
  request: JsonObject,
  field: string,
): SspLightningReceiveResult {
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

export function parseLightningSend(request: JsonObject, field: string): SspLightningSendResult {
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

export function parseCoopExitQuote(quote: JsonObject, field: string): SspCoopExitFeeQuote {
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
export function parseCoopExitStatus(request: JsonObject, field: string): SspCoopExitStatus {
  const transferId = optionalTransferId(
    request["coop_exit_request_transfer"],
    `${field}.coop_exit_request_transfer`,
  );
  const rawCoopExitTransaction = optionalHexBytes(
    request["coop_exit_request_raw_coop_exit_transaction"],
    `${field}.coop_exit_request_raw_coop_exit_transaction`,
  );
  return {
    id: asString(request["coop_exit_request_id"], `${field}.coop_exit_request_id`),
    status: asString(request["coop_exit_request_status"], `${field}.coop_exit_request_status`),
    ...(transferId === undefined ? {} : { transferId }),
    ...(rawCoopExitTransaction === undefined ? {} : { rawCoopExitTransaction }),
  };
}

/** Request_coop_exit additionally returns the payout + connector transactions to validate. */
export function parseCoopExitResult(request: JsonObject, field: string): SspCoopExitResult {
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

function optionalTxidHex(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  return asTxidHex(value, field);
}

/** The `transfers` query's per-item parse: id plus its user_request union member (or none). */
export function parseTransfersResponse(data: JsonObject): ReadonlyArray<SspTransferResult> {
  const items = data["transfers"];
  if (!Array.isArray(items)) {
    throw unexpectedResponse("transfers", "is not an array");
  }
  return items.map((item, index) => {
    const field = `transfers[${index}]`;
    const entry = asObject(item, field);
    const request = entry["transfer_user_request"];
    return {
      transferId: asString(entry["transfer_spark_id"], `${field}.transfer_spark_id`),
      request:
        request === undefined || request === null
          ? undefined
          : parseUserRequest(
              asObject(request, `${field}.transfer_user_request`),
              `${field}.transfer_user_request`,
            ),
    };
  });
}

/**
 * Discriminated `user_request` parse. An unknown `__typename` is a variant we do not model, not a
 * malformed response.
 */
export function parseUserRequest(request: JsonObject, field: string): SspUserRequest | undefined {
  switch (request["__typename"]) {
    case "LightningSendRequest": {
      const send = parseLightningSend(request, field);
      return {
        kind: "lightning-send",
        status: send.status,
        invoice: send.encodedInvoice,
        feeSats: send.feeSats,
        ...(send.paymentPreimage === undefined ? {} : { preimage: send.paymentPreimage }),
      };
    }
    case "LightningReceiveRequest": {
      const receive = parseLightningReceive(request, field);
      return {
        kind: "lightning-receive",
        status: receive.status,
        invoice: receive.invoice,
        ...(receive.paymentPreimage === undefined ? {} : { preimage: receive.paymentPreimage }),
      };
    }
    case "CoopExitRequest":
      return parseCoopExitRequest(request, field);
    case "ClaimStaticDeposit":
      return parseStaticDepositRequest(request, field);
    case "LeavesSwapRequest":
      return { kind: "leaves-swap" };
    default:
      return undefined;
  }
}

/** `coop_exit` for history: fee = `fee` + `l1_broadcast_fee`, status and payout txid. */
function parseCoopExitRequest(request: JsonObject, field: string): SspUserRequest {
  const txid = optionalTxidHex(
    request["coop_exit_request_coop_exit_txid"],
    `${field}.coop_exit_request_coop_exit_txid`,
  );
  return {
    kind: "coop-exit",
    status: asString(request["coop_exit_request_status"], `${field}.coop_exit_request_status`),
    feeSats:
      currencyAmountSats(request["coop_exit_request_fee"], `${field}.coop_exit_request_fee`) +
      currencyAmountSats(
        request["coop_exit_request_l1_broadcast_fee"],
        `${field}.coop_exit_request_l1_broadcast_fee`,
      ),
    ...(txid === undefined ? {} : { txid }),
  };
}

/** `claim_static_deposit` for history: the claim's txid, vout and credited amount. */
function parseStaticDepositRequest(request: JsonObject, field: string): SspUserRequest {
  return {
    kind: "static-deposit",
    txid: asTxidHex(
      request["claim_static_deposit_transaction_id"],
      `${field}.claim_static_deposit_transaction_id`,
    ),
    vout: asIndex(
      request["claim_static_deposit_output_index"],
      `${field}.claim_static_deposit_output_index`,
    ),
    depositAmountSats: currencyAmountSats(
      request["claim_static_deposit_deposit_amount"],
      `${field}.claim_static_deposit_deposit_amount`,
    ),
    creditAmountSats: currencyAmountSats(
      request["claim_static_deposit_credit_amount"],
      `${field}.claim_static_deposit_credit_amount`,
    ),
  };
}
