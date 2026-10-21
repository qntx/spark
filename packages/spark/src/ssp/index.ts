import { bytesToHex } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";

import type { SparkNetwork } from "../core/network.ts";
import { SESSION_EXPIRY_BUFFER_MS } from "../core/session.ts";
import { serverErrorText } from "../core/text.ts";
import { defaultSleep } from "../core/time.ts";
import { SparkInputError, SparkRequestError } from "../errors/index.ts";
import type { SparkSigner } from "../signer/types.ts";
import {
  CLAIM_STATIC_DEPOSIT,
  COMPLETE_COOP_EXIT,
  COOP_EXIT_FEE_QUOTE,
  GET_CHALLENGE,
  LEAVES_SWAP_FEE_ESTIMATE,
  LIGHTNING_SEND_FEE_ESTIMATE,
  REQUEST_COOP_EXIT,
  REQUEST_LIGHTNING_RECEIVE,
  REQUEST_LIGHTNING_SEND,
  REQUEST_SWAP,
  STATIC_DEPOSIT_QUOTE,
  SWAP_FAILED,
  USER_REQUEST,
  VERIFY_CHALLENGE,
} from "./documents.ts";
import {
  asObject,
  asSats,
  asString,
  currencyAmountSats,
  feeAmountSats,
  parseCoopExitQuote,
  parseCoopExitResult,
  parseCoopExitStatus,
  parseLightningReceive,
  parseLightningSend,
  unexpectedResponse,
} from "./parse.ts";
import type { JsonObject } from "./parse.ts";
import type {
  SspClaimStaticDepositRequest,
  SspClient,
  SspClaimStaticDepositResult,
  SspCoopExitFeeQuote,
  SspCoopExitRequest,
  SspCoopExitResult,
  SspCoopExitStatus,
  SspLightningReceiveRequest,
  SspLightningReceiveResult,
  SspLightningSendRequest,
  SspLightningSendResult,
  SspStaticDepositQuote,
  SspSwapRequest,
  SspSwapResult,
} from "./types.ts";

export type {
  SspClaimStaticDepositRequest,
  SspClaimStaticDepositResult,
  SspClient,
  SspCoopExitFeeQuote,
  SspCoopExitRequest,
  SspCoopExitResult,
  SspCoopExitSpeed,
  SspCoopExitStatus,
  SspDeps,
  SspLightningReceiveRequest,
  SspLightningReceiveResult,
  SspLightningSendRequest,
  SspLightningSendResult,
  SspStaticDepositQuote,
  SspSwapLeaf,
  SspSwapRequest,
  SspSwapResult,
} from "./types.ts";

/**
 * Minimal GraphQL-over-POST client for the SSP. Authenticates with GetChallenge → `signIdentity`
 * (`ssp-challenge`) → VerifyChallenge, sends `Authorization: Bearer <session token>`, and
 * re-authenticates once on a 401. Only the queries this stage needs are supported.
 */
/** Whole-round-trip bound for every GraphQL POST to the SSP. */
const SSP_REQUEST_TIMEOUT_MS = 60_000;
/** Read-only queries retry transport/timeout failures this many times total; mutations never retry. */
const SSP_READ_MAX_ATTEMPTS = 3;
const SSP_READ_RETRY_BASE_MS = 1000;

export function createSspClient(options: {
  readonly baseUrl: string;
  readonly graphqlPath: string;
  readonly signer: SparkSigner;
  readonly fetch: typeof globalThis.fetch;
  readonly now?: () => number;
  /** Whole-round-trip bound per GraphQL POST; defaults to {@link SSP_REQUEST_TIMEOUT_MS}. */
  readonly requestTimeoutMs?: number;
  /** Backoff source for read-query retries; defaults to a setTimeout sleep. */
  readonly sleep?: (ms: number) => Promise<void>;
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
    // AbortController + setTimeout is the Hermes-safe way to bound the whole round trip —
    // request and body read — without an injected timer.
    const timeout = new AbortController();
    const timer = setTimeout(
      () => timeout.abort(),
      options.requestTimeoutMs ?? SSP_REQUEST_TIMEOUT_MS,
    );
    try {
      let response: Response;
      try {
        response = await options.fetch(endpoint, {
          method: "POST",
          headers,
          body: JSON.stringify({ operationName, query, variables }),
          signal: timeout.signal,
        });
      } catch (error) {
        if (timeout.signal.aborted) {
          throw new SparkRequestError("ssp request timed out", {
            code: "deadline_exceeded",
            cause: error,
          });
        }
        throw new SparkRequestError("ssp request failed", {
          code: "unavailable",
          cause: error,
        });
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
        if (timeout.signal.aborted) {
          throw new SparkRequestError("ssp request timed out", {
            code: "deadline_exceeded",
            cause: error,
          });
        }
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
    } finally {
      clearTimeout(timer);
    }
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

  const sleep = options.sleep ?? defaultSleep;
  /**
   * `authedPost` for read-only queries only. A dropped connection or a timed-out read is safe to
   * repeat — a mutation is not, so mutations keep calling `authedPost` directly and surface the
   * first transport failure to the caller's own recovery path (transfer id, inputOutputIds).
   */
  async function readPost(
    operationName: string,
    query: string,
    variables: JsonObject,
  ): Promise<JsonObject> {
    for (let attempt = 1; ; attempt++) {
      try {
        // oxlint-disable-next-line no-await-in-loop -- retries are sequential by definition
        return await authedPost(operationName, query, variables);
      } catch (error) {
        const retryable =
          error instanceof SparkRequestError &&
          (error.code === "unavailable" || error.code === "deadline_exceeded");
        if (!retryable || attempt >= SSP_READ_MAX_ATTEMPTS) {
          throw error;
        }
        // oxlint-disable-next-line no-await-in-loop -- retries are sequential by definition
        await sleep(SSP_READ_RETRY_BASE_MS * 2 ** (attempt - 1));
      }
    }
  }

  return {
    async swapFeeEstimate(amountSats: number): Promise<number> {
      if (!Number.isSafeInteger(amountSats) || amountSats <= 0) {
        throw new SparkInputError("amount sats must be a positive integer");
      }
      const data = await readPost("LeavesSwapFeeEstimate", LEAVES_SWAP_FEE_ESTIMATE, {
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
      const data = await readPost("LightningSendFeeEstimate", LIGHTNING_SEND_FEE_ESTIMATE, {
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
      const data = await readPost("UserRequest", USER_REQUEST, { request_id: id });
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
      const data = await readPost("UserRequest", USER_REQUEST, { request_id: id });
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
      const data = await readPost("CoopExitFeeQuote", COOP_EXIT_FEE_QUOTE, {
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
      const data = await readPost("UserRequest", USER_REQUEST, { request_id: id });
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

    async staticDepositQuote(request: {
      transactionId: string;
      outputIndex: number;
      network: SparkNetwork;
    }): Promise<SspStaticDepositQuote> {
      const data = await readPost("StaticDepositQuote", STATIC_DEPOSIT_QUOTE, {
        transaction_id: request.transactionId,
        output_index: request.outputIndex,
        network: request.network === "mainnet" ? "MAINNET" : "REGTEST",
      });
      const output = asObject(data["static_deposit_quote"], "static_deposit_quote");
      const field = "static_deposit_quote";
      if (
        asString(
          output["static_deposit_quote_output_transaction_id"],
          `${field}.static_deposit_quote_output_transaction_id`,
        ) !== request.transactionId ||
        asSats(
          output["static_deposit_quote_output_output_index"],
          `${field}.static_deposit_quote_output_output_index`,
        ) !== request.outputIndex
      ) {
        throw unexpectedResponse(field, "quotes a different deposit output than requested");
      }
      return {
        creditAmountSats: asSats(
          output["static_deposit_quote_output_credit_amount_sats"],
          `${field}.static_deposit_quote_output_credit_amount_sats`,
        ),
        signature: asString(
          output["static_deposit_quote_output_signature"],
          `${field}.static_deposit_quote_output_signature`,
        ),
      };
    },

    async claimStaticDeposit(
      request: SspClaimStaticDepositRequest,
    ): Promise<SspClaimStaticDepositResult> {
      const data = await authedPost("ClaimStaticDeposit", CLAIM_STATIC_DEPOSIT, {
        transaction_id: request.transactionId,
        output_index: request.outputIndex,
        network: request.network === "mainnet" ? "MAINNET" : "REGTEST",
        credit_amount_sats: request.creditAmountSats,
        encrypted_deposit_secret_key: request.encryptedSecretKey,
        signature: request.signature,
        quote_signature: request.quoteSignature,
      });
      const output = asObject(data["claim_static_deposit"], "claim_static_deposit");
      const transferId = output["claim_static_deposit_output_transfer_id"];
      if (transferId === undefined || transferId === null) {
        return {};
      }
      return {
        transferId: asString(
          transferId,
          "claim_static_deposit.claim_static_deposit_output_transfer_id",
        ),
      };
    },
  };
}
