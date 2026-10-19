import { bytesToHex } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";

import { SESSION_EXPIRY_BUFFER_MS } from "../core/session.ts";
import { SparkInputError, SparkRequestError } from "../errors/index.ts";
import type { SparkSigner } from "../signer/types.ts";

export type SspClient = {
  /** `leaves_swap_fee_estimate` — the sats fee the SSP quotes for swapping `amountSats`. */
  readonly swapFeeEstimate: (amountSats: number) => Promise<number>;
  /** `request_swap` — submits the adaptor-signed leaves swap; resolves to the inbound transfer. */
  readonly requestSwap: (request: SspSwapRequest) => Promise<SspSwapResult>;
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
  const n = typeof value === "string" ? Number(value) : value;
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 0) {
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
        `ssp error: ${asString(first["message"], "errors[0].message")}`,
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
      if (status === "FAILED") {
        throw new SparkRequestError("ssp leaves swap failed", { code: "swap_failed" });
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
  };
}
