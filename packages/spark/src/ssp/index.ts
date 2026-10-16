import { bytesToHex } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";

import { SESSION_EXPIRY_BUFFER_MS } from "../core/session.ts";
import { SparkInputError, SparkRequestError } from "../errors/index.ts";
import type { SparkSigner } from "../signer/types.ts";

export type SspClient = {
  /** `leaves_swap_fee_estimate` — the sats fee the SSP quotes for swapping `amountSats`. */
  readonly swapFeeEstimate: (amountSats: number) => Promise<number>;
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
      const fee = asObject(
        output["leaves_swap_fee_estimate_output_fee_estimate"],
        "leaves_swap_fee_estimate_output_fee_estimate",
      );
      const unit = asString(fee["currency_amount_original_unit"], "currency_amount_original_unit");
      if (unit !== "SATOSHI") {
        throw unexpectedResponse("currency_amount_original_unit", `is not SATOSHI`);
      }
      return asSats(fee["currency_amount_original_value"], "currency_amount_original_value");
    },
  };
}
