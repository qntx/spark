import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { expect, test } from "vite-plus/test";

import { sspChallengeDigest } from "../src/core/hashing/index.ts";
import { SparkRequestError } from "../src/errors/index.ts";
import { createSspClient } from "../src/ssp/index.ts";
import { createTestSigner } from "./support/test-signer.ts";

const SIGNER = createTestSigner(new Uint8Array(32).fill(7));

type CapturedRequest = {
  operationName: string;
  variables: Record<string, unknown>;
  authorization: string | null;
};

function fakeSsp(handlers: {
  challenge?: string;
  token?: string;
  validUntil?: string;
  feeValue?: number;
  failFirstAuthed?: boolean;
  graphqlError?: { message: string; code?: string };
}) {
  const requests: CapturedRequest[] = [];
  const challengeBytes = new Uint8Array(32).fill(9);
  const challenge = handlers.challenge ?? base64.encode(challengeBytes);
  let authedCalls = 0;
  const fetchImpl: typeof globalThis.fetch = async (_input, init) => {
    const body = JSON.parse(String(init?.body)) as {
      operationName: string;
      variables: Record<string, unknown>;
    };
    const authorization = new Headers(init?.headers).get("authorization");
    requests.push({ operationName: body.operationName, variables: body.variables, authorization });
    const json = async (data: unknown) => Promise.resolve(Response.json({ data }));
    switch (body.operationName) {
      case "GetChallenge":
        return json({
          get_challenge: { get_challenge_output_protected_challenge: challenge },
        });
      case "VerifyChallenge": {
        const signature = base64.decode(String(body.variables["signature"]));
        const digest = sspChallengeDigest(String(body.variables["protected_challenge"]));
        const valid = secp256k1.verify(
          signature,
          digest,
          hexToBytes(String(body.variables["identity_public_key"])),
          {
            format: "der",
            prehash: false,
          },
        );
        if (!valid) {
          return Response.json({ errors: [{ message: "bad signature" }] });
        }
        return json({
          verify_challenge: {
            verify_challenge_output_session_token: handlers.token ?? "ssp-token-1",
            verify_challenge_output_valid_until:
              handlers.validUntil ?? new Date(Date.now() + 30 * 60 * 1000).toISOString(),
          },
        });
      }
      case "LeavesSwapFeeEstimate":
        authedCalls++;
        if (handlers.failFirstAuthed && authedCalls === 1) {
          return new Response("unauthorized", { status: 401 });
        }
        if (handlers.graphqlError !== undefined) {
          const err: Record<string, unknown> = { message: handlers.graphqlError.message };
          if (handlers.graphqlError.code !== undefined) {
            err["extensions"] = { code: handlers.graphqlError.code };
          }
          return Response.json({ errors: [err], data: null });
        }
        return json({
          leaves_swap_fee_estimate: {
            leaves_swap_fee_estimate_output_fee_estimate: {
              currency_amount_original_value: handlers.feeValue ?? 250,
              currency_amount_original_unit: "SATOSHI",
            },
          },
        });

      default:
        return new Response("not found", { status: 404 });
    }
  };
  return { fetchImpl, requests };
}

const SSP_OPTS = { baseUrl: "https://ssp.test", graphqlPath: "graphql/spark/2025-03-19" };

test("authenticates then answers a fee estimate with the bearer token", async () => {
  const { fetchImpl, requests } = fakeSsp({ feeValue: 333 });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  const estimate = await client.leavesSwapFeeEstimate(100_000);
  expect(estimate).toStrictEqual({ valueSats: 333, unit: "SATOSHI" });
  expect(requests.map((r) => r.operationName)).toStrictEqual([
    "GetChallenge",
    "VerifyChallenge",
    "LeavesSwapFeeEstimate",
  ]);
  const [challengeReq] = requests;
  expect(challengeReq?.variables["public_key"]).toBe(bytesToHex(await SIGNER.identityPublicKey()));
  expect(requests[2]?.authorization).toBe("Bearer ssp-token-1");
});

test("re-authenticates once when the session token is rejected", async () => {
  const { fetchImpl, requests } = fakeSsp({ failFirstAuthed: true });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  const estimate = await client.leavesSwapFeeEstimate(50_000);
  expect(estimate.valueSats).toBe(250);
  expect(requests.map((r) => r.operationName)).toStrictEqual([
    "GetChallenge",
    "VerifyChallenge",
    "LeavesSwapFeeEstimate",
    "GetChallenge",
    "VerifyChallenge",
    "LeavesSwapFeeEstimate",
  ]);
});

test("graphql errors map to SparkRequestError with the extensions code", async () => {
  const { fetchImpl } = fakeSsp({
    graphqlError: { message: "amount too small", code: "BAD_USER_INPUT" },
  });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  const error = await client.leavesSwapFeeEstimate(1).catch((error: unknown) => error);
  expect(error).toBeInstanceOf(SparkRequestError);
  expect((error as SparkRequestError).code).toBe("BAD_USER_INPUT");
  expect((error as SparkRequestError).message).toContain("amount too small");
});
