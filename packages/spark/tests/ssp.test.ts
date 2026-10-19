import { toBinary } from "@bufbuild/protobuf";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { expect, test } from "vite-plus/test";

import { sspChallengeDigest } from "../src/core/hashing/index.ts";
import { ProtectedChallengeSchema } from "../src/proto/gen/ssp_authn_pb.ts";
import { createSspClient } from "../src/ssp/index.ts";
import { createTestSigner } from "./support/test-signer.ts";

const SIGNER = createTestSigner(new Uint8Array(32).fill(7));
const SIGNER_PUBLIC_KEY = secp256k1.getPublicKey(SIGNER.secretKey, true);

/** A valid ssp_authn.ProtectedChallenge issued to `publicKey`, base64-encoded. */
export function protectedChallengeFor(publicKey: Uint8Array): string {
  return base64.encode(
    toBinary(ProtectedChallengeSchema, {
      $typeName: "ssp_authn.ProtectedChallenge",
      version: 1,
      challenge: {
        $typeName: "ssp_authn.Challenge",
        version: 1,
        timestamp: 1_786_974_052n,
        nonce: new Uint8Array(32).fill(9),
        publicKey,
      },
      serverHmac: new Uint8Array(32).fill(7),
    }),
  );
}

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
  swap?: {
    status?: string;
    sparkId?: string | null;
    feeValue?: number | string;
    feeUnit?: string;
    swapLeaves?: unknown[];
  };
}) {
  const requests: CapturedRequest[] = [];
  const challenge = handlers.challenge ?? protectedChallengeFor(SIGNER_PUBLIC_KEY);
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
        const digest = sspChallengeDigest(
          String(body.variables["protected_challenge"]),
          hexToBytes(String(body.variables["identity_public_key"])),
        );
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

      case "RequestSwap": {
        const swap = handlers.swap ?? {};
        const inbound =
          swap.sparkId === null || (swap.sparkId === undefined && swap.status === "FAILED")
            ? null
            : {
                __typename: "Transfer",
                transfer_total_amount: {
                  __typename: "CurrencyAmount",
                  currency_amount_original_value: 0,
                  currency_amount_original_unit: "SATOSHI",
                },
                transfer_spark_id: swap.sparkId ?? "inbound-transfer-1",
                transfer_user_request: { id: "req-1" },
              };
        return json({
          request_swap: {
            request: {
              __typename: "LeavesSwapRequest",
              leaves_swap_request_id: "swap-1",
              leaves_swap_request_created_at: "2025-01-01T00:00:00Z",
              leaves_swap_request_updated_at: "2025-01-01T00:00:00Z",
              leaves_swap_request_network: "REGTEST",
              leaves_swap_request_status: swap.status ?? "SUCCEEDED",
              leaves_swap_request_total_amount: {
                __typename: "CurrencyAmount",
                currency_amount_original_value: 0,
                currency_amount_original_unit: "SATOSHI",
              },
              leaves_swap_request_target_amount: {
                __typename: "CurrencyAmount",
                currency_amount_original_value: 0,
                currency_amount_original_unit: "SATOSHI",
              },
              leaves_swap_request_fee: {
                __typename: "CurrencyAmount",
                currency_amount_original_value: swap.feeValue ?? 42,
                currency_amount_original_unit: swap.feeUnit ?? "SATOSHI",
              },
              leaves_swap_request_inbound_transfer: inbound,
              leaves_swap_request_outbound_transfer: null,
              leaves_swap_request_expires_at: null,
              leaves_swap_request_swap_leaves: swap.swapLeaves ?? [
                {
                  __typename: "SwapLeaf",
                  swap_leaf_leaf_id: "swap-leaf-1",
                },
              ],
            },
          },
        });
      }
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
  const estimate = await client.swapFeeEstimate(100_000);
  expect(estimate).toBe(333);
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
  const estimate = await client.swapFeeEstimate(50_000);
  expect(estimate).toBe(250);
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
  await expect(client.swapFeeEstimate(1)).rejects.toMatchObject({
    name: "SparkRequestError",
    code: "bad_user_input",
    message: expect.stringContaining("amount too small"),
  });
});

const SWAP_INPUT = {
  adaptorPublicKey: new Uint8Array(33).fill(2),
  totalAmountSats: 150,
  targetAmountsSats: [100],
  feeSats: 0,
  userLeaves: [
    {
      leafId: "leaf-1",
      rawUnsignedRefundTransaction: new Uint8Array([1, 2, 3]),
      adaptorAddedSignature: new Uint8Array(64).fill(4),
    },
  ],
  userOutboundTransferId: "01955cc1-0000-7000-8000-000000000001",
};

test("requestSwap sends hex variables and parses the inbound transfer + fee", async () => {
  const { fetchImpl, requests } = fakeSsp({ swap: { sparkId: "inbound-abc", feeValue: 17 } });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  const result = await client.requestSwap(SWAP_INPUT);
  expect(result).toStrictEqual({
    status: "SUCCEEDED",
    inboundTransferId: "inbound-abc",
    feeSats: 17,
  });
  const call = requests.find((r) => r.operationName === "RequestSwap");
  expect(call).toBeDefined();
  expect(call?.authorization).toBe("Bearer ssp-token-1");
  expect(call?.variables).toStrictEqual({
    adaptor_pubkey: bytesToHex(SWAP_INPUT.adaptorPublicKey),
    total_amount_sats: 150,
    target_amount_sats: [100],
    fee_sats: 0,
    user_leaves: [
      {
        leaf_id: "leaf-1",
        raw_unsigned_refund_transaction: bytesToHex(
          SWAP_INPUT.userLeaves[0]!.rawUnsignedRefundTransaction,
        ),
        adaptor_added_signature: bytesToHex(SWAP_INPUT.userLeaves[0]!.adaptorAddedSignature),
      },
    ],
    user_outbound_transfer_external_id: SWAP_INPUT.userOutboundTransferId,
  });
});

test("requestSwap maps terminal failure statuses to swap_failed", async () => {
  const results = await Promise.all(
    ["FAILED", "EXPIRED"].map(async (status) => {
      const { fetchImpl } = fakeSsp({ swap: { status } });
      const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
      return client.requestSwap(SWAP_INPUT).then(
        () => "resolved",
        (error: unknown) => (error as { code?: string }).code,
      );
    }),
  );
  expect(results).toStrictEqual(["swap_failed", "swap_failed"]);
});

test("requestSwap rejects a missing or empty swap_leaves list", async () => {
  const { fetchImpl } = fakeSsp({ swap: { swapLeaves: [] } });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  await expect(client.requestSwap(SWAP_INPUT)).rejects.toMatchObject({
    code: "unexpected_response",
    message: expect.stringContaining("swap_leaves"),
  });
});

test("requestSwap accepts a decimal-string fee but rejects non-decimal forms", async () => {
  const decimal = fakeSsp({ swap: { sparkId: "in-1", feeValue: "42" } });
  const ok = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: decimal.fetchImpl });
  await expect(ok.requestSwap(SWAP_INPUT)).resolves.toMatchObject({ feeSats: 42 });
  const results = await Promise.all(
    ["0x10", " 5 ", "1e3"].map(async (feeValue) => {
      const { fetchImpl } = fakeSsp({ swap: { feeValue } });
      const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
      return client.requestSwap(SWAP_INPUT).then(
        () => "resolved",
        (error: unknown) => (error as { code?: string }).code,
      );
    }),
  );
  expect(results).toStrictEqual([
    "unexpected_response",
    "unexpected_response",
    "unexpected_response",
  ]);
});

test("requestSwap rejects a missing inbound transfer spark id", async () => {
  const { fetchImpl } = fakeSsp({ swap: { sparkId: null } });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  await expect(client.requestSwap(SWAP_INPUT)).rejects.toMatchObject({
    code: "unexpected_response",
  });
});

test("requestSwap rejects a non-SATOSHI fee", async () => {
  const { fetchImpl } = fakeSsp({ swap: { feeUnit: "MILLISATOSHI" } });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  await expect(client.requestSwap(SWAP_INPUT)).rejects.toMatchObject({
    code: "unexpected_response",
  });
});
