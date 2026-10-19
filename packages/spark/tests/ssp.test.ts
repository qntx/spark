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
  lightningReceive?: {
    id?: string;
    status?: string;
    invoice?: string;
    transferId?: string | null;
  };
  lightningSend?: {
    id?: string;
    status?: string;
    feeValue?: number | string;
    feeUnit?: string;
    transferId?: string | null;
    preimage?: string | null;
  };
  feeEstimate?: { value?: number | string; unit?: string } | null;
  coopExitQuote?: {
    id?: string;
    userFees?: { fast: number; medium: number; slow: number };
    l1Fees?: { fast: number; medium: number; slow: number };
    unit?: string;
    expiresAt?: string;
  } | null;
  coopExit?: {
    id?: string;
    status?: string;
    rawCoopExitTransaction?: string;
    coopExitTxid?: string;
    rawConnectorTransaction?: string;
    transferId?: string | null;
  };
  completeCoopExit?: { id?: string; status?: string; transferId?: string | null };
  staticQuote?: {
    transactionId?: string;
    outputIndex?: number;
    creditAmountSats?: number;
    signature?: string;
  } | null;
  claimDeposit?: { transferId?: string | null };
  userRequest?: unknown;
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
      case "RequestLightningReceive": {
        const req = handlers.lightningReceive ?? {};
        const transfer =
          req.transferId === null || req.transferId === undefined
            ? null
            : { __typename: "Transfer", transfer_spark_id: req.transferId };
        return json({
          request_lightning_receive: {
            request: {
              __typename: "LightningReceiveRequest",
              lightning_receive_request_id: req.id ?? "recv-1",
              lightning_receive_request_created_at: "2025-01-01T00:00:00Z",
              lightning_receive_request_updated_at: "2025-01-01T00:00:00Z",
              lightning_receive_request_network: "REGTEST",
              lightning_receive_request_invoice: {
                __typename: "Invoice",
                invoice_encoded_invoice: req.invoice ?? "lnbcrt10n1ptest",
                invoice_bitcoin_network: "REGTEST",
                invoice_payment_hash: "00".repeat(32),
              },
              lightning_receive_request_status: req.status ?? "LIGHTNING_PAYMENT_CREATED",
              lightning_receive_request_transfer: transfer,
              lightning_receive_request_payment_preimage: null,
              lightning_receive_request_receiver_identity_public_key: bytesToHex(SIGNER_PUBLIC_KEY),
            },
          },
        });
      }
      case "RequestLightningSend": {
        const req = handlers.lightningSend ?? {};
        return json({
          request_lightning_send: {
            request: lightningSendRequestJson(req),
          },
        });
      }
      case "LightningSendFeeEstimate":
        return json({
          lightning_send_fee_estimate:
            handlers.feeEstimate === null
              ? null
              : {
                  lightning_send_fee_estimate_output_fee_estimate: {
                    __typename: "CurrencyAmount",
                    currency_amount_original_value: handlers.feeEstimate?.value ?? 250,
                    currency_amount_original_unit: handlers.feeEstimate?.unit ?? "SATOSHI",
                  },
                },
        });
      case "CoopExitFeeQuote": {
        const quote = handlers.coopExitQuote;
        return json({
          coop_exit_fee_quote:
            quote === null
              ? null
              : {
                  coop_exit_fee_quote_quote: coopExitQuoteJson(quote ?? {}),
                },
        });
      }
      case "RequestCoopExit": {
        const req = handlers.coopExit ?? {};
        return json({ request_coop_exit: { request: coopExitRequestJson(req) } });
      }
      case "CompleteCoopExit": {
        const req = handlers.completeCoopExit ?? {};
        return json({ complete_coop_exit: { request: coopExitRequestJson(req) } });
      }
      case "StaticDepositQuote": {
        const quote = handlers.staticQuote;
        return json({
          static_deposit_quote:
            quote === null
              ? null
              : {
                  __typename: "StaticDepositQuoteOutput",
                  static_deposit_quote_output_transaction_id:
                    quote?.transactionId ?? "ab".repeat(32),
                  static_deposit_quote_output_output_index: quote?.outputIndex ?? 0,
                  static_deposit_quote_output_network: "REGTEST",
                  static_deposit_quote_output_credit_amount_sats: quote?.creditAmountSats ?? 950,
                  static_deposit_quote_output_signature: quote?.signature ?? "cd".repeat(64),
                },
        });
      }
      case "ClaimStaticDeposit": {
        const claim = handlers.claimDeposit ?? {};
        return json({
          claim_static_deposit: {
            __typename: "ClaimStaticDepositOutput",
            claim_static_deposit_output_transfer_id:
              claim.transferId === undefined ? "transfer-1" : claim.transferId,
          },
        });
      }
      case "UserRequest":
        return json({ user_request: handlers.userRequest ?? null });
      default:
        return new Response("not found", { status: 404 });
    }
  };
  return { fetchImpl, requests };
}

function lightningSendRequestJson(req: {
  id?: string;
  status?: string;
  feeValue?: number | string;
  feeUnit?: string;
  transferId?: string | null;
  preimage?: string | null;
  encodedInvoice?: string;
}): Record<string, unknown> {
  return {
    __typename: "LightningSendRequest",
    lightning_send_request_id: req.id ?? "send-1",
    lightning_send_request_created_at: "2025-01-01T00:00:00Z",
    lightning_send_request_updated_at: "2025-01-01T00:00:00Z",
    lightning_send_request_network: "REGTEST",
    lightning_send_request_encoded_invoice: req.encodedInvoice ?? "lnbcrt10n1ptest",
    lightning_send_request_fee: {
      __typename: "CurrencyAmount",
      currency_amount_original_value: req.feeValue ?? 7,
      currency_amount_original_unit: req.feeUnit ?? "SATOSHI",
    },
    lightning_send_request_idempotency_key: null,
    lightning_send_request_status: req.status ?? "LIGHTNING_PAYMENT_INITIATED",
    lightning_send_request_transfer:
      req.transferId === null || req.transferId === undefined
        ? null
        : { __typename: "Transfer", transfer_spark_id: req.transferId },
    lightning_send_request_payment_preimage: req.preimage ?? null,
  };
}

function coopExitQuoteJson(req: {
  id?: string;
  userFees?: { fast: number; medium: number; slow: number };
  l1Fees?: { fast: number; medium: number; slow: number };
  unit?: string;
  expiresAt?: string;
}): Record<string, unknown> {
  const unit = req.unit ?? "SATOSHI";
  const amount = (value: number) => ({
    __typename: "CurrencyAmount",
    currency_amount_original_value: value,
    currency_amount_original_unit: unit,
  });
  const userFees = req.userFees ?? { fast: 30, medium: 20, slow: 10 };
  const l1Fees = req.l1Fees ?? { fast: 300, medium: 200, slow: 100 };
  return {
    __typename: "CoopExitFeeQuote",
    coop_exit_fee_quote_id: req.id ?? "quote-1",
    coop_exit_fee_quote_created_at: "2025-01-01T00:00:00Z",
    coop_exit_fee_quote_updated_at: "2025-01-01T00:00:00Z",
    coop_exit_fee_quote_network: "REGTEST",
    coop_exit_fee_quote_user_fee_fast: amount(userFees.fast),
    coop_exit_fee_quote_user_fee_medium: amount(userFees.medium),
    coop_exit_fee_quote_user_fee_slow: amount(userFees.slow),
    coop_exit_fee_quote_l1_broadcast_fee_fast: amount(l1Fees.fast),
    coop_exit_fee_quote_l1_broadcast_fee_medium: amount(l1Fees.medium),
    coop_exit_fee_quote_l1_broadcast_fee_slow: amount(l1Fees.slow),
    coop_exit_fee_quote_expires_at: req.expiresAt ?? "2025-06-01T00:00:00Z",
  };
}

function coopExitRequestJson(req: {
  id?: string;
  status?: string;
  rawCoopExitTransaction?: string;
  coopExitTxid?: string;
  rawConnectorTransaction?: string;
  transferId?: string | null;
}): Record<string, unknown> {
  return {
    __typename: "CoopExitRequest",
    coop_exit_request_id: req.id ?? "exit-1",
    coop_exit_request_created_at: "2025-01-01T00:00:00Z",
    coop_exit_request_updated_at: "2025-01-01T00:00:00Z",
    coop_exit_request_network: "REGTEST",
    coop_exit_request_status: req.status ?? "TX_SIGNED",
    coop_exit_request_raw_connector_transaction: req.rawConnectorTransaction ?? "aabb".repeat(10),
    coop_exit_request_raw_coop_exit_transaction: req.rawCoopExitTransaction ?? "ccdd".repeat(10),
    coop_exit_request_coop_exit_txid: req.coopExitTxid ?? "ee".repeat(32),
    coop_exit_request_transfer:
      req.transferId === null || req.transferId === undefined
        ? null
        : { __typename: "Transfer", transfer_spark_id: req.transferId },
  };
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

test("graphql error messages are sanitized", async () => {
  const { fetchImpl } = fakeSsp({
    graphqlError: { message: `oops\nforged\u0007 ${"y".repeat(300)}` },
  });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  const thrown = await client.swapFeeEstimate(1).then(
    () => {
      throw new Error("expected rejection");
    },
    (error: unknown) => error,
  );
  const { message } = thrown as Error;
  expect(message).toContain("oopsforged");
  expect(message).not.toContain("\n");
  expect(message).not.toContain("\u0007");
  expect(message.length).toBeLessThanOrEqual("ssp error: ".length + 256 + 1);
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
  const failed = [
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
  ];
  const results = await Promise.all(
    failed.map(async (status) => {
      const { fetchImpl } = fakeSsp({ swap: { status } });
      const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
      return client.requestSwap(SWAP_INPUT).then(
        () => "resolved",
        (error: unknown) => (error as { code?: string }).code,
      );
    }),
  );
  expect(results).toStrictEqual(failed.map(() => "swap_failed"));
});

test("requestSwap keeps accepting in-flight and succeeded statuses", async () => {
  for (const status of ["TRANSFERS_COMPLETING_SCHEDULED", "OUTBOUND_TRANSFER_SENT", "SUCCEEDED"]) {
    const { fetchImpl } = fakeSsp({ swap: { status, sparkId: "in-1" } });
    const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
    // oxlint-disable-next-line no-await-in-loop -- serial checks keep failures attributable
    await expect(client.requestSwap(SWAP_INPUT)).resolves.toMatchObject({ status });
  }
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

const RECEIVE_INPUT = {
  network: "regtest" as const,
  amountSats: 1000,
  paymentHash: new Uint8Array(32).fill(1),
  expirySecs: 3600,
  receiverIdentityPublicKey: SIGNER_PUBLIC_KEY,
  memo: "hello",
  includeSparkAddress: true,
};

test("requestLightningReceive sends the invoice variables and parses the request", async () => {
  const { fetchImpl, requests } = fakeSsp({
    lightningReceive: { invoice: "lnbcrt10n1ptest", transferId: "tr-1" },
  });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  const result = await client.requestLightningReceive(RECEIVE_INPUT);
  expect(result).toStrictEqual({
    id: "recv-1",
    status: "LIGHTNING_PAYMENT_CREATED",
    invoice: "lnbcrt10n1ptest",
    transferId: "tr-1",
  });
  const call = requests.find((r) => r.operationName === "RequestLightningReceive");
  expect(call?.variables).toStrictEqual({
    network: "REGTEST",
    amount_sats: 1000,
    payment_hash: bytesToHex(RECEIVE_INPUT.paymentHash),
    expiry_secs: 3600,
    memo: "hello",
    include_spark_address: true,
    receiver_identity_pubkey: bytesToHex(RECEIVE_INPUT.receiverIdentityPublicKey),
  });
});

test("requestLightningSend sends the external transfer id and no idempotency_key", async () => {
  const { fetchImpl, requests } = fakeSsp({
    lightningSend: { status: "LIGHTNING_PAYMENT_INITIATED", feeValue: 7, transferId: "tr-9" },
  });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  const result = await client.requestLightningSend({
    encodedInvoice: "lnbcrt10n1ptest",
    userOutboundTransferExternalId: "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
  });
  expect(result.id).toBe("send-1");
  expect(result.feeSats).toBe(7);
  expect(result.transferId).toBe("tr-9");
  const call = requests.find((r) => r.operationName === "RequestLightningSend");
  expect(call?.variables).toStrictEqual({
    encoded_invoice: "lnbcrt10n1ptest",
    user_outbound_transfer_external_id: "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
  });
  // Neither idempotency_key nor amount_sats may be sent for a fixed-amount invoice.
  expect(call?.variables).not.toHaveProperty("idempotency_key");
  expect(call?.variables).not.toHaveProperty("amount_sats");
});

test("requestLightningSend forwards amount_sats only for amountless invoices", async () => {
  const { fetchImpl, requests } = fakeSsp({ lightningSend: {} });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  await client.requestLightningSend({
    encodedInvoice: "lnbcrt1ptest",
    amountSats: 500,
    userOutboundTransferExternalId: "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
  });
  const call = requests.find((r) => r.operationName === "RequestLightningSend");
  expect(call?.variables["amount_sats"]).toBe(500);
});

test("lightningSendFeeEstimate handles SATOSHI, MILLISATOSHI and rejects other units", async () => {
  const sat = createSspClient({
    ...SSP_OPTS,
    signer: SIGNER,
    fetch: fakeSsp({ feeEstimate: { value: 250, unit: "SATOSHI" } }).fetchImpl,
  });
  await expect(sat.lightningSendFeeEstimate("lnbcrt1x")).resolves.toBe(250);
  const msat = createSspClient({
    ...SSP_OPTS,
    signer: SIGNER,
    fetch: fakeSsp({ feeEstimate: { value: 2501, unit: "MILLISATOSHI" } }).fetchImpl,
  });
  await expect(msat.lightningSendFeeEstimate("lnbcrt1x", 500)).resolves.toBe(3);
  const other = createSspClient({
    ...SSP_OPTS,
    signer: SIGNER,
    fetch: fakeSsp({ feeEstimate: { value: 1, unit: "USD" } }).fetchImpl,
  });
  await expect(other.lightningSendFeeEstimate("lnbcrt1x")).rejects.toMatchObject({
    code: "unexpected_response",
  });
  const missing = createSspClient({
    ...SSP_OPTS,
    signer: SIGNER,
    fetch: fakeSsp({ feeEstimate: null }).fetchImpl,
  });
  await expect(missing.lightningSendFeeEstimate("lnbcrt1x")).rejects.toMatchObject({
    code: "unexpected_response",
  });
});

test("lightningSendRequest parses a settled send with preimage and transfer id", async () => {
  const { fetchImpl } = fakeSsp({
    userRequest: lightningSendRequestJson({
      status: "LIGHTNING_PAYMENT_SUCCEEDED",
      preimage: "ab".repeat(32),
      transferId: "tr-7",
      feeValue: "12",
      feeUnit: "MILLISATOSHI",
    }),
  });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  const result = await client.lightningSendRequest("send-1");
  expect(result.status).toBe("LIGHTNING_PAYMENT_SUCCEEDED");
  expect(bytesToHex(result.paymentPreimage!)).toBe("ab".repeat(32));
  expect(result.transferId).toBe("tr-7");
  // 12 millisats → ceil → 1 sat.
  expect(result.feeSats).toBe(1);
});

test("lightningSendRequest maps a non-hex or wrong-length preimage to unexpected_response", async () => {
  await Promise.all(
    (["zz".repeat(32), "ab".repeat(31), 42] as const).map(async (preimage) => {
      const { fetchImpl } = fakeSsp({
        userRequest: lightningSendRequestJson({ preimage: preimage as string }),
      });
      const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
      await expect(client.lightningSendRequest("send-1")).rejects.toMatchObject({
        code: "unexpected_response",
      });
    }),
  );
});

test("lightningSendRequest rejects a request of another type", async () => {
  const { fetchImpl } = fakeSsp({
    userRequest: { __typename: "CoopExitRequest" },
  });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  await expect(client.lightningSendRequest("x")).rejects.toMatchObject({
    code: "unexpected_response",
  });
});

test("lightningReceiveRequest parses status and transfer id; missing request fails", async () => {
  const { fetchImpl } = fakeSsp({
    userRequest: {
      __typename: "LightningReceiveRequest",
      lightning_receive_request_id: "recv-9",
      lightning_receive_request_status: "TRANSFER_COMPLETED",
      lightning_receive_request_invoice: { invoice_encoded_invoice: "lnbcrt1x" },
      lightning_receive_request_transfer: { transfer_spark_id: "tr-5" },
      lightning_receive_request_payment_preimage: null,
    },
  });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  const result = await client.lightningReceiveRequest("recv-9");
  expect(result.status).toBe("TRANSFER_COMPLETED");
  expect(result.transferId).toBe("tr-5");

  const missing = createSspClient({
    ...SSP_OPTS,
    signer: SIGNER,
    fetch: fakeSsp({ userRequest: null }).fetchImpl,
  });
  await expect(missing.lightningReceiveRequest("recv-x")).rejects.toMatchObject({
    code: "unexpected_response",
  });
});

const COOP_EXIT_LEAVES = ["0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee"];
const COOP_EXIT_ADDRESS = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

test("coopExitFeeQuote sums user fee + l1 broadcast fee per speed", async () => {
  const { fetchImpl, requests } = fakeSsp({
    coopExitQuote: {
      userFees: { fast: 11, medium: 7, slow: 3 },
      l1Fees: { fast: 90, medium: 60, slow: 30 },
      expiresAt: "2025-06-01T12:00:00Z",
    },
  });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  const quote = await client.coopExitFeeQuote(COOP_EXIT_LEAVES, COOP_EXIT_ADDRESS);
  expect(quote.id).toBe("quote-1");
  expect(quote.fees).toStrictEqual({ fast: 101, medium: 67, slow: 33 });
  expect(quote.expiresAtMs).toBe(Date.parse("2025-06-01T12:00:00Z"));
  const call = requests.find((r) => r.operationName === "CoopExitFeeQuote");
  expect(call?.authorization).toBe("Bearer ssp-token-1");
  expect(call?.variables).toStrictEqual({
    leaf_external_ids: COOP_EXIT_LEAVES,
    withdrawal_address: COOP_EXIT_ADDRESS,
  });
});

test("coopExitFeeQuote rejects non-SATOSHI fees and an unparseable expiry", async () => {
  const badUnit = createSspClient({
    ...SSP_OPTS,
    signer: SIGNER,
    fetch: fakeSsp({ coopExitQuote: { unit: "MILLISATOSHI" } }).fetchImpl,
  });
  await expect(badUnit.coopExitFeeQuote(COOP_EXIT_LEAVES, COOP_EXIT_ADDRESS)).rejects.toMatchObject(
    { code: "unexpected_response" },
  );
  const badDate = createSspClient({
    ...SSP_OPTS,
    signer: SIGNER,
    fetch: fakeSsp({ coopExitQuote: { expiresAt: "not a date" } }).fetchImpl,
  });
  await expect(badDate.coopExitFeeQuote(COOP_EXIT_LEAVES, COOP_EXIT_ADDRESS)).rejects.toMatchObject(
    { code: "unexpected_response" },
  );
});

test("requestCoopExit sends withdraw_all variables and parses the transactions", async () => {
  const { fetchImpl, requests } = fakeSsp({
    coopExit: {
      status: "INITIATED",
      rawCoopExitTransaction: "aa11".repeat(4),
      coopExitTxid: "bb22".repeat(16),
      rawConnectorTransaction: "cc33".repeat(4),
    },
  });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  const result = await client.requestCoopExit({
    leafIds: COOP_EXIT_LEAVES,
    withdrawalAddress: COOP_EXIT_ADDRESS,
    exitSpeed: "MEDIUM",
    withdrawAll: true,
    userOutboundTransferExternalId: "0199aaaa-bbbb-7ccc-8ddd-ffffffffffff",
  });
  expect(result).toStrictEqual({
    id: "exit-1",
    status: "INITIATED",
    rawCoopExitTransaction: hexToBytes("aa11".repeat(4)),
    coopExitTxid: "bb22".repeat(16),
    rawConnectorTransaction: hexToBytes("cc33".repeat(4)),
  });
  const call = requests.find((r) => r.operationName === "RequestCoopExit");
  expect(call?.variables).toStrictEqual({
    leaf_external_ids: COOP_EXIT_LEAVES,
    withdrawal_address: COOP_EXIT_ADDRESS,
    exit_speed: "MEDIUM",
    withdraw_all: true,
    user_outbound_transfer_external_id: "0199aaaa-bbbb-7ccc-8ddd-ffffffffffff",
  });
  // Fee-deduction mode sends none of the fee-leaf or idempotency variables.
  expect(call?.variables).not.toHaveProperty("idempotency_key");
  expect(call?.variables).not.toHaveProperty("fee_leaf_external_ids");
  expect(call?.variables).not.toHaveProperty("fee_quote_id");
});

test("requestCoopExit rejects empty leaves and malformed transaction fields", async () => {
  const client = createSspClient({
    ...SSP_OPTS,
    signer: SIGNER,
    fetch: fakeSsp({}).fetchImpl,
  });
  await expect(
    client.requestCoopExit({
      leafIds: [],
      withdrawalAddress: COOP_EXIT_ADDRESS,
      exitSpeed: "FAST",
      withdrawAll: true,
      userOutboundTransferExternalId: "0199aaaa-bbbb-7ccc-8ddd-ffffffffffff",
    }),
  ).rejects.toMatchObject({ name: "SparkInputError" });

  const cases = await Promise.all(
    [
      { rawCoopExitTransaction: "zz" },
      { rawConnectorTransaction: "0x1234" },
      { coopExitTxid: "abcd" },
      { coopExitTxid: "not-hex".repeat(4) },
    ].map(async (mutation) => {
      const { fetchImpl } = fakeSsp({ coopExit: mutation });
      const failing = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
      return failing
        .requestCoopExit({
          leafIds: COOP_EXIT_LEAVES,
          withdrawalAddress: COOP_EXIT_ADDRESS,
          exitSpeed: "SLOW",
          withdrawAll: true,
          userOutboundTransferExternalId: "0199aaaa-bbbb-7ccc-8ddd-ffffffffffff",
        })
        .then(
          () => "resolved",
          (error: unknown) => (error as { code?: string }).code,
        );
    }),
  );
  expect(cases).toStrictEqual([
    "unexpected_response",
    "unexpected_response",
    "unexpected_response",
    "unexpected_response",
  ]);
});

test("completeCoopExit sends both ids and parses the request status", async () => {
  const { fetchImpl, requests } = fakeSsp({
    completeCoopExit: { status: "TX_BROADCASTED", id: "exit-9", transferId: "tr-1" },
  });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  const result = await client.completeCoopExit({
    coopExitRequestId: "0199aaaa-bbbb-7ccc-8ddd-000000000009",
    userOutboundTransferExternalId: "0199aaaa-bbbb-7ccc-8ddd-ffffffffffff",
  });
  expect(result).toStrictEqual({
    id: "exit-9",
    status: "TX_BROADCASTED",
    transferId: "tr-1",
    rawCoopExitTransaction: hexToBytes("ccdd".repeat(10)),
  });
  const call = requests.find((r) => r.operationName === "CompleteCoopExit");
  expect(call?.variables).toStrictEqual({
    coop_exit_request_id: "0199aaaa-bbbb-7ccc-8ddd-000000000009",
    user_outbound_transfer_external_id: "0199aaaa-bbbb-7ccc-8ddd-ffffffffffff",
  });
});

test("coopExitRequest parses a CoopExitRequest and rejects other request types", async () => {
  const { fetchImpl, requests } = fakeSsp({
    userRequest: coopExitRequestJson({ id: "exit-7", status: "SUCCEEDED", transferId: "tr-3" }),
  });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  const result = await client.coopExitRequest("exit-7");
  expect(result).toStrictEqual({
    id: "exit-7",
    status: "SUCCEEDED",
    transferId: "tr-3",
    rawCoopExitTransaction: hexToBytes("ccdd".repeat(10)),
  });
  const call = requests.find((r) => r.operationName === "UserRequest");
  expect(call?.variables).toStrictEqual({ request_id: "exit-7" });

  const wrong = createSspClient({
    ...SSP_OPTS,
    signer: SIGNER,
    fetch: fakeSsp({ userRequest: { __typename: "LightningSendRequest" } }).fetchImpl,
  });
  await expect(wrong.coopExitRequest("x")).rejects.toMatchObject({
    code: "unexpected_response",
  });
});

test("staticDepositQuote sends the utxo coordinates and parses the quote", async () => {
  const transactionId = "ab".repeat(32);
  const { fetchImpl, requests } = fakeSsp({
    staticQuote: {
      transactionId,
      outputIndex: 1,
      creditAmountSats: 987,
      signature: "cd".repeat(70),
    },
  });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  const result = await client.staticDepositQuote({
    transactionId,
    outputIndex: 1,
    network: "regtest",
  });
  expect(result).toStrictEqual({ creditAmountSats: 987, signature: "cd".repeat(70) });
  const call = requests.find((r) => r.operationName === "StaticDepositQuote");
  expect(call?.variables).toStrictEqual({
    transaction_id: transactionId,
    output_index: 1,
    network: "REGTEST",
  });
});

test("staticDepositQuote rejects a quote for a different deposit output", async () => {
  const { fetchImpl } = fakeSsp({ staticQuote: { transactionId: "cd".repeat(32) } });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  await expect(
    client.staticDepositQuote({
      transactionId: "ab".repeat(32),
      outputIndex: 0,
      network: "regtest",
    }),
  ).rejects.toMatchObject({ code: "unexpected_response" });
});

test("staticDepositQuote rejects a null quote", async () => {
  const { fetchImpl } = fakeSsp({ staticQuote: null });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  await expect(
    client.staticDepositQuote({
      transactionId: "ab".repeat(32),
      outputIndex: 0,
      network: "regtest",
    }),
  ).rejects.toMatchObject({ code: "unexpected_response" });
});

test("claimStaticDeposit sends the sealed-key claim and parses the transfer id", async () => {
  const { fetchImpl, requests } = fakeSsp({ claimDeposit: { transferId: "tr-static-1" } });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  const result = await client.claimStaticDeposit({
    transactionId: "ab".repeat(32),
    outputIndex: 2,
    network: "regtest",
    creditAmountSats: 950,
    encryptedSecretKey: "01".repeat(65),
    signature: "3045".concat("02".repeat(66)),
    quoteSignature: "cd".repeat(70),
  });
  expect(result).toStrictEqual({ transferId: "tr-static-1" });
  const call = requests.find((r) => r.operationName === "ClaimStaticDeposit");
  expect(call?.variables).toStrictEqual({
    transaction_id: "ab".repeat(32),
    output_index: 2,
    network: "REGTEST",
    credit_amount_sats: 950,
    encrypted_deposit_secret_key: "01".repeat(65),
    signature: "3045".concat("02".repeat(66)),
    quote_signature: "cd".repeat(70),
  });
});

test("claimStaticDeposit tolerates a null transfer id", async () => {
  const { fetchImpl } = fakeSsp({ claimDeposit: { transferId: null } });
  const client = createSspClient({ ...SSP_OPTS, signer: SIGNER, fetch: fetchImpl });
  await expect(
    client.claimStaticDeposit({
      transactionId: "ab".repeat(32),
      outputIndex: 0,
      network: "regtest",
      creditAmountSats: 950,
      encryptedSecretKey: "01".repeat(65),
      signature: "3045".concat("02".repeat(66)),
      quoteSignature: "cd".repeat(70),
    }),
  ).resolves.toStrictEqual({});
});
