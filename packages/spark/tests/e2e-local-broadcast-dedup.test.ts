import { numberToBytesBE } from "@noble/curves/utils.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { connectOperator } from "../src/connection/index.ts";
import { sparkNetworkConfig, sparkNetworkProto } from "../src/core/network.ts";
import { encodeTokenIdentifier } from "../src/core/token-identifier.ts";
import { SparkError } from "../src/errors/index.ts";
import type { PartialTokenTransaction } from "../src/proto/gen/spark_token_pb.ts";
import type { SparkSigner } from "../src/signer/types.ts";
import { broadcastPartialTokenTransaction } from "../src/tokens/index.ts";
import { LOCAL_OPERATORS, localFetch, localWallet, sleep } from "./support/local.ts";

const TOKENS = sparkNetworkConfig("regtest").tokens;
const DEADLINE_MS = 120_000;

function metadata(
  now: () => number,
): NonNullable<PartialTokenTransaction["tokenTransactionMetadata"]> {
  const created = now();
  return {
    $typeName: "spark_token.TokenTransactionMetadata",
    network: sparkNetworkProto("regtest"),
    sparkOperatorIdentityPublicKeys: [...LOCAL_OPERATORS]
      .map((operator) => operator.identityPublicKey)
      .toSorted((a, b) => {
        const shared = Math.min(a.length, b.length);
        for (let i = 0; i < shared; i += 1) {
          if (a[i] !== b[i]) {
            return (a[i] ?? 0) - (b[i] ?? 0);
          }
        }
        return a.length - b.length;
      }),
    validityDurationSeconds: BigInt(TOKENS.validityDurationSeconds),
    clientCreatedTimestamp: {
      $typeName: "google.protobuf.Timestamp",
      seconds: BigInt(Math.floor(created / 1000)),
      nanos: (created % 1000) * 1_000_000,
    },
    invoiceAttachments: [],
  };
}

function createPartial(issuerPublicKey: Uint8Array, now: () => number): PartialTokenTransaction {
  return {
    $typeName: "spark_token.PartialTokenTransaction",
    version: 3,
    tokenTransactionMetadata: metadata(now),
    tokenInputs: {
      case: "createInput",
      value: {
        $typeName: "spark_token.TokenCreateInput",
        issuerPublicKey,
        tokenName: "Recovery Test Token",
        tokenTicker: "REC",
        decimals: 8,
        maxSupply: numberToBytesBE(1_000_000n, 16),
        isFreezable: false,
      },
    },
    partialTokenOutputs: [],
  };
}

function mintPartial(
  issuerPublicKey: Uint8Array,
  tokenIdentifier: Uint8Array,
  amount: bigint,
  now: () => number,
): PartialTokenTransaction {
  return {
    $typeName: "spark_token.PartialTokenTransaction",
    version: 3,
    tokenTransactionMetadata: metadata(now),
    tokenInputs: {
      case: "mintInput",
      value: {
        $typeName: "spark_token.TokenMintInput",
        issuerPublicKey,
        tokenIdentifier,
      },
    },
    partialTokenOutputs: [
      {
        $typeName: "spark_token.PartialTokenOutput",
        ownerPublicKey: issuerPublicKey,
        withdrawBondSats: BigInt(TOKENS.withdrawBondSats),
        withdrawRelativeBlockLocktime: BigInt(TOKENS.withdrawRelativeBlockLocktime),
        tokenIdentifier,
        tokenAmount: numberToBytesBE(amount, 16),
      },
    ],
  };
}

async function broadcast(
  signer: SparkSigner,
  partial: PartialTokenTransaction,
): Promise<{ transactionHash: string; tokenIdentifier?: Uint8Array }> {
  const connection = connectOperator(LOCAL_OPERATORS[0]!, {
    signer,
    fetch: localFetch(),
    random: (length: number) => randomBytes(length),
  });
  return broadcastPartialTokenTransaction({
    token: connection.token,
    signer,
    partial,
    network: "regtest",
    operators: LOCAL_OPERATORS,
    tokens: TOKENS,
  });
}

async function balanceUntil(
  client: {
    tokens: {
      balances: () => Promise<ReadonlyArray<{ tokenIdentifier: string; amount: bigint }>>;
    };
  },
  tokenIdentifier: string,
  expected: bigint,
  deadlineMs: number,
): Promise<void> {
  for (;;) {
    // oxlint-disable-next-line no-await-in-loop -- polling is sequential by definition
    const balances = await client.tokens.balances();
    const balance = balances.find((entry) => entry.tokenIdentifier === tokenIdentifier);
    if (balance?.amount === expected) {
      return;
    }
    if (Date.now() > deadlineMs) {
      throw new SparkError(`timed out waiting for token balance ${expected}`);
    }
    // oxlint-disable-next-line no-await-in-loop -- polling is sequential by definition
    await sleep(1000);
  }
}

function requiredIdentifier(value: Uint8Array | undefined): Uint8Array {
  if (value === undefined) {
    throw new SparkError("create broadcast did not return a token identifier");
  }
  return value;
}

/**
 * Lets `broadcast_transaction` requests reach the SO — the transaction commits server-side — then
 * returns 503 to the client, simulating a lost response. `dropped` counts how many broadcast
 * responses were swallowed; everything else passes through untouched.
 */
function dropBroadcastResponses(): {
  fetch: (input: string | URL | Request, init?: RequestInit) => Promise<Response>;
  dropped: () => number;
} {
  const inner = localFetch();
  let dropped = 0;
  const fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url.includes("SparkTokenService/broadcast_transaction")) {
      const response = await inner(input, init);
      void response.body?.cancel();
      dropped += 1;
      return new Response("simulated lost response", { status: 503 });
    }
    return inner(input, init);
  };
  return { fetch, dropped: () => dropped };
}

describe.skipIf(process.env["SPARK_E2E_LOCAL"] !== "1")("token broadcast recovery", () => {
  test(
    "a broadcast that commits but loses its response resolves via the committed transaction",
    { timeout: 300_000 },
    async () => {
      const dropper = dropBroadcastResponses();
      const walletA = await localWallet(randomBytes(32), { fetch: dropper.fetch });
      const walletB = await localWallet(randomBytes(32));
      const issuer = await walletA.signer.identityPublicKey();
      const now = () => Date.now();

      const created = await broadcast(walletA.signer, createPartial(issuer, now));
      const rawIdentifier = requiredIdentifier(created.tokenIdentifier);
      const tokenIdentifier = encodeTokenIdentifier(rawIdentifier, "regtest");
      await broadcast(walletA.signer, mintPartial(issuer, rawIdentifier, 1000n, now));
      await balanceUntil(walletA.client, tokenIdentifier, 1000n, Date.now() + DEADLINE_MS);

      // Every broadcast response is dropped: the first commits server-side, the idempotent
      // retry is swallowed too, and the committed-transaction probe resolves the call.
      const hash = await walletA.client.tokens.transfer({
        tokenIdentifier,
        amount: 400n,
        receiver: await walletB.signer.identityPublicKey(),
      });
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
      expect(dropper.dropped()).toBe(2);

      // The receiver got the amount exactly once — no double payment.
      await balanceUntil(walletA.client, tokenIdentifier, 600n, Date.now() + DEADLINE_MS);
      await balanceUntil(walletB.client, tokenIdentifier, 400n, Date.now() + DEADLINE_MS);
      const bOutputs = await walletB.client.tokens.outputs({ tokenIdentifier });
      expect(bOutputs).toHaveLength(1);
      expect(bOutputs[0]?.amount).toBe(400n);
    },
  );
});
