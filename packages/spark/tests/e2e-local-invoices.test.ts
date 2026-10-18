import { secp256k1 } from "@noble/curves/secp256k1.js";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { connectOperator } from "../src/connection/index.ts";
import { sparkNetworkConfig, sparkNetworkProto } from "../src/core/network.ts";
import { encodeTokenIdentifier } from "../src/core/token-identifier.ts";
import { SparkError, SparkInputError } from "../src/errors/index.ts";
import type { PartialTokenTransaction } from "../src/proto/gen/spark_token_pb.ts";
import type { SparkSigner } from "../src/signer/types.ts";
import { broadcastPartialTokenTransaction } from "../src/tokens/index.ts";
import {
  bitcoinRpc,
  CLAIM_DEADLINE_MS,
  claimPendingUntil,
  claimUntilAccepted,
  localFetch,
  localWallet,
  LOCAL_OPERATORS,
  pendingUntil,
  sleep,
} from "./support/local.ts";

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

// Shapes ported from upstream issuer-sdk constructPartialCreateTokenTransaction /
// constructPartialMintTokenTransaction (sdks/js/packages/issuer-sdk/src/services/
// token-transactions.ts).
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
        tokenName: "E2E Invoice Token",
        tokenTicker: "E2I",
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

/** Deposits `satsBtc` to a fresh address for `client` and claims the resulting leaf. */
async function depositSats(
  client: Parameters<typeof claimUntilAccepted>[0],
  satsBtc: number,
): Promise<void> {
  const address = await client.deposits.newAddress();
  const txid = (await bitcoinRpc("sendtoaddress", [address, satsBtc])) as string;
  const minerAddress = (await bitcoinRpc("getnewaddress", [])) as string;
  await bitcoinRpc("generatetoaddress", [1, minerAddress]);
  const rawHex = (await bitcoinRpc("getrawtransaction", [txid])) as string;
  await claimUntilAccepted(client, hexToBytes(rawHex), Date.now() + CLAIM_DEADLINE_MS);
}

/** Polls `leaves` until `client` owns at least `count` leaves (bounded). */
async function leavesCountUntil(
  client: Parameters<typeof claimUntilAccepted>[0],
  count: number,
  deadline: number,
): Promise<ReadonlyArray<{ id: string }>> {
  const leaves = await client.leaves();
  if (leaves.length >= count || Date.now() > deadline) {
    return leaves;
  }
  await sleep(3000);
  return leavesCountUntil(client, count, deadline);
}

function statusBy(statuses: ReadonlyArray<{ invoice: string; status: string }>, invoice: string) {
  const found = statuses.find((entry) => entry.invoice === invoice);
  if (found === undefined) {
    throw new SparkError(`invoice status for ${invoice} not returned`);
  }
  return found.status;
}

describe.skipIf(process.env["SPARK_E2E_LOCAL"] !== "1")("local SO invoices", () => {
  test(
    "B invoices A for sats: fixed and open amounts, status, duplicate and local rejections",
    { timeout: 600_000 },
    async () => {
      const walletA = await localWallet(randomBytes(32));
      const walletB = await localWallet(randomBytes(32));

      // Three 100k leaves for A: two pay the invoices, one funds the duplicate-pay attempt.
      await depositSats(walletA.client, 0.001);
      await depositSats(walletA.client, 0.001);
      await depositSats(walletA.client, 0.001);
      const leavesA = await leavesCountUntil(walletA.client, 3, Date.now() + CLAIM_DEADLINE_MS);
      expect(leavesA).toHaveLength(3);
      await expect(walletA.client.balance()).resolves.toBe(300_000);

      const fixedInvoice = await walletB.client.invoices.createSats({
        amountSats: 100_000,
        memo: "fixed sats invoice",
      });
      const openInvoice = await walletB.client.invoices.createSats({
        memo: "open sats invoice",
      });
      console.log("fixed invoice:", fixedInvoice);
      console.log("open invoice:", openInvoice);

      const fixedPaid = await walletA.client.invoices.pay(fixedInvoice);
      const openPaid = await walletA.client.invoices.pay(openInvoice, { amount: 100_000 });
      console.log("paid transfers:", fixedPaid, openPaid);

      await pendingUntil(walletB.client, Date.now() + CLAIM_DEADLINE_MS);
      const claimed = await claimPendingUntil(walletB.client, Date.now() + CLAIM_DEADLINE_MS);
      expect(claimed).toHaveLength(2);
      await expect(walletB.client.balance()).resolves.toBe(200_000);

      const statuses = await walletB.client.invoices.status([fixedInvoice, openInvoice]);
      console.log("invoice statuses:", statuses);
      expect(statusBy(statuses, fixedInvoice)).toBe("FINALIZED");
      expect(statusBy(statuses, openInvoice)).toBe("FINALIZED");

      // Paying the fixed invoice a second time is rejected by the SO.
      const duplicate = await walletA.client.invoices.pay(fixedInvoice).then(
        () => undefined,
        (error: unknown) => error,
      );
      console.log("duplicate pay rejected with:", duplicate);
      expect(duplicate).toBeInstanceOf(Error);

      // Expired and sender-restricted invoices are rejected locally before any RPC.
      const expired = await walletB.client.invoices.createSats({
        amountSats: 1,
        expiresAtMs: Date.now() - 1000,
      });
      await expect(walletA.client.invoices.pay(expired)).rejects.toThrow(SparkInputError);

      const restricted = await walletB.client.invoices.createSats({
        amountSats: 1,
        senderPublicKey: secp256k1.getPublicKey(randomBytes(32), true),
      });
      await expect(walletA.client.invoices.pay(restricted)).rejects.toThrow(SparkInputError);

      walletA.client.close();
      walletB.client.close();
      walletA.signer.dispose();
      walletB.signer.dispose();
    },
  );

  test(
    "B invoices A for tokens: A pays with an invoice attachment",
    { timeout: 300_000 },
    async () => {
      const walletA = await localWallet(randomBytes(32));
      const walletB = await localWallet(randomBytes(32));
      const issuer = await walletA.signer.identityPublicKey();
      const now = () => Date.now();

      const created = await broadcast(walletA.signer, createPartial(issuer, now));
      const rawIdentifier = requiredIdentifier(created.tokenIdentifier);
      const tokenIdentifier = encodeTokenIdentifier(rawIdentifier, "regtest");
      await broadcast(walletA.signer, mintPartial(issuer, rawIdentifier, 1000n, now));
      await balanceUntil(walletA.client, tokenIdentifier, 1000n, Date.now() + DEADLINE_MS);

      const tokenInvoice = await walletB.client.invoices.createTokens({
        tokenIdentifier,
        amount: 400n,
        memo: "token invoice",
      });
      console.log("token invoice:", tokenInvoice);

      const hash = await walletA.client.invoices.pay(tokenInvoice);
      console.log("token invoice paid, final tx:", hash);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
      await balanceUntil(walletA.client, tokenIdentifier, 600n, Date.now() + DEADLINE_MS);
      await balanceUntil(walletB.client, tokenIdentifier, 400n, Date.now() + DEADLINE_MS);

      const statuses = await walletB.client.invoices.status([tokenInvoice]);
      console.log("token invoice statuses:", statuses);
      expect(statusBy(statuses, tokenInvoice)).toBe("FINALIZED");

      walletA.client.close();
      walletB.client.close();
      walletA.signer.dispose();
      walletB.signer.dispose();
    },
  );
});
