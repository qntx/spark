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
import { requiredIdentifier } from "./support/fakes.ts";
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
        tokenName: "E2E Test Token",
        tokenTicker: "E2E",
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

async function outputsUntil(
  client: {
    tokens: {
      outputs: (options?: {
        tokenIdentifier?: string;
      }) => Promise<ReadonlyArray<{ amount: bigint; ownerPublicKey: Uint8Array }>>;
    };
  },
  tokenIdentifier: string,
  expected: number,
  deadlineMs = Date.now() + DEADLINE_MS,
) {
  for (;;) {
    // oxlint-disable-next-line no-await-in-loop -- polling is sequential by definition
    const outputs = await client.tokens.outputs({ tokenIdentifier });
    if (outputs.length === expected) {
      return outputs;
    }
    if (Date.now() > deadlineMs) {
      throw new SparkError(
        `timed out waiting for ${expected} token outputs (have ${outputs.length})`,
      );
    }
    // oxlint-disable-next-line no-await-in-loop -- polling is sequential by definition
    await sleep(1000);
  }
}

describe.skipIf(process.env["SPARK_E2E_LOCAL"] !== "1")("local SO tokens", () => {
  test("create, mint, then transfer tokens between two wallets", { timeout: 300_000 }, async () => {
    const walletA = await localWallet(randomBytes(32));
    const walletB = await localWallet(randomBytes(32));
    const issuer = await walletA.signer.identityPublicKey();
    const receiver = await walletB.signer.identityPublicKey();
    const now = () => Date.now();

    const created = await broadcast(walletA.signer, createPartial(issuer, now));
    const rawIdentifier = requiredIdentifier(created.tokenIdentifier);
    const tokenIdentifier = encodeTokenIdentifier(rawIdentifier, "regtest");

    const minted = await broadcast(walletA.signer, mintPartial(issuer, rawIdentifier, 1000n, now));
    expect(minted.transactionHash).toMatch(/^[0-9a-f]{64}$/);
    await balanceUntil(walletA.client, tokenIdentifier, 1000n, Date.now() + DEADLINE_MS);

    // A sends 400 of 1000 to B; A keeps a 600 change output.
    const sendHash = await walletA.client.tokens.transfer({
      tokenIdentifier,
      amount: 400n,
      receiver,
    });
    expect(sendHash).toMatch(/^[0-9a-f]{64}$/);
    await balanceUntil(walletA.client, tokenIdentifier, 600n, Date.now() + DEADLINE_MS);
    await balanceUntil(walletB.client, tokenIdentifier, 400n, Date.now() + DEADLINE_MS);
    const bOutputs = await walletB.client.tokens.outputs({ tokenIdentifier });
    expect(bOutputs).toHaveLength(1);
    expect(bOutputs[0]?.amount).toBe(400n);
    expect(bOutputs[0]?.ownerPublicKey).toStrictEqual(receiver);

    // B sends 150 back to A; B keeps a 250 change output.
    await walletB.client.tokens.transfer({
      tokenIdentifier,
      amount: 150n,
      receiver: issuer,
    });
    await balanceUntil(walletA.client, tokenIdentifier, 750n, Date.now() + DEADLINE_MS);
    await balanceUntil(walletB.client, tokenIdentifier, 250n, Date.now() + DEADLINE_MS);

    const aOutputs = await walletA.client.tokens.outputs({ tokenIdentifier });
    expect(aOutputs.map((output) => output.amount).toSorted((x, y) => Number(x - y))).toStrictEqual(
      [150n, 600n],
    );
    const bOutputsAfter = await walletB.client.tokens.outputs({ tokenIdentifier });
    expect(bOutputsAfter).toHaveLength(1);
    expect(bOutputsAfter[0]?.amount).toBe(250n);
  });

  test("consolidate merges several outputs into one", { timeout: 300_000 }, async () => {
    const walletA = await localWallet(randomBytes(32));
    const walletB = await localWallet(randomBytes(32));
    const issuer = await walletA.signer.identityPublicKey();
    const receiver = await walletB.signer.identityPublicKey();
    const now = () => Date.now();

    const created = await broadcast(walletA.signer, createPartial(issuer, now));
    const rawIdentifier = requiredIdentifier(created.tokenIdentifier);
    const tokenIdentifier = encodeTokenIdentifier(rawIdentifier, "regtest");
    await broadcast(walletA.signer, mintPartial(issuer, rawIdentifier, 1000n, now));
    await balanceUntil(walletA.client, tokenIdentifier, 1000n, Date.now() + DEADLINE_MS);

    // Three separate transfers give B three distinct outputs.
    for (const amount of [100n, 200n, 300n]) {
      // oxlint-disable-next-line no-await-in-loop -- sequential transfers by design
      await walletA.client.tokens.transfer({ tokenIdentifier, amount, receiver });
    }
    await balanceUntil(walletB.client, tokenIdentifier, 600n, Date.now() + DEADLINE_MS);
    const outputsBefore = await outputsUntil(walletB.client, tokenIdentifier, 3);
    expect(
      outputsBefore.map((output) => output.amount).toSorted((x, y) => Number(x - y)),
    ).toStrictEqual([100n, 200n, 300n]);

    const consolidated = await walletB.client.tokens.consolidate({ tokenIdentifier });
    expect(consolidated?.transactionHash).toMatch(/^[0-9a-f]{64}$/);
    const outputsAfter = await outputsUntil(walletB.client, tokenIdentifier, 1);
    expect(outputsAfter).toHaveLength(1);
    expect(outputsAfter[0]?.amount).toBe(600n);
    expect(outputsAfter[0]?.ownerPublicKey).toStrictEqual(receiver);
    await balanceUntil(walletB.client, tokenIdentifier, 600n, Date.now() + DEADLINE_MS);

    // Nothing left to merge: a second call is a no-op.
    await expect(walletB.client.tokens.consolidate({ tokenIdentifier })).resolves.toBeUndefined();
  });
});
