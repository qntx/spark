import { createRouterTransport } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { createSparkClientWith } from "../src/client/index.ts";
import type { SparkOperatorConfig } from "../src/core/network.ts";
import { createMemorySparkStore } from "../src/exit/store.ts";
import { SparkAuthnService } from "../src/proto/gen/spark_authn_pb.ts";
import type {
  QueryTokenOutputsResponse,
  TokenOutputStatus as TokenOutputStatusType,
} from "../src/proto/gen/spark_token_pb.ts";
import { SparkTokenService, TokenOutputStatus } from "../src/proto/gen/spark_token_pb.ts";
import { authnServiceImpl } from "./support/fakes.ts";
import { createTestSigner } from "./support/test-signer.ts";

// External-audit round 10, finding N-05: token outputs and balances used to trust the coordinator
// alone — it could inflate or hide outputs. `queryVerifiedTokenOutputs` now counts an output only
// when every operator serves exactly one row for its outpoint agreeing on owner, token identifier,
// amount, previous transaction hash/vout and status (output ids are SO-local UUIDs and are never
// compared). Reversed: coordinator-only rows, missing rows, duplicates and field disagreement are
// all excluded; a unanimous set still counts.

const OPERATORS: ReadonlyArray<SparkOperatorConfig> = [0, 1, 2].map((index) => ({
  id: index,
  identifier: (index + 1).toString(16).padStart(64, "0"),
  address: `https://operator-${index}.local`,
  identityPublicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(index + 1), true),
}));
const signer = createTestSigner(new Uint8Array(32).fill(7));
const OWNER = secp256k1.getPublicKey(new Uint8Array(32).fill(7), true);
const TOKEN_ID = hexToBytes("3f".repeat(32));
const PREV_HASH = hexToBytes("ee".repeat(32));

type Row = QueryTokenOutputsResponse["outputsWithPreviousTransactionData"][number];

function tokenRow(
  vout: number,
  amount: bigint,
  overrides?: { status?: TokenOutputStatusType; owner?: Uint8Array },
): Row {
  return {
    $typeName: "spark_token.OutputWithPreviousTransactionData",
    output: {
      $typeName: "spark_token.TokenOutput",
      id: `uuid-vout-${vout}`,
      ownerPublicKey: overrides?.owner ?? OWNER,
      tokenIdentifier: TOKEN_ID,
      tokenAmount: numberToBytesBE(amount, 16),
      status: overrides?.status ?? TokenOutputStatus.AVAILABLE,
    },
    previousTransactionHash: PREV_HASH,
    previousTransactionVout: vout,
  };
}

/**
 * A client whose connection index picks the response: 0 is the coordinator, 1..2 the other
 * operators (connectOperator order in client/index.ts).
 */
function clientWith(perConnection: ReadonlyArray<() => Row[]>) {
  let connectionIndex = 0;
  return createSparkClientWith(
    {
      network: "regtest",
      signer,
      store: createMemorySparkStore(),
      fetch: async () => {
        await Promise.resolve();
        return new Response("not found", { status: 404 });
      },
      random: (length) => new Uint8Array(length).fill(1),
      operators: OPERATORS.map((operator) => ({ ...operator })),
    },
    {
      transportFactory: (interceptors) => {
        const index = connectionIndex;
        connectionIndex += 1;
        return createRouterTransport(
          (router) => {
            router.service(SparkAuthnService, authnServiceImpl);
            router.service(SparkTokenService, {
              query_token_outputs: () => {
                const rows = perConnection[index]?.() ?? perConnection[0]?.() ?? [];
                return {
                  $typeName: "spark_token.QueryTokenOutputsResponse" as const,
                  outputsWithPreviousTransactionData: rows,
                };
              },
            });
          },
          { transport: { interceptors: [...interceptors] } },
        );
      },
    },
  );
}

const honest = [tokenRow(0, 30n), tokenRow(1, 20n)];

describe("N-05: token outputs must be unanimous across operators", () => {
  test("all operators agreeing counts and balances aggregate", async () => {
    const client = clientWith([() => honest, () => honest, () => honest]);
    const outputs = await client.tokens.outputs();
    expect(outputs).toHaveLength(2);
    const balances = await client.tokens.balances();
    expect(balances).toHaveLength(1);
    expect(balances[0]?.amount).toBe(50n);
    client.close();
  });

  test("a coordinator-only output is excluded from outputs and balances", async () => {
    const fabricated = [...honest, tokenRow(2, 999n)];
    const client = clientWith([() => fabricated, () => honest, () => honest]);
    await expect(client.tokens.outputs()).resolves.toHaveLength(2);
    const balances = await client.tokens.balances();
    expect(balances[0]?.amount).toBe(50n);
    client.close();
  });

  test("an output one operator does not serve is excluded", async () => {
    const thin = [tokenRow(0, 30n)];
    const client = clientWith([() => honest, () => thin, () => honest]);
    const outputs = await client.tokens.outputs();
    expect(outputs.map((output) => output.amount)).toStrictEqual([30n]);
    client.close();
  });

  test("a single disagreeing operator excludes the output", async () => {
    const bigger = [tokenRow(0, 31n), tokenRow(1, 20n)];
    const client = clientWith([() => honest, () => bigger, () => honest]);
    const outputs = await client.tokens.outputs();
    expect(outputs.map((output) => output.amount)).toStrictEqual([20n]);
    client.close();
  });

  test("a differing status on one operator excludes the output", async () => {
    const pending = [
      tokenRow(0, 30n, { status: TokenOutputStatus.PENDING_OUTBOUND }),
      tokenRow(1, 20n),
    ];
    const client = clientWith([() => honest, () => pending, () => honest]);
    const outputs = await client.tokens.outputs();
    expect(outputs.map((output) => output.amount)).toStrictEqual([20n]);
    client.close();
  });

  test("conflicting coordinator duplicates quarantine the outpoint", async () => {
    const duped = [...honest, tokenRow(0, 999n)];
    const client = clientWith([() => duped, () => honest, () => honest]);
    const outputs = await client.tokens.outputs();
    expect(outputs.map((output) => output.amount)).toStrictEqual([20n]);
    client.close();
  });

  test("an operator serving conflicting duplicates excludes the outpoint", async () => {
    const duped = [tokenRow(0, 30n), tokenRow(0, 999n), tokenRow(1, 20n)];
    const client = clientWith([() => honest, () => duped, () => honest]);
    const outputs = await client.tokens.outputs();
    expect(outputs.map((output) => output.amount)).toStrictEqual([20n]);
    client.close();
  });

  test("an output the coordinator hides but others serve stays excluded", async () => {
    const coordinatorView = [tokenRow(0, 30n)];
    const client = clientWith([() => coordinatorView, () => honest, () => honest]);
    const outputs = await client.tokens.outputs();
    expect(outputs.map((output) => output.amount)).toStrictEqual([30n]);
    client.close();
  });

  test("a failing operator fails the query closed", async () => {
    const failing = (): Row[] => {
      throw new Error("connection refused");
    };
    const client = clientWith([() => honest, failing, () => honest]);
    await expect(client.tokens.outputs()).rejects.toThrow("internal error");
    client.close();
  });
});
