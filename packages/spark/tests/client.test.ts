import { create } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { createRouterTransport } from "@connectrpc/connect";
import type { HandlerContext } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { base64 } from "@scure/base";
import { expect, test } from "vite-plus/test";

import { createSparkClientWith } from "../src/client/index.ts";
import type { SparkOperatorConfig } from "../src/core/network.ts";
import {
  ChallengeSchema,
  ProtectedChallengeSchema,
  SparkAuthnService,
} from "../src/proto/gen/spark_authn_pb.ts";
import {
  Network,
  QueryTransfersResponseSchema,
  SparkService,
  SubscribeToEventsResponseSchema,
  TreeNodeSchema,
  TreeNodeStatus,
  TransferStatus,
  TransferType,
} from "../src/proto/gen/spark_pb.ts";
import type { QueryNodesRequest, TreeNode } from "../src/proto/gen/spark_pb.ts";
import { createTestSigner } from "./support/test-signer.ts";

const COORDINATOR_ID = "0000000000000000000000000000000000000000000000000000000000000001";
const OPERATORS: ReadonlyArray<SparkOperatorConfig> = [
  {
    id: 0,
    identifier: COORDINATOR_ID,
    address: "https://op0.test",
    identityPublicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(9), true),
  },
  {
    id: 1,
    identifier: "0000000000000000000000000000000000000000000000000000000000000002",
    address: "https://op1.test",
    identityPublicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(8), true),
  },
];

function makeLeaf(id: string, valueSats: bigint, status = "AVAILABLE"): TreeNode {
  return create(TreeNodeSchema, {
    id,
    treeId: `tree-${id}`,
    value: valueSats,
    nodeTx: new Uint8Array([1, 2]),
    refundTx: new Uint8Array([3, 4]),
    vout: 0,
    verifyingPublicKey: new Uint8Array(33).fill(5),
    ownerIdentityPublicKey: new Uint8Array(33).fill(6),
    ownerSigningPublicKey: new Uint8Array(33).fill(6),
    signingKeyshare: {
      ownerIdentifiers: OPERATORS.map((op) => op.identifier),
      threshold: 2,
      publicKey: new Uint8Array(33).fill(7),
      publicShares: {},
    },
    status,
    network: Network.MAINNET,
    treenodeStatus: TreeNodeStatus.AVAILABLE,
    createdTime: timestampFromMs(1_700_000_000_000),
    updatedTime: timestampFromMs(1_700_000_000_000),
  });
}

const sspFetch: typeof globalThis.fetch = async (_input, init) => {
  const body = JSON.parse(String(init?.body)) as { operationName: string };
  const json = async (data: unknown) => Promise.resolve(Response.json({ data }));
  if (body.operationName === "GetChallenge") {
    return json({
      get_challenge: {
        get_challenge_output_protected_challenge: base64.encode(new Uint8Array(32).fill(9)),
      },
    });
  }
  if (body.operationName === "VerifyChallenge") {
    return json({
      verify_challenge: {
        verify_challenge_output_session_token: "ssp-tok",
        verify_challenge_output_valid_until: new Date(Date.now() + 600_000).toISOString(),
      },
    });
  }
  if (body.operationName === "LeavesSwapFeeEstimate") {
    return json({
      leaves_swap_fee_estimate: {
        leaves_swap_fee_estimate_output_fee_estimate: {
          currency_amount_original_value: 150,
          currency_amount_original_unit: "SATOSHI",
        },
      },
    });
  }
  return new Response("not found", { status: 404 });
};

function makeClient(signer: ReturnType<typeof createTestSigner>, sparkImpl: object) {
  return createSparkClientWith(
    {
      network: "mainnet",
      signer,
      fetch: sspFetch,
      random: (length) => new Uint8Array(length).fill(1),
      sleep: async () => Promise.resolve(),
      operators: OPERATORS,
    },
    {
      transportFactory: (interceptors) =>
        createRouterTransport(
          (router) => {
            router.service(SparkAuthnService, {
              get_challenge: (req) => ({
                protectedChallenge: create(ProtectedChallengeSchema, {
                  challenge: create(ChallengeSchema, {
                    version: 1,
                    timestamp: BigInt(Math.floor(Date.now() / 1000)),
                    nonce: new Uint8Array(4),
                    publicKey: req.publicKey,
                  }),
                  serverHmac: new Uint8Array(4),
                }),
              }),
              verify_challenge: () => ({
                sessionToken: "so-tok",
                expirationTimestamp: BigInt(Math.floor(Date.now() / 1000) + 600),
              }),
            });
            router.service(SparkService, sparkImpl);
          },
          { transport: { interceptors: [...interceptors] } },
        ),
    },
  );
}

test("leaves and balance page through query_nodes until a short page", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const pageRequests: QueryNodesRequest[] = [];
  const leaves = Array.from({ length: 51 }, (_, i) => makeLeaf(`leaf-${i}`, BigInt(100 + i)));
  const client = makeClient(signer, {
    query_nodes: (req: QueryNodesRequest) => {
      pageRequests.push(req);
      const offset = Number(req.offset);
      const page = leaves.slice(offset, offset + Number(req.limit));
      const nodes: Record<string, TreeNode> = {};
      for (const leaf of page) {
        nodes[leaf.id] = leaf;
      }
      return { nodes, offset: BigInt(offset + page.length) };
    },
  });
  const result = await client.leaves();
  expect(result).toHaveLength(51);
  expect(pageRequests).toHaveLength(2);
  expect(Number(pageRequests[0]?.offset)).toBe(0);
  expect(Number(pageRequests[1]?.offset)).toBe(50);
  expect(result[0]?.valueSats).toBe(100);
  await expect(client.balance()).resolves.toBe(
    leaves.reduce((sum, leaf) => sum + Number(leaf.value), 0),
  );
});

test("pending and all transfers map to plain SparkTransfer", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const pubkey = await signer.identityPublicKey();
  let listLimit = 0n;
  const client = makeClient(signer, {
    query_nodes: () => ({ nodes: {}, offset: 0n }),
    query_pending_transfers: () =>
      create(QueryTransfersResponseSchema, {
        transfers: [
          {
            id: "t-pending",
            senderIdentityPublicKey: new Uint8Array(33).fill(3),
            receiverIdentityPublicKey: pubkey,
            status: TransferStatus.SENDER_KEY_TWEAKED,
            totalValue: 4321n,
            expiryTime: timestampFromMs(1_700_000_600_000),
            createdTime: timestampFromMs(1_700_000_000_000),
            updatedTime: timestampFromMs(1_700_000_000_000),
            type: TransferType.TRANSFER,
            network: Network.MAINNET,
            leaves: [{ leaf: makeLeaf("pl-1", 4321n) }],
            receivers: [],
            senders: [],
          },
        ],
      }),
    query_all_transfers: (req: { limit: bigint }) => {
      listLimit = req.limit;
      return create(QueryTransfersResponseSchema, {
        transfers: [
          {
            id: "t-old",
            senderIdentityPublicKey: pubkey,
            receiverIdentityPublicKey: new Uint8Array(33).fill(4),
            status: TransferStatus.COMPLETED,
            totalValue: 10_000n,
            type: TransferType.SWAP,
            network: Network.MAINNET,
            leaves: [],
            receivers: [],
            senders: [],
          },
        ],
      });
    },
  });

  const pending = await client.transfers.pending();
  expect(pending).toHaveLength(1);
  const [transfer] = pending;
  expect(transfer?.id).toBe("t-pending");
  expect(transfer?.status).toBe("SENDER_KEY_TWEAKED");
  expect(transfer?.type).toBe("TRANSFER");
  expect(transfer?.totalValueSats).toBe(4321);
  expect(transfer?.expiryTimeMs).toBe(1_700_000_600_000);
  expect(transfer?.leaves[0]?.leaf.id).toBe("pl-1");

  const all = await client.transfers.list({ limit: 25 });
  expect(listLimit).toBe(25n);
  expect(all[0]?.id).toBe("t-old");
  expect(all[0]?.status).toBe("COMPLETED");
});

test("swapFeeEstimate goes through SSP auth and returns sats", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const client = makeClient(signer, {
    query_nodes: () => ({ nodes: {}, offset: 0n }),
  });
  const estimate = await client.swapFeeEstimate(100_000);
  expect(estimate).toBe(150);
});

test("close() stops an event stream started with a caller signal", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const client = makeClient(signer, {
    query_nodes: () => ({ nodes: {}, offset: 0n }),
    async *subscribe_to_events(_req: unknown, context: HandlerContext) {
      yield create(SubscribeToEventsResponseSchema, {
        event: { case: "connected", value: {} },
      });
      await new Promise<void>((resolve) => {
        context.signal.addEventListener("abort", () => {
          resolve();
        });
      });
    },
  });
  const caller = new AbortController();
  const iterator = client.events(caller.signal)[Symbol.asyncIterator]();
  const first = await iterator.next();
  client.close();
  const last = await iterator.next();
  expect(first.done).not.toBe(true);
  expect(last.done).toBe(true);
});
