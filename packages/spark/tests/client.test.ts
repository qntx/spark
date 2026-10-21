import { create, toBinary } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { Code, ConnectError, createRouterTransport } from "@connectrpc/connect";
import type { HandlerContext } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { Transaction } from "@scure/btc-signer";
import { expect, test } from "vite-plus/test";

import { createSparkClientWith } from "../src/client/index.ts";
import { p2trScriptFromPublicKey, txId } from "../src/core/bitcoin/index.ts";
import type { SparkOperatorConfig } from "../src/core/network.ts";
import { SparkRequestError } from "../src/errors/index.ts";
import { createMemorySparkStore } from "../src/exit/store.ts";
import type { SparkExitChain, SparkStore } from "../src/exit/store.ts";
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
  TransferReceiverStatus,
  TreeNodeSchema,
  TreeNodeStatus,
  TransferStatus,
  TransferType,
} from "../src/proto/gen/spark_pb.ts";
import type { QueryNodesRequest, TreeNode } from "../src/proto/gen/spark_pb.ts";
import { ProtectedChallengeSchema as SspProtectedChallengeSchema } from "../src/proto/gen/ssp_authn_pb.ts";
import { createTestSigner } from "./support/test-signer.ts";

const COORDINATOR_ID = "0000000000000000000000000000000000000000000000000000000000000001";
const OPERATOR1_ID = "0000000000000000000000000000000000000000000000000000000000000002";
const OPERATORS: ReadonlyArray<SparkOperatorConfig> = [
  {
    id: 0,
    identifier: COORDINATOR_ID,
    address: "https://op0.test",
    identityPublicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(9), true),
  },
  {
    id: 1,
    identifier: OPERATOR1_ID,
    address: "https://op1.test",
    identityPublicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(8), true),
  },
];

const KEYSHARE_PUBLIC = secp256k1.getPublicKey(new Uint8Array(32).fill(11), true);

/** A small valid scalar for leaf key material, keyed on `index`. */
function leafSecret(index: number): Uint8Array {
  const secret = new Uint8Array(32);
  secret[31] = index + 1;
  return secret;
}

/** The public-key map createTestSigner's `publicKeys` answers LEAF{id} lookups from. */
function leafKeyMap(leaves: ReadonlyArray<readonly [string, Uint8Array]>): Map<string, Uint8Array> {
  return new Map(leaves.map(([id, secret]) => [id, secp256k1.getPublicKey(secret, true)] as const));
}

/**
 * A leaf the wallet provably owns under `leafPriv`: real parseable transactions and a verifying key
 * that is the wallet leaf key plus the operators' keyshare.
 */
function ownedLeaf(
  id: string,
  valueSats: bigint,
  leafPriv: Uint8Array,
  status = "AVAILABLE",
): TreeNode {
  const node = makeLeaf(id, valueSats, status);
  node.nodeTx = txSpending(fakeTxid((id.codePointAt(0) ?? 0) + id.length), 0);
  node.refundTx = txSpending(
    hexToBytes(txId(node.nodeTx)),
    0x200,
    secp256k1.getPublicKey(leafPriv, true),
  );
  const ours = secp256k1.Point.fromBytes(secp256k1.getPublicKey(leafPriv, true));
  node.verifyingPublicKey = ours.add(secp256k1.Point.fromBytes(KEYSHARE_PUBLIC)).toBytes(true);
  if (node.signingKeyshare !== undefined) {
    node.signingKeyshare.publicKey = KEYSHARE_PUBLIC;
  }
  return node;
}

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

const SSP_IDENTITY_KEY = secp256k1.getPublicKey(new Uint8Array(32).fill(7), true);

const sspFetch: typeof globalThis.fetch = async (_input, init) => {
  const body = JSON.parse(String(init?.body)) as { operationName: string };
  const json = async (data: unknown) => Promise.resolve(Response.json({ data }));
  if (body.operationName === "GetChallenge") {
    return json({
      get_challenge: {
        get_challenge_output_protected_challenge: base64.encode(
          toBinary(SspProtectedChallengeSchema, {
            $typeName: "ssp_authn.ProtectedChallenge",
            version: 1,
            challenge: {
              $typeName: "ssp_authn.Challenge",
              version: 1,
              timestamp: 1_786_974_052n,
              nonce: new Uint8Array(32).fill(9),
              publicKey: SSP_IDENTITY_KEY,
            },
            serverHmac: new Uint8Array(32).fill(7),
          }),
        ),
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

function makeClient(
  signer: ReturnType<typeof createTestSigner>,
  sparkImpl: object,
  store?: SparkStore,
  /** Per-identifier overrides: an operator listed here gets this impl instead of `sparkImpl`. */
  operatorImpls: Record<string, object> = {},
) {
  return createSparkClientWith(
    {
      network: "mainnet",
      signer,
      fetch: sspFetch,
      random: (length) => new Uint8Array(length).fill(1),
      sleep: async () => Promise.resolve(),
      operators: OPERATORS,
      ...(store === undefined ? {} : { store }),
    },
    {
      transportFactory: (interceptors, operator) =>
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
            router.service(SparkService, operatorImpls[operator.identifier] ?? sparkImpl);
          },
          { transport: { interceptors: [...interceptors] } },
        ),
    },
  );
}

test("leaves and balance page through query_nodes until a short page", async () => {
  const secrets = Array.from({ length: 51 }, (_, i) => leafSecret(i));
  const signer = createTestSigner(
    new Uint8Array(32).fill(7),
    leafKeyMap(secrets.map((secret, i) => [`leaf-${i}`, secret])),
  );
  const pageRequests: QueryNodesRequest[] = [];
  const leaves = Array.from({ length: 51 }, (_, i) =>
    ownedLeaf(`leaf-${i}`, BigInt(100 + i), secrets[i]!),
  );
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
  // Both the coordinator and the other operator page through the same result set.
  expect(pageRequests).toHaveLength(4);
  expect(pageRequests.map((req) => Number(req.offset)).toSorted((a, b) => a - b)).toStrictEqual([
    0, 0, 50, 50,
  ]);
  expect(result[0]?.valueSats).toBe(100);
  await expect(client.balance()).resolves.toBe(
    leaves.reduce((sum, leaf) => sum + Number(leaf.value), 0),
  );
}, 60_000);

test("leaves throws when the coordinator never stops returning full pages", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const nodes: Record<string, TreeNode> = {};
  for (let i = 0; i < 50; i++) {
    nodes[`leaf-${i}`] = ownedLeaf(`leaf-${i}`, 100n, leafSecret(i));
  }
  let pages = 0;
  const client = makeClient(signer, {
    query_nodes: (req: QueryNodesRequest) => {
      pages += 1;
      return { nodes, offset: req.offset + 50n };
    },
  });
  await expect(client.leaves()).rejects.toThrow("did not stop returning full pages");
  // The cap bounds each operator's walk — coordinator and cross-check operator alike.
  expect(pages).toBe(2000);
  // Two thousand sequential coordinator calls — slow locally, fast in CI.
}, 600_000);

test("leaves throws when the coordinator's offset does not advance", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const nodes: Record<string, TreeNode> = {};
  for (let i = 0; i < 50; i++) {
    nodes[`leaf-${i}`] = ownedLeaf(`leaf-${i}`, 100n, leafSecret(i));
  }
  const client = makeClient(signer, {
    // A malicious coordinator repeating the same offset would paginate forever otherwise.
    query_nodes: () => ({ nodes, offset: 0n }),
  });
  await expect(client.leaves()).rejects.toThrow("non-advancing offset");
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
            leaves: [{ leaf: makeLeaf("pl-1", 4321n), transferReceiverId: "r-1" }],
            receivers: [
              {
                id: "r-1",
                identityPublicKey: pubkey,
                amountSats: 4321n,
                status: TransferReceiverStatus.KEY_TWEAKED,
              },
            ],
            senders: [],
          },
        ],
        offset: -1n,
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
  expect(transfer?.leaves[0]?.transferReceiverId).toBe("r-1");
  expect(transfer?.receivers).toHaveLength(1);
  expect(transfer?.receivers[0]?.id).toBe("r-1");
  expect(transfer?.receivers[0]?.status).toBe("KEY_TWEAKED");
  expect(transfer?.receivers[0]?.identityPublicKey).toStrictEqual(pubkey);

  const all = await client.transfers.list({ limit: 25 });
  expect(listLimit).toBe(25n);
  expect(all[0]?.id).toBe("t-old");
  expect(all[0]?.status).toBe("COMPLETED");
});

test("transfers.pending() pages until a short page", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const pubkey = await signer.identityPublicKey();
  const requests: Array<{ limit: bigint; offset: bigint }> = [];
  const transfer = (id: string) => ({
    id,
    senderIdentityPublicKey: new Uint8Array(33).fill(3),
    receiverIdentityPublicKey: pubkey,
    status: TransferStatus.SENDER_KEY_TWEAKED,
    totalValue: 1n,
    expiryTime: timestampFromMs(1_700_000_600_000),
    createdTime: timestampFromMs(1_700_000_000_000),
    updatedTime: timestampFromMs(1_700_000_000_000),
    type: TransferType.TRANSFER,
    network: Network.MAINNET,
    leaves: [],
    receivers: [],
    senders: [],
  });
  const pages = [
    {
      transfers: Array.from({ length: 100 }, (_, i) => transfer(`t-${i}`)),
      offset: 100n,
    },
    { transfers: [transfer("t-last")], offset: -1n },
  ];
  const client = makeClient(signer, {
    query_nodes: () => ({ nodes: {}, offset: 0n }),
    query_pending_transfers: (req: { limit: bigint; offset: bigint }) => {
      requests.push({ limit: req.limit, offset: req.offset });
      const page = pages[requests.length - 1]!;
      return create(QueryTransfersResponseSchema, page);
    },
  });
  const pending = await client.transfers.pending();
  expect(pending).toHaveLength(101);
  expect(pending[100]?.id).toBe("t-last");
  expect(requests).toStrictEqual([
    { limit: 100n, offset: 0n },
    { limit: 100n, offset: 100n },
  ]);
});

test("transfers.pending() keeps paging when a short page carries a positive offset", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const pubkey = await signer.identityPublicKey();
  const requests: Array<{ limit: bigint; offset: bigint }> = [];
  const transfer = (id: string) => ({
    id,
    senderIdentityPublicKey: new Uint8Array(33).fill(3),
    receiverIdentityPublicKey: pubkey,
    status: TransferStatus.SENDER_KEY_TWEAKED,
    totalValue: 1n,
    expiryTime: timestampFromMs(1_700_000_600_000),
    createdTime: timestampFromMs(1_700_000_000_000),
    updatedTime: timestampFromMs(1_700_000_000_000),
    type: TransferType.TRANSFER,
    network: Network.MAINNET,
    leaves: [],
    receivers: [],
    senders: [],
  });
  const pages = [
    {
      transfers: Array.from({ length: 50 }, (_, i) => transfer(`t-${i}`)),
      offset: 50n,
    },
    { transfers: [transfer("t-last")], offset: -1n },
  ];
  const client = makeClient(signer, {
    query_nodes: () => ({ nodes: {}, offset: 0n }),
    query_pending_transfers: (req: { limit: bigint; offset: bigint }) => {
      requests.push({ limit: req.limit, offset: req.offset });
      const page = pages[requests.length - 1]!;
      return create(QueryTransfersResponseSchema, page);
    },
  });
  const pending = await client.transfers.pending();
  expect(pending).toHaveLength(51);
  expect(pending[50]?.id).toBe("t-last");
  expect(requests).toStrictEqual([
    { limit: 100n, offset: 0n },
    { limit: 100n, offset: 50n },
  ]);
});

test("transfers.pending() throws when the coordinator's offset does not advance", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const pubkey = await signer.identityPublicKey();
  const client = makeClient(signer, {
    query_nodes: () => ({ nodes: {}, offset: 0n }),
    query_pending_transfers: () =>
      create(QueryTransfersResponseSchema, {
        transfers: Array.from({ length: 100 }, (_, i) => ({
          id: `t-${i}`,
          senderIdentityPublicKey: new Uint8Array(33).fill(3),
          receiverIdentityPublicKey: pubkey,
          status: TransferStatus.SENDER_KEY_TWEAKED,
          totalValue: 1n,
          type: TransferType.TRANSFER,
          network: Network.MAINNET,
          leaves: [],
          receivers: [],
          senders: [],
        })),
        offset: 0n,
      }),
  });
  await expect(client.transfers.pending()).rejects.toThrow("non-advancing offset");
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

test("breaking out of events() aborts the stream and does not resubscribe", async () => {
  const signer = createTestSigner(new Uint8Array(32).fill(7));
  const streamCalls = { calls: 0 };
  const client = makeClient(signer, {
    query_nodes: () => ({ nodes: {}, offset: 0n }),
    async *subscribe_to_events(_req: unknown, context: HandlerContext) {
      streamCalls.calls++;
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
  for await (const event of client.events()) {
    expect(event.type).toBe("connected");
    break;
  }
  await new Promise((resolve) => setTimeout(resolve, 10));
  expect(streamCalls.calls).toBe(1);
  client.close();
});

const KEY = secp256k1.getPublicKey(new Uint8Array(32).fill(7), true);

function fakeTxid(label: number): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = (label + i) % 256;
  }
  return out;
}

function txSpending(prevTxid: Uint8Array, sequence: number, payKey: Uint8Array = KEY): Uint8Array {
  const tx = new Transaction({ allowUnknownOutputs: true });
  tx.addInput({ txid: prevTxid, index: 0, sequence });
  tx.addOutput({ script: p2trScriptFromPublicKey(payKey, "mainnet"), amount: 1000n });
  return tx.toBytes(true);
}

function storedChain(leafId: string): SparkExitChain {
  return {
    leafId,
    nodes: [{ nodeId: leafId, nodeTx: new Uint8Array([1]) }],
    refundTx: new Uint8Array([2]),
  };
}

test("leaves() reconciles stored exit chains with the current leaf set", async () => {
  const signer = createTestSigner(
    new Uint8Array(32).fill(7),
    leafKeyMap([["leaf-1", leafSecret(0)]]),
  );
  const store = createMemorySparkStore();
  await store.putExitChains([storedChain("stale-leaf"), storedChain("leaf-1")]);
  const client = makeClient(
    signer,
    {
      query_nodes: () => ({
        nodes: { "leaf-1": ownedLeaf("leaf-1", 100n, leafSecret(0)) },
        offset: 1n,
      }),
    },
    store,
  );
  const leaves = await client.leaves();
  expect(leaves.map((leaf) => leaf.id)).toStrictEqual(["leaf-1"]);
  const chains = await store.exitChains();
  expect(chains.map((chain) => chain.leafId)).toStrictEqual(["leaf-1"]);
  expect(chains[0]?.nodes.map((node) => node.nodeId)).toStrictEqual(["leaf-1"]);
});

test("leaves() withholds a leaf one operator does not report but keeps its chain", async () => {
  const secrets = [leafSecret(0), leafSecret(1)];
  const signer = createTestSigner(
    new Uint8Array(32).fill(7),
    leafKeyMap([
      ["leaf-1", secrets[0]!],
      ["leaf-2", secrets[1]!],
    ]),
  );
  const store = createMemorySparkStore();
  await store.putExitChains([storedChain("leaf-1"), storedChain("leaf-2")]);
  const both = {
    nodes: {
      "leaf-1": ownedLeaf("leaf-1", 100n, secrets[0]!),
      "leaf-2": ownedLeaf("leaf-2", 200n, secrets[1]!),
    },
    offset: 2n,
  };
  const client = makeClient(signer, { query_nodes: () => both }, store, {
    [OPERATOR1_ID]: {
      query_nodes: () => ({ nodes: { "leaf-1": both.nodes["leaf-1"] }, offset: 1n }),
    },
  });
  const leaves = await client.leaves();
  expect(leaves.map((leaf) => leaf.id)).toStrictEqual(["leaf-1"]);
  const chains = await store.exitChains();
  expect(chains.map((chain) => chain.leafId).toSorted()).toStrictEqual(["leaf-1", "leaf-2"]);
});

test("leaves() withholds a leaf operators report differently", async () => {
  const secrets = [leafSecret(0), leafSecret(1)];
  const signer = createTestSigner(
    new Uint8Array(32).fill(7),
    leafKeyMap([
      ["leaf-1", secrets[0]!],
      ["leaf-2", secrets[1]!],
    ]),
  );
  const store = createMemorySparkStore();
  await store.putExitChains([storedChain("leaf-1"), storedChain("leaf-2")]);
  const leaf1 = ownedLeaf("leaf-1", 100n, secrets[0]!);
  const leaf2 = ownedLeaf("leaf-2", 200n, secrets[1]!);
  const inflated = create(TreeNodeSchema, { ...leaf2, value: 999n });
  const client = makeClient(
    signer,
    {
      query_nodes: () => ({ nodes: { "leaf-1": leaf1, "leaf-2": leaf2 }, offset: 2n }),
    },
    store,
    {
      [OPERATOR1_ID]: {
        query_nodes: () => ({ nodes: { "leaf-1": leaf1, "leaf-2": inflated }, offset: 2n }),
      },
    },
  );
  const leaves = await client.leaves();
  expect(leaves.map((leaf) => leaf.id)).toStrictEqual(["leaf-1"]);
  const chains = await store.exitChains();
  expect(chains.map((chain) => chain.leafId).toSorted()).toStrictEqual(["leaf-1", "leaf-2"]);
});

test("leaves() drops a leaf the wallet does not own and deletes its chain", async () => {
  const signer = createTestSigner(
    new Uint8Array(32).fill(7),
    leafKeyMap([
      ["leaf-1", leafSecret(0)],
      ["leaf-2", leafSecret(1)],
    ]),
  );
  const store = createMemorySparkStore();
  await store.putExitChains([storedChain("leaf-1"), storedChain("leaf-2")]);
  // leaf-2's verifying key is not our key + the operators' share.
  const foreign = ownedLeaf("leaf-2", 200n, leafSecret(1));
  foreign.verifyingPublicKey = secp256k1.Point.BASE.toBytes(true);
  const client = makeClient(
    signer,
    {
      query_nodes: () => ({
        nodes: { "leaf-1": ownedLeaf("leaf-1", 100n, leafSecret(0)), "leaf-2": foreign },
        offset: 2n,
      }),
    },
    store,
  );
  const leaves = await client.leaves();
  expect(leaves.map((leaf) => leaf.id)).toStrictEqual(["leaf-1"]);
  const chains = await store.exitChains();
  expect(chains.map((chain) => chain.leafId)).toStrictEqual(["leaf-1"]);
});

test("leaves() drops a leaf carrying a malformed transaction", async () => {
  const signer = createTestSigner(
    new Uint8Array(32).fill(7),
    leafKeyMap([
      ["leaf-1", leafSecret(0)],
      ["leaf-2", leafSecret(1)],
    ]),
  );
  const store = createMemorySparkStore();
  await store.putExitChains([storedChain("leaf-1"), storedChain("leaf-2")]);
  const malformed = ownedLeaf("leaf-2", 200n, leafSecret(1));
  const noInputs = new Transaction({ allowUnknownOutputs: true });
  noInputs.addOutput({ script: p2trScriptFromPublicKey(KEY, "mainnet"), amount: 200n });
  malformed.nodeTx = noInputs.toBytes(true);
  const client = makeClient(
    signer,
    {
      query_nodes: () => ({
        nodes: { "leaf-1": ownedLeaf("leaf-1", 100n, leafSecret(0)), "leaf-2": malformed },
        offset: 2n,
      }),
    },
    store,
  );
  const leaves = await client.leaves();
  expect(leaves.map((leaf) => leaf.id)).toStrictEqual(["leaf-1"]);
  const chains = await store.exitChains();
  expect(chains.map((chain) => chain.leafId)).toStrictEqual(["leaf-1"]);
});

test("leaves() quarantines a leaf whose exit chain fails verification", async () => {
  const secrets = [leafSecret(0), leafSecret(1)];
  const signer = createTestSigner(
    new Uint8Array(32).fill(7),
    leafKeyMap([
      ["leaf-1", secrets[0]!],
      ["leaf-2", secrets[1]!],
    ]),
  );
  const store = createMemorySparkStore();
  await store.putExitChains([storedChain("leaf-1"), storedChain("leaf-2")]);
  const poisoned = ownedLeaf("leaf-2", 200n, secrets[1]!);
  // Both operators agree on the poisoning, so it passes cross-operator comparison and fails
  // only inside exit-chain verification: a well-formed direct refund paying a foreign key.
  poisoned.directTx = txSpending(hexToBytes(txId(poisoned.nodeTx)), 0x300);
  poisoned.directRefundTx = txSpending(
    hexToBytes(txId(poisoned.directTx)),
    0x300,
    secp256k1.getPublicKey(new Uint8Array(32).fill(13), true),
  );
  const client = makeClient(
    signer,
    {
      query_nodes: () => ({
        nodes: { "leaf-1": ownedLeaf("leaf-1", 100n, secrets[0]!), "leaf-2": poisoned },
        offset: 2n,
      }),
    },
    store,
  );
  const leaves = await client.leaves();
  expect(leaves.map((leaf) => leaf.id)).toStrictEqual(["leaf-1"]);
  await expect(client.balance()).resolves.toBe(100);
  // The poisoned leaf is still owned — its previously verified stored chain survives the sweep.
  const chains = await store.exitChains();
  expect(chains.map((chain) => chain.leafId).toSorted()).toStrictEqual(["leaf-1", "leaf-2"]);
  // Explicitly requested, the same leaf still fails closed with its precise chain error.
  await expect(client.withdrawals.unilateralExit(["leaf-2"])).rejects.toThrow(
    "direct refund tx of leaf leaf-2",
  );
});

test("leaves() throws when an operator query fails", async () => {
  const signer = createTestSigner(
    new Uint8Array(32).fill(7),
    leafKeyMap([["leaf-1", leafSecret(0)]]),
  );
  const client = makeClient(
    signer,
    {
      query_nodes: () => ({
        nodes: { "leaf-1": ownedLeaf("leaf-1", 100n, leafSecret(0)) },
        offset: 1n,
      }),
    },
    undefined,
    {
      [OPERATOR1_ID]: {
        query_nodes: () => {
          throw new ConnectError("operator down", Code.Unavailable);
        },
      },
    },
  );
  await expect(client.leaves()).rejects.toThrow(SparkRequestError);
});

test("unilateralExit persists the queried exit chain in the store", async () => {
  const signer = createTestSigner(
    new Uint8Array(32).fill(7),
    leafKeyMap([["leaf-exit", leafSecret(0)]]),
  );
  const nodeTx = txSpending(fakeTxid(0x50), 0);
  const refundTx = txSpending(
    hexToBytes(txId(nodeTx)),
    500,
    secp256k1.getPublicKey(leafSecret(0), true),
  );
  const leaf = makeLeaf("leaf-exit", 1000n);
  leaf.nodeTx = nodeTx;
  leaf.refundTx = refundTx;
  const store = createMemorySparkStore();
  const client = makeClient(
    signer,
    {
      query_nodes: () => ({ nodes: { "leaf-exit": leaf }, offset: 0n }),
    },
    store,
  );
  const txs = await client.withdrawals.unilateralExit(["leaf-exit"]);
  expect(txs.map((tx) => tx.kind)).toStrictEqual(["node", "refund"]);
  const chains = await store.exitChains();
  expect(chains.map((chain) => chain.leafId)).toStrictEqual(["leaf-exit"]);
  expect(chains[0]?.nodes.map((node) => node.nodeId)).toStrictEqual(["leaf-exit"]);
});
