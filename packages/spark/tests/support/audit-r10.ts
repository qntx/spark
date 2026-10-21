import { clone, create } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { createRouterTransport } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { expect } from "vite-plus/test";

import { createSparkClientWith } from "../../src/client/index.ts";
import { p2trScriptFromPublicKey, txId } from "../../src/core/bitcoin/index.ts";
import { sparkNetworkConfig } from "../../src/core/network.ts";
import type { SparkOperatorConfig } from "../../src/core/network.ts";
import { SparkError, SparkRequestError } from "../../src/errors/index.ts";
import { createMemorySparkStore } from "../../src/exit/store.ts";
import type { SparkStore } from "../../src/exit/store.ts";
import {
  ChallengeSchema,
  ProtectedChallengeSchema,
  SparkAuthnService,
} from "../../src/proto/gen/spark_authn_pb.ts";
import {
  GetSigningCommitmentsResponseSchema,
  Network,
  RequestedSigningCommitmentsSchema,
  SigningKeyshareSchema,
  SparkService,
  TransferLeafSchema,
  TransferReceiverSchema,
  TransferSchema,
  TransferStatus,
  TransferType,
  TreeNodeSchema,
  TreeNodeStatus,
} from "../../src/proto/gen/spark_pb.ts";
import type {
  QueryNodesRequest,
  RequestedSigningCommitments,
  Transfer,
  TreeNode,
} from "../../src/proto/gen/spark_pb.ts";
import { createSparkSigner, sparkAccountKey } from "../../src/signer/index.ts";
import type { SparkSigner } from "../../src/signer/types.ts";
import { loadWasmBackend } from "./backend.ts";
import { createTestSigner } from "./test-signer.ts";

// Shared fixtures and mock-operator harnesses for the round-10 audit regression tests
// (audit-r10-chains, audit-r10-harness): realistic Bitcoin transactions with correct key
// relationships, generated protobuf rows, per-operator router transports, and the bounded
// single-mutation runners the external H1/H2 harnesses reduce to.

export function required<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new Error(`audit-r10 fixture: missing ${what}`);
  }
  return value;
}

export const OPERATORS: ReadonlyArray<SparkOperatorConfig> =
  sparkNetworkConfig("regtest").operators;
export const COORDINATOR: string = required(OPERATORS[0], "coordinator operator").identifier;
export const THRESHOLD = 2;

export const OTHER_IDENTITY: Uint8Array = secp256k1.getPublicKey(new Uint8Array(32).fill(8), true);
export const RECEIVER: Uint8Array = secp256k1.getPublicKey(new Uint8Array(32).fill(5), true);
export const LEAF_PUBLIC: Uint8Array = secp256k1.getPublicKey(new Uint8Array(32).fill(42), true);
export const SHARE_PUB: Uint8Array = secp256k1.getPublicKey(new Uint8Array(32).fill(11), true);
export const VERIFYING_KEY: Uint8Array = secp256k1.Point.fromBytes(LEAF_PUBLIC)
  .add(secp256k1.Point.fromBytes(SHARE_PUB))
  .toBytes(true);
export const TEST_IDENTITY: Uint8Array = secp256k1.getPublicKey(new Uint8Array(32).fill(7), true);
export const OTHER_LEAF_KEY: Uint8Array = secp256k1.getPublicKey(new Uint8Array(32).fill(9), true);
export const OTHER_VERIFYING: Uint8Array = secp256k1.Point.fromBytes(OTHER_LEAF_KEY)
  .add(secp256k1.Point.fromBytes(SHARE_PUB))
  .toBytes(true);

export function fakeTxid(label: number): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = (label + i) % 256;
  }
  return out;
}

export function txSpending(
  prevTxid: Uint8Array,
  sequence: number,
  payKey: Uint8Array,
  amount: bigint,
): Uint8Array {
  const tx = new Transaction({ allowUnknownOutputs: true });
  tx.addInput({ txid: prevTxid, index: 0, sequence });
  tx.addOutput({ script: p2trScriptFromPublicKey(payKey, "regtest"), amount });
  return tx.toBytes(true);
}

const STATUS_NAME = new Map<number, string>(
  Object.entries(TreeNodeStatus).map(([name, value]) => [value, name]),
);

export function leafProto(options: {
  id: string;
  valueSats: bigint;
  leafPublicKey: Uint8Array;
  verifyingPublicKey: Uint8Array;
  ownerIdentityPublicKey: Uint8Array;
  status?: TreeNodeStatus;
}): TreeNode {
  const nodeTx = txSpending(fakeTxid(0x50), 0, options.verifyingPublicKey, options.valueSats);
  const refundTx = txSpending(
    hexToBytes(txId(nodeTx)),
    2000,
    options.leafPublicKey,
    options.valueSats,
  );
  return create(TreeNodeSchema, {
    id: options.id,
    treeId: `tree-${options.id}`,
    value: options.valueSats,
    nodeTx,
    refundTx,
    vout: 0,
    verifyingPublicKey: options.verifyingPublicKey,
    ownerIdentityPublicKey: options.ownerIdentityPublicKey,
    ownerSigningPublicKey: options.leafPublicKey,
    signingKeyshare: {
      ownerIdentifiers: OPERATORS.map((operator) => operator.identifier),
      threshold: THRESHOLD,
      publicKey: SHARE_PUB,
      publicShares: {},
    },
    status: STATUS_NAME.get(options.status ?? TreeNodeStatus.AVAILABLE) ?? "AVAILABLE",
    network: Network.REGTEST,
    treenodeStatus: options.status ?? TreeNodeStatus.AVAILABLE,
  });
}

export function transferProto(options: {
  id: string;
  sender: Uint8Array;
  receiver: Uint8Array;
  receiverAmountSats?: bigint;
  /** SO-local TransferReceiver row id — each operator assigns its own (uuid.NewV7). */
  receiverId?: string;
  leaves: ReadonlyArray<TreeNode>;
  type?: TransferType;
  status?: TransferStatus;
}): Transfer {
  return create(TransferSchema, {
    id: options.id,
    senderIdentityPublicKey: options.sender,
    receiverIdentityPublicKey: options.receiver,
    receivers: [
      create(TransferReceiverSchema, {
        id: options.receiverId ?? "",
        identityPublicKey: options.receiver,
        amountSats: options.receiverAmountSats ?? 700n,
      }),
    ],
    status: options.status ?? TransferStatus.COMPLETED,
    totalValue: options.receiverAmountSats ?? 700n,
    expiryTime: timestampFromMs(Date.now() + 3_600_000),
    leaves: options.leaves.map((leaf) =>
      create(TransferLeafSchema, {
        leaf,
        secretCipher: new Uint8Array(64),
        sig: { case: "signature" as const, value: new Uint8Array(64) },
        intermediateRefundTx: new Uint8Array([9, 9, 9]),
      }),
    ),
    createdTime: timestampFromMs(1000),
    updatedTime: timestampFromMs(1000),
    type: options.type ?? TransferType.TRANSFER,
    network: Network.REGTEST,
  });
}

export function commitmentGroup(count: number): RequestedSigningCommitments[] {
  return Array.from({ length: count }, () =>
    create(RequestedSigningCommitmentsSchema, {
      signingNonceCommitments: Object.fromEntries(
        OPERATORS.map((operator, i) => [
          operator.identifier,
          {
            hiding: secp256k1.Point.BASE.toBytes(true),
            binding: secp256k1.Point.BASE.multiply(BigInt(i + 2)).toBytes(true),
          },
        ]),
      ),
    }),
  );
}

type Router = { service: (a: never, b: never) => void };

function authn(router: Router) {
  router.service(
    SparkAuthnService as never,
    {
      get_challenge: (req: { publicKey: Uint8Array }) => ({
        protectedChallenge: create(ProtectedChallengeSchema, {
          challenge: create(ChallengeSchema, {
            version: 1,
            timestamp: BigInt(Math.trunc(Date.now() / 1000)),
            nonce: new Uint8Array(4),
            publicKey: req.publicKey,
          }),
          serverHmac: new Uint8Array(4),
        }),
      }),
      verify_challenge: () => ({
        sessionToken: "so-tok",
        expirationTimestamp: BigInt(Math.trunc(Date.now() / 1000) + 600),
      }),
    } as never,
  );
}

export function clientWith(
  signer: Parameters<typeof createSparkClientWith>[0]["signer"],
  implFor: (identifier: string) => Record<string, unknown>,
  store: SparkStore,
): ReturnType<typeof createSparkClientWith> {
  return createSparkClientWith(
    {
      network: "regtest",
      signer,
      // oxlint-disable-next-line require-await -- the client fetch shape is async; nothing awaits here
      fetch: async () => {
        throw new Error("unexpected fetch");
      },
      random: (length) => randomBytes(length),
      sleep: async () => {
        await Promise.resolve();
      },
      store,
    },
    {
      transportFactory: (interceptors, operator) =>
        createRouterTransport(
          (router) => {
            authn(router);
            router.service(SparkService as never, implFor(operator.identifier));
          },
          { transport: { interceptors: [...interceptors] } },
        ),
    },
  );
}

/** The `query_nodes` handler used by every sync fixture: list all rows, or filter by id. */
export function queryNodesImpl(
  rowsFor: (identifier: string) => ReadonlyArray<TreeNode>,
  failingOps?: () => ReadonlyArray<string>,
): (identifier: string) => {
  query_nodes: (req: QueryNodesRequest) => {
    nodes: Record<string, TreeNode>;
    offset: bigint;
  };
} {
  return (identifier: string) => ({
    query_nodes: (req: QueryNodesRequest) => {
      if (
        req.source.case === "nodeIds" &&
        failingOps !== undefined &&
        failingOps().includes(identifier)
      ) {
        throw new SparkError("operator unavailable");
      }
      const rows = [...rowsFor(identifier)];
      const { source } = req;
      const hits =
        source.case === "nodeIds"
          ? rows.filter((row) => new Set(source.value.nodeIds).has(row.id))
          : rows;
      return {
        nodes: Object.fromEntries(hits.map((node, i) => [`${i}`, node])),
        offset: -1n,
      };
    },
  });
}

/** Returns `onRows` once `flag.active` flips, `offRows` before — a two-round row provider. */
export function toggleRows(
  flag: { active: boolean },
  offRows: () => TreeNode[],
  onRows: () => TreeNode[],
): () => TreeNode[] {
  return () => (flag.active ? onRows() : offRows());
}

/** Memory store that records every `deleteExitChains` call into `deleted`. */
export function recordingStore(): {
  readonly store: SparkStore;
  readonly deleted: string[];
} {
  const base = createMemorySparkStore();
  const deleted: string[] = [];
  const store: SparkStore = {
    ...base,
    deleteExitChains: async (leafIds) => {
      deleted.push(...leafIds);
      return base.deleteExitChains(leafIds);
    },
  };
  return { store, deleted };
}

/**
 * Real signer + every leaf served by every operator. Modes: `resume` passes an explicit transferId
 * so the send resolves on the retry probe alone; `lost` makes start_transfer_v2 fail so the send
 * recovers the committed row by the captured id; `fresh` answers start_transfer_v2 with the
 * inflated transfer. Each operator's query_transfers_by_id serves the same inflated transfer under
 * "same" or the honest `sendLeafId`-only transfer under "honest". Returns the transfer id the send
 * actually committed under.
 */
export async function sendHarness(state: {
  mode: "resume" | "lost" | "fresh";
  operatorTransfers: "same" | "honest";
  sendLeafId: string;
  otherLeafId: string;
  transferId: string;
  /** Operator identifiers whose `query_transfers_by_id` rejects — a transient failure. */
  failingOps?: ReadonlyArray<string>;
}): Promise<{
  client: ReturnType<typeof createSparkClientWith>;
  store: SparkStore;
  deleted: string[];
  signer: SparkSigner;
  committed: { id: string };
}> {
  const crypto = await loadWasmBackend();
  const signer = createSparkSigner({
    crypto,
    accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
    network: "regtest",
    random: (length) => randomBytes(length),
  });
  const identity = await signer.identityPublicKey();
  const [keyA, keyB] = await signer.publicKeys([
    { type: "leaf", leafId: state.sendLeafId },
    { type: "leaf", leafId: state.otherLeafId },
  ]);
  const leafRows = [keyA, keyB].map((key, i) => {
    const leafKey = required(key, `leaf public key ${i}`);
    return leafProto({
      id: i === 0 ? state.sendLeafId : state.otherLeafId,
      valueSats: 1000n,
      leafPublicKey: leafKey,
      verifyingPublicKey: secp256k1.Point.fromBytes(leafKey)
        .add(secp256k1.Point.fromBytes(SHARE_PUB))
        .toBytes(true),
      ownerIdentityPublicKey: identity,
    });
  });
  // The committed id is either the caller-supplied retry id (resume) or the id the mock
  // captured from start_transfer_v2 (lost/fresh) — a served row under any other id would not
  // match this send's expectation, exactly like production.
  const committed = { id: state.transferId };
  // Receiver edge ids are SO-local (upstream assigns a uuid.NewV7 per operator), so every
  // operator serves the same receiver under a different id — as the real SO does.
  const coordinatorTransfer = (leaves: ReadonlyArray<TreeNode>) =>
    transferProto({
      id: committed.id,
      sender: identity,
      receiver: RECEIVER,
      receiverAmountSats: 1000n,
      receiverId: `edge-${COORDINATOR}`,
      leaves,
    });
  const leafById = (id: string): TreeNode =>
    required(
      leafRows.find((row) => row.id === id),
      `leaf row ${id}`,
    );
  const operatorTransfer = (identifier: string, leaves: ReadonlyArray<TreeNode>) =>
    transferProto({
      id: committed.id,
      sender: identity,
      receiver: RECEIVER,
      receiverAmountSats: 1000n,
      receiverId: `edge-${identifier}`,
      leaves,
    });
  const honestTransfer = (identifier: string) =>
    operatorTransfer(identifier, [leafById(state.sendLeafId)]);
  const implFor = (identifier: string) => ({
    query_nodes: queryNodesImpl(() => leafRows)(identifier).query_nodes,
    get_signing_commitments: (req: { nodeIds?: string[]; count?: number }) =>
      create(GetSigningCommitmentsResponseSchema, {
        signingCommitments: commitmentGroup((req.count ?? 3) * (req.nodeIds?.length ?? 1)),
      }),
    ...(identifier === COORDINATOR
      ? {
          start_transfer_v2: (req: { transferId: string }) => {
            committed.id = req.transferId;
            if (state.mode === "lost") {
              throw new SparkError("response lost");
            }
            return { transfer: coordinatorTransfer(leafRows) };
          },
        }
      : {}),
    query_transfers_by_id: () => {
      if ((state.failingOps ?? []).includes(identifier)) {
        throw new SparkRequestError(`operator ${identifier} unreachable`, {
          code: "unavailable",
        });
      }
      if (identifier !== COORDINATOR && state.operatorTransfers === "honest") {
        return { transfers: [honestTransfer(identifier)] };
      }
      if (identifier !== COORDINATOR) {
        return { transfers: [operatorTransfer(identifier, leafRows)] };
      }
      return { transfers: [coordinatorTransfer(leafRows)] };
    },
  });
  const { store, deleted } = recordingStore();
  const client = clientWith(signer, implFor, store);
  return { client, store, deleted, signer, committed };
}

/** Sync harness: every operator serves `rows(identifier)`; nodeIds queries filter by id. */
export function syncHarness(state: {
  rows: (identifier: string) => TreeNode[];
  /** When set, the listed operators' nodeIds query rejects. */
  failingOps?: () => ReadonlyArray<string>;
  leafId: string;
  leafPublicKey: Uint8Array;
}): {
  client: ReturnType<typeof createSparkClientWith>;
  store: SparkStore;
  deleted: string[];
} {
  const implFor = queryNodesImpl(state.rows, state.failingOps);
  const { store, deleted } = recordingStore();
  const signer = createTestSigner(
    new Uint8Array(32).fill(7),
    new Map([[state.leafId, state.leafPublicKey]]),
  );
  return { client: clientWith(signer, implFor, store), store, deleted };
}

export function mulberry32(a: number): () => number {
  let t = a;
  return () => {
    t += 0x6d_2b_79_f5;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

/** Deterministic iteration picks: `pinned` plus a seeded sample of `total`. */
export function pickIterations(
  seed: number,
  total: number,
  count: number,
  pinned: ReadonlyArray<number>,
): number[] {
  const pick = new Set<number>(pinned);
  const rng = mulberry32(seed);
  while (pick.size < count) {
    pick.add(Math.trunc(rng() * total));
  }
  return [...pick].toSorted((a, b) => a - b);
}

const HARNESS_LEAF_IDS = ["leaf-0", "leaf-1", "leaf-2", "leaf-3"];
const HARNESS_NODE_IDS = [...HARNESS_LEAF_IDS, "mid-a", "mid-b", "root"];
const HARNESS_IDENTITY = secp256k1.getPublicKey(new Uint8Array(32).fill(1), true);
const HARNESS_LEAF_KEY = secp256k1.getPublicKey(new Uint8Array(32).fill(2), true);
const HARNESS_SHARE_PUB = secp256k1.getPublicKey(new Uint8Array(32).fill(3), true);

const STATUS_POOL = [
  TreeNodeStatus.AVAILABLE,
  TreeNodeStatus.EXITED,
  TreeNodeStatus.ON_CHAIN,
  TreeNodeStatus.RENEW_LOCKED,
  TreeNodeStatus.TRANSFER_LOCKED,
  TreeNodeStatus.UNAVAILABLE,
  TreeNodeStatus.FROZEN_BY_ISSUER,
];

type MutationKind =
  | "status"
  | "value"
  | "vout"
  | "keyshare-pub"
  | "drop-row"
  | "alias-row"
  | "duplicate-row";

const MUTATION_KINDS: MutationKind[] = [
  "status",
  "value",
  "vout",
  "keyshare-pub",
  "drop-row",
  "alias-row",
  "duplicate-row",
];

function mutateNode(
  row: TreeNode,
  rng: () => number,
  kind: MutationKind,
  aliasId: string,
): TreeNode {
  const copy = clone(TreeNodeSchema, row);
  if (kind === "status") {
    const status = required(STATUS_POOL[Math.trunc(rng() * STATUS_POOL.length)], "mutation status");
    copy.treenodeStatus = status;
    copy.status = status === TreeNodeStatus.AVAILABLE ? "AVAILABLE" : `STATUS_${status}`;
    return copy;
  }
  if (kind === "value") {
    copy.value += 1n + BigInt(Math.trunc(rng() * 8));
    return copy;
  }
  if (kind === "vout") {
    copy.vout = (row.vout + 1) % 4;
    return copy;
  }
  if (kind === "keyshare-pub") {
    const keyshare = required(row.signingKeyshare, "signing keyshare");
    copy.signingKeyshare = create(SigningKeyshareSchema, {
      ownerIdentifiers: [...keyshare.ownerIdentifiers],
      threshold: keyshare.threshold,
      publicKey: new Uint8Array(33).fill(8),
      publicShares: {},
    });
    return copy;
  }
  if (kind === "alias-row") {
    copy.id = aliasId;
  }
  return copy;
}

function harnessChainNode(
  id: string,
  parent: { id: string; nodeTx: Uint8Array } | undefined,
  keyshare: {
    ownerIdentifiers: string[];
    threshold: number;
    publicKey: Uint8Array;
    publicShares: Record<string, Uint8Array>;
  },
): TreeNode {
  const verifying = secp256k1.Point.fromBytes(HARNESS_LEAF_KEY)
    .add(secp256k1.Point.fromBytes(keyshare.publicKey))
    .toBytes(true);
  const nodeTx = txSpending(
    parent === undefined ? fakeTxid(0x30) : hexToBytes(txId(parent.nodeTx)),
    0,
    verifying,
    1000n,
  );
  const refundTx = txSpending(hexToBytes(txId(nodeTx)), 2000, HARNESS_LEAF_KEY, 1000n);
  return create(TreeNodeSchema, {
    id,
    treeId: `tree-${id.split("-")[0]}`,
    value: 1000n,
    nodeTx,
    refundTx,
    vout: 0,
    verifyingPublicKey: verifying,
    ownerIdentityPublicKey: HARNESS_IDENTITY,
    ownerSigningPublicKey: HARNESS_LEAF_KEY,
    signingKeyshare: keyshare,
    status: "AVAILABLE",
    network: Network.REGTEST,
    treenodeStatus: TreeNodeStatus.AVAILABLE,
    ...(parent === undefined ? {} : { parentNodeId: parent.id }),
  });
}

function harnessNodes(): Record<string, TreeNode> {
  const keyshare = {
    ownerIdentifiers: OPERATORS.map((operator) => operator.identifier),
    threshold: THRESHOLD,
    publicKey: HARNESS_SHARE_PUB,
    publicShares: {},
  };
  const root = harnessChainNode("root", undefined, keyshare);
  const midA = harnessChainNode("mid-a", root, keyshare);
  const midB = harnessChainNode("mid-b", root, keyshare);
  return {
    root,
    "mid-a": midA,
    "mid-b": midB,
    "leaf-0": harnessChainNode("leaf-0", midA, keyshare),
    "leaf-1": harnessChainNode("leaf-1", midA, keyshare),
    "leaf-2": harnessChainNode("leaf-2", midB, keyshare),
    "leaf-3": harnessChainNode("leaf-3", midB, keyshare),
  };
}

/** Rows matching `ids` plus, when `includeParents`, every ancestor reachable via parentNodeId. */
function withAncestors(
  nodes: Record<string, TreeNode>,
  ids: ReadonlyArray<string>,
  includeParents: boolean,
): TreeNode[] {
  const hits = new Map<string, TreeNode>();
  for (const id of ids) {
    let current = nodes[id];
    while (current !== undefined) {
      if (!hits.has(current.id)) {
        hits.set(current.id, current);
      }
      if (!includeParents) {
        break;
      }
      current = current.parentNodeId === undefined ? undefined : nodes[current.parentNodeId];
    }
  }
  return [...hits.values()];
}

/** Client whose test signer answers every leaf key — corrupt responses can name any id. */
export function harnessClientFor(
  implFor: (identifier: string) => Record<string, unknown>,
  store: SparkStore,
): ReturnType<typeof createSparkClientWith> {
  const signer = createTestSigner(new Uint8Array(32).fill(1), new Map(), HARNESS_LEAF_KEY);
  return createSparkClientWith(
    {
      network: "regtest",
      signer,
      // oxlint-disable-next-line require-await -- the client fetch shape is async; nothing awaits here
      fetch: async () => {
        throw new Error("unexpected fetch");
      },
      random: (length) => new Uint8Array(length).fill(1),
      sleep: async () => {
        await Promise.resolve();
      },
      store,
    },
    {
      transportFactory: (interceptors, operator) =>
        createRouterTransport(
          (router) => {
            authn(router);
            router.service(SparkService as never, implFor(operator.identifier));
          },
          { transport: { interceptors: [...interceptors] } },
        ),
    },
  );
}

/**
 * One H1 iteration: `iteration` seeds the corrupt party, its mutations and the nonce stream. A
 * fresh pair of clients — one honest view, one where `corruptIdentifier`'s node rows are mutated —
 * syncs; the violations collected are what the honest view proves impossible.
 */
export async function h1Iteration(iteration: number): Promise<string[]> {
  const seed = Math.imul(iteration, 2_654_435_761) >>> 0;
  const rng = mulberry32(seed);
  const corruptIndex = Math.trunc(rng() * OPERATORS.length);
  const corruptIdentifier = required(
    OPERATORS[corruptIndex],
    `operator ${corruptIndex}`,
  ).identifier;
  const mutCount = 1 + Math.trunc(rng() * 4);
  const mutations: Array<{ id: string; kind: MutationKind }> = [];
  for (let i = 0; i < mutCount; i++) {
    const id = required(
      HARNESS_NODE_IDS[Math.trunc(rng() * HARNESS_NODE_IDS.length)],
      "mutation target",
    );
    const kind = required(
      MUTATION_KINDS[Math.trunc(rng() * MUTATION_KINDS.length)],
      "mutation kind",
    );
    mutations.push({ id, kind });
  }

  const nodes = harnessNodes();
  const violations: string[] = [];

  const corruptImpl = (identifier: string) => ({
    query_nodes: (req: QueryNodesRequest) => {
      const all = serveHarnessNodes(nodes, req);
      const out = identifier === corruptIdentifier ? applyMutations(all, mutations, rng) : all;
      return { nodes: out, offset: -1n };
    },
  });
  const honestImpl = () => ({
    query_nodes: (req: QueryNodesRequest) => ({
      nodes: serveHarnessNodes(nodes, req),
      offset: -1n,
    }),
  });

  const honestStore = createMemorySparkStore();
  const honestClient = harnessClientFor(honestImpl, honestStore);
  const { store: corruptStore, deleted: corruptDeleted } = recordingStore();
  const corruptClient = harnessClientFor(corruptImpl, corruptStore);

  // The honest client's sync grounds truth: all four leaves owned, stored chains present.
  const honestLeaves = await honestClient.leaves();
  const honestBalance = await honestClient.balance();
  const honestChainsBefore = await honestStore.exitChains();
  expect(honestLeaves.map((leaf) => leaf.id)).toStrictEqual(HARNESS_LEAF_IDS);
  expect(honestChainsBefore.map((chain) => chain.leafId)).toStrictEqual(HARNESS_LEAF_IDS);

  // Same round on the corrupted party — may refuse or return a subset, but must never
  // inflate what the honest view reports.
  let corruptLeaves: ReadonlyArray<{ id: string; valueSats: number }> = [];
  let corruptBalance = -1;
  try {
    corruptLeaves = await corruptClient.leaves();
    corruptBalance = await corruptClient.balance();
  } catch (error) {
    if (!tolerableHarnessError(error)) {
      throw error;
    }
  }
  const beforeIds = new Set(honestLeaves.map((leaf) => leaf.id));
  const appeared = corruptLeaves.filter((leaf) => !beforeIds.has(leaf.id));
  if (appeared.length > 0) {
    violations.push(`I1: new ids appeared ${JSON.stringify(appeared.map((l) => l.id))}`);
  }
  if (corruptBalance > honestBalance) {
    violations.push(`I2: balance inflated ${corruptBalance} > ${honestBalance}`);
  }

  // A stored chain is deleted only on operator-endorsed positive evidence — mutations on a
  // single party can never fabricate it, so the corrupt store's chain count is non-decreasing
  // across syncs and a unilateral-exit attempt cannot shrink it either.
  const corruptChains = await corruptStore.exitChains();
  try {
    await corruptClient.leaves();
  } catch {
    // A corrupt sync may fail outright — the store must still be untouched.
  }
  const corruptChainsAfterSync = await corruptStore.exitChains();
  if (corruptChainsAfterSync.length < corruptChains.length) {
    const kept = new Set(corruptChainsAfterSync.map((chain) => chain.leafId));
    const dropped = corruptChains.map((chain) => chain.leafId).filter((id) => !kept.has(id));
    violations.push(
      `I5: corrupt sync dropped chains ${corruptChains.length} -> ${corruptChainsAfterSync.length} (${JSON.stringify(dropped)} party=${corruptIdentifier} mutations=${JSON.stringify(mutations)} deletedCalls=${JSON.stringify(corruptDeleted)})`,
    );
  }
  try {
    await corruptClient.withdrawals.unilateralExit(HARNESS_LEAF_IDS);
  } catch (error) {
    if (!tolerableHarnessError(error)) {
      throw error;
    }
  }
  const honestChainsAfter = await honestStore.exitChains();
  expect(honestChainsAfter.map((chain) => chain.leafId)).toStrictEqual(HARNESS_LEAF_IDS);
  const corruptChainsAfter = await corruptStore.exitChains();
  if (corruptChainsAfter.length < corruptChainsAfterSync.length) {
    violations.push("I6: unilateral exit mutated the corrupt store's chains");
  }
  return violations;
}

function serveHarnessNodes(
  nodes: Record<string, TreeNode>,
  req: QueryNodesRequest,
): Record<string, TreeNode> {
  if (req.source.case === "nodeIds") {
    const hits = withAncestors(nodes, req.source.value.nodeIds, req.includeParents);
    return Object.fromEntries(hits.map((row) => [row.id, row]));
  }
  if (req.source.case === "ownerIdentityPubkey" && !req.includeParents) {
    return Object.fromEntries(
      HARNESS_LEAF_IDS.map((id) => [id, required(nodes[id], `leaf ${id}`)]),
    );
  }
  return { ...nodes };
}

function applyMutations(
  served: Record<string, TreeNode>,
  mutations: ReadonlyArray<{ id: string; kind: MutationKind }>,
  rng: () => number,
): Record<string, TreeNode> {
  const dropIds = new Set(mutations.filter((m) => m.kind === "drop-row").map((m) => m.id));
  const out = Object.fromEntries(Object.entries(served).filter(([id]) => !dropIds.has(id)));
  for (const m of mutations) {
    if (m.kind === "drop-row") {
      continue;
    }
    const target = out[m.id];
    if (target === undefined) {
      continue;
    }
    const aliasId = `${m.id}-alias`;
    const mutated = mutateNode(target, rng, m.kind, aliasId);
    if (m.kind === "alias-row" || m.kind === "duplicate-row") {
      out[aliasId] = mutated;
    } else {
      out[m.id] = mutated;
    }
  }
  return out;
}

function tolerableHarnessError(error: unknown): boolean {
  return (
    error instanceof SparkError ||
    (error instanceof SparkRequestError &&
      (error.code === "unavailable" || error.code === "internal"))
  );
}

const H2_MUTATIONS = [
  "leaves-replace",
  "leaves-remove",
  "leaves-add",
  "leaf-id",
  "leaf-value",
  "status",
  "id-suffix",
  "receiver-identity",
  "receiver-key",
  "total-value",
  "expiry-past",
  "created-at",
  "id-mismatch",
] as const;
type H2Mutation = (typeof H2_MUTATIONS)[number];

const H2_TRANSFER_ID = "0199aaaa-bbbb-7ccc-8ddd-999999999999";
const H2_LEAF_IDS = ["send-a", "send-b", "send-c"];
const H2_UNSENT_IDS = ["unsent-a-0", "unsent-a-1", "unsent-b-2", "unsent-b-3"];

function h2Leaf(id: string, valueSats: bigint): TreeNode {
  const verifying = secp256k1.Point.fromBytes(HARNESS_LEAF_KEY)
    .add(secp256k1.Point.fromBytes(HARNESS_SHARE_PUB))
    .toBytes(true);
  const nodeTx = txSpending(fakeTxid(0x40), 0, verifying, valueSats);
  const refundTx = txSpending(hexToBytes(txId(nodeTx)), 2000, HARNESS_LEAF_KEY, valueSats);
  return create(TreeNodeSchema, {
    id,
    treeId: `tree-${id}`,
    value: valueSats,
    nodeTx,
    refundTx,
    vout: 0,
    verifyingPublicKey: verifying,
    ownerIdentityPublicKey: HARNESS_IDENTITY,
    ownerSigningPublicKey: HARNESS_LEAF_KEY,
    signingKeyshare: {
      ownerIdentifiers: OPERATORS.map((operator) => operator.identifier),
      threshold: THRESHOLD,
      publicKey: HARNESS_SHARE_PUB,
      publicShares: {},
    },
    status: "AVAILABLE",
    network: Network.REGTEST,
    treenodeStatus: TreeNodeStatus.AVAILABLE,
  });
}

function h2HonestTransfer(leafById: (id: string) => TreeNode, receiverId: string): Transfer {
  return create(TransferSchema, {
    id: H2_TRANSFER_ID,
    senderIdentityPublicKey: HARNESS_IDENTITY,
    receiverIdentityPublicKey: OTHER_LEAF_KEY,
    receivers: [
      create(TransferReceiverSchema, {
        id: receiverId,
        identityPublicKey: OTHER_LEAF_KEY,
        amountSats: 1000n,
      }),
    ],
    status: TransferStatus.COMPLETED,
    totalValue: 1000n,
    expiryTime: timestampFromMs(Date.now() + 3_600_000),
    leaves: H2_LEAF_IDS.map((id) =>
      create(TransferLeafSchema, {
        leaf: leafById(id),
        secretCipher: new Uint8Array(64),
        sig: { case: "signature" as const, value: new Uint8Array(64) },
        intermediateRefundTx: new Uint8Array([9, 9, 9]),
      }),
    ),
    createdTime: timestampFromMs(1000),
    updatedTime: timestampFromMs(1000),
    type: TransferType.TRANSFER,
    network: Network.REGTEST,
  });
}

function mutateTransfer(
  transfer: Transfer,
  mutation: H2Mutation,
  extraLeafId: string,
  leafById: (id: string) => TreeNode,
): Transfer {
  const copy = clone(TransferSchema, transfer);
  switch (mutation) {
    case "leaves-replace":
      copy.leaves = copy.leaves.map((leaf) =>
        create(TransferLeafSchema, { ...leaf, leaf: leafById(extraLeafId) }),
      );
      break;
    case "leaves-remove":
      copy.leaves = copy.leaves.slice(1);
      break;
    case "leaves-add":
      copy.leaves.push(
        create(TransferLeafSchema, {
          leaf: leafById(extraLeafId),
          secretCipher: new Uint8Array(64),
          sig: { case: "signature" as const, value: new Uint8Array(64) },
          intermediateRefundTx: new Uint8Array([9, 9, 9]),
        }),
      );
      break;
    case "leaf-id": {
      const [first] = copy.leaves;
      if (first?.leaf !== undefined) {
        first.leaf.id = "leaf-mutated";
      }
      break;
    }
    case "leaf-value": {
      const [first] = copy.leaves;
      if (first?.leaf !== undefined) {
        first.leaf.value = 999_999n;
      }
      break;
    }
    case "status":
      copy.status = TransferStatus.SENDER_KEY_TWEAKED;
      break;
    case "id-suffix":
    case "id-mismatch":
      copy.id = `${copy.id}-mutated`;
      break;
    case "receiver-identity":
      copy.receiverIdentityPublicKey = new Uint8Array(33).fill(9);
      break;
    case "receiver-key": {
      const [edge] = copy.receivers;
      if (edge !== undefined) {
        edge.identityPublicKey = new Uint8Array(33).fill(9);
      }
      break;
    }
    case "total-value":
      copy.totalValue += 1n;
      break;
    case "expiry-past":
      copy.expiryTime = timestampFromMs(Date.now() - 3_600_000);
      break;
    case "created-at":
      copy.createdTime = timestampFromMs(Date.now() - 86_400_000);
      break;
  }
  return copy;
}

/**
 * One H2 iteration: the coordinator alone serves a mutated commit (fresh response or lost-response
 * recovery); every other operator serves the honest transfer. A resolved send may only delete
 * chains for leaves the cross-verified transfer commits; a failed send deletes nothing.
 */
export async function h2Iteration(iteration: number): Promise<string[]> {
  const seed = Math.imul(iteration, 2_654_435_761) >>> 0;
  const rng = mulberry32(seed);
  const mutation = required(H2_MUTATIONS[Math.trunc(rng() * H2_MUTATIONS.length)], "h2 mutation");
  const extraLeaf = `unsent-${rng() > 0.5 ? "a" : "b"}-${Math.trunc(rng() * 4)}`;
  const startThrows = rng() > 0.5;
  const violations: string[] = [];

  const nodes: Record<string, TreeNode> = Object.fromEntries(
    H2_LEAF_IDS.map((id) => [id, h2Leaf(id, 1000n)]),
  );
  for (const id of H2_UNSENT_IDS) {
    nodes[id] = h2Leaf(id, 500n);
  }
  const leafById = (id: string): TreeNode => required(nodes[id], `leaf ${id}`);

  const implFor = (identifier: string) => {
    const isCoord = identifier === COORDINATOR;
    return {
      query_nodes: (req: QueryNodesRequest) => {
        if (req.source.case === "nodeIds") {
          const hits = req.source.value.nodeIds.flatMap((id) => {
            const row = nodes[id];
            return row === undefined ? [] : [row];
          });
          return { nodes: Object.fromEntries(hits.map((row) => [row.id, row])), offset: -1n };
        }
        return { nodes: { ...nodes }, offset: -1n };
      },
      get_signing_commitments: (req: { nodeIds?: string[]; count?: number }) =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: Array.from(
            { length: (req.count ?? 3) * (req.nodeIds?.length ?? 1) },
            () => create(RequestedSigningCommitmentsSchema, { signingNonceCommitments: {} }),
          ),
        }),
      ...(isCoord
        ? {
            start_transfer_v2: () => {
              if (startThrows) {
                throw new SparkError("response lost");
              }
              return {
                transfer: mutateTransfer(
                  h2HonestTransfer(leafById, `edge-${identifier}`),
                  mutation,
                  extraLeaf,
                  leafById,
                ),
              };
            },
          }
        : {}),
      query_transfers_by_id: () => {
        if (isCoord && !startThrows) {
          return { transfers: [] };
        }
        if (isCoord) {
          return {
            transfers: [
              mutateTransfer(
                h2HonestTransfer(leafById, `edge-${identifier}`),
                mutation,
                extraLeaf,
                leafById,
              ),
            ],
          };
        }
        return { transfers: [h2HonestTransfer(leafById, `edge-${identifier}`)] };
      },
    };
  };

  const store = createMemorySparkStore();
  const client = harnessClientFor(implFor, store);
  await client.leaves();
  const beforeChains = await store.exitChains();
  const chainsBefore = beforeChains.map((chain) => chain.leafId).toSorted();

  let sent: { id: string; leaves: ReadonlyArray<{ leaf: { id: string } }> } | undefined;
  try {
    sent = await client.transfers.send({ receiver: OTHER_LEAF_KEY, amountSats: 1000 });
  } catch {
    sent = undefined;
  }
  const afterChains = await store.exitChains();
  const chainsAfter = afterChains.map((chain) => chain.leafId).toSorted();
  const afterIds = new Set(chainsAfter);
  const deleted = chainsBefore.filter((id) => !afterIds.has(id));

  if (sent === undefined) {
    // An uncommitted or unverifiable send must not delete anything.
    if (deleted.length > 0) {
      violations.push(
        `iter ${iteration} (${mutation}): send failed but chains dropped ${JSON.stringify(deleted)}`,
      );
    }
    return violations;
  }
  // A resolved send may only drop leaf ids the cross-verified transfer actually commits.
  const committed = new Set(sent.leaves.map((leaf) => leaf.leaf.id));
  const orphanDeletes = deleted.filter((id) => !committed.has(id));
  if (orphanDeletes.length > 0) {
    violations.push(
      `iter ${iteration} (${mutation}): deleted uncommitted chains ${JSON.stringify(orphanDeletes)}`,
    );
  }
  // Chains for leaves NOT named in the verified transfer must survive.
  const survivingShould = H2_UNSENT_IDS.filter((id) => !committed.has(id));
  const missing = survivingShould.filter((id) => !afterIds.has(id));
  if (missing.length > 0) {
    violations.push(
      `iter ${iteration} (${mutation}): unrelated chains disappeared ${JSON.stringify(missing)}`,
    );
  }
  return violations;
}

export type { H2Mutation, MutationKind };
