import { describe, expect, test } from "vite-plus/test";

import { TreeNodeStatus } from "../src/proto/gen/spark_pb.ts";
import type { TreeNode } from "../src/proto/gen/spark_pb.ts";
import {
  COORDINATOR,
  LEAF_PUBLIC,
  OPERATORS,
  OTHER_IDENTITY,
  OTHER_LEAF_KEY,
  OTHER_VERIFYING,
  RECEIVER,
  TEST_IDENTITY,
  VERIFYING_KEY,
  leafProto,
  required,
  sendHarness,
  syncHarness,
  toggleRows,
} from "./support/audit-r10.ts";

const OP1 = required(OPERATORS[1], "operator 1").identifier;
const OP2 = required(OPERATORS[2], "operator 2").identifier;

// Regression coverage for external-audit round 10 N-01, N-02, N-04 and L-05: an exit chain is
// deleted only on operator-endorsed positive evidence — a reported transfer leaf list deletes
// only the intersection with this call's selection, a retry-probe hit deletes nothing, and the
// sync sweep deletes only when every operator agrees the leaf is gone or terminally non-exitable.

describe("N-01/L-05: reported transfer leaf lists never delete unrelated chains", () => {
  const LEAF_A = "send-a";
  const LEAF_B = "send-b";
  const TRANSFER_ID = "0199aaaa-bbbb-7ccc-8ddd-111111111111";

  test("a retry-probe hit naming an unrelated leaf resolves but deletes nothing", async () => {
    const { client, store, deleted, signer } = await sendHarness({
      mode: "resume",
      operatorTransfers: "same",
      sendLeafId: LEAF_A,
      otherLeafId: LEAF_B,
      transferId: TRANSFER_ID,
    });
    await client.leaves();
    const chainsBefore = await store.exitChains();
    expect(chainsBefore.map((chain) => chain.leafId).toSorted()).toStrictEqual([LEAF_A, LEAF_B]);

    // The probe finds a committed transfer whose leaf list includes send-b, which this send
    // never selected. Every operator serves the same row, so the transfer is genuinely
    // committed — the result resolves — but a probe hit deletes no chains (N-01): the sync
    // sweep is the only place a spent leaf's chain is reclaimed.
    const sent = await client.transfers.send({
      receiver: RECEIVER,
      amountSats: 1000,
      transferId: TRANSFER_ID,
    });
    expect(sent.id).toBe(TRANSFER_ID);
    expect(sent.leaves.map((leaf) => leaf.leaf.id).toSorted()).toStrictEqual([LEAF_A, LEAF_B]);
    expect(deleted).toStrictEqual([]);
    const chainsAfter = await store.exitChains();
    expect(chainsAfter.map((chain) => chain.leafId).toSorted()).toStrictEqual([LEAF_A, LEAF_B]);
    await expect(client.withdrawals.offlineExitTransactions([LEAF_B])).resolves.toHaveLength(2);
    const leaves = await client.leaves();
    expect(leaves.map((leaf) => leaf.id).toSorted()).toStrictEqual([LEAF_A, LEAF_B]);
    signer.dispose();
  });

  test("a probe hit whose leaf set differs across operators aborts the send", async () => {
    const { client, store, deleted, signer } = await sendHarness({
      mode: "resume",
      operatorTransfers: "honest",
      sendLeafId: LEAF_A,
      otherLeafId: LEAF_B,
      transferId: TRANSFER_ID,
    });
    await client.leaves();
    await expect(
      client.transfers.send({ receiver: RECEIVER, amountSats: 1000, transferId: TRANSFER_ID }),
    ).rejects.toThrow(/differs across operators/);
    expect(deleted).toStrictEqual([]);
    const chains = await store.exitChains();
    expect(chains.map((chain) => chain.leafId).toSorted()).toStrictEqual([LEAF_A, LEAF_B]);
    signer.dispose();
  });

  test("a fresh commit naming unselected leaves deletes only the verified selection", async () => {
    const { client, store, deleted, signer, committed } = await sendHarness({
      mode: "fresh",
      operatorTransfers: "same",
      sendLeafId: LEAF_A,
      otherLeafId: LEAF_B,
      transferId: TRANSFER_ID,
    });
    await client.leaves();
    // Every operator agrees the committed transfer names both leaves — but this call selected
    // only send-a, so only send-a's chain may go (N-01). send-b stays spendable and exitable.
    const sent = await client.transfers.send({ receiver: RECEIVER, amountSats: 1000 });
    expect(sent.id).toBe(committed.id);
    expect(deleted).toStrictEqual([LEAF_A]);
    const chains = await store.exitChains();
    expect(chains.map((chain) => chain.leafId)).toStrictEqual([LEAF_B]);
    await expect(client.withdrawals.offlineExitTransactions([LEAF_B])).resolves.toHaveLength(2);
    signer.dispose();
  });

  test("a lost-response recovery names the committed leaves but deletes only the verified selection", async () => {
    const { client, store, deleted, signer } = await sendHarness({
      mode: "lost",
      operatorTransfers: "same",
      sendLeafId: LEAF_A,
      otherLeafId: LEAF_B,
      transferId: TRANSFER_ID,
    });
    await client.leaves();
    // The response was lost but the transfer committed server-side; every operator confirms it
    // names both leaves. The send resolves and may delete only what this call selected AND the
    // verified transfer commits — send-b's chain survives (N-01).
    const sent = await client.transfers.send({ receiver: RECEIVER, amountSats: 1000 });
    expect(sent.leaves.map((leaf) => leaf.leaf.id).toSorted()).toStrictEqual([LEAF_A, LEAF_B]);
    expect(deleted).toHaveLength(1);
    const remainingChains = await store.exitChains();
    const remaining = remainingChains.map((chain) => chain.leafId);
    expect(remaining).toHaveLength(1);
    expect(remaining[0]).not.toBe(deleted[0]);
    signer.dispose();
  });

  test("a fresh commit whose leaf set differs across operators aborts before any deletion", async () => {
    const { client, store, deleted, signer } = await sendHarness({
      mode: "fresh",
      operatorTransfers: "honest",
      sendLeafId: LEAF_A,
      otherLeafId: LEAF_B,
      transferId: TRANSFER_ID,
    });
    await client.leaves();
    await expect(client.transfers.send({ receiver: RECEIVER, amountSats: 1000 })).rejects.toThrow(
      /differs across operators/,
    );
    expect(deleted).toStrictEqual([]);
    const chains = await store.exitChains();
    expect(chains.map((chain) => chain.leafId).toSorted()).toStrictEqual([LEAF_A, LEAF_B]);
    signer.dispose();
  });
});

describe("N-02: stored chains are dropped only on all-operator terminal evidence", () => {
  const LEAF_ID = "leaf-1";

  const ownedLeaf = (status: TreeNodeStatus, transferred = false) =>
    leafProto({
      id: LEAF_ID,
      valueSats: 1000n,
      leafPublicKey: transferred ? OTHER_LEAF_KEY : LEAF_PUBLIC,
      verifyingPublicKey: transferred ? OTHER_VERIFYING : VERIFYING_KEY,
      ownerIdentityPublicKey: transferred ? OTHER_IDENTITY : TEST_IDENTITY,
      status,
    });

  /** Rows keyed by per-operator status; unspecified operators get AVAILABLE. */
  const perOpRows = (byOp: Record<string, TreeNodeStatus>) => (identifier: string) => [
    ownedLeaf(byOp[identifier] ?? TreeNodeStatus.AVAILABLE),
  ];

  test("an AVAILABLE -> ON_CHAIN flip keeps the stored chain and the offline exit package", async () => {
    const status: { current: TreeNodeStatus } = { current: TreeNodeStatus.AVAILABLE };
    const { client, store } = syncHarness({
      rows: () => [ownedLeaf(status.current)],
      leafId: LEAF_ID,
      leafPublicKey: LEAF_PUBLIC,
    });
    await expect(client.leaves()).resolves.toHaveLength(1);
    await expect(store.exitChains()).resolves.toHaveLength(1);

    // The node tx confirmed: every operator reports ON_CHAIN. That is not terminal — the
    // refund path is still live — so the chain must survive every later sync (N-02).
    status.current = TreeNodeStatus.ON_CHAIN;
    await expect(client.leaves()).resolves.toStrictEqual([]);
    const chains = await store.exitChains();
    expect(chains.map((chain) => chain.leafId)).toStrictEqual([LEAF_ID]);
    const backup = await client.withdrawals.offlineExitTransactions([LEAF_ID]);
    expect(backup.map((tx) => tx.kind)).toStrictEqual(["node", "refund"]);
  });

  test("an EXITED status on every operator drops the stored chain", async () => {
    const status: { current: TreeNodeStatus } = { current: TreeNodeStatus.AVAILABLE };
    const { client, store } = syncHarness({
      rows: () => [ownedLeaf(status.current)],
      leafId: LEAF_ID,
      leafPublicKey: LEAF_PUBLIC,
    });
    await client.leaves();
    status.current = TreeNodeStatus.EXITED;
    await expect(client.leaves()).resolves.toStrictEqual([]);
    await expect(store.exitChains()).resolves.toStrictEqual([]);
  });

  test("an owner change on every operator drops the stored chain", async () => {
    const moved = { current: false };
    const { client, store } = syncHarness({
      rows: () => [ownedLeaf(TreeNodeStatus.AVAILABLE, moved.current)],
      leafId: LEAF_ID,
      leafPublicKey: LEAF_PUBLIC,
    });
    await client.leaves();
    moved.current = true;
    await expect(client.leaves()).resolves.toStrictEqual([]);
    await expect(store.exitChains()).resolves.toStrictEqual([]);
  });

  test("disagreeing terminal evidence retains the chain", async () => {
    const statusByOp: Record<string, TreeNodeStatus> = {};
    const { client, store } = syncHarness({
      rows: perOpRows(statusByOp),
      leafId: LEAF_ID,
      leafPublicKey: LEAF_PUBLIC,
    });
    await client.leaves();
    await expect(store.exitChains()).resolves.toHaveLength(1);

    // The coordinator claims EXITED; two operators still report ON_CHAIN — no unanimous
    // terminal evidence, so the chain survives.
    statusByOp[COORDINATOR] = TreeNodeStatus.EXITED;
    statusByOp[OP1] = TreeNodeStatus.ON_CHAIN;
    statusByOp[OP2] = TreeNodeStatus.ON_CHAIN;
    await expect(client.leaves()).resolves.toStrictEqual([]);
    const chains = await store.exitChains();
    expect(chains.map((chain) => chain.leafId)).toStrictEqual([LEAF_ID]);
  });

  test("an operator error on the terminal-evidence query retains the chain", async () => {
    const status: { current: TreeNodeStatus } = { current: TreeNodeStatus.AVAILABLE };
    const failing = { ops: [] as string[] };
    const { client, store } = syncHarness({
      rows: () => [ownedLeaf(status.current)],
      failingOps: () => failing.ops,
      leafId: LEAF_ID,
      leafPublicKey: LEAF_PUBLIC,
    });
    await client.leaves();
    await expect(store.exitChains()).resolves.toHaveLength(1);

    status.current = TreeNodeStatus.ON_CHAIN;
    failing.ops = [OP1];
    await expect(client.leaves()).resolves.toStrictEqual([]);
    const chains = await store.exitChains();
    expect(chains.map((chain) => chain.leafId)).toStrictEqual([LEAF_ID]);
  });

  test("a leaf no operator serves any more is deleted", async () => {
    const served = { active: true };
    const { client, store } = syncHarness({
      rows: toggleRows(
        served,
        () => [],
        () => [ownedLeaf(TreeNodeStatus.AVAILABLE)],
      ),
      leafId: LEAF_ID,
      leafPublicKey: LEAF_PUBLIC,
    });
    await client.leaves();
    await expect(store.exitChains()).resolves.toHaveLength(1);
    served.active = false;
    await expect(client.leaves()).resolves.toStrictEqual([]);
    await expect(store.exitChains()).resolves.toStrictEqual([]);
  });
});

describe("N-04: conflicting duplicate rows quarantine an id", () => {
  const LEAF_ID = "leaf-1";

  const row = (overrides: { value?: bigint; transferred?: boolean } = {}) =>
    leafProto({
      id: LEAF_ID,
      valueSats: overrides.value ?? 1000n,
      leafPublicKey: overrides.transferred === true ? OTHER_LEAF_KEY : LEAF_PUBLIC,
      verifyingPublicKey: overrides.transferred === true ? OTHER_VERIFYING : VERIFYING_KEY,
      ownerIdentityPublicKey: overrides.transferred === true ? OTHER_IDENTITY : TEST_IDENTITY,
    });

  function dupHarness(coordinatorRows: () => TreeNode[]) {
    return syncHarness({
      rows: (identifier) => (identifier === COORDINATOR ? coordinatorRows() : [row()]),
      leafId: LEAF_ID,
      leafPublicKey: LEAF_PUBLIC,
    });
  }

  test("two differing rows for one id are neither spendable nor a deletion witness", async () => {
    // Round 1 stores the chain from one honest row. Round 2 serves the same id under two map
    // keys with different values: the id is quarantined — not spendable, not counted — and,
    // crucially, the stored chain is NOT deleted even though the other operators keep serving
    // a clean AVAILABLE row.
    const conflicted = { active: false };
    const { client, store } = dupHarness(
      toggleRows(
        conflicted,
        () => [row()],
        () => [row(), row({ value: 2000n })],
      ),
    );
    await client.leaves();
    await expect(store.exitChains()).resolves.toHaveLength(1);

    conflicted.active = true;
    await expect(client.leaves()).resolves.toStrictEqual([]);
    await expect(client.balance()).resolves.toBe(0);
    const chains = await store.exitChains();
    expect(chains.map((chain) => chain.leafId)).toStrictEqual([LEAF_ID]);
  });

  test("identical duplicate rows dedupe to one spendable leaf", async () => {
    const { client, store } = dupHarness(() => [row(), row()]);
    const leaves = await client.leaves();
    expect(leaves.map((leaf) => leaf.id)).toStrictEqual([LEAF_ID]);
    await expect(client.balance()).resolves.toBe(1000);
    await expect(store.exitChains()).resolves.toHaveLength(1);
  });

  test("an owned+not-owned pair never endorses a chain deletion", async () => {
    // Round 1: one owned row, chain stored. Round 2: the coordinator serves the same id twice —
    // once owned, once belonging to someone else. The not-owned row must not endorse deleting
    // the chain while the owned row exists.
    const mutated = { active: false };
    const { client, store } = dupHarness(
      toggleRows(
        mutated,
        () => [row()],
        () => [row(), row({ transferred: true })],
      ),
    );
    await client.leaves();
    await expect(store.exitChains()).resolves.toHaveLength(1);

    mutated.active = true;
    await expect(client.leaves()).resolves.toStrictEqual([]);
    const chains = await store.exitChains();
    expect(chains.map((chain) => chain.leafId)).toStrictEqual([LEAF_ID]);
  });
});
