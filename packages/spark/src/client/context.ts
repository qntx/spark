import { equalBytes } from "@noble/curves/utils.js";

import type { OperatorConnection } from "../connection/index.ts";
import { decodeSparkAddress, verifySparkAddressSignature } from "../core/address.ts";
import { createMutex } from "../core/mutex.ts";
import type { Mutex } from "../core/mutex.ts";
import type { SparkNetwork, SparkNetworkConfig, SparkOperatorConfig } from "../core/network.ts";
import { decodeTokenIdentifier } from "../core/token-identifier.ts";
import type { DepositCoordinator } from "../deposit/index.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import type { SparkStore } from "../exit/store.ts";
import { queryExitChains } from "../exit/unilateral.ts";
import { TreeNodeStatus } from "../proto/gen/spark_pb.ts";
import type { TreeNode } from "../proto/gen/spark_pb.ts";
import type { SparkSigner } from "../signer/types.ts";
import type { createSspClient } from "../ssp/index.ts";
import type { TransferCoordinator } from "../transfer/index.ts";
import {
  dedupeLeafRows,
  malformedLeafTx,
  mapTreeNode,
  operatorsDisagree,
  ownsLeaf,
  queryLeaves,
  queryNodesByIds,
  sameLeafRow,
} from "../tree/index.ts";
import type { SparkLeaf } from "../tree/index.ts";
import { batchedPublicKeys } from "../tree/signing.ts";

/** Everything the per-group factories share, built once per client. */
export type ClientContext = {
  readonly coordinatorConnection: OperatorConnection;
  /** A connection per non-coordinator operator, for cross-operator agreement checks. */
  readonly otherConnections: ReadonlyArray<OperatorConnection>;
  readonly signer: SparkSigner;
  readonly network: SparkNetwork;
  readonly config: SparkNetworkConfig;
  readonly operators: ReadonlyArray<SparkOperatorConfig>;
  readonly store: SparkStore;
  readonly random: (length: number) => Uint8Array;
  readonly now: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly transferCoordinator: TransferCoordinator;
  readonly depositCoordinator: DepositCoordinator;
  readonly sspClient: ReturnType<typeof createSspClient>;
  /**
   * Serializes every leaf-list mutation: selection through commit and exit-chain bookkeeping run
   * under it so two spends cannot pick the same leaves. Helpers taking part in a spend document
   * "caller holds leafLock" and never acquire it themselves.
   */
  readonly leafLock: Mutex;
  /** Serializes token output selection against broadcast, the same way leafLock does for sats. */
  readonly tokenLock: Mutex;
  /**
   * Refreshes and stores the exit chains of `leaves`; returns the ids of leaves whose served chain
   * failed verification — they are quarantined like operator-disagreeing leaves rather than thrown
   * over, so a commit that already happened still succeeds. Caller holds `leafLock`.
   */
  readonly storeChainsFor: (leaves: ReadonlyArray<SparkLeaf>) => Promise<ReadonlyArray<string>>;
  /** The unlocked leaf sync — caller holds `leafLock`. */
  readonly syncLeaves: () => Promise<ReadonlyArray<SparkLeaf>>;
  /** `syncLeaves` under `leafLock` — the public read path. */
  readonly leaves: () => Promise<ReadonlyArray<SparkLeaf>>;
  readonly receiverIdentityKey: (receiver: string | Uint8Array) => Uint8Array;
  readonly tokenIdentifierForNetwork: (text: string) => Uint8Array;
};

/**
 * The node statuses that prove a stored exit chain can never be broadcast again — deletion is
 * justified only on this positive evidence (or unanimous owner change), never on absence from the
 * AVAILABLE listing. ON_CHAIN is deliberately absent: upstream `MarkExitingNodes`
 * (so/tree/tree.go:55-82) flips a leaf to it the moment its node tx confirms while the refund is
 * still CSV-locked — the stored chain is exactly what the wallet needs to finish that exit. For the
 * same reason PARENT_EXITED (non-terminal, drains to EXITED), CONSOLIDATED (exit-only node whose
 * stored package is the exit path), FROZEN_BY_ISSUER, TRANSFER_LOCKED, RENEW_LOCKED and the retired
 * SPLITTED/AGGREGATED keep their chains: the SO's own `IsTerminal`
 * (so/ent/schema/schematype/treenode_status.go:285-312) does not mark them exited, and a leaf whose
 * renewal split it keeps an owner it still has — internal_renew_handler.go:175 carries the owner
 * key to the split node, so no owner-change evidence exists. Of `IsTerminal`'s statuses,
 * LOST/REIMBURSED/CREATION_ABANDONED never reach the wire enum, leaving:
 */
const TERMINAL_CHAIN_STATUSES: ReadonlySet<number> = new Set([
  // Refund tx confirmed — the exit completed (treenode_status.go:23-24).
  TreeNodeStatus.EXITED,
  // An ancestor's direct tx conflict-spent the outpoint the node's tx claims — terminal
  // (treenode_status.go:43-46).
  TreeNodeStatus.WATCHTOWER_EXITED,
  // The swept output already has a co-signed spend — terminal (treenode_status.go:47-56).
  TreeNodeStatus.WATCHTOWER_EXIT_RECOVERED,
]);

export function createClientContext(
  parts: Omit<
    ClientContext,
    | "leafLock"
    | "tokenLock"
    | "storeChainsFor"
    | "syncLeaves"
    | "leaves"
    | "receiverIdentityKey"
    | "tokenIdentifierForNetwork"
  >,
): ClientContext {
  const { coordinatorConnection, otherConnections, signer, network, store } = parts;
  const leafLock = createMutex();
  const tokenLock = createMutex();

  const storeChainsFor = async (
    forLeaves: ReadonlyArray<SparkLeaf>,
  ): Promise<ReadonlyArray<string>> => {
    const { chains, rejected } = await queryExitChains({
      spark: coordinatorConnection.spark,
      operators: otherConnections.map((connection) => connection.spark),
      network,
      signer,
      leaves: forLeaves,
    });
    await store.putExitChains(chains);
    return rejected.map((entry) => entry.leafId);
  };

  // Syncing leaves is the reconciliation point: refresh every spendable leaf's exit chain and
  // drop chains only on operator-endorsed proof the leaf is gone for good (see the sweep below).
  // The coordinator can lie, so a leaf is spendable only when it is well-formed, held under our
  // LEAF{id} key (ownership: our public key plus the operators' share reaches the verifying key),
  // and reported identically by every operator — breez-spark-sdk refresh_leaves @956ff90. An
  // owned leaf one operator does not report is withheld from the result but keeps its stored
  // chain, so a lagging operator cannot make a just-claimed leaf look gone.
  const syncLeaves = async (): Promise<ReadonlyArray<SparkLeaf>> => {
    const ownerIdentityPublicKey = await signer.identityPublicKey();
    const [coordinatorResult, ...operatorResults] = await Promise.all([
      queryLeaves({
        spark: coordinatorConnection.spark,
        ownerIdentityPublicKey,
        network,
      }),
      ...otherConnections.map(async (connection) =>
        queryLeaves({
          spark: connection.spark,
          ownerIdentityPublicKey,
          network,
        }),
      ),
    ]);
    // A party can serve the same leaf id under two map keys (honest paging overlap repeats rows
    // too). Identical copies dedupe to one row; two DIFFERENT rows for one id are unverifiable and
    // quarantine the id — it is never spendable, never counted in the balance, and never a
    // deletion witness this sync (otherwise a coordinator could pair a tampered copy with an
    // honest one to smuggle a leaf past the agreement checks).
    const coordinatorRows = dedupeLeafRows(coordinatorResult.leaves);
    const operatorRows = operatorResults.map((result) => dedupeLeafRows(result.leaves));
    const conflictedIds = new Set(coordinatorRows.conflicted);
    for (const rows of operatorRows) {
      for (const id of rows.conflicted) {
        conflictedIds.add(id);
      }
    }

    // An ancestor of another reported node is not a leaf, whatever status it carries.
    const parentIds = new Set<string>();
    for (const leaf of coordinatorRows.unique) {
      if (leaf.parentNodeId !== undefined) {
        parentIds.add(leaf.parentNodeId);
      }
    }
    const reported = coordinatorRows.unique.filter(
      (leaf) => !parentIds.has(leaf.id) && malformedLeafTx(leaf) === undefined,
    );

    const ownedIds = new Set<string>();
    const keys = await batchedPublicKeys(
      signer,
      reported.map((leaf) => ({ type: "leaf", leafId: leaf.id })),
    );
    for (const [i, leaf] of reported.entries()) {
      const leafPublicKey = keys[i];
      if (leafPublicKey === undefined) {
        throw new SparkError("leaves: signer returned fewer public keys than requested");
      }
      if (ownsLeaf(leaf, leafPublicKey)) {
        ownedIds.add(leaf.id);
      }
    }

    const operatorMaps = operatorRows.map(
      ({ unique }) => new Map(unique.map((leaf) => [leaf.id, leaf])),
    );
    const spendable = reported.filter(
      (leaf) =>
        ownedIds.has(leaf.id) &&
        operatorMaps.every((byId) => {
          const operatorLeaf = byId.get(leaf.id);
          return operatorLeaf !== undefined && !operatorsDisagree(leaf, operatorLeaf);
        }),
    );

    // A leaf whose served exit chain fails verification is quarantined like a disagreeing
    // leaf — withheld from the spendable result but still counted as owned, so its previously
    // stored (already verified) chain survives the stale sweep and unilateralExit on it still
    // reports the precise error.
    const rejectedIds = new Set(await storeChainsFor(spendable));
    const usable = spendable.filter((leaf) => !rejectedIds.has(leaf.id));
    const chains = await store.exitChains();
    // A stored chain is the wallet's offline-exit data — deleting one takes operator-endorsed
    // positive evidence, never mere absence from this sync's AVAILABLE listing: a leaf mid
    // unilateral exit flips to ON_CHAIN (its node tx confirmed while the refund is still
    // CSV-locked, MarkExitingNodes) and simply stops being listed, so "not reported" must not
    // erase the chain the wallet needs right then. Every stored id outside this sync's spendable
    // set is re-queried by node id — no status filter — from EVERY operator; a chain is deleted
    // only when every operator answers and either none of them serves the node at all, or all
    // serve the same row showing it is no longer exitable by this wallet (owner changed, a
    // TERMINAL_CHAIN_STATUSES status, or a row the wallet's key math cannot own). Any
    // operator error, a missing row on some but not all
    // operators, disagreement, or a conflicting-row id keeps the chain.
    const spendableIds = new Set(spendable.map((leaf) => leaf.id));
    const candidates: string[] = [];
    for (const chain of chains) {
      if (!spendableIds.has(chain.leafId) && !conflictedIds.has(chain.leafId)) {
        candidates.push(chain.leafId);
      }
    }
    const stale = await endorsedChainDeletions(candidates, ownerIdentityPublicKey);
    if (stale.length > 0) {
      await store.deleteExitChains(stale);
    }
    return usable;
  };

  /**
   * The stored-chain ids every operator agrees are gone for good. Queries `leafIds` by node id — no
   * status filter — from the coordinator and every other operator. An operator transport error
   * fails the sweep closed: no deletions at all.
   */
  const endorsedChainDeletions = async (
    leafIds: ReadonlyArray<string>,
    ownerIdentityPublicKey: Uint8Array,
  ): Promise<ReadonlyArray<string>> => {
    if (leafIds.length === 0) {
      return [];
    }
    const clients = [
      coordinatorConnection.spark,
      ...otherConnections.map((connection) => connection.spark),
    ];
    let maps: ReadonlyArray<ReadonlyMap<string, TreeNode[]>>;
    try {
      maps = await Promise.all(
        clients.map(async (spark) => {
          const rows = new Map<string, TreeNode[]>();
          for (const node of await queryNodesByIds(spark, leafIds, network, false)) {
            const list = rows.get(node.id);
            if (list === undefined) {
              rows.set(node.id, [node]);
            } else {
              list.push(node);
            }
          }
          return rows;
        }),
      );
    } catch {
      return [];
    }
    const stale: string[] = [];
    const keyChecks = new Map<string, SparkLeaf>();
    for (const leafId of leafIds) {
      const served = maps.map((byId) => byId.get(leafId) ?? []);
      // An operator serving two rows for the id cannot be evaluated — keep the chain.
      if (served.some((rows) => rows.length > 1)) {
        continue;
      }
      const rows = served.map((list) => list[0]);
      if (rows.every((row) => row === undefined)) {
        // Endorsed absence: every operator answered and none serves the node.
        stale.push(leafId);
        continue;
      }
      const present = rows.filter((row) => row !== undefined);
      if (present.length !== rows.length) {
        continue;
      }
      const [reference] = present;
      if (reference === undefined) {
        continue;
      }
      // "All agree" means literally the same row on every operator: a coordinator whose row
      // differs on any mapped field cannot borrow the other rows' verdict, and a row that
      // cannot be mapped cannot vouch for anything.
      const mapped: SparkLeaf[] = [];
      let unmappable = false;
      for (const row of present) {
        try {
          mapped.push(mapTreeNode(row));
        } catch {
          unmappable = true;
          break;
        }
      }
      const [referenceLeaf] = mapped;
      if (unmappable || referenceLeaf === undefined) {
        continue;
      }
      const agree =
        present.every((row) => row.treenodeStatus === reference.treenodeStatus) &&
        mapped.every((leaf) => sameLeafRow(referenceLeaf, leaf));
      if (!agree) {
        continue;
      }
      const notOurs =
        reference.ownerIdentityPublicKey.length === 33 &&
        !equalBytes(reference.ownerIdentityPublicKey, ownerIdentityPublicKey);
      if (notOurs || TERMINAL_CHAIN_STATUSES.has(reference.treenodeStatus)) {
        stale.push(leafId);
        continue;
      }
      // A unanimously served row the wallet cannot sign for — its leaf key plus the reported
      // keyshare does not reach the verifying key — is endorsed evidence the leaf is not
      // exitable here, the same judgement the spendable filter made on it.
      keyChecks.set(leafId, referenceLeaf);
    }
    if (keyChecks.size > 0) {
      const ids = [...keyChecks.keys()];
      const keys = await batchedPublicKeys(
        signer,
        ids.map((leafId) => ({ type: "leaf", leafId })),
      );
      for (const [i, leafId] of ids.entries()) {
        const leaf = keyChecks.get(leafId);
        const leafPublicKey = keys[i];
        if (leaf !== undefined && leafPublicKey !== undefined && !ownsLeaf(leaf, leafPublicKey)) {
          stale.push(leafId);
        }
      }
    }
    return stale;
  };

  /** Resolves a spark address string or raw identity public key to the receiver's identity key. */
  const receiverIdentityKey = (receiver: string | Uint8Array): Uint8Array => {
    if (typeof receiver !== "string") {
      if (receiver.length !== 33) {
        throw new SparkInputError("send: receiver identity public key must be 33 bytes");
      }
      return receiver;
    }
    const address = decodeSparkAddress(receiver);
    if (address.network !== network) {
      throw new SparkInputError(`send: receiver address is for ${address.network}`);
    }
    if (address.invoice !== undefined) {
      throw new SparkInputError("send: invoice-carrying addresses must be paid via invoices.pay");
    }
    if (
      address.signature !== undefined &&
      address.signature.length > 0 &&
      !verifySparkAddressSignature(address)
    ) {
      throw new SparkInputError("send: receiver address signature is invalid");
    }
    return address.identityPublicKey;
  };

  /** Decodes a bech32m token identifier and rejects other networks' prefixes. */
  const tokenIdentifierForNetwork = (text: string): Uint8Array => {
    const decoded = decodeTokenIdentifier(text);
    if (decoded.network !== network) {
      throw new SparkInputError(`token identifier is for ${decoded.network}, expected ${network}`);
    }
    return decoded.tokenIdentifier;
  };

  return {
    ...parts,
    leafLock,
    tokenLock,
    storeChainsFor,
    syncLeaves,
    leaves: async () => leafLock.run(syncLeaves),
    receiverIdentityKey,
    tokenIdentifierForNetwork,
  };
}
