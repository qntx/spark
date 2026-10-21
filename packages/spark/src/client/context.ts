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
import type { SparkSigner } from "../signer/types.ts";
import type { createSspClient } from "../ssp/index.ts";
import type { TransferCoordinator } from "../transfer/index.ts";
import { malformedLeafTx, operatorsDisagree, ownsLeaf, queryLeaves } from "../tree/index.ts";
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
  // drop chains for leaves the coordinator no longer reports as ours. The coordinator can lie,
  // so a leaf is spendable only when it is well-formed, held under our LEAF{id} key (ownership:
  // our public key plus the operators' share reaches the verifying key), and reported
  // identically by every operator — breez-spark-sdk refresh_leaves @956ff90. An owned leaf one
  // operator does not report is withheld from the result but keeps its stored chain, so a
  // lagging operator cannot make a just-claimed leaf look gone.
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
    const coordinatorLeaves = coordinatorResult.leaves;

    // An ancestor of another reported node is not a leaf, whatever status it carries.
    const parentIds = new Set<string>();
    for (const leaf of coordinatorLeaves) {
      if (leaf.parentNodeId !== undefined) {
        parentIds.add(leaf.parentNodeId);
      }
    }
    const reported = coordinatorLeaves.filter(
      (leaf) => !parentIds.has(leaf.id) && malformedLeafTx(leaf) === undefined,
    );

    // A coordinator row that failed to map never reaches `reported`, and an operator row that
    // failed to map is absent from that operator's map — both already read as unverifiable and
    // are quarantined below; they only matter here as still-reported ids for the chain sweep.
    const reportedIds = new Set<string>(coordinatorResult.unmappableIds);
    for (const leaf of coordinatorLeaves) {
      reportedIds.add(leaf.id);
    }
    for (const result of operatorResults) {
      for (const leaf of result.leaves) {
        reportedIds.add(leaf.id);
      }
      for (const id of result.unmappableIds) {
        reportedIds.add(id);
      }
    }

    const ownedIds = new Set<string>();
    const notOwnedIds = new Set<string>();
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
      } else {
        notOwnedIds.add(leaf.id);
      }
    }

    // Paging over a set an operator is concurrently mutating can return the same leaf on more
    // than one page; like Breez, keep the first occurrence.
    const operatorMaps = operatorResults.map(({ leaves: operatorLeaves }) => {
      const byId = new Map<string, SparkLeaf>();
      for (const leaf of operatorLeaves) {
        if (!byId.has(leaf.id)) {
          byId.set(leaf.id, leaf);
        }
      }
      return byId;
    });
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
    // A stored chain is the wallet's offline-exit data, so deleting one takes more than the
    // coordinator's word. Drop a chain only when no operator reported the id at all in this
    // sync — mapped or unmappable — or when the coordinator's row is not owned AND every other
    // operator serves a row agreeing with it: the operators then collectively attest the leaf
    // is no longer ours, as when a transferred-away leaf still shows up under our identity. A
    // coordinator-side omission, or a coordinator-tampered row another operator contradicts,
    // must not erase the chain the wallet would need to exit around a hostile coordinator.
    const reportedById = new Map(reported.map((leaf) => [leaf.id, leaf]));
    const attestedNotOwnedIds = new Set<string>();
    for (const leafId of notOwnedIds) {
      const coordinatorLeaf = reportedById.get(leafId);
      if (
        coordinatorLeaf !== undefined &&
        operatorMaps.every((byId) => {
          const operatorLeaf = byId.get(leafId);
          return operatorLeaf !== undefined && !operatorsDisagree(coordinatorLeaf, operatorLeaf);
        })
      ) {
        attestedNotOwnedIds.add(leafId);
      }
    }
    const stale = chains
      .map((chain) => chain.leafId)
      .filter((leafId) => !reportedIds.has(leafId) || attestedNotOwnedIds.has(leafId));
    if (stale.length > 0) {
      await store.deleteExitChains(stale);
    }
    return usable;
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
