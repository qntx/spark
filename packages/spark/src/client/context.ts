import type { OperatorConnection } from "../connection/index.ts";
import { decodeSparkAddress, verifySparkAddressSignature } from "../core/address.ts";
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

/** Signer `publicKeys`/`signFrost` calls bound each batch; match the signer's per-call limit. */
const SIGNER_BATCH = 256;

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
  readonly transferCoordinator: TransferCoordinator;
  readonly depositCoordinator: DepositCoordinator;
  readonly sspClient: ReturnType<typeof createSspClient>;
  readonly storeChainsFor: (leaves: ReadonlyArray<SparkLeaf>) => Promise<void>;
  readonly leaves: () => Promise<ReadonlyArray<SparkLeaf>>;
  readonly receiverIdentityKey: (receiver: string | Uint8Array) => Uint8Array;
  readonly tokenIdentifierForNetwork: (text: string) => Uint8Array;
};

export function createClientContext(
  parts: Omit<
    ClientContext,
    "storeChainsFor" | "leaves" | "receiverIdentityKey" | "tokenIdentifierForNetwork"
  >,
): ClientContext {
  const { coordinatorConnection, otherConnections, signer, network, store } = parts;

  const storeChainsFor = async (forLeaves: ReadonlyArray<SparkLeaf>): Promise<void> =>
    store.putExitChains(
      await queryExitChains({
        spark: coordinatorConnection.spark,
        network,
        leaves: forLeaves,
      }),
    );

  // Syncing leaves is the reconciliation point: refresh every spendable leaf's exit chain and
  // drop chains for leaves the coordinator no longer reports as ours. The coordinator can lie,
  // so a leaf is spendable only when it is well-formed, held under our LEAF{id} key (ownership:
  // our public key plus the operators' share reaches the verifying key), and reported
  // identically by every operator — breez-spark-sdk refresh_leaves @956ff90. An owned leaf one
  // operator does not report is withheld from the result but keeps its stored chain, so a
  // lagging operator cannot make a just-claimed leaf look gone.
  const leaves = async (): Promise<ReadonlyArray<SparkLeaf>> => {
    const ownerIdentityPublicKey = await signer.identityPublicKey();
    const [coordinatorLeaves, ...operatorLeafLists] = await Promise.all([
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

    const ownedIds = new Set<string>();
    const chunks: SparkLeaf[][] = [];
    for (let i = 0; i < reported.length; i += SIGNER_BATCH) {
      chunks.push(reported.slice(i, i + SIGNER_BATCH));
    }
    const chunkKeys = await Promise.all(
      chunks.map(async (chunk) =>
        signer.publicKeys(chunk.map((leaf) => ({ type: "leaf", leafId: leaf.id }))),
      ),
    );
    for (const [i, chunk] of chunks.entries()) {
      const keys = chunkKeys[i];
      for (const [j, leaf] of chunk.entries()) {
        const leafPublicKey = keys?.[j];
        if (leafPublicKey === undefined) {
          throw new SparkError("leaves: signer returned fewer public keys than requested");
        }
        if (ownsLeaf(leaf, leafPublicKey)) {
          ownedIds.add(leaf.id);
        }
      }
    }

    // Paging over a set an operator is concurrently mutating can return the same leaf on more
    // than one page; like Breez, keep the first occurrence.
    const operatorMaps = operatorLeafLists.map((operatorLeaves) => {
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

    await storeChainsFor(spendable);
    const chains = await store.exitChains();
    const stale = chains.map((chain) => chain.leafId).filter((leafId) => !ownedIds.has(leafId));
    if (stale.length > 0) {
      await store.deleteExitChains(stale);
    }
    return spendable;
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
    storeChainsFor,
    leaves,
    receiverIdentityKey,
    tokenIdentifierForNetwork,
  };
}
