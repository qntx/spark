import type { OperatorConnection } from "../connection/index.ts";
import { decodeSparkAddress, verifySparkAddressSignature } from "../core/address.ts";
import type { SparkNetwork, SparkNetworkConfig, SparkOperatorConfig } from "../core/network.ts";
import { decodeTokenIdentifier } from "../core/token-identifier.ts";
import type { DepositCoordinator } from "../deposit/index.ts";
import { SparkInputError } from "../errors/index.ts";
import type { SparkStore } from "../exit/store.ts";
import { queryExitChains } from "../exit/unilateral.ts";
import type { SparkSigner } from "../signer/types.ts";
import type { createSspClient } from "../ssp/index.ts";
import type { TransferCoordinator } from "../transfer/index.ts";
import { queryLeaves } from "../tree/index.ts";
import type { SparkLeaf } from "../tree/index.ts";

/** Everything the per-group factories share, built once per client. */
export type ClientContext = {
  readonly coordinatorConnection: OperatorConnection;
  readonly signer: SparkSigner;
  readonly network: SparkNetwork;
  readonly config: SparkNetworkConfig;
  readonly operators: ReadonlyArray<SparkOperatorConfig>;
  readonly store: SparkStore;
  readonly random: (length: number) => Uint8Array;
  readonly now?: () => number;
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
  const { coordinatorConnection, signer, network, store } = parts;

  const storeChainsFor = async (forLeaves: ReadonlyArray<SparkLeaf>): Promise<void> =>
    store.putExitChains(
      await queryExitChains({
        spark: coordinatorConnection.spark,
        network,
        leaves: forLeaves,
      }),
    );

  // Syncing leaves is the reconciliation point: refresh every leaf's exit chain and drop
  // chains for leaves the coordinator no longer reports as ours.
  const leaves = async (): Promise<ReadonlyArray<SparkLeaf>> => {
    const current = await queryLeaves({
      spark: coordinatorConnection.spark,
      ownerIdentityPublicKey: await signer.identityPublicKey(),
      network,
    });
    await storeChainsFor(current);
    const live = new Set(current.map((leaf) => leaf.id));
    const chains = await store.exitChains();
    const stale = chains.map((chain) => chain.leafId).filter((leafId) => !live.has(leafId));
    if (stale.length > 0) {
      await store.deleteExitChains(stale);
    }
    return current;
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
      throw new SparkInputError("send: invoice-carrying addresses are not supported yet");
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
