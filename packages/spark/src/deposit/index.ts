import type { CallOptions, Client } from "@connectrpc/connect";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { equalBytes } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { Address as BitcoinAddress, OutScript } from "@scure/btc-signer";

import { requireLength, u64ToSats } from "../core/assert.ts";
import {
  btcNetwork,
  computeTaprootKeyNoScript,
  createInitialTimelockRefundTxs,
  createRootNodeTx,
  p2trScriptFromPublicKey,
  parseTransaction,
  taprootKeySpendSighash,
  txId,
  verifyFinalizedTaprootSignature,
  xOnlyPublicKey,
} from "../core/bitcoin/index.ts";
import { proofOfPossessionDigest } from "../core/hashing/statements.ts";
import { sparkNetworkProto } from "../core/network.ts";
import type { SparkNetwork, SparkOperatorConfig } from "../core/network.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import { HashVariant } from "../proto/gen/spark_pb.ts";
import type { Address, SparkService } from "../proto/gen/spark_pb.ts";
import type { SigningTarget, SparkKey, SparkSigner } from "../signer/types.ts";
import { mapTreeNode } from "../tree/index.ts";
import type { SparkLeaf } from "../tree/index.ts";
import { signUserJobs } from "../tree/signing.ts";
import type { UserSigningSpec } from "../tree/signing.ts";

export type DepositCoordinator = {
  /** Connect client for the coordinator operator. */
  readonly spark: Client<typeof SparkService>;
  readonly signer: SparkSigner;
  readonly network: SparkNetwork;
  /** Every signing operator, coordinator included. */
  readonly operators: ReadonlyArray<SparkOperatorConfig>;
  /** Identifier of the coordinator (`options.spark`); its address signature is not checked. */
  readonly coordinatorIdentifier: string;
};

export type UnusedDepositAddress = {
  readonly address: string;
  readonly leafId: string;
  readonly verifyingPublicKey: Uint8Array;
};

const PUBLIC_KEY_LENGTH = 33;
const UNUSED_PAGE_SIZE = 100;

/**
 * The BIP-341 key-path P2TR script over a coordinator-supplied verifying key — the only output
 * script funds at a deposit address may pay to (breez-spark-sdk
 * `validate_address_pays_to_verifying_key`, services/deposit.rs @956ff90).
 */
function depositScript(verifyingKey: Uint8Array, network: SparkNetwork): Uint8Array {
  try {
    return p2trScriptFromPublicKey(verifyingKey, network);
  } catch (error) {
    throw new SparkError("deposit: verifyingPublicKey is not a valid public key", {
      cause: error,
    });
  }
}

/** Output script of a coordinator-supplied address, decoded under our network only. */
function depositAddressScript(address: string, network: SparkNetwork): Uint8Array {
  try {
    return OutScript.encode(BitcoinAddress(btcNetwork(network)).decode(address));
  } catch (error) {
    throw new SparkError("deposit: address does not decode under our network", { cause: error });
  }
}

/**
 * Validates a deposit address exactly like the upstream SDK: the coordinator's proof-of-possession
 * is a BIP-340 signature over `sha256("proof_of_possession" ‖ identity ‖ operatorShare ‖ address)`
 * made by the key-path-tweaked operator share (`verifyingKey − signingPublicKey`), and each
 * non-coordinator operator attaches a DER ECDSA signature over `sha256(address)`.
 */
function validateDepositAddress(
  result: Address,
  signingPublicKey: Uint8Array,
  identityPublicKey: Uint8Array,
  options: DepositCoordinator,
): void {
  if (result.address.length === 0) {
    throw new SparkInputError("deposit address is empty");
  }
  requireLength(result.verifyingKey, PUBLIC_KEY_LENGTH, "verifyingKey");
  const verifyingPoint = secp256k1.Point.fromBytes(result.verifyingKey);
  const signingPoint = secp256k1.Point.fromBytes(signingPublicKey);
  const operatorShare = verifyingPoint.subtract(signingPoint).toBytes(true);
  const digest = proofOfPossessionDigest(identityPublicKey, operatorShare, result.address);
  const taprootKey = computeTaprootKeyNoScript(xOnlyPublicKey(operatorShare)).subarray(1);
  const proof = result.depositAddressProof;
  if (
    proof === undefined ||
    !schnorr.verify(proof.proofOfPossessionSignature, digest, taprootKey)
  ) {
    throw new SparkInputError("deposit address proof of possession is invalid");
  }
  const addressHash = sha256(utf8ToBytes(result.address));
  for (const operator of options.operators) {
    if (operator.identifier === options.coordinatorIdentifier) {
      continue;
    }
    const signature = proof.addressSignatures[operator.identifier];
    if (signature === undefined) {
      throw new SparkInputError(
        `deposit address: missing signature from operator ${operator.identifier}`,
      );
    }
    const parsed = secp256k1.Signature.fromBytes(signature, "der");
    if (
      !secp256k1.verify(parsed.toBytes(), addressHash, operator.identityPublicKey, {
        prehash: false,
      })
    ) {
      throw new SparkInputError(
        `deposit address: bad signature from operator ${operator.identifier}`,
      );
    }
  }
}

/**
 * Requests a single-use deposit address from the coordinator (`signingPublicKey` bound to `leafId`)
 * and validates its proof-of-possession plus every non-coordinator operator's address signature
 * before returning it.
 */
export async function generateDepositAddress(
  options: DepositCoordinator & { readonly leafId: string },
): Promise<string> {
  const [signingPublicKey] = await options.signer.publicKeys([
    { type: "leaf", leafId: options.leafId },
  ]);
  if (signingPublicKey === undefined) {
    throw new SparkError("deposit address: signer returned no leaf public key");
  }
  const identityPublicKey = await options.signer.identityPublicKey();
  const response = await options.spark.generate_deposit_address({
    signingPublicKey,
    identityPublicKey,
    network: sparkNetworkProto(options.network),
    leafId: options.leafId,
    hashVariant: HashVariant.V2,
  });
  if (response.depositAddress === undefined) {
    throw new SparkError("generateDepositAddress: coordinator returned no address");
  }
  validateDepositAddress(response.depositAddress, signingPublicKey, identityPublicKey, options);
  const deposit = response.depositAddress;
  const expectedScript = depositScript(deposit.verifyingKey, options.network);
  if (!equalBytes(depositAddressScript(deposit.address, options.network), expectedScript)) {
    throw new SparkError("deposit address does not pay to its verifying key");
  }
  return deposit.address;
}

/**
 * Pages `query_unused_deposit_addresses` (batches of 100 until a short page) and returns every
 * address the SO still considers unused.
 */
export async function queryUnusedDepositAddresses(
  options: DepositCoordinator & { readonly call?: CallOptions },
): Promise<UnusedDepositAddress[]> {
  const identityPublicKey = await options.signer.identityPublicKey();
  const fetchPage = async (offset: number): Promise<UnusedDepositAddress[]> => {
    const response = await options.spark.query_unused_deposit_addresses(
      {
        identityPublicKey,
        network: sparkNetworkProto(options.network),
        limit: BigInt(UNUSED_PAGE_SIZE),
        offset: BigInt(offset),
      },
      options.call,
    );
    const page = response.depositAddresses.map((entry) => {
      const expectedScript = depositScript(entry.verifyingPublicKey, options.network);
      const actualScript = depositAddressScript(entry.depositAddress, options.network);
      if (!equalBytes(actualScript, expectedScript)) {
        throw new SparkError(
          `deposit: unused address ${entry.depositAddress} does not pay to its verifying key`,
        );
      }
      return {
        address: entry.depositAddress,
        leafId: entry.leafId ?? "",
        verifyingPublicKey: entry.verifyingPublicKey,
      };
    });
    if (response.depositAddresses.length < UNUSED_PAGE_SIZE) {
      return page;
    }
    const rest = await fetchPage(Number(response.offset));
    return [...page, ...rest];
  };
  return fetchPage(0);
}

/**
 * Finds the output of `transaction` paying to one of the caller's unused deposit addresses, builds
 * the CPFP root node tx plus the CPFP and direct-from-CPFP refund txs, requests three signing
 * commitments, produces the three user signature shares in one `signFrost` batch and finalizes tree
 * creation with the coordinator.
 */
export async function claimDeposit(
  options: DepositCoordinator & {
    readonly transaction: Uint8Array;
    readonly vout?: number;
  },
): Promise<SparkLeaf> {
  const { spark, signer, network } = options;
  const transaction = parseTransaction(options.transaction);

  const unused = await queryUnusedDepositAddresses(options);
  const byAddress = new Map(unused.map((entry) => [entry.address, entry]));
  const bitcoin = btcNetwork(network);
  const matches: Array<{ vout: number; result: UnusedDepositAddress }> = [];
  for (let i = 0; i < transaction.outputsLength; i++) {
    const output = transaction.getOutput(i);
    if (output.script === undefined) {
      continue;
    }
    const address = BitcoinAddress(bitcoin).encode(OutScript.decode(output.script));
    const found = byAddress.get(address);
    if (found !== undefined) {
      matches.push({ vout: i, result: found });
    }
  }
  let match: { vout: number; result: UnusedDepositAddress } | undefined;
  if (options.vout === undefined) {
    if (matches.length === 0) {
      throw new SparkInputError("claimDeposit: transaction pays to none of the unused addresses");
    }
    if (matches.length > 1) {
      throw new SparkInputError(
        "claimDeposit: transaction pays to more than one unused address; pass vout",
      );
    }
    [match] = matches;
  } else {
    match = matches.find((entry) => entry.vout === options.vout);
  }
  if (match === undefined) {
    throw new SparkInputError(
      `claimDeposit: output ${options.vout ?? ""} does not pay to an unused address`,
    );
  }
  const { vout } = match;
  const { verifyingPublicKey } = match.result;
  const depositOutput = transaction.getOutput(vout);
  if (depositOutput.script === undefined || depositOutput.amount === undefined) {
    throw new SparkInputError("claimDeposit: deposit output is missing script or amount");
  }
  if (!equalBytes(depositOutput.script, depositScript(verifyingPublicKey, network))) {
    throw new SparkError("claimDeposit: deposit output does not pay to the verifying key");
  }

  if (match.result.leafId === "") {
    throw new SparkInputError("claimDeposit: the address is not a single-use leaf deposit address");
  }
  const key: SparkKey = { type: "leaf", leafId: match.result.leafId };
  const [signingPublicKey] = await signer.publicKeys([key]);
  if (signingPublicKey === undefined) {
    throw new SparkError("claimDeposit: signer returned no signing public key");
  }

  const root = createRootNodeTx(options.transaction, vout, network);
  const refunds = createInitialTimelockRefundTxs({
    nodeTx: root.cpfp.txBytes,
    receivingPublicKey: signingPublicKey,
    network,
  });
  const rootOutput = parseTransaction(root.cpfp.txBytes).getOutput(0);
  if (rootOutput.script === undefined || rootOutput.amount === undefined) {
    throw new SparkError("claimDeposit: built root node tx has no output 0");
  }
  const rootPrevout = {
    script: depositOutput.script,
    amount: u64ToSats(depositOutput.amount, "deposit output"),
  };
  const refundPrevout = {
    script: rootOutput.script,
    amount: u64ToSats(rootOutput.amount, "root node output"),
  };
  const targets: SigningTarget[] = [
    { transaction: root.cpfp.txBytes, inputIndex: 0, prevouts: [rootPrevout] },
    {
      transaction: refunds.cpfpRefund.txBytes,
      inputIndex: 0,
      prevouts: [refundPrevout],
    },
    {
      transaction: refunds.directFromCpfpRefund.txBytes,
      inputIndex: 0,
      prevouts: [refundPrevout],
    },
  ];

  const signingCommitments = await spark.get_signing_commitments({
    count: 3,
    nodeIdCount: 1,
  });
  const specs: UserSigningSpec[] = targets.map((target, index) => {
    const commitments = signingCommitments.signingCommitments[index];
    if (commitments === undefined) {
      throw new SparkError("claimDeposit: coordinator returned fewer than three commitments");
    }
    return {
      key,
      signingPublicKey,
      verifyingKey: verifyingPublicKey,
      target,
      commitments,
    };
  });
  const signingJobs = await signUserJobs(signer, specs);

  const response = await spark.finalize_deposit_tree_creation({
    identityPublicKey: await signer.identityPublicKey(),
    onChainUtxo: {
      vout,
      rawTx: options.transaction,
      network: sparkNetworkProto(network),
    },
    rootTxSigningJob: signingJobs[0],
    refundTxSigningJob: signingJobs[1],
    directFromCpfpRefundTxSigningJob: signingJobs[2],
  });
  const { rootNode } = response;
  if (rootNode === undefined) {
    throw new SparkError("claimDeposit: coordinator returned no root node");
  }
  // The coordinator aggregates server-side, so the returned transactions must be the ones we
  // signed for and carry valid key-path signatures under the tweaked verifying key —
  // breez-spark-sdk services/deposit.rs @956ff90. direct_from_cpfp carries no signature.
  if (!equalBytes(rootNode.verifyingPublicKey, verifyingPublicKey)) {
    throw new SparkError("claimDeposit: root node carries an unexpected verifying key");
  }
  const [rootTarget, refundTarget] = targets;
  if (rootTarget === undefined || refundTarget === undefined) {
    throw new SparkError("claimDeposit: missing signing targets");
  }
  const finalized: ReadonlyArray<{
    name: string;
    returned: Uint8Array;
    built: Uint8Array;
    target: SigningTarget;
  }> = [
    { name: "nodeTx", returned: rootNode.nodeTx, built: root.cpfp.txBytes, target: rootTarget },
    {
      name: "refundTx",
      returned: rootNode.refundTx,
      built: refunds.cpfpRefund.txBytes,
      target: refundTarget,
    },
  ];
  for (const entry of finalized) {
    if (txId(entry.returned) !== txId(entry.built)) {
      throw new SparkError(`claimDeposit: root node ${entry.name} is not the transaction we built`);
    }
    if (
      !verifyFinalizedTaprootSignature(
        entry.returned,
        taprootKeySpendSighash(entry.target),
        verifyingPublicKey,
      )
    ) {
      throw new SparkError(
        `claimDeposit: root node ${entry.name} has an invalid taproot signature`,
      );
    }
  }
  return mapTreeNode(rootNode);
}
