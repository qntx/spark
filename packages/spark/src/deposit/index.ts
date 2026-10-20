import { create } from "@bufbuild/protobuf";
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
  createMultiInputRootTx,
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
import {
  HashVariant,
  InputSigningDataSchema,
  UserSignedTxSigningJobSchema,
} from "../proto/gen/spark_pb.ts";
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
export function depositScript(verifyingKey: Uint8Array, network: SparkNetwork): Uint8Array {
  try {
    return p2trScriptFromPublicKey(verifyingKey, network);
  } catch (error) {
    throw new SparkError("deposit: verifyingPublicKey is not a valid public key", {
      cause: error,
    });
  }
}

/** Output script of a coordinator-supplied address, decoded under our network only. */
export function depositAddressScript(address: string, network: SparkNetwork): Uint8Array {
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
 * `verifyCoordinatorProof` also checks the coordinator's signature — upstream enables it for static
 * deposit addresses only.
 */
export function validateDepositAddress(
  result: Address,
  signingPublicKey: Uint8Array,
  identityPublicKey: Uint8Array,
  options: DepositCoordinator & { readonly verifyCoordinatorProof?: boolean },
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
    // Single-use addresses skip the coordinator (its PoP is self-issued); static
    // addresses verify it too (upstream validateDepositAddress verifyCoordinatorProof).
    if (
      operator.identifier === options.coordinatorIdentifier &&
      options.verifyCoordinatorProof !== true
    ) {
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

export type DepositOutput = {
  readonly transaction: Uint8Array;
  /** Output index paying the deposit address; resolved by unique match when omitted. */
  readonly vout?: number;
};

/** `finalize_deposit_tree_creation` takes one `on_chain_utxo` plus at most 10 additional. */
const MAX_CLAIM_OUTPUTS = 11;

/**
 * Resolves the output of `transaction` paying to one of the caller's unused deposit addresses: an
 * explicit `vout` must pay an unused address, otherwise exactly one output may.
 */
function resolveDepositOutput(
  transaction: Uint8Array,
  vout: number | undefined,
  byAddress: ReadonlyMap<string, UnusedDepositAddress>,
  network: SparkNetwork,
): { vout: number; result: UnusedDepositAddress } {
  const tx = parseTransaction(transaction);
  const bitcoin = btcNetwork(network);
  const matches: Array<{ vout: number; result: UnusedDepositAddress }> = [];
  for (let i = 0; i < tx.outputsLength; i++) {
    const output = tx.getOutput(i);
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
  if (vout === undefined) {
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
    match = matches.find((entry) => entry.vout === vout);
  }
  if (match === undefined) {
    throw new SparkInputError(
      `claimDeposit: output ${vout ?? ""} does not pay to an unused address`,
    );
  }
  return match;
}

/**
 * Claims one or more confirmed UTXOs paying the SAME single-use deposit address into one leaf:
 * every output resolves to an unused address, the multi-input root tx consolidates them in caller
 * order, each root input is signed over ALL deposit prevouts, and the cpfp/direct-from-cpfp refund
 * txs spend root output 0 — N+2 signature shares in one `signFrost` batch, matching upstream
 * `createTreeRootMultiUtxo`. A single-use address is consumed by a claim, so sibling UTXOs can only
 * ever be claimed together.
 */
export async function claimDeposit(
  options: DepositCoordinator & {
    readonly outputs: ReadonlyArray<DepositOutput>;
  },
): Promise<SparkLeaf> {
  const { spark, signer, network } = options;
  if (options.outputs.length === 0) {
    throw new SparkInputError("claimDeposit: outputs must not be empty");
  }
  if (options.outputs.length > MAX_CLAIM_OUTPUTS) {
    throw new SparkInputError(`claimDeposit: at most ${MAX_CLAIM_OUTPUTS} outputs per claim`);
  }

  const unused = await queryUnusedDepositAddresses(options);
  const byAddress = new Map(unused.map((entry) => [entry.address, entry]));
  const resolved = options.outputs.map((output) => ({
    transaction: output.transaction,
    ...resolveDepositOutput(output.transaction, output.vout, byAddress, network),
  }));

  const [first] = resolved;
  if (first === undefined) {
    throw new SparkError("claimDeposit: resolved no outputs");
  }
  for (const entry of resolved) {
    if (entry.result.address !== first.result.address) {
      throw new SparkInputError("claimDeposit: outputs pay different deposit addresses");
    }
  }
  const outpoints = new Set<string>();
  for (const entry of resolved) {
    const outpoint = `${txId(entry.transaction)}:${entry.vout}`;
    if (outpoints.has(outpoint)) {
      throw new SparkInputError("claimDeposit: duplicate deposit outpoint");
    }
    outpoints.add(outpoint);
  }
  if (first.result.leafId === "") {
    throw new SparkInputError("claimDeposit: the address is not a single-use leaf deposit address");
  }
  const { verifyingPublicKey } = first.result;
  const prevouts = resolved.map((entry) => {
    const output = parseTransaction(entry.transaction).getOutput(entry.vout);
    if (output.script === undefined || output.amount === undefined) {
      throw new SparkInputError("claimDeposit: deposit output is missing script or amount");
    }
    if (!equalBytes(output.script, depositScript(verifyingPublicKey, network))) {
      throw new SparkError("claimDeposit: deposit output does not pay to the verifying key");
    }
    return { script: output.script, amount: u64ToSats(output.amount, "deposit output") };
  });

  const key: SparkKey = { type: "leaf", leafId: first.result.leafId };
  const [signingPublicKey] = await signer.publicKeys([key]);
  if (signingPublicKey === undefined) {
    throw new SparkError("claimDeposit: signer returned no signing public key");
  }

  const rootTxBytes = createMultiInputRootTx(
    resolved.map(({ transaction, vout }) => ({ tx: transaction, vout })),
  );
  const refunds = createInitialTimelockRefundTxs({
    nodeTx: rootTxBytes,
    receivingPublicKey: signingPublicKey,
    network,
  });
  const rootOutput = parseTransaction(rootTxBytes).getOutput(0);
  if (rootOutput.script === undefined || rootOutput.amount === undefined) {
    throw new SparkError("claimDeposit: built root node tx has no output 0");
  }
  const refundPrevout = {
    script: rootOutput.script,
    amount: u64ToSats(rootOutput.amount, "root node output"),
  };
  // Commitments 0..N-1 sign the root inputs (each over all N prevouts), N the cpfp refund and
  // N+1 the direct-from-cpfp refund — the SO's order, same as upstream.
  const targets: SigningTarget[] = [
    ...resolved.map((_, inputIndex) => ({
      transaction: rootTxBytes,
      inputIndex,
      prevouts,
    })),
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
    count: targets.length,
    nodeIdCount: 1,
  });
  const specs: UserSigningSpec[] = targets.map((target, index) => {
    const commitments = signingCommitments.signingCommitments[index];
    if (commitments === undefined) {
      throw new SparkError(
        `claimDeposit: coordinator returned fewer than ${targets.length} commitments`,
      );
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
  const [rootJob] = signingJobs;
  const refundJob = signingJobs[resolved.length];
  const directRefundJob = signingJobs[resolved.length + 1];
  if (rootJob === undefined || refundJob === undefined || directRefundJob === undefined) {
    throw new SparkError("claimDeposit: missing signing jobs");
  }

  const response = await spark.finalize_deposit_tree_creation({
    identityPublicKey: await signer.identityPublicKey(),
    onChainUtxo: {
      vout: first.vout,
      rawTx: first.transaction,
      network: sparkNetworkProto(network),
    },
    rootTxSigningJob: create(UserSignedTxSigningJobSchema, {
      signingPublicKey: rootJob.signingPublicKey,
      rawTx: rootJob.rawTx,
      signingNonceCommitment: rootJob.signingNonceCommitment,
      userSignature: rootJob.userSignature,
      signingCommitments: rootJob.signingCommitments,
      additionalInputs: signingJobs.slice(1, resolved.length).map((job) =>
        create(InputSigningDataSchema, {
          signingNonceCommitment: job.signingNonceCommitment,
          userSignature: job.userSignature,
          signingCommitments: job.signingCommitments,
        }),
      ),
    }),
    refundTxSigningJob: refundJob,
    directFromCpfpRefundTxSigningJob: directRefundJob,
    additionalOnChainUtxos: resolved.slice(1).map((entry) => ({
      vout: entry.vout,
      rawTx: entry.transaction,
      network: sparkNetworkProto(network),
    })),
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
  if (txId(rootNode.nodeTx) !== txId(rootTxBytes)) {
    throw new SparkError("claimDeposit: root node nodeTx is not the transaction we built");
  }
  // Every root input gets its own aggregated signature over its own all-prevouts sighash.
  for (const [inputIndex, target] of targets.slice(0, resolved.length).entries()) {
    if (
      !verifyFinalizedTaprootSignature(
        rootNode.nodeTx,
        taprootKeySpendSighash(target),
        verifyingPublicKey,
        inputIndex,
      )
    ) {
      throw new SparkError(
        `claimDeposit: root node nodeTx input ${inputIndex} has an invalid taproot signature`,
      );
    }
  }
  const refundTarget = targets[resolved.length];
  if (refundTarget === undefined) {
    throw new SparkError("claimDeposit: missing refund signing target");
  }
  if (txId(rootNode.refundTx) !== txId(refunds.cpfpRefund.txBytes)) {
    throw new SparkError("claimDeposit: root node refundTx is not the transaction we built");
  }
  if (
    !verifyFinalizedTaprootSignature(
      rootNode.refundTx,
      taprootKeySpendSighash(refundTarget),
      verifyingPublicKey,
      0,
    )
  ) {
    throw new SparkError("claimDeposit: root node refundTx has an invalid taproot signature");
  }
  return mapTreeNode(rootNode);
}
