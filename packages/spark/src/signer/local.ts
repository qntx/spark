import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { taprootTweakPrivKey } from "@scure/btc-signer/utils.js";

import { requireLength } from "../core/assert.ts";
import {
  createSequenceLockScript,
  LIGHTNING_HTLC_SEQUENCE,
  lightningHtlcOutputScript,
} from "../core/bitcoin/htlc.ts";
import { checkIfValidSequence, getTimelockFromSequence } from "../core/bitcoin/sequence.ts";
import {
  parseTransaction,
  taprootKeySpendSighash,
  taprootScriptSpendSighash,
} from "../core/bitcoin/sighash.ts";
import type { SigningTarget } from "../core/bitcoin/sighash.ts";
import { sparkNetworkConfig } from "../core/network.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SPARK_ABI_VERSION } from "../crypto/index.ts";
import type { SparkCrypto } from "../crypto/index.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import {
  checkBatch,
  checkOperators,
  checkThreshold,
  PUBLIC_KEY_LENGTH,
  randomBytes,
  ready,
} from "./backend.ts";
import { frostAggregateJobs, frostSignJobs } from "./frost.ts";
import { openKeys } from "./keys.ts";
import type { SignerKeys } from "./keys.ts";
import { createNonceStore } from "./nonces.ts";
import type { NonceStore } from "./nonces.ts";
import { createOutflowTracker, onchainOutflow, tokenOutflow } from "./outflow.ts";
import type { AuthorizeOutflow } from "./outflow.ts";
import {
  claimStaticDepositPackage,
  prepareClaimPackage,
  prepareLightningReceivePackage,
  prepareTransferPackage,
} from "./packages.ts";
import type { PackageContext } from "./packages.ts";
import { signDigest, statementDigest } from "./statements.ts";
import type { StatementContext } from "./statements.ts";
import type {
  FrostAggregateJob,
  FrostSignJob,
  HtlcTimeoutSignRequest,
  IdentityStatement,
  PrepareClaimRequest,
  PreparedClaim,
  PreparedLightningReceive,
  PreparedTransfer,
  PrepareTransferRequest,
  SigningCommitment,
  SparkKey,
  SparkLeafKey,
  SparkOperator,
  SparkSigner,
  StaticDepositClaimRequest,
} from "./types.ts";

// Upstream reference: sdks/js/packages/spark-sdk/src/signer/signer.ts
// (DefaultSparkSigner), services/transfer.ts (key-tweak packages),
// services/lightning.ts (preimage shares) — buildonspark/spark@0b3a32a.

export { sparkAccountKey } from "./keys.ts";

/**
 * Creates the local Spark signer: the implementation of {@link SparkSigner} that holds the account
 * extended private key and delegates curve-heavy FROST/ECIES/VSS work to a `SparkCrypto` backend.
 * Throws `SparkInputError` on an ABI version mismatch or a malformed `accountKey`.
 *
 * The operator set, VSS threshold and SSP identity are bound here and default to the network's
 * `sparkNetworkConfig`; every key-tweak share and the static-deposit secret is sealed to these keys
 * and no request can retarget them. Pass explicit values only to point the signer at a different
 * deployment (the local stack's operators/SSP), exactly like the client's `operators` and `ssp`
 * options.
 */
export function createSparkSigner(options: {
  readonly crypto: SparkCrypto;
  readonly accountKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly random: (length: number) => Uint8Array;
  /**
   * Signing-operator set the key-tweak and preimage shares are sealed to; defaults to the network's
   * operator set.
   */
  readonly operators?: ReadonlyArray<SparkOperator>;
  /** VSS threshold across `operators`; defaults to the network's threshold. */
  readonly threshold?: number;
  /** SSP identity the static-deposit secret is sealed to; defaults to the network's SSP key. */
  readonly sspIdentityPublicKey?: Uint8Array;
  /**
   * Optional gate invoked with the signer-derived {@link SparkOutflow} before every signature that
   * sends value out (transfer packages, onchain spends, token transactions). Throwing aborts the
   * signature; the records stay so a later authorize can be retried.
   */
  readonly authorize?: AuthorizeOutflow;
}): SparkSigner {
  const { crypto, network, random } = options;
  if (crypto.abiVersion !== SPARK_ABI_VERSION) {
    throw new SparkInputError(
      `crypto.abiVersion: expected ${SPARK_ABI_VERSION}, got ${crypto.abiVersion}`,
    );
  }
  if (network !== "mainnet" && network !== "regtest") {
    throw new SparkInputError(`network: unsupported network ${String(network)}`);
  }

  const config = sparkNetworkConfig(network);
  const operators = options.operators ?? config.operators;
  const threshold = options.threshold ?? config.threshold;
  const sspIdentityPublicKey = options.sspIdentityPublicKey ?? config.ssp.identityPublicKey;
  checkOperators(operators);
  checkThreshold(threshold, operators);
  requireLength(sspIdentityPublicKey, PUBLIC_KEY_LENGTH, "sspIdentityPublicKey");
  try {
    secp256k1.Point.fromBytes(sspIdentityPublicKey);
  } catch (error) {
    throw new SparkInputError("sspIdentityPublicKey is not a valid point", { cause: error });
  }

  const keys: SignerKeys = openKeys(options.accountKey, crypto);
  const nonces: NonceStore = createNonceStore(crypto, keys.accountPrivate, random);
  const outflow = createOutflowTracker(sspIdentityPublicKey, network, keys.identityPublicKey);
  const { authorize } = options;

  /** The signing public key for any key descriptor — resolved here, private copy wiped. */
  const publicKeyOf = (key: SparkKey): Uint8Array => {
    const secretKey = keys.resolve(key);
    try {
      return secp256k1.getPublicKey(secretKey, true);
    } finally {
      secretKey.fill(0);
    }
  };
  const statements: StatementContext = {
    identityPoint: keys.identityPoint,
    identityPublicKey: keys.identityPublicKey,
    network,
  };
  const packages: PackageContext = {
    crypto,
    keys,
    network,
    random,
    operators,
    threshold,
    sspIdentityPublicKey,
  };

  let disposed = false;

  function ensureAlive(): void {
    if (disposed) {
      throw new SparkError("signer: disposed");
    }
  }

  const identityPublicKey = async (): Promise<Uint8Array> => {
    ensureAlive();
    await ready;
    ensureAlive();
    return new Uint8Array(keys.identityPublicKey);
  };

  const publicKeys = async (
    descriptors: ReadonlyArray<SparkLeafKey>,
  ): Promise<ReadonlyArray<Uint8Array>> => {
    ensureAlive();
    await ready;
    ensureAlive();
    checkBatch(descriptors.length, "publicKeys");
    return keys.publicKeys(descriptors);
  };

  const receivedPublicKeys = async (
    ciphertexts: ReadonlyArray<Uint8Array>,
  ): Promise<ReadonlyArray<Uint8Array>> => {
    ensureAlive();
    await ready;
    ensureAlive();
    checkBatch(ciphertexts.length, "receivedPublicKeys");
    return keys.receivedPublicKeys(ciphertexts);
  };

  const newCommitments = async (count: number): Promise<ReadonlyArray<SigningCommitment>> => {
    ensureAlive();
    await ready;
    ensureAlive();
    return nonces.commit(count);
  };

  const signFrost = async (
    jobs: ReadonlyArray<FrostSignJob>,
  ): Promise<ReadonlyArray<Uint8Array>> => {
    ensureAlive();
    await ready;
    ensureAlive();
    const publicKeys = jobs.map((job) => publicKeyOf(job.key));
    // Whitelist before any share: a signed package can be paired with any shares the signer
    // ever issued, so HTLC/connector-shaped targets must be authorized before signing (G-SV).
    // Authorizing before frostSignJobs leaves commitments unconsumed on rejection — a retry
    // with an approving authorize works; signing failures keep consuming them.
    const batchOutflow = outflow.evaluateJobs(
      jobs.map((job, i) => {
        const publicKey = publicKeys[i];
        if (publicKey === undefined) {
          throw new SparkError("signFrost: public key resolution out of range");
        }
        return {
          key: job.key,
          publicKey,
          target: job.target,
          ...(job.exit === undefined ? {} : { exit: job.exit }),
        };
      }),
    );
    if (batchOutflow !== undefined) {
      await authorize?.(batchOutflow);
    }
    const shares = frostSignJobs(crypto, jobs, keys, nonces);
    for (const [i, job] of jobs.entries()) {
      const publicKey = publicKeys[i];
      if (publicKey === undefined) {
        throw new SparkError("signFrost: public key resolution out of range");
      }
      outflow.recordSign(publicKey, job.target);
    }
    if (batchOutflow !== undefined) {
      outflow.markServiceAuthorized(batchOutflow.leaves.map((leaf) => leaf.publicKey));
    }
    return shares;
  };

  const aggregateFrost = async (
    jobs: ReadonlyArray<FrostAggregateJob>,
  ): Promise<ReadonlyArray<Uint8Array>> => {
    ensureAlive();
    await ready;
    ensureAlive();
    return frostAggregateJobs(crypto, jobs, keys);
  };

  const signIdentity = async (statement: IdentityStatement): Promise<Uint8Array> => {
    ensureAlive();
    await ready;
    ensureAlive();
    if (statement.kind === "transfer-package") {
      // Fail closed: the package must be byte-equal to this signer's recorded preparation and
      // every leaf needs a recorded refund signature; authorize gates the signature itself.
      // A service (lightning/exit) authorization at signFrost already covered this transfer —
      // packageOutflow returns undefined then and no second authorize call is made.
      const transferOutflow = outflow.packageOutflow(statement.transferId, statement.package);
      if (transferOutflow !== undefined) {
        await authorize?.(transferOutflow);
      }
      const { digest, format } = statementDigest(statement, statements);
      const signature = signDigest(digest, format, keys.identityPrivateKey, random);
      outflow.drop(statement.transferId);
      return signature;
    }
    const { digest, format } = statementDigest(statement, statements);
    if (statement.kind === "static-deposit-refund" || statement.kind === "watchtower-recovery") {
      await authorize?.(onchainOutflow(statement.kind, statement.target));
    } else if (statement.kind === "token-transaction") {
      await authorize?.(tokenOutflow(statement.partialTransaction));
    }
    return signDigest(digest, format, keys.identityPrivateKey, random);
  };

  const signKeySpend = async (key: SparkKey, target: SigningTarget): Promise<Uint8Array> => {
    ensureAlive();
    await ready;
    ensureAlive();
    await authorize?.(onchainOutflow("key-spend", target));
    const secretKey = keys.resolve(key);
    let tweaked: Uint8Array | undefined;
    try {
      tweaked = taprootTweakPrivKey(secretKey);
      return schnorr.sign(taprootKeySpendSighash(target), tweaked, randomBytes(random, 32));
    } finally {
      secretKey.fill(0);
      tweaked?.fill(0);
    }
  };

  const signHtlcTimeout = async (request: HtlcTimeoutSignRequest): Promise<Uint8Array> => {
    ensureAlive();
    await ready;
    ensureAlive();
    await authorize?.(
      onchainOutflow("htlc-timeout", {
        transaction: request.transaction,
        inputIndex: request.inputIndex,
        prevouts: [
          {
            script: lightningHtlcOutputScript(
              request.paymentHash,
              request.hashLockPublicKey,
              keys.identityPublicKey,
            ),
            amount: request.prevoutAmountSats,
          },
        ],
      }),
    );
    const tx = parseTransaction(request.transaction);
    if (tx.inputsLength !== 1 || request.inputIndex !== 0) {
      throw new SparkInputError("htlc timeout: only the single-input sender sweep is supported");
    }
    const { sequence } = tx.getInput(0);
    if (sequence === undefined) {
      throw new SparkInputError("htlc timeout: input has no sequence");
    }
    checkIfValidSequence(sequence);
    if (getTimelockFromSequence(sequence) < LIGHTNING_HTLC_SEQUENCE) {
      throw new SparkInputError(
        `htlc timeout: input sequence ${String(sequence)} does not satisfy the ` +
          `${LIGHTNING_HTLC_SEQUENCE}-block HTLC CSV`,
      );
    }
    const sequenceLockScript = createSequenceLockScript(
      LIGHTNING_HTLC_SEQUENCE,
      keys.identityPublicKey,
    );
    const sighash = taprootScriptSpendSighash(
      {
        transaction: request.transaction,
        inputIndex: request.inputIndex,
        prevouts: [
          {
            script: lightningHtlcOutputScript(
              request.paymentHash,
              request.hashLockPublicKey,
              keys.identityPublicKey,
            ),
            amount: request.prevoutAmountSats,
          },
        ],
      },
      sequenceLockScript,
    );
    return signDigest(sighash, "schnorr", keys.identityPrivateKey, random);
  };

  const prepareTransfer = async (request: PrepareTransferRequest): Promise<PreparedTransfer> => {
    ensureAlive();
    await ready;
    ensureAlive();
    const prepared = prepareTransferPackage(request, packages);
    const leafPublicKeys = keys.publicKeys(request.leaves.map((leaf) => leaf.key));
    outflow.recordPrepare(
      request.transferId,
      request.leaves.map((leaf, i) => {
        const publicKey = leafPublicKeys[i];
        if (publicKey === undefined) {
          throw new SparkError("prepareTransfer: public key resolution out of range");
        }
        return { ...leaf, publicKey };
      }),
      prepared.operatorPackages,
    );
    return prepared;
  };

  const prepareClaim = async (request: PrepareClaimRequest): Promise<PreparedClaim> => {
    ensureAlive();
    await ready;
    ensureAlive();
    return prepareClaimPackage(request, packages);
  };

  const prepareLightningReceive = async (): Promise<PreparedLightningReceive> => {
    ensureAlive();
    await ready;
    ensureAlive();
    return prepareLightningReceivePackage(packages);
  };

  const claimStaticDeposit = async (
    request: StaticDepositClaimRequest,
  ): Promise<{ encryptedSecretKey: Uint8Array; signature: Uint8Array }> => {
    ensureAlive();
    await ready;
    ensureAlive();
    return claimStaticDepositPackage(request, packages);
  };

  const dispose = (): void => {
    if (disposed) {
      return;
    }
    disposed = true;
    nonces.wipe();
    keys.wipe();
    outflow.wipe();
  };

  return {
    identityPublicKey,
    publicKeys,
    receivedPublicKeys,
    newCommitments,
    signFrost,
    aggregateFrost,
    signIdentity,
    signKeySpend,
    signHtlcTimeout,
    prepareTransfer,
    prepareClaim,
    prepareLightningReceive,
    claimStaticDeposit,
    dispose,
  };
}
