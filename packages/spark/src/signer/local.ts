import { schnorr } from "@noble/curves/secp256k1.js";
import { taprootTweakPrivKey } from "@scure/btc-signer/utils.js";

import { taprootKeySpendSighash } from "../core/bitcoin/sighash.ts";
import type { SigningTarget } from "../core/bitcoin/sighash.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SPARK_ABI_VERSION } from "../crypto/index.ts";
import type { SparkCrypto } from "../crypto/index.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import { checkBatch, randomBytes, ready } from "./backend.ts";
import { frostAggregateJobs, frostSignJobs } from "./frost.ts";
import { openKeys } from "./keys.ts";
import type { SignerKeys } from "./keys.ts";
import { createNonceStore } from "./nonces.ts";
import type { NonceStore } from "./nonces.ts";
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
 */
export function createSparkSigner(options: {
  readonly crypto: SparkCrypto;
  readonly accountKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly random: (length: number) => Uint8Array;
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

  const keys: SignerKeys = openKeys(options.accountKey, crypto);
  const nonces: NonceStore = createNonceStore(crypto, keys.accountPrivate, random);
  const statements: StatementContext = {
    identityPoint: keys.identityPoint,
    identityPublicKey: keys.identityPublicKey,
    network,
  };
  const packages: PackageContext = { crypto, keys, network, random };

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
    return frostSignJobs(crypto, jobs, keys, nonces);
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
    const { digest, format } = statementDigest(statement, statements);
    return signDigest(digest, format, keys.identityPrivateKey, random);
  };

  const signKeySpend = async (key: SparkKey, target: SigningTarget): Promise<Uint8Array> => {
    ensureAlive();
    await ready;
    ensureAlive();
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

  const prepareTransfer = async (request: PrepareTransferRequest): Promise<PreparedTransfer> => {
    ensureAlive();
    await ready;
    ensureAlive();
    return prepareTransferPackage(request, packages);
  };

  const prepareClaim = async (request: PrepareClaimRequest): Promise<PreparedClaim> => {
    ensureAlive();
    await ready;
    ensureAlive();
    return prepareClaimPackage(request, packages);
  };

  const prepareLightningReceive = async (request: {
    readonly operators: ReadonlyArray<SparkOperator>;
    readonly threshold: number;
  }): Promise<PreparedLightningReceive> => {
    ensureAlive();
    await ready;
    ensureAlive();
    return prepareLightningReceivePackage(request, packages);
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
    prepareTransfer,
    prepareClaim,
    prepareLightningReceive,
    claimStaticDeposit,
    dispose,
  };
}
