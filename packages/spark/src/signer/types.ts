import type { SigningTarget } from "../core/bitcoin/sighash.ts";
import type { SparkNetwork } from "../core/network.ts";

/**
 * A private key the local signer can resolve, addressed by how upstream derives it. The key
 * material never leaves the signer; callers pass only these descriptors.
 *
 * - `leaf`: `LEAF{leafId}` path — hardened child `u32be(sha256(utf8(leafId))[0..4]) mod 2^31` of the
 *   signing root (`m/8797555'/a'/1'`).
 * - `deposit`: the deposit key (`m/8797555'/a'/2'`).
 * - `static-deposit`: hardened child `index` of the static-deposit root (`m/8797555'/a'/3'`).
 */
export type SparkLeafKey =
  | { readonly type: "leaf"; readonly leafId: string }
  | { readonly type: "deposit" }
  | { readonly type: "static-deposit"; readonly index: number };

/**
 * Any private key a FROST or key-spend job can use. `received` decrypts `ciphertext` with the
 * identity key (ECIES) to recover the 32-byte key the sender sealed for this identity.
 */
export type SparkKey =
  | { readonly type: "identity" }
  | SparkLeafKey
  | { readonly type: "received"; readonly ciphertext: Uint8Array };

/** The user's FROST signing commitment pair: 33-byte compressed `hiding` and `binding` points. */
export type SigningCommitment = {
  readonly hiding: Uint8Array;
  readonly binding: Uint8Array;
};

/** An operator's FROST identifier and its commitment for one signing session. */
export type OperatorCommitment = {
  /** 64 lowercase hex characters; the operator's FROST identifier scalar. */
  readonly identifier: string;
  readonly commitment: SigningCommitment;
};

/** Re-exported so sign callers do not need the bitcoin internals module. */
export type { SigningTarget } from "../core/bitcoin/sighash.ts";

/**
 * A user-side FROST signing job. `commitment` must come from {@link SparkSigner.newCommitments}; it
 * is consumed by the call — signing once removes it, so a second job carrying the same commitment
 * fails even if the first signing attempt itself failed.
 */
export type FrostSignJob = {
  readonly key: SparkKey;
  readonly target: SigningTarget;
  /** 33-byte compressed combined (aggregate) verifying key for this session. */
  readonly verifyingKey: Uint8Array;
  readonly commitment: SigningCommitment;
  readonly operatorCommitments: ReadonlyArray<OperatorCommitment>;
  /** Optional 33-byte adaptor point; omit or leave empty for plain signatures. */
  readonly adaptorPublicKey?: Uint8Array;
};

/** Aggregation of the user's share (obtained from {@link SparkSigner.signFrost}) with the SOs'. */
export type FrostAggregateJob = {
  readonly key: SparkKey;
  readonly target: SigningTarget;
  readonly verifyingKey: Uint8Array;
  readonly commitment: SigningCommitment;
  /** The user's 32-byte signature share produced by `signFrost` for this session. */
  readonly signatureShare: Uint8Array;
  readonly operators: ReadonlyArray<{
    /** 64 lowercase hex characters. */
    readonly identifier: string;
    readonly commitment: SigningCommitment;
    /** The operator's 32-byte signature share. */
    readonly signatureShare: Uint8Array;
    /** The operator's 33-byte verifying share. */
    readonly publicKey: Uint8Array;
  }>;
  readonly adaptorPublicKey?: Uint8Array;
};

/**
 * A statement the signer signs with the identity key. The signer computes every digest itself from
 * the full statement content — there is no sign-arbitrary-hash method.
 *
 * - `so-challenge`: `challenge` is a serialized `spark_authn.Challenge`; decoded strictly (no unknown
 *   fields), its `publicKey` must equal the identity public key as a curve point.
 * - `ssp-challenge`: `protectedChallenge` is the base64 SSP session challenge.
 * - `transfer-package` / `claim-package`: `package` is the serialized `spark.TransferPackage` /
 *   `spark.ClaimPackage`; the digest is computed from the decoded message fields.
 * - `static-deposit-claim`: the fixed-quote claim statement (`txid` in display byte order,
 *   `sspSignature` is the SSP quote signature string).
 * - `static-deposit-refund`: the refund statement; `txid`/`vout`/`amount` describe the deposit output
 *   and `target` is the refund transaction whose sighash becomes the payload.
 * - `instant-static-deposit`: the 0-confirmation tagged-hash statement.
 * - `watchtower-recovery`: `target` is the recovery transaction; its sighash enters the digest.
 * - `receive-quote`: `manifest` is a serialized `spark.TransferManifest`; `network` must match the
 *   manifest's own network field.
 * - `spark-invoice`: `invoice` is a serialized `spark.SparkInvoiceFields`; signed with BIP-340.
 * - `token-transaction`: `partialTransaction` is a serialized `spark_token.PartialTokenTransaction`;
 *   the digest is its V3 protoreflecthash, signed with BIP-340 (upstream tokenSignatures:
 *   SCHNORR).
 */
export type IdentityStatement =
  | { readonly kind: "so-challenge"; readonly challenge: Uint8Array }
  | { readonly kind: "ssp-challenge"; readonly protectedChallenge: string }
  | { readonly kind: "transfer-package"; readonly transferId: string; readonly package: Uint8Array }
  | { readonly kind: "claim-package"; readonly transferId: string; readonly package: Uint8Array }
  | {
      readonly kind: "static-deposit-claim";
      readonly network: SparkNetwork;
      /** The deposit transaction id in display (big-endian) byte order. */
      readonly txid: Uint8Array;
      readonly vout: number;
      readonly creditAmountSats: number;
      /** The SSP quote signature string (ASCII hex). */
      readonly sspSignature: string;
    }
  | {
      readonly kind: "static-deposit-refund";
      readonly network: SparkNetwork;
      /** The deposit transaction id in display (big-endian) byte order. */
      readonly txid: Uint8Array;
      readonly vout: number;
      readonly amount: number;
      readonly target: SigningTarget;
    }
  | {
      readonly kind: "instant-static-deposit";
      readonly network: SparkNetwork;
      readonly creditAmountSats: number;
      readonly secondaryCreditAmountSats: number;
      readonly destinationAddress: string;
      readonly satsValue: number;
      readonly sspSignature: Uint8Array;
    }
  | {
      readonly kind: "watchtower-recovery";
      readonly network: SparkNetwork;
      readonly leafId: string;
      readonly target: SigningTarget;
    }
  | {
      readonly kind: "receive-quote";
      readonly network: SparkNetwork;
      /** Serialized `spark.TransferManifest`. */
      readonly manifest: Uint8Array;
      readonly paymentHash: Uint8Array;
    }
  | { readonly kind: "spark-invoice"; readonly invoice: Uint8Array }
  | {
      readonly kind: "token-transaction";
      /** Serialized `spark_token.PartialTokenTransaction`. */
      readonly partialTransaction: Uint8Array;
    };

/** A signing operator the signer builds per-operator packages for. */
export type SparkOperator = {
  readonly id: number;
  /** 64 lowercase hex characters; the FROST identifier scalar. */
  readonly identifier: string;
  /** 33-byte compressed secp256k1 public key the packages are ECIES-encrypted to. */
  readonly identityPublicKey: Uint8Array;
};

/**
 * PrepareTransfer input: every leaf gets a fresh random recipient key; the operator-visible tweak
 * is `old − new` (mod n) split by VSS and encrypted per operator.
 */
export type PrepareTransferRequest = {
  readonly transferId: string;
  /** 33-byte compressed identity public key the per-leaf `secret_cipher` is encrypted to. */
  readonly receiverIdentityPublicKey: Uint8Array;
  readonly leaves: ReadonlyArray<{ readonly leafId: string; readonly key: SparkLeafKey }>;
  readonly operators: ReadonlyArray<SparkOperator>;
  readonly threshold: number;
};

/** One leaf's transfer output, mirroring the per-leaf fields of `spark.SendLeafKeyTweak`. */
export type PreparedTransferLeaf = {
  readonly leafId: string;
  /** The fresh 33-byte leaf key the receiver will claim with. */
  readonly newPublicKey: Uint8Array;
  /** ECIES(receiverIdentityPublicKey) ciphertext sealing the new 32-byte leaf key. */
  readonly secretCipher: Uint8Array;
  /** 64-byte compact ECDSA signature over `sha256(leafId ‖ transferId ‖ secretCipher)`. */
  readonly signature: Uint8Array;
};

/**
 * Sender transfer preparation. `operatorPackages` maps each operator's 64-hex identifier to the
 * ECIES-encrypted `spark.SendLeafKeyTweaks` it can open.
 */
export type PreparedTransfer = {
  /** SO identifier → ECIES(identityPublicKey) of the serialized `spark.SendLeafKeyTweaks`. */
  readonly operatorPackages: Record<string, Uint8Array>;
  readonly leaves: ReadonlyArray<PreparedTransferLeaf>;
};

/** PrepareClaim input: each leaf's `secretCipher` is the sender's ECIES-encrypted leaf key. */
export type PrepareClaimRequest = {
  readonly transferId: string;
  readonly leaves: ReadonlyArray<{ readonly leafId: string; readonly secretCipher: Uint8Array }>;
  readonly operators: ReadonlyArray<SparkOperator>;
  readonly threshold: number;
};

/**
 * Receiver claim preparation. `operatorPackages` maps each operator's identifier to the
 * ECIES-encrypted `spark.ClaimLeafKeyTweaks` it can open.
 */
export type PreparedClaim = {
  /** SO identifier → ECIES(identityPublicKey) of the serialized `spark.ClaimLeafKeyTweaks`. */
  readonly operatorPackages: Record<string, Uint8Array>;
};

/**
 * Lightning receive preparation. The preimage is generated inside the signer and never leaves;
 * `paymentHash` is `sha256(preimage)` and `operatorPackages` maps each operator's identifier to the
 * ECIES-encrypted `spark.SecretShare` it can open (the V2 store-preimage-share payload).
 */
export type PreparedLightningReceive = {
  readonly paymentHash: Uint8Array;
  /** SO identifier → ECIES(identityPublicKey) of the serialized `spark.SecretShare`. */
  readonly operatorPackages: Record<string, Uint8Array>;
};

/** The static-deposit claim request: which key index and the statement the SSP expects signed. */
export type StaticDepositClaimRequest = {
  /** Static-deposit child index (upstream uses 0 for the current deposit address). */
  readonly index: number;
  readonly statement: Extract<IdentityStatement, { readonly kind: "static-deposit-claim" }>;
};

/**
 * The signer's identity surface. Private keys never leave the signer; every method returns protocol
 * values only (Uint8Array, strings, safe integers, plain objects) so an implementation may live
 * behind a binding boundary.
 */
export type SparkSigner = {
  /** The 33-byte compressed secp256k1 identity public key. */
  readonly identityPublicKey: () => Promise<Uint8Array>;
  /** Compressed public keys for the given private-key descriptors, in order. */
  readonly publicKeys: (keys: ReadonlyArray<SparkLeafKey>) => Promise<ReadonlyArray<Uint8Array>>;
  /**
   * Public keys of ECIES-sealed ("received") keys: each ciphertext is decrypted with the identity
   * key (must yield 32 bytes) and its compressed public key returned.
   */
  readonly receivedPublicKeys: (
    ciphertexts: ReadonlyArray<Uint8Array>,
  ) => Promise<ReadonlyArray<Uint8Array>>;
  /**
   * Generates `count` FROST commitment pairs (at most 256). The secret nonces are stored inside the
   * signer keyed by the commitment pair and consumed by {@link signFrost}.
   */
  readonly newCommitments: (count: number) => Promise<ReadonlyArray<SigningCommitment>>;
  /**
   * User-side FROST signature shares, one 32-byte share per job in order (at most 256 jobs). Each
   * job's commitment is consumed — removed before signing, so reuse fails even after an error.
   */
  readonly signFrost: (jobs: ReadonlyArray<FrostSignJob>) => Promise<ReadonlyArray<Uint8Array>>;
  /**
   * Aggregated 64-byte FROST (Schnorr) signatures, one per job in order. The user verifying share
   * is derived from the resolved private key inside the signer.
   */
  readonly aggregateFrost: (
    jobs: ReadonlyArray<FrostAggregateJob>,
  ) => Promise<ReadonlyArray<Uint8Array>>;
  /**
   * Signs a protocol statement with the identity key. DER ECDSA for protocol statements, BIP-340
   * for `spark-invoice`.
   */
  readonly signIdentity: (statement: IdentityStatement) => Promise<Uint8Array>;
  /**
   * BIP-341 key-path signature over the target's sighash: the resolved key is tweaked with
   * `TapTweak` (empty merkle root) and BIP-340-signed with fresh aux randomness. Returns 64 bytes.
   */
  readonly signKeySpend: (key: SparkKey, target: SigningTarget) => Promise<Uint8Array>;
  /** Builds the sender transfer package: per-leaf fresh keys, VSS tweaks, per-SO ECIES packages. */
  readonly prepareTransfer: (request: PrepareTransferRequest) => Promise<PreparedTransfer>;
  /** Builds the receiver claim package: VSS `received − LEAF{leafId}` tweaks, per-SO ECIES packages. */
  readonly prepareClaim: (request: PrepareClaimRequest) => Promise<PreparedClaim>;
  /** Generates a preimage, splits it by VSS and encrypts one `SecretShare` per operator. */
  readonly prepareLightningReceive: (request: {
    readonly operators: ReadonlyArray<SparkOperator>;
    readonly threshold: number;
  }) => Promise<PreparedLightningReceive>;
  /**
   * The only method returning private key material (the SSP claim protocol requires it): the
   * static-deposit child secret key plus the identity-key DER signature over the claim statement.
   */
  readonly claimStaticDeposit: (
    request: StaticDepositClaimRequest,
  ) => Promise<{ readonly secretKey: Uint8Array; readonly signature: Uint8Array }>;
  /** Wipes every private key, cached secret and unused nonce, then rejects all further calls. */
  readonly dispose: () => void;
};
