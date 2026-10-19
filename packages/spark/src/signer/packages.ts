import { create, toBinary } from "@bufbuild/protobuf";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { requireLength } from "../core/assert.ts";
import { sendLeafSigningDigest } from "../core/hashing/statements.ts";
import type { SparkNetwork } from "../core/network.ts";
import type { SparkCrypto } from "../crypto/index.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import {
  ClaimLeafKeyTweaksSchema,
  ClaimLeafKeyTweakSchema,
  SecretShareSchema,
  SendLeafKeyTweaksSchema,
  SendLeafKeyTweakSchema,
} from "../proto/gen/spark_pb.ts";
import type { ClaimLeafKeyTweak, SendLeafKeyTweak } from "../proto/gen/spark_pb.ts";
import {
  backendCall,
  checkOperators,
  operatorShare,
  parseSplit,
  PUBLIC_KEY_LENGTH,
  randomBytes,
  randomScalar,
} from "./backend.ts";
import type { SignerKeys } from "./keys.ts";
import { ecdsaSign, statementDigest } from "./statements.ts";
import type {
  PrepareClaimRequest,
  PreparedClaim,
  PreparedLightningReceive,
  PreparedTransfer,
  PreparedTransferLeaf,
  PrepareTransferRequest,
  SparkOperator,
  StaticDepositClaimRequest,
} from "./types.ts";

/** What the package-building methods need from the signer. */
export type PackageContext = {
  readonly crypto: SparkCrypto;
  readonly keys: SignerKeys;
  readonly network: SparkNetwork;
  readonly random: (length: number) => Uint8Array;
};

type TweakSplit = {
  readonly proofs: Uint8Array[];
  readonly shareFor: (operator: SparkOperator) => Uint8Array;
  readonly pubkeySharesTweak: Record<string, Uint8Array>;
};

/**
 * VSS-splits `tweak` across `operators` at `threshold`, returning the proofs, a per-operator share
 * accessor and each operator's share public key (`share·G`). The backend output is registered in
 * `secrets` so the caller's `finally` wipes it.
 */
function splitTweak(
  tweak: Uint8Array,
  operators: ReadonlyArray<SparkOperator>,
  threshold: number,
  context: PackageContext,
  secrets: Uint8Array[],
  label: string,
): TweakSplit {
  const { crypto, random } = context;
  const split = backendCall(() =>
    crypto.splitSecretWithProofs(tweak, threshold, operators.length, randomBytes(random, 32)),
  );
  secrets.push(split);
  const { proofs, shares } = parseSplit(split, threshold, operators.length);
  const shareFor = (operator: SparkOperator): Uint8Array => operatorShare(shares, operator, label);
  const pubkeySharesTweak: Record<string, Uint8Array> = {};
  for (const operator of operators) {
    pubkeySharesTweak[operator.identifier] = secp256k1.getPublicKey(shareFor(operator), true);
  }
  return { proofs, shareFor, pubkeySharesTweak };
}

/**
 * Builds one plaintext per operator and ECIES-seals it to that operator's identity key. Every
 * plaintext is registered in `plaintexts` so the caller's `finally` wipes it.
 */
function sealPerOperator(
  operators: ReadonlyArray<SparkOperator>,
  plaintextFor: (operator: SparkOperator) => Uint8Array,
  context: PackageContext,
  plaintexts: Uint8Array[],
): Record<string, Uint8Array> {
  const { crypto, random } = context;
  const operatorPackages: Record<string, Uint8Array> = {};
  for (const operator of operators) {
    const plaintext = plaintextFor(operator);
    plaintexts.push(plaintext);
    operatorPackages[operator.identifier] = backendCall(() =>
      crypto.eciesEncrypt(operator.identityPublicKey, plaintext, randomBytes(random, 32)),
    );
  }
  return operatorPackages;
}

/**
 * Builds the sender transfer package: every leaf gets a fresh random recipient key, the
 * operator-visible tweak is `old − new` (mod n) split by VSS, and each `SendLeafKeyTweaks`
 * plaintext is ECIES-sealed to the operator it belongs to.
 */
export function prepareTransferPackage(
  request: PrepareTransferRequest,
  context: PackageContext,
): PreparedTransfer {
  const { crypto, keys, random } = context;
  if (request.leaves.length === 0) {
    throw new SparkInputError("leaves: must not be empty");
  }
  checkOperators(request.operators);
  requireLength(request.receiverIdentityPublicKey, PUBLIC_KEY_LENGTH, "receiverIdentityPublicKey");
  const secrets: Uint8Array[] = [];
  const plaintexts: Uint8Array[] = [];
  try {
    // Per-operator tweak entries, grouped by operator identifier.
    const perOperator = new Map<string, SendLeafKeyTweak[]>();
    for (const operator of request.operators) {
      perOperator.set(operator.identifier, []);
    }
    const leaves: PreparedTransferLeaf[] = [];
    for (const leaf of request.leaves) {
      const oldPrivateKey = keys.resolve(leaf.key);
      const newPrivateKey = randomScalar(random);
      secrets.push(oldPrivateKey, newPrivateKey);
      const secretCipher = backendCall(() =>
        crypto.eciesEncrypt(
          request.receiverIdentityPublicKey,
          newPrivateKey,
          randomBytes(random, 32),
        ),
      );
      const signature = ecdsaSign(
        sendLeafSigningDigest(leaf.leafId, request.transferId, secretCipher),
        keys.identityPrivateKey,
        "compact",
      );
      const tweak = secp256k1.Point.Fn.toBytes(
        secp256k1.Point.Fn.sub(
          secp256k1.Point.Fn.fromBytes(oldPrivateKey),
          secp256k1.Point.Fn.fromBytes(newPrivateKey),
        ),
      );
      secrets.push(tweak);
      const { proofs, shareFor, pubkeySharesTweak } = splitTweak(
        tweak,
        request.operators,
        request.threshold,
        context,
        secrets,
        "prepareTransfer",
      );
      for (const operator of request.operators) {
        perOperator.get(operator.identifier)?.push(
          create(SendLeafKeyTweakSchema, {
            leafId: leaf.leafId,
            secretShareTweak: {
              secretShare: shareFor(operator),
              proofs,
            },
            pubkeySharesTweak,
            secretCipher,
            sig: { case: "signature", value: signature },
          }),
        );
      }
      leaves.push({
        leafId: leaf.leafId,
        newPublicKey: secp256k1.getPublicKey(newPrivateKey, true),
        secretCipher,
        signature,
      });
    }
    const operatorPackages = sealPerOperator(
      request.operators,
      (operator) => {
        const tweaks = perOperator.get(operator.identifier);
        if (tweaks === undefined) {
          throw new SparkError("prepareTransfer: internal operator grouping failure");
        }
        return toBinary(
          SendLeafKeyTweaksSchema,
          create(SendLeafKeyTweaksSchema, { leavesToSend: tweaks }),
        );
      },
      context,
      plaintexts,
    );
    return { operatorPackages, leaves };
  } finally {
    for (const secret of secrets) {
      secret.fill(0);
    }
    for (const plaintext of plaintexts) {
      plaintext.fill(0);
    }
  }
}

/**
 * Builds the receiver claim package: each leaf's tweak is `received − leaf` (the sealed key minus
 * the local `LEAF{leafId}` key), VSS-split and sealed per operator as `ClaimLeafKeyTweaks`.
 */
export function prepareClaimPackage(
  request: PrepareClaimRequest,
  context: PackageContext,
): PreparedClaim {
  const { keys } = context;
  if (request.leaves.length === 0) {
    throw new SparkInputError("leaves: must not be empty");
  }
  checkOperators(request.operators);
  const secrets: Uint8Array[] = [];
  const plaintexts: Uint8Array[] = [];
  try {
    const perOperator = new Map<string, ClaimLeafKeyTweak[]>();
    for (const operator of request.operators) {
      perOperator.set(operator.identifier, []);
    }
    for (const leaf of request.leaves) {
      const receivedPrivateKey = keys.resolve({
        type: "received",
        ciphertext: leaf.secretCipher,
      });
      const newPrivateKey = keys.resolve({ type: "leaf", leafId: leaf.leafId });
      secrets.push(receivedPrivateKey, newPrivateKey);
      const tweak = secp256k1.Point.Fn.toBytes(
        secp256k1.Point.Fn.sub(
          secp256k1.Point.Fn.fromBytes(receivedPrivateKey),
          secp256k1.Point.Fn.fromBytes(newPrivateKey),
        ),
      );
      secrets.push(tweak);
      const { proofs, shareFor, pubkeySharesTweak } = splitTweak(
        tweak,
        request.operators,
        request.threshold,
        context,
        secrets,
        "prepareClaim",
      );
      for (const operator of request.operators) {
        perOperator.get(operator.identifier)?.push(
          create(ClaimLeafKeyTweakSchema, {
            leafId: leaf.leafId,
            secretShareTweak: {
              secretShare: shareFor(operator),
              proofs,
            },
            pubkeySharesTweak,
          }),
        );
      }
    }
    const operatorPackages = sealPerOperator(
      request.operators,
      (operator) => {
        const tweaks = perOperator.get(operator.identifier);
        if (tweaks === undefined) {
          throw new SparkError("prepareClaim: internal operator grouping failure");
        }
        return toBinary(
          ClaimLeafKeyTweaksSchema,
          create(ClaimLeafKeyTweaksSchema, { leavesToReceive: tweaks }),
        );
      },
      context,
      plaintexts,
    );
    return { operatorPackages };
  } finally {
    for (const secret of secrets) {
      secret.fill(0);
    }
    for (const plaintext of plaintexts) {
      plaintext.fill(0);
    }
  }
}

/**
 * Generates a preimage, VSS-splits it across `operators` at `threshold`, and seals one
 * `SecretShare` plaintext per operator. Returns `sha256(preimage)` as the payment hash.
 */
export function prepareLightningReceivePackage(
  request: {
    readonly operators: ReadonlyArray<SparkOperator>;
    readonly threshold: number;
  },
  context: PackageContext,
): PreparedLightningReceive {
  const { crypto, random } = context;
  checkOperators(request.operators);
  const secrets: Uint8Array[] = [];
  const plaintexts: Uint8Array[] = [];
  try {
    const preimage = randomScalar(random);
    secrets.push(preimage);
    const split = backendCall(() =>
      crypto.splitSecretWithProofs(
        preimage,
        request.threshold,
        request.operators.length,
        randomBytes(random, 32),
      ),
    );
    secrets.push(split);
    const { proofs, shares } = parseSplit(split, request.threshold, request.operators.length);
    const operatorPackages = sealPerOperator(
      request.operators,
      (operator) =>
        toBinary(
          SecretShareSchema,
          create(SecretShareSchema, {
            secretShare: operatorShare(shares, operator, "prepareLightningReceive"),
            proofs,
          }),
        ),
      context,
      plaintexts,
    );
    return { paymentHash: sha256(preimage), operatorPackages };
  } finally {
    for (const secret of secrets) {
      secret.fill(0);
    }
    for (const plaintext of plaintexts) {
      plaintext.fill(0);
    }
  }
}

/**
 * The static-deposit claim: ECIES-seals the child secret key to the SSP identity (the same scheme
 * as transfer leaf secret ciphers) and signs the claim statement with the identity key. The
 * plaintext key is wiped before returning.
 */
export function claimStaticDepositPackage(
  request: StaticDepositClaimRequest,
  context: PackageContext,
): { encryptedSecretKey: Uint8Array; signature: Uint8Array } {
  const { crypto, keys, network, random } = context;
  const { digest } = statementDigest(request.statement, {
    identityPoint: keys.identityPoint,
    identityPublicKey: keys.identityPublicKey,
    network,
  });
  if (request.sspIdentityPublicKey.length !== PUBLIC_KEY_LENGTH) {
    throw new SparkInputError("claimStaticDeposit: sspIdentityPublicKey must be 33 bytes");
  }
  try {
    secp256k1.Point.fromBytes(request.sspIdentityPublicKey);
  } catch (error) {
    throw new SparkInputError("claimStaticDeposit: sspIdentityPublicKey is not a valid point", {
      cause: error,
    });
  }
  const secret = keys.staticDepositPrivateKey(request.index);
  try {
    return {
      encryptedSecretKey: backendCall(() =>
        crypto.eciesEncrypt(request.sspIdentityPublicKey, secret, randomBytes(random, 32)),
      ),
      signature: ecdsaSign(digest, keys.identityPrivateKey, "der"),
    };
  } finally {
    secret.fill(0);
  }
}
