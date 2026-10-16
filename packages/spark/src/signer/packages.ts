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
      const split = backendCall(() =>
        crypto.splitSecretWithProofs(
          tweak,
          request.threshold,
          request.operators.length,
          randomBytes(random, 32),
        ),
      );
      secrets.push(split);
      const { proofs, shares } = parseSplit(split, request.threshold, request.operators.length);
      const pubkeySharesTweak: Record<string, Uint8Array> = {};
      for (const operator of request.operators) {
        pubkeySharesTweak[operator.identifier] = secp256k1.getPublicKey(
          operatorShare(shares, operator, "prepareTransfer"),
          true,
        );
      }
      for (const operator of request.operators) {
        perOperator.get(operator.identifier)?.push(
          create(SendLeafKeyTweakSchema, {
            leafId: leaf.leafId,
            secretShareTweak: {
              secretShare: operatorShare(shares, operator, "prepareTransfer"),
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
    const operatorPackages: Record<string, Uint8Array> = {};
    for (const operator of request.operators) {
      const tweaks = perOperator.get(operator.identifier);
      if (tweaks === undefined) {
        throw new SparkError("prepareTransfer: internal operator grouping failure");
      }
      const plaintext = toBinary(
        SendLeafKeyTweaksSchema,
        create(SendLeafKeyTweaksSchema, { leavesToSend: tweaks }),
      );
      plaintexts.push(plaintext);
      operatorPackages[operator.identifier] = backendCall(() =>
        crypto.eciesEncrypt(operator.identityPublicKey, plaintext, randomBytes(random, 32)),
      );
    }
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
  const { crypto, keys, random } = context;
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
      const split = backendCall(() =>
        crypto.splitSecretWithProofs(
          tweak,
          request.threshold,
          request.operators.length,
          randomBytes(random, 32),
        ),
      );
      secrets.push(split);
      const { proofs, shares } = parseSplit(split, request.threshold, request.operators.length);
      const pubkeySharesTweak: Record<string, Uint8Array> = {};
      for (const operator of request.operators) {
        pubkeySharesTweak[operator.identifier] = secp256k1.getPublicKey(
          operatorShare(shares, operator, "prepareClaim"),
          true,
        );
      }
      for (const operator of request.operators) {
        perOperator.get(operator.identifier)?.push(
          create(ClaimLeafKeyTweakSchema, {
            leafId: leaf.leafId,
            secretShareTweak: {
              secretShare: operatorShare(shares, operator, "prepareClaim"),
              proofs,
            },
            pubkeySharesTweak,
          }),
        );
      }
    }
    const operatorPackages: Record<string, Uint8Array> = {};
    for (const operator of request.operators) {
      const tweaks = perOperator.get(operator.identifier);
      if (tweaks === undefined) {
        throw new SparkError("prepareClaim: internal operator grouping failure");
      }
      const plaintext = toBinary(
        ClaimLeafKeyTweaksSchema,
        create(ClaimLeafKeyTweaksSchema, { leavesToReceive: tweaks }),
      );
      plaintexts.push(plaintext);
      operatorPackages[operator.identifier] = backendCall(() =>
        crypto.eciesEncrypt(operator.identityPublicKey, plaintext, randomBytes(random, 32)),
      );
    }
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
    const operatorPackages: Record<string, Uint8Array> = {};
    for (const operator of request.operators) {
      const plaintext = toBinary(
        SecretShareSchema,
        create(SecretShareSchema, {
          secretShare: operatorShare(shares, operator, "prepareLightningReceive"),
          proofs,
        }),
      );
      plaintexts.push(plaintext);
      operatorPackages[operator.identifier] = backendCall(() =>
        crypto.eciesEncrypt(operator.identityPublicKey, plaintext, randomBytes(random, 32)),
      );
    }
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
 * The only method returning private key material: the static-deposit child secret key plus the
 * identity-key DER signature over the claim statement.
 */
export function claimStaticDepositPackage(
  request: StaticDepositClaimRequest,
  context: PackageContext,
): { secretKey: Uint8Array; signature: Uint8Array } {
  const { keys, network } = context;
  const { digest } = statementDigest(request.statement, {
    identityPoint: keys.identityPoint,
    identityPublicKey: keys.identityPublicKey,
    network,
  });
  return {
    secretKey: keys.staticDepositPrivateKey(request.index),
    signature: ecdsaSign(digest, keys.identityPrivateKey, "der"),
  };
}
