import { fromBinary } from "@bufbuild/protobuf";
import { secp256k1 } from "@noble/curves/secp256k1.js";

import { authnChallengeDigest, sspChallengeDigest } from "../../src/core/hashing/index.ts";
import { ChallengeSchema } from "../../src/proto/gen/spark_authn_pb.ts";
import type { IdentityStatement, SparkSigner } from "../../src/signer/types.ts";

const NOT_IMPLEMENTED = "test signer: not implemented";

/**
 * Test-only SparkSigner built on noble. Mirrors the upstream signer contract: the challenge bytes
 * are hashed inside the signer (`authnChallengeDigest` / `sspChallengeDigest`) and signed with
 * DER-encoded ECDSA over the identity key. Only `identityPublicKey` and the challenge statements
 * are implemented — connection tests never exercise the rest of the surface.
 */
export function createTestSigner(secretKey: Uint8Array): SparkSigner & {
  readonly secretKey: Uint8Array;
} {
  if (secretKey.length !== 32) {
    throw new Error("test signer secret key must be 32 bytes");
  }
  const publicKey = secp256k1.getPublicKey(secretKey, true);
  const ready = Promise.resolve();
  return {
    secretKey,
    identityPublicKey: async () => {
      await ready;
      return publicKey;
    },
    publicKeys: async () => {
      await ready;
      throw new Error(NOT_IMPLEMENTED);
    },
    receivedPublicKeys: async () => {
      await ready;
      throw new Error(NOT_IMPLEMENTED);
    },
    newCommitments: async () => {
      await ready;
      throw new Error(NOT_IMPLEMENTED);
    },
    signFrost: async () => {
      await ready;
      throw new Error(NOT_IMPLEMENTED);
    },
    aggregateFrost: async () => {
      await ready;
      throw new Error(NOT_IMPLEMENTED);
    },
    signIdentity: async (statement: IdentityStatement) => {
      await ready;
      switch (statement.kind) {
        case "so-challenge":
          return secp256k1.sign(
            authnChallengeDigest(fromBinary(ChallengeSchema, statement.challenge)),
            secretKey,
            { format: "der", prehash: false },
          );
        case "ssp-challenge":
          return secp256k1.sign(sspChallengeDigest(statement.protectedChallenge), secretKey, {
            format: "der",
            prehash: false,
          });
        default:
          throw new Error(NOT_IMPLEMENTED);
      }
    },
    signKeySpend: async () => {
      await ready;
      throw new Error(NOT_IMPLEMENTED);
    },
    prepareTransfer: async () => {
      await ready;
      throw new Error(NOT_IMPLEMENTED);
    },
    prepareClaim: async () => {
      await ready;
      throw new Error(NOT_IMPLEMENTED);
    },
    prepareLightningReceive: async () => {
      await ready;
      throw new Error(NOT_IMPLEMENTED);
    },
    claimStaticDeposit: async () => {
      await ready;
      throw new Error(NOT_IMPLEMENTED);
    },
    dispose: () => undefined,
  };
}
