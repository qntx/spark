import { fromBinary } from "@bufbuild/protobuf";
import { secp256k1 } from "@noble/curves/secp256k1.js";

import { authnChallengeDigest, sspChallengeDigest } from "../../src/core/hashing/index.ts";
import { ChallengeSchema } from "../../src/proto/gen/spark_authn_pb.ts";
import type { IdentityStatement, SparkSigner } from "../../src/signer/types.ts";

/**
 * Test-only SparkSigner built on noble. Mirrors the upstream signer contract: the challenge bytes
 * are hashed inside the signer (`authnChallengeDigest` / `sspChallengeDigest`) and signed with
 * DER-encoded ECDSA over the identity key.
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
    signIdentity: async (statement: IdentityStatement) => {
      await ready;
      const digest =
        statement.kind === "so-challenge"
          ? authnChallengeDigest(fromBinary(ChallengeSchema, statement.challenge))
          : sspChallengeDigest(statement.protectedChallenge);
      return secp256k1.sign(digest, secretKey, { format: "der", prehash: false });
    },
  };
}
