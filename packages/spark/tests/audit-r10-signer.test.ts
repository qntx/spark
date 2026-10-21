import { fromBinary } from "@bufbuild/protobuf";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { equalBytes } from "@noble/curves/utils.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { SparkCryptoError } from "../src/errors/index.ts";
import { ClaimLeafKeyTweaksSchema, SendLeafKeyTweaksSchema } from "../src/proto/gen/spark_pb.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import type { SparkOperator, SparkSigner } from "../src/signer/index.ts";
import { loadWasmBackend } from "./support/backend.ts";

// External-audit round 10, PoC N-03 (reversed): the signer used to seal each leaf's VSS tweak
// shares to caller-supplied operator identities and the static-deposit secret to a caller-supplied
// "SSP" key, so any caller recombined the threshold shares and recovered wallet keys. The operator
// set, threshold and SSP identity are now bound at construction and no request carries them:
// packages are provably sealed to the configured keys, and attacker secrets cannot open them.

const { Fn } = secp256k1.Point;

function hexId(id: number): string {
  return (id + 1).toString(16).padStart(64, "0");
}

/** Lagrange-interpolate the VSS secret at x=0 from (x = operator.id + 1, share) pairs, mod n. */
function reconstruct(pairs: ReadonlyArray<{ x: bigint; share: Uint8Array }>): Uint8Array {
  let acc = Fn.ZERO;
  for (const [i, a] of pairs.entries()) {
    let lambda = Fn.ONE;
    for (const [j, b] of pairs.entries()) {
      if (i === j) {
        continue;
      }
      lambda = Fn.mul(lambda, Fn.mul(b.x, Fn.inv(Fn.sub(b.x, a.x))));
    }
    acc = Fn.add(acc, Fn.mul(Fn.fromBytes(a.share), lambda));
  }
  return Fn.toBytes(acc);
}

type OperatorSecrets = SparkOperator & { readonly secret: Uint8Array };

function testOperators(): OperatorSecrets[] {
  return [0, 1, 2]
    .map((id) => ({ id, identifier: hexId(id), secret: randomBytes(32) }))
    .map((op) => ({ ...op, identityPublicKey: secp256k1.getPublicKey(op.secret, true) }));
}

async function boundSigner(operators: ReadonlyArray<SparkOperator>): Promise<SparkSigner> {
  return createSparkSigner({
    crypto: await loadWasmBackend(),
    accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
    network: "regtest",
    random: (length) => randomBytes(length),
    operators,
    threshold: 2,
  });
}

describe("N-03: package destinations are bound at signer construction", () => {
  test("A: prepareTransfer seals tweaks only to the construction-time operator set", async () => {
    const crypto = await loadWasmBackend();
    const operators = testOperators();
    const signer = await boundSigner(operators);
    const attackerReceiverSecret = randomBytes(32);
    const attackerReceiverPub = secp256k1.getPublicKey(attackerReceiverSecret, true);
    const attackerOperatorSecret = randomBytes(32);

    // The request can no longer carry operators/threshold — only the receiver identity stays
    // per-call, which is what a transfer to a receiver is.
    const prepared = await signer.prepareTransfer({
      transferId: "01989abc-def0-7000-8000-0000000000aa",
      leaves: [
        {
          leafId: "victim-leaf",
          key: { type: "leaf", leafId: "victim-leaf" },
          receiverIdentityPublicKey: attackerReceiverPub,
        },
      ],
    });

    // Every package is sealed to a construction-bound operator identifier — nothing else exists.
    expect(Object.keys(prepared.operatorPackages).toSorted()).toStrictEqual(
      operators.map((op) => op.identifier).toSorted(),
    );
    for (const cipher of Object.values(prepared.operatorPackages)) {
      expect(() => crypto.eciesDecrypt(attackerOperatorSecret, cipher)).toThrow(SparkCryptoError);
    }

    // The construction-bound operators still recombine the tweak and recover the leaf key — the
    // protocol works for the real operator set exactly as before.
    const shares = operators.map((operator, index) => {
      const plain = crypto.eciesDecrypt(
        operator.secret,
        prepared.operatorPackages[operator.identifier]!,
      );
      const tweaks = fromBinary(SendLeafKeyTweaksSchema, plain);
      const tweak = tweaks.leavesToSend.find((leaf) => leaf.leafId === "victim-leaf");
      expect(tweak?.secretShareTweak?.secretShare).toBeDefined();
      return { x: BigInt(index + 1), share: tweak!.secretShareTweak!.secretShare };
    });
    const tweak = reconstruct(shares.slice(0, 2));
    expect(reconstruct(shares.slice(1, 3))).toStrictEqual(tweak);

    const newKey = crypto.eciesDecrypt(attackerReceiverSecret, prepared.leaves[0]!.secretCipher);
    const leafPrivateKey = Fn.toBytes(Fn.add(Fn.fromBytes(tweak), Fn.fromBytes(newKey)));
    const [expectedPublic] = await signer.publicKeys([{ type: "leaf", leafId: "victim-leaf" }]);
    expect(secp256k1.getPublicKey(leafPrivateKey, true)).toStrictEqual(expectedPublic);
    signer.dispose();
  }, 60_000);

  test("B: prepareClaim seals tweaks only to the construction-time operator set", async () => {
    const crypto = await loadWasmBackend();
    const operators = testOperators();
    const signer = await boundSigner(operators);
    const attackerOperatorSecret = randomBytes(32);

    const receivedSecret = randomBytes(32);
    const secretCipher = crypto.eciesEncrypt(
      await signer.identityPublicKey(),
      receivedSecret,
      randomBytes(32),
    );
    const prepared = await signer.prepareClaim({
      transferId: "01989abc-def0-7000-8000-0000000000bb",
      leaves: [{ leafId: "victim-leaf-2", secretCipher }],
    });

    expect(Object.keys(prepared.operatorPackages).toSorted()).toStrictEqual(
      operators.map((op) => op.identifier).toSorted(),
    );
    for (const cipher of Object.values(prepared.operatorPackages)) {
      expect(() => crypto.eciesDecrypt(attackerOperatorSecret, cipher)).toThrow(SparkCryptoError);
    }

    const shares = operators.slice(0, 2).map((operator, index) => {
      const plain = crypto.eciesDecrypt(
        operator.secret,
        prepared.operatorPackages[operator.identifier]!,
      );
      const tweaks = fromBinary(ClaimLeafKeyTweaksSchema, plain);
      const tweak = tweaks.leavesToReceive.find((leaf) => leaf.leafId === "victim-leaf-2");
      expect(tweak?.secretShareTweak?.secretShare).toBeDefined();
      return { x: BigInt(index + 1), share: tweak!.secretShareTweak!.secretShare };
    });
    const tweak = reconstruct(shares);
    const leafPrivateKey = Fn.toBytes(Fn.sub(Fn.fromBytes(receivedSecret), Fn.fromBytes(tweak)));
    const [expectedPublic] = await signer.publicKeys([{ type: "leaf", leafId: "victim-leaf-2" }]);
    expect(secp256k1.getPublicKey(leafPrivateKey, true)).toStrictEqual(expectedPublic);
    signer.dispose();
  }, 60_000);

  test("C: claimStaticDeposit seals the deposit key only to the construction SSP identity", async () => {
    const crypto = await loadWasmBackend();
    const sspSecret = randomBytes(32);
    const sspIdentity = secp256k1.getPublicKey(sspSecret, true);
    const attackerSspSecret = randomBytes(32);
    const signer = createSparkSigner({
      crypto,
      accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
      network: "regtest",
      random: (length) => randomBytes(length),
      sspIdentityPublicKey: sspIdentity,
    });

    const { encryptedSecretKey } = await signer.claimStaticDeposit({
      index: 0,
      statement: {
        kind: "static-deposit-claim",
        network: "regtest",
        txid: randomBytes(32),
        vout: 0,
        creditAmountSats: 950,
        sspSignature: randomBytes(64),
      },
    });
    expect(() => crypto.eciesDecrypt(attackerSspSecret, encryptedSecretKey)).toThrow(
      SparkCryptoError,
    );

    const depositPrivateKey = crypto.eciesDecrypt(sspSecret, encryptedSecretKey);
    expect(depositPrivateKey).toHaveLength(32);
    const [expectedPublic] = await signer.publicKeys([{ type: "static-deposit", index: 0 }]);
    expect(equalBytes(secp256k1.getPublicKey(depositPrivateKey, true), expectedPublic!)).toBe(true);
    signer.dispose();
  }, 60_000);

  test("prepareLightningReceive seals preimage shares only to the bound operator set", async () => {
    const crypto = await loadWasmBackend();
    const operators = testOperators();
    const signer = await boundSigner(operators);
    const prepared = await signer.prepareLightningReceive();
    expect(Object.keys(prepared.operatorPackages).toSorted()).toStrictEqual(
      operators.map((op) => op.identifier).toSorted(),
    );
    for (const cipher of Object.values(prepared.operatorPackages)) {
      expect(() => crypto.eciesDecrypt(randomBytes(32), cipher)).toThrow(SparkCryptoError);
    }
    signer.dispose();
  }, 60_000);
});
