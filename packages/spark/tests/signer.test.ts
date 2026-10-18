import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { describe, expect, test } from "vite-plus/test";

import type { SigningTarget } from "../src/core/bitcoin/sighash.ts";
import { taprootKeySpendSighash } from "../src/core/bitcoin/sighash.ts";
import {
  QuoteReason,
  QuoteRole,
  authnChallengeDigest,
  claimPackageDigest,
  hashSparkInvoice,
  hashTransferManifest,
  instantStaticDepositStatementDigest,
  quoteEnvelopeDigest,
  receiveAttestorTarget,
  sendLeafSigningDigest,
  sspChallengeDigest,
  staticDepositStatementDigest,
  transferPackageDigest,
  watchtowerRecoveryStatementDigest,
} from "../src/core/hashing/index.ts";
import { hashPartialTokenTransaction } from "../src/core/hashing/token.ts";
import type { SparkInvoiceFields } from "../src/core/invoice.ts";
import type { SparkCrypto } from "../src/crypto/index.ts";
import { SparkCryptoError, SparkError, SparkInputError } from "../src/errors/index.ts";
import { ChallengeSchema } from "../src/proto/gen/spark_authn_pb.ts";
import type { SendLeafKeyTweak } from "../src/proto/gen/spark_pb.ts";
import {
  ClaimLeafKeyTweaksSchema,
  ClaimPackageSchema,
  HashVariant,
  Network,
  SecretShareSchema,
  SendLeafKeyTweaksSchema,
  SparkInvoiceFieldsSchema,
  TransferManifestSchema,
  TransferPackageSchema,
} from "../src/proto/gen/spark_pb.ts";
import { PartialTokenTransactionSchema } from "../src/proto/gen/spark_token_pb.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import type { SparkOperator, SparkSigner } from "../src/signer/index.ts";
import { loadWasmBackend } from "./support/backend.ts";
import {
  be32,
  frostGroup,
  lagrangeCoefficient,
  operatorSetup,
  operatorSignatureShares,
  taprootTweakedKey,
} from "./support/frost.ts";

type DerivationCase = {
  seed_hex: string;
  account: number;
  account_key: string;
  identity_public_key: string;
  deposit_public_key: string;
  static_deposit_public_keys: Array<{ index: number; public_key: string }>;
  leaf_public_keys: Array<{ leaf_id: string; public_key: string }>;
};

const derivation = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "../../../vectors/derivation.json"), "utf8"),
) as { cases: DerivationCase[] };

const transactions = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "../../../vectors/transactions.json"), "utf8"),
) as {
  multiInputSighash: Array<{
    inputIndex: number;
    prevOutScripts: string[];
    prevOutValues: number[];
    sighash: string;
    tx: string;
  }>;
};

const sighashVector = transactions.multiInputSighash[0]!;
const TARGET: SigningTarget = {
  transaction: hexToBytes(sighashVector.tx),
  inputIndex: sighashVector.inputIndex,
  prevouts: sighashVector.prevOutScripts.map((script, i) => ({
    script: hexToBytes(script),
    amount: sighashVector.prevOutValues[i]!,
  })),
};

const TRANSFER_ID = "550e8400-e29b-41d4-a716-446655440000";
const { Fn } = secp256k1.Point;
const { Point } = secp256k1;

let cryptoPromise: Promise<SparkCrypto> | undefined;
const backend = async (): Promise<SparkCrypto> => {
  cryptoPromise ??= loadWasmBackend();
  return cryptoPromise;
};

/** Deterministic non-repeating "randomness" — distinct sha256 blocks per call. */
function seededRandom(seed: Uint8Array): (length: number) => Uint8Array {
  let counter = 0;
  return (length) => {
    const out = new Uint8Array(length);
    for (let offset = 0; offset < length; offset += 32) {
      const block = sha256(concatBytes(seed, be32(BigInt(counter))));
      counter += 1;
      out.set(block.subarray(0, Math.min(32, length - offset)), offset);
    }
    return out;
  };
}

async function signerFor(seedHex: string, account = 0, randomSeed = 1): Promise<SparkSigner> {
  const accountKey = sparkAccountKey(hexToBytes(seedHex), "regtest", account);
  return createSparkSigner({
    crypto: await backend(),
    accountKey,
    network: "regtest",
    random: seededRandom(new Uint8Array(32).fill(randomSeed)),
  });
}

function expectDerSignature(
  signature: Uint8Array,
  digest: Uint8Array,
  publicKey: Uint8Array,
): void {
  expect(signature[0]).toBe(0x30);
  const decoded = secp256k1.Signature.fromBytes(signature, "der");
  expect(decoded.hasHighS()).toBe(false);
  expect(secp256k1.verify(decoded.toBytes(), digest, publicKey, { prehash: false })).toBe(true);
}

function testOperator(id: number, secret: bigint): SparkOperator {
  return {
    id,
    identifier: bytesToHex(be32(BigInt(id + 1))),
    identityPublicKey: Point.BASE.multiply(secret).toBytes(true),
  };
}

describe("sparkAccountKey + derivation vectors", () => {
  test.each(derivation.cases)("account $account key material matches upstream", (c) => {
    const accountKey = sparkAccountKey(hexToBytes(c.seed_hex), "regtest", c.account);
    expect(bytesToHex(accountKey)).toBe(c.account_key);
  });

  test("default accounts follow the SDK: mainnet 1, regtest 0", () => {
    const seed = hexToBytes(derivation.cases[0]!.seed_hex);
    expect(bytesToHex(sparkAccountKey(seed, "regtest"))).toBe(
      bytesToHex(sparkAccountKey(seed, "regtest", 0)),
    );
    expect(bytesToHex(sparkAccountKey(seed, "mainnet"))).toBe(
      bytesToHex(sparkAccountKey(seed, "mainnet", 1)),
    );
  });

  test.each(derivation.cases)(
    "identity/deposit/static/leaf public keys match upstream (case $account)",
    async (c) => {
      const signer = await signerFor(c.seed_hex, c.account);
      expect(bytesToHex(await signer.identityPublicKey())).toBe(c.identity_public_key);
      const keys = await signer.publicKeys([
        { type: "deposit" },
        ...c.static_deposit_public_keys.map(
          (k) => ({ type: "static-deposit", index: k.index }) as const,
        ),
        ...c.leaf_public_keys.map((k) => ({ type: "leaf", leafId: k.leaf_id }) as const),
      ]);
      expect(bytesToHex(keys[0]!)).toBe(c.deposit_public_key);
      for (const [i, k] of c.static_deposit_public_keys.entries()) {
        expect(bytesToHex(keys[i + 1]!)).toBe(k.public_key);
      }
      for (const [i, k] of c.leaf_public_keys.entries()) {
        expect(bytesToHex(keys[i + 1 + c.static_deposit_public_keys.length]!)).toBe(k.public_key);
      }
      signer.dispose();
    },
  );
});

describe("signIdentity", () => {
  test("so-challenge signs sha256(challenge) with DER, accepting 65- and 33-byte keys", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const identity = await signer.identityPublicKey();
    await Promise.all(
      [identity, Point.fromBytes(identity).toBytes(false)].map(async (encoded) => {
        const challenge = create(ChallengeSchema, {
          version: 1,
          timestamp: 1_700_000_000n,
          nonce: new Uint8Array(32).fill(7),
          publicKey: encoded,
        });
        const bytes = toBinary(ChallengeSchema, challenge);
        const signature = await signer.signIdentity({ kind: "so-challenge", challenge: bytes });
        expectDerSignature(signature, authnChallengeDigest(challenge), identity);
      }),
    );
    signer.dispose();
  });

  test("so-challenge rejects unknown fields and a foreign public key", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const identity = await signer.identityPublicKey();
    const challenge = create(ChallengeSchema, {
      version: 1,
      timestamp: 1_700_000_000n,
      nonce: new Uint8Array(32).fill(7),
      publicKey: identity,
    });
    const clean = toBinary(ChallengeSchema, challenge);
    // Field 99, varint value 1: tag = (99 << 3) | 0 = 792 -> 0x98 0x06, then 0x01.
    const withUnknown = concatBytes(clean, new Uint8Array([0x98, 0x06, 0x01]));
    await expect(
      signer.signIdentity({ kind: "so-challenge", challenge: withUnknown }),
    ).rejects.toThrow(SparkInputError);
    const foreign = create(ChallengeSchema, {
      version: 1,
      timestamp: 1_700_000_000n,
      nonce: new Uint8Array(32).fill(7),
      publicKey: Point.BASE.multiply(2n).toBytes(true),
    });
    await expect(
      signer.signIdentity({
        kind: "so-challenge",
        challenge: toBinary(ChallengeSchema, foreign),
      }),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  });

  test("ssp-challenge signs sha256(decoded challenge) with DER", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const identity = await signer.identityPublicKey();
    const protectedChallenge = base64.encode(new Uint8Array(40).fill(0xab));
    const signature = await signer.signIdentity({
      kind: "ssp-challenge",
      protectedChallenge,
    });
    expectDerSignature(signature, sspChallengeDigest(protectedChallenge), identity);
    signer.dispose();
  });

  test("transfer-package signs the V2 package digest; other variants rejected", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const identity = await signer.identityPublicKey();
    const pkg = create(TransferPackageSchema, {
      keyTweakPackage: { operator: new Uint8Array([1, 2, 3]) },
      hashVariant: HashVariant.V2,
    });
    const bytes = toBinary(TransferPackageSchema, pkg);
    const signature = await signer.signIdentity({
      kind: "transfer-package",
      transferId: TRANSFER_ID,
      package: bytes,
    });
    expectDerSignature(
      signature,
      transferPackageDigest(TRANSFER_ID, fromBinary(TransferPackageSchema, bytes)),
      identity,
    );
    const legacy = toBinary(
      TransferPackageSchema,
      create(TransferPackageSchema, { hashVariant: HashVariant.UNSPECIFIED }),
    );
    await expect(
      signer.signIdentity({ kind: "transfer-package", transferId: TRANSFER_ID, package: legacy }),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  });

  test("claim-package signs the claim digest", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const identity = await signer.identityPublicKey();
    const pkg = create(ClaimPackageSchema, {
      keyTweakPackage: { operator: new Uint8Array([4, 5]) },
    });
    const bytes = toBinary(ClaimPackageSchema, pkg);
    const signature = await signer.signIdentity({
      kind: "claim-package",
      transferId: TRANSFER_ID,
      package: bytes,
    });
    expectDerSignature(
      signature,
      claimPackageDigest(TRANSFER_ID, fromBinary(ClaimPackageSchema, bytes).keyTweakPackage),
      identity,
    );
    signer.dispose();
  });

  test("static-deposit-claim signs the fixed-quote statement", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const identity = await signer.identityPublicKey();
    const txid = new Uint8Array(32).fill(9);
    const signature = await signer.signIdentity({
      kind: "static-deposit-claim",
      network: "regtest",
      txid,
      vout: 2,
      creditAmountSats: 50_000,
      sspSignature: "aabbcc",
    });
    expectDerSignature(
      signature,
      staticDepositStatementDigest({
        transactionId: bytesToHex(txid),
        outputIndex: 2,
        network: "regtest",
        requestType: "fixed",
        creditAmountSats: 50_000,
        payload: utf8ToBytes("aabbcc"),
      }),
      identity,
    );
    signer.dispose();
  });

  test("static-deposit-refund signs the refund statement over the target sighash", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const identity = await signer.identityPublicKey();
    const txid = new Uint8Array(32).fill(8);
    const signature = await signer.signIdentity({
      kind: "static-deposit-refund",
      network: "regtest",
      txid,
      vout: 0,
      amount: 21_000,
      target: TARGET,
    });
    expectDerSignature(
      signature,
      staticDepositStatementDigest({
        transactionId: bytesToHex(txid),
        outputIndex: 0,
        network: "regtest",
        requestType: "refund",
        creditAmountSats: 21_000,
        payload: utf8ToBytes(bytesToHex(taprootKeySpendSighash(TARGET))),
      }),
      identity,
    );
    signer.dispose();
  });

  test("instant-static-deposit signs the zero-confirmation statement", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const identity = await signer.identityPublicKey();
    const statement = {
      kind: "instant-static-deposit",
      network: "regtest",
      creditAmountSats: 10_000,
      secondaryCreditAmountSats: 5000,
      destinationAddress: "bcrt1ptest",
      satsValue: 9000,
      sspSignature: new Uint8Array(64).fill(3),
    } as const;
    const signature = await signer.signIdentity(statement);
    expectDerSignature(
      signature,
      instantStaticDepositStatementDigest({
        network: "regtest",
        creditAmountSats: 10_000,
        secondaryCreditAmountSats: 5000,
        destinationAddress: "bcrt1ptest",
        satsValue: 9000,
        sspSignature: statement.sspSignature,
      }),
      identity,
    );
    signer.dispose();
  });

  test("watchtower-recovery signs the recovery statement", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const identity = await signer.identityPublicKey();
    const signature = await signer.signIdentity({
      kind: "watchtower-recovery",
      network: "regtest",
      leafId: TRANSFER_ID,
      target: TARGET,
    });
    expectDerSignature(
      signature,
      watchtowerRecoveryStatementDigest("regtest", TRANSFER_ID, taprootKeySpendSighash(TARGET)),
      identity,
    );
    signer.dispose();
  });

  test("receive-quote signs the attestor envelope digest", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const identity = await signer.identityPublicKey();
    const manifest = create(TransferManifestSchema, {
      version: 1,
      transferId: TRANSFER_ID,
      network: Network.REGTEST,
      edges: [
        {
          senderIdentityPublicKey: identity,
          receiverIdentityPublicKey: Point.BASE.toBytes(true),
          amount: { amount: { case: "sats", value: 1000n } },
        },
      ],
    });
    const manifestBytes = toBinary(TransferManifestSchema, manifest);
    const paymentHash = new Uint8Array(32).fill(11);
    const signature = await signer.signIdentity({
      kind: "receive-quote",
      network: "regtest",
      manifest: manifestBytes,
      paymentHash,
    });
    expectDerSignature(
      signature,
      quoteEnvelopeDigest({
        network: Network.REGTEST,
        manifestHash: hashTransferManifest(manifest),
        reason: QuoteReason.RECEIVE,
        role: QuoteRole.ATTESTOR,
        target: receiveAttestorTarget(paymentHash),
      }),
      identity,
    );
    await expect(
      signer.signIdentity({
        kind: "receive-quote",
        network: "mainnet",
        manifest: manifestBytes,
        paymentHash,
      }),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  });

  test("spark-invoice signs the invoice hash with BIP-340", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const identity = await signer.identityPublicKey();
    const proto = create(SparkInvoiceFieldsSchema, {
      version: 1,
      id: hexToBytes("550e8400e29b41d4a716446655440000"),
      paymentType: { case: "satsPayment", value: { amount: 1234n } },
      memo: "hello",
    });
    const bytes = toBinary(SparkInvoiceFieldsSchema, proto);
    const signature = await signer.signIdentity({ kind: "spark-invoice", invoice: bytes });
    expect(signature).toHaveLength(64);
    const plain: SparkInvoiceFields = {
      version: 1,
      id: TRANSFER_ID,
      payment: { type: "sats", amount: 1234 },
      memo: "hello",
    };
    const digest = hashSparkInvoice(plain, identity, "regtest");
    expect(schnorr.verify(signature, digest, identity.slice(1))).toBe(true);
    signer.dispose();
  });

  test("token-transaction signs the partial transaction hash with BIP-340", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const identity = await signer.identityPublicKey();
    const partial = create(PartialTokenTransactionSchema, {
      version: 3,
      tokenInputs: {
        case: "transferInput",
        value: {
          outputsToSpend: [
            { prevTokenTransactionHash: hexToBytes("ab".repeat(32)), prevTokenTransactionVout: 0 },
          ],
        },
      },
      partialTokenOutputs: [
        {
          ownerPublicKey: identity,
          tokenIdentifier: hexToBytes("cd".repeat(32)),
          tokenAmount: hexToBytes(`${"00".repeat(15)}64`),
          withdrawBondSats: 10_000n,
          withdrawRelativeBlockLocktime: 1000n,
        },
      ],
    });
    const bytes = toBinary(PartialTokenTransactionSchema, partial);
    const signature = await signer.signIdentity({
      kind: "token-transaction",
      partialTransaction: bytes,
    });
    expect(signature).toHaveLength(64);
    const digest = hashPartialTokenTransaction(fromBinary(PartialTokenTransactionSchema, bytes));
    expect(schnorr.verify(signature, digest, identity.slice(1))).toBe(true);
    signer.dispose();
  });

  test("token-transaction rejects malformed partial transaction bytes", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    await expect(
      signer.signIdentity({
        kind: "token-transaction",
        partialTransaction: hexToBytes("ff".repeat(8)),
      }),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  });
});

describe("signKeySpend", () => {
  test("produces a BIP-340 signature valid under the taproot-tweaked key", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const [depositPublic] = await signer.publicKeys([{ type: "deposit" }]);
    const signature = await signer.signKeySpend({ type: "deposit" }, TARGET);
    expect(signature).toHaveLength(64);
    const tweaked = taprootTweakedKey(depositPublic!).point;
    expect(
      schnorr.verify(signature, taprootKeySpendSighash(TARGET), be32(tweaked.toAffine().x)),
    ).toBe(true);
    signer.dispose();
  });
});

describe("FROST commitments", () => {
  test("newCommitments enforces the batch bounds", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    await expect(signer.newCommitments(0)).rejects.toThrow(SparkInputError);
    await expect(signer.newCommitments(257)).rejects.toThrow(SparkInputError);
    const commitments = await signer.newCommitments(2);
    expect(commitments).toHaveLength(2);
    for (const commitment of commitments) {
      expect(commitment.hiding).toHaveLength(33);
      expect(commitment.binding).toHaveLength(33);
    }
    signer.dispose();
  });

  // 1024 FROST nonce derivations take ~2 s alone, past the 5 s default under a parallel run.
  test("newCommitments bounds outstanding nonces at 1024", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    await signer.newCommitments(256);
    await signer.newCommitments(256);
    await signer.newCommitments(256);
    await signer.newCommitments(256);
    await expect(signer.newCommitments(1)).rejects.toThrow(
      "newCommitments: too many outstanding signing commitments",
    );
    signer.dispose();
  }, 30_000);

  test("signFrost rejects unknown and reused commitments", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const [commitment] = await signer.newCommitments(1);
    const foreignCommitment = {
      hiding: Point.BASE.toBytes(true),
      binding: Point.BASE.toBytes(true),
    };
    const secret = 0x5ea5n;
    const { operators, verifyingKey } = frostGroup(
      secret,
      [11111n, 44444n],
      [
        [22222n, 33333n],
        [55555n, 66666n],
      ],
    );
    const fixtures = operatorSetup(operators);
    // Encrypt the user secret to the signer's identity — the "received" key path.
    const crypto = await backend();
    const ciphertext = crypto.eciesEncrypt(
      await signer.identityPublicKey(),
      be32(secret),
      new Uint8Array(32).fill(1),
    );
    const job = {
      key: { type: "received", ciphertext } as const,
      target: TARGET,
      verifyingKey,
      commitment: commitment!,
      operatorCommitments: fixtures.map((f) => ({
        identifier: f.identifier,
        commitment: f.commitment,
      })),
    };
    await expect(signer.signFrost([{ ...job, commitment: foreignCommitment }])).rejects.toThrow(
      SparkError,
    );
    // The real commitment works once; a second use fails even though the first succeeded.
    const shares = await signer.signFrost([job]);
    expect(shares).toHaveLength(1);
    await expect(signer.signFrost([job])).rejects.toThrow(SparkError);
    signer.dispose();
  });
});

describe("FROST sign + aggregate round trip", () => {
  test("two batched jobs aggregate to BIP-340 signatures under the tweaked key", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const crypto = await backend();
    const secrets = [0x5ea5n, 0xbeefn];
    const groups = secrets.map((secret) =>
      frostGroup(
        secret,
        [11111n, 44444n],
        [
          [22222n, 33333n],
          [55555n, 66666n],
        ],
      ),
    );
    const fixtures = groups.map((group) => operatorSetup(group.operators));
    // Encrypt each secret to the signer identity — the "received" key path.
    const identity = await signer.identityPublicKey();
    const keys = secrets.map((secret, i) => ({
      type: "received" as const,
      ciphertext: crypto.eciesEncrypt(identity, be32(secret), new Uint8Array(32).fill(i + 1)),
    }));
    const commitments = await signer.newCommitments(2);
    const signJobs = keys.map((key, i) => ({
      key,
      target: TARGET,
      verifyingKey: groups[i]!.verifyingKey,
      commitment: commitments[i]!,
      operatorCommitments: fixtures[i]!.map((f) => ({
        identifier: f.identifier,
        commitment: f.commitment,
      })),
    }));
    const userShares = await signer.signFrost(signJobs);
    expect(userShares).toHaveLength(2);
    const message = taprootKeySpendSighash(TARGET);
    const signatures = await signer.aggregateFrost(
      keys.map((key, i) => {
        const operatorShares = operatorSignatureShares({
          operators: groups[i]!.operators,
          verifyingKey: groups[i]!.verifyingKey,
          userCommitment: commitments[i]!,
          message,
        });
        return {
          key,
          target: TARGET,
          verifyingKey: groups[i]!.verifyingKey,
          commitment: commitments[i]!,
          signatureShare: userShares[i]!,
          operators: fixtures[i]!.map((f, j) => ({
            identifier: f.identifier,
            commitment: f.commitment,
            signatureShare: operatorShares[j]!,
            publicKey: f.publicKey,
          })),
        };
      }),
    );
    expect(signatures).toHaveLength(2);
    for (let i = 0; i < signatures.length; i++) {
      const tweaked = taprootTweakedKey(groups[i]!.verifyingKey).point;
      expect(schnorr.verify(signatures[i]!, message, be32(tweaked.toAffine().x))).toBe(true);
    }
    signer.dispose();
  });

  test("a commitment is consumed even when the backend fails", async () => {
    const crypto = await backend();
    const { calls, wrapped } = failFirstCall(crypto.frostSign);
    const flaky: SparkCrypto = { ...crypto, frostSign: wrapped };
    const accountKey = sparkAccountKey(hexToBytes(derivation.cases[0]!.seed_hex), "regtest", 0);
    const signer = createSparkSigner({
      crypto: flaky,
      accountKey,
      network: "regtest",
      random: seededRandom(new Uint8Array(32).fill(5)),
    });
    const [commitment] = await signer.newCommitments(1);
    const job = {
      key: { type: "deposit" } as const,
      target: TARGET,
      verifyingKey: Point.BASE.toBytes(true),
      commitment: commitment!,
      operatorCommitments: [
        {
          identifier: bytesToHex(be32(1n)),
          commitment: { hiding: Point.BASE.toBytes(true), binding: Point.BASE.toBytes(true) },
        },
      ],
    };
    await expect(signer.signFrost([job])).rejects.toThrow(SparkCryptoError);
    await expect(signer.signFrost([job])).rejects.toThrow(SparkError);
    expect(calls()).toBe(1);
    signer.dispose();
  });

  test("backend errors carry their numeric code", async () => {
    const crypto = await backend();
    const coded: SparkCrypto = {
      ...crypto,
      frostCommit: () => {
        throw Object.assign(new Error("backend nack"), { code: 5 });
      },
    };
    const accountKey = sparkAccountKey(hexToBytes(derivation.cases[0]!.seed_hex), "regtest", 0);
    const signer = createSparkSigner({
      crypto: coded,
      accountKey,
      network: "regtest",
      random: seededRandom(new Uint8Array(32).fill(6)),
    });
    await expect(signer.newCommitments(1)).rejects.toThrow(SparkCryptoError);
    const thrown = await signer.newCommitments(1).catch((error: unknown) => error);
    expect(cryptoCode(thrown)).toBe(5);
    signer.dispose();
  });
});

/** Narrows a thrown value to {@link SparkCryptoError} so its ABI code can be asserted. */
function cryptoCode(error: unknown): number {
  if (!(error instanceof SparkCryptoError)) {
    throw new Error("expected a SparkCryptoError");
  }
  return error.code;
}

/** Extracts the ECDSA signature member of a leaf tweak's `sig` oneof. */
function signatureValue(tweak: SendLeafKeyTweak): Uint8Array {
  if (tweak.sig.case !== "signature") {
    throw new Error("expected a signature tweak");
  }
  return tweak.sig.value;
}

/** Wraps `fn` so its first invocation throws — the failure itself is the fixture's subject. */
function failFirstCall(fn: (request: Uint8Array) => Uint8Array): {
  calls: () => number;
  wrapped: (request: Uint8Array) => Uint8Array;
} {
  let calls = 0;
  return {
    calls: () => calls,
    wrapped: (request) => {
      calls += 1;
      if (calls === 1) {
        throw new SparkCryptoError(6);
      }
      return fn(request);
    },
  };
}

function verifyVssShare(
  share: Uint8Array,
  index: bigint,
  proofs: ReadonlyArray<Uint8Array>,
): boolean {
  const lhs = Point.BASE.multiply(Fn.fromBytes(share));
  let rhs = Point.ZERO;
  let power = 1n;
  for (const proof of proofs) {
    rhs = rhs.add(Point.fromBytes(proof).multiply(power));
    power = Fn.mul(power, index);
  }
  return lhs.equals(rhs);
}

function recoverSecret(pairs: ReadonlyArray<readonly [bigint, Uint8Array]>): Uint8Array {
  const xs = pairs.map(([x]) => x);
  let acc = 0n;
  for (const [xi, share] of pairs) {
    acc = Fn.add(acc, Fn.mul(lagrangeCoefficient(xi, xs), Fn.fromBytes(share)));
  }
  return Fn.toBytes(acc);
}

describe("prepareTransfer", () => {
  test("operator packages carry verifiable shares sealing old − new", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const crypto = await backend();
    const identity = await signer.identityPublicKey();
    const leafId = "01905f9b-5b77-7c00-9f60-1c2a2e0a1b2c";
    const [oldPublicKey] = await signer.publicKeys([{ type: "leaf", leafId }]);

    const operatorSecrets = [101n, 202n, 303n];
    const operators = operatorSecrets.map((secret, i) => ({
      ...testOperator(i, secret),
      secret,
    }));
    const receiverSecret = 0x0f00dn;
    const receiverPublicKey = Point.BASE.multiply(receiverSecret).toBytes(true);

    const prepared = await signer.prepareTransfer({
      transferId: TRANSFER_ID,
      receiverIdentityPublicKey: receiverPublicKey,
      leaves: [{ leafId, key: { type: "leaf", leafId } }],
      operators,
      threshold: 2,
    });
    expect(prepared.leaves).toHaveLength(1);
    const leaf = prepared.leaves[0]!;
    const tweaks = operators.map((operator) => {
      const pkg = crypto.eciesDecrypt(
        be32(operator.secret),
        prepared.operatorPackages[operator.identifier]!,
      );
      const decoded = fromBinary(SendLeafKeyTweaksSchema, pkg);
      expect(decoded.leavesToSend).toHaveLength(1);
      return decoded.leavesToSend[0]!;
    });

    const sharePairs: Array<[bigint, Uint8Array]> = [];
    for (const [i, tweak] of tweaks.entries()) {
      const share = tweak.secretShareTweak!.secretShare;
      const { proofs } = tweak.secretShareTweak!;
      const index = BigInt(i + 1);
      expect(proofs).toHaveLength(2);
      expect(verifyVssShare(share, index, proofs)).toBe(true);
      sharePairs.push([index, share]);
      expect(bytesToHex(tweak.secretCipher)).toBe(bytesToHex(leaf.secretCipher));
      expect(tweak.sig.case).toBe("signature");
      expect(bytesToHex(signatureValue(tweak))).toBe(bytesToHex(leaf.signature));
    }
    // pubkeySharesTweak binds every operator's share public key.
    for (const [i, operator] of operators.entries()) {
      const expectedPub = Point.BASE.multiply(Fn.fromBytes(sharePairs[i]![1])).toBytes(true);
      for (const tweak of tweaks) {
        expect(bytesToHex(tweak.pubkeySharesTweak[operator.identifier]!)).toBe(
          bytesToHex(expectedPub),
        );
      }
    }
    // The per-leaf signature is the compact ECDSA over sha256(leafId ‖ transferId ‖ cipher).
    const digest = sendLeafSigningDigest(leafId, TRANSFER_ID, leaf.secretCipher);
    const compact = secp256k1.Signature.fromBytes(leaf.signature);
    expect(secp256k1.verify(compact.toBytes(), digest, identity, { prehash: false })).toBe(true);
    // The receiver unwraps the new leaf key; the VSS-recovered tweak ties old to new.
    const newPrivateKey = crypto.eciesDecrypt(be32(receiverSecret), leaf.secretCipher);
    expect(newPrivateKey).toHaveLength(32);
    expect(bytesToHex(Point.BASE.multiply(Fn.fromBytes(newPrivateKey)).toBytes(true))).toBe(
      bytesToHex(leaf.newPublicKey),
    );
    const tweakSecret = recoverSecret(sharePairs.slice(0, 2));
    const reconstructed = Point.BASE.multiply(Fn.fromBytes(newPrivateKey))
      .add(Point.BASE.multiply(Fn.fromBytes(tweakSecret)))
      .toBytes(true);
    expect(bytesToHex(reconstructed)).toBe(bytesToHex(oldPublicKey!));
    newPrivateKey.fill(0);
    signer.dispose();
  });

  test("rejects empty leaves and operators", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const operators = [testOperator(0, 101n)];
    await expect(
      signer.prepareTransfer({
        transferId: TRANSFER_ID,
        receiverIdentityPublicKey: Point.BASE.toBytes(true),
        leaves: [],
        operators,
        threshold: 1,
      }),
    ).rejects.toThrow(SparkInputError);
    await expect(
      signer.prepareTransfer({
        transferId: TRANSFER_ID,
        receiverIdentityPublicKey: Point.BASE.toBytes(true),
        leaves: [{ leafId: "x", key: { type: "leaf", leafId: "x" } }],
        operators: [],
        threshold: 1,
      }),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  });
});

describe("prepareClaim", () => {
  test("operator packages carry verifiable shares sealing received − leaf", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const crypto = await backend();
    const identity = await signer.identityPublicKey();
    const leafId = "6f9619ff-8b86-d011-b42d-00cf4fc964ff";
    const [leafPublicKey] = await signer.publicKeys([{ type: "leaf", leafId }]);

    const receivedSecret = 0xabcd1234n;
    const receivedPublicKey = Point.BASE.multiply(receivedSecret).toBytes(true);
    const secretCipher = crypto.eciesEncrypt(
      identity,
      be32(receivedSecret),
      new Uint8Array(32).fill(3),
    );

    const operatorSecrets = [111n, 222n, 333n];
    const operators = operatorSecrets.map((secret, i) => ({
      ...testOperator(i, secret),
      secret,
    }));
    const prepared = await signer.prepareClaim({
      transferId: TRANSFER_ID,
      leaves: [{ leafId, secretCipher }],
      operators,
      threshold: 2,
    });

    const sharePairs: Array<[bigint, Uint8Array]> = [];
    for (const [i, operator] of operators.entries()) {
      const pkg = crypto.eciesDecrypt(
        be32(operator.secret),
        prepared.operatorPackages[operator.identifier]!,
      );
      const decoded = fromBinary(ClaimLeafKeyTweaksSchema, pkg);
      expect(decoded.leavesToReceive).toHaveLength(1);
      const tweak = decoded.leavesToReceive[0]!;
      const index = BigInt(i + 1);
      const share = tweak.secretShareTweak!.secretShare;
      expect(verifyVssShare(share, index, tweak.secretShareTweak!.proofs)).toBe(true);
      sharePairs.push([index, share]);
    }
    // pubkeySharesTweak binds every operator's share public key.
    const pkgs = operators.map((operator) =>
      fromBinary(
        ClaimLeafKeyTweaksSchema,
        crypto.eciesDecrypt(be32(operator.secret), prepared.operatorPackages[operator.identifier]!),
      ),
    );
    for (const [i, operator] of operators.entries()) {
      const expectedPub = Point.BASE.multiply(Fn.fromBytes(sharePairs[i]![1])).toBytes(true);
      for (const pkg of pkgs) {
        expect(bytesToHex(pkg.leavesToReceive[0]!.pubkeySharesTweak[operator.identifier]!)).toBe(
          bytesToHex(expectedPub),
        );
      }
    }
    // recovered tweak = received − leaf → leaf·G + tweak·G = received·G
    const tweakSecret = recoverSecret(sharePairs.slice(0, 2));
    const reconstructed = Point.fromBytes(leafPublicKey!)
      .add(Point.BASE.multiply(Fn.fromBytes(tweakSecret)))
      .toBytes(true);
    expect(bytesToHex(reconstructed)).toBe(bytesToHex(receivedPublicKey));
    signer.dispose();
  });
});

describe("prepareLightningReceive", () => {
  test("payment hash is sha256 of the VSS-recovered preimage", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const crypto = await backend();
    const operatorSecrets = [41n, 42n, 43n];
    const operators = operatorSecrets.map((secret, i) => ({
      ...testOperator(i, secret),
      secret,
    }));
    const prepared = await signer.prepareLightningReceive({ operators, threshold: 2 });
    expect(prepared.paymentHash).toHaveLength(32);
    const sharePairs: Array<[bigint, Uint8Array]> = [];
    for (const [i, operator] of operators.entries()) {
      const pkg = crypto.eciesDecrypt(
        be32(operator.secret),
        prepared.operatorPackages[operator.identifier]!,
      );
      const share = fromBinary(SecretShareSchema, pkg);
      const index = BigInt(i + 1);
      expect(verifyVssShare(share.secretShare, index, share.proofs)).toBe(true);
      sharePairs.push([index, share.secretShare]);
    }
    const preimage = recoverSecret(sharePairs.slice(0, 2));
    expect(bytesToHex(sha256(preimage))).toBe(bytesToHex(prepared.paymentHash));
    preimage.fill(0);
    signer.dispose();
  });
});

describe("claimStaticDeposit + receivedPublicKeys", () => {
  test("returns the static-deposit secret and a DER statement signature", async () => {
    const c = derivation.cases[0]!;
    const signer = await signerFor(c.seed_hex);
    const identity = await signer.identityPublicKey();
    const txid = new Uint8Array(32).fill(9);
    const statement = {
      kind: "static-deposit-claim",
      network: "regtest",
      txid,
      vout: 0,
      creditAmountSats: 10_000,
      sspSignature: "ff00",
    } as const;
    const result = await signer.claimStaticDeposit({ index: 0, statement });
    expect(result.secretKey).toHaveLength(32);
    expect(bytesToHex(Point.BASE.multiply(Fn.fromBytes(result.secretKey)).toBytes(true))).toBe(
      c.static_deposit_public_keys[0]!.public_key,
    );
    expectDerSignature(
      result.signature,
      staticDepositStatementDigest({
        transactionId: bytesToHex(txid),
        outputIndex: 0,
        network: "regtest",
        requestType: "fixed",
        creditAmountSats: 10_000,
        payload: utf8ToBytes("ff00"),
      }),
      identity,
    );
    signer.dispose();
  });

  test("receivedPublicKeys decrypts sealed secrets to their public keys", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const crypto = await backend();
    const identity = await signer.identityPublicKey();
    const secret = 0xdec0den;
    const ciphertext = crypto.eciesEncrypt(identity, be32(secret), new Uint8Array(32).fill(2));
    const keys = await signer.receivedPublicKeys([ciphertext]);
    expect(bytesToHex(keys[0]!)).toBe(bytesToHex(Point.BASE.multiply(secret).toBytes(true)));
    await expect(signer.receivedPublicKeys([new Uint8Array(10)])).rejects.toThrow(SparkError);
    signer.dispose();
  });
});

describe("signer lifecycle", () => {
  test("dispose rejects every subsequent call", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    signer.dispose();
    signer.dispose();
    await expect(signer.identityPublicKey()).rejects.toThrow(SparkError);
    await expect(signer.newCommitments(1)).rejects.toThrow(SparkError);
    await expect(
      signer.signIdentity({ kind: "ssp-challenge", protectedChallenge: "eA" }),
    ).rejects.toThrow(SparkError);
    await expect(signer.signKeySpend({ type: "deposit" }, TARGET)).rejects.toThrow(SparkError);
    await expect(signer.signFrost([])).rejects.toThrow(SparkError);
  });

  test("createSparkSigner rejects ABI mismatches and malformed keys", async () => {
    const crypto = await backend();
    const accountKey = sparkAccountKey(hexToBytes(derivation.cases[0]!.seed_hex), "regtest", 0);
    expect(() =>
      createSparkSigner({
        crypto: { ...crypto, abiVersion: 2 },
        accountKey,
        network: "regtest",
        random: seededRandom(new Uint8Array(32)),
      }),
    ).toThrow(SparkInputError);
    expect(() =>
      createSparkSigner({
        crypto,
        accountKey: new Uint8Array(63),
        network: "regtest",
        random: seededRandom(new Uint8Array(32)),
      }),
    ).toThrow(SparkInputError);
    expect(() =>
      createSparkSigner({
        crypto,
        accountKey: new Uint8Array(64),
        network: "regtest",
        random: seededRandom(new Uint8Array(32)),
      }),
    ).toThrow(SparkInputError);
  });
});
