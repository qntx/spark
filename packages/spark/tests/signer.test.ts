import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import {
  constructHtlcSenderSpend,
  constructHtlcTransaction,
  createSequenceLockScript,
  LIGHTNING_HTLC_SEQUENCE,
  lightningHtlcOutputScript,
} from "../src/core/bitcoin/htlc.ts";
import { EPHEMERAL_ANCHOR_SCRIPT, p2trScriptFromPublicKey } from "../src/core/bitcoin/script.ts";
import type { SigningTarget } from "../src/core/bitcoin/sighash.ts";
import { taprootKeySpendSighash, taprootScriptSpendSighash } from "../src/core/bitcoin/sighash.ts";
import { txIdInputBytes } from "../src/core/bitcoin/transactions.ts";
import {
  authnChallengeDigest,
  claimPackageDigest,
  hashSparkInvoice,
  sendLeafSigningDigest,
  sspChallengeDigest,
  staticDepositStatementDigest,
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
  SecretShareSchema,
  SendLeafKeyTweaksSchema,
  SparkInvoiceFieldsSchema,
  TransferPackageSchema,
} from "../src/proto/gen/spark_pb.ts";
import { PartialTokenTransactionSchema } from "../src/proto/gen/spark_token_pb.ts";
import { ProtectedChallengeSchema } from "../src/proto/gen/ssp_authn_pb.ts";
import {
  createSparkSigner,
  lightningSendHtlcScript,
  sparkAccountKey,
} from "../src/signer/index.ts";
import type { SparkKey, SparkOperator, SparkOutflow, SparkSigner } from "../src/signer/index.ts";
import { loadWasmBackend } from "./support/backend.ts";
import { seededRandom } from "./support/fakes.ts";
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
  htlc: Array<{
    name: string;
    htlcTx?: string;
    paymentHash: string;
    hashLockPublicKey: string;
  }>;
};

const TRANSFER_ID = "550e8400-e29b-41d4-a716-446655440000";
const { Fn } = secp256k1.Point;
const { Point } = secp256k1;

// Minimal whitelisted target: single input, P2A-anchor output — keeps FROST mechanics tests
// out of the exit/lightning whitelist path. The shares' sighash verifies against this target.
const targetTx = new Transaction({ allowUnknownOutputs: true });
targetTx.addInput({ txid: new Uint8Array(32).fill(3), index: 0 });
targetTx.addOutput({ script: EPHEMERAL_ANCHOR_SCRIPT, amount: 0n });
const TARGET: SigningTarget = {
  transaction: targetTx.toBytes(),
  inputIndex: 0,
  prevouts: [
    { script: p2trScriptFromPublicKey(Point.BASE.toBytes(true), "regtest"), amount: 1000 },
  ],
};

let cryptoPromise: Promise<SparkCrypto> | undefined;
const backend = async (): Promise<SparkCrypto> => {
  cryptoPromise ??= loadWasmBackend();
  return cryptoPromise;
};

async function signerFor(
  seedHex: string,
  account = 0,
  randomSeed = 1,
  binding?: {
    readonly operators?: ReadonlyArray<SparkOperator>;
    readonly threshold?: number;
    readonly sspIdentityPublicKey?: Uint8Array;
    readonly authorize?: (outflow: SparkOutflow) => Promise<void>;
  },
): Promise<SparkSigner> {
  const accountKey = sparkAccountKey(hexToBytes(seedHex), "regtest", account);
  return createSparkSigner({
    crypto: await backend(),
    accountKey,
    network: "regtest",
    random: seededRandom(new Uint8Array(32).fill(randomSeed)),
    ...binding,
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
    "identity/static/leaf public keys match upstream (case $account)",
    async (c) => {
      const signer = await signerFor(c.seed_hex, c.account);
      expect(bytesToHex(await signer.identityPublicKey())).toBe(c.identity_public_key);
      const keys = await signer.publicKeys([
        ...c.static_deposit_public_keys.map(
          (k) => ({ type: "static-deposit", index: k.index }) as const,
        ),
        ...c.leaf_public_keys.map((k) => ({ type: "leaf", leafId: k.leaf_id }) as const),
      ]);
      for (const [i, k] of c.static_deposit_public_keys.entries()) {
        expect(bytesToHex(keys[i]!)).toBe(k.public_key);
      }
      for (const [i, k] of c.leaf_public_keys.entries()) {
        expect(bytesToHex(keys[i + c.static_deposit_public_keys.length]!)).toBe(k.public_key);
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
    const protectedChallenge = base64.encode(
      toBinary(ProtectedChallengeSchema, {
        $typeName: "ssp_authn.ProtectedChallenge",
        version: 1,
        challenge: {
          $typeName: "ssp_authn.Challenge",
          version: 1,
          timestamp: 1_786_974_052n,
          nonce: new Uint8Array(32).fill(9),
          publicKey: identity,
        },
        serverHmac: new Uint8Array(32).fill(7),
      }),
    );
    const signature = await signer.signIdentity({
      kind: "ssp-challenge",
      protectedChallenge,
    });
    expectDerSignature(signature, sspChallengeDigest(protectedChallenge, identity), identity);
    signer.dispose();
  });

  // protected_challenge responses served by api.lightspark.com, captured by
  // breez-spark-sdk crates/spark/src/ssp/challenge.rs tests @956ff90: the first
  // for the secp256k1 generator point, the second for another key.
  const LIVE_CHALLENGES: ReadonlyArray<readonly [string, string]> = [
    [
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
      "0801524f080150e49e8cd406a201203cc9ed127c551fb4ea5fb97233115307c4fa9233ece3e6087aad7" +
        "d95e01f9d7ef201210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798a2" +
        "0120543f1936b8b6422fa7fdd92b8bb5aa8b0a31f0c7989675a2fec3a8c6487f42b7",
    ],
    [
      "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
      "0801524f080150bec28cd406a20120562fb45d2f8388acae10b882c86a08c6f4e4a93742f7f8568f83d" +
        "d18a8024a32f2012103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556a2" +
        "012014b947efeab6d6a3d34c2e19ee3bc94fbfd8893cf0b09c4d16df9d6d4549ebed",
    ],
  ];

  test("ssp-challenge accepts the live captured challenges", () => {
    for (const [publicKeyHex, challengeHex] of LIVE_CHALLENGES) {
      const bytes = hexToBytes(challengeHex);
      const digest = sspChallengeDigest(base64.encode(bytes), hexToBytes(publicKeyHex));
      expect(bytesToHex(digest)).toBe(bytesToHex(sha256(bytes)));
    }
  });

  test("ssp-challenge rejects a challenge issued to another key", () => {
    const bytes = hexToBytes(LIVE_CHALLENGES[0]![1]);
    expect(() =>
      sspChallengeDigest(base64.encode(bytes), hexToBytes(LIVE_CHALLENGES[1]![0])),
    ).toThrow(SparkInputError);
  });

  test("ssp-challenge accepts either public key encoding", () => {
    const uncompressed = secp256k1.Point.BASE.toBytes(false);
    const bytes = toBinary(ProtectedChallengeSchema, {
      $typeName: "ssp_authn.ProtectedChallenge",
      version: 1,
      challenge: {
        $typeName: "ssp_authn.Challenge",
        version: 1,
        timestamp: 1n,
        nonce: new Uint8Array(32).fill(7),
        publicKey: uncompressed,
      },
      serverHmac: new Uint8Array(32).fill(9),
    });
    expect(() =>
      sspChallengeDigest(base64.encode(bytes), secp256k1.Point.BASE.toBytes(true)),
    ).not.toThrow();
  });

  test("ssp-challenge rejects arbitrary text", () => {
    for (const text of ["sign this please", "v2\naction\nexample.com\nalice\n1786974052"]) {
      expect(() =>
        sspChallengeDigest(base64.encode(utf8ToBytes(text)), secp256k1.Point.BASE.toBytes(true)),
      ).toThrow(SparkInputError);
    }
  });

  test("ssp-challenge tolerates unknown leading and trailing fields", () => {
    const live = hexToBytes(LIVE_CHALLENGES[0]![1]);
    const identity = hexToBytes(LIVE_CHALLENGES[0]![0]);
    // field 40, wire type 2: "added later" (0xA2 0x02 = tag(40)<<3|2, len 11 → wait: 11 bytes)
    const trailing = concatBytes(
      live,
      new Uint8Array([0xc2, 0x02, 0x0b]),
      utf8ToBytes("added later"),
    );
    expect(() => sspChallengeDigest(base64.encode(trailing), identity)).not.toThrow();
    const leading = concatBytes(new Uint8Array([0x62, 0x0b]), utf8ToBytes("added later"), live);
    expect(() => sspChallengeDigest(base64.encode(leading), identity)).not.toThrow();
  });

  test("ssp-challenge rejects missing challenge, empty key and malformed key", () => {
    const identity = secp256k1.Point.BASE.toBytes(true);
    const noChallenge = toBinary(ProtectedChallengeSchema, {
      $typeName: "ssp_authn.ProtectedChallenge",
      version: 1,
      serverHmac: new Uint8Array(32).fill(9),
    });
    expect(() => sspChallengeDigest(base64.encode(noChallenge), identity)).toThrow(SparkInputError);
    for (const badKey of [new Uint8Array(0), new Uint8Array(33)]) {
      const bytes = toBinary(ProtectedChallengeSchema, {
        $typeName: "ssp_authn.ProtectedChallenge",
        version: 1,
        challenge: {
          $typeName: "ssp_authn.Challenge",
          version: 1,
          timestamp: 1n,
          nonce: new Uint8Array(32).fill(7),
          publicKey: badKey,
        },
        serverHmac: new Uint8Array(32).fill(9),
      });
      expect(() => sspChallengeDigest(base64.encode(bytes), identity)).toThrow(SparkInputError);
    }
  });

  test("ssp-challenge rejects an SO challenge serialized for the same key", () => {
    // Regression: a spark_authn.Challenge (SO authn) must never be accepted as
    // an ssp_authn.ProtectedChallenge — cross-protocol challenge confusion.
    const identity = secp256k1.Point.BASE.toBytes(true);
    const soChallenge = toBinary(ChallengeSchema, {
      $typeName: "spark_authn.Challenge",
      version: 1,
      timestamp: 1_700_000_000n,
      nonce: new Uint8Array(32).fill(7),
      publicKey: identity,
    });
    expect(() => sspChallengeDigest(base64.encode(soChallenge), identity)).toThrow(SparkInputError);
  });

  test("transfer-package fails closed without a recorded prepareTransfer", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const pkg = create(TransferPackageSchema, {
      keyTweakPackage: { operator: new Uint8Array([1, 2, 3]) },
      hashVariant: HashVariant.V2,
    });
    const bytes = toBinary(TransferPackageSchema, pkg);
    await expect(
      signer.signIdentity({ kind: "transfer-package", transferId: TRANSFER_ID, package: bytes }),
    ).rejects.toThrow(SparkInputError);
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
      sspSignature: hexToBytes("aabbcc"),
    });
    expectDerSignature(
      signature,
      staticDepositStatementDigest({
        transactionId: bytesToHex(txid),
        outputIndex: 2,
        network: "regtest",
        requestType: "fixed",
        creditAmountSats: 50_000,
        payload: hexToBytes("aabbcc"),
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
        payload: taprootKeySpendSighash(TARGET),
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
    const [staticPublic] = await signer.publicKeys([{ type: "static-deposit", index: 0 }]);
    const signature = await signer.signKeySpend({ type: "static-deposit", index: 0 }, TARGET);
    expect(signature).toHaveLength(64);
    const tweaked = taprootTweakedKey(staticPublic!).point;
    expect(
      schnorr.verify(signature, taprootKeySpendSighash(TARGET), be32(tweaked.toAffine().x)),
    ).toBe(true);
    signer.dispose();
  });
});

describe("signHtlcTimeout", () => {
  const htlcVector = transactions.htlc.find(
    (c) => c.name === "sender-spend" && c.htlcTx !== undefined,
  )!;
  const PARENT_TX = hexToBytes(htlcVector.htlcTx!);
  const PAYMENT_HASH = hexToBytes(htlcVector.paymentHash);
  const HASH_LOCK_KEY = hexToBytes(htlcVector.hashLockPublicKey);
  const DESTINATION = hexToBytes(`5120${"11".repeat(32)}`);

  // The "refund transaction" carrying the HTLC output — built with the signer's own identity on
  // the sequence-lock leaf, so output 0 is exactly what signHtlcTimeout rebuilds.
  const htlcTxFor = (identity: Uint8Array) =>
    constructHtlcTransaction(
      PARENT_TX,
      0,
      2000,
      PAYMENT_HASH,
      HASH_LOCK_KEY,
      identity,
      LIGHTNING_HTLC_SEQUENCE,
      false,
      0,
    ).txBytes;
  const prevoutSats = (htlcTx: Uint8Array) =>
    Number(Transaction.fromRaw(htlcTx, { allowUnknownOutputs: true }).getOutput(0).amount);
  const senderSweep = (htlcTx: Uint8Array, identity: Uint8Array) =>
    constructHtlcSenderSpend(
      htlcTx,
      0,
      DESTINATION,
      PAYMENT_HASH,
      HASH_LOCK_KEY,
      identity,
      LIGHTNING_HTLC_SEQUENCE,
      0,
    );

  test("BIP-340-signs the sequence-lock-leaf sighash with the identity key", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const identity = await signer.identityPublicKey();
    const htlcTx = htlcTxFor(identity);
    const spend = senderSweep(htlcTx, identity);
    const signature = await signer.signHtlcTimeout({
      transaction: spend.txBytes,
      inputIndex: 0,
      prevoutAmountSats: prevoutSats(htlcTx),
      paymentHash: PAYMENT_HASH,
      hashLockPublicKey: HASH_LOCK_KEY,
    });
    expect(signature).toHaveLength(64);
    expect(schnorr.verify(signature, spend.sighash, identity.subarray(1))).toBe(true);
    signer.dispose();
  });

  test("the sighash is exactly the sequence-lock-leaf script spend", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const identity = await signer.identityPublicKey();
    const htlcTx = htlcTxFor(identity);
    const spend = senderSweep(htlcTx, identity);
    const expected = taprootScriptSpendSighash(
      {
        transaction: spend.txBytes,
        inputIndex: 0,
        prevouts: [
          {
            script: lightningHtlcOutputScript(PAYMENT_HASH, HASH_LOCK_KEY, identity),
            amount: prevoutSats(htlcTx),
          },
        ],
      },
      createSequenceLockScript(LIGHTNING_HTLC_SEQUENCE, identity),
    );
    expect(bytesToHex(spend.sighash)).toBe(bytesToHex(expected));
    signer.dispose();
  });

  test.each([
    {
      name: "relative timelock below the HTLC CSV",
      sequence: LIGHTNING_HTLC_SEQUENCE - 1,
    },
    {
      name: "relative timelock disabled",
      sequence: (0x80_00_00_00 | LIGHTNING_HTLC_SEQUENCE) >>> 0,
    },
    { name: "final sequence", sequence: 0xff_ff_ff_ff },
  ])("rejects an input with $name", async ({ sequence }) => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const tx = new Transaction({ version: 3, allowUnknownOutputs: true });
    tx.addInput({ txid: new Uint8Array(32).fill(1), index: 0, sequence });
    tx.addOutput({ script: DESTINATION, amount: 1000n });
    await expect(
      signer.signHtlcTimeout({
        transaction: tx.toBytes(true),
        inputIndex: 0,
        prevoutAmountSats: 1000,
        paymentHash: PAYMENT_HASH,
        hashLockPublicKey: HASH_LOCK_KEY,
      }),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  });

  test.each([
    { name: "a two-input transaction", inputs: 2, inputIndex: 0 },
    { name: "a nonzero input index", inputs: 1, inputIndex: 1 },
  ])("rejects $name", async ({ inputs, inputIndex }) => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const tx = new Transaction({ version: 3, allowUnknownOutputs: true });
    for (let i = 0; i < inputs; i += 1) {
      tx.addInput({
        txid: new Uint8Array(32).fill(1),
        index: i,
        sequence: LIGHTNING_HTLC_SEQUENCE,
      });
    }
    tx.addOutput({ script: DESTINATION, amount: 1000n });
    await expect(
      signer.signHtlcTimeout({
        transaction: tx.toBytes(true),
        inputIndex,
        prevoutAmountSats: 1000,
        paymentHash: PAYMENT_HASH,
        hashLockPublicKey: HASH_LOCK_KEY,
      }),
    ).rejects.toThrow(SparkInputError);
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
  test("newCommitments evicts the oldest outstanding nonces past 1024", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const first = await signer.newCommitments(256);
    await signer.newCommitments(256);
    await signer.newCommitments(256);
    await signer.newCommitments(256);
    // A valid count is never refused: the oldest outstanding nonces are evicted (wiped) instead.
    const extra = await signer.newCommitments(8);
    expect(extra).toHaveLength(8);
    const job = (commitment: (typeof first)[number]) => ({
      key: { type: "static-deposit", index: 0 } as const,
      target: TARGET,
      verifyingKey: Point.BASE.toBytes(true),
      commitment,
      operatorCommitments: [
        {
          identifier: bytesToHex(be32(1n)),
          commitment: { hiding: Point.BASE.toBytes(true), binding: Point.BASE.toBytes(true) },
        },
      ],
    });
    // The evicted commitment is gone for good; one that survived still reaches the backend.
    await expect(signer.signFrost([job(first[0]!)])).rejects.toThrow(
      "unknown or already-consumed signing commitment",
    );
    await expect(signer.signFrost([job(first[8]!)])).resolves.toHaveLength(1);
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

describe("backend randomness seeds", () => {
  test("every seed passed to the backend is wiped after the call", async () => {
    const produced: Uint8Array[] = [];
    const draw = seededRandom(new Uint8Array(32).fill(3));
    const recording = (length: number): Uint8Array => {
      const out = draw(length);
      produced.push(out);
      return out;
    };
    const accountKey = sparkAccountKey(hexToBytes(derivation.cases[0]!.seed_hex), "regtest", 0);
    const signer = createSparkSigner({
      crypto: await backend(),
      accountKey,
      network: "regtest",
      random: recording,
      operators: [testOperator(0, 0x21n), testOperator(1, 0x22n), testOperator(2, 0x23n)],
      threshold: 2,
    });
    try {
      // frostCommit (nonces) then a VSS split + per-operator ECIES seals.
      await signer.newCommitments(2);
      await signer.prepareLightningReceive();
      expect(produced.length).toBeGreaterThan(0);
      for (const seed of produced) {
        expect(seed.every((byte) => byte === 0)).toBe(true);
      }
    } finally {
      signer.dispose();
    }
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
      key: { type: "static-deposit", index: 0 } as const,
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
    const operatorSecrets = [101n, 202n, 303n];
    const operators = operatorSecrets.map((secret, i) => ({
      ...testOperator(i, secret),
      secret,
    }));
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      operators,
      threshold: 2,
    });
    const crypto = await backend();
    const identity = await signer.identityPublicKey();
    const leafId = "01905f9b-5b77-7c00-9f60-1c2a2e0a1b2c";
    const [oldPublicKey] = await signer.publicKeys([{ type: "leaf", leafId }]);

    const receiverSecret = 0x0f00dn;
    const receiverPublicKey = Point.BASE.multiply(receiverSecret).toBytes(true);

    const prepared = await signer.prepareTransfer({
      transferId: TRANSFER_ID,
      leaves: [
        {
          leafId,
          key: { type: "leaf", leafId },
          receiverIdentityPublicKey: receiverPublicKey,
        },
      ],
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

  test("each leaf's secret cipher opens only under its own receiver's key", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const crypto = await backend();
    const leafIds = [
      "01905f9b-5b77-7c00-9f60-1c2a2e0a1b2c",
      "6f9619ff-8b86-d011-b42d-00cf4fc964ff",
    ];
    const receiverSecrets = [0x0f00dn, 0xabcd1234n];
    const receiverPublicKeys = receiverSecrets.map((secret) =>
      Point.BASE.multiply(secret).toBytes(true),
    );

    const prepared = await signer.prepareTransfer({
      transferId: TRANSFER_ID,
      leaves: leafIds.map((leafId, index) => ({
        leafId,
        key: { type: "leaf" as const, leafId },
        receiverIdentityPublicKey: receiverPublicKeys[index]!,
      })),
    });
    expect(prepared.leaves).toHaveLength(2);

    for (const [index, leaf] of prepared.leaves.entries()) {
      const opened = crypto.eciesDecrypt(be32(receiverSecrets[index]!), leaf.secretCipher);
      expect(bytesToHex(Point.BASE.multiply(Fn.fromBytes(opened)).toBytes(true))).toBe(
        bytesToHex(leaf.newPublicKey),
      );
      opened.fill(0);
    }
    // The other receiver's key cannot open leaf 0's cipher.
    expect(() =>
      crypto.eciesDecrypt(be32(receiverSecrets[1]!), prepared.leaves[0]!.secretCipher),
    ).toThrow(SparkCryptoError);
    signer.dispose();
  });

  test("rejects empty leaves and an empty construction-time operator set", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    await expect(
      signer.prepareTransfer({
        transferId: TRANSFER_ID,
        leaves: [],
      }),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
    await expect(signerFor(derivation.cases[0]!.seed_hex, 0, 1, { operators: [] })).rejects.toThrow(
      SparkInputError,
    );
  });

  test("rejects a malformed per-leaf receiver identity key", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const leafId = "01905f9b-5b77-7c00-9f60-1c2a2e0a1b2c";
    await expect(
      signer.prepareTransfer({
        transferId: TRANSFER_ID,
        leaves: [
          {
            leafId,
            key: { type: "leaf", leafId },
            receiverIdentityPublicKey: new Uint8Array(32),
          },
        ],
      }),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  });
});

describe("prepareClaim", () => {
  test("operator packages carry verifiable shares sealing received − leaf", async () => {
    const operatorSecrets = [111n, 222n, 333n];
    const operators = operatorSecrets.map((secret, i) => ({
      ...testOperator(i, secret),
      secret,
    }));
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      operators,
      threshold: 2,
    });
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

    const prepared = await signer.prepareClaim({
      transferId: TRANSFER_ID,
      leaves: [{ leafId, secretCipher }],
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

describe("threshold validation", () => {
  test.each([2.5, 0, 1, 4, 2 ** 32 + 3])(
    "rejects threshold %s at construction",
    async (threshold) => {
      const operators = [testOperator(0, 101n), testOperator(1, 102n), testOperator(2, 103n)];
      await expect(
        signerFor(derivation.cases[0]!.seed_hex, 0, 1, { operators, threshold }),
      ).rejects.toThrow(SparkInputError);
    },
  );
});

describe("prepareLightningReceive", () => {
  test("payment hash is sha256 of the VSS-recovered preimage", async () => {
    const operatorSecrets = [41n, 42n, 43n];
    const operators = operatorSecrets.map((secret, i) => ({
      ...testOperator(i, secret),
      secret,
    }));
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      operators,
      threshold: 2,
    });
    const crypto = await backend();
    const prepared = await signer.prepareLightningReceive();
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
  const SSP_SECRET = new Uint8Array(32).fill(42);
  const SSP_IDENTITY = secp256k1.getPublicKey(SSP_SECRET, true);

  test("seals the static-deposit secret to the SSP and signs the claim statement", async () => {
    const c = derivation.cases[0]!;
    const signer = await signerFor(c.seed_hex, c.account, 1, {
      sspIdentityPublicKey: SSP_IDENTITY,
    });
    const identity = await signer.identityPublicKey();
    const txid = new Uint8Array(32).fill(9);
    const statement = {
      kind: "static-deposit-claim",
      network: "regtest",
      txid,
      vout: 0,
      creditAmountSats: 10_000,
      sspSignature: hexToBytes("ff00"),
    } as const;
    const result = await signer.claimStaticDeposit({
      index: 0,
      statement,
    });
    // Only the SSP identity key can open the sealed deposit key.
    const crypto = await backend();
    const secret = crypto.eciesDecrypt(SSP_SECRET, result.encryptedSecretKey);
    try {
      expect(bytesToHex(Point.BASE.multiply(Fn.fromBytes(secret)).toBytes(true))).toBe(
        c.static_deposit_public_keys[0]!.public_key,
      );
    } finally {
      secret.fill(0);
    }
    expectDerSignature(
      result.signature,
      staticDepositStatementDigest({
        transactionId: bytesToHex(txid),
        outputIndex: 0,
        network: "regtest",
        requestType: "fixed",
        creditAmountSats: 10_000,
        payload: hexToBytes("ff00"),
      }),
      identity,
    );
    signer.dispose();
  });

  test("rejects an sspIdentityPublicKey that is not a 33-byte point", async () => {
    const seed = derivation.cases[0]!.seed_hex;
    await expect(
      signerFor(seed, 0, 1, { sspIdentityPublicKey: new Uint8Array(32) }),
    ).rejects.toThrow(SparkInputError);
    await expect(
      signerFor(seed, 0, 1, { sspIdentityPublicKey: new Uint8Array(33).fill(4) }),
    ).rejects.toThrow(SparkInputError);
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
    await expect(signer.signKeySpend({ type: "static-deposit", index: 0 }, TARGET)).rejects.toThrow(
      SparkError,
    );
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

describe("outflow derivation", () => {
  const outflowAs = <K extends SparkOutflow["kind"]>(
    outflow: SparkOutflow,
    kind: K,
  ): Extract<SparkOutflow, { readonly kind: K }> => {
    if (outflow.kind !== kind) {
      throw new Error(`expected ${kind} outflow, got ${outflow.kind}`);
    }
    return outflow as Extract<SparkOutflow, { readonly kind: K }>;
  };
  const p2trScript = (publicKey: Uint8Array): Uint8Array =>
    concatBytes(Uint8Array.of(0x51, 0x20), publicKey.subarray(1));

  function refundTarget(options: {
    readonly leafAmount: number;
    readonly outputScripts: ReadonlyArray<Uint8Array>;
    readonly connectorTxid?: Uint8Array;
    readonly sameScriptInputs?: number;
  }): SigningTarget {
    const tx = new Transaction({ allowUnknownOutputs: true });
    tx.addInput({ txid: new Uint8Array(32).fill(3), index: 0 });
    if (options.connectorTxid !== undefined) {
      tx.addInput({ txid: options.connectorTxid, index: 7 });
    }
    const spentScript = p2trScript(Point.BASE.toBytes(true));
    const prevouts = [{ script: spentScript, amount: options.leafAmount }];
    if (options.connectorTxid !== undefined) {
      prevouts.push({ script: p2trScript(Point.BASE.multiply(2n).toBytes(true)), amount: 0 });
    }
    // Extra inputs spending the SAME script — a multi-UTXO root, not a connector.
    for (let i = 0; i < (options.sameScriptInputs ?? 0); i++) {
      tx.addInput({ txid: new Uint8Array(32).fill(20 + i), index: i });
      prevouts.push({ script: spentScript, amount: 1000 });
    }
    for (const [i, script] of options.outputScripts.entries()) {
      tx.addOutput({ script, amount: BigInt((i + 1) * 500) });
    }
    return { transaction: tx.toBytes(), inputIndex: 0, prevouts };
  }

  async function signRefund(
    signer: SparkSigner,
    key: SparkKey,
    options: {
      readonly leafAmount: number;
      readonly receiver?: Uint8Array;
      readonly outputScripts?: ReadonlyArray<Uint8Array>;
      readonly connectorTxid?: Uint8Array;
      readonly exit?: { readonly connectorTx: Uint8Array; readonly exitTx: Uint8Array };
    },
  ): Promise<void> {
    const [commitment] = await signer.newCommitments(1);
    const { operators, verifyingKey } = frostGroup(
      0x5ea5n,
      [11111n, 44444n],
      [
        [22222n, 33333n],
        [55555n, 66666n],
      ],
    );
    const fixtures = operatorSetup(operators);
    const receiver = options.receiver ?? Point.BASE.toBytes(true);
    const target = refundTarget({
      leafAmount: options.leafAmount,
      outputScripts: options.outputScripts ?? [p2trScriptFromPublicKey(receiver, "regtest")],
      ...(options.connectorTxid === undefined ? {} : { connectorTxid: options.connectorTxid }),
    });
    const shares = await signer.signFrost([
      {
        key,
        target,
        verifyingKey,
        commitment: commitment!,
        operatorCommitments: fixtures.map((f) => ({
          identifier: f.identifier,
          commitment: f.commitment,
        })),
        ...(options.exit === undefined ? {} : { exit: options.exit }),
      },
    ]);
    expect(shares).toHaveLength(1);
  }

  /** One signFrost batch over several refund specs — batch-level rules apply to the whole call. */
  async function signRefundBatch(
    signer: SparkSigner,
    specs: ReadonlyArray<{
      readonly key: SparkKey;
      readonly leafAmount: number;
      readonly receiver?: Uint8Array;
      readonly outputScripts?: ReadonlyArray<Uint8Array>;
      readonly connectorTxid?: Uint8Array;
      readonly sameScriptInputs?: number;
      readonly target?: SigningTarget;
      readonly exit?: { readonly connectorTx: Uint8Array; readonly exitTx: Uint8Array };
    }>,
  ): Promise<ReadonlyArray<Uint8Array>> {
    const commitments = await signer.newCommitments(specs.length);
    const { operators, verifyingKey } = frostGroup(
      0x5ea5n,
      [11111n, 44444n],
      [
        [22222n, 33333n],
        [55555n, 66666n],
      ],
    );
    const fixtures = operatorSetup(operators);
    return signer.signFrost(
      specs.map((spec, i) => ({
        key: spec.key,
        target:
          spec.target ??
          refundTarget({
            leafAmount: spec.leafAmount,
            outputScripts: spec.outputScripts ?? [
              p2trScriptFromPublicKey(spec.receiver ?? Point.BASE.toBytes(true), "regtest"),
            ],
            ...(spec.connectorTxid === undefined ? {} : { connectorTxid: spec.connectorTxid }),
            ...(spec.sameScriptInputs === undefined
              ? {}
              : { sameScriptInputs: spec.sameScriptInputs }),
          }),
        verifyingKey,
        commitment: commitments[i]!,
        operatorCommitments: fixtures.map((f) => ({
          identifier: f.identifier,
          commitment: f.commitment,
        })),
        ...(spec.exit === undefined ? {} : { exit: spec.exit }),
      })),
    );
  }

  /** A fabricated connector/exit pair: exitTx pays a destination; connectorTx input 0 spends it. */
  function exitPair(payoutScript?: Uint8Array): {
    connectorTx: Uint8Array;
    exitTx: Uint8Array;
    connectorTxid: Uint8Array;
  } {
    const exitTx = new Transaction({ allowUnknownOutputs: true });
    exitTx.addInput({ txid: new Uint8Array(32).fill(0xaa), index: 0 });
    exitTx.addOutput({
      script:
        payoutScript ?? p2trScriptFromPublicKey(Point.BASE.multiply(3n).toBytes(true), "regtest"),
      amount: 15_000n,
    });
    const exitTxBytes = exitTx.toBytes();
    const connectorTx = new Transaction({ allowUnknownOutputs: true });
    connectorTx.addInput({ txid: txIdInputBytes(exitTxBytes), index: 0 });
    connectorTx.addOutput({
      script: p2trScriptFromPublicKey(Point.BASE.multiply(2n).toBytes(true), "regtest"),
      amount: 330n,
    });
    connectorTx.addOutput({ script: EPHEMERAL_ANCHOR_SCRIPT, amount: 0n });
    const connectorTxBytes = connectorTx.toBytes();
    return {
      connectorTx: connectorTxBytes,
      exitTx: exitTxBytes,
      connectorTxid: txIdInputBytes(connectorTxBytes),
    };
  }

  function packageBytes(operatorPackages: Record<string, Uint8Array>): Uint8Array {
    return toBinary(
      TransferPackageSchema,
      create(TransferPackageSchema, {
        keyTweakPackage: operatorPackages,
        hashVariant: HashVariant.V2,
      }),
    );
  }

  const LEAF_A = "01905f9b-5b77-7c00-9f60-1c2a2e0a1b2a";
  const LEAF_B = "01905f9b-5b77-7c00-9f60-1c2a2e0a1b2b";

  test("transfer: single and multi-receiver totals", async () => {
    const outflows: SparkOutflow[] = [];
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      authorize: async (o) => {
        await Promise.resolve(outflows.push(o));
      },
    });
    const receiverA = Point.BASE.multiply(0xa11ce11ce11cen).toBytes(true);
    const receiverB = Point.BASE.multiply(0xb22ce22ce22cen).toBytes(true);
    const transferId = "550e8400-e29b-41d4-a716-446655440001";
    const prepared = await signer.prepareTransfer({
      transferId,
      leaves: [
        {
          leafId: LEAF_A,
          key: { type: "leaf", leafId: LEAF_A },
          receiverIdentityPublicKey: receiverA,
        },
        {
          leafId: LEAF_B,
          key: { type: "leaf", leafId: LEAF_B },
          receiverIdentityPublicKey: receiverB,
        },
      ],
    });
    await signRefund(
      signer,
      { type: "leaf", leafId: LEAF_A },
      { leafAmount: 1000, receiver: receiverA },
    );
    await signRefund(
      signer,
      { type: "leaf", leafId: LEAF_B },
      { leafAmount: 2000, receiver: receiverB },
    );
    const signature = await signer.signIdentity({
      kind: "transfer-package",
      transferId,
      package: packageBytes(prepared.operatorPackages),
    });
    expect(signature[0]).toBe(0x30);
    expect(outflows).toHaveLength(1);
    const outflow = outflowAs(outflows[0]!, "transfer");
    expect(outflow.totalSats).toBe(3000);
    expect(outflow.receivers).toHaveLength(2);
    expect(outflow.receivers[0]).toStrictEqual({
      identityPublicKey: receiverA,
      amountSats: 1000,
    });
    expect(outflow.receivers[1]).toStrictEqual({
      identityPublicKey: receiverB,
      amountSats: 2000,
    });
    signer.dispose();
  });

  test("lightning: reports the HTLC script lightningSendHtlcScript reproduces", async () => {
    const ssp = Point.BASE.multiply(0x555777n).toBytes(true);
    const outflows: SparkOutflow[] = [];
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      sspIdentityPublicKey: ssp,
      authorize: async (o) => {
        await Promise.resolve(outflows.push(o));
      },
    });
    const identity = await signer.identityPublicKey();
    const paymentHash = new Uint8Array(32).fill(9);
    const htlcScript = lightningSendHtlcScript({
      paymentHash,
      sspIdentityPublicKey: ssp,
      identityPublicKey: identity,
    });
    const transferId = "550e8400-e29b-41d4-a716-446655440002";
    const prepared = await signer.prepareTransfer({
      transferId,
      leaves: [
        { leafId: LEAF_A, key: { type: "leaf", leafId: LEAF_A }, receiverIdentityPublicKey: ssp },
      ],
    });
    await signRefund(
      signer,
      { type: "leaf", leafId: LEAF_A },
      { leafAmount: 42_000, outputScripts: [htlcScript] },
    );
    const outflow = outflowAs(outflows[0]!, "lightning");
    expect(outflow.totalSats).toBe(42_000);
    expect(bytesToHex(outflow.htlcOutputScript)).toBe(bytesToHex(htlcScript));
    expect(outflow.leaves).toHaveLength(1);
    expect(outflow.leaves[0]!.amountSats).toBe(42_000);
    // The HTLC shares were authorized at signFrost: signing the package charges nothing again.
    await signer.signIdentity({
      kind: "transfer-package",
      transferId,
      package: packageBytes(prepared.operatorPackages),
    });
    expect(outflows).toHaveLength(1);
    signer.dispose();
  });

  test("exit: two-input connector refund reports the connector txid", async () => {
    const ssp = Point.BASE.multiply(0x555777n).toBytes(true);
    const outflows: SparkOutflow[] = [];
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      sspIdentityPublicKey: ssp,
      authorize: async (o) => {
        await Promise.resolve(outflows.push(o));
      },
    });
    const transferId = "550e8400-e29b-41d4-a716-446655440003";
    const prepared = await signer.prepareTransfer({
      transferId,
      leaves: [
        { leafId: LEAF_A, key: { type: "leaf", leafId: LEAF_A }, receiverIdentityPublicKey: ssp },
      ],
    });
    const pair = exitPair();
    await signRefund(
      signer,
      { type: "leaf", leafId: LEAF_A },
      { leafAmount: 7000, outputScripts: [], connectorTxid: pair.connectorTxid, exit: pair },
    );
    const outflow = outflowAs(outflows[0]!, "exit");
    expect(outflow.totalSats).toBe(7000);
    expect(bytesToHex(outflow.connectorTxid)).toBe(bytesToHex(pair.connectorTxid));
    expect(outflow.exitOutputs).toHaveLength(1);
    expect(outflow.exitOutputs[0]!.amountSats).toBe(15_000);
    await signer.signIdentity({
      kind: "transfer-package",
      transferId,
      package: packageBytes(prepared.operatorPackages),
    });
    expect(outflows).toHaveLength(1);
    signer.dispose();
  });

  test("swap: leaves returning to the bound SSP identity classify as swap", async () => {
    const outflows: SparkOutflow[] = [];
    const ssp = Point.BASE.multiply(0x555777n).toBytes(true);
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      sspIdentityPublicKey: ssp,
      authorize: async (o) => {
        await Promise.resolve(outflows.push(o));
      },
    });
    const transferId = "550e8400-e29b-41d4-a716-446655440004";
    const prepared = await signer.prepareTransfer({
      transferId,
      leaves: [
        { leafId: LEAF_A, key: { type: "leaf", leafId: LEAF_A }, receiverIdentityPublicKey: ssp },
      ],
    });
    await signRefund(signer, { type: "leaf", leafId: LEAF_A }, { leafAmount: 5000, receiver: ssp });
    await signer.signIdentity({
      kind: "transfer-package",
      transferId,
      package: packageBytes(prepared.operatorPackages),
    });
    expect(outflowAs(outflows[0]!, "swap").totalSats).toBe(5000);
    signer.dispose();
  });

  test("forged small refund then honest refund: the maximum prevout wins", async () => {
    const outflows: SparkOutflow[] = [];
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      authorize: async (o) => {
        await Promise.resolve(outflows.push(o));
      },
    });
    const receiver = Point.BASE.multiply(0xa11ce11ce11cen).toBytes(true);
    const transferId = "550e8400-e29b-41d4-a716-446655440005";
    const prepared = await signer.prepareTransfer({
      transferId,
      leaves: [
        {
          leafId: LEAF_A,
          key: { type: "leaf", leafId: LEAF_A },
          receiverIdentityPublicKey: receiver,
        },
      ],
    });
    await signRefund(signer, { type: "leaf", leafId: LEAF_A }, { leafAmount: 100, receiver });
    await signRefund(signer, { type: "leaf", leafId: LEAF_A }, { leafAmount: 9000, receiver });
    await signer.signIdentity({
      kind: "transfer-package",
      transferId,
      package: packageBytes(prepared.operatorPackages),
    });
    expect(outflowAs(outflows[0]!, "transfer").totalSats).toBe(9000);
    signer.dispose();
  });

  test("fails closed: no recorded signFrost, mismatched or forged packages, mixed shapes", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const receiver = Point.BASE.multiply(0xa11ce11ce11cen).toBytes(true);
    const receiverB = Point.BASE.multiply(0xb22ce22ce22cen).toBytes(true);
    const transferId = "550e8400-e29b-41d4-a716-446655440006";

    // No signFrost record for the leaf's key → reject before any signature.
    const prepared = await signer.prepareTransfer({
      transferId,
      leaves: [
        {
          leafId: LEAF_A,
          key: { type: "leaf", leafId: LEAF_A },
          receiverIdentityPublicKey: receiver,
        },
      ],
    });
    await expect(
      signer.signIdentity({
        kind: "transfer-package",
        transferId,
        package: packageBytes(prepared.operatorPackages),
      }),
    ).rejects.toThrow(SparkInputError);

    // With the refund recorded, tampered packages still reject: flipped byte and missing key.
    await signRefund(signer, { type: "leaf", leafId: LEAF_A }, { leafAmount: 1000, receiver });
    const flipped = { ...prepared.operatorPackages };
    const first = Object.keys(flipped)[0]!;
    flipped[first] = Uint8Array.from(flipped[first]!, (v) => v ^ 0xff);
    await expect(
      signer.signIdentity({
        kind: "transfer-package",
        transferId,
        package: packageBytes(flipped),
      }),
    ).rejects.toThrow(SparkInputError);
    const { [first]: _dropped, ...missing } = prepared.operatorPackages;
    await expect(
      signer.signIdentity({
        kind: "transfer-package",
        transferId,
        package: packageBytes(missing),
      }),
    ).rejects.toThrow(SparkInputError);

    // Mixed shapes across leaves: one connector refund, one plain → reject.
    const mixedId = "550e8400-e29b-41d4-a716-446655440007";
    await signer.prepareTransfer({
      transferId: mixedId,
      leaves: [
        {
          leafId: LEAF_A,
          key: { type: "leaf", leafId: LEAF_A },
          receiverIdentityPublicKey: receiver,
        },
        {
          leafId: LEAF_B,
          key: { type: "leaf", leafId: LEAF_B },
          receiverIdentityPublicKey: receiverB,
        },
      ],
    });
    const htlcScript = lightningSendHtlcScript({
      paymentHash: new Uint8Array(32).fill(9),
      sspIdentityPublicKey: receiverB,
      identityPublicKey: await signer.identityPublicKey(),
    });
    await expect(
      signRefundBatch(signer, [
        {
          key: { type: "leaf", leafId: LEAF_A },
          leafAmount: 1000,
          outputScripts: [],
          connectorTxid: new Uint8Array(32).fill(7),
        },
        { key: { type: "leaf", leafId: LEAF_B }, leafAmount: 2000, outputScripts: [htlcScript] },
      ]),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  });

  test("fails closed: two different HTLC refund scripts reject", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex);
    const ssp = Point.BASE.multiply(0x555777n).toBytes(true);
    const identity = await signer.identityPublicKey();
    const scriptA = lightningSendHtlcScript({
      paymentHash: new Uint8Array(32).fill(1),
      sspIdentityPublicKey: ssp,
      identityPublicKey: identity,
    });
    const scriptB = lightningSendHtlcScript({
      paymentHash: new Uint8Array(32).fill(2),
      sspIdentityPublicKey: ssp,
      identityPublicKey: identity,
    });
    const transferId = "550e8400-e29b-41d4-a716-446655440008";
    await signer.prepareTransfer({
      transferId,
      leaves: [
        { leafId: LEAF_A, key: { type: "leaf", leafId: LEAF_A }, receiverIdentityPublicKey: ssp },
        { leafId: LEAF_B, key: { type: "leaf", leafId: LEAF_B }, receiverIdentityPublicKey: ssp },
      ],
    });
    await expect(
      signRefundBatch(signer, [
        { key: { type: "leaf", leafId: LEAF_A }, leafAmount: 1000, outputScripts: [scriptA] },
        { key: { type: "leaf", leafId: LEAF_B }, leafAmount: 2000, outputScripts: [scriptB] },
      ]),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  });

  test("HTLC batch reaches authorize; a throwing authorize signs nothing and retry works", async () => {
    let calls = 0;
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      authorize: async (o) => {
        calls += 1;
        // oxlint-disable-next-line vitest/no-conditional-in-test -- the deny-then-allow retry path
        if (calls === 1) {
          throw new Error("denied");
        }
        await Promise.resolve(o);
      },
    });
    const identity = await signer.identityPublicKey();
    const ssp = Point.BASE.multiply(0x555777n).toBytes(true);
    const htlcScript = lightningSendHtlcScript({
      paymentHash: new Uint8Array(32).fill(9),
      sspIdentityPublicKey: ssp,
      identityPublicKey: identity,
    });
    await signer.prepareTransfer({
      transferId: "550e8400-e29b-41d4-a716-44665544000a",
      leaves: [
        { leafId: LEAF_A, key: { type: "leaf", leafId: LEAF_A }, receiverIdentityPublicKey: ssp },
      ],
    });
    // authorize throws BEFORE frostSignJobs — no shares, commitments unconsumed, retry works.
    await expect(
      signRefundBatch(signer, [
        { key: { type: "leaf", leafId: LEAF_A }, leafAmount: 5000, outputScripts: [htlcScript] },
      ]),
    ).rejects.toThrow("denied");
    const shares = await signRefundBatch(signer, [
      { key: { type: "leaf", leafId: LEAF_A }, leafAmount: 5000, outputScripts: [htlcScript] },
    ]);
    expect(shares).toHaveLength(1);
    expect(calls).toBe(2);
    signer.dispose();
  });

  test("a non-anchor output to p2tr(random key) on a leaf destined elsewhere reports lightning", async () => {
    const outflows: SparkOutflow[] = [];
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      authorize: async (o) => {
        await Promise.resolve(outflows.push(o));
      },
    });
    const receiver = Point.BASE.multiply(0xa11ce11ce11cen).toBytes(true);
    await signer.prepareTransfer({
      transferId: "550e8400-e29b-41d4-a716-44665544000b",
      leaves: [
        {
          leafId: LEAF_A,
          key: { type: "leaf", leafId: LEAF_A },
          receiverIdentityPublicKey: receiver,
        },
      ],
    });
    // The output pays a stranger's key — the whitelist rejects it; policy (authorize) decides.
    await signRefundBatch(signer, [
      {
        key: { type: "leaf", leafId: LEAF_A },
        leafAmount: 3000,
        outputScripts: [p2trScriptFromPublicKey(Point.BASE.multiply(99n).toBytes(true), "regtest")],
      },
    ]);
    const outflow = outflowAs(outflows[0]!, "lightning");
    expect(outflow.totalSats).toBe(3000);
    signer.dispose();
  });

  test("fails closed: exit jobs must bind a connector/exit pair", async () => {
    const ssp = Point.BASE.multiply(0x555777n).toBytes(true);
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      sspIdentityPublicKey: ssp,
    });
    const pair = exitPair();
    // Missing pair on a connector-shaped job.
    await expect(
      signRefundBatch(signer, [
        {
          key: { type: "leaf", leafId: LEAF_A },
          leafAmount: 1000,
          outputScripts: [],
          connectorTxid: pair.connectorTxid,
        },
      ]),
    ).rejects.toThrow(SparkInputError);
    // A pair on a plain single-input job.
    await expect(
      signRefundBatch(signer, [
        {
          key: { type: "leaf", leafId: LEAF_A },
          leafAmount: 1000,
          receiver: ssp,
          exit: pair,
        },
      ]),
    ).rejects.toThrow(SparkInputError);
    // connectorTx whose txid is not the foreign input's.
    const otherPair = exitPair();
    otherPair.connectorTxid.set(Uint8Array.of(0xff), 0);
    await expect(
      signRefundBatch(signer, [
        {
          key: { type: "leaf", leafId: LEAF_A },
          leafAmount: 1000,
          outputScripts: [],
          connectorTxid: new Uint8Array(32).fill(0xee),
          exit: { connectorTx: pair.connectorTx, exitTx: pair.exitTx },
        },
      ]),
    ).rejects.toThrow(SparkInputError);
    // connectorTx that does not spend the claimed exitTx.
    const strayExitTx = new Transaction({ allowUnknownOutputs: true });
    strayExitTx.addInput({ txid: new Uint8Array(32).fill(0xbb), index: 0 });
    strayExitTx.addOutput({
      script: p2trScriptFromPublicKey(Point.BASE.multiply(3n).toBytes(true), "regtest"),
      amount: 9000n,
    });
    await expect(
      signRefundBatch(signer, [
        {
          key: { type: "leaf", leafId: LEAF_A },
          leafAmount: 1000,
          outputScripts: [],
          connectorTxid: pair.connectorTxid,
          exit: { connectorTx: pair.connectorTx, exitTx: strayExitTx.toBytes() },
        },
      ]),
    ).rejects.toThrow(SparkInputError);
    // Two different pairs in one batch.
    await expect(
      signRefundBatch(signer, [
        {
          key: { type: "leaf", leafId: LEAF_A },
          leafAmount: 1000,
          outputScripts: [],
          connectorTxid: pair.connectorTxid,
          exit: pair,
        },
        {
          key: { type: "leaf", leafId: LEAF_B },
          leafAmount: 2000,
          outputScripts: [],
          connectorTxid: pair.connectorTxid,
          exit: { connectorTx: pair.connectorTx, exitTx: strayExitTx.toBytes() },
        },
      ]),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  });

  test("fails closed: SSP and non-SSP receivers in one transfer reject", async () => {
    const ssp = Point.BASE.multiply(0x555777n).toBytes(true);
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      sspIdentityPublicKey: ssp,
    });
    const receiver = Point.BASE.multiply(0xa11ce11ce11cen).toBytes(true);
    const transferId = "550e8400-e29b-41d4-a716-44665544000c";
    const prepared = await signer.prepareTransfer({
      transferId,
      leaves: [
        { leafId: LEAF_A, key: { type: "leaf", leafId: LEAF_A }, receiverIdentityPublicKey: ssp },
        {
          leafId: LEAF_B,
          key: { type: "leaf", leafId: LEAF_B },
          receiverIdentityPublicKey: receiver,
        },
      ],
    });
    await signRefund(signer, { type: "leaf", leafId: LEAF_A }, { leafAmount: 1000, receiver: ssp });
    await signRefund(signer, { type: "leaf", leafId: LEAF_B }, { leafAmount: 2000, receiver });
    await expect(
      signer.signIdentity({
        kind: "transfer-package",
        transferId,
        package: packageBytes(prepared.operatorPackages),
      }),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  });

  test("a received-key job paying P2TR(that key) is not whitelisted — it is a lightning candidate", async () => {
    const outflows: SparkOutflow[] = [];
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      authorize: async (o) => {
        await Promise.resolve(outflows.push(o));
      },
    });
    const crypto = await backend();
    const secret = 0x77aa55n;
    const ciphertext = crypto.eciesEncrypt(
      await signer.identityPublicKey(),
      be32(secret),
      new Uint8Array(32).fill(1),
    );
    const receivedPublicKey = Point.BASE.multiply(secret).toBytes(true);
    await signRefundBatch(signer, [
      {
        key: { type: "received", ciphertext },
        leafAmount: 4000,
        outputScripts: [p2trScriptFromPublicKey(receivedPublicKey, "regtest")],
      },
    ]);
    const outflow = outflowAs(outflows[0]!, "lightning");
    expect(outflow.leaves).toHaveLength(1);
    expect(outflow.totalSats).toBe(4000);
    signer.dispose();
  });

  test("multi-UTXO root: same-script inputs paying the leaf key sign without authorize", async () => {
    let authorized = 0;
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      authorize: async (o) => {
        authorized += 1;
        await Promise.resolve(o);
      },
    });
    const leafPublicKey = await signer.publicKeys([{ type: "leaf", leafId: LEAF_A }]);
    const shares = await signRefundBatch(signer, [
      {
        key: { type: "leaf", leafId: LEAF_A },
        leafAmount: 5000,
        sameScriptInputs: 2,
        outputScripts: [p2trScriptFromPublicKey(leafPublicKey[0]!, "regtest")],
      },
    ]);
    expect(shares).toHaveLength(1);
    expect(authorized).toBe(0);
    signer.dispose();
  });

  test("fails closed: multi-input same-script tx with a foreign output rejects", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1);
    await expect(
      signRefundBatch(signer, [
        {
          key: { type: "leaf", leafId: LEAF_A },
          leafAmount: 5000,
          sameScriptInputs: 1,
          outputScripts: [
            p2trScriptFromPublicKey(Point.BASE.multiply(99n).toBytes(true), "regtest"),
          ],
        },
      ]),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  });

  test("a throwing authorize stops the signature; the record survives for retry", async () => {
    let gate = false;
    const outflows: SparkOutflow[] = [];
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      authorize: async (o) => {
        await Promise.resolve(outflows.push(o));
        // oxlint-disable-next-line vitest/no-conditional-in-test -- the deny-then-allow retry path
        if (!gate) {
          throw new Error("denied");
        }
      },
    });
    const receiver = Point.BASE.multiply(0xa11ce11ce11cen).toBytes(true);
    const transferId = "550e8400-e29b-41d4-a716-446655440009";
    const prepared = await signer.prepareTransfer({
      transferId,
      leaves: [
        {
          leafId: LEAF_A,
          key: { type: "leaf", leafId: LEAF_A },
          receiverIdentityPublicKey: receiver,
        },
      ],
    });
    await signRefund(signer, { type: "leaf", leafId: LEAF_A }, { leafAmount: 1000, receiver });
    await expect(
      signer.signIdentity({
        kind: "transfer-package",
        transferId,
        package: packageBytes(prepared.operatorPackages),
      }),
    ).rejects.toThrow("denied");
    // Retry with the gate open: the same recorded preparation signs.
    gate = true;
    const signature = await signer.signIdentity({
      kind: "transfer-package",
      transferId,
      package: packageBytes(prepared.operatorPackages),
    });
    expect(signature[0]).toBe(0x30);
    expect(outflows).toHaveLength(2);
    signer.dispose();
  });

  test("transfer record eviction: the oldest of >256 prepared transfers rejects", async () => {
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      operators: [testOperator(0, 0x0b0b0bn), testOperator(1, 0x0c0c0cn)],
      threshold: 2,
    });
    const receiver = Point.BASE.multiply(0xa11ce11ce11cen).toBytes(true);
    const firstId = "550e8400-e29b-41d4-a716-446655440010";
    for (let i = 0; i < 257; i++) {
      // oxlint-disable-next-line eslint/no-await-in-loop -- sequential fills the LRU in order
      await signer.prepareTransfer({
        // oxlint-disable-next-line vitest/no-conditional-in-test -- bounded loop fills the LRU
        transferId: i === 0 ? firstId : `550e8400-e29b-41d4-a716-${String(i).padStart(12, "0")}`,
        leaves: [
          {
            leafId: LEAF_A,
            key: { type: "leaf", leafId: LEAF_A },
            receiverIdentityPublicKey: receiver,
          },
        ],
      });
    }
    await expect(
      signer.signIdentity({
        kind: "transfer-package",
        transferId: firstId,
        package: packageBytes({ [testOperator(0, 0x0b0b0bn).identifier]: new Uint8Array(1) }),
      }),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  }, 60_000);

  test("onchain and token outflows decode from the signed payload", async () => {
    const outflows: SparkOutflow[] = [];
    const signer = await signerFor(derivation.cases[0]!.seed_hex, 0, 1, {
      authorize: async (o) => {
        await Promise.resolve(outflows.push(o));
      },
    });
    const identity = await signer.identityPublicKey();

    await signer.signKeySpend({ type: "static-deposit", index: 0 }, TARGET);
    const onchain = outflowAs(outflows[0]!, "onchain");
    expect(onchain.source).toBe("key-spend");
    {
      const tx = Transaction.fromRaw(TARGET.transaction, { allowUnknownOutputs: true });
      let expected = 0;
      for (let i = 0; i < tx.outputsLength; i++) {
        // oxlint-disable-next-line vitest/no-conditional-in-test -- sum every output's amount
        expected += Number(tx.getOutput(i).amount ?? 0n);
      }
      expect(onchain.totalSats).toBe(expected);
      expect(onchain.outputs).toHaveLength(tx.outputsLength);
    }

    const hugeAmount = 2n ** 53n + 12345n;
    const amountBytes = new Uint8Array(16);
    new DataView(amountBytes.buffer).setBigUint64(8, hugeAmount, false);
    const partial = create(PartialTokenTransactionSchema, {
      version: 3,
      tokenInputs: {
        case: "transferInput",
        value: {
          outputsToSpend: [
            {
              prevTokenTransactionHash: new Uint8Array(32).fill(0xab),
              prevTokenTransactionVout: 0,
            },
          ],
        },
      },
      partialTokenOutputs: [
        {
          ownerPublicKey: identity,
          tokenIdentifier: new Uint8Array(32).fill(0xcd),
          tokenAmount: amountBytes,
          withdrawBondSats: 0n,
          withdrawRelativeBlockLocktime: 0n,
        },
      ],
    });
    await signer.signIdentity({
      kind: "token-transaction",
      partialTransaction: toBinary(PartialTokenTransactionSchema, partial),
    });
    const token = outflowAs(outflows[1]!, "token");
    expect(token.outputs).toHaveLength(1);
    expect(token.outputs[0]!.amount).toBe(hugeAmount);
    expect(token.outputs[0]!.tokenIdentifier).toStrictEqual(new Uint8Array(32).fill(0xcd));
    signer.dispose();
  });
});
