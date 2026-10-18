/**
 * Hermes smoke test: loads the packed `.`, `./crypto` and `./signer` builds. `smoke:hermes` packs
 * first; these dist files are the contract React Native bundles.
 */
import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { taprootTweakPubkey } from "@scure/btc-signer/utils.js";

import * as crypto from "../../dist/crypto.mjs";
import type { SparkCrypto } from "../../dist/crypto.mjs";
import * as root from "../../dist/index.mjs";
import * as signer from "../../dist/signer.mjs";

declare function print(msg: string): void;

/** Returns a fixed byte pattern — the smoke never reaches the backend. */
const fakeCrypto: SparkCrypto = {
  abiVersion: crypto.SPARK_ABI_VERSION,
  frostCommit: () => new Uint8Array(130).fill(0xaa),
  frostSign: () => new Uint8Array(32).fill(0xbb),
  frostAggregate: () => new Uint8Array(64).fill(0xcc),
  eciesEncrypt: () => new Uint8Array(97).fill(0xdd),
  eciesDecrypt: () => new Uint8Array(32).fill(0xee),
  splitSecretWithProofs: () => new Uint8Array(98).fill(0xff),
};

/**
 * First case of `vectors/derivation.json` (upstream `DefaultSparkSigner`, the standard BIP-39
 * mnemonic) — duplicated here because the bundled smoke cannot read vector files.
 */
const DERIVATION = {
  seed: "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
  identity: "02698b27ac308b275671b3ca25436346469d04a5bba578ae39feba1d65897a6abc",
  deposit: "02f4f6db6cf8f0ab8c9c95659b78448d09ebf490c4251349c6ebef7caf9ad6e10a",
  static0: "029f061ac1595c7b9386624866131a25af763233f8de42e2c5e623687cd67cc1b1",
  leafId: "01905f9b-5b77-7c00-9f60-1c2a2e0a1b2c",
  leaf: "0247a58a9af49c825fe343f3d270aad5d77ac567a12b9bff4044e23db9d3369e31",
};

/**
 * First case of `vectors/lnurl-auth.json` (LUD-05 derivation replayed from the Breez SDK by
 * `crates/interop/tests/lnurl_auth.rs`).
 */
const LNURL_AUTH = {
  rootKey:
    "073c09c9d514a456addfb05479736383270d120ae88f20bd841f48e0457cec8c1605e57d7613bb1d44d1bd18b1d44b5f60f21eae739f57eedda920623bc98d85",
  domain: "site.com",
  k1: "e2af6254a8df433264fa23f67eb8188635d15ce883e8fc020989d5f82ae6f11e",
  linkingKey: "027da5d64331f61260eb8e2b356403446555f525bc7dc35b991ec1447e4f58991f",
  signature:
    "3045022100fea478533fe923d9cc48633de6473e244b0c54d8de69fb77616b9ade3a5dbccd022074975d5d7f8356330b97b3b1aa99babd426075eb37d92f70a2e19e83fcce6103",
};

/** First case of `vectors/transactions.json` `multiInputSighash`. */
const TARGET = {
  transaction: hexToBytes(
    "03000000029223c8aa843cc1c7063523e5f23b23fcfdfca24eb9faedde300a85498a923c690000000000000000009223c8aa843cc1c7063523e5f23b23fcfdfca24eb9faedde300a85498a923c69010000000000000000025892010000000000225120340c02f493522d92c3bb4a8a1229752819db231d511d7b434b30133c37ddfbd500000000000000000451024e7300000000",
  ),
  inputIndex: 0,
  prevouts: [
    {
      script: hexToBytes("5120340c02f493522d92c3bb4a8a1229752819db231d511d7b434b30133c37ddfbd5"),
      amount: 100_000,
    },
    {
      script: hexToBytes("51209bc2f8be809cb9252abecdcc3622b90dbcffc80baf1168df8b4bceb831110f69"),
      amount: 3000,
    },
  ],
  sighash: hexToBytes("55ded8c7e2ee2dfa8905116385281d5c14ac62216651191ddc2c35238c1a46e6"),
};

function assert(cond: boolean, name: string): asserts cond {
  if (!cond) {
    throw new Error(`smoke: ${name}`);
  }
}

export async function main(): Promise<void> {
  assert(crypto.SPARK_ABI_VERSION === 1, "SPARK_ABI_VERSION");

  const error = new crypto.SparkCryptoError(7);
  assert(error instanceof root.SparkError, "SparkCryptoError extends SparkError");
  assert(error instanceof root.SparkCryptoError, "SparkCryptoError instance");
  assert(error.name === "SparkCryptoError", "SparkCryptoError name");
  assert(error.code === 7, "SparkCryptoError code");
  assert(
    error.message === "spark crypto backend failed (code 7)",
    "SparkCryptoError message carries no inputs",
  );

  const invoice = root.decodeBolt11(
    "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql",
  );
  assert(invoice.network === "mainnet", "bolt11 network");
  assert(invoice.timestamp === 1496314658, "bolt11 timestamp");
  assert(
    bytesToHex(invoice.paymentHash) ===
      "0001020304050607080900010203040506070809000102030405060708090102",
    "bolt11 paymentHash",
  );
  assert(
    bytesToHex(invoice.payee) ===
      "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad",
    "bolt11 payee",
  );

  const address = root.decodeSparkAddress(
    "sparkrt1pgssx5us3wkqjza8g80xz3a9gznx25msq6g3ty8exfym9q3ahcv86vsnxxdy83",
  );
  assert(address.network === "regtest", "address network");
  assert(
    bytesToHex(address.identityPublicKey) ===
      "0353908bac090ba741de6147a540a665537006911590f93249b2823dbe187d3213",
    "address identityPublicKey",
  );

  const operators = root.sparkNetworkConfig("regtest").operators;
  assert(operators.length === 3, "regtest operator count");
  assert(
    bytesToHex(operators[0]!.identityPublicKey) ===
      bytesToHex(hexToBytes("03dfbdff4b6332c220f8fa2ba8ed496c698ceada563fa01b67d9983bfc5c95e763")),
    "regtest operator 0 key",
  );

  const sparkSigner = signer.createSparkSigner({
    crypto: fakeCrypto,
    accountKey: signer.sparkAccountKey(hexToBytes(DERIVATION.seed), "regtest", 0),
    network: "regtest",
    random: (length) => new Uint8Array(length).fill(0xab),
  });
  const [identity, deposit, static0, leaf] = await Promise.all([
    sparkSigner.identityPublicKey(),
    sparkSigner.publicKeys([{ type: "deposit" }]),
    sparkSigner.publicKeys([{ type: "static-deposit", index: 0 }]),
    sparkSigner.publicKeys([{ type: "leaf", leafId: DERIVATION.leafId }]),
  ]);
  assert(bytesToHex(identity) === DERIVATION.identity, "identity pubkey matches upstream vector");
  assert(bytesToHex(deposit[0]!) === DERIVATION.deposit, "deposit pubkey matches upstream vector");
  assert(bytesToHex(static0[0]!) === DERIVATION.static0, "static-deposit pubkey matches vector");
  assert(bytesToHex(leaf[0]!) === DERIVATION.leaf, "leaf pubkey matches upstream vector");

  // signKeySpend covers the BIP-341 tweak + BIP-340 path end to end: verifying the signature
  // against the vector sighash and the tweaked deposit key checks the digest function too.
  const signature = await sparkSigner.signKeySpend({ type: "deposit" }, TARGET);
  assert(signature.length === 64, "key-spend signature is 64 bytes");
  const [tweakedX] = taprootTweakPubkey(hexToBytes(DERIVATION.deposit).slice(1), new Uint8Array());
  assert(schnorr.verify(signature, TARGET.sighash, tweakedX), "key-spend signature verifies");

  // Hot loops — printed so host runs can compare CPU timings across Hermes builds.
  let started = Date.now();
  const leafKeys = Array.from({ length: 100 }, (_, i) => ({
    type: "leaf" as const,
    leafId: `smoke-leaf-${i}`,
  }));
  const leafPubs = await sparkSigner.publicKeys(leafKeys);
  assert(leafPubs.length === 100, "100 leaf keys derived");
  print(`hermes timing: 100 leaf derivations ${Date.now() - started}ms`);
  started = Date.now();
  for (let i = 0; i < 10; i++) {
    const sig = await sparkSigner.signKeySpend({ type: "deposit" }, TARGET);
    assert(sig.length === 64, "sighash loop signature");
  }
  print(`hermes timing: 10 key-spend sighashes ${Date.now() - started}ms`);
  sparkSigner.dispose();

  // LUD-05: the linking-key derivation and the RFC-6979 DER signature are byte-exact against the
  // interop vector, covering HDKey + hmac + secp256k1 under Hermes.
  const authRoot = signer.lnurlAuthRootKey(hexToBytes(DERIVATION.seed));
  assert(bytesToHex(authRoot) === LNURL_AUTH.rootKey, "lnurl-auth root key matches vector");
  const authSigner = signer.createLnurlAuthSigner({ rootKey: authRoot });
  assert(
    bytesToHex(await authSigner.linkingKey(LNURL_AUTH.domain)) === LNURL_AUTH.linkingKey,
    "lnurl-auth linking key matches vector",
  );
  const { signature: authSig } = await authSigner.sign({
    domain: LNURL_AUTH.domain,
    k1: hexToBytes(LNURL_AUTH.k1),
  });
  assert(bytesToHex(authSig) === LNURL_AUTH.signature, "lnurl-auth signature matches vector");
  authSigner.dispose();
  authRoot.fill(0);
}
