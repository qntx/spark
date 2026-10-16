/**
 * Hermes smoke test: loads the packed `.`, `./crypto` and `./signer` builds. `smoke:hermes` packs
 * first; these dist files are the contract React Native bundles.
 */
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import * as crypto from "../../dist/crypto.mjs";
import * as root from "../../dist/index.mjs";
import "../../dist/signer.mjs";

function assert(cond: boolean, name: string): asserts cond {
  if (!cond) {
    throw new Error(`smoke: ${name}`);
  }
}

export function main(): void {
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
}
