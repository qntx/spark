import { expect, test } from "vite-plus/test";

import * as crypto from "../src/crypto/index.ts";
import * as root from "../src/index.ts";
import * as signer from "../src/signer/index.ts";

// Type-only exports cannot be enumerated at runtime; re-exporting each expected
// name makes a missing or renamed type export a compile error.
export type {
  SparkNetwork,
  SparkNetworkConfig,
  SparkOperatorConfig,
  SparkAddress,
  SparkInvoiceFields,
  SparkPayment,
  Bolt11Invoice,
  Bolt11Network,
} from "../src/index.ts";
export type { SparkCrypto } from "../src/crypto/index.ts";
export type {
  FrostAggregateJob,
  FrostSignJob,
  IdentityStatement,
  OperatorCommitment,
  PrepareClaimRequest,
  PreparedClaim,
  PreparedLightningReceive,
  PreparedTransfer,
  PreparedTransferLeaf,
  PrepareTransferRequest,
  SigningCommitment,
  SigningTarget,
  SparkKey,
  SparkLeafKey,
  SparkNetwork as SignerNetwork,
  SparkOperator,
  SparkSigner,
  StaticDepositClaimRequest,
} from "../src/signer/index.ts";
export type {
  ExitTransaction,
  FundingInput,
  ParsedSparkInvoice,
  SparkExitChain,
  SparkStore,
  SparkClient,
  SparkClientOptions,
  SparkEvent,
  SparkLeaf,
  SparkTokenIdentifierData,
  SparkTransfer,
  SparkTransferLeaf,
  SparkTokenBalance,
  SparkTokenOutput,
  SparkTokenOutputStatus,
  SparkInvoiceStatus,
} from "../src/index.ts";

function names(mod: object): string[] {
  return Object.keys(mod).toSorted();
}

test("root runtime exports are exactly the core surface", () => {
  expect(names(root)).toStrictEqual([
    "SparkCryptoError",
    "SparkError",
    "SparkInputError",
    "SparkRequestError",
    "buildCpfpChild",
    "createMemorySparkStore",
    "createSatsInvoice",
    "createSparkClient",
    "createTokensInvoice",
    "decodeBolt11",
    "decodeSparkAddress",
    "decodeTokenIdentifier",
    "encodeSparkAddress",
    "encodeTokenIdentifier",
    "exitTransactions",
    "isExpired",
    "parseSparkInvoice",
    "sparkNetworkConfig",
    "verifySparkAddressSignature",
  ]);
});

test("crypto runtime exports are exactly the backend contract", () => {
  expect(names(crypto)).toStrictEqual(["SPARK_ABI_VERSION", "SparkCryptoError", "SparkError"]);
  expect(crypto.SPARK_ABI_VERSION).toBe(1);
});

test("signer runtime exports are exactly the signer factory surface", () => {
  expect(names(signer)).toStrictEqual(["createSparkSigner", "sparkAccountKey"]);
});
