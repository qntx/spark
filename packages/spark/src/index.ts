export {
  SparkError,
  SparkCryptoError,
  SparkInputError,
  SparkRequestError,
} from "./errors/index.ts";
export {
  sparkNetworkConfig,
  encodeSparkAddress,
  decodeSparkAddress,
  decodeBolt11,
  decodeTokenIdentifier,
  encodeTokenIdentifier,
  isExpired,
  verifySparkAddressSignature,
} from "./core/index.ts";
export type {
  SparkNetwork,
  SparkNetworkConfig,
  SparkOperatorConfig,
  SparkAddress,
  SparkInvoiceFields,
  SparkPayment,
  SparkTokenIdentifierData,
} from "./core/index.ts";
export type { Bolt11Invoice, Bolt11Network } from "./core/index.ts";
export { createSparkClient } from "./client/index.ts";
export type { SparkClient, SparkClientOptions } from "./client/index.ts";
export type { SparkEvent } from "./connection/index.ts";
export type { UnusedDepositAddress } from "./deposit/index.ts";
export { buildCpfpChild } from "./core/bitcoin/cpfp.ts";
export type { FundingInput } from "./core/bitcoin/cpfp.ts";
export { exitTransactions } from "./exit/unilateral.ts";
export type { ExitTransaction } from "./exit/unilateral.ts";
export { createMemorySparkStore } from "./exit/store.ts";
export type { SparkExitChain, SparkStore } from "./exit/store.ts";
export type { SparkLeaf } from "./tree/index.ts";
export type { SparkTransfer, SparkTransferLeaf } from "./transfer/index.ts";
