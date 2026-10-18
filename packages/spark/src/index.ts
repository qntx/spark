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
} from "./core/index.ts";
export type { Bolt11Invoice, Bolt11Network } from "./core/index.ts";
export { createSparkClient } from "./client/index.ts";
export type { SparkClient, SparkClientOptions } from "./client/index.ts";
export type { SparkEvent } from "./connection/index.ts";
export type { UnusedDepositAddress } from "./deposit/index.ts";
export type { ExitTransaction } from "./exit/unilateral.ts";
export type { SparkLeaf } from "./tree/index.ts";
export type { SparkTransfer, SparkTransferLeaf } from "./transfer/index.ts";
