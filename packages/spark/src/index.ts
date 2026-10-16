export { SparkError, SparkCryptoError, SparkInputError } from "./errors/index.ts";
export {
  sparkNetworkConfig,
  encodeSparkAddress,
  decodeSparkAddress,
  decodeBolt11,
  isExpired,
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
