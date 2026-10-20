export { sparkNetworkConfig } from "./network.ts";
export { encodeSparkAddress, decodeSparkAddress, verifySparkAddressSignature } from "./address.ts";
export { encodeTokenIdentifier, decodeTokenIdentifier } from "./token-identifier.ts";
export type { SparkTokenIdentifierData } from "./token-identifier.ts";
export { decodeBolt11, isExpired } from "./bolt11.ts";
export {
  LIGHTNING_ADDRESS_MAX_DESCRIPTION_LENGTH,
  LIGHTNING_ADDRESS_USERNAME_PATTERN,
  LIGHTNING_ADDRESS_VALIDITY_SECS,
  checkLightningAddressDomain,
  checkLightningAddressUsername,
  lightningAddressDescriptionHash,
  lightningAddressMessage,
  lightningAddressMessageDigest,
  lightningAddressRegisterMessage,
  lightningAddressStatementHash,
  lightningAddressTimestampFresh,
  lightningAddressUnregisterMessage,
} from "./lightning-address.ts";
export type { LightningAddressStatement } from "./lightning-address.ts";
export type { SparkNetwork, SparkNetworkConfig, SparkOperatorConfig } from "./network.ts";
export type { SparkAddress } from "./address.ts";
export type { SparkInvoiceFields, SparkPayment } from "./invoice.ts";
export type {
  Bolt11Invoice,
  Bolt11Network,
  Bolt11FallbackAddress,
  Bolt11RouteHintHop,
} from "./bolt11.ts";
