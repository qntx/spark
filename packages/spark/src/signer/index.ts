export { createSparkSigner, sparkAccountKey } from "./local.ts";
export { lightningSendHtlcScript } from "./outflow.ts";
export type { AuthorizeOutflow, SparkOutflow } from "./outflow.ts";
export { createLnurlAuthSigner, lnurlAuthRootKey } from "./lnurl-auth.ts";
export type { LnurlAuthSigner } from "./lnurl-auth.ts";
export type {
  FrostAggregateJob,
  FrostSignJob,
  HtlcTimeoutSignRequest,
  IdentityStatement,
  OperatorCommitment,
  PrepareClaimRequest,
  PreparedClaim,
  PreparedLightningReceive,
  PreparedTransfer,
  PreparedTransferLeaf,
  PrepareTransferRequest,
  SigningCommitment,
  SparkKey,
  SparkLeafKey,
  SparkOperator,
  SparkSigner,
  StaticDepositClaimRequest,
} from "./types.ts";
export type { SigningTarget } from "./types.ts";
export type { SparkNetwork } from "../core/network.ts";
export { decodeBolt11 } from "../core/bolt11.ts";
export { sparkNetworkConfig } from "../core/network.ts";
export { EPHEMERAL_ANCHOR_SCRIPT } from "../core/bitcoin/script.ts";
export { addressToScript } from "../core/bitcoin/transactions.ts";
