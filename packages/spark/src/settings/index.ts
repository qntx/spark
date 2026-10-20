import type { Client } from "@connectrpc/connect";
import { equalBytes } from "@noble/curves/utils.js";

import { SparkError } from "../errors/index.ts";
import type { SparkService, WalletSetting } from "../proto/gen/spark_pb.ts";

// Per-wallet settings the coordinator stores and gossips to the other operators
// (upstream so/handler/wallet_setting_handler.go). `privateEnabled` restricts
// the wallet's node/transfer queries to its owner's own session.

export type SparkWalletSettings = {
  /**
   * When true, only the owner's (or master's) session may read this wallet's nodes and transfers.
   * Other identities get no error — their queries simply come back empty (observed on hosted).
   */
  readonly privateEnabled: boolean;
};

/**
 * Maps the coordinator's `wallet_setting`. A wallet with no stored setting is public by default.
 * The setting's owner must be the identity we authenticated as — a mismatch means the coordinator
 * answered for someone else's wallet.
 */
function mapWalletSetting(
  setting: WalletSetting | undefined,
  identityPublicKey: Uint8Array,
): SparkWalletSettings {
  if (setting === undefined) {
    return { privateEnabled: false };
  }
  if (!equalBytes(setting.ownerIdentityPublicKey, identityPublicKey)) {
    throw new SparkError("wallet setting: owner does not match our identity");
  }
  return { privateEnabled: setting.privateEnabled };
}

/** `query_wallet_setting` — the session's own wallet settings; absent means public. */
export async function queryWalletSettings(options: {
  readonly spark: Client<typeof SparkService>;
  readonly identityPublicKey: Uint8Array;
}): Promise<SparkWalletSettings> {
  const response = await options.spark.query_wallet_setting({});
  return mapWalletSetting(response.walletSetting, options.identityPublicKey);
}

/**
 * `update_wallet_setting` — sets `private_enabled` and returns the resulting setting. The
 * coordinator gossips the update to the other operators, so the change applies to every operator's
 * read-access checks.
 */
export async function updateWalletPrivate(options: {
  readonly spark: Client<typeof SparkService>;
  readonly identityPublicKey: Uint8Array;
  readonly privateEnabled: boolean;
}): Promise<SparkWalletSettings> {
  const response = await options.spark.update_wallet_setting({
    privateEnabled: options.privateEnabled,
  });
  return mapWalletSetting(response.walletSetting, options.identityPublicKey);
}
