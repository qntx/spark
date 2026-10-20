import { queryWalletSettings, updateWalletPrivate } from "../settings/index.ts";
import type { ClientContext } from "./context.ts";
import type { SparkClient } from "./index.ts";

export function createWalletSettings(context: ClientContext): SparkClient["walletSettings"] {
  const { coordinatorConnection, signer } = context;
  return {
    get: async () =>
      queryWalletSettings({
        spark: coordinatorConnection.spark,
        identityPublicKey: await signer.identityPublicKey(),
      }),
    setPrivate: async (enabled) =>
      updateWalletPrivate({
        spark: coordinatorConnection.spark,
        identityPublicKey: await signer.identityPublicKey(),
        privateEnabled: enabled,
      }),
  };
}
