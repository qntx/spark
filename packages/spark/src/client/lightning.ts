import { SparkError } from "../errors/index.ts";
import {
  createLightningInvoice,
  lightningReceiveStatus,
  lightningSendStatus,
  payLightningInvoice,
} from "../lightning/index.ts";
import type { LightningDeps } from "../lightning/index.ts";
import type { ClientContext } from "./context.ts";
import type { SparkClient } from "./index.ts";
import { selectSendLeaves } from "./leaves.ts";

export function createLightning(context: ClientContext): SparkClient["lightning"] {
  const deps: LightningDeps = {
    spark: context.coordinatorConnection.spark,
    ssp: context.sspClient,
    sspIdentityPublicKey: context.config.ssp.identityPublicKey,
    signer: context.signer,
    network: context.network,
    operators: context.operators,
    threshold: context.transferCoordinator.threshold,
    random: context.random,
    now: context.now,
  };
  return {
    createInvoice: async (options) => createLightningInvoice(deps, options),
    pay: async (options) =>
      payLightningInvoice(
        {
          ...deps,
          spendLeaves: async (amountSats, use) =>
            context.leafLock.run(async () => {
              const [group] = await selectSendLeaves(context, [amountSats]);
              if (group === undefined) {
                throw new SparkError("lightning pay: leaf selection returned no group");
              }
              return use(group);
            }),
          deleteExitChains: async (leafIds) => context.store.deleteExitChains(leafIds),
        },
        options,
      ),
    sendStatus: async (request) => lightningSendStatus(context.sspClient, request),
    receiveStatus: async (requestId) => lightningReceiveStatus(context.sspClient, requestId),
  };
}
