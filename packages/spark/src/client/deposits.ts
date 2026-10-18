import { uuidv7 } from "../core/uuid.ts";
import {
  claimDeposit,
  generateDepositAddress,
  queryUnusedDepositAddresses,
} from "../deposit/index.ts";
import type { ClientContext } from "./context.ts";
import type { SparkClient } from "./index.ts";

export function createDeposits(context: ClientContext): SparkClient["deposits"] {
  const { random, now } = context;
  return {
    newAddress: async () =>
      generateDepositAddress({
        ...context.depositCoordinator,
        leafId: uuidv7(random, now),
      }),
    unused: async () => queryUnusedDepositAddresses(context.depositCoordinator),
    claim: async (claimOptions) => {
      const leaf = await claimDeposit({
        ...context.depositCoordinator,
        transaction: claimOptions.transaction,
        ...(claimOptions.vout === undefined ? {} : { vout: claimOptions.vout }),
      });
      await context.storeChainsFor([leaf]);
      return leaf;
    },
  };
}
