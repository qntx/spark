import { equalBytes } from "@noble/curves/utils.js";

import {
  buildKeySpendSweep,
  finalizeKeySpend,
  p2trScriptFromPublicKey,
  parseTransaction,
} from "../core/bitcoin/index.ts";
import { SparkInputError } from "../errors/index.ts";
import { cooperativeExit, cooperativeExitStatus, quoteCooperativeExit } from "../exit/coop.ts";
import { unilateralExitTransactions } from "../exit/unilateral.ts";
import { queryWatchtowerExitedLeaves, recoverWatchtowerExit } from "../exit/watchtower.ts";
import type { ClientContext } from "./context.ts";
import type { SparkClient } from "./index.ts";
import { renewStaleLeaves, selectSendLeaves } from "./leaves.ts";

export function createWithdrawals(context: ClientContext): SparkClient["withdrawals"] {
  const { coordinatorConnection, signer, network, config, store } = context;
  // All spendable leaves withdraw everything; an amount selects exactly (swapping if needed).
  // Either way every leaf is renewed before it leaves the wallet. Caller holds `leafLock`.
  const selectExitLeaves = async (amountSats?: number) => {
    if (amountSats === undefined) {
      return renewStaleLeaves(context, await context.syncLeaves());
    }
    const [group] = await selectSendLeaves(context, [amountSats]);
    if (group === undefined) {
      throw new SparkInputError("coop exit: leaf selection returned no group");
    }
    return group;
  };
  return {
    quoteCooperativeExit: async (options) =>
      quoteCooperativeExit(
        {
          ssp: context.sspClient,
          network,
          selectLeaves: async (amountSats) =>
            context.leafLock.run(async () => selectExitLeaves(amountSats)),
        },
        options,
      ),
    cooperativeExit: async (options) =>
      cooperativeExit(
        {
          spark: coordinatorConnection.spark,
          ssp: context.sspClient,
          sspIdentityPublicKey: config.ssp.identityPublicKey,
          signer,
          network,
          operators: context.operators,
          threshold: config.threshold,
          random: context.random,
          now: context.now,
          spendLeaves: async (amountSats, use) =>
            context.leafLock.run(async () => use(await selectExitLeaves(amountSats))),
          deleteExitChains: async (leafIds) => store.deleteExitChains(leafIds),
          ...(context.sleep === undefined ? {} : { sleep: context.sleep }),
        },
        options,
      ),
    cooperativeExitStatus: async (requestId) =>
      cooperativeExitStatus({ ssp: context.sspClient }, requestId),
    unilateralExit: async (leafIds) =>
      context.leafLock.run(async () => {
        const { transactions, chains } = await unilateralExitTransactions({
          spark: coordinatorConnection.spark,
          network,
          signer,
          leafIds,
        });
        await store.putExitChains(chains);
        return transactions;
      }),
    watchtowerExitedLeaves: async () =>
      queryWatchtowerExitedLeaves({
        spark: coordinatorConnection.spark,
        identityPublicKey: await signer.identityPublicKey(),
        network,
      }),
    recoverWatchtowerExit: async (options) =>
      recoverWatchtowerExit({ spark: coordinatorConnection.spark, signer, network }, options),
    sweepRefund: async ({ leafId, refundTx, destinationScript, feeRateSatPerVbyte }) => {
      const key = { type: "leaf" as const, leafId };
      const [publicKey] = await signer.publicKeys([key]);
      if (publicKey === undefined) {
        throw new SparkInputError(`sweepRefund: no public key for leaf ${leafId}`);
      }
      const output = parseTransaction(refundTx).getOutput(0);
      if (
        output.script === undefined ||
        !equalBytes(output.script, p2trScriptFromPublicKey(publicKey, network))
      ) {
        throw new SparkInputError(
          `sweepRefund: refund tx output 0 does not pay leaf ${leafId}'s key-path script`,
        );
      }
      const sweep = buildKeySpendSweep({
        prevTx: refundTx,
        vout: 0,
        destinationScript,
        feeRateSatPerVbyte,
      });
      const signature = await signer.signKeySpend(key, sweep.target);
      return finalizeKeySpend(sweep.transaction, signature);
    },
  };
}
