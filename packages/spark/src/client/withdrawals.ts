import { equalBytes } from "@noble/curves/utils.js";

import {
  buildKeySpendSweep,
  finalizeKeySpend,
  p2trScriptFromPublicKey,
  parseTransaction,
} from "../core/bitcoin/index.ts";
import { SparkInputError } from "../errors/index.ts";
import { unilateralExitTransactions } from "../exit/unilateral.ts";
import type { ClientContext } from "./context.ts";
import type { SparkClient } from "./index.ts";

export function createWithdrawals(context: ClientContext): SparkClient["withdrawals"] {
  const { coordinatorConnection, signer, network, store } = context;
  return {
    unilateralExit: async (leafIds) => {
      const { transactions, chains } = await unilateralExitTransactions({
        spark: coordinatorConnection.spark,
        network,
        leafIds,
      });
      await store.putExitChains(chains);
      return transactions;
    },
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
