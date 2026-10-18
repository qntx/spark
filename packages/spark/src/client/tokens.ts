import {
  buildTransferPartial,
  broadcastPartialTokenTransaction,
  queryTokenOutputs,
  selectTokenOutputs,
  tokenBalances,
} from "../tokens/index.ts";
import type { ClientContext } from "./context.ts";
import type { SparkClient } from "./index.ts";

export function createTokens(context: ClientContext): SparkClient["tokens"] {
  const { coordinatorConnection, signer, network, operators, config, now } = context;
  const { token } = coordinatorConnection;
  return {
    outputs: async (outputsOptions) => {
      const identifier =
        outputsOptions?.tokenIdentifier === undefined
          ? undefined
          : context.tokenIdentifierForNetwork(outputsOptions.tokenIdentifier);
      return queryTokenOutputs({
        token,
        ownerPublicKey: await signer.identityPublicKey(),
        network,
        tokenIdentifiers: identifier === undefined ? [] : [identifier],
      });
    },
    balances: async () =>
      tokenBalances(
        await queryTokenOutputs({
          token,
          ownerPublicKey: await signer.identityPublicKey(),
          network,
        }),
        network,
      ),
    transfer: async (transferOptions) => {
      const identifier = context.tokenIdentifierForNetwork(transferOptions.tokenIdentifier);
      const receiver = context.receiverIdentityKey(transferOptions.receiver);
      const owned = await queryTokenOutputs({
        token,
        ownerPublicKey: await signer.identityPublicKey(),
        network,
        tokenIdentifiers: [identifier],
      });
      const selected = selectTokenOutputs(owned, transferOptions.amount);
      const partial = buildTransferPartial({
        selectedOutputs: selected,
        receiverPublicKey: receiver,
        tokenIdentifier: identifier,
        amount: transferOptions.amount,
        senderPublicKey: await signer.identityPublicKey(),
        network,
        operators,
        tokens: config.tokens,
        now: now ?? (() => Date.now()),
      });
      const result = await broadcastPartialTokenTransaction({
        token,
        signer,
        partial,
        network,
        operators,
        tokens: config.tokens,
      });
      return result.transactionHash;
    },
  };
}
