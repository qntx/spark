import {
  buildTransferPartial,
  broadcastPartialTokenTransaction,
  queryTokenOutputs,
  selectTokenOutputs,
  tokenBalances,
} from "../tokens/index.ts";
import type { ClientContext } from "./context.ts";
import type { SparkClient } from "./index.ts";

/** Select-owned-outputs → partial → broadcast path shared by `tokens.transfer` and `invoices.pay`. */
export async function sendTokens(
  context: ClientContext,
  options: {
    readonly tokenIdentifier: Uint8Array;
    readonly amount: bigint;
    readonly receiver: Uint8Array;
    readonly invoiceAttachments?: ReadonlyArray<string>;
  },
): Promise<{ transactionHash: string; tokenIdentifier?: Uint8Array }> {
  const { coordinatorConnection, signer, network, operators, config, now } = context;
  const owned = await queryTokenOutputs({
    token: coordinatorConnection.token,
    ownerPublicKey: await signer.identityPublicKey(),
    network,
    tokenIdentifiers: [options.tokenIdentifier],
  });
  const selected = selectTokenOutputs(owned, options.amount);
  const partial = buildTransferPartial({
    selectedOutputs: selected,
    receiverPublicKey: options.receiver,
    tokenIdentifier: options.tokenIdentifier,
    amount: options.amount,
    senderPublicKey: await signer.identityPublicKey(),
    network,
    operators,
    tokens: config.tokens,
    now,
    ...(options.invoiceAttachments === undefined
      ? {}
      : { invoiceAttachments: options.invoiceAttachments }),
  });
  return broadcastPartialTokenTransaction({
    token: coordinatorConnection.token,
    signer,
    partial,
    network,
    operators,
    tokens: config.tokens,
  });
}

export function createTokens(context: ClientContext): SparkClient["tokens"] {
  const { coordinatorConnection, signer, network } = context;
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
      const { transactionHash } = await sendTokens(context, {
        tokenIdentifier: context.tokenIdentifierForNetwork(transferOptions.tokenIdentifier),
        amount: transferOptions.amount,
        receiver: context.receiverIdentityKey(transferOptions.receiver),
      });
      return transactionHash;
    },
  };
}
