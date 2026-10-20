import {
  buildTransferPartial,
  broadcastPartialTokenTransaction,
  MAX_TOKEN_OUTPUTS_TX,
  queryTokenOutputs,
  selectTokenOutputs,
  tokenBalances,
} from "../tokens/index.ts";
import type { ClientContext } from "./context.ts";
import type { SparkClient } from "./index.ts";

/**
 * Select-owned-outputs → partial → broadcast path shared by `tokens.transfer` and `invoices.pay`.
 * The whole sequence runs under `tokenLock` so two transfers cannot select the same outputs.
 */
export async function sendTokens(
  context: ClientContext,
  options: {
    readonly tokenIdentifier: Uint8Array;
    readonly amount: bigint;
    readonly receiver: Uint8Array;
    readonly invoiceAttachments?: ReadonlyArray<string>;
  },
): Promise<{ transactionHash: string; tokenIdentifier?: Uint8Array }> {
  return context.tokenLock.run(async () => {
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
      inputOutputIds: selected.map((output) => output.id),
    });
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
    consolidate: async (consolidateOptions) => {
      const tokenIdentifier = context.tokenIdentifierForNetwork(consolidateOptions.tokenIdentifier);
      return context.tokenLock.run(async () => {
        const { operators, config, now } = context;
        const identityPublicKey = await signer.identityPublicKey();
        const owned = await queryTokenOutputs({
          token,
          ownerPublicKey: identityPublicKey,
          network,
          tokenIdentifiers: [tokenIdentifier],
        });
        // Smallest-first, capped like upstream optimizeTokenOutputs: one transaction merges at
        // most MAX_TOKEN_OUTPUTS_TX inputs, so dust consolidates first.
        const available = owned
          .filter((output) => output.status === "available")
          .sort((a, b) => (a.amount < b.amount ? -1 : a.amount > b.amount ? 1 : 0))
          .slice(0, MAX_TOKEN_OUTPUTS_TX);
        if (available.length <= 1) {
          return undefined;
        }
        let total = 0n;
        for (const output of available) {
          total += output.amount;
        }
        const partial = buildTransferPartial({
          selectedOutputs: available,
          receiverPublicKey: identityPublicKey,
          tokenIdentifier,
          amount: total,
          senderPublicKey: identityPublicKey,
          network,
          operators,
          tokens: config.tokens,
          now,
        });
        const { transactionHash } = await broadcastPartialTokenTransaction({
          token,
          signer,
          partial,
          network,
          operators,
          tokens: config.tokens,
          inputOutputIds: available.map((output) => output.id),
        });
        return { transactionHash };
      });
    },
  };
}
