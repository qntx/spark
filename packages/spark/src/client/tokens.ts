import { SparkInputError } from "../errors/index.ts";
import {
  buildTransferPartial,
  broadcastPartialTokenTransaction,
  MAX_TOKEN_OUTPUTS_TX,
  queryTokenOutputs,
  selectTokenOutputs,
  tokenBalances,
  transferWithInputIds,
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
    readonly inputOutputIds?: ReadonlyArray<string>;
  },
): Promise<{ transactionHash: string; tokenIdentifier?: Uint8Array }> {
  return context.tokenLock.run(async () => {
    const { coordinatorConnection, signer, network, operators, config, now } = context;
    if (options.inputOutputIds !== undefined) {
      return transferWithInputIds({
        token: coordinatorConnection.token,
        signer,
        network,
        operators,
        tokens: config.tokens,
        now,
        tokenIdentifier: options.tokenIdentifier,
        amount: options.amount,
        receiverPublicKey: options.receiver,
        senderPublicKey: await signer.identityPublicKey(),
        inputOutputIds: options.inputOutputIds,
        ...(options.invoiceAttachments === undefined
          ? {}
          : { invoiceAttachments: options.invoiceAttachments }),
      });
    }
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
        ...(transferOptions.inputOutputIds === undefined
          ? {}
          : { inputOutputIds: transferOptions.inputOutputIds }),
      });
      return transactionHash;
    },
    consolidate: async (consolidateOptions) => {
      const tokenIdentifier = context.tokenIdentifierForNetwork(consolidateOptions.tokenIdentifier);
      return context.tokenLock.run(async () => {
        const { operators, config, now } = context;
        const identityPublicKey = await signer.identityPublicKey();
        if (consolidateOptions.inputOutputIds !== undefined) {
          if (consolidateOptions.inputOutputIds.length < 2) {
            throw new SparkInputError(
              "token consolidate: inputOutputIds needs at least two outputs",
            );
          }
          const { transactionHash } = await transferWithInputIds({
            token,
            signer,
            network,
            operators,
            tokens: config.tokens,
            now,
            tokenIdentifier,
            receiverPublicKey: identityPublicKey,
            senderPublicKey: identityPublicKey,
            inputOutputIds: consolidateOptions.inputOutputIds,
          });
          return { transactionHash };
        }
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
