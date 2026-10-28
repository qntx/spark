import { equalBytes } from "@noble/curves/utils.js";

import { SparkInputError } from "../../errors/index.ts";
import type { SparkNetwork } from "../network.ts";
import { parseTransaction } from "./sighash.ts";
import { bitcoinAddressScript, txId } from "./transactions.ts";

// Cooperative-exit validation, ported from
// sdks/js/packages/spark-sdk/src/utils/bitcoin.ts (buildonspark/spark@0b3a32a).

/**
 * Ensures the SSP's connector transaction's first input spends the coop-exit transaction.
 * `coopExitTxIdInternal` is the txid in internal (wire) byte order — the byte order a serialized
 * outpoint carries, i.e. the reverse of the conventional hex display order. btc-signer stores
 * `TxIn.txid` in display order, so the parent id is reversed before comparing.
 */
export function validateConnectorTxBindsToCoopExitTxid(
  connectorTxBytes: Uint8Array,
  coopExitTxIdInternal: Uint8Array,
): void {
  const connectorTx = parseTransaction(connectorTxBytes);
  if (connectorTx.inputsLength === 0) {
    throw new SparkInputError("connectorTx: transaction has no inputs");
  }
  const parentTxid = connectorTx.getInput(0).txid;
  if (parentTxid === undefined) {
    throw new SparkInputError("connectorTx: input 0 has no parent txid");
  }
  if (!equalBytes(Uint8Array.from(parentTxid).reverse(), coopExitTxIdInternal)) {
    throw new SparkInputError("connectorTx: input 0 does not spend coopExitTxId");
  }
}

export type CoopExitPayoutValidation = {
  /** Raw cooperative-exit transaction bytes. */
  readonly rawCoopExitTransaction: Uint8Array;
  /** Display-order txid the SSP claims it signed. */
  readonly expectedCoopExitTxid: string;
  /** Withdrawal address the payout must reach. */
  readonly expectedPayoutAddress: string;
  readonly expectedPayoutAmountSats: number;
  readonly network: SparkNetwork;
};

/**
 * Verifies the SSP-signed cooperative-exit payout transaction: the txid matches and some output
 * pays at least `expectedPayoutAmountSats` to the requested withdrawal address.
 */
export function validateCoopExitPayoutTransaction(params: CoopExitPayoutValidation): void {
  const coopExitTx = parseTransaction(params.rawCoopExitTransaction);
  if (txId(params.rawCoopExitTransaction) !== params.expectedCoopExitTxid) {
    throw new SparkInputError("coopExitTxid: does not match rawCoopExitTransaction");
  }
  const expectedScript = p2trAddressScript(params.expectedPayoutAddress, params.network);
  for (let i = 0; i < coopExitTx.outputsLength; i += 1) {
    const output = coopExitTx.getOutput(i);
    const { script, amount } = output;
    if (script === undefined || amount === undefined) {
      continue;
    }
    if (!equalBytes(script, expectedScript)) {
      continue;
    }
    if (amount >= BigInt(params.expectedPayoutAmountSats)) {
      return;
    }
  }
  throw new SparkInputError(
    "rawCoopExitTransaction: no output pays the requested address for the expected amount",
  );
}

function p2trAddressScript(address: string, network: SparkNetwork): Uint8Array {
  try {
    return bitcoinAddressScript(address, network);
  } catch (error) {
    throw new SparkInputError("expectedPayoutAddress: could not decode the withdrawal address", {
      cause: error,
    });
  }
}
