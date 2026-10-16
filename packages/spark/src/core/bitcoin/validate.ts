import { Address, OutScript } from "@scure/btc-signer";

import { SparkInputError } from "../../errors/index.ts";
import type { SparkNetwork } from "../network.ts";
import { btcNetwork } from "./script.ts";
import { parseTransaction } from "./sighash.ts";
import { txId } from "./transactions.ts";

// Cooperative-exit validation, ported from
// sdks/js/packages/spark-sdk/src/utils/bitcoin.ts (buildonspark/spark@0b3a32a).

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

function equalBytesReversed(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[b.length - 1 - i]) {
      return false;
    }
  }
  return true;
}

/**
 * Ensures the SSP's connector transaction's first input spends `coopExitTxId`. Both byte orders are
 * accepted, mirroring the upstream validator's tolerance.
 */
export function validateConnectorTxBindsToCoopExitTxid(
  connectorTxBytes: Uint8Array,
  coopExitTxId: Uint8Array,
): void {
  const connectorTx = parseTransaction(connectorTxBytes);
  if (connectorTx.inputsLength === 0) {
    throw new SparkInputError("connectorTx: transaction has no inputs");
  }
  const parentTxid = connectorTx.getInput(0).txid;
  if (parentTxid === undefined) {
    throw new SparkInputError("connectorTx: input 0 has no parent txid");
  }
  if (!equalBytes(parentTxid, coopExitTxId) && !equalBytesReversed(parentTxid, coopExitTxId)) {
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
    return OutScript.encode(Address(btcNetwork(network)).decode(address));
  } catch (error) {
    throw new SparkInputError("expectedPayoutAddress: could not decode the withdrawal address", {
      cause: error,
    });
  }
}
