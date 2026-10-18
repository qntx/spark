import { hexToBytes } from "@noble/hashes/utils.js";
import { Address, OutScript, Transaction } from "@scure/btc-signer";

import { SparkInputError } from "../../errors/index.ts";
import { assertSats, assertU32, MAX_SATS } from "../assert.ts";
import type { SparkNetwork } from "../network.ts";
import {
  btcNetwork,
  EPHEMERAL_ANCHOR_SCRIPT,
  p2trAddressFromScript,
  p2trScriptFromPublicKey,
} from "./script.ts";
import {
  checkIfValidSequence,
  DIRECT_TIMELOCK_OFFSET,
  DEFAULT_FEE_SATS,
  INITIAL_ROOT_NODE_SEQUENCE,
  INITIAL_SEQUENCE,
  getTimelockFromSequence,
  isZeroTimelock,
  roundDownToTimelockInterval,
  TIME_LOCK_INTERVAL,
  ZERO_SEQUENCE,
  getNextTransactionSequence,
} from "./sequence.ts";
import { keySpendSighash, parseTransaction } from "./sighash.ts";

// Spark node/refund/root transaction constructors. Upstream references:
// signer/spark-frost/src/transaction.rs (authoritative byte formats) and
// sdks/js/packages/spark-sdk/src/utils/transaction.ts (the create* wrappers).

/** A constructed transaction: consensus-serialized bytes plus its BIP-341 sighash. */
export type ConstructedTransaction = {
  readonly txBytes: Uint8Array;
  readonly sighash: Uint8Array;
};

/** CPFP + direct node transaction pair built over the same parent output. */
export type NodeTxPair = {
  readonly cpfp: ConstructedTransaction;
  readonly direct: ConstructedTransaction;
};

/** The three refund variants over a node transaction. */
export type RefundTxTrio = {
  readonly cpfpRefund: ConstructedTransaction;
  /** Absent when no direct node transaction exists (zero timelock). */
  readonly directRefund: ConstructedTransaction | undefined;
  readonly directFromCpfpRefund: ConstructedTransaction;
};

/**
 * Display-order txid (the usual block-explorer hex form). The txid never covers witness data —
 * hashing the raw serialization of a segwit transaction would yield its wtxid instead.
 */
export function txId(txBytes: Uint8Array): string {
  return parseTransaction(txBytes).id;
}

/** Internal byte order for the txid (hash byte order as written in outpoints). */
export function txIdBytes(txBytes: Uint8Array): Uint8Array {
  return hexToBytes(parseTransaction(txBytes).id).reverse();
}

/**
 * Display-order txid bytes — the form btc-signer's `TransactionInput.txid` expects (it reverses
 * internally when serializing the outpoint).
 */
export function txIdInputBytes(txBytes: Uint8Array): Uint8Array {
  return hexToBytes(parseTransaction(txBytes).id);
}

/** Subtracts `feeSats` when the amount can cover it; otherwise returns the amount unchanged. */
export function maybeApplyFee(amountSats: number, feeSats: number): number {
  assertSats(amountSats, "amount");
  assertSats(feeSats, "feeSats");
  return amountSats > feeSats ? amountSats - feeSats : amountSats;
}

function prevOutAt(tx: Transaction, vout: number): { script: Uint8Array; amountSats: number } {
  if (!Number.isSafeInteger(vout) || vout < 0 || vout >= tx.outputsLength) {
    throw new SparkInputError("vout: out of range for the transaction's outputs");
  }
  const output = tx.getOutput(vout);
  const { script, amount } = output;
  if (script === undefined || amount === undefined) {
    throw new SparkInputError("vout: output is missing its script or amount");
  }
  if (amount > BigInt(MAX_SATS)) {
    throw new SparkInputError(`vout: amount exceeds ${MAX_SATS} sats`);
  }
  return { script, amountSats: Number(amount) };
}

/**
 * Decodes a Bitcoin address to its output script under any network — matching upstream
 * `Address::from_str(..).assume_checked()`, which never checks that the address's network matches
 * the operating network.
 */
export function addressToScript(address: string): Uint8Array {
  for (const net of [btcNetwork("mainnet"), btcNetwork("regtest")]) {
    try {
      return OutScript.encode(Address(net).decode(address));
    } catch {
      // try the other network parameters
    }
  }
  throw new SparkInputError("address: not a decodable Bitcoin address");
}

/**
 * Shared builder for node/refund transactions: one input spending `parentTxBytes`'s `vout`, one
 * destination output, and optionally the ephemeral anchor output. Version 3, locktime 0.
 */
function buildSingleOutputTx(
  parentTxBytes: Uint8Array,
  vout: number,
  outputScript: Uint8Array,
  sequence: number,
  applyFee: boolean,
  feeSats: number,
  includeAnchor: boolean,
): ConstructedTransaction {
  const prevTx = parseTransaction(parentTxBytes);
  const prevOut = prevOutAt(prevTx, vout);
  const outAmount = applyFee ? maybeApplyFee(prevOut.amountSats, feeSats) : prevOut.amountSats;

  const tx = new Transaction({ version: 3, allowUnknownOutputs: true });
  tx.addInput({ txid: txIdInputBytes(parentTxBytes), index: vout, sequence });
  tx.addOutput({ script: outputScript, amount: BigInt(outAmount) });
  if (includeAnchor) {
    tx.addOutput({ script: EPHEMERAL_ANCHOR_SCRIPT, amount: 0n });
  }
  const txBytes = tx.toBytes(true);
  return {
    txBytes,
    sighash: keySpendSighash(tx, 0, [{ script: prevOut.script, amount: prevOut.amountSats }]),
  };
}

/**
 * Both node transactions over a parent output. The CPFP variant carries the full amount plus the
 * anchor output at `sequence`; the direct variant deducts the fee, has no anchor, and uses
 * `directSequence`.
 */
export function constructNodeTxPair(
  parentTx: Uint8Array,
  vout: number,
  address: string,
  sequence: number,
  directSequence: number,
  feeSats: number,
): NodeTxPair {
  checkIfValidSequence(sequence);
  checkIfValidSequence(directSequence);
  const outputScript = addressToScript(address);
  return {
    cpfp: buildSingleOutputTx(parentTx, vout, outputScript, sequence, false, feeSats, true),
    direct: buildSingleOutputTx(parentTx, vout, outputScript, directSequence, true, feeSats, false),
  };
}

/**
 * The three refund variants spending a node transaction's `vout` to the P2TR script of
 * `receivingPublicKey`: CPFP (no fee, with anchor), direct (fee, no anchor, only when a direct node
 * tx exists), and direct-from-CPFP (fee, no anchor, spending the CPFP node tx at
 * `directSequence`).
 */
export function constructRefundTxTrio(
  cpfpNodeTx: Uint8Array,
  directNodeTx: Uint8Array | undefined,
  vout: number,
  receivingPublicKey: Uint8Array,
  network: SparkNetwork,
  sequence: number,
  directSequence: number,
  feeSats: number,
): RefundTxTrio {
  checkIfValidSequence(sequence);
  checkIfValidSequence(directSequence);
  const outputScript = p2trScriptFromPublicKey(receivingPublicKey, network);
  return {
    cpfpRefund: buildSingleOutputTx(cpfpNodeTx, vout, outputScript, sequence, false, feeSats, true),
    directRefund:
      directNodeTx === undefined
        ? undefined
        : buildSingleOutputTx(
            directNodeTx,
            vout,
            outputScript,
            directSequence,
            true,
            feeSats,
            false,
          ),
    directFromCpfpRefund: buildSingleOutputTx(
      cpfpNodeTx,
      vout,
      outputScript,
      directSequence,
      true,
      feeSats,
      false,
    ),
  };
}

// ---------------------------------------------------------------------------
// Upstream TS wrappers (sdks/…/utils/transaction.ts): take parsed/raw parent
// transactions and pick the destination address from the parent output.
// ---------------------------------------------------------------------------

export type NodeTxsParams = {
  readonly parentTx: Uint8Array;
  readonly vout: number;
  readonly sequence: number;
  readonly directSequence?: number | undefined;
  readonly network: SparkNetwork;
};

/** Node tx pair whose destination is the parent output's own P2TR address. */
export function createNodeTxs(params: NodeTxsParams): NodeTxPair {
  const parent = parseTransaction(params.parentTx);
  const parentOutput = prevOutAt(parent, params.vout);
  const address = p2trAddressFromScript(parentOutput.script, params.network);
  const directSequence = params.directSequence ?? params.sequence + DIRECT_TIMELOCK_OFFSET;
  return constructNodeTxPair(
    params.parentTx,
    params.vout,
    address,
    params.sequence,
    directSequence,
    DEFAULT_FEE_SATS,
  );
}

/** Root node transactions: sequence 0, direct sequence `DIRECT_TIMELOCK_OFFSET`. */
export function createRootNodeTx(
  parentTx: Uint8Array,
  vout: number,
  network: SparkNetwork,
): NodeTxPair {
  return createNodeTxs({
    parentTx,
    sequence: INITIAL_ROOT_NODE_SEQUENCE,
    directSequence: DIRECT_TIMELOCK_OFFSET,
    vout,
    network,
  });
}

/** Zero-timelock node transactions over output 0 (root variant of `createNodeTxs`). */
export function createZeroTimelockNodeTx(parentTx: Uint8Array, network: SparkNetwork): NodeTxPair {
  return createNodeTxs({
    parentTx,
    sequence: INITIAL_ROOT_NODE_SEQUENCE,
    directSequence: DIRECT_TIMELOCK_OFFSET,
    vout: 0,
    network,
  });
}

/** Node transactions at `INITIAL_SEQUENCE` (2000 blocks). */
export function createInitialTimelockNodeTx(
  parentTx: Uint8Array,
  network: SparkNetwork,
): NodeTxPair {
  return createNodeTxs({ parentTx, sequence: INITIAL_SEQUENCE, vout: 0, network });
}

/** Node transactions one `TIME_LOCK_INTERVAL` below `currentTx`'s input sequence. */
export function createDecrementedTimelockNodeTx(
  parentTx: Uint8Array,
  currentTx: Uint8Array,
  network: SparkNetwork,
): NodeTxPair {
  const current = parseTransaction(currentTx);
  const input = current.getInput(0);
  const { sequence } = input;
  if (sequence === undefined) {
    throw new SparkInputError("currentTx: input 0 has no sequence");
  }
  return createNodeTxs({
    parentTx,
    sequence: getNextTransactionSequence(sequence).nextSequence,
    vout: 0,
    network,
  });
}

export type RefundTxsParams = {
  readonly nodeTx: Uint8Array;
  readonly directNodeTx?: Uint8Array | undefined;
  readonly receivingPublicKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly sequence: number;
  /** Rounds the timelock down to a `TIME_LOCK_INTERVAL` multiple, keeping bit 30. */
  readonly enforceTimelocks?: boolean | undefined;
};

/**
 * The refund trio for a node transaction. With `enforceTimelocks`, the sequence's timelock is first
 * rounded down to the interval grid (upstream behaviour when renewing); a zero-timelock node tx
 * never produces a direct refund.
 */
export function createRefundTxs(params: RefundTxsParams): RefundTxTrio {
  let { sequence } = params;
  if (params.enforceTimelocks === true) {
    sequence =
      roundDownToTimelockInterval(getTimelockFromSequence(sequence), TIME_LOCK_INTERVAL) |
      (sequence & (1 << 30));
  }
  const directSequence = sequence + DIRECT_TIMELOCK_OFFSET;
  const node = parseTransaction(params.nodeTx);
  const nodeInput = node.getInput(0);
  const nodeSequence = nodeInput.sequence;
  if (nodeSequence === undefined) {
    throw new SparkInputError("nodeTx: input 0 has no sequence");
  }
  const directNodeTx = isZeroTimelock(nodeSequence) ? undefined : params.directNodeTx;
  return constructRefundTxTrio(
    params.nodeTx,
    directNodeTx,
    0,
    params.receivingPublicKey,
    params.network,
    sequence,
    directSequence,
    DEFAULT_FEE_SATS,
  );
}

/** Refund trio at `INITIAL_SEQUENCE`. */
export function createInitialTimelockRefundTxs(
  params: Omit<RefundTxsParams, "sequence" | "enforceTimelocks">,
): RefundTxTrio {
  return createRefundTxs({ ...params, sequence: INITIAL_SEQUENCE });
}

/** Refund trio one interval below `sequence`, rounded to the interval grid. */
export function createDecrementedTimelockRefundTxs(params: RefundTxsParams): RefundTxTrio {
  const { nextSequence } = getNextTransactionSequence(params.sequence);
  return createRefundTxs({ ...params, sequence: nextSequence, enforceTimelocks: true });
}

/** Refund trio at the current timelock, rounded down to the interval grid. */
export function createCurrentTimelockRefundTxs(params: RefundTxsParams): RefundTxTrio {
  return createRefundTxs({ ...params, enforceTimelocks: true });
}

export type ConnectorRefundTxsParams = RefundTxsParams & {
  /**
   * Connector output appended as a second input to every refund variant. `txid` is in display
   * order; `sequence` defaults to btc-signer's final sequence when omitted.
   */
  readonly connectorInput: {
    readonly txid: Uint8Array;
    readonly index: number;
    readonly sequence?: number | undefined;
  };
};

/**
 * The decremented refund trio plus the connector input appended to each transaction. The connector
 * changes every input commitment, so the returned transactions must be re-signed via
 * `taprootKeySpendSighash` with both prevouts — the sibling `sighash` fields describe the one-input
 * forms.
 */
export function createConnectorRefundTxs(params: ConnectorRefundTxsParams): {
  cpfpRefundTx: Uint8Array;
  directRefundTx: Uint8Array | undefined;
  directFromCpfpRefundTx: Uint8Array;
} {
  const { connectorInput, ...base } = params;
  assertU32(connectorInput.index, "connectorInput.index");
  if (connectorInput.txid.length !== 32) {
    throw new SparkInputError("connectorInput.txid: must be 32 bytes");
  }
  const trio = createDecrementedTimelockRefundTxs(base);
  const splice = (txBytes: Uint8Array): Uint8Array => {
    const tx = parseTransaction(txBytes);
    tx.addInput({
      txid: connectorInput.txid,
      index: connectorInput.index,
      ...(connectorInput.sequence === undefined ? {} : { sequence: connectorInput.sequence }),
    });
    return tx.toBytes(true);
  };
  return {
    cpfpRefundTx: splice(trio.cpfpRefund.txBytes),
    directRefundTx: trio.directRefund === undefined ? undefined : splice(trio.directRefund.txBytes),
    directFromCpfpRefundTx: splice(trio.directFromCpfpRefund.txBytes),
  };
}

/**
 * Consolidates deposit UTXOs (all paying the same address) into one root output plus the ephemeral
 * anchor. Inputs keep the caller's order; the output reuses the first deposit output's script and
 * the summed amount.
 */
export function createMultiInputRootTx(
  depositTxs: ReadonlyArray<{ tx: Uint8Array; vout: number }>,
): Uint8Array {
  if (depositTxs.length === 0) {
    throw new SparkInputError("depositTxs: must not be empty");
  }
  const tx = new Transaction({ version: 3, allowUnknownOutputs: true });
  let total = 0;
  let firstScript: Uint8Array | undefined;
  for (const { tx: txBytes, vout } of depositTxs) {
    const prevOut = prevOutAt(parseTransaction(txBytes), vout);
    tx.addInput({ txid: txIdInputBytes(txBytes), index: vout, sequence: ZERO_SEQUENCE });
    firstScript ??= prevOut.script;
    total += prevOut.amountSats;
    assertSats(total, "totalAmount");
  }
  if (firstScript === undefined) {
    throw new SparkInputError("depositTxs: must not be empty");
  }
  tx.addOutput({ script: firstScript, amount: BigInt(total) });
  tx.addOutput({ script: EPHEMERAL_ANCHOR_SCRIPT, amount: 0n });
  return tx.toBytes(true);
}

/** Rough vbytes estimate used for fee planning: 10 + 150/input + 34/output. */
export function estimateVbytes(numInputs: number, numOutputs: number): number {
  return 10 + numInputs * 150 + numOutputs * 34;
}
