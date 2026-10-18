import { equalBytes } from "@noble/curves/utils.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";

import { SparkInputError } from "../../errors/index.ts";
import { assertSats, assertU32 } from "../assert.ts";
import { EPHEMERAL_ANCHOR_SCRIPT } from "./script.ts";
import { parseTransaction } from "./sighash.ts";
import type { SigningTarget } from "./sighash.ts";
import { txIdInputBytes } from "./transactions.ts";

// CPFP package construction for unilateral exit: the pre-signed Spark node/refund
// transactions are zero-fee v3 (TRUC) transactions carrying a 0-value P2A anchor.
// A confirmed wallet UTXO funds a v3 child that spends the anchor; the package is
// broadcast together so the parent's fee is paid by the child.

/** TRUC (v3) transactions cap the child at 1000 virtual bytes. */
const TRUC_CHILD_MAX_VSIZE = 1000;

/** Whether `script` is a segwit program (`OP_0`/`OP_1..16` + 2..40-byte program). */
function isWitnessProgram(script: Uint8Array): boolean {
  const [first, programLength] = script;
  return (
    script.length >= 4 &&
    script.length <= 42 &&
    (first === 0x00 || (first !== undefined && first >= 0x51 && first <= 0x60)) &&
    programLength !== undefined &&
    programLength >= 2 &&
    script.length === 2 + programLength
  );
}

/**
 * Bitcoin Core's dust rule at the 3 sat/vB relay floor: `3 × (output size + spend size)` where the
 * output serializes to `8 + 1 + script.length` bytes and the spend is estimated at 67 vB for
 * witness programs, 148 vB otherwise (294 sats for P2WPKH, 330 for P2TR).
 */
export function dustLimit(script: Uint8Array): number {
  const spendVbytes = isWitnessProgram(script) ? 67 : 148;
  return 3 * (8 + 1 + script.length + spendVbytes);
}

function assertFeeRate(feeRateSatPerVbyte: number): void {
  if (!Number.isFinite(feeRateSatPerVbyte) || feeRateSatPerVbyte <= 0) {
    throw new SparkInputError("feeRateSatPerVbyte: must be a positive finite number");
  }
}

export type FundingInput = {
  /** Display-order hex txid of the confirmed funding output. */
  readonly txid: string;
  readonly vout: number;
  /** Witness program scriptPubKey (P2WPKH, P2TR, …). */
  readonly script: Uint8Array;
  readonly amountSats: number;
  /** Caller's upper bound for this input once signed (68 vB P2WPKH, 58 vB P2TR). */
  readonly signedInputVbytes: number;
};

/**
 * Builds the unsigned fee-paying child for a zero-fee v3 parent: inputs are the caller's confirmed
 * funding UTXOs (kept in the given order — a TRUC child may have only one unconfirmed ancestor, so
 * funding must be confirmed) followed by the parent's P2A anchor carrying only its `witness_utxo`.
 * Signing software finalizes the anyone-can-spend anchor with an empty witness (Bitcoin Core's
 * `walletprocesspsbt`/`finalizepsbt` does), so only the funding inputs need signatures. Returns the
 * PSBT, the package fee (covering parent + child at `feeRateSatPerVbyte`), and the estimated child
 * vsize.
 */
export function buildCpfpChild(options: {
  readonly parent: Uint8Array;
  readonly funding: ReadonlyArray<FundingInput>;
  readonly changeScript: Uint8Array;
  readonly feeRateSatPerVbyte: number;
}): { readonly psbt: Uint8Array; readonly feeSats: number; readonly vsize: number } {
  const { parent, funding, changeScript, feeRateSatPerVbyte } = options;
  assertFeeRate(feeRateSatPerVbyte);
  if (changeScript.length === 0) {
    throw new SparkInputError("changeScript: must not be empty");
  }
  if (funding.length === 0) {
    throw new SparkInputError("funding: at least one confirmed input is required");
  }
  for (const input of funding) {
    assertU32(input.vout, "funding.vout");
    assertSats(input.amountSats, "funding.amountSats");
    if (!Number.isSafeInteger(input.signedInputVbytes) || input.signedInputVbytes <= 0) {
      throw new SparkInputError("funding.signedInputVbytes: must be a positive safe integer");
    }
    if (!/^[0-9a-f]{64}$/i.test(input.txid)) {
      throw new SparkInputError("funding.txid: must be 32-byte display-order hex");
    }
    if (!isWitnessProgram(input.script)) {
      throw new SparkInputError("funding.script: must be a witness program (P2WPKH, P2TR, …)");
    }
  }

  const parentTx = parseTransaction(parent);
  let anchorVout: number | undefined;
  for (let i = 0; i < parentTx.outputsLength; i++) {
    const output = parentTx.getOutput(i);
    if (
      output.script !== undefined &&
      output.amount === 0n &&
      equalBytes(output.script, EPHEMERAL_ANCHOR_SCRIPT)
    ) {
      anchorVout = i;
      break;
    }
  }
  if (anchorVout === undefined) {
    throw new SparkInputError("parent: no 0-value P2A anchor output found");
  }

  const fundingVbytes = funding.reduce((total, input) => total + input.signedInputVbytes, 0);
  // 10.5 = version/marker/flag/counts/locktime; 41 = anchor input (outpoint 36 +
  // script len 1 + sequence 4) with an empty witness; output = 8 + 1 + script len.
  const vsize = Math.ceil(10.5 + fundingVbytes + 41 + (8 + 1 + changeScript.length));
  if (vsize > TRUC_CHILD_MAX_VSIZE) {
    throw new SparkInputError(
      `cpfp child: estimated ${vsize} vB exceeds the TRUC ${TRUC_CHILD_MAX_VSIZE} vB limit`,
    );
  }
  // scure's .vsize requires every input finalized; weight the parent from its
  // raw serialization instead (base×3 + total)/4, valid with or without witness.
  const parentBytes = parentTx.toBytes(true, true);
  const parentBase = parentTx.toBytes(true, false);
  const parentVsize = Math.ceil((parentBase.length * 3 + parentBytes.length) / 4);
  const feeSats = Math.ceil(feeRateSatPerVbyte * (parentVsize + vsize));
  const fundedSats = funding.reduce((total, input) => total + input.amountSats, 0);
  const changeSats = fundedSats - feeSats;
  const dust = dustLimit(changeScript);
  if (changeSats < dust) {
    throw new SparkInputError(
      `cpfp child: change ${changeSats} sats is below the ${dust} sat dust limit`,
    );
  }

  const child = new Transaction({
    version: 3,
    lockTime: 0,
    allowUnknownInputs: true,
    allowUnknownOutputs: true,
    disableScriptCheck: true,
  });
  for (const input of funding) {
    child.addInput({
      txid: hexToBytes(input.txid),
      index: input.vout,
      witnessUtxo: { script: input.script, amount: BigInt(input.amountSats) },
    });
  }
  child.addInput({
    txid: txIdInputBytes(parent),
    index: anchorVout,
    witnessUtxo: { script: EPHEMERAL_ANCHOR_SCRIPT, amount: 0n },
  });
  child.addOutput({ script: changeScript, amount: BigInt(changeSats) });
  return { psbt: child.toPSBT(), feeSats, vsize };
}

/**
 * Builds a v2 key-path sweep of `prevTx:vout` (a confirmed refund output) to `destinationScript`,
 * charging `fee = ceil(feeRate × vsize)` against the prevout amount. The returned `target` is what
 * `signer.signKeySpend` signs.
 */
export function buildKeySpendSweep(options: {
  readonly prevTx: Uint8Array;
  readonly vout: number;
  readonly destinationScript: Uint8Array;
  readonly feeRateSatPerVbyte: number;
}): { readonly transaction: Uint8Array; readonly target: SigningTarget; readonly feeSats: number } {
  const { prevTx, vout, destinationScript, feeRateSatPerVbyte } = options;
  assertFeeRate(feeRateSatPerVbyte);
  if (destinationScript.length === 0) {
    throw new SparkInputError("destinationScript: must not be empty");
  }
  const prev = parseTransaction(prevTx);
  if (!Number.isSafeInteger(vout) || vout < 0 || vout >= prev.outputsLength) {
    throw new SparkInputError("vout: out of range for the previous transaction's outputs");
  }
  const prevOut = prev.getOutput(vout);
  if (prevOut.script === undefined || prevOut.amount === undefined) {
    throw new SparkInputError("vout: output is missing its script or amount");
  }
  const amountSats = Number(prevOut.amount);
  assertSats(amountSats, "prevTx amount");

  // 10.5 overhead + 58 vB taproot key-path input + output.
  const vsize = Math.ceil(10.5 + 58 + (8 + 1 + destinationScript.length));
  const feeSats = Math.ceil(feeRateSatPerVbyte * vsize);
  const dust = dustLimit(destinationScript);
  const outSats = amountSats - feeSats;
  if (outSats < dust) {
    throw new SparkInputError(
      `key-spend sweep: output ${outSats} sats is below the ${dust} sat dust limit`,
    );
  }

  const tx = new Transaction({ version: 2, lockTime: 0, allowUnknownOutputs: true });
  tx.addInput({
    txid: txIdInputBytes(prevTx),
    index: vout,
    witnessUtxo: { script: prevOut.script, amount: prevOut.amount },
  });
  tx.addOutput({ script: destinationScript, amount: BigInt(outSats) });
  const transaction = tx.toBytes(true);
  return {
    transaction,
    target: {
      transaction,
      inputIndex: 0,
      prevouts: [{ script: prevOut.script, amount: amountSats }],
    },
    feeSats,
  };
}

/**
 * Attaches the 64-byte BIP-340 key-path signature as input 0's single witness element and returns
 * the network-serialized signed transaction.
 */
export function finalizeKeySpend(transaction: Uint8Array, signature: Uint8Array): Uint8Array {
  if (signature.length !== 64) {
    throw new SparkInputError("signature: must be a 64-byte schnorr signature");
  }
  const tx = parseTransaction(transaction);
  tx.updateInput(0, { finalScriptWitness: [signature] });
  // toBytes(withScriptSig, withWitness): the signed sweep needs the witness.
  return tx.toBytes(true, true);
}
