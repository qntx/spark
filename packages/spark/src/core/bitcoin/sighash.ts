import { SigHash, Transaction } from "@scure/btc-signer";

import { SparkInputError } from "../../errors/index.ts";

// BIP-341/342 sighash computation. Upstream references:
// signer/spark-frost/src/transaction.rs (`compute_multi_input_sighash` and the
// single-input sighash inside `build_single_output_tx` — both are the same
// BIP-341 digest with a `Prevouts::All` commitment) and htlc.rs
// (`taproot_script_spend_signature_hash` for HTLC spends).

const MAX_SATS = 2_100_000_000_000_000;

function assertSats(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_SATS) {
    throw new SparkInputError(`${field}: must be a non-negative satoshi amount (<= ${MAX_SATS})`);
  }
}

/** A transaction to sign: raw bytes plus every input's prevout script and amount. */
export type SigningTarget = {
  readonly transaction: Uint8Array;
  readonly inputIndex: number;
  readonly prevouts: ReadonlyArray<{ script: Uint8Array; amount: number }>;
};

/** Parses raw transaction bytes, tolerating nonstandard outputs (P2A anchors). */
export function parseTransaction(bytes: Uint8Array): Transaction {
  try {
    return Transaction.fromRaw(bytes, { allowUnknownOutputs: true });
  } catch (error) {
    throw new SparkInputError("transaction: failed to parse raw transaction", { cause: error });
  }
}

/** Internal: BIP-341 sighash over an already-parsed transaction. */
export function keySpendSighash(
  tx: Transaction,
  inputIndex: number,
  prevouts: ReadonlyArray<{ script: Uint8Array; amount: number }>,
): Uint8Array {
  if (!Number.isSafeInteger(inputIndex) || inputIndex < 0 || inputIndex >= tx.inputsLength) {
    throw new SparkInputError("inputIndex: out of range for the transaction's inputs");
  }
  if (prevouts.length !== tx.inputsLength) {
    throw new SparkInputError("prevouts: must contain one entry per transaction input");
  }
  const scripts: Uint8Array[] = [];
  const amounts: bigint[] = [];
  for (const prevout of prevouts) {
    if (prevout.script.length === 0) {
      throw new SparkInputError("prevouts.script: must not be empty");
    }
    assertSats(prevout.amount, "prevouts.amount");
    scripts.push(prevout.script);
    amounts.push(BigInt(prevout.amount));
  }
  try {
    return tx.preimageWitnessV1(inputIndex, scripts, SigHash.DEFAULT, amounts);
  } catch (error) {
    throw new SparkInputError("sighash: taproot key-spend preimage failed", { cause: error });
  }
}

/**
 * BIP-341 key-spend sighash (SIGHASH_DEFAULT) for `inputIndex`, committing to all inputs' prevouts.
 * The single-input case is the same function with a one-element `prevouts` array.
 */
export function taprootKeySpendSighash(target: SigningTarget): Uint8Array {
  return keySpendSighash(parseTransaction(target.transaction), target.inputIndex, target.prevouts);
}

/**
 * BIP-342 script-path sighash for `inputIndex` spending via `leafScript` (tapscript leaf version
 * 0xc0). Used by the HTLC sender/receiver spends.
 */
export function taprootScriptSpendSighash(
  target: SigningTarget,
  leafScript: Uint8Array,
): Uint8Array {
  const tx = parseTransaction(target.transaction);
  const scripts: Uint8Array[] = [];
  const amounts: bigint[] = [];
  for (const prevout of target.prevouts) {
    assertSats(prevout.amount, "prevouts.amount");
    scripts.push(prevout.script);
    amounts.push(BigInt(prevout.amount));
  }
  if (!Number.isSafeInteger(target.inputIndex) || target.inputIndex < 0) {
    throw new SparkInputError("inputIndex: must be a non-negative integer");
  }
  try {
    return tx.preimageWitnessV1(
      target.inputIndex,
      scripts,
      SigHash.DEFAULT,
      amounts,
      -1,
      leafScript,
      0xc0,
    );
  } catch (error) {
    throw new SparkInputError("sighash: taproot script-spend preimage failed", { cause: error });
  }
}
