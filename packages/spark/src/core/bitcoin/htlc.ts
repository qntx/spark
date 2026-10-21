import {
  p2tr,
  Script,
  ScriptNum,
  SigHash,
  TaprootControlBlock,
  taprootListToTree,
  Transaction,
} from "@scure/btc-signer";
import type { ScriptType } from "@scure/btc-signer";

import { SparkInputError } from "../../errors/index.ts";
import { EPHEMERAL_ANCHOR_SCRIPT, xOnlyPublicKey } from "./script.ts";
import { checkIfValidSequence, DEFAULT_FEE_SATS } from "./sequence.ts";
import { parseTransaction, taprootScriptSpendSighash } from "./sighash.ts";
import { maybeApplyFee, txIdInputBytes } from "./transactions.ts";
import type { ConstructedTransaction } from "./transactions.ts";

// Lightning HTLC transactions and spends. Upstream references:
// signer/spark-frost/src/htlc.rs (authoritative) and
// sdks/js/packages/spark-sdk/src/utils/htlc-transactions.ts (buildonspark/spark@0b3a32a).

/** X-only taproot NUMS internal key — unspendable key-path for HTLC outputs. */
export const NUMS_INTERNAL_KEY: Uint8Array = new Uint8Array([
  0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
  0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
]);

export const LIGHTNING_HTLC_SEQUENCE = 2160;

/** `OP_SHA256 <32-byte hash> OP_EQUALVERIFY <x-only pubkey> OP_CHECKSIG`. */
export function createHashLockScript(paymentHash: Uint8Array, publicKey: Uint8Array): Uint8Array {
  if (paymentHash.length !== 32) {
    throw new SparkInputError("paymentHash: must be 32 bytes");
  }
  return Script.encode([
    "SHA256",
    paymentHash,
    "EQUALVERIFY",
    xOnlyPublicKey(publicKey),
    "CHECKSIG",
  ]);
}

/** `<sequence> OP_CHECKSEQUENCEVERIFY OP_DROP <x-only pubkey> OP_CHECKSIG`. */
export function createSequenceLockScript(sequence: number, publicKey: Uint8Array): Uint8Array {
  const elements: ScriptType =
    sequence <= 16
      ? [sequence, "CHECKSEQUENCEVERIFY", "DROP", xOnlyPublicKey(publicKey), "CHECKSIG"]
      : [
          ScriptNum().encode(BigInt(sequence)),
          "CHECKSEQUENCEVERIFY",
          "DROP",
          xOnlyPublicKey(publicKey),
          "CHECKSIG",
        ];
  return Script.encode(elements);
}

type TapLeafEntry = NonNullable<ReturnType<typeof p2tr>["tapLeafScript"]>[number];

type HtlcP2tr = {
  readonly script: Uint8Array;
  readonly leafScripts: ReadonlyArray<TapLeafEntry>;
};

/**
 * Two-leaf taproot tree (hash-lock leaf first, sequence-lock leaf second) on the NUMS internal key
 * — the HTLC output structure. The output script does not depend on the network, so upstream's
 * `network` parameter is not needed here.
 */
function htlcP2tr(hashLockScript: Uint8Array, sequenceLockScript: Uint8Array): HtlcP2tr {
  const tree = taprootListToTree([
    { leafVersion: 0xc0, script: hashLockScript },
    { leafVersion: 0xc0, script: sequenceLockScript },
  ]);
  const p2 = p2tr(NUMS_INTERNAL_KEY, tree, undefined, true);
  const { script } = p2;
  const leafScripts = p2.tapLeafScript;
  if (script === undefined || leafScripts === undefined || leafScripts.length !== 2) {
    throw new SparkInputError("htlc: failed to build the two-leaf taproot tree");
  }
  return { script, leafScripts };
}

function findLeafScript(
  leafScripts: ReadonlyArray<TapLeafEntry>,
  leafScript: Uint8Array,
): TapLeafEntry {
  for (const entry of leafScripts) {
    const [, versionedScript] = entry;
    // The leaf encoding is script bytes followed by the leaf version.
    if (versionedScript.length === leafScript.length + 1) {
      let same = versionedScript.at(-1) === 0xc0;
      for (let i = 0; i < leafScript.length && same; i += 1) {
        same = versionedScript[i] === leafScript[i];
      }
      if (same) {
        return entry;
      }
    }
  }
  throw new SparkInputError("htlc: leaf script not present in the taproot tree");
}

/**
 * The HTLC refund transaction's output 0 script — the two-leaf NUMS-keyed P2TR every
 * `createRefundTxsForLightning` variant carries, built exactly as `constructHtlcTransaction` builds
 * it (hash-lock leaf first, `LIGHTNING_HTLC_SEQUENCE` CSV leaf second). Comparing it against a
 * committed refund's output 0 binds the payment hash and both destination keys without rebuilding
 * the whole transaction: the input sequence, prevout and fee never enter the script.
 */
export function lightningHtlcOutputScript(
  paymentHash: Uint8Array,
  hashLockPublicKey: Uint8Array,
  sequenceLockPublicKey: Uint8Array,
): Uint8Array {
  return htlcP2tr(
    createHashLockScript(paymentHash, hashLockPublicKey),
    createSequenceLockScript(LIGHTNING_HTLC_SEQUENCE, sequenceLockPublicKey),
  ).script;
}

export type HtlcSpend = ConstructedTransaction & {
  /** The tapscript leaf the input witnesses (hash-lock or sequence-lock script). */
  readonly script: Uint8Array;
  /** Taproot control block proving that leaf against the NUMS internal key. */
  readonly controlBlock: Uint8Array;
};

/**
 * HTLC transaction spending `nodeTx`'s `vout` into the two-leaf NUMS-keyed P2TR output plus the
 * ephemeral anchor. `sequence` is the input's relative timelock; `htlcSequence` is the
 * sequence-lock leaf's CSV delay.
 */
export function constructHtlcTransaction(
  nodeTx: Uint8Array,
  vout: number,
  sequence: number,
  paymentHash: Uint8Array,
  hashLockPublicKey: Uint8Array,
  sequenceLockPublicKey: Uint8Array,
  htlcSequence: number,
  applyFee: boolean,
  feeSats: number,
): ConstructedTransaction {
  checkIfValidSequence(sequence);
  checkIfValidSequence(htlcSequence);
  const node = parseTransaction(nodeTx);
  if (!Number.isSafeInteger(vout) || vout < 0 || vout >= node.outputsLength) {
    throw new SparkInputError("vout: out of range for the node transaction's outputs");
  }
  const output = node.getOutput(vout);
  const prevAmount = output.amount;
  const prevScript = output.script;
  if (prevAmount === undefined || prevScript === undefined) {
    throw new SparkInputError("vout: node transaction output is missing script or amount");
  }
  const outAmount = applyFee ? maybeApplyFee(Number(prevAmount), feeSats) : prevAmount;

  const hashLockScript = createHashLockScript(paymentHash, hashLockPublicKey);
  const sequenceLockScript = createSequenceLockScript(htlcSequence, sequenceLockPublicKey);
  const { script } = htlcP2tr(hashLockScript, sequenceLockScript);

  const tx = new Transaction({ version: 3, allowUnknownOutputs: true });
  tx.addInput({ txid: txIdInputBytes(nodeTx), index: vout, sequence });
  tx.addOutput({ script, amount: BigInt(outAmount) });
  if (!applyFee) {
    tx.addOutput({ script: EPHEMERAL_ANCHOR_SCRIPT, amount: 0n });
  }

  const txBytes = tx.toBytes(true);
  const sighash = tx.preimageWitnessV1(0, [prevScript], SigHash.DEFAULT, [prevAmount]);
  return { txBytes, sighash };
}

function buildHtlcSpend(
  htlcTx: Uint8Array,
  vout: number,
  destinationScript: Uint8Array,
  paymentHash: Uint8Array,
  hashLockPublicKey: Uint8Array,
  sequenceLockPublicKey: Uint8Array,
  htlcSequence: number,
  inputSequence: number,
  spendLeafScript: Uint8Array,
  feeSats: number,
): HtlcSpend {
  checkIfValidSequence(htlcSequence);
  if (destinationScript.length === 0) {
    throw new SparkInputError("destinationScript: must not be empty");
  }
  const node = parseTransaction(htlcTx);
  if (!Number.isSafeInteger(vout) || vout < 0 || vout >= node.outputsLength) {
    throw new SparkInputError("vout: out of range for the HTLC transaction's outputs");
  }
  const output = node.getOutput(vout);
  const prevAmount = output.amount;
  const prevScript = output.script;
  if (prevAmount === undefined || prevScript === undefined) {
    throw new SparkInputError("vout: HTLC output is missing script or amount");
  }
  const outAmount = maybeApplyFee(Number(prevAmount), feeSats);
  const hashLockScript = createHashLockScript(paymentHash, hashLockPublicKey);
  const sequenceLockScript = createSequenceLockScript(htlcSequence, sequenceLockPublicKey);
  const { leafScripts } = htlcP2tr(hashLockScript, sequenceLockScript);
  const [controlBlockData] = findLeafScript(leafScripts, spendLeafScript);

  const tx = new Transaction({ version: 3, allowUnknownOutputs: true });
  tx.addInput({ txid: txIdInputBytes(htlcTx), index: vout, sequence: inputSequence });
  tx.addOutput({
    script: destinationScript,
    amount: BigInt(outAmount),
  });
  const txBytes = tx.toBytes(true);
  const sighash = taprootScriptSpendSighash(
    {
      transaction: txBytes,
      inputIndex: 0,
      prevouts: [{ script: prevScript, amount: Number(prevAmount) }],
    },
    spendLeafScript,
  );
  return {
    txBytes,
    sighash,
    script: spendLeafScript,
    controlBlock: TaprootControlBlock.encode(controlBlockData),
  };
}

/**
 * Timeout path: spends `htlcTx`'s `vout` output through the sequence-lock leaf to
 * `destinationScript`. Input sequence equals `htlcSequence` so the leaf's CSV is satisfied.
 */
export function constructHtlcSenderSpend(
  htlcTx: Uint8Array,
  vout: number,
  destinationScript: Uint8Array,
  paymentHash: Uint8Array,
  hashLockPublicKey: Uint8Array,
  sequenceLockPublicKey: Uint8Array,
  htlcSequence: number,
  feeSats: number,
): HtlcSpend {
  const spendLeafScript = createSequenceLockScript(htlcSequence, sequenceLockPublicKey);
  return buildHtlcSpend(
    htlcTx,
    vout,
    destinationScript,
    paymentHash,
    hashLockPublicKey,
    sequenceLockPublicKey,
    htlcSequence,
    htlcSequence,
    spendLeafScript,
    feeSats,
  );
}

/**
 * Preimage path: spends `htlcTx`'s `vout` output through the hash-lock leaf to `destinationScript`.
 * The input sequence is 0xffffffff (final).
 */
export function constructHtlcReceiverSpend(
  htlcTx: Uint8Array,
  vout: number,
  destinationScript: Uint8Array,
  paymentHash: Uint8Array,
  hashLockPublicKey: Uint8Array,
  sequenceLockPublicKey: Uint8Array,
  htlcSequence: number,
  feeSats: number,
): HtlcSpend {
  const spendLeafScript = createHashLockScript(paymentHash, hashLockPublicKey);
  return buildHtlcSpend(
    htlcTx,
    vout,
    destinationScript,
    paymentHash,
    hashLockPublicKey,
    sequenceLockPublicKey,
    htlcSequence,
    0xff_ff_ff_ff,
    spendLeafScript,
    feeSats,
  );
}

/**
 * Attaches the 64-byte BIP-340 leaf signature plus the spend's leaf script and control block as
 * input 0's witness — `<sig> <script> <control block>` — and returns the network-serialized signed
 * spend.
 */
export function finalizeHtlcSpend(spend: HtlcSpend, signature: Uint8Array): Uint8Array {
  if (signature.length !== 64) {
    throw new SparkInputError("signature: must be a 64-byte schnorr signature");
  }
  const tx = parseTransaction(spend.txBytes);
  tx.updateInput(0, {
    finalScriptWitness: [signature, spend.script, spend.controlBlock],
  });
  return tx.toBytes(true, true);
}

export type RefundTxsForLightningParams = {
  readonly nodeTx: Uint8Array;
  readonly directNodeTx?: Uint8Array | undefined;
  readonly vout: number;
  readonly sequence: number;
  /** Direct variants' sequence, already offset (see `getNextHTLCTransactionSequence`). */
  readonly directSequence: number;
  readonly paymentHash: Uint8Array;
  readonly hashLockDestinationPublicKey: Uint8Array;
  readonly sequenceLockDestinationPublicKey: Uint8Array;
  readonly feeSats?: number | undefined;
};

export type RefundTxsForLightning = {
  readonly cpfpRefundTx: { readonly txBytes: Uint8Array; readonly sighash: Uint8Array };
  readonly directRefundTx:
    | { readonly txBytes: Uint8Array; readonly sighash: Uint8Array }
    | undefined;
  readonly directFromCpfpRefundTx: { readonly txBytes: Uint8Array; readonly sighash: Uint8Array };
};

/**
 * CPFP + direct HTLC refund transactions spending a node tx into the HTLC output (sender side of a
 * Lightning transfer). Mirrors the upstream TS `createRefundTxsForLightning` composition.
 */
export function createRefundTxsForLightning(
  params: RefundTxsForLightningParams,
): RefundTxsForLightning {
  const feeSats = params.feeSats ?? DEFAULT_FEE_SATS;
  const cpfpRefundTx = constructHtlcTransaction(
    params.nodeTx,
    params.vout,
    params.sequence,
    params.paymentHash,
    params.hashLockDestinationPublicKey,
    params.sequenceLockDestinationPublicKey,
    LIGHTNING_HTLC_SEQUENCE,
    false,
    feeSats,
  );
  let directRefundTx: ConstructedTransaction | undefined;
  if (params.directSequence !== 0 && params.directNodeTx !== undefined) {
    directRefundTx = constructHtlcTransaction(
      params.directNodeTx,
      params.vout,
      params.directSequence,
      params.paymentHash,
      params.hashLockDestinationPublicKey,
      params.sequenceLockDestinationPublicKey,
      LIGHTNING_HTLC_SEQUENCE,
      true,
      feeSats,
    );
  }
  const directFromCpfpRefundTx = constructHtlcTransaction(
    params.nodeTx,
    params.vout,
    params.directSequence,
    params.paymentHash,
    params.hashLockDestinationPublicKey,
    params.sequenceLockDestinationPublicKey,
    LIGHTNING_HTLC_SEQUENCE,
    true,
    feeSats,
  );
  return { cpfpRefundTx, directRefundTx, directFromCpfpRefundTx };
}
