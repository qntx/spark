import { equalBytes } from "@noble/curves/utils.js";

import { dustLimit } from "../core/bitcoin/cpfp.ts";
import {
  constructHtlcSenderSpend,
  finalizeHtlcSpend,
  LIGHTNING_HTLC_SEQUENCE,
  lightningHtlcOutputScript,
} from "../core/bitcoin/htlc.ts";
import { parseTransaction } from "../core/bitcoin/sighash.ts";
import { bitcoinAddressScript } from "../core/bitcoin/transactions.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SparkInputError } from "../errors/index.ts";
import type { SparkSigner } from "../signer/types.ts";

// The sender's on-chain timeout path for a Lightning send: when the refund transaction of an
// in-flight send reaches the chain (the SSP never settled it), the funds sit in the two-leaf
// HTLC output until the sequence-lock leaf's LIGHTNING_HTLC_SEQUENCE CSV matures. This builds
// and signs that sweep; broadcasting stays with the caller.
// Known limitation: stored exit chains do not cover the HTLC outputs of in-flight Lightning
// sends, so there is no offline package for them — the caller must retain `htlcTx` (the
// committed cpfp/direct refund transaction) to sweep after the timeout.

/**
 * Signs the sender timeout spend of `htlcTx`'s `vout` — the HTLC output of a committed Lightning
 * refund transaction — to `destinationAddress`. Verifies the output is the Lightning HTLC script
 * for `paymentHash` with the SSP on the hash-lock leaf and this identity on the sequence-lock leaf,
 * then signs via `signer.signHtlcTimeout`. Returns the signed transaction UNBROADCAST; it relays
 * only once `htlcTx` has at least `LIGHTNING_HTLC_SEQUENCE` confirmations.
 */
export async function sweepHtlcTimeout(
  deps: {
    readonly signer: SparkSigner;
    /** 33-byte compressed SSP identity key — the hash-lock leaf key the send committed to. */
    readonly sspIdentityPublicKey: Uint8Array;
    /** The network `destinationAddress` must decode under — checked before any signing. */
    readonly network: SparkNetwork;
  },
  options: {
    /** The committed refund transaction carrying the HTLC output. */
    readonly htlcTx: Uint8Array;
    readonly vout: number;
    readonly paymentHash: Uint8Array;
    readonly destinationAddress: string;
    /** Fee rate in sats per virtual byte; no upper cap is enforced — the caller picks the value. */
    readonly feeRateSatPerVbyte: number;
  },
): Promise<Uint8Array> {
  if (!Number.isFinite(options.feeRateSatPerVbyte) || options.feeRateSatPerVbyte <= 0) {
    throw new SparkInputError("feeRateSatPerVbyte: must be a positive finite number");
  }
  const destinationScript = bitcoinAddressScript(options.destinationAddress, deps.network);
  const htlc = parseTransaction(options.htlcTx);
  if (
    !Number.isSafeInteger(options.vout) ||
    options.vout < 0 ||
    options.vout >= htlc.outputsLength
  ) {
    throw new SparkInputError("vout: out of range for the HTLC transaction's outputs");
  }
  const output = htlc.getOutput(options.vout);
  if (output.script === undefined || output.amount === undefined) {
    throw new SparkInputError("vout: HTLC output is missing script or amount");
  }
  const prevoutAmountSats = Number(output.amount);
  const identityPublicKey = await deps.signer.identityPublicKey();
  const expectedScript = lightningHtlcOutputScript(
    options.paymentHash,
    deps.sspIdentityPublicKey,
    identityPublicKey,
  );
  if (!equalBytes(output.script, expectedScript)) {
    throw new SparkInputError(
      "htlcTx: output does not match the Lightning HTLC script for this payment hash",
    );
  }
  const build = (feeSats: number) =>
    constructHtlcSenderSpend(
      options.htlcTx,
      options.vout,
      destinationScript,
      options.paymentHash,
      deps.sspIdentityPublicKey,
      identityPublicKey,
      LIGHTNING_HTLC_SEQUENCE,
      feeSats,
    );
  const draft = build(0);
  // Weight: the stripped transaction plus the `<sig> <script> <control block>` witness.
  const witnessBytes = 1 + (1 + 64) + (1 + draft.script.length) + (1 + draft.controlBlock.length);
  const vsize = Math.ceil((draft.txBytes.length * 4 + witnessBytes) / 4);
  const feeSats = Math.ceil(options.feeRateSatPerVbyte * vsize);
  const dust = dustLimit(destinationScript);
  const outSats = prevoutAmountSats - feeSats;
  if (outSats < dust) {
    throw new SparkInputError(
      `htlc timeout sweep: output ${outSats} sats is below the ${dust} sat dust limit`,
    );
  }
  const spend = feeSats === 0 ? draft : build(feeSats);
  const signature = await deps.signer.signHtlcTimeout({
    transaction: spend.txBytes,
    inputIndex: 0,
    prevoutAmountSats,
    paymentHash: options.paymentHash,
    hashLockPublicKey: deps.sspIdentityPublicKey,
  });
  return finalizeHtlcSpend(spend, signature);
}
