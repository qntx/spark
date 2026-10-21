import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import { constructHtlcTransaction, LIGHTNING_HTLC_SEQUENCE } from "../src/core/bitcoin/htlc.ts";
import { p2trScriptFromPublicKey, p2wpkhAddressFromPublicKey } from "../src/core/bitcoin/index.ts";
import { txIdInputBytes } from "../src/core/bitcoin/transactions.ts";
import { sweepHtlcTimeout } from "../src/lightning/htlc-timeout.ts";
import type { HtlcTimeoutSignRequest, SparkSigner } from "../src/signer/types.ts";
import { createTestSigner } from "./support/test-signer.ts";

const SSP_IDENTITY = secp256k1.getPublicKey(new Uint8Array(32).fill(0x53), true);
const PAYMENT_HASH = new Uint8Array(32).fill(0x99);
const DESTINATION = p2wpkhAddressFromPublicKey(
  secp256k1.getPublicKey(new Uint8Array(32).fill(0x44), true),
  "regtest",
);

function required<T>(value: T | undefined, name: string): T {
  if (value === undefined) {
    throw new Error(`${name}: missing`);
  }
  return value;
}

function parentTx(amountSats: bigint): Uint8Array {
  const tx = new Transaction({ allowUnknownOutputs: true });
  tx.addInput({ txid: new Uint8Array(32).fill(7), index: 0 });
  tx.addOutput({ script: p2trScriptFromPublicKey(SSP_IDENTITY, "regtest"), amount: amountSats });
  return tx.toBytes(true);
}

function htlcTx(identity: Uint8Array, amountSats: bigint): Uint8Array {
  return constructHtlcTransaction(
    parentTx(amountSats),
    0,
    0,
    PAYMENT_HASH,
    SSP_IDENTITY,
    identity,
    LIGHTNING_HTLC_SEQUENCE,
    false,
    0,
  ).txBytes;
}

function baseOptions(
  identity: Uint8Array,
  overrides?: Partial<{
    htlcTx: Uint8Array;
    vout: number;
    paymentHash: Uint8Array;
    destinationAddress: string;
    feeRateSatPerVbyte: number;
  }>,
) {
  return {
    htlcTx: overrides?.htlcTx ?? htlcTx(identity, 100_000n),
    vout: overrides?.vout ?? 0,
    paymentHash: overrides?.paymentHash ?? PAYMENT_HASH,
    destinationAddress: overrides?.destinationAddress ?? DESTINATION,
    feeRateSatPerVbyte: overrides?.feeRateSatPerVbyte ?? 2,
  };
}

describe("sweepHtlcTimeout", () => {
  test("signs the sequence-lock spend and passes the HTLC details to the signer", async () => {
    const signer = createTestSigner(new Uint8Array(32).fill(0x11));
    const identity = await signer.identityPublicKey();
    let request: HtlcTimeoutSignRequest | undefined;
    const wrapped: SparkSigner = {
      ...signer,
      signHtlcTimeout: async (req) => {
        request = req;
        return Promise.resolve(new Uint8Array(64).fill(0x42));
      },
    };
    const tx = htlcTx(identity, 100_000n);
    const signed = await sweepHtlcTimeout(
      { signer: wrapped, sspIdentityPublicKey: SSP_IDENTITY },
      baseOptions(identity, { htlcTx: tx }),
    );

    const req = required(request, "signHtlcTimeout request");
    expect(req.inputIndex).toBe(0);
    expect(req.prevoutAmountSats).toBe(100_000);
    expect(req.paymentHash).toStrictEqual(PAYMENT_HASH);
    expect(req.hashLockPublicKey).toStrictEqual(SSP_IDENTITY);

    const spend = Transaction.fromRaw(signed, { allowUnknownOutputs: true });
    const input = spend.getInput(0);
    expect(bytesToHex(required(input.txid, "sweep input txid"))).toBe(
      bytesToHex(txIdInputBytes(tx)),
    );
    expect(input.index).toBe(0);
    expect(Number(input.sequence)).toBe(LIGHTNING_HTLC_SEQUENCE);
    expect(spend.outputsLength).toBe(1);
    signer.dispose();
  });

  test("rejects a non-positive fee rate", async () => {
    const signer = createTestSigner(new Uint8Array(32).fill(0x11));
    const identity = await signer.identityPublicKey();
    await expect(
      sweepHtlcTimeout(
        { signer, sspIdentityPublicKey: SSP_IDENTITY },
        baseOptions(identity, { feeRateSatPerVbyte: 0 }),
      ),
    ).rejects.toThrow("feeRateSatPerVbyte: must be a positive finite number");
    signer.dispose();
  });

  test("rejects a vout outside the transaction's outputs", async () => {
    const signer = createTestSigner(new Uint8Array(32).fill(0x11));
    const identity = await signer.identityPublicKey();
    await expect(
      sweepHtlcTimeout(
        { signer, sspIdentityPublicKey: SSP_IDENTITY },
        baseOptions(identity, { vout: 5 }),
      ),
    ).rejects.toThrow("vout: out of range");
    signer.dispose();
  });

  test("rejects an output that is not the Lightning HTLC script", async () => {
    const signer = createTestSigner(new Uint8Array(32).fill(0x11));
    const identity = await signer.identityPublicKey();
    await expect(
      sweepHtlcTimeout(
        { signer, sspIdentityPublicKey: SSP_IDENTITY },
        baseOptions(identity, { htlcTx: parentTx(100_000n) }),
      ),
    ).rejects.toThrow("does not match the Lightning HTLC script");
    signer.dispose();
  });

  test("rejects a sweep whose output would be dust", async () => {
    const signer = createTestSigner(new Uint8Array(32).fill(0x11));
    const identity = await signer.identityPublicKey();
    await expect(
      sweepHtlcTimeout(
        { signer, sspIdentityPublicKey: SSP_IDENTITY },
        baseOptions(identity, { htlcTx: htlcTx(identity, 400n), feeRateSatPerVbyte: 10 }),
      ),
    ).rejects.toThrow("below the");
    signer.dispose();
  });
});
