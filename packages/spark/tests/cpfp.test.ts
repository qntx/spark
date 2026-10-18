import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { Transaction, Address, OutScript } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import {
  buildCpfpChild,
  buildKeySpendSweep,
  dustLimit,
  EPHEMERAL_ANCHOR_SCRIPT,
  finalizeKeySpend,
  p2trScriptFromPublicKey,
  p2wpkhAddressFromPublicKey,
  txId,
  btcNetwork,
} from "../src/core/bitcoin/index.ts";

const KEY = secp256k1.getPublicKey(new Uint8Array(32).fill(9), true);
const P2TR_SCRIPT = p2trScriptFromPublicKey(KEY, "regtest");
const P2WPKH_SCRIPT = OutScript.encode(
  Address(btcNetwork("regtest")).decode(
    p2wpkhAddressFromPublicKey(secp256k1.getPublicKey(new Uint8Array(32).fill(5), true), "regtest"),
  ),
);

/** V3 parent spending a fake prevout, with one paying output and the P2A anchor. */
function fakeParent(anchorAmount: bigint): Uint8Array {
  const tx = new Transaction({ version: 3, allowUnknownOutputs: true });
  tx.addInput({ txid: new Uint8Array(32).fill(7), index: 0, sequence: 0 });
  tx.addOutput({ script: P2TR_SCRIPT, amount: 100_000n });
  tx.addOutput({ script: EPHEMERAL_ANCHOR_SCRIPT, amount: anchorAmount });
  return tx.toBytes(true);
}

const FUNDING_TXID = bytesToHex(new Uint8Array(32).fill(1));

function funding(options?: { txid?: string; vbytes?: number; amountSats?: number }) {
  return {
    txid: options?.txid ?? FUNDING_TXID,
    vout: 0,
    script: P2WPKH_SCRIPT,
    amountSats: options?.amountSats ?? 100_000,
    signedInputVbytes: options?.vbytes ?? 68,
  };
}

describe("dustLimit", () => {
  test("follows Bitcoin Core's 3 sat/vB rule", () => {
    expect(dustLimit(P2WPKH_SCRIPT)).toBe(294);
    expect(dustLimit(P2TR_SCRIPT)).toBe(330);
    // Non-witness script: 148 vB spend estimate.
    expect(dustLimit(new Uint8Array([0x76, 0xa9, 0x14, ...new Uint8Array(20), 0x88, 0xac]))).toBe(
      3 * (9 + 25 + 148),
    );
  });
});

describe("buildCpfpChild", () => {
  test("builds a v3 child spending the anchor with funding signed later", () => {
    const parent = fakeParent(0n);
    const result = buildCpfpChild({
      parent,
      funding: [funding()],
      changeScript: P2WPKH_SCRIPT,
      feeRateSatPerVbyte: 10,
    });

    const child = Transaction.fromPSBT(result.psbt, {
      allowUnknownInputs: true,
      allowUnknownOutputs: true,
      disableScriptCheck: true,
    });
    expect(child.version).toBe(3);
    expect(child.inputsLength).toBe(2);
    // Funding input first, anchor second. The anchor carries only witness_utxo;
    // the signing wallet finalizes the anyone-can-spend input itself.
    expect(child.getInput(0).txid).toStrictEqual(hexToBytes(FUNDING_TXID));
    expect(child.getInput(0).finalScriptWitness).toBeUndefined();
    const anchorInput = child.getInput(1);
    expect(anchorInput.txid).toStrictEqual(hexToBytes(txId(parent)));
    expect(anchorInput.index).toBe(1);
    expect(anchorInput.witnessUtxo?.script).toStrictEqual(EPHEMERAL_ANCHOR_SCRIPT);
    expect(anchorInput.witnessUtxo?.amount).toBe(0n);
    expect(anchorInput.finalScriptWitness).toBeUndefined();

    // One change output; fee covers the package at the requested rate.
    expect(child.outputsLength).toBe(1);
    const change = child.getOutput(0);
    expect(change.script).toStrictEqual(P2WPKH_SCRIPT);
    const expectedVsize = Math.ceil(10.5 + 68 + 41 + (8 + 1 + P2WPKH_SCRIPT.length));
    const parsedParent = Transaction.fromRaw(parent, { allowUnknownOutputs: true });
    const parentVsize = Math.ceil(
      (parsedParent.toBytes(true, false).length * 3 + parsedParent.toBytes(true, true).length) / 4,
    );
    const expectedFee = Math.ceil(10 * (parentVsize + expectedVsize));
    expect(result.vsize).toBe(expectedVsize);
    expect(result.feeSats).toBe(expectedFee);
    expect(change.amount).toBe(BigInt(100_000 - expectedFee));
  });

  test("keeps the funding input order", () => {
    const otherTxid = bytesToHex(new Uint8Array(32).fill(2));
    const result = buildCpfpChild({
      parent: fakeParent(0n),
      funding: [funding(), funding({ txid: otherTxid })],
      changeScript: P2WPKH_SCRIPT,
      feeRateSatPerVbyte: 5,
    });
    const child = Transaction.fromPSBT(result.psbt, {
      allowUnknownInputs: true,
      allowUnknownOutputs: true,
      disableScriptCheck: true,
    });
    expect(child.inputsLength).toBe(3);
    expect(child.getInput(0).txid).toStrictEqual(hexToBytes(FUNDING_TXID));
    expect(child.getInput(1).txid).toStrictEqual(hexToBytes(otherTxid));
    expect(child.getInput(2).finalScriptWitness).toBeUndefined();
  });

  test("rejects a parent without a zero-value P2A anchor", () => {
    expect(() =>
      buildCpfpChild({
        parent: fakeParent(546n),
        funding: [funding()],
        changeScript: P2WPKH_SCRIPT,
        feeRateSatPerVbyte: 10,
      }),
    ).toThrow("P2A anchor");
  });

  test("rejects non-witness funding scripts and dust-level change", () => {
    const parent = fakeParent(0n);
    expect(() =>
      buildCpfpChild({
        parent,
        funding: [funding()],
        changeScript: P2WPKH_SCRIPT,
        feeRateSatPerVbyte: 10,
      }),
    ).not.toThrow();
    expect(() =>
      buildCpfpChild({
        parent,
        funding: [{ ...funding(), script: new Uint8Array([0x6a, 0x04, 1, 2, 3, 4]) }],
        changeScript: P2WPKH_SCRIPT,
        feeRateSatPerVbyte: 10,
      }),
    ).toThrow("witness program");
    // Tiny funding input cannot cover the package fee plus dust change.
    expect(() =>
      buildCpfpChild({
        parent,
        funding: [funding({ amountSats: 2000 })],
        changeScript: P2WPKH_SCRIPT,
        feeRateSatPerVbyte: 50,
      }),
    ).toThrow("dust");
  });

  test("rejects children above the 1000 vB TRUC limit", () => {
    const many = Array.from({ length: 15 }, (_, i) =>
      funding({ txid: bytesToHex(new Uint8Array(32).fill(i + 1)) }),
    );
    expect(() =>
      buildCpfpChild({
        parent: fakeParent(0n),
        funding: many,
        changeScript: P2WPKH_SCRIPT,
        feeRateSatPerVbyte: 1,
      }),
    ).toThrow("1000");
  });

  test("rejects invalid fee rates and empty funding", () => {
    const parent = fakeParent(0n);
    for (const feeRateSatPerVbyte of [0, -1, Number.NaN]) {
      expect(() =>
        buildCpfpChild({
          parent,
          funding: [funding()],
          changeScript: P2WPKH_SCRIPT,
          feeRateSatPerVbyte,
        }),
      ).toThrow("feeRateSatPerVbyte");
    }
    expect(() =>
      buildCpfpChild({
        parent,
        funding: [],
        changeScript: P2WPKH_SCRIPT,
        feeRateSatPerVbyte: 1,
      }),
    ).toThrow("at least one");
  });
});

describe("buildKeySpendSweep + finalizeKeySpend", () => {
  test("sweeps a P2TR output minus the relay fee", () => {
    const prev = new Transaction({ version: 2, allowUnknownOutputs: true });
    prev.addInput({ txid: new Uint8Array(32).fill(3), index: 0, sequence: 0 });
    prev.addOutput({ script: P2TR_SCRIPT, amount: 50_000n });
    const prevTx = prev.toBytes(true);

    const { transaction, target, feeSats } = buildKeySpendSweep({
      prevTx,
      vout: 0,
      destinationScript: P2WPKH_SCRIPT,
      feeRateSatPerVbyte: 2,
    });

    const expectedVsize = Math.ceil(10.5 + 58 + (8 + 1 + P2WPKH_SCRIPT.length));
    expect(feeSats).toBe(Math.ceil(2 * expectedVsize));

    const parsed = Transaction.fromRaw(transaction, { allowUnknownOutputs: true });
    expect(parsed.inputsLength).toBe(1);
    expect(parsed.outputsLength).toBe(1);
    const out = parsed.getOutput(0);
    expect(out.script).toStrictEqual(P2WPKH_SCRIPT);
    expect(out.amount).toBe(BigInt(50_000 - feeSats));

    expect(target.transaction).toStrictEqual(transaction);
    expect(target.inputIndex).toBe(0);
    expect(target.prevouts[0]).toStrictEqual({ script: P2TR_SCRIPT, amount: 50_000 });

    const signature = new Uint8Array(64).fill(0xaa);
    const signed = finalizeKeySpend(transaction, signature);
    const signedTx = Transaction.fromRaw(signed, { allowUnknownOutputs: true });
    expect(signedTx.getInput(0).finalScriptWitness).toStrictEqual([signature]);
    // The signed txid differs from the unsigned one only in witness data — wtxid
    // changes, txid (which finalizeKeySpend does not touch) stays.
    expect(txId(signed)).toBe(txId(transaction));
  });

  test("rejects sub-dust sweeps and malformed signatures", () => {
    const prev = new Transaction({ version: 2, allowUnknownOutputs: true });
    prev.addInput({ txid: new Uint8Array(32).fill(3), index: 0, sequence: 0 });
    prev.addOutput({ script: P2TR_SCRIPT, amount: 400n });
    expect(() =>
      buildKeySpendSweep({
        prevTx: prev.toBytes(true),
        vout: 0,
        destinationScript: P2WPKH_SCRIPT,
        feeRateSatPerVbyte: 2,
      }),
    ).toThrow("dust");

    const { transaction } = buildKeySpendSweep({
      prevTx: (() => {
        const rich = new Transaction({ version: 2, allowUnknownOutputs: true });
        rich.addInput({ txid: new Uint8Array(32).fill(3), index: 0, sequence: 0 });
        rich.addOutput({ script: P2TR_SCRIPT, amount: 50_000n });
        return rich.toBytes(true);
      })(),
      vout: 0,
      destinationScript: P2WPKH_SCRIPT,
      feeRateSatPerVbyte: 2,
    });
    expect(() => finalizeKeySpend(transaction, new Uint8Array(63))).toThrow("64-byte");
  });
});
