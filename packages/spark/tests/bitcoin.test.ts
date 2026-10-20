import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { Address, OutScript, Transaction } from "@scure/btc-signer";
import { expect, test } from "vite-plus/test";

import {
  constructHtlcReceiverSpend,
  constructHtlcSenderSpend,
  constructHtlcTransaction,
  createHashLockScript,
  createSequenceLockScript,
  NUMS_INTERNAL_KEY,
} from "../src/core/bitcoin/htlc.ts";
import {
  btcNetwork,
  computeTaprootKeyNoScript,
  p2trAddressFromPublicKey,
  p2trAddressFromScript,
  p2trScriptFromPublicKey,
  p2wpkhAddressFromPublicKey,
} from "../src/core/bitcoin/script.ts";
import {
  checkIfValidSequence,
  DIRECT_TIMELOCK_OFFSET,
  getNextHTLCTransactionSequence,
  getNextTransactionSequence,
  getTimelockFromSequence,
  INITIAL_ROOT_NODE_SEQUENCE,
  isZeroTimelock,
  roundDownToTimelockInterval,
} from "../src/core/bitcoin/sequence.ts";
import { taprootKeySpendSighash } from "../src/core/bitcoin/sighash.ts";
import {
  constructNodeTxPair,
  constructRefundTxTrio,
  createConnectorRefundTxs,
  createInitialTimelockNodeTx,
  createMultiInputRootTx,
  createNodeTxs,
  createRefundTxs,
  estimateVbytes,
  txId,
  txIdBytes,
  txIdInputBytes,
} from "../src/core/bitcoin/transactions.ts";
import {
  validateConnectorTxBindsToCoopExitTxid,
  validateCoopExitPayoutTransaction,
} from "../src/core/bitcoin/validate.ts";
import { SparkInputError } from "../src/errors/index.ts";

type TxResult = { tx: string; sighash: string };

const vectors = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "../../../vectors/transactions.json"), "utf8"),
) as {
  sequence: {
    getTimelockFromSequence: Array<{ sequence: number; timelock: number }>;
    checkIfValidSequence: Array<{ sequence: number; ok: boolean }>;
    isZeroTimelock: Array<{ sequence: number; zero: boolean }>;
    roundDownToTimelockInterval: Array<{ timelock: number; interval: number; result: number }>;
  };
  nodeTxPairs: Array<{
    name: string;
    parentTx: string;
    vout: number;
    address: string;
    sequence: number;
    directSequence: number;
    feeSats: number;
    cpfp: TxResult;
    direct: TxResult;
  }>;
  refundTxTrios: Array<{
    name: string;
    nodeTx: string;
    directNodeTx: string | null;
    vout: number;
    receivingPublicKey: string;
    network: "mainnet" | "regtest";
    sequence: number;
    directSequence: number;
    feeSats: number;
    cpfpRefund: TxResult;
    directRefund: TxResult | null;
    directFromCpfpRefund: TxResult;
  }>;
  htlc: Array<
    {
      name: string;
      paymentHash: string;
      hashLockPublicKey: string;
      sequenceLockPublicKey: string;
      htlcSequence: number;
      feeSats: number;
      network: "mainnet" | "regtest";
      tx: string;
      sighash: string;
    } & (
      | {
          name: "cpfp" | "fee";
          nodeTx: string;
          vout: number;
          sequence: number;
          applyFee: boolean;
        }
      | {
          name: "sender-spend" | "receiver-spend";
          htlcTx: string;
          destinationPublicKey: string;
          script: string;
          controlBlock: string;
        }
    )
  >;
  multiInputSighash: Array<{
    tx: string;
    inputIndex: number;
    prevOutScripts: string[];
    prevOutValues: number[];
    sighash: string;
  }>;
};

// Module-level helpers keep test bodies free of conditionals (vitest lint rule).

function required<T>(value: T | null | undefined, what: string): T {
  if (value === undefined || value === null) {
    throw new Error(`${what}: missing`);
  }
  return value;
}

function parent(): Uint8Array {
  return hexToBytes(PARENT_TX);
}

function scriptOf(txBytes: Uint8Array, index: number): Uint8Array {
  return required(
    Transaction.fromRaw(txBytes, { allowUnknownOutputs: true }).getOutput(index).script,
    `output ${index} script`,
  );
}

function inputSequence(txBytes: Uint8Array, index: number): number {
  return required(
    Transaction.fromRaw(txBytes, { allowUnknownOutputs: true }).getInput(index).sequence,
    `input ${index} sequence`,
  );
}

function amountOf(txBytes: Uint8Array, index: number): number {
  return Number(
    required(
      Transaction.fromRaw(txBytes, { allowUnknownOutputs: true }).getOutput(index).amount,
      `output ${index} amount`,
    ),
  );
}

const firstNodePair = required(vectors.nodeTxPairs.at(0), "nodeTxPairs[0]");
const firstRefundTrio = required(vectors.refundTxTrios.at(0), "refundTxTrios[0]");
const PARENT_TX = firstNodePair.parentTx;
const PARENT_VOUT = firstNodePair.vout;
const RECEIVING_PUBLIC_KEY = firstRefundTrio.receivingPublicKey;

// -- Rust-vector-backed: sequence helpers ----------------------------------------

test.each(vectors.sequence.getTimelockFromSequence)(
  "getTimelockFromSequence %#",
  ({ sequence, timelock }) => {
    expect(getTimelockFromSequence(sequence)).toBe(timelock);
  },
);

test.each(vectors.sequence.checkIfValidSequence.filter((c) => c.ok))(
  "checkIfValidSequence accepts %#",
  ({ sequence }) => {
    expect(() => checkIfValidSequence(sequence)).not.toThrow();
  },
);

test.each(vectors.sequence.checkIfValidSequence.filter((c) => !c.ok))(
  "checkIfValidSequence rejects %#",
  ({ sequence }) => {
    expect(() => checkIfValidSequence(sequence)).toThrow(SparkInputError);
  },
);

test.each(vectors.sequence.isZeroTimelock)("isZeroTimelock %#", ({ sequence, zero }) => {
  expect(isZeroTimelock(sequence)).toBe(zero);
});

test.each(vectors.sequence.roundDownToTimelockInterval)(
  "roundDownToTimelockInterval %#",
  ({ timelock, interval, result }) => {
    expect(roundDownToTimelockInterval(timelock, interval)).toBe(result);
  },
);

// -- Rust-vector-backed: node transaction pairs -----------------------------------

test.each(vectors.nodeTxPairs)("constructNodeTxPair $name", (c) => {
  const pair = constructNodeTxPair(
    hexToBytes(c.parentTx),
    c.vout,
    c.address,
    c.sequence,
    c.directSequence,
    c.feeSats,
  );
  expect(bytesToHex(pair.cpfp.txBytes)).toBe(c.cpfp.tx);
  expect(bytesToHex(pair.cpfp.sighash)).toBe(c.cpfp.sighash);
  expect(bytesToHex(pair.direct.txBytes)).toBe(c.direct.tx);
  expect(bytesToHex(pair.direct.sighash)).toBe(c.direct.sighash);
});

// -- Rust-vector-backed: refund transaction trios ---------------------------------

function directNodeTxBytes(c: (typeof vectors.refundTxTrios)[number]): Uint8Array | undefined {
  if (c.directNodeTx === null) {
    return undefined;
  }
  return hexToBytes(c.directNodeTx);
}

test.each(vectors.refundTxTrios)("constructRefundTxTrio $name", (c) => {
  const trio = constructRefundTxTrio(
    hexToBytes(c.nodeTx),
    directNodeTxBytes(c),
    c.vout,
    hexToBytes(c.receivingPublicKey),
    c.network,
    c.sequence,
    c.directSequence,
    c.feeSats,
  );
  expect(bytesToHex(trio.cpfpRefund.txBytes)).toBe(c.cpfpRefund.tx);
  expect(bytesToHex(trio.cpfpRefund.sighash)).toBe(c.cpfpRefund.sighash);
  expect(trio.directRefund === undefined).toBe(c.directRefund === null);
  expect(bytesToHex(trio.directFromCpfpRefund.txBytes)).toBe(c.directFromCpfpRefund.tx);
  expect(bytesToHex(trio.directFromCpfpRefund.sighash)).toBe(c.directFromCpfpRefund.sighash);
});

test.each(vectors.refundTxTrios.filter((c) => c.directRefund !== null))(
  "constructRefundTxTrio direct variant $name",
  (c) => {
    const trio = constructRefundTxTrio(
      hexToBytes(c.nodeTx),
      directNodeTxBytes(c),
      c.vout,
      hexToBytes(c.receivingPublicKey),
      c.network,
      c.sequence,
      c.directSequence,
      c.feeSats,
    );
    const direct = required(trio.directRefund, "directRefund");
    const expected = required(c.directRefund, "vector.directRefund");
    expect(bytesToHex(direct.txBytes)).toBe(expected.tx);
    expect(bytesToHex(direct.sighash)).toBe(expected.sighash);
  },
);

// -- Rust-vector-backed: HTLC -----------------------------------------------------

type SpendCase = Extract<(typeof vectors.htlc)[number], { htlcTx: string }>;

const htlcTxCases = vectors.htlc.filter(
  (c): c is Extract<(typeof vectors.htlc)[number], { nodeTx: string }> => "nodeTx" in c,
);
const htlcSpendCases = vectors.htlc.filter((c): c is SpendCase => "htlcTx" in c);
const senderSpend = htlcSpendCases.filter((c) => c.name === "sender-spend");
const receiverSpend = htlcSpendCases.filter((c) => c.name === "receiver-spend");

test.each(htlcTxCases)("constructHtlcTransaction $name", (c) => {
  const result = constructHtlcTransaction(
    hexToBytes(c.nodeTx),
    c.vout,
    c.sequence,
    hexToBytes(c.paymentHash),
    hexToBytes(c.hashLockPublicKey),
    hexToBytes(c.sequenceLockPublicKey),
    c.htlcSequence,
    c.applyFee,
    c.feeSats,
  );
  expect(bytesToHex(result.txBytes)).toBe(c.tx);
  expect(bytesToHex(result.sighash)).toBe(c.sighash);
});

function spendResult(
  c: SpendCase,
  fn: typeof constructHtlcSenderSpend,
): { tx: string; sighash: string; script: string; controlBlock: string } {
  const result = fn(
    hexToBytes(c.htlcTx),
    hexToBytes(c.destinationPublicKey),
    hexToBytes(c.paymentHash),
    hexToBytes(c.hashLockPublicKey),
    hexToBytes(c.sequenceLockPublicKey),
    c.htlcSequence,
    c.feeSats,
    c.network,
  );
  return {
    tx: bytesToHex(result.txBytes),
    sighash: bytesToHex(result.sighash),
    script: bytesToHex(result.script),
    controlBlock: bytesToHex(result.controlBlock),
  };
}

test.each(senderSpend)("sender spend %#", (c) => {
  expect(spendResult(c, constructHtlcSenderSpend)).toStrictEqual({
    tx: c.tx,
    sighash: c.sighash,
    script: c.script,
    controlBlock: c.controlBlock,
  });
});

test.each(receiverSpend)("receiver spend %#", (c) => {
  expect(spendResult(c, constructHtlcReceiverSpend)).toStrictEqual({
    tx: c.tx,
    sighash: c.sighash,
    script: c.script,
    controlBlock: c.controlBlock,
  });
});

// -- Rust-vector-backed: multi-input sighash --------------------------------------

test.each(vectors.multiInputSighash)("multi-input sighash input %#", (c) => {
  const sighash = taprootKeySpendSighash({
    transaction: hexToBytes(c.tx),
    inputIndex: c.inputIndex,
    prevouts: c.prevOutScripts.map((script, i) => ({
      script: hexToBytes(script),
      amount: required(c.prevOutValues.at(i), "prevOutValues"),
    })),
  });
  expect(bytesToHex(sighash)).toBe(c.sighash);
});

// -- Upstream-TS fixed vectors -----------------------------------------------------

test("p2tr address from public key (upstream vectors)", () => {
  expect(
    p2trAddressFromPublicKey(
      hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
      "mainnet",
    ),
  ).toBe("bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9");
});

test("p2tr address from pk script (upstream vectors)", () => {
  expect(
    p2trAddressFromScript(
      hexToBytes("51206d2a651074ff19686d4cd4e45aaaad3f85639e90bb24e21b875b174b0635eb30"),
      "mainnet",
    ),
  ).toBe("bc1pd54x2yr5luvksm2v6nj9424d87zk885shvjwyxu8tvt5kp34avcq024v6k");
  expect(
    p2trAddressFromScript(
      hexToBytes("5120d0cd6fade9979fc9e0cc353d8e06a22f43d659cf09c8f909834e80468f4af966"),
      "regtest",
    ),
  ).toBe("bcrt1p6rxklt0fj70uncxvx57cup4z9apavkw0p8y0jzvrf6qydr62l9nqd94jkz");
});

test("p2tr script from public key (upstream vector)", () => {
  const script = p2trScriptFromPublicKey(
    hexToBytes("03ef261da8259f5ea86abe1b7d658ebd13fe2b2ce2418dabe854ccec67bdb9ba87"),
    "mainnet",
  );
  expect(bytesToHex(script)).toBe(
    "51208af8e5e92783248418d5c68007dc8659a2100261b5bb561efc28dde94ec8cb93",
  );
});

test("taproot tweak of the generator key matches its BIP-86 address", () => {
  const tweaked = computeTaprootKeyNoScript(
    hexToBytes("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
  );
  const script = hexToBytes(`5120${bytesToHex(tweaked.subarray(1))}`);
  expect(p2trAddressFromScript(script, "mainnet")).toBe(
    "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9",
  );
});

const SIGHASH_VECTOR_PREV_TX =
  "020000000001010cb9feccc0bdaac30304e469c50b4420c13c43d466e13813fcf42a73defd3f010000000000ffffffff018038010000000000225120d21e50e12ae122b4a5662c09b67cec7449c8182913bc06761e8b65f0fa2242f701400536f9b7542799f98739eeb6c6adaeb12d7bd418771bc5c6847f2abd19297bd466153600af26ccf0accb605c11ad667c842c5713832af4b7b11f1bcebe57745900000000";

test("key-spend sighash matches the upstream fixed vector", () => {
  const prevTxBytes = hexToBytes(SIGHASH_VECTOR_PREV_TX);
  const prevTx = Transaction.fromRaw(prevTxBytes, { allowUnknownOutputs: true });
  const tx = new Transaction();
  tx.addInput({ txid: prevTx.id, index: 0 });
  tx.addOutput({ script: scriptOf(prevTxBytes, 0), amount: 70_000n });
  const sighash = taprootKeySpendSighash({
    transaction: tx.toBytes(true),
    inputIndex: 0,
    prevouts: [{ script: scriptOf(prevTxBytes, 0), amount: amountOf(prevTxBytes, 0) }],
  });
  expect(bytesToHex(sighash)).toBe(
    "8da5e7aa2b03491d7c2f4359ea4968dd58f69adf9af1a2c6881be0295591c293",
  );
});

// -- Structure tests for TS-only wrappers -------------------------------------------

test("createNodeTxs builds the version-3 CPFP/direct pair with the parent's address", () => {
  const { cpfp, direct } = createNodeTxs({
    parentTx: parent(),
    sequence: 2000,
    vout: PARENT_VOUT,
    network: "mainnet",
  });
  const cpfpTx = Transaction.fromRaw(cpfp.txBytes, { allowUnknownOutputs: true });
  const directTx = Transaction.fromRaw(direct.txBytes, { allowUnknownOutputs: true });
  expect(cpfpTx.version).toBe(3);
  expect(cpfpTx.lockTime).toBe(0);
  expect(cpfpTx.inputsLength).toBe(1);
  expect(cpfpTx.outputsLength).toBe(2);
  expect(bytesToHex(scriptOf(cpfp.txBytes, 1))).toBe("51024e73");
  expect(amountOf(cpfp.txBytes, 0)).toBe(100_000);
  expect(directTx.outputsLength).toBe(1);
  expect(amountOf(direct.txBytes, 0)).toBe(100_000 - 955);
  expect(cpfp.sighash).toHaveLength(32);
});

test("createInitialTimelockNodeTx uses sequence 2000", () => {
  const { cpfp } = createInitialTimelockNodeTx(parent(), "mainnet");
  expect(inputSequence(cpfp.txBytes, 0)).toBe(2000);
});

test("createRefundTxs gates the direct refund on a non-zero timelock", () => {
  const { cpfp, direct } = createNodeTxs({
    parentTx: parent(),
    sequence: 2000,
    vout: PARENT_VOUT,
    network: "mainnet",
  });
  const trio = createRefundTxs({
    nodeTx: cpfp.txBytes,
    directNodeTx: direct.txBytes,
    receivingPublicKey: hexToBytes(RECEIVING_PUBLIC_KEY),
    network: "mainnet",
    sequence: 2000,
  });
  expect(trio.directRefund).toBeDefined();

  const zero = createNodeTxs({
    parentTx: parent(),
    sequence: 0,
    vout: PARENT_VOUT,
    network: "mainnet",
  });
  const zeroTrio = createRefundTxs({
    nodeTx: zero.cpfp.txBytes,
    directNodeTx: zero.direct.txBytes,
    receivingPublicKey: hexToBytes(RECEIVING_PUBLIC_KEY),
    network: "mainnet",
    sequence: 0,
  });
  expect(zeroTrio.directRefund).toBeUndefined();
});

test("createConnectorRefundTxs appends the connector input to every variant", () => {
  const { cpfp, direct } = createNodeTxs({
    parentTx: parent(),
    sequence: 2000,
    vout: PARENT_VOUT,
    network: "mainnet",
  });
  const connectorTxid = hexToBytes("ab".repeat(32));
  const result = createConnectorRefundTxs({
    nodeTx: cpfp.txBytes,
    directNodeTx: direct.txBytes,
    receivingPublicKey: hexToBytes(RECEIVING_PUBLIC_KEY),
    network: "mainnet",
    sequence: 2000,
    connectorInput: { txid: connectorTxid, index: 0, sequence: 500 },
  });
  const variants = [result.cpfpRefundTx, result.directRefundTx, result.directFromCpfpRefundTx];
  const inputCounts = variants.map(
    (b) => Transaction.fromRaw(required(b, "variant"), { allowUnknownOutputs: true }).inputsLength,
  );
  expect(inputCounts).toStrictEqual([2, 2, 2]);
  const connectorInput = Transaction.fromRaw(result.cpfpRefundTx, {
    allowUnknownOutputs: true,
  }).getInput(1);
  expect(bytesToHex(required(connectorInput.txid, "connector txid"))).toBe("ab".repeat(32));
  expect(connectorInput.sequence).toBe(500);
});

test.each([{ vout: 0 }, { vout: 1 }])(
  "createMultiInputRootTx with one input matches the classic root node builder (vout $vout)",
  ({ vout }) => {
    // claimDeposit's one-UTXO claim is the multi path with N=1 — it must be byte-identical to
    // the sequence-0 root node tx the single-input builder produced.
    const classic = createNodeTxs({
      parentTx: parent(),
      vout,
      sequence: INITIAL_ROOT_NODE_SEQUENCE,
      directSequence: DIRECT_TIMELOCK_OFFSET,
      network: "regtest",
    }).cpfp.txBytes;
    expect(createMultiInputRootTx([{ tx: parent(), vout }])).toStrictEqual(classic);
  },
);

test("createMultiInputRootTx sums the deposits into one output plus the anchor", () => {
  const txBytes = createMultiInputRootTx([
    { tx: parent(), vout: 0 },
    { tx: parent(), vout: 1 },
  ]);
  const tx = Transaction.fromRaw(txBytes, { allowUnknownOutputs: true });
  expect(tx.version).toBe(3);
  expect(tx.lockTime).toBe(0);
  expect(tx.inputsLength).toBe(2);
  expect(inputSequence(txBytes, 0)).toBe(0);
  expect(Transaction.fromRaw(txBytes, { allowUnknownOutputs: true }).getInput(1).index).toBe(1);
  expect(amountOf(txBytes, 0)).toBe(amountOf(parent(), 0) + amountOf(parent(), 1));
  expect(bytesToHex(scriptOf(txBytes, 0))).toBe(bytesToHex(scriptOf(parent(), 0)));
  expect(tx.outputsLength).toBe(2);
  expect(bytesToHex(scriptOf(txBytes, 1))).toBe("51024e73");
  expect(amountOf(txBytes, 1)).toBe(0);
});

test("HTLC sender/receiver spend input sequences match upstream", () => {
  const sender = required(
    vectors.htlc.find((c) => c.name === "sender-spend"),
    "sender-spend",
  );
  const receiver = required(
    vectors.htlc.find((c) => c.name === "receiver-spend"),
    "receiver-spend",
  );
  expect(inputSequence(hexToBytes(sender.tx), 0)).toBe(2160);
  expect(inputSequence(hexToBytes(receiver.tx), 0)).toBe(0xff_ff_ff_ff);
});

test("hash-lock and sequence-lock scripts match the Rust byte format", () => {
  const paymentHash = new Uint8Array(32).fill(0x55);
  const pubkey = hexToBytes(RECEIVING_PUBLIC_KEY);
  const hashLock = createHashLockScript(paymentHash, pubkey);
  // OP_SHA256 <32-byte push> OP_EQUALVERIFY <32-byte push> OP_CHECKSIG
  expect(hashLock[0]).toBe(0xa8);
  expect(hashLock[1]).toBe(0x20);
  expect(hashLock[34]).toBe(0x88);
  expect(hashLock.at(-1)).toBe(0xac);
  const seq = createSequenceLockScript(2160, pubkey);
  // minimal ScriptNum push of 2160 = 0x02 0x70 0x08, then OP_CSV OP_DROP <key> OP_CHECKSIG
  expect(bytesToHex(seq.subarray(0, 4))).toBe("027008b2");
  expect(NUMS_INTERNAL_KEY).toHaveLength(32);
});

// -- Validation -----------------------------------------------------------------

test("validateConnectorTxBindsToCoopExitTxid requires internal byte order", () => {
  const { cpfp } = createInitialTimelockNodeTx(parent(), "mainnet");
  const connector = new Transaction({ version: 3, allowUnknownOutputs: true });
  connector.addInput({ txid: txIdInputBytes(cpfp.txBytes), index: 0 });
  connector.addOutput({ script: hexToBytes(`5120${"11".repeat(32)}`), amount: 500n });
  const connectorBytes = connector.toBytes(true);
  const internalId = txIdBytes(cpfp.txBytes);
  const displayId = hexToBytes(txId(cpfp.txBytes));
  validateConnectorTxBindsToCoopExitTxid(connectorBytes, internalId);
  // Display (reversed) order no longer passes.
  expect(() => validateConnectorTxBindsToCoopExitTxid(connectorBytes, displayId)).toThrow(
    SparkInputError,
  );
  expect(() =>
    validateConnectorTxBindsToCoopExitTxid(connectorBytes, new Uint8Array(32).fill(9)),
  ).toThrow(SparkInputError);
});

function addressForScript(script: Uint8Array, network: "mainnet" | "regtest"): string {
  return Address(btcNetwork(network)).encode(OutScript.decode(script));
}

test("validateCoopExitPayoutTransaction checks txid, destination and amount", () => {
  const payoutScript = hexToBytes(`0014${"33".repeat(20)}`);
  const payout = new Transaction({ version: 3, allowUnknownOutputs: true });
  payout.addInput({ txid: txIdInputBytes(parent()), index: 0 });
  payout.addOutput({ script: payoutScript, amount: 55_000n });
  const payoutBytes = payout.toBytes(true);
  const params = {
    rawCoopExitTransaction: payoutBytes,
    expectedCoopExitTxid: txId(payoutBytes),
    expectedPayoutAddress: addressForScript(payoutScript, "mainnet"),
    expectedPayoutAmountSats: 55_000,
    network: "mainnet" as const,
  };
  validateCoopExitPayoutTransaction(params);
  expect(() =>
    validateCoopExitPayoutTransaction({ ...params, expectedPayoutAmountSats: 55_001 }),
  ).toThrow(SparkInputError);
  expect(() =>
    validateCoopExitPayoutTransaction({
      ...params,
      expectedCoopExitTxid: "00".repeat(32),
    }),
  ).toThrow(SparkInputError);
});

// -- Sequence wrappers -----------------------------------------------------------

test("getNextTransactionSequence decrements and carries bit 30", () => {
  expect(getNextTransactionSequence(2000)).toStrictEqual({
    nextSequence: 1900,
    nextDirectSequence: 1950,
  });
  expect(getNextTransactionSequence(0x40_00_07_d0)).toStrictEqual({
    nextSequence: 0x40_00_07_6c,
    nextDirectSequence: 0x40_00_07_9e,
  });
});

test("getNextTransactionSequence guards the low bound", () => {
  expect(() => getNextTransactionSequence(100)).toThrow(SparkInputError);
  expect(getNextTransactionSequence(100, true)).toStrictEqual({
    nextSequence: 0,
    nextDirectSequence: 50,
  });
});

test("getNextHTLCTransactionSequence applies HTLC offsets", () => {
  expect(getNextHTLCTransactionSequence(2000)).toStrictEqual({
    nextSequence: 1970,
    nextDirectSequence: 1985,
  });
});

test("p2wpkh address and vbytes estimate", () => {
  const address = p2wpkhAddressFromPublicKey(
    hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
    "mainnet",
  );
  expect(address.startsWith("bc1q")).toBe(true);
  expect(estimateVbytes(2, 3)).toBe(412);
});

test("txId returns the display-order txid", () => {
  const tx = Transaction.fromRaw(parent(), { allowUnknownOutputs: true });
  expect(txId(parent())).toBe(tx.id);
});
