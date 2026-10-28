import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vite-plus/test";

import type { SspUserRequest } from "../src/ssp/types.ts";
import { toSparkPayment } from "../src/transfer/index.ts";
import type { SparkPayment, SparkTransfer } from "../src/transfer/index.ts";
import { encodeTestBolt11 } from "./support/bolt11.ts";

const OUR_ID = new Uint8Array(33).fill(2);
const SSP_ID = new Uint8Array(33).fill(3);
const OTHER_ID = new Uint8Array(33).fill(4);
const TXID = "ab".repeat(32);
const SECRET = new Uint8Array(32).fill(9);
const PAYMENT_HASH = new Uint8Array(32).fill(5);
const INVOICE = encodeTestBolt11({
  paymentHash: PAYMENT_HASH,
  secretKey: SECRET,
  description: "test invoice",
  network: "regtest",
});

function transfer(partial: Partial<SparkTransfer>): SparkTransfer {
  return {
    id: "t1",
    senderIdentityPublicKey: OTHER_ID,
    receiverIdentityPublicKey: OUR_ID,
    receivers: [],
    status: "COMPLETED",
    type: "TRANSFER",
    network: "regtest",
    totalValueSats: 1000,
    createdTimeMs: 1_700_000_000_000,
    leaves: [],
    ...partial,
  };
}

function pay(t: Partial<SparkTransfer>, request?: SspUserRequest): SparkPayment {
  return toSparkPayment({
    transfer: transfer(t),
    request,
    identityPublicKey: OUR_ID,
    sspIdentityPublicKey: SSP_ID,
  });
}

describe("direction and method", () => {
  it("send when the sender is our identity, receive otherwise", () => {
    expect(pay({ senderIdentityPublicKey: OUR_ID }).direction).toBe("send");
    expect(pay({}).direction).toBe("receive");
  });

  it("maps every type and counterparty to its method", () => {
    expect(pay({ type: "TRANSFER" }).method).toBe("spark");
    // PREIMAGE_SWAP: lightning only with the SSP on the other side.
    expect(pay({ type: "PREIMAGE_SWAP" }).method).toBe("spark");
    expect(
      pay({
        senderIdentityPublicKey: OUR_ID,
        receiverIdentityPublicKey: SSP_ID,
        type: "PREIMAGE_SWAP",
      }).method,
    ).toBe("lightning");
    expect(pay({ senderIdentityPublicKey: SSP_ID, type: "PREIMAGE_SWAP" }).method).toBe(
      "lightning",
    );
    expect(pay({ type: "COOPERATIVE_EXIT" }).method).toBe("withdraw");
    expect(pay({ type: "UTXO_SWAP" }).method).toBe("deposit");
  });
});

describe("status", () => {
  it("COMPLETED is completed; outgoing SENDER_KEY_TWEAKED is completed", () => {
    expect(pay({}).status).toBe("completed");
    expect(pay({ senderIdentityPublicKey: OUR_ID, status: "SENDER_KEY_TWEAKED" }).status).toBe(
      "completed",
    );
    // …but only for the sender — an inbound tweak is still in flight for us.
    expect(pay({ status: "SENDER_KEY_TWEAKED" }).status).toBe("pending");
  });

  it("EXPIRED and RETURNED are failed; other statuses pending", () => {
    expect(pay({ status: "EXPIRED" }).status).toBe("failed");
    expect(pay({ status: "RETURNED" }).status).toBe("failed");
    expect(pay({ status: "SENDER_INITIATED" }).status).toBe("pending");
  });

  it("a lightning send with a known preimage is completed", () => {
    const payment = pay(
      {
        senderIdentityPublicKey: OUR_ID,
        receiverIdentityPublicKey: SSP_ID,
        type: "PREIMAGE_SWAP",
        status: "SENDER_KEY_TWEAKED",
      },
      {
        kind: "lightning-send",
        status: "LIGHTNING_PAYMENT_INITIATED",
        invoice: INVOICE,
        feeSats: 10,
      },
    );
    // Without the preimage the tweak already means completed — the preimage only pins it.
    expect(payment.status).toBe("completed");
  });

  it("coop-exit acceptance maps to status — Breez buckets", () => {
    const base = {
      senderIdentityPublicKey: OUR_ID,
      receiverIdentityPublicKey: SSP_ID,
      type: "COOPERATIVE_EXIT",
      status: "COMPLETED",
    };
    const req = (status: string): SspUserRequest => ({ kind: "coop-exit", status, feeSats: 100 });
    // Accepted: the SSP took the exit over — the SO status keeps telling completion.
    for (const accepted of [
      "INBOUND_TRANSFER_CHECKED",
      "TX_SIGNED",
      "TX_BROADCASTED",
      "WAITING_ON_TX_CONFIRMATIONS",
      "COMPLETE_REQUEST_RECEIVED",
      "ON_CHAIN_TX_CONFIRMED",
      "SUCCEEDED",
    ]) {
      expect(pay(base, req(accepted)).status).toBe("completed");
    }
    // Terminal failures.
    for (const failed of [
      "EXPIRED",
      "FAILED",
      "INBOUND_TRANSFER_CLAIMING_FAILED",
      "EXPIRING_FAILED",
      "FAILING_FAILED",
    ]) {
      expect(pay(base, req(failed)).status).toBe("failed");
    }
    // Everything else is in flight — an unknown status must never read as accepted.
    for (const waiting of [
      "INITIATED",
      "EXPIRING_SCHEDULED",
      "FAILING_SCHEDULED",
      "FUTURE_VALUE",
      "BRAND_NEW_STATUS",
    ]) {
      expect(pay(base, req(waiting)).status).toBe("pending");
    }
  });

  it("an SSP-method transfer completed without its request is pending", () => {
    expect(
      pay({
        senderIdentityPublicKey: OUR_ID,
        receiverIdentityPublicKey: SSP_ID,
        type: "PREIMAGE_SWAP",
      }).status,
    ).toBe("pending");
    expect(pay({ senderIdentityPublicKey: OUR_ID, type: "COOPERATIVE_EXIT" }).status).toBe(
      "pending",
    );
    expect(pay({ senderIdentityPublicKey: SSP_ID, type: "UTXO_SWAP" }).status).toBe("pending");
    // …while a plain spark transfer needs no request to be completed.
    expect(pay({ type: "TRANSFER" }).status).toBe("completed");
  });
});

describe("amounts and fees", () => {
  it("lightning send: fee from the SSP, amount = total − fee", () => {
    const payment = pay(
      { senderIdentityPublicKey: OUR_ID, receiverIdentityPublicKey: SSP_ID, type: "PREIMAGE_SWAP" },
      { kind: "lightning-send", status: "SUCCEEDED", invoice: INVOICE, feeSats: 25 },
    );
    expect({ fee: payment.feeSats, amount: payment.amountSats }).toStrictEqual({
      fee: 25,
      amount: 975,
    });
  });

  it("coop-exit: fee = user fee + l1 broadcast, amount = total − fee", () => {
    const payment = pay(
      { senderIdentityPublicKey: OUR_ID, type: "COOPERATIVE_EXIT" },
      { kind: "coop-exit", status: "SUCCEEDED", feeSats: 150, txid: TXID },
    );
    expect({ fee: payment.feeSats, amount: payment.amountSats }).toStrictEqual({
      fee: 150,
      amount: 850,
    });
  });

  it("static deposit: fee = total − credit, amount = total", () => {
    const payment = pay(
      { senderIdentityPublicKey: SSP_ID, type: "UTXO_SWAP", totalValueSats: 4900 },
      {
        kind: "static-deposit",
        txid: TXID,
        vout: 1,
        depositAmountSats: 5000,
        creditAmountSats: 4900,
      },
    );
    expect({ fee: payment.feeSats, amount: payment.amountSats }).toStrictEqual({
      fee: 100,
      amount: 4900,
    });
  });

  it("spark and multi-receiver sends carry no fee and the full total", () => {
    const receivers = [
      { id: "r1", identityPublicKey: OTHER_ID, amountSats: 300, status: "COMPLETED" },
      {
        id: "r2",
        identityPublicKey: new Uint8Array(33).fill(6),
        amountSats: 200,
        status: "COMPLETED",
      },
    ];
    const payment = pay({ senderIdentityPublicKey: OUR_ID, receivers, totalValueSats: 500 });
    expect({ fee: payment.feeSats, amount: payment.amountSats }).toStrictEqual({
      fee: 0,
      amount: 500,
    });
  });
});

describe("details", () => {
  it("lightning carries the decoded payment hash, description and preimage", () => {
    const preimage = new Uint8Array(32).fill(7);
    const payment = pay(
      { senderIdentityPublicKey: OUR_ID, receiverIdentityPublicKey: SSP_ID, type: "PREIMAGE_SWAP" },
      { kind: "lightning-send", status: "SUCCEEDED", invoice: INVOICE, feeSats: 5, preimage },
    );
    expect(payment.details).toStrictEqual({
      kind: "lightning",
      invoice: INVOICE,
      paymentHash: bytesToHex(PAYMENT_HASH),
      description: "test invoice",
      preimage: bytesToHex(preimage),
    });
  });

  it("spark carries the transfer's spark invoice; withdraw the txid; deposit txid+vout", () => {
    const spark = pay({ sparkInvoice: "spark1test" });
    expect(spark.details).toStrictEqual({ kind: "spark", invoice: "spark1test" });
    const withdraw = pay(
      { senderIdentityPublicKey: OUR_ID, type: "COOPERATIVE_EXIT" },
      { kind: "coop-exit", status: "SUCCEEDED", feeSats: 100, txid: TXID },
    );
    expect(withdraw.details).toStrictEqual({ kind: "withdraw", txid: TXID });
    const deposit = pay(
      { senderIdentityPublicKey: SSP_ID, type: "UTXO_SWAP" },
      {
        kind: "static-deposit",
        txid: TXID,
        vout: 3,
        depositAmountSats: 1000,
        creditAmountSats: 990,
      },
    );
    expect(deposit.details).toStrictEqual({ kind: "deposit", txid: TXID, vout: 3 });
  });

  it("an SSP fee above the total clamps the amount at zero", () => {
    const send = pay(
      {
        senderIdentityPublicKey: OUR_ID,
        receiverIdentityPublicKey: SSP_ID,
        type: "PREIMAGE_SWAP",
        totalValueSats: 100,
      },
      { kind: "lightning-send", status: "SUCCEEDED", invoice: INVOICE, feeSats: 250 },
    );
    expect({ fee: send.feeSats, amount: send.amountSats }).toStrictEqual({ fee: 250, amount: 0 });
    const exit = pay(
      { senderIdentityPublicKey: OUR_ID, type: "COOPERATIVE_EXIT", totalValueSats: 100 },
      { kind: "coop-exit", status: "SUCCEEDED", feeSats: 250 },
    );
    expect({ fee: exit.feeSats, amount: exit.amountSats }).toStrictEqual({ fee: 250, amount: 0 });
  });

  it("a malformed invoice demotes to pending with no details", () => {
    const payment = pay(
      { senderIdentityPublicKey: OUR_ID, receiverIdentityPublicKey: SSP_ID, type: "PREIMAGE_SWAP" },
      { kind: "lightning-send", status: "SUCCEEDED", invoice: "not-an-invoice", feeSats: 5 },
    );
    expect({ status: payment.status, details: payment.details }).toStrictEqual({
      status: "pending",
      details: undefined,
    });
  });

  it("createdAt mirrors the transfer creation time", () => {
    expect(pay({}).createdAt).toBe(1_700_000_000_000);
    const { createdTimeMs: _ignored, ...withoutTime } = transfer({});
    expect(
      toSparkPayment({
        transfer: withoutTime,
        request: undefined,
        identityPublicKey: OUR_ID,
        sspIdentityPublicKey: SSP_ID,
      }).createdAt,
    ).toBeUndefined();
  });
});
