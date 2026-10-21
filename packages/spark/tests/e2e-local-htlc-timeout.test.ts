import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import { LIGHTNING_HTLC_SEQUENCE, lightningHtlcOutputScript } from "../src/core/bitcoin/htlc.ts";
import { p2trAddressFromScript } from "../src/core/bitcoin/script.ts";
import { txIdInputBytes } from "../src/core/bitcoin/transactions.ts";
import { sparkNetworkConfig } from "../src/core/network.ts";
import {
  bitcoinRpc,
  confirmations,
  destinationFor,
  localTestWallet,
  mine,
  mineUntilConfirmations,
  required,
} from "./support/local.ts";

describe.skipIf(process.env["SPARK_E2E_LOCAL"] !== "1")("lightning HTLC timeout sweep", () => {
  test("the sequence-lock leaf sweep relays only after the HTLC CSV matures", async () => {
    const wallet = await localTestWallet(randomBytes(32));
    const { client } = wallet;

    // Fund an HTLC output the way a committed Lightning refund tx builds it: the SSP on the
    // hash-lock leaf, this wallet's identity on the sequence-lock leaf.
    const paymentHash = sha256(randomBytes(32));
    const sspIdentity = sparkNetworkConfig("regtest").ssp.identityPublicKey;
    const htlcScript = lightningHtlcOutputScript(paymentHash, sspIdentity, wallet.identity);
    const fundTxid = (await bitcoinRpc("sendtoaddress", [
      p2trAddressFromScript(htlcScript, "regtest"),
      0.0002,
    ])) as string;
    await mine(1);
    const htlcTx = hexToBytes((await bitcoinRpc("getrawtransaction", [fundTxid])) as string);

    const verbose = (await bitcoinRpc("getrawtransaction", [fundTxid, true])) as {
      vout: ReadonlyArray<{ n: number; scriptPubKey: { hex: string } }>;
    };
    const funded = required(
      verbose.vout.find((out) => out.scriptPubKey.hex === bytesToHex(htlcScript)),
      "funding tx has no HTLC output",
    );

    const destination = await destinationFor();
    const signed = await client.lightning.sweepHtlcTimeout({
      htlcTx,
      vout: funded.n,
      paymentHash,
      destinationAddress: destination.address,
      feeRateSatPerVbyte: 2,
    });

    const sweep = Transaction.fromRaw(signed, { allowUnknownOutputs: true });
    const input = sweep.getInput(0);
    expect(bytesToHex(required(input.txid, "sweep input txid"))).toBe(
      bytesToHex(txIdInputBytes(htlcTx)),
    );
    expect(input.index).toBe(funded.n);
    expect(Number(input.sequence)).toBe(LIGHTNING_HTLC_SEQUENCE);
    expect(bytesToHex(required(sweep.getOutput(0).script, "sweep output script"))).toBe(
      bytesToHex(destination.script),
    );

    // Before the CSV matures the spend is not final.
    await expect(bitcoinRpc("sendrawtransaction", [bytesToHex(signed)])).rejects.toThrow(
      /non-BIP68-final/,
    );

    await mineUntilConfirmations(fundTxid, LIGHTNING_HTLC_SEQUENCE + 1);
    const sweepTxid = (await bitcoinRpc("sendrawtransaction", [bytesToHex(signed)])) as string;
    await mine(1);
    await expect(confirmations(sweepTxid)).resolves.toBeGreaterThanOrEqual(1);

    // null here means the sweep never confirmed — the property reads below fail the test.
    const utxo = (await bitcoinRpc("gettxout", [sweepTxid, 0])) as {
      scriptPubKey: { hex: string };
      value: number;
    };
    expect(utxo.scriptPubKey.hex).toBe(bytesToHex(destination.script));
    expect(Math.round(utxo.value * 1e8)).toBeGreaterThan(0);
  }, 600_000);
});
