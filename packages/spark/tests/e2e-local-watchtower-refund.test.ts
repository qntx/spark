import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import { txId } from "../src/core/bitcoin/index.ts";
import {
  awaitWatchtowerBroadcast,
  bitcoinRpc,
  CLAIM_DEADLINE_MS,
  claimUntilAccepted,
  destinationFor,
  generateBlockWith,
  knownConfirmations,
  leavesUntil,
  localTestWallet,
  mine,
  pingPongUntilRenewed,
  refundTimelock,
  required,
  storedExitChain,
} from "./support/local.ts";

const SEND_SATS = 100_000;

describe.skipIf(process.env["SPARK_E2E_LOCAL"] !== "1")("local SO watchtower refund", () => {
  test("watchtower broadcasts direct-from-cpfp refund; sweepRefund spends its output", async () => {
    const walletA = await localTestWallet(randomBytes(32));
    const walletB = await localTestWallet(randomBytes(32));
    const { client: clientA, signer: signerA } = walletA;
    const { client: clientB, signer: signerB } = walletB;

    const address = await clientA.deposits.newAddress();
    const depositTxid = (await bitcoinRpc("sendtoaddress", [address, 0.001])) as string;
    await mine(1);
    const rawHex = (await bitcoinRpc("getrawtransaction", [depositTxid])) as string;
    const deposited = await claimUntilAccepted(
      clientA,
      hexToBytes(rawHex),
      Date.now() + CLAIM_DEADLINE_MS,
    );
    await leavesUntil(clientA, Date.now() + CLAIM_DEADLINE_MS);
    const leafId = deposited.id;

    // One zero-timelock renewal leaves the leaf carrying witness-stripped
    // directTx / directFromCpfpRefundTx templates alongside its node tx; keep
    // ping-ponging afterwards to walk the refund timelock down — same mechanism,
    // far fewer blocks to mine.
    const { holder, leaf, renewals } = await pingPongUntilRenewed(walletA, walletB, deposited, {
      needed: 1,
      amountSats: SEND_SATS,
      refundBelow: 300,
    });
    expect(renewals).toBe(1);
    expect(leaf.id).toBe(leafId);

    const chain = storedExitChain(await holder.store.exitChains(), leafId);
    const leafNode = required(chain.nodes.at(-1), "exit chain has no leaf node");
    const directTx = required(leafNode.directTx, "renewed leaf has no directTx template");
    const directRefund = required(
      chain.directFromCpfpRefundTx,
      "renewed leaf has no direct-from-cpfp refund template",
    );
    const directTxid = txId(directTx);
    const directRefundTxid = txId(directRefund);
    const refundTimelockBlocks = refundTimelock({ refundTx: directRefund });
    console.log(
      `leaf ${leafId}: directTx ${directTxid} (never broadcasts — node tx confirmed),`,
      `direct-from-cpfp refund ${directRefundTxid} timelock ${refundTimelockBlocks}`,
    );

    // The templates carry no witness — they cannot be broadcast, only recognised.
    const stripped = Transaction.fromRaw(directRefund, { allowUnknownOutputs: true });
    expect(stripped.getInput(0).finalScriptWitness).toBeUndefined();

    // Mining the whole chain's node txs (root first — each input spends the previous
    // node's output) lands the leaf on-chain in time, so the watchtower skips its
    // directTx and only arms the refund deadline.
    await generateBlockWith(chain.nodes.map((node) => bytesToHex(node.nodeTx)));
    await expect(knownConfirmations(txId(leafNode.nodeTx))).resolves.toBe(1);

    // The refund's BIP-68 timelock counts from the leaf node tx's confirmation; mine
    // right up to it, then keep mining in batches until the watchtower publishes.
    await mine(refundTimelockBlocks);
    await awaitWatchtowerBroadcast(directRefundTxid, 20, 30);
    const refundConfs = await knownConfirmations(directRefundTxid);
    expect(refundConfs).toBeGreaterThanOrEqual(1);
    await expect(knownConfirmations(directTxid)).resolves.toBe(-1);
    console.log(`direct-from-cpfp refund confirmed (${refundConfs} confs); directTx never aired`);

    // The refund output pays the leaf key-path — a witness-less template is all
    // sweepRefund needs to recognise and spend it.
    const destination = await destinationFor();
    const sweep = await holder.client.withdrawals.sweepRefund({
      leafId,
      refundTx: directRefund,
      destinationScript: destination.script,
      feeRateSatPerVbyte: 5,
    });
    const sweepTx = Transaction.fromRaw(sweep, { allowUnknownOutputs: true });
    const sweepInput = sweepTx.getInput(0);
    expect(bytesToHex(required(sweepInput.txid, "sweep input txid"))).toBe(directRefundTxid);
    expect(sweepInput.index).toBe(0);
    const sweptSats = required(sweepTx.getOutput(0).amount, "sweep output amount");
    expect(sweptSats).toBeLessThan(BigInt(SEND_SATS));
    console.log("sweep tx:", txId(sweep), "pays", sweptSats, "sats");

    const sweepTxid = (await bitcoinRpc("sendrawtransaction", [bytesToHex(sweep)])) as string;
    await mine(1);
    await expect(knownConfirmations(sweepTxid)).resolves.toBeGreaterThanOrEqual(1);
    const received = (await bitcoinRpc("getreceivedbyaddress", [destination.address])) as number;
    expect(Math.round(received * 1e8)).toBe(Number(sweptSats));
    console.log("destination received", received, "BTC — refund swept to bitcoind");

    clientA.close();
    clientB.close();
    signerA.dispose();
    signerB.dispose();
  }, 1_200_000);
});
