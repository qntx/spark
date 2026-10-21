import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import {
  bitcoinRpc,
  broadcastExitPackage,
  CLAIM_DEADLINE_MS,
  claimPendingUntil,
  claimUntilAccepted,
  fundP2wpkh,
  leavesUntil,
  localWallet,
  mine,
  mineUntilConfirmations,
  requiredTransfer,
  utxoFor,
} from "./support/local.ts";

describe.skipIf(process.env["SPARK_E2E_LOCAL"] !== "1")("local SO unilateral exit", () => {
  test("unilateral exit: node+refund packages confirm on-chain, refund sweeps to wallet", async () => {
    const { signer: signerA, client: clientA } = await localWallet(randomBytes(32));
    const { signer: signerB, client: clientB } = await localWallet(randomBytes(32));

    // A deposits, sends to B, B claims — B's leaf is the exit chain's tail.
    const address = await clientA.deposits.newAddress();
    const txid = (await bitcoinRpc("sendtoaddress", [address, 0.001])) as string;
    await mine(1);
    const rawHex = (await bitcoinRpc("getrawtransaction", [txid])) as string;
    await claimUntilAccepted(clientA, hexToBytes(rawHex), Date.now() + CLAIM_DEADLINE_MS);
    await leavesUntil(clientA, Date.now() + CLAIM_DEADLINE_MS);
    await clientA.transfers.send({
      receiver: await signerB.identityPublicKey(),
      amountSats: 100_000,
    });
    const claimedByB = await claimPendingUntil(clientB, Date.now() + CLAIM_DEADLINE_MS);
    const leafB = requiredTransfer(claimedByB[0]);
    await leavesUntil(clientB, Date.now() + CLAIM_DEADLINE_MS);
    console.log("exit leaf:", leafB.id);

    // The offline path builds the same broadcast list from the claim's stored exit chain as
    // the live query does — no network needed once the chain is stored.
    const [live, offline] = await Promise.all([
      clientB.withdrawals.unilateralExit([leafB.id]),
      clientB.withdrawals.offlineExitTransactions([leafB.id]),
    ]);
    expect(offline.map((tx) => tx.txid)).toStrictEqual(live.map((tx) => tx.txid));
    const exits = offline;
    expect(exits.map((e) => e.kind)).toStrictEqual(["node", "refund"]);
    const nodeExit = requiredTransfer(exits[0]);
    const refundExit = requiredTransfer(exits[1]);
    console.log(
      `exit txs: node ${nodeExit.txid} (timelock ${nodeExit.relativeTimelock}), refund ${refundExit.txid} (timelock ${refundExit.relativeTimelock})`,
    );

    // Two confirmed wallet UTXOs fund the two CPFP children.
    const fundingTx1 = await fundP2wpkh(0.0006);
    const fundingTx2 = await fundP2wpkh(0.0006);
    await mine(1);
    const utxo1 = await utxoFor(fundingTx1.txid, fundingTx1.address);
    const utxo2 = await utxoFor(fundingTx2.txid, fundingTx2.address);

    // Node tx package.
    const nodeSubmit = await broadcastExitPackage(nodeExit, utxo1);
    expect(JSON.stringify(nodeSubmit)).toContain('"package_msg":"success"');
    await mine(1);
    const nodeConfirmed = (await bitcoinRpc("getrawtransaction", [nodeExit.txid, true])) as {
      confirmations?: number;
    };
    expect(nodeConfirmed.confirmations).toBeGreaterThanOrEqual(1);
    console.log("node tx confirmed:", nodeExit.txid);

    // Watchtower observation: does an SO react to the on-chain node tx?
    const mempoolAfterNode = (await bitcoinRpc("getrawmempool", [])) as string[];
    console.log("mempool after node tx:", JSON.stringify(mempoolAfterNode));

    // The refund's BIP68 lock needs relativeTimelock confirmations on its
    // parent (the node tx); stop one block short and show the rejection.
    await mineUntilConfirmations(nodeExit.txid, refundExit.relativeTimelock - 1);
    const early = await broadcastExitPackage(refundExit, utxo2);
    expect(JSON.stringify(early)).toContain("non-BIP68-final");
    console.log("refund one block early rejected as expected");

    // utxo2 was not consumed by the rejected package; reuse it.
    await mine(1);
    const refundSubmit = await broadcastExitPackage(refundExit, utxo2);
    expect(JSON.stringify(refundSubmit)).toContain('"package_msg":"success"');
    await mine(1);
    const refundConfirmed = (await bitcoinRpc("getrawtransaction", [refundExit.txid, true])) as {
      confirmations?: number;
    };
    expect(refundConfirmed.confirmations).toBeGreaterThanOrEqual(1);
    console.log("refund tx confirmed:", refundExit.txid);
    console.log("mempool after refund:", JSON.stringify(await bitcoinRpc("getrawmempool", [])));

    // Sweep the confirmed refund output to a fresh wallet address.
    const sweepAddress = (await bitcoinRpc("getnewaddress", ["", "bech32"])) as string;
    const sweepInfo = (await bitcoinRpc("getaddressinfo", [sweepAddress])) as {
      scriptPubKey: string;
    };
    const sweepTx = await clientB.withdrawals.sweepRefund({
      leafId: leafB.id,
      refundTx: refundExit.transaction,
      destinationScript: hexToBytes(sweepInfo.scriptPubKey),
      feeRateSatPerVbyte: 2,
    });
    const sweepTxid = (await bitcoinRpc("sendrawtransaction", [bytesToHex(sweepTx)])) as string;
    await mine(1);
    const sweepConfirmed = (await bitcoinRpc("getrawtransaction", [sweepTxid, true])) as {
      confirmations?: number;
      vout: ReadonlyArray<{ value: number; scriptPubKey: { address?: string } }>;
    };
    expect(sweepConfirmed.confirmations).toBeGreaterThanOrEqual(1);
    const swept = requiredTransfer(
      sweepConfirmed.vout.find((o) => o.scriptPubKey.address === sweepAddress),
    );
    const sweptSats = Math.round(swept.value * 1e8);
    console.log(`swept ${sweptSats} sats to ${sweepAddress} (refund was ${leafB.valueSats})`);
    expect(sweptSats).toBeGreaterThan(leafB.valueSats - 1000);
    expect(sweptSats).toBeLessThan(leafB.valueSats);

    clientA.close();
    clientB.close();
    signerA.dispose();
    signerB.dispose();
  }, 600_000);
});
