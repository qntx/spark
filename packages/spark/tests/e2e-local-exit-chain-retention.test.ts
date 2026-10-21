import { hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import {
  bitcoinRpc,
  broadcastExitPackage,
  CLAIM_DEADLINE_MS,
  claimUntilAccepted,
  fundP2wpkh,
  leavesUntil,
  localTestWallet,
  mine,
  requiredTransfer,
  storedExitChain,
  utxoFor,
} from "./support/local.ts";

// Regression coverage for external-audit round-10 N-02, against a real SO cluster: a leaf whose
// node transaction confirmed flips from AVAILABLE to ON_CHAIN while its refund is still
// CSV-locked. The sync sweep must keep the stored exit chain — absence from the AVAILABLE list
// is not evidence the exit path ended — so `offlineExitTransactions` still serves the refund
// for a wallet that goes offline mid-exit.
describe.skipIf(process.env["SPARK_E2E_LOCAL"] !== "1")("local SO exit-chain retention", () => {
  test("an ON_CHAIN leaf keeps its stored exit chain through sync", async () => {
    const { client, store } = await localTestWallet(randomBytes(32));

    const address = await client.deposits.newAddress();
    const txid = (await bitcoinRpc("sendtoaddress", [address, 0.001])) as string;
    await mine(1);
    const rawHex = (await bitcoinRpc("getrawtransaction", [txid])) as string;
    const claimed = await claimUntilAccepted(
      client,
      hexToBytes(rawHex),
      Date.now() + CLAIM_DEADLINE_MS,
    );
    const leafId = claimed.id;
    await leavesUntil(client, Date.now() + CLAIM_DEADLINE_MS);
    const stored = storedExitChain(await store.exitChains(), leafId);
    console.log("exit chain stored for", leafId, "nodes:", stored.nodes.length);

    const exits = await client.withdrawals.unilateralExit([leafId]);
    const nodeExit = requiredTransfer(exits[0]);
    console.log(`exit txs: node ${nodeExit.txid} refund ${requiredTransfer(exits[1]).txid}`);

    const funding = await fundP2wpkh(0.0006);
    await mine(1);
    const utxo = await utxoFor(funding.txid, funding.address);

    // Broadcast ONLY the node tx. It confirms -> operators mark the node ON_CHAIN while the
    // refund is still unbroadcast and CSV-locked — the in-progress unilateral exit.
    const submit = await broadcastExitPackage(nodeExit, utxo);
    expect(JSON.stringify(submit)).toContain('"package_msg":"success"');
    await mine(1);
    const confirmed = (await bitcoinRpc("getrawtransaction", [nodeExit.txid, true])) as {
      confirmations?: number;
    };
    expect(confirmed.confirmations).toBeGreaterThanOrEqual(1);
    console.log("node tx confirmed:", nodeExit.txid);
    await mine(1); // let the SO's chain watcher observe it

    // The sync sweep must not reclaim the stored chain: the leaf has left the AVAILABLE list
    // but its exit path is live. balance()/leaves() may drop the leaf; the chain stays.
    const balance = await client.balance();
    const leaves = await client.leaves();
    const leafVisible = leaves.some((leaf) => leaf.id === leafId);
    console.log(`post-onchain sync: balance=${balance} leaf visible=${leafVisible}`);
    const chainsAfter = await store.exitChains();
    expect(chainsAfter.some((chain) => chain.leafId === leafId)).toBe(true);
    const offline = await client.withdrawals.offlineExitTransactions([leafId]);
    expect(offline.map((tx) => tx.txid)).toStrictEqual(exits.map((tx) => tx.txid));
    console.log("chain retained; offline package still complete:", offline.length, "txs");
  }, 600_000);
});
