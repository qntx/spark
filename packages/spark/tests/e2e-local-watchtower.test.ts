import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import type { createSparkClient } from "../src/client/index.ts";
import { getTimelockFromSequence, txId } from "../src/core/bitcoin/index.ts";
import type { SparkExitChain, SparkStore } from "../src/exit/store.ts";
import type { WatchtowerExitedLeaf } from "../src/exit/watchtower.ts";
import type { SparkLeaf } from "../src/tree/index.ts";
import {
  bitcoinRpc,
  CLAIM_DEADLINE_MS,
  claimPendingUntil,
  claimUntilAccepted,
  generateBlockWith,
  leavesUntil,
  localWallet,
  mine,
} from "./support/local.ts";

const SEND_SATS = 100_000;
// 18 sends walk the refund timelock 2000 -> 200, the 19th renews. Twice that, plus slack.
const MAX_SENDS = 60;
const RENEWALS_REQUIRED = 2;

function refundTimelock(leaf: { refundTx: Uint8Array }): number {
  const { sequence } = Transaction.fromRaw(leaf.refundTx, {
    allowUnknownOutputs: true,
  }).getInput(0);
  if (sequence === undefined) {
    throw new Error("refund tx has no sequence");
  }
  return getTimelockFromSequence(sequence);
}

function required<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new Error(what);
  }
  return value;
}

type Wallet = {
  client: ReturnType<typeof createSparkClient>;
  store: SparkStore;
  identity: Uint8Array;
};

async function transferWholeLeaf(from: Wallet, to: Wallet): Promise<SparkLeaf> {
  await from.client.transfers.send({ receiver: to.identity, amountSats: SEND_SATS });
  const claimed = await claimPendingUntil(to.client, Date.now() + CLAIM_DEADLINE_MS);
  const leaf = required(claimed[0], "receiver claimed nothing");
  await leavesUntil(to.client, Date.now() + CLAIM_DEADLINE_MS);
  return leaf;
}

type PingPongResult = {
  holder: Wallet;
  leaf: SparkLeaf;
  renewals: number;
};

/** Ping-pong the whole leaf until it has renewed `needed` times (or `MAX_SENDS` runs out). */
async function pingPongUntilRenewed(
  holder: Wallet,
  other: Wallet,
  leaf: SparkLeaf,
  needed: number,
): Promise<PingPongResult> {
  let previousTimelock = refundTimelock(leaf);
  let renewals = 0;
  let current = leaf;
  for (let i = 1; renewals < needed && i <= MAX_SENDS; i++) {
    // oxlint-disable-next-line no-await-in-loop -- sends must stay sequential
    current = await transferWholeLeaf(holder, other);
    [holder, other] = [other, holder];
    const timelock = refundTimelock(current);
    if (timelock > previousTimelock) {
      renewals += 1;
      console.log(`send ${i}: renewed (${renewals}), refund timelock ${timelock}`);
    }
    previousTimelock = timelock;
  }
  return { holder, leaf: current, renewals };
}

/** The exit chain's parent and grandparent — the nodes above the leaf, root first. */
function chainAncestors(chains: ReadonlyArray<SparkExitChain>, leafId: string) {
  const chain = chains.find((entry) => entry.leafId === leafId);
  if (chain === undefined || chain.nodes.length < 3) {
    throw new Error(`exit chain for ${leafId} has ${chain?.nodes.length ?? 0} nodes`);
  }
  const parent = required(chain.nodes.at(-2), "exit chain is missing the parent node");
  const grandparent = required(chain.nodes.at(-3), "exit chain is missing the grandparent node");
  return { parent, grandparent };
}

/** Polls the watchtower-exited listing for `leafId`, driving the chain watcher with fresh blocks. */
async function watchtowerExitedUntil(
  client: ReturnType<typeof createSparkClient>,
  leafId: string,
): Promise<WatchtowerExitedLeaf> {
  for (let attempt = 0; attempt < 30; attempt++) {
    // oxlint-disable-next-line no-await-in-loop -- the chain watcher only acts on a new block
    const listed = await client.withdrawals.watchtowerExitedLeaves();
    const entry = listed.find((candidate) => candidate.leafId === leafId);
    if (entry !== undefined) {
      return entry;
    }
    console.log(`poll ${attempt}: leaf not yet watchtower-exited`);
    // oxlint-disable-next-line no-await-in-loop -- drive the chain watcher
    await mine(2);
  }
  throw new Error("leaf never reached a watchtower-exited status");
}

async function destinationFor(): Promise<{ address: string; script: Uint8Array }> {
  const address = (await bitcoinRpc("getnewaddress", [])) as string;
  const info = (await bitcoinRpc("getaddressinfo", [address])) as { scriptPubKey: string };
  return { address, script: hexToBytes(info.scriptPubKey) };
}

describe.skipIf(process.env["SPARK_E2E_LOCAL"] !== "1")("local SO watchtower exit", () => {
  test("watchtower exit strands the leaf; recovery re-signs the stranded output", async () => {
    const { signer: signerA, store: storeA, client: clientA } = await localWallet(randomBytes(32));
    const { signer: signerB, store: storeB, client: clientB } = await localWallet(randomBytes(32));
    const walletA: Wallet = {
      client: clientA,
      store: storeA,
      identity: await signerA.identityPublicKey(),
    };
    const walletB: Wallet = {
      client: clientB,
      store: storeB,
      identity: await signerB.identityPublicKey(),
    };

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
    console.log("deposited leaf:", leafId, "refund timelock", refundTimelock(deposited));

    const { holder, leaf, renewals } = await pingPongUntilRenewed(
      walletA,
      walletB,
      deposited,
      RENEWALS_REQUIRED,
    );
    expect(renewals).toBe(RENEWALS_REQUIRED);
    expect(leaf.id).toBe(leafId);

    // Confirming the grandparent's node tx — zero-fee, so it must be mined directly —
    // tells the watchtower an exit is underway below it.
    const { parent, grandparent } = chainAncestors(await holder.store.exitChains(), leafId);
    const parentDirectTx = required(parent.directTx, "parent direct tx missing from exit chain");
    const parentDirectTxid = txId(parentDirectTx);
    console.log(
      "grandparent node tx:",
      txId(grandparent.nodeTx),
      "parent direct tx:",
      parentDirectTxid,
    );
    await generateBlockWith([bytesToHex(grandparent.nodeTx)]);
    await mine(6);

    // The parent's direct tx unlocks 50 blocks past the grandparent's confirmation; the
    // SO's watchtower broadcasts it and marks every descendant WATCHTOWER_EXITED.
    await mine(55);
    const stranded = await watchtowerExitedUntil(holder.client, leafId);
    console.log("watchtower-exited leaf:", stranded.leafId, stranded.status);
    expect(stranded.status).toBe("WATCHTOWER_EXITED");
    expect(stranded.valueSats).toBe(SEND_SATS);
    const recovery = required(stranded.recovery, "listed leaf has no recovery output");
    expect(recovery.txid).toBe(parentDirectTxid);
    expect(recovery.valueSats).toBeGreaterThan(0);

    // The stranded leaf is out of the spendable pool.
    const leaves = await leavesUntil(holder.client, Date.now() + CLAIM_DEADLINE_MS);
    expect(leaves.map((entry) => entry.id)).not.toContain(leafId);

    const destination = await destinationFor();
    const recovered = await holder.client.withdrawals.recoverWatchtowerExit({
      leafId,
      recoveryTxid: recovery.txid,
      outputIndex: recovery.outputIndex,
      destinationScript: destination.script,
      feeRateSatPerVbyte: 5,
    });
    const signed = Transaction.fromRaw(recovered.transaction, { allowUnknownOutputs: true });
    const input = signed.getInput(0);
    expect(bytesToHex(required(input.txid, "recovery input txid"))).toBe(recovery.txid);
    expect(input.index).toBe(recovery.outputIndex);
    const output = signed.getOutput(0);
    const outputSats = required(output.amount, "recovery output amount");
    expect(outputSats).toBeLessThan(BigInt(recovery.valueSats));
    console.log("recovery tx:", recovered.txid, "pays out", outputSats, "sats");

    // Signing retires the leaf — the SE never sees the broadcast.
    const relisted = await holder.client.withdrawals.watchtowerExitedLeaves();
    expect(relisted.find((entry) => entry.leafId === leafId)?.status).toBe(
      "WATCHTOWER_EXIT_RECOVERED",
    );

    // Re-signing without a txid picks the same outpoint at a higher fee.
    const bumped = await holder.client.withdrawals.recoverWatchtowerExit({
      leafId,
      destinationScript: destination.script,
      feeRateSatPerVbyte: 20,
    });
    const bumpedTx = Transaction.fromRaw(bumped.transaction, { allowUnknownOutputs: true });
    const bumpedInput = bumpedTx.getInput(0);
    expect(bytesToHex(required(bumpedInput.txid, "bumped input txid"))).toBe(recovery.txid);
    expect(bumpedInput.index).toBe(recovery.outputIndex);
    const bumpedSats = required(bumpedTx.getOutput(0).amount, "bumped output amount");
    expect(bumpedSats).toBeLessThan(outputSats);

    const recoveryTxid = (await bitcoinRpc("sendrawtransaction", [
      bytesToHex(bumped.transaction),
    ])) as string;
    console.log("broadcast recovery tx:", recoveryTxid);
    await mine(2);
    const received = (await bitcoinRpc("getreceivedbyaddress", [destination.address])) as number;
    console.log("destination received:", received, "BTC");
    expect(Math.round(received * 1e8)).toBe(Number(bumpedSats));

    clientA.close();
    clientB.close();
    signerA.dispose();
    signerB.dispose();
  }, 900_000);
});
