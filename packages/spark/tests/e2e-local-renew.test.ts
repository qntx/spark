import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import type { createSparkClient } from "../src/client/index.ts";
import { getTimelockFromSequence } from "../src/core/bitcoin/index.ts";
import {
  bitcoinRpc,
  CLAIM_DEADLINE_MS,
  claimPendingUntil,
  claimUntilAccepted,
  leavesUntil,
  localWallet,
} from "./support/local.ts";

function refundTimelock(leaf: { refundTx: Uint8Array }): number {
  const { sequence } = Transaction.fromRaw(leaf.refundTx, {
    allowUnknownOutputs: true,
  }).getInput(0);
  if (sequence === undefined) {
    throw new Error("refund tx has no sequence");
  }
  return getTimelockFromSequence(sequence);
}

type PingPongState = {
  sender: ReturnType<typeof createSparkClient>;
  receiver: ReturnType<typeof createSparkClient>;
  senderIdentity: Uint8Array;
  receiverIdentity: Uint8Array;
  previousTimelock: number;
  previousNodeTx: Uint8Array;
  renewedRound: number;
  renewedTimelock: number;
};

// The refund timelock starts at 2000 and loses 100 per send; the send that would
// push it below 200 renews the leaf first. Recursion keeps the rounds sequential.
async function pingPongUntilRenewed(state: PingPongState, sendsLeft: number, round: number) {
  if (sendsLeft === 0) {
    return state;
  }
  await state.sender.transfers.send({
    receiver: state.receiverIdentity,
    amountSats: 100_000,
  });
  const claimed = await claimPendingUntil(state.receiver, Date.now() + CLAIM_DEADLINE_MS);
  const [claimedLeaf] = claimed;
  if (claimedLeaf === undefined) {
    throw new Error(`send ${round}: receiver claimed nothing`);
  }
  const timelock = refundTimelock(claimedLeaf);
  const renewedNow =
    timelock > state.previousTimelock ||
    bytesToHex(claimedLeaf.nodeTx) !== bytesToHex(state.previousNodeTx);
  console.log(
    renewedNow && state.renewedRound === 0
      ? `send ${round}: renewed, refund timelock ${state.previousTimelock} -> ${timelock}`
      : `send ${round}: refund timelock ${timelock}`,
  );
  await leavesUntil(state.receiver, Date.now() + CLAIM_DEADLINE_MS);
  return pingPongUntilRenewed(
    {
      sender: state.receiver,
      receiver: state.sender,
      senderIdentity: state.receiverIdentity,
      receiverIdentity: state.senderIdentity,
      previousTimelock: timelock,
      previousNodeTx: claimedLeaf.nodeTx,
      renewedRound: renewedNow && state.renewedRound === 0 ? round : state.renewedRound,
      renewedTimelock: renewedNow && state.renewedRound === 0 ? timelock : state.renewedTimelock,
    },
    sendsLeft - 1,
    round + 1,
  );
}

describe.skipIf(process.env["SPARK_E2E_LOCAL"] !== "1")("local SO timelock renewal", () => {
  test("ping-pong sends renew the leaf timelock once it drops below 200", async () => {
    const { signer: signerA, client: clientA } = await localWallet(randomBytes(32));
    const { signer: signerB, client: clientB } = await localWallet(randomBytes(32));

    const address = await clientA.deposits.newAddress();
    const txid = (await bitcoinRpc("sendtoaddress", [address, 0.001])) as string;
    const minerAddress = (await bitcoinRpc("getnewaddress", [])) as string;
    await bitcoinRpc("generatetoaddress", [1, minerAddress]);
    const rawHex = (await bitcoinRpc("getrawtransaction", [txid])) as string;
    const leafA = await claimUntilAccepted(
      clientA,
      hexToBytes(rawHex),
      Date.now() + CLAIM_DEADLINE_MS,
    );
    await leavesUntil(clientA, Date.now() + CLAIM_DEADLINE_MS);

    // 22 sends cover the ~19 sends needed to exhaust a 2000-timelock refund.
    const state = await pingPongUntilRenewed(
      {
        sender: clientA,
        receiver: clientB,
        senderIdentity: await signerA.identityPublicKey(),
        receiverIdentity: await signerB.identityPublicKey(),
        previousTimelock: refundTimelock(leafA),
        previousNodeTx: leafA.nodeTx,
        renewedRound: 0,
        renewedTimelock: 0,
      },
      22,
      1,
    );

    // A 2000-timelock refund drops by 100 per send, so renewal must fire on
    // send 20 (timelock 100 -> renewed 2000 -> decremented to 1900 by the send).
    expect(state.renewedRound).toBe(20);
    expect(state.renewedTimelock).toBe(1900);
    const finalLeaves = await leavesUntil(state.sender, Date.now() + CLAIM_DEADLINE_MS);
    expect(finalLeaves.length).toBeGreaterThan(0);
    await expect(state.sender.balance()).resolves.toBe(100_000);
    await expect(state.receiver.balance()).resolves.toBe(0);
    console.log("final holder after 22 sends:", await state.sender.balance(), "sats");

    clientA.close();
    clientB.close();
    signerA.dispose();
    signerB.dispose();
  }, 600_000);
});
