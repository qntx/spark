import { describe, expect, test } from "vite-plus/test";

import { p2trAddressFromPublicKey } from "../src/core/bitcoin/index.ts";
import type { HostedWallet } from "./support/hosted.ts";
import { hostedSeed, hostedWallet } from "./support/hosted.ts";

const STATUS_POLLS = 6;
const STATUS_POLL_DELAY_MS = 10_000;
const FUNDED_ADDRESS = "sparkrt1pgssy2j63j3kmdzg54wavqs2z7yljfmk7j5adt5p4046lk5dzp7qjn3mz0ecyh";

async function pollExitStatus(client: HostedWallet["client"], requestId: string): Promise<string> {
  let status = "";
  for (let i = 0; i < STATUS_POLLS; i++) {
    // oxlint-disable-next-line no-await-in-loop -- status polls are sequential by nature
    const { status: current } = await client.withdrawals.cooperativeExitStatus(requestId);
    status = current;
    console.log(`status poll ${i + 1}:`, status);
    if (status === "SUCCEEDED" || status === "FAILED" || status === "EXPIRED") {
      break;
    }
    // oxlint-disable-next-line no-await-in-loop -- status polls are sequential by nature
    await new Promise((resolve) => setTimeout(resolve, STATUS_POLL_DELAY_MS));
  }
  return status;
}

describe.skipIf(process.env["SPARK_E2E_HOSTED"] !== "1")("hosted regtest cooperative exit", () => {
  test("A quotes and cooperatively exits ~3000 sats to a P2TR address", async (ctx) => {
    const seed = hostedSeed();
    const walletA = await hostedWallet(seed, 0);
    const { client: clientA } = walletA;

    // Destination: a P2TR address we control, derived deterministically from the test
    // seed — account index 2's identity key.
    const walletDest = await hostedWallet(seed, 2);
    const destination = p2trAddressFromPublicKey(
      await walletDest.client.identityPublicKey(),
      "regtest",
    );
    walletDest.client.close();
    walletDest.signer.dispose();
    console.log("destination:", destination);

    await clientA.transfers.claimPending();
    const balanceA0 = await clientA.balance();
    console.log("A balance:", balanceA0);
    ctx.skip(
      balanceA0 < 3500,
      `hosted account 0 holds ${balanceA0} sats (< 3500) — fund ${FUNDED_ADDRESS} via the web faucet`,
    );

    const quote = await clientA.withdrawals.quoteCooperativeExit({
      address: destination,
      amountSats: 3000,
    });
    console.log(
      "quote:",
      quote.id,
      "fees fast/medium/slow:",
      quote.fees.fast,
      quote.fees.medium,
      quote.fees.slow,
      "expires:",
      new Date(quote.expiresAtMs).toISOString(),
    );

    // A generous but bounded cap: covers the slow tier with headroom while still
    // rejecting a quote that drifts far above the one we just printed.
    const maxFeeSats = quote.fees.slow + 500;
    const exit = await clientA.withdrawals.cooperativeExit({
      address: destination,
      speed: "SLOW",
      maxFeeSats,
      amountSats: 3000,
    });
    console.log(
      "exit:",
      exit.requestId,
      "transfer:",
      exit.transferId,
      "txid:",
      exit.coopExitTxid,
      "payout:",
      exit.payoutSats,
      "fee:",
      exit.feeSats,
      "status:",
      exit.status,
    );
    expect(exit.requestId.length).toBeGreaterThan(0);
    expect(exit.coopExitTxid).toMatch(/^[0-9a-f]{64}$/);
    expect(exit.feeSats).toBeLessThanOrEqual(maxFeeSats);
    expect(exit.payoutSats).toBe(3000 - exit.feeSats);

    const status = await pollExitStatus(clientA, exit.requestId);
    console.log("final status:", status);
    expect(status).not.toBe("FAILED");

    const balanceA1 = await clientA.balance();
    console.log("A balance after:", balanceA1);
    // The 3000 sats leave the wallet only once the SSP claims the inbound transfer, which
    // trails the broadcast — a balance drop is expected but its timing is the SSP's.
    expect(balanceA1).toBeLessThanOrEqual(balanceA0);

    clientA.close();
    walletA.signer.dispose();
  }, 600_000);
});
