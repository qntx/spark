#!/usr/bin/env bun
/// <reference types="node" />
// Hosted-suite balance guard: prints account 0's spendable balance (sats, one
// number) and exits 1 below MIN_BALANCE_SATS with the faucet instructions. The
// spark address is public; the seed is never logged. .github/workflows/regtest.yml
// runs this before and after the hosted suite; locally it works the same way
// (seed from SPARK_HOSTED_SEED or the gitignored .env.hosted).
import { encodeSparkAddress } from "../src/core/address.ts";
import { hostedSeed, hostedWallet } from "../tests/support/hosted.ts";

const MIN_BALANCE_SATS = 100_000;

const wallet = await hostedWallet(hostedSeed(), 0);
const balance = await wallet.client.balance();
const address = encodeSparkAddress({
  network: "regtest",
  identityPublicKey: await wallet.signer.identityPublicKey(),
});
console.log(balance);
wallet.client.close();
wallet.signer.dispose();
if (balance < MIN_BALANCE_SATS) {
  console.error(
    `hosted balance ${balance} sats is below ${MIN_BALANCE_SATS} — top up via ` +
      `https://app.lightspark.com/regtest-faucet (account 0 address: ${address})`,
  );
  process.exit(1);
}
