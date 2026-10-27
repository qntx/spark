/* eslint-disable no-console -- a smoke script reports to stdout */
// Image smoke test against a live container (`SMOKE_BASE_URL`, default http://127.0.0.1:8080):
// wait for /ready, register a throwaway name over real HTTP with a signed statement, then read
// back the LNURL payRequest and check its shape. The /ready→503 leg is driven from CI.

import { randomBytes } from "node:crypto";

import { loadSparkWasm } from "@qntx/spark-wasm";
import { lightningAddressRegisterBody } from "@qntx/spark/lnurl";
import { createSparkSigner, sparkAccountKey } from "@qntx/spark/signer";

const base = process.env["SMOKE_BASE_URL"] ?? "http://127.0.0.1:8080";
const domain = process.env["SMOKE_DOMAIN"] ?? "localhost";
const name = `smoke${Date.now().toString(36)}`;

async function untilReady(deadlineMs: number): Promise<void> {
  const end = Date.now() + deadlineMs;
  for (;;) {
    try {
      // oxlint-disable-next-line no-await-in-loop -- readiness polls on an interval
      const res = await fetch(`${base}/ready`);
      if (res.status === 200) {
        return;
      }
    } catch {
      // container not up yet
    }
    if (Date.now() > end) {
      throw new Error("server never became ready");
    }
    // oxlint-disable-next-line no-await-in-loop -- readiness polls on an interval
    await new Promise<void>((resolve) => {
      setTimeout(resolve, 500);
    });
  }
}

await untilReady(60_000);
console.log("ready: /ready -> 200");

const crypto = await loadSparkWasm();
const signer = createSparkSigner({
  crypto,
  accountKey: sparkAccountKey(randomBytes(64), "regtest"),
  network: "regtest",
  random: (length) => randomBytes(length),
});
const { pubkeyHex, body } = await lightningAddressRegisterBody({
  domain,
  username: name,
  description: "smoke",
  signer,
});
const reg = await fetch(`${base}/lnurlpay/${pubkeyHex}`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(body),
});
console.log(`register: ${reg.status}`);
if (reg.status !== 200) {
  console.log(await reg.text());
  throw new Error(`register failed: ${reg.status}`);
}

const pay = await fetch(`${base}/.well-known/lnurlp/${name}`);
const raw: unknown = await pay.json();
const parsed = (typeof raw === "object" && raw !== null ? raw : {}) as {
  tag?: unknown;
  allowsNostr?: unknown;
};
const tag = typeof parsed.tag === "string" ? parsed.tag : "?";
console.log(`lnurlp: ${pay.status} tag=${tag} allowsNostr=${String(parsed.allowsNostr)}`);
if (pay.status !== 200 || parsed.tag !== "payRequest" || parsed.allowsNostr !== true) {
  throw new Error(`lnurlp shape failed: ${pay.status}`);
}
console.log("smoke OK");
