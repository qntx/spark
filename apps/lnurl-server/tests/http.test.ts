import { describe, expect, test } from "vite-plus/test";

import type { LightningAddressServer } from "@qntx/spark/server";

import { MAX_BODY_BYTES, createLnurlApp } from "../src/http.ts";

type Call = { method: string; args: ReadonlyArray<unknown> };

function fakeServer(results: Partial<Record<string, { status: number; body: unknown }>> = {}): {
  server: LightningAddressServer;
  calls: Call[];
} {
  const calls: Call[] = [];
  const canned = (method: string) => results[method] ?? { status: 200, body: { ok: method } };
  const record = (method: string) => {
    return async (...args: ReadonlyArray<unknown>) => {
      calls.push({ method, args });
      return Promise.resolve(canned(method));
    };
  };
  const server = {
    register: record("register"),
    unregister: record("unregister"),
    payRequest: record("payRequest"),
    invoice: record("invoice"),
    verify: record("verify"),
    settlePending: record("settlePending"),
  } as unknown as LightningAddressServer;
  return { calls, server };
}

describe("lnurl http routes", () => {
  test("POST/DELETE /lnurlpay/:pubkey forward the JSON body", async () => {
    const { calls, server } = fakeServer({ register: { status: 200, body: { lnurl: "l" } } });
    const app = createLnurlApp(server);
    const body = JSON.stringify({ username: "alice" });
    const res = await app.request(`/lnurlpay/${"aa".repeat(33)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toStrictEqual({ lnurl: "l" });
    expect(calls[0]).toStrictEqual({
      method: "register",
      args: ["aa".repeat(33), { username: "alice" }],
    });

    const del = await app.request(`/lnurlpay/${"bb".repeat(33)}`, {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "alice", signature: "ff", timestamp: 1 }),
    });
    expect(del.status).toBe(200);
    expect(calls[1]?.method).toBe("unregister");
  });

  test("malformed JSON is a 400 and an oversized body a 413", async () => {
    const { calls, server } = fakeServer();
    const app = createLnurlApp(server);
    const bad = await app.request(`/lnurlpay/${"aa".repeat(33)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{not-json",
    });
    expect(bad.status).toBe(400);

    const huge = await app.request(`/lnurlpay/${"aa".repeat(33)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: `{"pad":"${"x".repeat(MAX_BODY_BYTES)}"}`,
    });
    expect(huge.status).toBe(413);
    // Neither request reached the handlers.
    expect(calls).toHaveLength(0);
  });

  test("GET routes map query params and CORS is open", async () => {
    const { calls, server } = fakeServer();
    const app = createLnurlApp(server);
    const res = await app.request("/lnurlp/alice/invoice?amount=7000&comment=hi&nostr=%7B%7D");
    expect(res.status).toBe(200);
    expect(res.headers.get("access-control-allow-origin")).toBe("*");
    expect(calls[0]).toStrictEqual({
      method: "invoice",
      args: ["alice", { amount: 7000, comment: "hi", nostr: "{}" }],
    });

    await app.request("/lnurlp/alice/invoice?amount=not-a-number");
    // A non-integer amount is passed through raw for the handler to reject.
    expect(calls[1]?.args[1]).toStrictEqual({ amount: "not-a-number" });

    await app.request("/.well-known/lnurlp/bob");
    expect(calls[2]).toStrictEqual({ method: "payRequest", args: ["bob"] });
    await app.request("/lnurlp/carol");
    expect(calls[3]).toStrictEqual({ method: "payRequest", args: ["carol"] });
  });

  test("the verify user's invoice callback outranks /lnurlp/verify/:hash", async () => {
    const { calls, server } = fakeServer();
    const app = createLnurlApp(server);
    await app.request("/lnurlp/verify/invoice?amount=1000");
    expect(calls[0]?.method).toBe("invoice");
    expect(calls[0]?.args[0]).toBe("verify");

    await app.request("/lnurlp/verify/deadbeef");
    expect(calls[1]).toStrictEqual({ method: "verify", args: ["deadbeef"] });

    // And "verify" still resolves as a username on the other routes.
    await app.request("/lnurlp/verify");
    expect(calls[2]).toStrictEqual({ method: "payRequest", args: ["verify"] });
  });

  test("string bodies serialize as JSON strings; health is a bare 200", async () => {
    const { server } = fakeServer({ payRequest: { status: 404, body: "not found" } });
    const app = createLnurlApp(server);
    const res = await app.request("/lnurlp/missing");
    expect(res.status).toBe(404);
    await expect(res.json()).resolves.toBe("not found");

    const health = await app.request("/health");
    expect(health.status).toBe(200);
  });
});
