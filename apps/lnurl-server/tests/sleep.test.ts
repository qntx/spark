import { getEventListeners } from "node:events";

import { describe, expect, test } from "vite-plus/test";

import { abortableSleep } from "../src/sleep.ts";

describe("abortableSleep", () => {
  test("resolves after the delay and removes its abort listener", async () => {
    const controller = new AbortController();
    const start = Date.now();
    await abortableSleep(20, controller.signal);
    expect(Date.now() - start).toBeGreaterThanOrEqual(15);
    expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
  });

  test("resolves early on abort and leaves no listener or timer behind", async () => {
    const controller = new AbortController();
    const start = Date.now();
    const pending = abortableSleep(60_000, controller.signal);
    controller.abort();
    await pending;
    expect(Date.now() - start).toBeLessThan(5000);
    expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
  });

  test("an already-aborted signal resolves immediately", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(abortableSleep(60_000, controller.signal)).resolves.toBeUndefined();
    expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
  });

  test("repeated rounds accumulate no listeners", async () => {
    const controller = new AbortController();
    await Promise.all(Array.from({ length: 64 }, async () => abortableSleep(1, controller.signal)));
    expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
  });
});
