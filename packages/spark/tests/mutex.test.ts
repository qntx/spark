import { describe, expect, test } from "vite-plus/test";

import { createMutex } from "../src/core/mutex.ts";

/** A manually resolvable promise for ordering assertions. */
function deferred() {
  let release: () => void = () => undefined;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, resolve: () => release() };
}

describe("createMutex", () => {
  test("runs overlapping tasks strictly in submission order", async () => {
    const mutex = createMutex();
    const order: string[] = [];
    const gate = deferred();
    let running = 0;

    const task = async (id: string, wait: Promise<void>): Promise<string> =>
      mutex.run(async () => {
        running += 1;
        order.push(`start:${id}`);
        expect(running).toBe(1);
        await wait;
        running -= 1;
        order.push(`end:${id}`);
        return id;
      });

    const first = task("a", gate.promise);
    const second = task("b", Promise.resolve());
    const third = task("c", Promise.resolve());
    gate.resolve();
    await expect(Promise.all([first, second, third])).resolves.toStrictEqual(["a", "b", "c"]);
    expect(order).toStrictEqual(["start:a", "end:a", "start:b", "end:b", "start:c", "end:c"]);
  });

  test("a rejected task passes its error through and does not poison later tasks", async () => {
    const mutex = createMutex();
    const boom = new Error("boom");
    const order: string[] = [];

    const first = mutex.run(async () => {
      order.push("a");
      await Promise.resolve();
      throw boom;
    });
    const second = mutex.run(async () => {
      order.push("b");
      await Promise.resolve();
      return 42;
    });
    const third = mutex.run(async () => {
      order.push("c");
      await Promise.resolve();
      return "done";
    });

    await expect(first).rejects.toThrow(boom);
    await expect(second).resolves.toBe(42);
    await expect(third).resolves.toBe("done");
    expect(order).toStrictEqual(["a", "b", "c"]);
  });
});
