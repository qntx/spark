import { describe, expect, test } from "vite-plus/test";

import { createMemorySparkStore } from "../src/exit/store.ts";
import type { SparkExitChain } from "../src/exit/store.ts";

function chain(leafId: string, bytes = 1): SparkExitChain {
  return {
    leafId,
    nodes: [
      { nodeId: `${leafId}-root`, nodeTx: new Uint8Array([bytes]) },
      {
        nodeId: leafId,
        nodeTx: new Uint8Array([bytes + 1]),
        directTx: new Uint8Array([bytes + 2]),
      },
    ],
    refundTx: new Uint8Array([bytes + 3]),
    directRefundTx: new Uint8Array([bytes + 4]),
    directFromCpfpRefundTx: new Uint8Array([bytes + 5]),
  };
}

describe("createMemorySparkStore", () => {
  test("put/upsert/delete by leafId", async () => {
    const store = createMemorySparkStore();
    await store.putExitChains([chain("a"), chain("b")]);
    const all = await store.exitChains();
    expect(all.map((c) => c.leafId).toSorted()).toStrictEqual(["a", "b"]);

    await store.putExitChains([chain("a", 9)]);
    const afterUpsert = await store.exitChains();
    const updated = afterUpsert.find((c) => c.leafId === "a");
    expect(updated?.refundTx).toStrictEqual(new Uint8Array([12]));

    await store.deleteExitChains(["a"]);
    const remaining = await store.exitChains();
    expect(remaining.map((c) => c.leafId)).toStrictEqual(["b"]);
    await store.deleteExitChains(["missing"]);
    const afterNoop = await store.exitChains();
    expect(afterNoop).toHaveLength(1);
  });

  test("stored bytes cannot be aliased through put or read", async () => {
    const store = createMemorySparkStore();
    const original = chain("a");
    await store.putExitChains([original]);
    // Mutating the caller's array must not corrupt the stored chain.
    original.refundTx.fill(0xff);
    original.nodes[0]?.nodeTx.fill(0xff);
    const firstRead = await store.exitChains();
    let stored = firstRead.find((c) => c.leafId === "a");
    expect(stored?.refundTx).toStrictEqual(new Uint8Array([4]));
    expect(stored?.nodes[0]?.nodeTx).toStrictEqual(new Uint8Array([1]));
    // Mutating a read copy must not corrupt the stored chain either.
    stored?.refundTx.fill(0xee);
    stored?.nodes[1]?.directTx?.fill(0xee);
    const secondRead = await store.exitChains();
    stored = secondRead.find((c) => c.leafId === "a");
    expect(stored?.refundTx).toStrictEqual(new Uint8Array([4]));
    expect(stored?.nodes[1]?.directTx).toStrictEqual(new Uint8Array([3]));
  });
});
