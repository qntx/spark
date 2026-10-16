import { describe, expect, test } from "vite-plus/test";

import { checkParity } from "./check.ts";

const exists =
  (files: string[]) =>
  (path: string): boolean =>
    files.includes(path);

const CAPABILITY = {
  id: "frost.sign",
  implementations: {
    rust: { module: "crates/spark-crypto/src/frost.rs", tests: ["crates/interop/tests/frost.rs"] },
    ts: { module: "packages/spark/src/crypto/index.ts", tests: ["packages/spark/tests/f.test.ts"] },
  },
  vectors: ["vectors/frost-sign.json"],
};

const FILES = [
  "crates/spark-crypto/src/frost.rs",
  "crates/interop/tests/frost.rs",
  "packages/spark/src/crypto/index.ts",
  "packages/spark/tests/f.test.ts",
  "vectors/frost-sign.json",
];

describe("parity check", () => {
  test("accepts an empty capability list", () => {
    expect(checkParity({ schema: 1, capabilities: [] }, [], exists([]))).toStrictEqual([]);
  });

  test("accepts a consistent capability", () => {
    const errors = checkParity(
      { schema: 1, capabilities: [CAPABILITY] },
      ["vectors/frost-sign.json"],
      exists(FILES),
    );
    expect(errors).toStrictEqual([]);
  });

  test("rejects a missing capabilities array", () => {
    expect(checkParity({}, [], exists([]))).toStrictEqual([
      'parity.json: missing "capabilities" array',
    ]);
  });

  test("rejects an unknown implementation target", () => {
    const cap = {
      ...CAPABILITY,
      implementations: { ...CAPABILITY.implementations, hermes: { module: "x.ts" } },
    };
    const errors = checkParity({ capabilities: [cap] }, [], exists([...FILES, "x.ts"]));
    expect(errors).toStrictEqual([
      'capability "frost.sign": unknown implementation target "hermes"',
    ]);
  });

  test("rejects a missing referenced file", () => {
    const errors = checkParity({ capabilities: [CAPABILITY] }, [], exists([]));
    expect(errors).toContain(
      'capability "frost.sign": rust path does not exist: crates/spark-crypto/src/frost.rs',
    );
    expect(errors).toContain(
      'capability "frost.sign": vector file does not exist: vectors/frost-sign.json',
    );
  });

  test("rejects an unreferenced vector file", () => {
    const errors = checkParity(
      { capabilities: [CAPABILITY] },
      ["vectors/frost-sign.json", "vectors/orphan.json"],
      exists([...FILES, "vectors/orphan.json"]),
    );
    expect(errors).toStrictEqual([
      "vector file is not referenced by any capability: vectors/orphan.json",
    ]);
  });

  test("rejects a duplicate capability id", () => {
    const errors = checkParity(
      { capabilities: [CAPABILITY, CAPABILITY] },
      ["vectors/frost-sign.json"],
      exists(FILES),
    );
    expect(errors).toStrictEqual(['capability "frost.sign": duplicate id']);
  });
});
