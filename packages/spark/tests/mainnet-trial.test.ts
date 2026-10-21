// Unit tests for the mainnet trial runner: file store durability, ledger
// accounting, seed loading and command ledger behaviour against fakes — no
// network, no real keys.
import {
  chmodSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { afterEach, describe, expect, test } from "vite-plus/test";

import { envFileValue, envSeed } from "../scripts/env-seed.ts";
import {
  cmdClaim,
  cmdPay,
  cmdReport,
  cmdSend,
  LedgerMismatchError,
  MAX_TRIAL_SATS,
} from "../scripts/mainnet-trial/commands.ts";
import type { TrialDeps } from "../scripts/mainnet-trial/commands.ts";
import { createFileSparkStore } from "../scripts/mainnet-trial/file-store.ts";
import { createLedger, formatLedgerReport } from "../scripts/mainnet-trial/ledger.ts";
import type { LedgerEntry } from "../scripts/mainnet-trial/ledger.ts";
import type { SparkClient } from "../src/client/index.ts";
import type { SparkExitChain } from "../src/exit/store.ts";
import type { SparkLeaf } from "../src/tree/index.ts";

const tmpDirs: string[] = [];

afterEach(() => {
  for (const dir of tmpDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function tmp(): string {
  const dir = mkdtempSync(join(tmpdir(), "mainnet-trial-"));
  tmpDirs.push(dir);
  return dir;
}

function chain(leafId: string): SparkExitChain {
  return {
    leafId,
    nodes: [
      { nodeId: `${leafId}-n1`, nodeTx: hexToBytes("0102"), directTx: hexToBytes("0304") },
      { nodeId: `${leafId}-n2`, nodeTx: hexToBytes("0506") },
    ],
    refundTx: hexToBytes("aabb"),
    directRefundTx: hexToBytes("ccdd"),
    directFromCpfpRefundTx: hexToBytes("eeff"),
  };
}

describe("file store", () => {
  test("round trips chains byte-for-byte with copies on read", async () => {
    const path = join(tmp(), "exit-chains.json");
    const store = createFileSparkStore(path);
    const input = chain("leaf-1");
    await store.putExitChains([input]);
    input.nodes[0]!.nodeTx[0] = 0xff; // mutating the input must not corrupt the store

    const stored = await createFileSparkStore(path).exitChains();
    expect(stored).toStrictEqual([chain("leaf-1")]);

    stored[0]!.refundTx[0] = 0x00; // mutating the read must not corrupt the store
    const again = await createFileSparkStore(path).exitChains();
    expect(again).toStrictEqual([chain("leaf-1")]);
  });

  test("delete removes only the named chains", async () => {
    const path = join(tmp(), "exit-chains.json");
    const store = createFileSparkStore(path);
    await store.putExitChains([chain("a"), chain("b")]);
    await store.deleteExitChains(["a"]);
    const kept = await createFileSparkStore(path).exitChains();
    expect(kept.map((entry) => entry.leafId)).toStrictEqual(["b"]);
  });

  test("writes are atomic: the only files are the store and nothing partial", async () => {
    const dir = tmp();
    const path = join(dir, "exit-chains.json");
    const store = createFileSparkStore(path);
    await store.putExitChains([chain("a"), chain("b")]);
    await store.deleteExitChains(["a"]);
    expect(readdirSync(dir)).toStrictEqual(["exit-chains.json"]);
    const parsed = JSON.parse(readFileSync(path, "utf8")) as { chains: unknown[] };
    expect(parsed.chains).toHaveLength(1);
  });

  test("a malformed file throws instead of dropping chains", () => {
    const path = join(tmp(), "exit-chains.json");
    writeFileSync(path, JSON.stringify({ chains: [{ leafId: "x", nodes: "oops" }] }));
    expect(() => createFileSparkStore(path)).toThrow(/exit chain store/);

    const bad = join(tmp(), "exit-chains.json");
    writeFileSync(bad, "not json at all");
    expect(() => createFileSparkStore(bad)).toThrow(/malformed JSON/);
  });

  test("store file is mode 0600 in a mode 0700 directory", async () => {
    const dir = join(tmp(), "nested");
    const path = join(dir, "exit-chains.json");
    const store = createFileSparkStore(path);
    await store.putExitChains([chain("a")]);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
  });
});

function entry(partial: Partial<LedgerEntry>): LedgerEntry {
  return {
    time: "2026-01-01T00:00:00.000Z",
    network: "mainnet",
    account: 0,
    command: "send",
    balanceBefore: 1000,
    balanceAfter: 900,
    expectedDelta: -100,
    actualDelta: -100,
    status: "ok",
    ...partial,
  };
}

describe("ledger", () => {
  test("appends JSONL and reports per-account totals", () => {
    const path = join(tmp(), "ledger.jsonl");
    const ledger = createLedger(path);
    ledger.append(entry({ account: 0, actualDelta: -100, feeSats: 5 }));
    ledger.append(entry({ account: 0, actualDelta: 250, balanceAfter: 1150 }));
    ledger.append(entry({ account: 1, actualDelta: -10, balanceAfter: 90 }));
    ledger.append(entry({ status: "mismatch", expectedDelta: 0, actualDelta: -5, command: "pay" }));

    const report = formatLedgerReport(ledger.entries());
    expect(report).toContain("account 0: received 250 sats, sent 100 sats, fees 5 sats");
    expect(report).toContain("account 1: received 0 sats, sent 10 sats");
    expect(report).toContain("MISMATCH");
    expect(report).toContain("pay");
  });

  test("report on an empty ledger says so", () => {
    expect(formatLedgerReport([])).toBe("ledger: no entries");
  });

  test("a malformed line throws on read", () => {
    const path = join(tmp(), "ledger.jsonl");
    writeFileSync(path, '{"command":"x"}\n');
    expect(() => createLedger(path).entries()).toThrow(/ledger: line 1/);
  });
});

describe("seed loading", () => {
  const SEED_HEX = "ab".repeat(64);

  test("env var wins and parses 64-byte hex", () => {
    const dir = tmp();
    process.env["TRIAL_TEST_SEED"] = SEED_HEX;
    try {
      const seed = envSeed({ envVar: "TRIAL_TEST_SEED", envFile: join(dir, "missing") });
      expect(seed).toHaveLength(64);
      expect(bytesToHex(seed)).toBe(SEED_HEX);
    } finally {
      delete process.env["TRIAL_TEST_SEED"];
    }
  });

  test("falls back to the KEY= line in the file", () => {
    const file = join(tmp(), ".env.test");
    writeFileSync(file, `OTHER=1\nTRIAL_TEST_SEED=${SEED_HEX}\n`, { mode: 0o600 });
    const seed = envSeed({ envVar: "TRIAL_TEST_SEED", envFile: file });
    expect(seed).toHaveLength(64);
  });

  test("rejects a group/world-readable file when required", () => {
    const file = join(tmp(), ".env.test");
    writeFileSync(file, `TRIAL_TEST_SEED=${SEED_HEX}\n`);
    chmodSync(file, 0o644);
    expect(() =>
      envSeed({ envVar: "TRIAL_TEST_SEED", envFile: file, requirePrivateFile: true }),
    ).toThrow(/chmod 600/);
    chmodSync(file, 0o600);
    expect(
      envSeed({ envVar: "TRIAL_TEST_SEED", envFile: file, requirePrivateFile: true }),
    ).toHaveLength(64);
  });

  test("bad length or missing value fails without echoing it", () => {
    const file = join(tmp(), ".env.test");
    writeFileSync(file, "TRIAL_TEST_SEED=deadbeef\n", { mode: 0o600 });
    expect(() =>
      envSeed({ envVar: "TRIAL_TEST_SEED", envFile: file, requirePrivateFile: true }),
    ).toThrow(/expected TRIAL_TEST_SEED \(64-byte hex\)/);
  });

  test("envFileValue returns undefined for missing file or key", () => {
    expect(envFileValue(join(tmp(), "nope"), "K")).toBeUndefined();
    const file = join(tmp(), ".env");
    writeFileSync(file, "A=1\nK=v=two\n");
    expect(envFileValue(file, "K")).toBe("v=two");
  });
});

type FakeClient = {
  balanceValues: number[];
  sent?: { receiver: string; amountSats: number; transferId?: string };
};

type FakeOverrides = {
  balanceValues: number[];
  leaves?: SparkLeaf[];
  payAmount?: number;
  payFee?: number;
  sendStatus?: { status: string; outcome: string };
};

function fakeDeps(
  overrides: FakeOverrides,
  ledgerPath: string,
): { deps: TrialDeps; fake: FakeClient } {
  const fake: FakeClient = { balanceValues: overrides.balanceValues };
  const client = {
    balance: async () => {
      await Promise.resolve();
      return fake.balanceValues.shift() ?? 0;
    },
    transfers: {
      send: async (options: { receiver: string; amountSats: number; transferId?: string }) => {
        await Promise.resolve();
        fake.sent = options;
        return { id: options.transferId };
      },
      claimPending: async () => {
        await Promise.resolve();
        return {
          leaves: overrides.leaves ?? [],
          failures: [],
        };
      },
    },
    lightning: {
      pay: async () => {
        await Promise.resolve();
        return {
          transferId: "tid",
          requestId: "rid",
          status: "INITIATED",
          paymentHash: new Uint8Array(32),
          amountSats: overrides.payAmount ?? 1000,
          feeSats: overrides.payFee ?? 10,
        };
      },
      sendStatus: async () => {
        await Promise.resolve();
        return (
          overrides.sendStatus ?? { status: "LIGHTNING_PAYMENT_SUCCEEDED", outcome: "succeeded" }
        );
      },
    },
    identityPublicKey: async () => {
      await Promise.resolve();
      return new Uint8Array(33);
    },
  } as unknown as SparkClient;
  const lines: string[] = [];
  return {
    fake,
    deps: {
      client,
      network: "mainnet",
      account: 0,
      sparkAddress: "spark1fake",
      accountAddress: async () => {
        await Promise.resolve();
        return "spark1other";
      },
      store: {
        exitChains: async () => Promise.resolve([]),
        putExitChains: async () => Promise.resolve(),
        deleteExitChains: async () => Promise.resolve(),
      },
      ledger: createLedger(ledgerPath),
      out: (line) => lines.push(line),
      now: () => Date.now(),
      sleep: async () => {},
    },
  };
}

describe("commands", () => {
  test("send records a -amount delta and prints the transferId before sending", async () => {
    const ledgerPath = join(tmp(), "ledger.jsonl");
    const { deps, fake } = fakeDeps({ balanceValues: [5000, 4000] }, ledgerPath);
    await cmdSend(deps, { to: "spark1dest", amountSats: 1000, transferId: "tid-1" });
    expect(fake.sent).toStrictEqual({
      receiver: "spark1dest",
      amountSats: 1000,
      transferId: "tid-1",
    });
    const [logged] = createLedger(ledgerPath).entries();
    expect(logged).toMatchObject({
      command: "send",
      expectedDelta: -1000,
      actualDelta: -1000,
      status: "ok",
    });
  });

  test("a same-id retry that moves nothing records an idempotent replay", async () => {
    const ledgerPath = join(tmp(), "ledger.jsonl");
    const { deps } = fakeDeps({ balanceValues: [4000, 4000] }, ledgerPath);
    await cmdSend(deps, { to: "spark1dest", amountSats: 1000, transferId: "tid-1" });
    const [logged] = createLedger(ledgerPath).entries();
    expect(logged).toMatchObject({ expectedDelta: 0, actualDelta: 0, status: "ok" });
  });

  test("a balance mismatch appends the entry and throws LedgerMismatchError", async () => {
    const ledgerPath = join(tmp(), "ledger.jsonl");
    const { deps } = fakeDeps({ balanceValues: [5000, 4500] }, ledgerPath);
    await expect(
      cmdSend(deps, { to: "spark1dest", amountSats: 1000, transferId: "t" }),
    ).rejects.toBeInstanceOf(LedgerMismatchError);
    const [logged] = createLedger(ledgerPath).entries();
    expect(logged?.status).toBe("mismatch");
    expect(logged?.actualDelta).toBe(-500);
  });

  test("claim records the sum of claimed leaves", async () => {
    const ledgerPath = join(tmp(), "ledger.jsonl");
    const leaves = [{ valueSats: 700 }, { valueSats: 300 }] as SparkLeaf[];
    const { deps } = fakeDeps({ balanceValues: [1000, 2000], leaves }, ledgerPath);
    await cmdClaim(deps);
    const [logged] = createLedger(ledgerPath).entries();
    expect(logged).toMatchObject({ expectedDelta: 1000, actualDelta: 1000, status: "ok" });
  });

  test("pay returned records a zero delta", async () => {
    const ledgerPath = join(tmp(), "ledger.jsonl");
    const { deps } = fakeDeps(
      {
        balanceValues: [5000, 5000],
        sendStatus: { status: "USER_SWAP_RETURNED", outcome: "returned" },
      },
      ledgerPath,
    );
    await cmdPay(deps, { invoice: "lnbc1x", maxFeeSats: 50, timeoutMin: 1 });
    const [logged] = createLedger(ledgerPath).entries();
    expect(logged).toMatchObject({ expectedDelta: 0, actualDelta: 0, status: "ok" });
  });

  test("pay still in flight records pending", async () => {
    const ledgerPath = join(tmp(), "ledger.jsonl");
    let now = 0;
    const { deps } = fakeDeps(
      { balanceValues: [5000, 4000], sendStatus: { status: "INITIATED", outcome: "pending" } },
      ledgerPath,
    );
    // Freeze clock so the poll deadline is reached immediately.
    const timed: TrialDeps = {
      ...deps,
      now: () => {
        now += 60_000;
        return now;
      },
    };
    await cmdPay(timed, { invoice: "lnbc1x", maxFeeSats: 50, timeoutMin: 1 });
    const [logged] = createLedger(ledgerPath).entries();
    expect(logged?.status).toBe("pending");
  });

  test("report exits 2-shaped: mismatches counted", () => {
    const path = join(tmp(), "ledger.jsonl");
    const ledger = createLedger(path);
    ledger.append(entry({ status: "mismatch", actualDelta: -1 }));
    const lines: string[] = [];
    const { mismatches } = cmdReport({ ledger, out: (line) => lines.push(line) });
    expect(mismatches).toBe(1);
    expect(lines.join("\n")).toContain("MISMATCH");
  });

  test("MAX_TRIAL_SATS caps every amount", () => {
    expect(MAX_TRIAL_SATS).toBe(200_000);
  });
});
