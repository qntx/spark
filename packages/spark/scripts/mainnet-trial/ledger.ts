// Append-only JSONL ledger for the mainnet trial: one entry per money-moving
// step with the balance observed before and after. The ledger is the audit
// trail — every send, claim and exit is checked against its expected delta and
// any mismatch is recorded, printed as a STOP and reported again by `report`.
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";

export type LedgerStatus = "ok" | "mismatch" | "pending";

export type LedgerIds = {
  readonly transferId?: string;
  readonly requestId?: string;
  readonly txid?: string;
};

export type LedgerEntry = {
  /** ISO-8601 timestamp. */
  readonly time: string;
  readonly network: string;
  readonly account: number;
  readonly command: string;
  readonly ids?: LedgerIds;
  readonly amountSats?: number;
  readonly feeSats?: number;
  readonly balanceBefore: number;
  readonly balanceAfter: number;
  readonly expectedDelta: number;
  readonly actualDelta: number;
  readonly status: LedgerStatus;
};

export type Ledger = {
  readonly path: string;
  readonly append: (entry: LedgerEntry) => void;
  readonly entries: () => LedgerEntry[];
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function validateEntry(raw: unknown, line: number): LedgerEntry {
  if (!isRecord(raw)) {
    throw new TypeError(`ledger: line ${line} is not an object`);
  }
  const stringField = (name: string): string => {
    const value = raw[name];
    if (typeof value !== "string") {
      throw new TypeError(`ledger: line ${line} has no string ${name}`);
    }
    return value;
  };
  const intField = (name: string): number => {
    const value = raw[name];
    if (typeof value !== "number" || !Number.isSafeInteger(value)) {
      throw new TypeError(`ledger: line ${line} has no integer ${name}`);
    }
    return value;
  };
  const optionalInt = (name: string): number | undefined => {
    const value = raw[name];
    if (value === undefined) {
      return undefined;
    }
    if (typeof value !== "number" || !Number.isSafeInteger(value)) {
      throw new TypeError(`ledger: line ${line} has a non-integer ${name}`);
    }
    return value;
  };
  const status = stringField("status");
  if (status !== "ok" && status !== "mismatch" && status !== "pending") {
    throw new TypeError(`ledger: line ${line} has an unknown status`);
  }
  let ids: LedgerIds | undefined;
  const rawIds = raw["ids"];
  if (rawIds !== undefined) {
    if (!isRecord(rawIds)) {
      throw new TypeError(`ledger: line ${line} has a non-object ids`);
    }
    const parsed: { transferId?: string; requestId?: string; txid?: string } = {};
    for (const name of ["transferId", "requestId", "txid"] as const) {
      const value = rawIds[name];
      if (value !== undefined) {
        if (typeof value !== "string") {
          throw new TypeError(`ledger: line ${line} has a non-string ids.${name}`);
        }
        parsed[name] = value;
      }
    }
    ids = parsed;
  }
  const amountSats = optionalInt("amountSats");
  const feeSats = optionalInt("feeSats");
  return {
    time: stringField("time"),
    network: stringField("network"),
    account: intField("account"),
    command: stringField("command"),
    ...(ids === undefined ? {} : { ids }),
    ...(amountSats === undefined ? {} : { amountSats }),
    ...(feeSats === undefined ? {} : { feeSats }),
    balanceBefore: intField("balanceBefore"),
    balanceAfter: intField("balanceAfter"),
    expectedDelta: intField("expectedDelta"),
    actualDelta: intField("actualDelta"),
    status,
  };
}

/** Append-only JSONL ledger at `path`. A malformed existing line throws on read — never skipped. */
export function createLedger(path: string): Ledger {
  return {
    path,
    append(entry) {
      mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
      appendFileSync(path, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
    },
    entries() {
      if (!existsSync(path)) {
        return [];
      }
      return readFileSync(path, "utf8")
        .split("\n")
        .filter((line) => line.trim().length > 0)
        .map((line, index) => validateEntry(JSON.parse(line), index + 1));
    },
  };
}

export type LedgerTotals = {
  readonly account: number;
  readonly receivedSats: number;
  readonly sentSats: number;
  readonly feeSats: number;
  readonly mismatches: LedgerEntry[];
  readonly pending: LedgerEntry[];
};

type Totals = {
  account: number;
  receivedSats: number;
  sentSats: number;
  feeSats: number;
  mismatches: LedgerEntry[];
  pending: LedgerEntry[];
};

/** Per-account sums over `ok` entries plus every mismatch and pending entry. */
export function ledgerTotals(entries: ReadonlyArray<LedgerEntry>): LedgerTotals[] {
  const byAccount = new Map<number, Totals>();
  const bucket = (account: number): Totals => {
    let totals = byAccount.get(account);
    if (totals === undefined) {
      totals = { account, receivedSats: 0, sentSats: 0, feeSats: 0, mismatches: [], pending: [] };
      byAccount.set(account, totals);
    }
    return totals;
  };
  for (const entry of entries) {
    const totals = bucket(entry.account);
    if (entry.status === "mismatch") {
      totals.mismatches.push(entry);
      continue;
    }
    if (entry.status === "pending") {
      totals.pending.push(entry);
      continue;
    }
    if (entry.actualDelta > 0) {
      totals.receivedSats += entry.actualDelta;
    } else {
      totals.sentSats += -entry.actualDelta;
    }
    totals.feeSats += entry.feeSats ?? 0;
  }
  return [...byAccount.values()].toSorted((a, b) => a.account - b.account);
}

/** Human-readable `report` output: per-account totals followed by mismatch/pending details. */
export function formatLedgerReport(entries: ReadonlyArray<LedgerEntry>): string {
  const lines: string[] = [];
  if (entries.length === 0) {
    return "ledger: no entries";
  }
  for (const totals of ledgerTotals(entries)) {
    lines.push(
      `account ${totals.account}: received ${totals.receivedSats} sats, sent ${totals.sentSats} sats, fees ${totals.feeSats} sats${
        totals.mismatches.length > 0 ? `, ${totals.mismatches.length} MISMATCH` : ""
      }${totals.pending.length > 0 ? `, ${totals.pending.length} pending` : ""}`,
    );
  }
  for (const totals of ledgerTotals(entries)) {
    for (const entry of [...totals.mismatches, ...totals.pending]) {
      const ids = entry.ids === undefined ? "" : ` ids=${JSON.stringify(entry.ids)}`;
      lines.push(
        `${entry.status.toUpperCase()} ${entry.time} ${entry.command} account ${entry.account}${ids}` +
          ` expected ${entry.expectedDelta} got ${entry.actualDelta} (before ${entry.balanceBefore} after ${entry.balanceAfter})`,
      );
    }
  }
  return lines.join("\n");
}
