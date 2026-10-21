#!/usr/bin/env bun
/// <reference types="node" />
// Mainnet trial runner: phase-by-phase mainnet rehearsal with a persistent
// exit-chain store and an append-only balance ledger. See README.md for the
// runbook; the same code rehearses on the hosted regtest with --network regtest.
//
//   bun packages/spark/scripts/mainnet-trial/main.ts <command> [options]
//
// Exit codes: 0 ok, 1 usage/runtime error, 2 a ledger mismatch or pending entry.
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import type { CooperativeExitSpeed } from "../../src/exit/coop.ts";
import {
  cmdClaim,
  cmdClaimDeposit,
  cmdClaimStatic,
  cmdCoopExit,
  cmdDepositAddress,
  cmdEvents,
  cmdExitPackage,
  cmdOptimize,
  cmdPay,
  cmdPayAddress,
  cmdReceiveLn,
  cmdReport,
  cmdSend,
  cmdStaticAddress,
  cmdStaticUtxos,
  cmdStatus,
  LedgerMismatchError,
  MAX_TRIAL_SATS,
  resolveReceiver,
} from "./commands.ts";
import type { TrialDeps } from "./commands.ts";
import { createFileSparkStore } from "./file-store.ts";
import { createLedger } from "./ledger.ts";
import { trialSeed, trialWallet } from "./wallet.ts";

const REPO_ROOT = fileURLToPath(new URL("../../../../", import.meta.url));
const DEFAULT_STATE_DIR = join(REPO_ROOT, ".mainnet-trial");

const SPEEDS: Record<string, CooperativeExitSpeed> = {
  fast: "FAST",
  medium: "MEDIUM",
  slow: "SLOW",
};

const out = (line: string): void => {
  console.log(line);
};

/** Commands that move funds out — on mainnet they require --confirm. */
const SPENDING_COMMANDS = new Set(["send", "pay", "pay-address", "coop-exit"]);

const COMMANDS = new Set([
  "status",
  "receive-ln",
  "deposit-address",
  "claim-deposit",
  "static-address",
  "static-utxos",
  "claim-static",
  "send",
  "claim",
  "pay",
  "pay-address",
  "optimize",
  "exit-package",
  "coop-exit",
  "events",
  "report",
]);

const USAGE = `usage: main.ts <command> [--network mainnet|regtest] [--account N] [--state-dir DIR] [options]

commands:
  status                          identity, spark address, balance, leaves, chains, pending
  receive-ln    --amount [--memo] [--timeout-min 30]
  deposit-address                 fresh single-use deposit address
  claim-deposit --txid            claim a single-use deposit via public esplora
  static-address                  reusable static deposit address
  static-utxos                    confirmed unclaimed static UTXOs
  claim-static  --txid --vout --max-fee
  send          --to <spark address|account:N> --amount [--transfer-id]
  claim                           claim pending incoming transfers
  pay           --invoice [--amount] --max-fee [--transfer-id] [--timeout-min 30]
  pay-address   --address name@domain --amount --max-fee [--comment] [--timeout-min 30]
  optimize                        leaf optimization (no funds move)
  exit-package  --out FILE        verify stored chains against live query, write the package
  coop-exit     --address [--amount] --max-fee --speed fast|medium|slow [--transfer-id] [--timeout-min 30]
  events        --minutes N       print coordinator events for N minutes
  report                          per-account ledger totals and mismatches

safety: mainnet spending commands require --confirm; amounts and fees cap at
${MAX_TRIAL_SATS} sats. State lives in .mainnet-trial/ (override --state-dir).`;

function fail(message: string): never {
  console.error(`error: ${message}`);
  process.exit(1);
}

function satsOption(
  name: string,
  value: string | undefined,
  required: boolean,
): number | undefined {
  if (value === undefined) {
    if (required) {
      fail(`--${name} is required`);
    }
    return undefined;
  }
  const sats = Number(value);
  if (!Number.isSafeInteger(sats) || sats <= 0) {
    fail(`--${name} must be a positive integer (sats)`);
  }
  if (sats > MAX_TRIAL_SATS) {
    fail(`--${name} ${sats} exceeds the hard trial cap of ${MAX_TRIAL_SATS} sats`);
  }
  return sats;
}

function intOption(name: string, value: string | undefined, fallback: number): number {
  if (value === undefined) {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    fail(`--${name} must be a non-negative integer`);
  }
  return parsed;
}

/** Parses a required non-negative integer option (e.g. a UTXO vout). */
function requiredIndex(name: string, value: string | undefined): number {
  const parsed = value === undefined ? Number.NaN : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    fail(`--${name} is required and must be a non-negative integer`);
  }
  return parsed;
}

async function run(): Promise<number> {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: {
      network: { type: "string" },
      account: { type: "string" },
      "state-dir": { type: "string" },
      confirm: { type: "boolean" },
      amount: { type: "string" },
      memo: { type: "string" },
      "timeout-min": { type: "string" },
      txid: { type: "string" },
      vout: { type: "string" },
      "max-fee": { type: "string" },
      to: { type: "string" },
      "transfer-id": { type: "string" },
      invoice: { type: "string" },
      address: { type: "string" },
      comment: { type: "string" },
      speed: { type: "string" },
      out: { type: "string" },
      minutes: { type: "string" },
      help: { type: "boolean" },
    },
  });

  const [command] = positionals;
  if (values.help === true || command === undefined || !COMMANDS.has(command)) {
    console.log(USAGE);
    return command === undefined || values.help === true ? 0 : 1;
  }

  const network = values.network ?? "mainnet";
  if (network !== "mainnet" && network !== "regtest") {
    fail("--network must be mainnet or regtest");
  }
  const account = intOption("account", values.account, 0);
  const timeoutMin = intOption("timeout-min", values["timeout-min"], 30);
  const stateDir = values["state-dir"] ?? DEFAULT_STATE_DIR;
  const ledger = createLedger(join(stateDir, network, "ledger.jsonl"));

  if (command === "report") {
    const { mismatches } = cmdReport({ ledger, out });
    return mismatches > 0 ? 2 : 0;
  }

  const seed = trialSeed(network);
  const store = createFileSparkStore(
    join(stateDir, network, `account-${account}`, "exit-chains.json"),
  );
  const wallet = await trialWallet(seed, network, account, store);
  const deps: TrialDeps = {
    client: wallet.client,
    network,
    account,
    sparkAddress: wallet.sparkAddress,
    seed,
    store,
    ledger,
    out,
    now: () => Date.now(),
    sleep: async (ms) =>
      new Promise((resolve) => {
        setTimeout(resolve, ms);
      }),
  };

  try {
    if (SPENDING_COMMANDS.has(command) && network === "mainnet" && values.confirm !== true) {
      console.log("dry run (add --confirm to execute on mainnet):");
      if (command === "send") {
        const to = values.to ?? fail("--to is required");
        const amountSats =
          satsOption("amount", values.amount, true) ?? fail("--amount is required");
        console.log(`  send ${amountSats} sats to ${await resolveReceiver(deps, to)}`);
      } else if (command === "pay") {
        const invoice = values.invoice ?? fail("--invoice is required");
        console.log(
          `  pay invoice ${invoice} ` +
            `(amount ${values.amount ?? "invoice"} sats, max fee ${values["max-fee"] ?? "?"} sats)`,
        );
      } else if (command === "pay-address") {
        const address = values.address ?? fail("--address is required");
        const amount = values.amount ?? "?";
        console.log(
          `  pay ${amount} sats to ${address} (max fee ${values["max-fee"] ?? "?"} sats)`,
        );
      } else {
        const address = values.address ?? fail("--address is required");
        const dryAmount = satsOption("amount", values.amount, false);
        const quote = await wallet.client.withdrawals.quoteCooperativeExit({
          address,
          ...(dryAmount === undefined ? {} : { amountSats: dryAmount }),
        });
        console.log(
          `  coop-exit ${values.amount ?? "all"} sats to ${address} ` +
            `(max fee ${values["max-fee"] ?? "?"} sats; quoted fast ${quote.fees.fast} / ` +
            `medium ${quote.fees.medium} / slow ${quote.fees.slow})`,
        );
      }
      return 0;
    }

    switch (command) {
      case "status":
        await cmdStatus(deps);
        break;
      case "receive-ln":
        await cmdReceiveLn(deps, {
          amountSats: satsOption("amount", values.amount, true) ?? 0,
          ...(values.memo === undefined ? {} : { memo: values.memo }),
          timeoutMin,
        });
        break;
      case "deposit-address":
        await cmdDepositAddress(deps);
        break;
      case "claim-deposit":
        await cmdClaimDeposit(deps, { txid: values.txid ?? fail("--txid is required") });
        break;
      case "static-address":
        await cmdStaticAddress(deps);
        break;
      case "static-utxos":
        await cmdStaticUtxos(deps);
        break;
      case "claim-static":
        await cmdClaimStatic(deps, {
          txid: values.txid ?? fail("--txid is required"),
          vout: requiredIndex("vout", values.vout),
          maxFeeSats: satsOption("max-fee", values["max-fee"], true) ?? 0,
        });
        break;
      case "send":
        await cmdSend(deps, {
          to: values.to ?? fail("--to is required"),
          amountSats: satsOption("amount", values.amount, true) ?? 0,
          ...(values["transfer-id"] === undefined ? {} : { transferId: values["transfer-id"] }),
        });
        break;
      case "claim":
        await cmdClaim(deps);
        break;
      case "pay": {
        const amountSats = satsOption("amount", values.amount, false);
        await cmdPay(deps, {
          invoice: values.invoice ?? fail("--invoice is required"),
          ...(amountSats === undefined ? {} : { amountSats }),
          maxFeeSats: satsOption("max-fee", values["max-fee"], true) ?? 0,
          ...(values["transfer-id"] === undefined ? {} : { transferId: values["transfer-id"] }),
          timeoutMin,
        });
        break;
      }
      case "pay-address":
        await cmdPayAddress(deps, {
          address: values.address ?? fail("--address is required"),
          amountSats: satsOption("amount", values.amount, true) ?? 0,
          maxFeeSats: satsOption("max-fee", values["max-fee"], true) ?? 0,
          ...(values.comment === undefined ? {} : { comment: values.comment }),
          timeoutMin,
        });
        break;
      case "optimize":
        await cmdOptimize(deps);
        break;
      case "exit-package":
        await cmdExitPackage(deps, { out: values.out ?? fail("--out is required") });
        break;
      case "coop-exit": {
        const speed = SPEEDS[values.speed ?? ""];
        if (speed === undefined) {
          fail("--speed is required and must be fast, medium or slow");
        }
        const exitAmount = satsOption("amount", values.amount, false);
        await cmdCoopExit(deps, {
          address: values.address ?? fail("--address is required"),
          ...(exitAmount === undefined ? {} : { amountSats: exitAmount }),
          maxFeeSats: satsOption("max-fee", values["max-fee"], true) ?? 0,
          speed,
          ...(values["transfer-id"] === undefined ? {} : { transferId: values["transfer-id"] }),
          timeoutMin,
        });
        break;
      }
      case "events":
        if (values.minutes === undefined) {
          fail("--minutes is required");
        }
        await cmdEvents(deps, { minutes: intOption("minutes", values.minutes, 0) });
        break;
      default:
        fail(`unknown command ${command}`);
    }
    return 0;
  } finally {
    wallet.client.close();
  }
}

try {
  const code = await run();
  process.exit(code);
} catch (error) {
  if (error instanceof LedgerMismatchError) {
    console.error(error.message);
    process.exit(2);
  }
  console.error(`error: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}
