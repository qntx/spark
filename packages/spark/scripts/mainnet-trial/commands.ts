// One function per trial command. Each takes injected deps (client, ledger,
// clock, sleep, stdout) so the whole command layer is unit-testable with fakes.
import { writeFileSync } from "node:fs";

import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";

import type { SparkClient } from "../../src/client/index.ts";
import type { SparkEvent } from "../../src/connection/index.ts";
import type { SparkNetwork } from "../../src/core/network.ts";
import { uuidv7 } from "../../src/core/uuid.ts";
import { COOP_EXIT_FAILED } from "../../src/exit/coop.ts";
import type { CooperativeExitSpeed } from "../../src/exit/coop.ts";
import type { SparkStore } from "../../src/exit/store.ts";
import { requestInvoice, resolveLnurl } from "../../src/lnurl/index.ts";
import type { Ledger, LedgerIds } from "./ledger.ts";
import { formatLedgerReport } from "./ledger.ts";
import { esploraTxHex } from "./wallet.ts";

/** Hard cap on every sats amount the trial can move or spend as fee — no override. */
export const MAX_TRIAL_SATS = 200_000;

/** Thrown after a mismatch entry is appended; main exits 2. */
export class LedgerMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LedgerMismatchError";
  }
}

export type TrialDeps = {
  readonly client: SparkClient;
  readonly network: SparkNetwork;
  readonly account: number;
  readonly sparkAddress: string;
  readonly accountAddress: (account: number) => Promise<string>;
  readonly store: SparkStore;
  readonly ledger: Ledger;
  readonly out: (line: string) => void;
  readonly now: () => number;
  readonly sleep: (ms: number) => Promise<void>;
};

type MoneyFields = {
  readonly command: string;
  readonly balanceBefore: number;
  readonly expectedDelta: number;
  readonly amountSats?: number;
  readonly feeSats?: number;
  readonly ids?: LedgerIds;
};

/**
 * Records a settled money-moving step; throws LedgerMismatchError when the delta is wrong.
 * `idempotentRetry` marks a command re-invoked with an explicit transfer id: a successful call that
 * moved nothing means the earlier attempt already settled, so the expected delta is 0.
 */
async function record(
  deps: TrialDeps,
  fields: MoneyFields,
  options?: { readonly idempotentRetry?: boolean },
): Promise<void> {
  const balanceAfter = await deps.client.balance();
  const actualDelta = balanceAfter - fields.balanceBefore;
  const replayed = options?.idempotentRetry === true && actualDelta === 0;
  const expectedDelta = replayed ? 0 : fields.expectedDelta;
  if (replayed) {
    deps.out("balance unchanged — the request id was already settled (idempotent replay)");
  }
  append(deps, {
    ...fields,
    balanceAfter,
    actualDelta,
    expectedDelta,
    status: actualDelta === expectedDelta ? "ok" : "mismatch",
  });
  if (actualDelta !== expectedDelta) {
    throw new LedgerMismatchError(
      `STOP: ${fields.command} moved the balance ${actualDelta} sats, expected ${expectedDelta} — ` +
        "keep the state directory and investigate before continuing",
    );
  }
}

/** Records an inconclusive step (timed-out poll) so `report` surfaces it. */
async function recordPending(deps: TrialDeps, fields: MoneyFields): Promise<void> {
  const balanceAfter = await deps.client.balance();
  append(deps, {
    ...fields,
    balanceAfter,
    actualDelta: balanceAfter - fields.balanceBefore,
    status: "pending",
  });
}

function append(
  deps: TrialDeps,
  fields: MoneyFields & {
    readonly balanceAfter: number;
    readonly actualDelta: number;
    readonly status: "ok" | "mismatch" | "pending";
  },
): void {
  deps.ledger.append({
    time: new Date(deps.now()).toISOString(),
    network: deps.network,
    account: deps.account,
    command: fields.command,
    ...(fields.ids === undefined ? {} : { ids: fields.ids }),
    ...(fields.amountSats === undefined ? {} : { amountSats: fields.amountSats }),
    ...(fields.feeSats === undefined ? {} : { feeSats: fields.feeSats }),
    balanceBefore: fields.balanceBefore,
    balanceAfter: fields.balanceAfter,
    expectedDelta: fields.expectedDelta,
    actualDelta: fields.actualDelta,
    status: fields.status,
  });
}

/** Polls `poll` every `intervalMs` until it returns a non-undefined value or `timeoutMs` elapses. */
async function pollUntil<T>(
  deps: TrialDeps,
  timeoutMs: number,
  intervalMs: number,
  poll: () => Promise<T | undefined>,
): Promise<T | undefined> {
  const deadline = deps.now() + timeoutMs;
  for (;;) {
    // eslint-disable-next-line no-await-in-loop -- sequential polling is the point
    const value = await poll();
    if (value !== undefined || deps.now() >= deadline) {
      return value;
    }
    // eslint-disable-next-line no-await-in-loop
    await deps.sleep(intervalMs);
  }
}

const identity = (key: Uint8Array): string => bytesToHex(key);

export async function cmdStatus(deps: TrialDeps): Promise<void> {
  const identityKey = await deps.client.identityPublicKey();
  const balance = await deps.client.balance();
  const leaves = await deps.client.leaves();
  const chains = await deps.store.exitChains();
  const pending = await deps.client.transfers.pending();
  const pendingSats = pending.reduce((sum, transfer) => sum + transfer.totalValueSats, 0);
  deps.out(`identityPublicKey: ${identity(identityKey)}`);
  deps.out(`spark address: ${deps.sparkAddress}`);
  deps.out(`balance: ${balance} sats`);
  deps.out(`leaves: ${leaves.length}`);
  deps.out(`stored exit chains: ${chains.length}`);
  deps.out(`pending incoming transfers: ${pending.length} (${pendingSats} sats)`);
}

export async function cmdReceiveLn(
  deps: TrialDeps,
  options: { readonly amountSats: number; readonly memo?: string; readonly timeoutMin: number },
): Promise<void> {
  const balanceBefore = await deps.client.balance();
  const invoice = await deps.client.lightning.createInvoice({
    amountSats: options.amountSats,
    ...(options.memo === undefined ? {} : { memo: options.memo }),
  });
  deps.out(`requestId: ${invoice.id}`);
  deps.out(`bolt11: ${invoice.invoice}`);
  const fields = {
    command: "receive-ln",
    balanceBefore,
    expectedDelta: options.amountSats,
    amountSats: options.amountSats,
    ids: { requestId: invoice.id },
  };
  const timeoutMs = options.timeoutMin * 60_000;
  const status = await pollUntil(deps, timeoutMs, 5000, async () => {
    const current = await deps.client.lightning.receiveStatus({
      requestId: invoice.id,
      paymentHash: invoice.paymentHash,
    });
    return current.preimage !== undefined || current.transferId !== undefined ? current : undefined;
  });
  if (status === undefined) {
    deps.out(`not paid within ${options.timeoutMin} minutes — rerun when the invoice is paid`);
    await recordPending(deps, fields);
    return;
  }
  deps.out(`paid: transferId ${status.transferId ?? "(none yet)"}`);
  const claimed = await pollUntil(deps, timeoutMs, 5000, async () => {
    const result = await deps.client.transfers.claimPending();
    return result.leaves.length === 0 ? undefined : result;
  });
  const claimedSats = (claimed?.leaves ?? []).reduce((sum, leaf) => sum + leaf.valueSats, 0);
  if (claimedSats === 0) {
    deps.out("the inbound transfer never became claimable — rerun `claim` later");
    await recordPending(deps, fields);
    return;
  }
  deps.out(`claimed ${claimedSats} sats`);
  await record(deps, {
    ...fields,
    ids: {
      requestId: invoice.id,
      ...(status.transferId === undefined ? {} : { transferId: status.transferId }),
    },
  });
}

export async function cmdDepositAddress(deps: TrialDeps): Promise<void> {
  deps.out(`deposit address: ${await deps.client.deposits.newAddress()}`);
}

export async function cmdClaimDeposit(
  deps: TrialDeps,
  options: { readonly txid: string },
): Promise<void> {
  const raw = await esploraTxHex(deps.network, options.txid, globalThis.fetch);
  const balanceBefore = await deps.client.balance();
  const leaf = await deps.client.deposits.claim({ transaction: raw });
  deps.out(`claimed leaf ${leaf.id} (${leaf.valueSats} sats)`);
  await record(deps, {
    command: "claim-deposit",
    balanceBefore,
    expectedDelta: leaf.valueSats,
    amountSats: leaf.valueSats,
    ids: { txid: options.txid },
  });
}

export async function cmdStaticAddress(deps: TrialDeps): Promise<void> {
  deps.out(`static deposit address: ${await deps.client.deposits.staticAddress()}`);
}

export async function cmdStaticUtxos(deps: TrialDeps): Promise<void> {
  const utxos = await deps.client.deposits.staticUtxos();
  if (utxos.length === 0) {
    deps.out("no confirmed unclaimed UTXOs");
  }
  for (const utxo of utxos) {
    deps.out(`${utxo.txid}:${utxo.vout} ${utxo.amountSats ?? "?"} sats`);
  }
}

export async function cmdClaimStatic(
  deps: TrialDeps,
  options: { readonly txid: string; readonly vout: number; readonly maxFeeSats: number },
): Promise<void> {
  const utxos = await deps.client.deposits.staticUtxos();
  const utxo = utxos.find((entry) => entry.txid === options.txid && entry.vout === options.vout);
  if (utxo === undefined) {
    throw new Error(`no unclaimed static UTXO ${options.txid}:${options.vout}`);
  }
  deps.out(`utxo ${options.txid}:${options.vout} (${utxo.amountSats ?? "?"} sats)`);
  const balanceBefore = await deps.client.balance();
  const result = await deps.client.deposits.claimStatic({
    txid: options.txid,
    vout: options.vout,
    maxFeeSats: options.maxFeeSats,
  });
  deps.out(
    `credit ${result.creditAmountSats} sats, fee ${result.feeSats} sats${
      result.transferId === undefined ? "" : `, transferId ${result.transferId}`
    }`,
  );
  await record(deps, {
    command: "claim-static",
    balanceBefore,
    expectedDelta: result.creditAmountSats,
    amountSats: result.creditAmountSats,
    feeSats: result.feeSats,
    ids: {
      txid: options.txid,
      ...(result.transferId === undefined ? {} : { transferId: result.transferId }),
    },
  });
}

/** Resolves `--to` to a spark address: `account:N` derives the address from the same seed. */
export async function resolveReceiver(deps: TrialDeps, to: string): Promise<string> {
  const match = /^account:(\d+)$/.exec(to);
  if (match === null) {
    return to;
  }
  const account = Number(match[1] ?? "0");
  return deps.accountAddress(account);
}

export async function cmdSend(
  deps: TrialDeps,
  options: { readonly to: string; readonly amountSats: number; readonly transferId?: string },
): Promise<void> {
  const receiver = await resolveReceiver(deps, options.to);
  const transferId = options.transferId ?? uuidv7((length) => randomBytes(length), deps.now);
  deps.out(`transferId: ${transferId}`);
  deps.out(`sending ${options.amountSats} sats to ${receiver}`);
  const balanceBefore = await deps.client.balance();
  await deps.client.transfers.send({ receiver, amountSats: options.amountSats, transferId });
  await record(
    deps,
    {
      command: "send",
      balanceBefore,
      expectedDelta: -options.amountSats,
      amountSats: options.amountSats,
      ids: { transferId },
    },
    { idempotentRetry: options.transferId !== undefined },
  );
  deps.out("sent");
}

export async function cmdClaim(deps: TrialDeps): Promise<void> {
  const balanceBefore = await deps.client.balance();
  const result = await deps.client.transfers.claimPending();
  const claimedSats = result.leaves.reduce((sum, leaf) => sum + leaf.valueSats, 0);
  for (const failure of result.failures) {
    deps.out(`claim failed for ${failure.transferId}: ${String(failure.error)}`);
  }
  deps.out(`claimed ${result.leaves.length} leaves (${claimedSats} sats)`);
  await record(deps, {
    command: "claim",
    balanceBefore,
    expectedDelta: claimedSats,
    amountSats: claimedSats,
  });
}

/** Shared pay flow for bolt11 invoices (direct `pay` and LNURL-resolved `pay-address`). */
async function payBolt11(
  deps: TrialDeps,
  options: {
    readonly invoice: string;
    readonly amountSats?: number;
    readonly maxFeeSats: number;
    readonly transferId?: string;
    readonly command: string;
    readonly timeoutMs: number;
  },
): Promise<void> {
  const balanceBefore = await deps.client.balance();
  const payment = await deps.client.lightning.pay({
    invoice: options.invoice,
    maxFeeSats: options.maxFeeSats,
    ...(options.amountSats === undefined ? {} : { amountSats: options.amountSats }),
    ...(options.transferId === undefined ? {} : { transferId: options.transferId }),
  });
  deps.out(`requestId: ${payment.requestId}`);
  deps.out(`transferId: ${payment.transferId}`);
  deps.out(`amount ${payment.amountSats} sats + fee ${payment.feeSats} sats`);
  const expected = -(payment.amountSats + payment.feeSats);
  const fields = {
    command: options.command,
    balanceBefore,
    expectedDelta: expected,
    amountSats: payment.amountSats,
    feeSats: payment.feeSats,
    ids: { requestId: payment.requestId, transferId: payment.transferId },
  };
  const status = await pollUntil(deps, options.timeoutMs, 5000, async () => {
    const current = await deps.client.lightning.sendStatus({
      requestId: payment.requestId,
      paymentHash: payment.paymentHash,
    });
    return current.outcome === "succeeded" || current.outcome === "returned" ? current : undefined;
  });
  if (status === undefined) {
    deps.out("payment still in flight after the timeout — check `status`/`report` later");
    await recordPending(deps, fields);
    return;
  }
  const idempotentRetry = { idempotentRetry: options.transferId !== undefined };
  if (status.outcome === "returned") {
    deps.out("payment returned — the swap was undone, funds are back");
    await record(deps, { ...fields, expectedDelta: 0 }, idempotentRetry);
    return;
  }
  deps.out("paid");
  await record(deps, fields, idempotentRetry);
}

export async function cmdPay(
  deps: TrialDeps,
  options: {
    readonly invoice: string;
    readonly amountSats?: number;
    readonly maxFeeSats: number;
    readonly transferId?: string;
    readonly timeoutMin: number;
  },
): Promise<void> {
  await payBolt11(deps, { ...options, command: "pay", timeoutMs: options.timeoutMin * 60_000 });
}

export async function cmdPayAddress(
  deps: TrialDeps,
  options: {
    readonly address: string;
    readonly amountSats: number;
    readonly maxFeeSats: number;
    readonly comment?: string;
    readonly timeoutMin: number;
  },
): Promise<void> {
  const resolved = await resolveLnurl(options.address, { fetch: globalThis.fetch });
  if (resolved.tag !== "payRequest") {
    throw new Error(`${options.address} does not resolve to an LNURL pay request`);
  }
  const lnurlInvoice = await requestInvoice(resolved, {
    fetch: globalThis.fetch,
    network: deps.network,
    amountMsat: options.amountSats * 1000,
    ...(options.comment === undefined ? {} : { comment: options.comment }),
  });
  deps.out(`invoice for ${options.address}: ${lnurlInvoice.invoice}`);
  await payBolt11(deps, {
    invoice: lnurlInvoice.invoice,
    maxFeeSats: options.maxFeeSats,
    command: "pay-address",
    timeoutMs: options.timeoutMin * 60_000,
  });
}

export async function cmdOptimize(deps: TrialDeps): Promise<void> {
  const balanceBefore = await deps.client.balance();
  const result = await deps.client.optimizeLeaves();
  deps.out(
    `optimized: ${result.swaps} swaps, leaves ${result.leavesBefore} -> ${result.leavesAfter}`,
  );
  await record(deps, { command: "optimize", balanceBefore, expectedDelta: 0 });
}

export async function cmdCoopExit(
  deps: TrialDeps,
  options: {
    readonly address: string;
    readonly amountSats?: number;
    readonly maxFeeSats: number;
    readonly speed: CooperativeExitSpeed;
    readonly transferId?: string;
    readonly timeoutMin: number;
  },
): Promise<void> {
  const quote = await deps.client.withdrawals.quoteCooperativeExit({
    address: options.address,
    ...(options.amountSats === undefined ? {} : { amountSats: options.amountSats }),
  });
  deps.out(
    `quote: fast ${quote.fees.fast}, medium ${quote.fees.medium}, slow ${quote.fees.slow} sats`,
  );
  const balanceBefore = await deps.client.balance();
  const result = await deps.client.withdrawals.cooperativeExit({
    address: options.address,
    speed: options.speed,
    maxFeeSats: options.maxFeeSats,
    ...(options.amountSats === undefined ? {} : { amountSats: options.amountSats }),
    ...(options.transferId === undefined ? {} : { transferId: options.transferId }),
  });
  deps.out(`requestId: ${result.requestId}`);
  deps.out(`transferId: ${result.transferId}`);
  deps.out(
    `payout ${result.payoutSats} sats, fee ${result.feeSats} sats, txid ${result.coopExitTxid}`,
  );
  const fields = {
    command: "coop-exit",
    balanceBefore,
    expectedDelta: -(result.payoutSats + result.feeSats),
    amountSats: result.payoutSats,
    feeSats: result.feeSats,
    ids: {
      requestId: result.requestId,
      transferId: result.transferId,
      txid: result.coopExitTxid,
    },
  };
  const status = await pollUntil(deps, options.timeoutMin * 60_000, 10_000, async () => {
    const current = await deps.client.withdrawals.cooperativeExitStatus(result.requestId);
    return current.status === "SUCCEEDED" || COOP_EXIT_FAILED.has(current.status)
      ? current
      : undefined;
  });
  if (status === undefined) {
    deps.out(`exit still in progress (requestId ${result.requestId}) — check later`);
    await recordPending(deps, fields);
    return;
  }
  const idempotentRetry = { idempotentRetry: options.transferId !== undefined };
  if (status.status !== "SUCCEEDED") {
    deps.out(`cooperative exit ended with status ${status.status} — funds should return`);
    await record(deps, { ...fields, expectedDelta: 0 }, idempotentRetry);
    return;
  }
  deps.out("exited");
  await record(deps, fields, idempotentRetry);
}

export async function cmdExitPackage(
  deps: TrialDeps,
  options: { readonly out: string },
): Promise<void> {
  const leaves = await deps.client.leaves();
  const leafIds = leaves.map((leaf) => leaf.id);
  const offline = await deps.client.withdrawals.offlineExitTransactions(leafIds);
  const live = await deps.client.withdrawals.unilateralExit(leafIds);
  if (offline.length !== live.length || offline.some((tx, i) => tx.txid !== live[i]?.txid)) {
    throw new Error(
      `offline exit package diverges from the live view (${offline.length} vs ${live.length} transactions)`,
    );
  }
  const content = {
    network: deps.network,
    account: deps.account,
    generatedAt: new Date(deps.now()).toISOString(),
    transactions: offline.map((tx) => ({
      nodeId: tx.nodeId,
      kind: tx.kind,
      txid: tx.txid,
      parentTxid: tx.parentTxid,
      relativeTimelock: tx.relativeTimelock,
      tx: bytesToHex(tx.transaction),
    })),
  };
  writeFileSync(options.out, `${JSON.stringify(content, null, 2)}\n`, { mode: 0o600 });
  deps.out(
    `wrote ${offline.length} transactions (broadcast order) for ${leafIds.length} leaves to ${options.out}`,
  );
}

function formatEvent(event: SparkEvent): string {
  switch (event.type) {
    case "transfer":
      return `transfer ${event.direction} ${event.transferId}`;
    case "deposit":
      return `deposit leaf ${event.leafId}`;
    case "token-transaction":
      return `token-transaction ${bytesToHex(event.transactionHash)}`;
    default:
      return event.type;
  }
}

export async function cmdEvents(
  deps: TrialDeps,
  options: { readonly minutes: number },
): Promise<void> {
  const controller = new AbortController();
  const iterator = deps.client.events(controller.signal)[Symbol.asyncIterator]();
  const deadline = deps.now() + options.minutes * 60_000;
  for (;;) {
    const remaining = deadline - deps.now();
    if (remaining <= 0) {
      break;
    }
    let timedOut = false;
    // eslint-disable-next-line no-await-in-loop -- bounded event stream, one await per tick
    const event = await Promise.race([
      iterator.next(),
      deps.sleep(remaining).then(() => {
        timedOut = true;
        return undefined;
      }),
    ]);
    if (timedOut || event === undefined || event.done === true) {
      break;
    }
    deps.out(`${new Date(deps.now()).toISOString()} ${formatEvent(event.value)}`);
  }
  controller.abort();
}

export type ReportResult = { readonly mismatches: number };

export function cmdReport(deps: Pick<TrialDeps, "ledger" | "out">): ReportResult {
  const entries = deps.ledger.entries();
  deps.out(formatLedgerReport(entries));
  return { mismatches: entries.filter((entry) => entry.status === "mismatch").length };
}
