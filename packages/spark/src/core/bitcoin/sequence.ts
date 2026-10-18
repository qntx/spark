import { SparkInputError } from "../../errors/index.ts";
import { assertU32 } from "../assert.ts";

// Timelock/sequence math for Spark node, refund and HTLC transactions.
// Upstream references: signer/spark-frost/src/transaction.rs and
// sdks/js/packages/spark-sdk/src/utils/transaction.ts (buildonspark/spark@0b3a32a).
// `nextSequence` follows the Rust semantics exactly; the `getNext*Sequence`
// helpers mirror the upstream TS wrappers used by the services layer.
// Observed on the local SOs (S7a deposit e2e, docker compose stack): they accept the
// initial deposit with root sequence 0 and refund timelocks 2000 / 2050 — the
// `getNextTransactionSequence`-style initial timelocks. Whether `nextSequence` matches
// renewal paths is still unverified against the SO; keep both until S7b.

// BIP-68: bit 31 disables relative lock-time, bit 22 selects a time-based lock.
const SEQUENCE_LOCK_TIME_DISABLED = 0x80_00_00_00;
const SEQUENCE_LOCK_TIME_IS_SECONDS = 0x00_40_00_00;
/** Lower 16 bits carry the block-based timelock value. */
const SEQUENCE_LOCK_TIME_MASK = 0x00_00_ff_ff;
const BIT_30 = 1 << 30;

export const TIME_LOCK_INTERVAL = 100;
export const DIRECT_TIMELOCK_OFFSET = 50;
export const HTLC_TIMELOCK_OFFSET = 70;
export const DIRECT_HTLC_TIMELOCK_OFFSET = 85;
export const ZERO_SEQUENCE = 0;
export const INITIAL_TIMELOCK = 2000;
export const INITIAL_SEQUENCE: number = INITIAL_TIMELOCK;
export const INITIAL_ROOT_NODE_SEQUENCE: number = ZERO_SEQUENCE;

// Default fee constants matching upstream (estimated tx size × sats/vbyte).
export const ESTIMATED_TX_SIZE = 191;
export const DEFAULT_SATS_PER_VBYTE = 5;
export const DEFAULT_FEE_SATS: number = ESTIMATED_TX_SIZE * DEFAULT_SATS_PER_VBYTE;

/** Extracts the block-based timelock (lower 16 bits) from a sequence number. */
export function getTimelockFromSequence(sequence: number): number {
  assertU32(sequence, "sequence");
  return sequence & SEQUENCE_LOCK_TIME_MASK;
}

/**
 * Rejects sequences with bit 31 (timelock disabled) or bit 22 (time-based timelock) set — Spark
 * only uses block-based relative timelocks.
 */
export function checkIfValidSequence(sequence: number): void {
  assertU32(sequence, "sequence");
  if ((sequence & SEQUENCE_LOCK_TIME_DISABLED) !== 0) {
    throw new SparkInputError("sequence: bit 31 set disables the relative timelock");
  }
  if ((sequence & SEQUENCE_LOCK_TIME_IS_SECONDS) !== 0) {
    throw new SparkInputError("sequence: bit 22 selects a time-based timelock");
  }
}

/** True when the sequence's timelock value is zero (upper bits ignored). */
export function isZeroTimelock(sequence: number): boolean {
  return getTimelockFromSequence(sequence) === 0;
}

/** Rounds `timelock` down to the nearest multiple of `timeLockInterval` (0 disables rounding). */
export function roundDownToTimelockInterval(timelock: number, timeLockInterval: number): number {
  assertU32(timelock, "timelock");
  assertU32(timeLockInterval, "timeLockInterval");
  if (timeLockInterval === 0) {
    return timelock;
  }
  return timelock - (timelock % timeLockInterval);
}

/**
 * Decrements the timelock by one interval, preserving all upper bits, and returns the direct-spend
 * sequence at `directTimelockOffset` above it. Ported 1:1 from upstream Rust `next_sequence`
 * (buildonspark/spark@0b3a32a).
 */
export function nextSequence(
  currSequence: number,
  timeLockInterval: number,
  directTimelockOffset: number,
): { nextSequence: number; nextDirectSequence: number } {
  assertU32(currSequence, "currSequence");
  assertU32(timeLockInterval, "timeLockInterval");
  assertU32(directTimelockOffset, "directTimelockOffset");
  const currTimelock = getTimelockFromSequence(currSequence);
  const nextTimelock = currTimelock - timeLockInterval;
  if (nextTimelock < 0) {
    throw new SparkInputError("sequence: next timelock is below zero — renew the node timelock");
  }
  const upperBits = currSequence & 0xff_ff_00_00;
  const nextDirectTimelock = nextTimelock + directTimelockOffset;
  if (nextDirectTimelock > SEQUENCE_LOCK_TIME_MASK) {
    throw new SparkInputError("sequence: direct timelock offset overflows the lower 16 bits");
  }
  return {
    nextSequence: upperBits | nextTimelock,
    nextDirectSequence: upperBits | nextDirectTimelock,
  };
}

/**
 * Current sequence without decrementing (bit 30 carried, like upstream TS): the direct variant sits
 * `DIRECT_TIMELOCK_OFFSET` blocks higher.
 */
export function getTransactionSequence(currSequence: number): {
  nextSequence: number;
  nextDirectSequence: number;
} {
  const timelock = getTimelockFromSequence(currSequence);
  const upper = currSequence & BIT_30;
  return {
    nextSequence: upper | timelock,
    nextDirectSequence: upper | (timelock + DIRECT_TIMELOCK_OFFSET),
  };
}

/**
 * Next node/refund sequence: decrements the timelock by `TIME_LOCK_INTERVAL`. Mirrors the upstream
 * TS helper: node transactions may decrement to zero, other transactions must stay above zero; only
 * bit 30 is preserved.
 */
export function getNextTransactionSequence(
  currSequence: number,
  isNodeTx?: boolean,
): { nextSequence: number; nextDirectSequence: number } {
  const timelock = getTimelockFromSequence(currSequence);
  const nextTimelock = timelock - TIME_LOCK_INTERVAL;
  const upper = currSequence & BIT_30;
  if (isNodeTx === true && nextTimelock < 0) {
    throw new SparkInputError("sequence: next timelock is below zero");
  }
  if (isNodeTx !== true && nextTimelock <= 0) {
    throw new SparkInputError("sequence: next timelock must stay above zero");
  }
  return {
    nextSequence: upper | nextTimelock,
    nextDirectSequence: upper | (nextTimelock + DIRECT_TIMELOCK_OFFSET),
  };
}

/** Same decrement for HTLC transactions, offset by the HTLC timelock deltas. */
export function getNextHTLCTransactionSequence(
  currSequence: number,
  isNodeTx?: boolean,
): { nextSequence: number; nextDirectSequence: number } {
  const timelock = getTimelockFromSequence(currSequence);
  const nextTimelock = timelock - TIME_LOCK_INTERVAL;
  const upper = currSequence & BIT_30;
  if (isNodeTx === true && nextTimelock < 0) {
    throw new SparkInputError("sequence: next timelock is below zero");
  }
  if (isNodeTx !== true && nextTimelock <= 0) {
    throw new SparkInputError("sequence: next timelock must stay above zero");
  }
  return {
    nextSequence: upper | (nextTimelock + HTLC_TIMELOCK_OFFSET),
    nextDirectSequence: upper | (nextTimelock + DIRECT_HTLC_TIMELOCK_OFFSET),
  };
}

/**
 * Whether the transaction should be renewed: refresh before the timelock drops below 200 blocks so
 * it cannot fall under 100 after a transfer or renewal, which would risk interfering with
 * watchtowers.
 */
export function doesTxnNeedRenewed(currSequence: number): boolean {
  return getTimelockFromSequence(currSequence) < 200;
}

/** Whether a leaf must be refreshed before handing it to the next owner. */
export function doesLeafNeedRefresh(currSequence: number, isNodeTx?: boolean): boolean {
  const timelock = getTimelockFromSequence(currSequence);
  return isNodeTx === true ? timelock === 0 : timelock <= TIME_LOCK_INTERVAL;
}
