import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { uint64be } from "../core/bytes.ts";
import type { SparkCrypto } from "../crypto/index.ts";
import { SparkCryptoError, SparkError, SparkInputError } from "../errors/index.ts";
import { backendCall, commitmentKey, MAX_JOBS, PUBLIC_KEY_LENGTH, withRandom } from "./backend.ts";
import type { SigningCommitment } from "./types.ts";

const FROST_COMMITMENT_ITEM = 130; // nonces(64) ‖ commitments(66)
const NONCE_LENGTH = 64;
const FROST_HEDGE_TAG = "spark/frost-hedge";
const MAX_OUTSTANDING = 1024;

/**
 * Single-use FROST nonce storage. `commit` asks the backend for `count` commitment items and stores
 * each secret nonce keyed by its `hiding‖binding` commitment pair; `take` removes and returns the
 * nonce — it is gone even if the signing that consumed it later fails.
 *
 * Two bounds keep remote-driven load from hurting the signer:
 *
 * - Each call's hedge is HMAC-SHA256(HMAC(accountPrivate, tag), tag ‖ u64be counter) over a
 *   store-local monotone counter, so an injected RNG that repeats within one signer instance can no
 *   longer repeat nonces (a repeating RNG across restarts remains the caller's responsibility);
 * - Committing past MAX_OUTSTANDING evicts the oldest outstanding nonces (wiped, insertion order)
 *   instead of refusing, so leaked commitments can never wedge the store.
 */
export type NonceStore = {
  readonly commit: (count: number) => SigningCommitment[];
  readonly take: (commitment: SigningCommitment) => Uint8Array;
  readonly wipe: () => void;
};

export function createNonceStore(
  crypto: SparkCrypto,
  accountPrivate: Uint8Array,
  random: (length: number) => Uint8Array,
): NonceStore {
  const hedgeKey = hmac(sha256, accountPrivate, utf8ToBytes(FROST_HEDGE_TAG));
  const nonces = new Map<string, Uint8Array>();
  let hedgeCounter = 0n;

  return {
    commit(count) {
      if (!Number.isSafeInteger(count) || count < 1 || count > MAX_JOBS) {
        throw new SparkInputError(`newCommitments: count must be between 1 and ${MAX_JOBS}`);
      }
      for (const [key, nonce] of nonces) {
        if (nonces.size + count <= MAX_OUTSTANDING) {
          break;
        }
        nonce.fill(0);
        nonces.delete(key);
      }
      const hedge = hmac(
        sha256,
        hedgeKey,
        concatBytes(utf8ToBytes(FROST_HEDGE_TAG), uint64be(hedgeCounter)),
      );
      hedgeCounter += 1n;
      let items: Uint8Array;
      try {
        items = backendCall(() =>
          withRandom(random, 32 * count, (seed) => crypto.frostCommit(hedge, seed)),
        );
      } finally {
        hedge.fill(0);
      }
      if (items.length !== count * FROST_COMMITMENT_ITEM) {
        items.fill(0);
        throw new SparkCryptoError(8);
      }
      const commitments: SigningCommitment[] = [];
      for (let i = 0; i < count; i++) {
        const item = items.subarray(i * FROST_COMMITMENT_ITEM, (i + 1) * FROST_COMMITMENT_ITEM);
        const nonce = item.slice(0, NONCE_LENGTH);
        const hiding = item.slice(NONCE_LENGTH, NONCE_LENGTH + PUBLIC_KEY_LENGTH);
        const binding = item.slice(NONCE_LENGTH + PUBLIC_KEY_LENGTH, FROST_COMMITMENT_ITEM);
        nonces.set(bytesToHex(concatBytes(hiding, binding)), nonce);
        commitments.push({ hiding, binding });
      }
      items.fill(0);
      return commitments;
    },
    take(commitment) {
      const key = commitmentKey(commitment);
      const nonce = nonces.get(key);
      nonces.delete(key);
      if (nonce === undefined) {
        throw new SparkError("signFrost: unknown or already-consumed signing commitment");
      }
      return nonce;
    },
    wipe() {
      hedgeKey.fill(0);
      for (const nonce of nonces.values()) {
        nonce.fill(0);
      }
      nonces.clear();
    },
  };
}
