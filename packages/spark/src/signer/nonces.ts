import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import type { SparkCrypto } from "../crypto/index.ts";
import { SparkCryptoError, SparkError, SparkInputError } from "../errors/index.ts";
import { backendCall, commitmentKey, MAX_JOBS, PUBLIC_KEY_LENGTH, randomBytes } from "./backend.ts";
import type { SigningCommitment } from "./types.ts";

const FROST_COMMITMENT_ITEM = 130; // nonces(64) ‖ commitments(66)
const NONCE_LENGTH = 64;
const FROST_HEDGE_TAG = "spark/frost-hedge";

/**
 * Single-use FROST nonce storage. `commit` asks the backend for `count` commitment items (`hedge` =
 * HMAC-SHA256(accountPrivate, "spark/frost-hedge"), random = n×32 bytes) and stores each secret
 * nonce keyed by its `hiding‖binding` commitment pair; `take` removes and returns the nonce — it is
 * gone even if the signing that consumed it later fails.
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
  const hedge = hmac(sha256, accountPrivate, utf8ToBytes(FROST_HEDGE_TAG));
  const nonces = new Map<string, Uint8Array>();

  return {
    commit(count) {
      if (!Number.isSafeInteger(count) || count < 1 || count > MAX_JOBS) {
        throw new SparkInputError(`newCommitments: count must be between 1 and ${MAX_JOBS}`);
      }
      const items = backendCall(() => crypto.frostCommit(hedge, randomBytes(random, 32 * count)));
      if (items.length !== count * FROST_COMMITMENT_ITEM) {
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
      hedge.fill(0);
      for (const nonce of nonces.values()) {
        nonce.fill(0);
      }
      nonces.clear();
    },
  };
}
