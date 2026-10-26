import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import { EPHEMERAL_ANCHOR_SCRIPT, p2trScriptFromPublicKey } from "../src/core/bitcoin/script.ts";
import type { SigningTarget } from "../src/core/bitcoin/sighash.ts";
import type { SparkCrypto } from "../src/crypto/index.ts";
import { SparkInputError } from "../src/errors/index.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import type { FrostSignJob, SigningCommitment, SparkOperator } from "../src/signer/index.ts";
import { loadWasmBackend } from "./support/backend.ts";
import { seededRandom } from "./support/fakes.ts";
import { be32 } from "./support/frost.ts";

// External-audit round, group B: PoC d2 asserted a mid-batch validation failure inside signFrost
// stranded the not-yet-processed jobs' nonces, and ~4 poisoned batches wedged the signer at the
// 1024-outstanding cap. Reversed: the batch takes every commitment up front (a failure consumes
// the whole batch), commits past the cap evict the oldest outstanding nonces instead of refusing,
// and a repeating RNG within one signer instance can no longer repeat nonces.

const { Point } = secp256k1;

const derivation = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "../../../vectors/derivation.json"), "utf8"),
) as { cases: Array<{ seed_hex: string }> };

const TARGET: SigningTarget = {
  transaction: (() => {
    const tx = new Transaction({ allowUnknownOutputs: true });
    tx.addInput({ txid: new Uint8Array(32).fill(3), index: 0 });
    tx.addOutput({ script: EPHEMERAL_ANCHOR_SCRIPT, amount: 0n });
    return tx.toBytes();
  })(),
  inputIndex: 0,
  prevouts: [
    {
      script: p2trScriptFromPublicKey(secp256k1.Point.BASE.toBytes(true), "regtest"),
      amount: 1000,
    },
  ],
};

const VALID_IDENTIFIER = bytesToHex(be32(1n));
const VALID_COMMITMENT = { hiding: Point.BASE.toBytes(true), binding: Point.BASE.toBytes(true) };

let cryptoPromise: Promise<SparkCrypto> | undefined;
const backend = async (): Promise<SparkCrypto> => {
  cryptoPromise ??= loadWasmBackend();
  return cryptoPromise;
};

function jobFor(commitment: SigningCommitment, identifier = VALID_IDENTIFIER): FrostSignJob {
  return {
    key: { type: "static-deposit", index: 0 },
    target: TARGET,
    verifyingKey: Point.BASE.toBytes(true),
    commitment,
    operatorCommitments: [{ identifier, commitment: VALID_COMMITMENT }],
  };
}

describe("M-01: signFrost batch failure cannot wedge the nonce store", () => {
  test("a mid-batch failure consumes every commitment; poisoned rounds never accumulate", async () => {
    const accountKey = sparkAccountKey(hexToBytes(derivation.cases[0]!.seed_hex), "regtest", 0);
    const signer = createSparkSigner({
      crypto: await backend(),
      accountKey,
      network: "regtest",
      random: seededRandom(new Uint8Array(32).fill(9)),
    });
    try {
      // Three commitments, job index 1 malformed — the batch fails validation, but the upfront
      // take already consumed every commitment in it.
      const [c0, c1, c2] = await signer.newCommitments(3);
      const jobs = [jobFor(c0!), jobFor(c1!, "XYZ"), jobFor(c2!)];
      await expect(signer.signFrost(jobs)).rejects.toThrow(SparkInputError);
      for (const commitment of [c0!, c1!, c2!]) {
        // oxlint-disable-next-line no-await-in-loop -- sequential: each take must observe the store
        await expect(signer.signFrost([jobFor(commitment)])).rejects.toThrow(
          "unknown or already-consumed signing commitment",
        );
      }

      // Five poisoned 256-job rounds: each consumes its whole batch, so outstanding stays at zero
      // and the store accepts the next full batch — the old code wedged on round 5.
      for (let round = 1; round <= 5; round++) {
        // oxlint-disable-next-line no-await-in-loop -- rounds are sequential: later commits must observe the earlier failures
        const commitments = await signer.newCommitments(256);
        const batch = commitments.map((commitment) => jobFor(commitment));
        batch[1] = jobFor(commitments[1]!, "XYZ");
        // oxlint-disable-next-line no-await-in-loop -- rounds are sequential
        await expect(signer.signFrost(batch)).rejects.toThrow(
          "identifier: must be 64 lowercase hex characters",
        );
      }
    } finally {
      signer.dispose();
    }
  }, 60_000);
});

describe("I-01: the per-call hedge counters a repeating RNG", () => {
  test("an RNG that always returns the same seed still yields distinct commitments", async () => {
    const accountKey = sparkAccountKey(hexToBytes(derivation.cases[0]!.seed_hex), "regtest", 0);
    const constant = (length: number): Uint8Array => new Uint8Array(length).fill(7);
    const signer = createSparkSigner({
      crypto: await backend(),
      accountKey,
      network: "regtest",
      random: constant,
    });
    try {
      const [a] = await signer.newCommitments(1);
      const [b] = await signer.newCommitments(1);
      expect(bytesToHex(a!.binding)).not.toBe(bytesToHex(b!.binding));
      expect(bytesToHex(a!.hiding)).not.toBe(bytesToHex(b!.hiding));
    } finally {
      signer.dispose();
    }
  });
});

describe("L-05: operator lists must be unique", () => {
  test("a duplicate id, identifier or identityPublicKey is rejected", async () => {
    const accountKey = sparkAccountKey(hexToBytes(derivation.cases[0]!.seed_hex), "regtest", 0);
    const crypto = await backend();
    const random = seededRandom(new Uint8Array(32).fill(4));
    const first: SparkOperator = {
      id: 0,
      identifier: bytesToHex(be32(1n)),
      identityPublicKey: Point.BASE.toBytes(true),
    };
    const second: SparkOperator = {
      id: 1,
      identifier: bytesToHex(be32(2n)),
      identityPublicKey: Point.BASE.multiply(2n).toBytes(true),
    };
    const lists: SparkOperator[][] = [
      [first, second, { ...second, id: 0 }],
      [
        first,
        second,
        {
          ...second,
          id: 2,
          identityPublicKey: Point.BASE.multiply(3n).toBytes(true),
        },
      ],
      [
        first,
        second,
        {
          ...second,
          id: 2,
          identifier: bytesToHex(be32(3n)),
          identityPublicKey: Point.BASE.toBytes(true),
        },
      ],
    ];
    for (const operators of lists) {
      // oxlint-disable-next-line no-await-in-loop -- sequential construction attempts
      await expect(
        Promise.resolve().then(() =>
          createSparkSigner({
            crypto,
            accountKey,
            network: "regtest",
            random,
            operators,
            threshold: 2,
          }),
        ),
      ).rejects.toThrow("id, identifier and identityPublicKey must each be unique");
    }
  });
});
