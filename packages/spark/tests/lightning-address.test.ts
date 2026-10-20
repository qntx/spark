import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import {
  LIGHTNING_ADDRESS_VALIDITY_SECS,
  checkLightningAddressDomain,
  checkLightningAddressUsername,
  lightningAddressDescriptionHash,
  lightningAddressMessage,
  lightningAddressMessageDigest,
  lightningAddressRegisterMessage,
  lightningAddressStatementHash,
  lightningAddressTimestampFresh,
  lightningAddressUnregisterMessage,
} from "../src/core/lightning-address.ts";
import type { LightningAddressStatement } from "../src/core/lightning-address.ts";
import type { SparkCrypto } from "../src/crypto/index.ts";
import { SparkInputError } from "../src/errors/index.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import { loadWasmBackend } from "./support/backend.ts";

// vectors/lightning-address.json — the Breez golden vectors, which are the
// byte-level spec every client and server must produce identically.

type VectorCase = {
  kind: "register" | "unregister";
  domain: string;
  username: string;
  description?: string;
  timestamp: number;
  message: string;
};

const vectors = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "../../../vectors/lightning-address.json"), "utf8"),
) as { cases: VectorCase[]; descriptionHashes: Array<{ description: string; hash: string }> };

const BUILDERS = {
  register: (c: VectorCase) =>
    lightningAddressRegisterMessage(c.domain, c.username, c.description ?? "", c.timestamp),
  unregister: (c: VectorCase) =>
    lightningAddressUnregisterMessage(c.domain, c.username, c.timestamp),
} as const;

describe("lightning address golden vectors", () => {
  test.each(vectors.cases)("$kind message is byte-identical to Breez", (c) => {
    expect(BUILDERS[c.kind](c)).toBe(c.message);
  });

  test.each(vectors.descriptionHashes)("description hash of '$description'", (c) => {
    expect(lightningAddressDescriptionHash(c.description)).toBe(c.hash);
  });
});

describe("lightningAddressMessage", () => {
  const register: LightningAddressStatement = {
    kind: "lightning-address",
    action: "register",
    domain: "lnurl.example.com",
    username: "alice",
    description: "Pay to alice",
    timestamp: 1_700_000_000,
  };

  test("dispatches on the action", () => {
    expect(lightningAddressMessage(register)).toBe(
      `breez-lnurl:v2\nregister\nlnurl.example.com\nalice\n${lightningAddressDescriptionHash("Pay to alice")}\n1700000000`,
    );
    const unregister: LightningAddressStatement = {
      kind: "lightning-address",
      action: "unregister",
      domain: "lnurl.example.com",
      username: "alice",
      timestamp: 1_700_000_000,
    };
    expect(lightningAddressMessage(unregister)).toBe(
      "breez-lnurl:v2\nunregister\nlnurl.example.com\nalice\n1700000000",
    );
  });

  test("a description containing LF stays one field", () => {
    const sneaky = "x\n1700000000";
    const message = lightningAddressMessage({ ...register, description: sneaky });
    expect(message.split("\n")).toHaveLength(6);
    expect(message).not.toContain(sneaky);
  });

  test.each([
    "Alice",
    "ALICE",
    "",
    "a".repeat(65),
    "white space",
    "under\nscore",
    "semi;colon",
    "percent%name",
  ])("rejects username %j", (username) => {
    expect(() => checkLightningAddressUsername(username)).toThrow(SparkInputError);
  });

  test.each(["alice", "a", "0", "a.b", "a-b", "a_b", "a+b", "a".repeat(64)])(
    "accepts username %j",
    (username) => {
      expect(() => checkLightningAddressUsername(username)).not.toThrow();
    },
  );

  test.each([
    "",
    "UPPER.com",
    "ln url.example.com",
    "lnurl\nexample.com",
    "-leading.example.com",
    "trailing-.example.com",
    ".dot.example.com",
    "trailing.example.com.",
    `too-long.${"a".repeat(64)}.com`,
    `x.${"a".repeat(250)}`,
  ])("rejects domain %j", (domain) => {
    expect(() => checkLightningAddressDomain(domain)).toThrow(SparkInputError);
  });

  test.each(["lnurl.example.com", "a.com", "host-name.example", "localhost"])(
    "accepts domain %j",
    (domain) => {
      expect(() => checkLightningAddressDomain(domain)).not.toThrow();
    },
  );

  test.each([-1, 1.5, Number.NaN, 2 ** 60])("rejects timestamp %j", (timestamp) => {
    expect(() =>
      lightningAddressUnregisterMessage("lnurl.example.com", "alice", timestamp),
    ).toThrow(SparkInputError);
  });
});

describe("lightningAddressStatementHash + freshness", () => {
  test("matches sha256(pubkeyHex ‖ 0x00 ‖ message)", () => {
    const pubkey = "02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc";
    const message = "breez-lnurl:v2\nunregister\nlnurl.example.com\nalice\n1700000000";
    const expected = sha256(new Uint8Array([...utf8ToBytes(pubkey), 0, ...utf8ToBytes(message)]));
    expect(lightningAddressStatementHash(pubkey, message)).toBe(bytesToHex(expected));
  });

  test("freshness is bounded symmetrically by the validity window", () => {
    const now = 1_700_000_000;
    expect(lightningAddressTimestampFresh(now, now)).toBe(true);
    expect(lightningAddressTimestampFresh(now + LIGHTNING_ADDRESS_VALIDITY_SECS, now)).toBe(true);
    expect(lightningAddressTimestampFresh(now - LIGHTNING_ADDRESS_VALIDITY_SECS, now)).toBe(true);
    expect(lightningAddressTimestampFresh(now + LIGHTNING_ADDRESS_VALIDITY_SECS + 1, now)).toBe(
      false,
    );
    expect(lightningAddressTimestampFresh(now - LIGHTNING_ADDRESS_VALIDITY_SECS - 1, now)).toBe(
      false,
    );
    expect(lightningAddressTimestampFresh(-1, now)).toBe(false);
  });
});

describe("signIdentity lightning-address", () => {
  const SEED = hexToBytes(
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
  );

  let cryptoPromise: Promise<SparkCrypto> | undefined;
  const backend = async (): Promise<SparkCrypto> => {
    cryptoPromise ??= loadWasmBackend();
    return cryptoPromise;
  };

  test("signs sha256(message) as low-S DER", async () => {
    const signer = createSparkSigner({
      crypto: await backend(),
      accountKey: sparkAccountKey(SEED, "regtest", 0),
      network: "regtest",
      random: (length) => {
        const out = new Uint8Array(length);
        out.set(sha256(utf8ToBytes("nonce")).subarray(0, Math.min(32, length)));
        return out;
      },
    });
    try {
      const statement: LightningAddressStatement = {
        kind: "lightning-address",
        action: "register",
        domain: "lnurl.example.com",
        username: "alice",
        description: "Pay to alice",
        timestamp: 1_700_000_000,
      };
      const signature = await signer.signIdentity(statement);
      expect(signature[0]).toBe(0x30);
      const identity = await signer.identityPublicKey();
      const digest = lightningAddressMessageDigest(lightningAddressMessage(statement));
      expect(secp256k1.verify(signature, digest, identity, { format: "der", prehash: false })).toBe(
        true,
      );
    } finally {
      signer.dispose();
    }
  });

  test("rejects a statement that fails core validation before signing", async () => {
    const signer = createSparkSigner({
      crypto: await backend(),
      accountKey: sparkAccountKey(SEED, "regtest", 0),
      network: "regtest",
      random: (length) => {
        const out = new Uint8Array(length);
        out.set(sha256(utf8ToBytes("nonce")).subarray(0, Math.min(32, length)));
        return out;
      },
    });
    try {
      await expect(
        signer.signIdentity({
          kind: "lightning-address",
          action: "unregister",
          domain: "lnurl.example.com",
          username: "Alice",
          timestamp: 1_700_000_000,
        }),
      ).rejects.toThrow(SparkInputError);
      await expect(
        signer.signIdentity({
          kind: "lightning-address",
          action: "unregister",
          domain: "lnurl\n.example.com",
          username: "alice",
          timestamp: 1_700_000_000,
        }),
      ).rejects.toThrow(SparkInputError);
      await expect(
        signer.signIdentity({
          kind: "lightning-address",
          action: "unregister",
          domain: "lnurl.example.com",
          username: "alice",
          timestamp: -5,
        }),
      ).rejects.toThrow(SparkInputError);
    } finally {
      signer.dispose();
    }
  });
});
