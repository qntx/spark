import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vite-plus/test";

import { SparkCryptoError, SparkError } from "@qntx/spark/crypto";
import type { SparkCrypto } from "@qntx/spark/crypto";

import { bindSparkNative } from "../src/bind.ts";
import { fakeSparkNative } from "./support/fake-native.ts";

const VECTORS = new URL("../../../vectors/", import.meta.url);

type Cases<T> = { cases: T[] };

async function vector<T>(name: string): Promise<T[]> {
  const doc = JSON.parse(await readFile(new URL(name, VECTORS), "utf8")) as Cases<T>;
  return doc.cases;
}

async function loadBackend(): Promise<{
  crypto: SparkCrypto;
  received: Map<string, ArrayBuffer[]>;
}> {
  const { native, received } = await fakeSparkNative();
  return { crypto: bindSparkNative(native), received };
}

function hex(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function syncThrow(fn: () => unknown): unknown {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error("expected throw");
}

describe("abi version", () => {
  test("a loaded library reports SPARK_ABI_VERSION", async () => {
    const { crypto } = await loadBackend();
    expect(crypto.abiVersion).toBe(1);
  });

  test("a version mismatch is a SparkError, not a bound backend", async () => {
    const { native } = await fakeSparkNative(2);
    const error = syncThrow(() => bindSparkNative(native));
    expect(error).toBeInstanceOf(SparkError);
    expect(error).not.toBeInstanceOf(SparkCryptoError);
  });
});

describe("frost-commit vectors", () => {
  test("every case", async () => {
    const { crypto } = await loadBackend();
    type Case = { hedge: string; random: string; nonces: string; commitments: string };
    const cases = await vector<Case>("frost-commit.json");
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      const out = crypto.frostCommit(hex(c.hedge), hex(c.random));
      expect(out).toHaveLength(130);
      expect(toHex(out.slice(0, 64))).toBe(c.nonces);
      expect(toHex(out.slice(64))).toBe(c.commitments);
    }
  });
});

describe("ffi-sign vectors", () => {
  test("every case", async () => {
    const { crypto } = await loadBackend();
    const cases = await vector<{ request: string; response: string }>("ffi-sign.json");
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      expect(toHex(crypto.frostSign(hex(c.request)))).toBe(c.response);
    }
  });
});

describe("ffi-aggregate vectors", () => {
  test("every case", async () => {
    const { crypto } = await loadBackend();
    const cases = await vector<{ request: string; response: string }>("ffi-aggregate.json");
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      expect(toHex(crypto.frostAggregate(hex(c.request)))).toBe(c.response);
    }
  });
});

describe("ecies vectors", () => {
  test("every case round-trips", async () => {
    const { crypto } = await loadBackend();
    type Case = {
      secret_key: string;
      public_key: string;
      random: string;
      plaintext: string;
      ciphertext: string;
    };
    const cases = await vector<Case>("ecies.json");
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      expect(toHex(crypto.eciesEncrypt(hex(c.public_key), hex(c.plaintext), hex(c.random)))).toBe(
        c.ciphertext,
      );
      expect(toHex(crypto.eciesDecrypt(hex(c.secret_key), hex(c.ciphertext)))).toBe(c.plaintext);
    }
  });
});

describe("vss vectors", () => {
  test("every case", async () => {
    const { crypto } = await loadBackend();
    type Case = {
      secret: string;
      threshold: number;
      share_count: number;
      random: string;
      proofs: string[];
      shares: string[];
    };
    const cases = await vector<Case>("vss.json");
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      const out = crypto.splitSecretWithProofs(
        hex(c.secret),
        c.threshold,
        c.share_count,
        hex(c.random),
      );
      expect(toHex(out)).toBe([...c.proofs, ...c.shares].join(""));
    }
  });
});

describe("ffi-errors vectors", () => {
  test("every qntx_spark:<code> error maps to a SparkCryptoError with that code", async () => {
    const { crypto } = await loadBackend();
    type Case = { function: string; code: number } & Record<string, unknown>;
    const cases = await vector<Case>("ffi-errors.json");
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      const error = syncThrow(() => dispatch(crypto, c));
      expect(error, `${c.function} ${JSON.stringify(c)}`).toBeInstanceOf(SparkCryptoError);
      expect((error as SparkCryptoError).code).toBe(c.code);
    }
  });
});

describe("non-ABI errors", () => {
  test("errors without a qntx_spark code are rethrown unchanged", async () => {
    const { native } = await fakeSparkNative();
    const broken = Object.create(native) as typeof native;
    const failure = new RangeError("native bridge exploded");
    broken.frostCommit = () => {
      throw failure;
    };
    const crypto = bindSparkNative(broken);
    const error = syncThrow(() => crypto.frostCommit(hex("00".repeat(32)), hex("11".repeat(32))));
    expect(error).toBe(failure);
  });
});

describe("nitro-prefixed ABI errors", () => {
  test("a function-prefixed qntx_spark:<code> maps to SparkCryptoError", async () => {
    const { native } = await fakeSparkNative();
    const broken = Object.create(native) as typeof native;
    broken.frostSign = () => {
      throw new Error("SparkNative.frostSign(...): qntx_spark:5");
    };
    const crypto = bindSparkNative(broken);
    const error = syncThrow(() => crypto.frostSign(new Uint8Array(4)));
    expect(error).toBeInstanceOf(SparkCryptoError);
    expect((error as SparkCryptoError).code).toBe(5);
  });

  test("a bare qntx_spark:<code> message still maps", async () => {
    const { native } = await fakeSparkNative();
    const broken = Object.create(native) as typeof native;
    broken.frostSign = () => {
      throw new Error("qntx_spark:5");
    };
    const crypto = bindSparkNative(broken);
    const error = syncThrow(() => crypto.frostSign(new Uint8Array(4)));
    expect(error).toBeInstanceOf(SparkCryptoError);
    expect((error as SparkCryptoError).code).toBe(5);
  });

  test("an unrelated prefixed message is rethrown unchanged", async () => {
    const { native } = await fakeSparkNative();
    const broken = Object.create(native) as typeof native;
    const failure = new Error("foo: bar");
    broken.frostSign = () => {
      throw failure;
    };
    const crypto = bindSparkNative(broken);
    expect(syncThrow(() => crypto.frostSign(new Uint8Array(4)))).toBe(failure);
  });
});

/** ArrayBuffer `index` recorded for `name` — throws if the hybrid never saw that argument. */
function receivedAt(
  received: Map<string, ArrayBuffer[]>,
  name: string,
  index: number,
): ArrayBuffer {
  const buffer = (received.get(name) ?? [])[index];
  if (buffer === undefined) {
    throw new Error(`no ${name} buffer ${index} recorded`);
  }
  return buffer;
}

/** First ArrayBuffer recorded for `name` — throws if the hybrid never saw a call. */
function firstReceived(received: Map<string, ArrayBuffer[]>, name: string): ArrayBuffer {
  return receivedAt(received, name, 0);
}

describe("private input copies", () => {
  const ECIES_CASE = {
    secret_key: "20f12d0fdc7fe5d0b7da9f4a02689b98c5c4b94b84fc6e8179e5854ad6c152e8",
    ciphertext:
      "04c5f2b3e236d39c5f79dd2f7a8e52e1b7457f8328ee2f7d0e8b9532226ffae4cb2bb054e7d7e8d6c9e7e0be2f66f2b4fb2f9d2ffafe39a0a3a3bd841b27ee1c2d6bcb8ba2dcd8f15b6f1b3c949c0d408421c7fd5228f9e0d91df452",
  };

  test("a view-backed secret input is copied, and the copy is wiped after the call", async () => {
    const { crypto, received } = await loadBackend();
    // Bigger backing buffer with the private key at a non-zero offset forces the copy path.
    const backing = new Uint8Array(96);
    backing.set(hex(ECIES_CASE.secret_key), 32);
    const privateKey = backing.subarray(32, 64);
    const error = syncThrow(() => crypto.eciesDecrypt(privateKey, hex(ECIES_CASE.ciphertext)));
    // The ciphertext is malformed; what matters is the buffer handed to the hybrid.
    expect(error).toBeInstanceOf(SparkCryptoError);
    const handed = firstReceived(received, "eciesDecrypt");
    expect(handed).not.toBe(backing.buffer);
    expect(new Uint8Array(handed)).toStrictEqual(new Uint8Array(32));
    // The caller's backing buffer is untouched.
    expect(backing.slice(32, 64)).toStrictEqual(hex(ECIES_CASE.secret_key));
  });

  test("a whole-buffer input is passed without a copy and never wiped", async () => {
    const { crypto, received } = await loadBackend();
    const privateKey = hex(ECIES_CASE.secret_key);
    syncThrow(() => crypto.eciesDecrypt(privateKey, hex(ECIES_CASE.ciphertext)));
    const handed = firstReceived(received, "eciesDecrypt");
    expect(handed).toBe(privateKey.buffer);
    expect(toHex(privateKey)).toBe(ECIES_CASE.secret_key);
  });

  test("frostCommit view inputs are copied and wiped after the call", async () => {
    const { crypto, received } = await loadBackend();
    const hedgeBacking = new Uint8Array(96);
    hedgeBacking.set(hex("11".repeat(32)), 32);
    const randomBacking = new Uint8Array(96);
    randomBacking.set(hex("22".repeat(32)), 64);
    const out = crypto.frostCommit(hedgeBacking.subarray(32, 64), randomBacking.subarray(64, 96));
    expect(out).toHaveLength(130);
    expect(new Uint8Array(receivedAt(received, "frostCommit", 0))).toStrictEqual(
      new Uint8Array(32),
    );
    expect(new Uint8Array(receivedAt(received, "frostCommit", 1))).toStrictEqual(
      new Uint8Array(32),
    );
  });

  test("eciesEncrypt view plaintext and random are copied and wiped", async () => {
    const { crypto, received } = await loadBackend();
    const generator = hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    const plaintextBacking = new Uint8Array(64);
    plaintextBacking.set(hex("aa".repeat(32)), 16);
    const randomBacking = new Uint8Array(64);
    randomBacking.set(hex("33".repeat(32)), 8);
    const out = crypto.eciesEncrypt(
      generator,
      plaintextBacking.subarray(16, 48),
      randomBacking.subarray(8, 40),
    );
    expect(out.length).toBeGreaterThan(0);
    expect(new Uint8Array(receivedAt(received, "eciesEncrypt", 1))).toStrictEqual(
      new Uint8Array(32),
    );
    expect(new Uint8Array(receivedAt(received, "eciesEncrypt", 2))).toStrictEqual(
      new Uint8Array(32),
    );
  });

  test("splitSecretWithProofs view random is copied and wiped", async () => {
    const { crypto, received } = await loadBackend();
    const randomBacking = new Uint8Array(64);
    randomBacking.set(hex("44".repeat(32)), 5);
    const out = crypto.splitSecretWithProofs(
      hex("20".repeat(32)),
      2,
      3,
      randomBacking.subarray(5, 37),
    );
    expect(out).toHaveLength(2 * 33 + 3 * 32);
    expect(new Uint8Array(receivedAt(received, "splitSecretWithProofs", 1))).toStrictEqual(
      new Uint8Array(32),
    );
  });
});

function dispatch(crypto: SparkCrypto, c: Record<string, unknown>): void {
  const field = (name: string): Uint8Array => hex(c[name] as string);
  switch (c["function"]) {
    case "frost_commit":
      crypto.frostCommit(field("hedge"), field("random"));
      return;
    case "frost_sign":
      crypto.frostSign(field("request"));
      return;
    case "frost_aggregate":
      crypto.frostAggregate(field("request"));
      return;
    case "ecies_encrypt":
      crypto.eciesEncrypt(field("public_key"), field("plaintext"), field("random"));
      return;
    case "ecies_decrypt":
      crypto.eciesDecrypt(field("secret_key"), field("ciphertext"));
      return;
    case "split_secret_with_proofs":
      crypto.splitSecretWithProofs(
        field("secret"),
        c["threshold"] as number,
        c["share_count"] as number,
        field("random"),
      );
      return;
    default:
      throw new Error(`unknown ffi function ${c["function"]}`);
  }
}
