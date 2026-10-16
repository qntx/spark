import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

import { SparkInputError } from "../../errors/index.ts";
import { compareBytes, uint64be } from "../bytes.ts";

// Upstream references: sdks/js/packages/spark-sdk/src/utils/hashstructure.ts
// and signer/spark-token-primitives/src/hashstructure.rs
// (buildonspark/spark@0b3a32a). Domain-separated SHA-256 used for every
// non-protobuf signing statement: the tag is serialized component-wise and
// hashed once, then written twice into the digest state (BIP-340 tagged hash).
// Every value is length-prefixed with an 8-byte big-endian length, so fields
// can never be re-framed into each other.

const MAX_UINT64 = 0xff_ff_ff_ff_ff_ff_ff_ffn;

function serializeTag(tag: ReadonlyArray<string>): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const component of tag) {
    const componentBytes = utf8ToBytes(component);
    const lengthBytes = uint64be(BigInt(componentBytes.length));
    parts.push(lengthBytes, componentBytes);
  }
  const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/**
 * BIP-340-style tagged hasher for Spark signing statements. Tag order matters and acts as the
 * statement version: a schema change must change the tag, not the encoding.
 */
export class Hasher {
  private readonly hasher: ReturnType<typeof sha256.create>;

  private constructor(tag: ReadonlyArray<string>) {
    const tagHash = sha256(serializeTag(tag));
    this.hasher = sha256.create();
    this.hasher.update(tagHash);
    this.hasher.update(tagHash);
  }

  static new(tag: ReadonlyArray<string>): Hasher {
    return new Hasher(tag);
  }

  addBytes(b: Uint8Array): this {
    this.addValue(b);
    return this;
  }

  addString(s: string): this {
    this.addValue(utf8ToBytes(s));
    return this;
  }

  /** Numbers must be non-negative safe integers; bigints may cover the full uint64 range. */
  addUint64(v: number | bigint): this {
    let value: bigint;
    if (typeof v === "number") {
      if (!Number.isSafeInteger(v) || v < 0) {
        throw new SparkInputError("addUint64: number must be a non-negative safe integer");
      }
      value = BigInt(v);
    } else {
      if (v < 0n || v > MAX_UINT64) {
        throw new SparkInputError("addUint64: bigint must be within uint64 range");
      }
      value = v;
    }
    const valueBytes = uint64be(value);
    this.addValue(valueBytes);
    return this;
  }

  addUint32(v: number): this {
    if (!Number.isSafeInteger(v) || v < 0 || v > 0xffffffff) {
      throw new SparkInputError("addUint32: value must be a valid uint32");
    }
    return this.addUint64(BigInt(v));
  }

  addUint16(v: number): this {
    if (!Number.isSafeInteger(v) || v < 0 || v > 0xffff) {
      throw new SparkInputError("addUint16: value must be a valid uint16");
    }
    return this.addUint64(BigInt(v));
  }

  addUint8(v: number): this {
    if (!Number.isSafeInteger(v) || v < 0 || v > 0xff) {
      throw new SparkInputError("addUint8: value must be a valid uint8");
    }
    return this.addUint64(BigInt(v));
  }

  /** Count, then key/value pairs sorted by UTF-8 bytewise key order. */
  addMapStringToBytes(m: Readonly<Record<string, Uint8Array>>): this {
    this.addUint64(Object.keys(m).length);
    const pairs = Object.entries(m).map(([key, value]) => ({
      key,
      value,
      keyBytes: utf8ToBytes(key),
    }));
    pairs.sort((a, b) => compareBytes(a.keyBytes, b.keyBytes));
    for (const pair of pairs) {
      this.addString(pair.key);
      this.addBytes(pair.value);
    }
    return this;
  }

  /** Count, then key/value pairs sorted by UTF-8 bytewise key order. */
  addMapStringToUint64(m: Readonly<Record<string, number | bigint>>): this {
    this.addUint64(Object.keys(m).length);
    const pairs = Object.entries(m).map(([key, value]) => ({
      key,
      value,
      keyBytes: utf8ToBytes(key),
    }));
    pairs.sort((a, b) => compareBytes(a.keyBytes, b.keyBytes));
    for (const pair of pairs) {
      this.addString(pair.key);
      this.addUint64(pair.value);
    }
    return this;
  }

  private addValue(valueBytes: Uint8Array): void {
    const lengthBytes = uint64be(BigInt(valueBytes.length));
    this.hasher.update(lengthBytes);
    this.hasher.update(valueBytes);
  }

  hash(): Uint8Array {
    return this.hasher.digest();
  }
}

export function newHasher(tag: ReadonlyArray<string>): Hasher {
  return Hasher.new(tag);
}
