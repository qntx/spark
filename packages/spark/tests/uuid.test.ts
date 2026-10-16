import { expect, test } from "vite-plus/test";

import { uuidFromBytes, uuidToBytes, uuidv7 } from "../src/core/uuid.ts";
import { SparkInputError } from "../src/errors/index.ts";

test("RFC 9562 Appendix A.6 example vector", () => {
  // unix_ts_ms 0x017F22E279B0, rand_a 0xCC3, rand_b 0x18C4DC0C0C07398F
  const rand = () => Uint8Array.of(0x0c, 0xc3, 0x18, 0xc4, 0xdc, 0x0c, 0x0c, 0x07, 0x39, 0x8f);
  const id = uuidv7(rand, () => 0x017f22e279b0);
  expect(id).toBe("017f22e2-79b0-7cc3-98c4-dc0c0c07398f");
});

test("version and variant bits are set", () => {
  const rand = () => new Uint8Array(10).fill(0xff);
  const id = uuidv7(rand, () => 0);
  expect(id[14]).toBe("7");
  expect(["8", "9", "a", "b"]).toContain(id[19]);
});

test("bytes round trip", () => {
  const id = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f";
  expect(uuidFromBytes(uuidToBytes(id))).toBe(id);
});

test("uppercase input accepted, lowercase output", () => {
  expect(uuidFromBytes(uuidToBytes("017F22E2-79B0-7CC3-98C4-DC0C0C07398F"))).toBe(
    "017f22e2-79b0-7cc3-98c4-dc0c0c07398f",
  );
});

test("malformed ids rejected", () => {
  for (const bad of [
    "",
    "not-a-uuid",
    "017f22e279b07cc398c4dc0c0c07398f",
    "{017f22e2-79b0-7cc3-98c4-dc0c0c07398f}",
    "017f22e2-79b0-7cc3-98c4-dc0c0c07398g",
  ]) {
    expect(() => uuidToBytes(bad)).toThrow(SparkInputError);
  }
  expect(() => uuidFromBytes(new Uint8Array(15))).toThrow(SparkInputError);
});

test("timestamp bounds", () => {
  const rand = () => new Uint8Array(10);
  expect(() => uuidv7(rand, () => -1)).toThrow(SparkInputError);
  expect(() => uuidv7(rand, () => 2 ** 48)).toThrow(SparkInputError);
  expect(() =>
    uuidv7(
      () => new Uint8Array(4),
      () => 0,
    ),
  ).toThrow(SparkInputError);
});
