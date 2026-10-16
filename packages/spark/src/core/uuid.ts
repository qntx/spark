import { SparkInputError } from "../errors/index.ts";

/**
 * UUIDv7 (RFC 9562 §5.7): 48-bit millisecond timestamp, then 74 random bits with the version (0111)
 * and variant (10) fields applied. Randomness and the clock are injected so the function stays
 * platform-neutral and deterministic under test.
 */
export function uuidv7(
  random: (length: number) => Uint8Array,
  now: () => number = () => Date.now(),
): string {
  const timestamp = now();
  if (!Number.isSafeInteger(timestamp) || timestamp < 0 || timestamp > 0xffffffffffff) {
    throw new SparkInputError("timestamp: must be a non-negative 48-bit millisecond value");
  }
  const rand = random(10);
  if (rand.length < 10) {
    throw new SparkInputError("random: must return at least 10 bytes");
  }
  const bytes = new Uint8Array(16);
  bytes[0] = timestamp / 0x10000000000;
  bytes[1] = timestamp / 0x100000000;
  bytes[2] = timestamp / 0x1000000;
  bytes[3] = timestamp / 0x10000;
  bytes[4] = timestamp / 0x100;
  bytes[5] = timestamp;
  const [r0 = 0, r1 = 0, r2 = 0] = rand;
  bytes[6] = 0x70 | (r0 & 0x0f);
  bytes[7] = r1;
  bytes[8] = 0x80 | (r2 & 0x3f);
  bytes.set(rand.subarray(3, 10), 9);
  return uuidFromBytes(bytes);
}

const HEX = "0123456789abcdef";

/** Formats 16 bytes as a canonical lowercase UUID string. */
export function uuidFromBytes(bytes: Uint8Array): string {
  if (bytes.length !== 16) {
    throw new SparkInputError("uuid: must be 16 bytes");
  }
  let out = "";
  let i = 0;
  for (const b of bytes) {
    if (i === 4 || i === 6 || i === 8 || i === 10) {
      out += "-";
    }
    out += HEX.charAt(b >> 4) + HEX.charAt(b & 0x0f);
    i += 1;
  }
  return out;
}

/**
 * Parses a UUID string to its 16 bytes. Accepts upper- and lowercase hex; braces and the
 * `urn:uuid:` prefix are rejected — only the canonical `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` shape
 * is valid here.
 */
export function uuidToBytes(id: string): Uint8Array {
  if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(id)) {
    throw new SparkInputError("id: must be a UUID in canonical form");
  }
  const hex = id.replaceAll("-", "");
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
