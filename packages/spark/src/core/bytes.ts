/** Byte-level helpers shared across core. */

/** Lexicographic byte comparison; equal prefixes order by length (shorter first). */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const minLength = Math.min(a.length, b.length);
  for (let i = 0; i < minLength; i++) {
    const av = a[i];
    const bv = b[i];
    if (av !== undefined && bv !== undefined && av !== bv) {
      return av - bv;
    }
  }
  return a.length - b.length;
}

/** Big-endian u32 serialization. */
export function uint32be(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value >>> 0, false);
  return bytes;
}

/** Big-endian u64 serialization. */
export function uint64be(value: bigint): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value, false);
  return bytes;
}
