/** Reverse-looks-up a proto enum value's name; falls back to the numeric string. */
export function protoEnumName(table: Record<string, number>, value: number): string {
  for (const [name, v] of Object.entries(table)) {
    if (v === value) {
      return name;
    }
  }
  return String(value);
}
