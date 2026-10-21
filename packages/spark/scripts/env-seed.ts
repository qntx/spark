// Shared dotenv seed loading for scripts and e2e support. Seed values are never
// logged and never appear in error messages.
import { readFileSync, statSync } from "node:fs";

import { hexToBytes } from "@noble/hashes/utils.js";

/** First `KEY=` value in a dotenv-style file; `undefined` when the file or key is absent. */
export function envFileValue(path: string, key: string): string | undefined {
  let content: string | undefined;
  try {
    content = readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
  for (const line of content.split("\n")) {
    const [name, ...rest] = line.split("=");
    if (name?.trim() === key) {
      return rest.join("=").trim();
    }
  }
  return undefined;
}

/** True when `path` exists and is readable by group or others. */
function fileIsWorldOrGroupReadable(path: string): boolean {
  try {
    // The group/other permission bits are the low two octal digits of the mode.
    return statSync(path).mode % 0o100 !== 0;
  } catch {
    return false;
  }
}

export type EnvSeedOptions = {
  /** Environment variable consulted before the file. */
  readonly envVar: string;
  /** Dotenv file consulted when the env var is unset. */
  readonly envFile: string;
  /** Refuse to read `envFile` when its mode allows group/other access. */
  readonly requirePrivateFile?: boolean;
};

/**
 * The 64-byte hex seed from `envVar` or `envFile`'s `<envVar>=` line. With `requirePrivateFile`, a
 * group/world-readable file aborts before its contents are touched.
 */
export function envSeed(options: EnvSeedOptions): Uint8Array {
  let hex = process.env[options.envVar]?.trim();
  if (hex === undefined) {
    if (options.requirePrivateFile === true && fileIsWorldOrGroupReadable(options.envFile)) {
      throw new Error(
        `${options.envFile} must not be readable by group or others — run chmod 600 on it`,
      );
    }
    hex = envFileValue(options.envFile, options.envVar);
  }
  if (hex === undefined || !/^[0-9a-f]{128}$/i.test(hex)) {
    throw new Error(
      `expected ${options.envVar} (64-byte hex) in the environment or ${options.envFile}`,
    );
  }
  return hexToBytes(hex);
}
