/// <reference types="node" />
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";

type JsonObject = Record<string, unknown>;

const IMPLEMENTATIONS = new Set(["rust", "wasm", "native", "native-host", "ts"]);

function isRecord(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): JsonObject {
  return isRecord(value) ? value : {};
}

function asStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/**
 * Validates parity.json against the vectors/ tree and the referenced source files. Returns error
 * messages; an empty array means the file is consistent.
 *
 * Every capability lists the files behind each implementation target (`rust`, `wasm`, `native`,
 * `native-host`, `ts`) as `{ module, tests }` plus the shared `vectors/` files it consumes.
 * Referenced paths must exist and every vector file (except README.md) must be claimed by some
 * capability.
 */
export function checkParity(
  parity: unknown,
  vectorFiles: string[],
  fileExists: (path: string) => boolean,
): string[] {
  const errors: string[] = [];
  const { capabilities } = asRecord(parity);
  if (!Array.isArray(capabilities)) {
    return ['parity.json: missing "capabilities" array'];
  }

  const seen = new Set<string>();
  const referencedVectors = new Set<string>();

  for (const item of capabilities) {
    const cap = asRecord(item);
    const { id: rawId } = cap;
    const id = typeof rawId === "string" ? rawId : "?";
    const label = `capability "${id}"`;

    if (typeof rawId !== "string" || rawId === "") {
      errors.push("capability without a string id");
    } else if (seen.has(id)) {
      errors.push(`${label}: duplicate id`);
    }
    seen.add(id);

    const implementations = asRecord(cap["implementations"]);
    if (Object.keys(implementations).length === 0) {
      errors.push(`${label}: missing "implementations"`);
    }
    for (const [target, impl] of Object.entries(implementations)) {
      if (!IMPLEMENTATIONS.has(target)) {
        errors.push(`${label}: unknown implementation target "${target}"`);
        continue;
      }
      const record = asRecord(impl);
      const paths = [
        ...(typeof record["module"] === "string" ? [record["module"]] : []),
        ...asStrings(record["tests"]),
      ];
      for (const path of paths) {
        if (!fileExists(path)) {
          errors.push(`${label}: ${target} path does not exist: ${path}`);
        }
      }
    }

    for (const vector of asStrings(cap["vectors"])) {
      referencedVectors.add(vector);
      if (!fileExists(vector)) {
        errors.push(`${label}: vector file does not exist: ${vector}`);
      }
    }
  }

  for (const file of vectorFiles) {
    if (basename(file) === "README.md") {
      continue;
    }
    if (!referencedVectors.has(file)) {
      errors.push(`vector file is not referenced by any capability: ${file}`);
    }
  }

  return errors;
}

function listVectors(dir: string, prefix: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(prefix, entry.name);
    if (entry.isDirectory()) {
      out.push(...listVectors(join(dir, entry.name), path));
    } else {
      out.push(path);
    }
  }
  return out.toSorted();
}

if (import.meta.main) {
  const parity: unknown = JSON.parse(readFileSync("parity.json", "utf8"));
  const vectorFiles = existsSync("vectors") ? listVectors("vectors", "vectors") : [];
  const errors = checkParity(parity, vectorFiles, (path) => existsSync(path));
  for (const error of errors) {
    console.error(`parity: ${error}`);
  }
  if (errors.length > 0) {
    process.exitCode = 1;
  }
}
