/// <reference types="node" />
import { readFileSync } from "node:fs";

// Pins every upstream reference to scripts/lock.json: the frost git rev in the
// root Cargo.toml workspace dependencies and the spark git rev in the
// standalone crates/interop manifest must equal the locked commits.

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function repoCommit(lock: unknown, name: string): string | undefined {
  if (!isRecord(lock)) {
    return undefined;
  }
  const section = lock[name];
  if (!isRecord(section)) {
    return undefined;
  }
  const { commit } = section;
  return typeof commit === "string" ? commit : undefined;
}

const lock: unknown = JSON.parse(readFileSync("scripts/lock.json", "utf8"));
const errors: string[] = [];

function checkRev(manifest: string, dep: string, commit: string | undefined, label: string) {
  if (typeof commit !== "string") {
    errors.push(`lock.json: missing ${label} commit`);
    return;
  }
  const pattern = new RegExp(`^${dep}\\s*=.*\\brev\\s*=\\s*"([0-9a-f]{40})"`, "m");
  const rev = pattern.exec(manifest)?.[1];
  if (rev !== commit) {
    errors.push(`${label}: ${dep} rev ${rev ?? "missing"} != lock.json ${commit}`);
  }
}

const rootManifest = readFileSync("Cargo.toml", "utf8");
const interopManifest = readFileSync("crates/interop/Cargo.toml", "utf8");

checkRev(rootManifest, "frost-core", repoCommit(lock, "frost"), "Cargo.toml");
checkRev(rootManifest, "frost-secp256k1-tr", repoCommit(lock, "frost"), "Cargo.toml");
checkRev(interopManifest, "spark-frost", repoCommit(lock, "spark"), "crates/interop/Cargo.toml");

for (const error of errors) {
  console.error(`check-lock: ${error}`);
}
if (errors.length > 0) {
  process.exitCode = 1;
} else {
  console.log("check-lock: upstream pins match scripts/lock.json");
}
