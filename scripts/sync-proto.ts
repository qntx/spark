/// <reference types="node" />
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

// Syncs the protocol .proto files from the upstream commit pinned in
// scripts/lock.json into proto/spark/ (the buf module rooted at the repo).
// `--check` verifies without writing and exits 1 on any drift.

const FILES = [
  "common.proto",
  "spark.proto",
  "spark_authn.proto",
  "spark_token.proto",
  "multisig.proto",
  "validate/validate.proto",
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

const lock: unknown = JSON.parse(readFileSync("scripts/lock.json", "utf8"));
const spark = isRecord(lock) && isRecord(lock["spark"]) ? lock["spark"] : {};
const { repository } = spark;
const { commit } = spark;

async function sync(repo: string, rev: string): Promise<boolean> {
  const results = await Promise.all(
    FILES.map(async (name) => {
      const url = `https://raw.githubusercontent.com/${repo}/${rev}/protos/${name}`;
      const response = await fetch(url);
      return {
        name,
        url,
        status: response.status,
        content: response.ok ? await response.text() : undefined,
      };
    }),
  );

  const checkOnly = process.argv.includes("--check");
  let failed = false;
  for (const { name, url, status, content } of results) {
    if (content === undefined) {
      console.error(`sync-proto: GET ${url} -> ${status}`);
      failed = true;
      continue;
    }
    const path = join("proto/spark", name);
    let current: string | undefined;
    try {
      current = readFileSync(path, "utf8");
    } catch {
      // missing
    }
    if (current === content) {
      console.log(`sync-proto: ${name} up to date`);
      continue;
    }
    if (checkOnly) {
      console.error(`sync-proto: ${name} differs from ${repo}@${rev.slice(0, 7)}`);
      failed = true;
      continue;
    }
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
    console.log(`sync-proto: wrote ${name} (${content.length} bytes)`);
  }
  return failed;
}

if (typeof repository !== "string" || typeof commit !== "string") {
  console.error("sync-proto: scripts/lock.json is missing spark.repository or spark.commit");
  process.exitCode = 1;
} else if (await sync(repository, commit)) {
  process.exitCode = 1;
}
