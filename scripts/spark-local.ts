#!/usr/bin/env bun
/// <reference types="node" />
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

// Local SO environment: the upstream docker-compose stack at the commit pinned in
// scripts/lock.json (three TLS operators + bitcoind + postgres). Test-only tooling; the
// packages never run against it.
//
//   bun scripts/spark-local.ts up      # verify pin, start stack, wait for SOs, export certs
//   bun scripts/spark-local.ts status  # compose ps + port probe
//   bun scripts/spark-local.ts down    # stop the stack (keeps volumes)
//   bun scripts/spark-local.ts certs   # re-export the TLS certs only
//
// SPARK_REF is required: point it at a checkout of buildonspark/spark (the script verifies it
// is at the commit pinned in scripts/lock.json before touching docker).

const REPO = resolve(import.meta.dirname, "..");
const SPARK_REF_ENV = process.env["SPARK_REF"];
if (SPARK_REF_ENV === undefined || SPARK_REF_ENV === "") {
  console.error(
    "set SPARK_REF to a checkout of buildonspark/spark at the commit in scripts/lock.json",
  );
  process.exit(1);
}
const SPARK_REF = resolve(SPARK_REF_ENV);
const COMPOSE = join(SPARK_REF, "docker-compose.yml");
// Runs bitcoind 31 for TRUC package relay (ephemeral P2A anchor outputs are
// rejected as dust by v28). See scripts/spark-local.override.yml.
const COMPOSE_OVERRIDE = join(REPO, "scripts/spark-local.override.yml");
const PROJECT = "spark-local";
const SO_PORTS = [8535, 8536, 8537] as const;
const CERT_DIR = join(tmpdir(), "spark-local-certs");
const READY_TIMEOUT_MS = 300_000;

function fail(message: string): never {
  console.error(`spark-local: ${message}`);
  process.exit(1);
}

function sh(cmd: string, args: ReadonlyArray<string>, quiet = false): string {
  const result = spawnSync(cmd, [...args], { encoding: "utf8" });
  if (result.status !== 0) {
    if (!quiet) {
      process.stderr.write(result.stderr ?? "");
    }
    fail(`${cmd} ${args.join(" ")} exited ${result.status ?? "?"}\n${result.stderr ?? ""}`);
  }
  return result.stdout ?? "";
}

function compose(...args: ReadonlyArray<string>): string {
  return sh("docker", ["compose", "-f", COMPOSE, "-f", COMPOSE_OVERRIDE, "-p", PROJECT, ...args]);
}

type Lock = { spark?: { commit?: unknown } };

function isLock(value: unknown): value is Lock {
  return typeof value === "object" && value !== null;
}

function ensureLocked(): void {
  if (!existsSync(COMPOSE)) {
    fail(`no docker-compose.yml at ${SPARK_REF} (set SPARK_REF)`);
  }
  const parsed: unknown = JSON.parse(readFileSync(join(REPO, "scripts/lock.json"), "utf8"));
  const expected = isLock(parsed) ? parsed.spark?.commit : undefined;
  if (typeof expected !== "string") {
    fail("scripts/lock.json has no spark.commit");
  }
  const actual = sh("git", ["-C", SPARK_REF, "rev-parse", "HEAD"], true).trim();
  if (actual !== expected) {
    fail(`${SPARK_REF} is at ${actual.slice(0, 12)}, locked commit is ${expected.slice(0, 12)}`);
  }
}

/** HTTPS probe: any HTTP status means the TLS gRPC-web listener is up. */
function probePort(port: number): boolean {
  const result = spawnSync(
    "curl",
    ["-ks", "-o", "/dev/null", "-w", "%{http_code}", "-m", "3", `https://localhost:${port}/`],
    { encoding: "utf8" },
  );
  const code = (result.stdout ?? "").trim();
  return result.status === 0 && code !== "000" && code !== "";
}

function waitForOperators(): void {
  const deadline = Date.now() + READY_TIMEOUT_MS;
  for (;;) {
    const ready = SO_PORTS.filter((port) => probePort(port));
    if (ready.length === SO_PORTS.length) {
      console.log(`all ${SO_PORTS.length} operators answer TLS on ${SO_PORTS.join(", ")}`);
      return;
    }
    if (Date.now() > deadline) {
      fail(`operators not ready after ${READY_TIMEOUT_MS / 1000}s (ready: ${ready.join(",")})`);
    }
    const pending = SO_PORTS.filter((port) => !ready.includes(port));
    console.log(`waiting for operators on ${pending.join(", ")}…`);
    spawnSync("sleep", ["3"]);
  }
}

function exportCerts(): void {
  const volume = `${PROJECT}_tls-certs`;
  const listing = sh(
    "docker",
    ["run", "--rm", "-v", `${volume}:/certs:ro`, "alpine:latest", "ls", "/certs"],
    true,
  ).trim();
  const files = listing.split("\n").filter((name) => name.endsWith(".crt"));
  if (files.length === 0) {
    fail(`no .crt files in volume ${volume} — is the stack up?`);
  }
  mkdirSync(CERT_DIR, { recursive: true });
  for (const name of files) {
    const pem = execFileSync(
      "docker",
      ["run", "--rm", "-i", "-v", `${volume}:/certs:ro`, "alpine:latest", "cat", `/certs/${name}`],
      { encoding: "utf8" },
    );
    writeFileSync(join(CERT_DIR, name), pem);
  }
  console.log(`certs: ${CERT_DIR} (${files.join(", ")})`);
}

function printEnv(): void {
  console.log(`operators:  https://localhost:${SO_PORTS.join(", ")} (TLS gRPC-web)`);
  console.log(`bitcoind:   http://testutil:testutilpassword@localhost:8332 (regtest)`);
  console.log(`certs:      SPARK_LOCAL_CERT_DIR=${CERT_DIR}`);
}

const [command] = process.argv.slice(2);
switch (command) {
  case "up":
    ensureLocked();
    compose("up", "-d");
    waitForOperators();
    exportCerts();
    printEnv();
    break;
  case "down":
    compose("down");
    break;
  case "status":
    process.stdout.write(compose("ps"));
    for (const port of SO_PORTS) {
      console.log(`:${port} ${probePort(port) ? "answers TLS" : "no response"}`);
    }
    printEnv();
    break;
  case "certs":
    exportCerts();
    break;
  default:
    fail("usage: spark-local.ts {up|down|status|certs}");
}
