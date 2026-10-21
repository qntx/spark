// SparkStore backed by a single JSON file so a mainnet trial keeps its
// unilateral-exit chains across restarts. Single-process use: the file is the
// store's write target, not a shared database.
import {
  chmodSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";

import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import type { SparkExitChain, SparkStore } from "../../src/exit/store.ts";

function fail(message: string): never {
  throw new Error(`exit chain store: ${message}`);
}

function asHex(value: unknown, field: string): Uint8Array {
  if (typeof value !== "string" || !/^([0-9a-f]{2})+$/.test(value)) {
    fail(`${field}: expected even-length lowercase hex`);
  }
  return hexToBytes(value);
}

function asString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${field}: expected a non-empty string`);
  }
  return value;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function decodeChain(raw: unknown): SparkExitChain {
  if (!isObject(raw)) {
    fail("chain: expected an object");
  }
  if (!Array.isArray(raw["nodes"])) {
    fail("chain.nodes: expected an array");
  }
  return {
    leafId: asString(raw["leafId"], "chain.leafId"),
    nodes: raw["nodes"].map((node: unknown) => {
      if (!isObject(node)) {
        fail("chain.nodes[]: expected an object");
      }
      return {
        nodeId: asString(node["nodeId"], "chain.nodes[].nodeId"),
        nodeTx: asHex(node["nodeTx"], "chain.nodes[].nodeTx"),
        ...(node["directTx"] === undefined
          ? {}
          : { directTx: asHex(node["directTx"], "chain.nodes[].directTx") }),
      };
    }),
    refundTx: asHex(raw["refundTx"], "chain.refundTx"),
    ...(raw["directRefundTx"] === undefined
      ? {}
      : { directRefundTx: asHex(raw["directRefundTx"], "chain.directRefundTx") }),
    ...(raw["directFromCpfpRefundTx"] === undefined
      ? {}
      : {
          directFromCpfpRefundTx: asHex(
            raw["directFromCpfpRefundTx"],
            "chain.directFromCpfpRefundTx",
          ),
        }),
  };
}

/** Deep copy via the codec so callers can never alias stored bytes. */
function copyChain(chain: SparkExitChain): SparkExitChain {
  return decodeChain(encodeChain(chain));
}

function encodeChain(chain: SparkExitChain): Record<string, unknown> {
  return {
    leafId: chain.leafId,
    nodes: chain.nodes.map((node) => ({
      nodeId: node.nodeId,
      nodeTx: bytesToHex(node.nodeTx),
      ...(node.directTx === undefined ? {} : { directTx: bytesToHex(node.directTx) }),
    })),
    refundTx: bytesToHex(chain.refundTx),
    ...(chain.directRefundTx === undefined
      ? {}
      : { directRefundTx: bytesToHex(chain.directRefundTx) }),
    ...(chain.directFromCpfpRefundTx === undefined
      ? {}
      : { directFromCpfpRefundTx: bytesToHex(chain.directFromCpfpRefundTx) }),
  };
}

function readChains(path: string): Map<string, SparkExitChain> {
  const chains = new Map<string, SparkExitChain>();
  if (!existsSync(path)) {
    return chains;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    fail(`malformed JSON in ${path}`);
  }
  if (!isObject(parsed) || !Array.isArray(parsed["chains"])) {
    fail(`${path}: expected { "chains": [...] }`);
  }
  for (const raw of parsed["chains"]) {
    const chain = decodeChain(raw);
    if (chains.has(chain.leafId)) {
      fail(`${path}: duplicate leafId ${chain.leafId}`);
    }
    chains.set(chain.leafId, chain);
  }
  return chains;
}

/** Fsync an opened path (a written file or a directory) so a crash cannot lose the change. */
function fsyncPath(path: string): void {
  const fd = openSync(path, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * `SparkStore` on disk at `path` (JSON with hex-encoded transactions). Writes are atomic and
 * durable — temp file in the same directory, fsync, rename, then fsync of the directory — so a
 * crash mid-write neither truncates the chains nor loses a completed write to the page cache. File
 * mode is 0600, directory 0700. Loading is strict: a malformed file throws instead of silently
 * dropping a chain the wallet might need to exit.
 */
export function createFileSparkStore(path: string): SparkStore {
  const chains = readChains(path);
  const persist = (): void => {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    chmodSync(dirname(path), 0o700);
    const tmp = `${path}.tmp`;
    writeFileSync(
      tmp,
      `${JSON.stringify({ version: 1, chains: [...chains.values()].map(encodeChain) }, null, 2)}\n`,
      {
        mode: 0o600,
      },
    );
    fsyncPath(tmp);
    renameSync(tmp, path);
    fsyncPath(dirname(path));
    chmodSync(path, 0o600);
  };
  return {
    exitChains: async () => {
      await Promise.resolve();
      return [...chains.values()].map(copyChain);
    },
    putExitChains: async (put) => {
      for (const chain of put) {
        chains.set(chain.leafId, copyChain(chain));
      }
      persist();
      await Promise.resolve();
    },
    deleteExitChains: async (leafIds) => {
      for (const leafId of leafIds) {
        chains.delete(leafId);
      }
      persist();
      await Promise.resolve();
    },
  };
}
