/// <reference types="node" />
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

// The repo does not depend on @types/bun; declare the used surface.
declare const Bun: {
  TOML: { parse: (text: string) => unknown };
};

type JsonObject = Record<string, unknown>;

// ---------------------------------------------------------------------------
// Rust crates
//
// Allowed internal dependency edges. `spark-crypto` is the leaf library crate;
// the FFI crate sits on top of it. crates/interop is a standalone project
// excluded from the root workspace and is not checked here.
// ---------------------------------------------------------------------------

const ALLOWED: Record<string, string[]> = {
  "spark-crypto": [],
  "spark-ffi": ["spark-crypto"],
};

export type CrateInfo = {
  name: string;
  publish: boolean;
  deps: string[];
};

function isRecord(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): JsonObject {
  return isRecord(value) ? value : {};
}

function depNames(section: unknown): string[] {
  const names: string[] = [];
  for (const [key, spec] of Object.entries(asRecord(section))) {
    const renamed = asRecord(spec)["package"];
    names.push(typeof renamed === "string" ? renamed : key);
  }
  return names;
}

/**
 * Builds a CrateInfo from a parsed Cargo.toml. Normal deps include `[dependencies]` plus every
 * `[target.<cfg>.dependencies]` table so a leaf crate cannot smuggle a dependency in through a
 * target section.
 */
export function crateFromManifest(manifest: unknown, fallbackName: string): CrateInfo {
  const root = asRecord(manifest);
  const pkg = asRecord(root["package"]);
  const deps = depNames(root["dependencies"]);
  for (const target of Object.values(asRecord(root["target"]))) {
    deps.push(...depNames(asRecord(target)["dependencies"]));
  }
  return {
    name: typeof pkg["name"] === "string" ? pkg["name"] : fallbackName,
    publish: pkg["publish"] !== false,
    deps,
  };
}

export function checkCrates(crates: CrateInfo[]): string[] {
  const errors: string[] = [];
  const byName = new Map<string, CrateInfo>();

  for (const crate of crates) {
    if (crate.name.startsWith("spark-") && !(crate.name in ALLOWED)) {
      errors.push(`unknown crate "${crate.name}"`);
    }
    byName.set(crate.name, crate);
  }

  for (const crate of crates) {
    const allowed = ALLOWED[crate.name] ?? [];
    for (const dep of crate.deps) {
      if (!dep.startsWith("spark-")) {
        continue;
      }
      if (!(dep in ALLOWED)) {
        errors.push(`${crate.name}: unknown internal dependency "${dep}"`);
        continue;
      }
      if (!allowed.includes(dep)) {
        errors.push(`${crate.name}: must not depend on ${dep}`);
      }
      if (crate.publish && byName.get(dep)?.publish === false) {
        errors.push(`${crate.name}: published crate must not depend on ${dep}`);
      }
    }
  }

  return errors;
}

// ---------------------------------------------------------------------------
// TypeScript layers
//
// One-directional layering in packages/spark/src (AGENTS.md). Every layer may
// import only the layers in its allow list; a layer not listed may not be
// imported at all. Layers may contain nested directories — resolution maps the
// first src-relative path segment of an import specifier to its layer.
// ---------------------------------------------------------------------------

const BASE = ["connection", "ssp", "core", "proto", "errors"] as const;

const LAYERS: Record<string, ReadonlyArray<string>> = {
  errors: [],
  proto: [],
  crypto: ["errors"],
  core: ["errors", "proto"],
  signer: ["crypto", "core", "proto", "errors"],
  connection: ["core", "proto", "errors"],
  ssp: ["core", "errors"],
  tree: [...BASE],
  transfer: ["tree", ...BASE],
  lightning: ["transfer", "tree", ...BASE],
  deposit: ["tree", ...BASE],
  exit: ["transfer", "tree", ...BASE],
  tokens: [...BASE],
  invoice: ["transfer", "tokens", ...BASE],
  lnurl: ["core", "errors"],
  client: ["tree", "transfer", "lightning", "deposit", "exit", "tokens", "invoice", ...BASE],
  server: ["client", "lnurl", "core", "errors"],
};

// Layers reachable through `import type` / `export type … from` only. The
// signer implementation (signer/local.ts) is reachable only through
// src/signer/index.ts — from outside src/signer/ it may not be imported at all.
const TYPE_ONLY: Record<string, ReadonlyArray<string>> = Object.fromEntries(
  ["tree", "transfer", "lightning", "deposit", "exit", "tokens", "invoice", "client"].map(
    (layer) => [layer, ["signer"]],
  ),
);

export type SourceFile = { path: string; source: string };

type ImportRef = { specifier: string; typeOnly: boolean; reexported: boolean };

// `import … from "x"`, `export … from "x"` (type-only when the statement opens
// with `import type`/`export type`), side-effect `import "x"`, and dynamic
// `import("x")` (always a value import).
const FROM_RE = /\b(?:import|export)\s+(type\s+)?[^'"]*?\bfrom\s*['"]([^'"]+)['"]/g;
const SIDE_EFFECT_RE = /\bimport\s+['"]([^'"]+)['"]/g;
const DYNAMIC_RE = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g;

export function importSpecifiers(source: string): ImportRef[] {
  const refs: ImportRef[] = [];
  for (const match of source.matchAll(FROM_RE)) {
    refs.push({
      specifier: match[2] ?? "",
      typeOnly: match[1] !== undefined,
      reexported: match[0].startsWith("export"),
    });
  }
  for (const match of source.matchAll(SIDE_EFFECT_RE)) {
    refs.push({ specifier: match[1] ?? "", typeOnly: false, reexported: false });
  }
  for (const match of source.matchAll(DYNAMIC_RE)) {
    refs.push({ specifier: match[1] ?? "", typeOnly: false, reexported: false });
  }
  return refs;
}

function isLocalSignerPath(srcRelative: string): boolean {
  const segments = srcRelative.split("/");
  // "signer/local", "signer/local.ts" and "signer/local/**" all resolve to the
  // same second segment.
  return segments[0] === "signer" && (segments[1] === "local" || segments[1] === "local.ts");
}

/**
 * Enforces the src/ layer graph. `srcDir` is the posix path prefix of the source root (e.g.
 * "packages/spark/src"). Returns error messages; empty means consistent.
 *
 * Rules: a layer file may import only its allow list; a type-only layer may be reached solely
 * through `import type`/`export type … from`; no layer file may import the package root
 * `src/index.ts`; `signer/local` is unreachable from outside `src/signer/` and re-exportable only
 * by `src/signer/index.ts`; the only file directly under `src/` is `index.ts`; unknown top-level
 * directories are rejected.
 */
export function checkTsLayers(files: ReadonlyArray<SourceFile>, srcDir: string): string[] {
  const errors: string[] = [];
  const prefix = `${srcDir}/`;

  for (const { path, source } of files) {
    if (!path.startsWith(prefix)) {
      continue;
    }
    const rel = path.slice(prefix.length);
    const fileSegments = rel.split("/");
    const inSigner = fileSegments[0] === "signer";
    const fileLabel = path;

    if (fileSegments.length === 1) {
      if (rel !== "index.ts") {
        errors.push(`${fileLabel}: only index.ts may live directly under src/`);
      }
      continue;
    }
    const fileLayer = fileSegments[0] ?? "";
    if (!(fileLayer in LAYERS)) {
      errors.push(`${fileLabel}: unknown top-level directory "${fileLayer}"`);
      continue;
    }

    const fileDir = fileSegments.slice(0, -1).join("/");
    for (const { specifier, typeOnly, reexported } of importSpecifiers(source)) {
      if (!specifier.startsWith(".")) {
        continue;
      }
      const resolved = normalize(`${srcDir}/${fileDir}/${specifier}`);
      if (!resolved.startsWith(`${srcDir}/`) && resolved !== srcDir) {
        continue; // import escapes src/ — not a layer concern
      }
      const target = resolved.slice(srcDir.length).replace(/^\//, "");
      const targetSeg = target.split("/")[0] ?? "";
      const atRoot = target === "" || target === "index" || target === "index.ts";

      if (isLocalSignerPath(target)) {
        if (!inSigner) {
          errors.push(
            `${fileLabel}: signer/local is reachable only through ${srcDir}/signer/index.ts`,
          );
        } else if (rel !== "signer/index.ts" && reexported) {
          errors.push(`${fileLabel}: only ${srcDir}/signer/index.ts may re-export signer/local`);
        }
        continue;
      }

      if (atRoot) {
        errors.push(`${fileLabel}: layer files must not import the package root`);
        continue;
      }
      if (targetSeg === fileLayer) {
        continue; // intra-layer
      }
      if (!(targetSeg in LAYERS)) {
        errors.push(`${fileLabel}: unknown top-level directory "${targetSeg}"`);
        continue;
      }
      if ((LAYERS[fileLayer] ?? []).includes(targetSeg)) {
        continue;
      }
      if ((TYPE_ONLY[fileLayer] ?? []).includes(targetSeg)) {
        if (!typeOnly) {
          errors.push(
            `${fileLabel}: ${targetSeg} is reachable only through import type (AGENTS.md layering)`,
          );
        }
        continue;
      }
      errors.push(`${fileLabel}: must not import layer "${targetSeg}" (AGENTS.md layering)`);
    }
  }

  return errors;
}

function normalize(path: string): string {
  const out: string[] = [];
  for (const segment of path.split("/")) {
    if (segment === "" || segment === ".") {
      continue;
    }
    if (segment === "..") {
      out.pop();
      continue;
    }
    out.push(segment);
  }
  return out.join("/");
}

// ---------------------------------------------------------------------------

if (import.meta.main) {
  const rootExclude = asRecord(
    asRecord(Bun.TOML.parse(readFileSync("Cargo.toml", "utf8")))["workspace"],
  )["exclude"];
  const excluded = new Set(
    (Array.isArray(rootExclude) ? rootExclude : [])
      .filter((v): v is string => typeof v === "string")
      .map((v) => v.replace(/^crates\//, "")),
  );
  const crates: CrateInfo[] = [];
  for (const dir of readdirSync("crates", { withFileTypes: true })) {
    if (!dir.isDirectory() || excluded.has(dir.name)) {
      continue;
    }
    const manifestPath = join("crates", dir.name, "Cargo.toml");
    let manifest: string;
    try {
      manifest = readFileSync(manifestPath, "utf8");
    } catch {
      continue;
    }
    crates.push(crateFromManifest(Bun.TOML.parse(manifest), dir.name));
  }

  const srcFiles: SourceFile[] = [];
  const srcDir = "packages/spark/src";
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(path);
      } else if (entry.name.endsWith(".ts")) {
        srcFiles.push({ path, source: readFileSync(path, "utf8") });
      }
    }
  };
  try {
    walk(srcDir);
  } catch {
    // packages/spark/src does not exist yet.
  }

  const errors = [...checkCrates(crates), ...checkTsLayers(srcFiles, srcDir)];
  for (const error of errors) {
    console.error(`check-layers: ${error}`);
  }
  if (errors.length > 0) {
    process.exitCode = 1;
  }
}
