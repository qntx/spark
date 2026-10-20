/// <reference types="node" />
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

// The repo does not depend on @types/bun; declare the used surface.
declare const Bun: {
  TOML: { parse: (text: string) => unknown };
};

type JsonObject = Record<string, unknown>;

function isRecord(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): JsonObject {
  return isRecord(value) ? value : {};
}

function escapeRegExp(text: string): string {
  return text.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
}

export type PackageEntry = { path: string; pkg: unknown };
export type CrateEntry = { path: string; manifest: unknown };

const CORE_PACKAGE = "@qntx/spark";

/**
 * The caret range packages must use when depending on {@link CORE_PACKAGE}: `^0.y.0` while the
 * lockstep version is 0.x, `^x.0.0` after 1.x.
 */
export function peerRange(version: string): string {
  const [major = "0", minor = "0"] = version.split(".");
  return major === "0" ? `^0.${minor}.0` : `^${major}.0.0`;
}

/**
 * Rewrite `pkg`'s {@link CORE_PACKAGE} peer range to the {@link peerRange} of `version`, in place.
 * bumpp's `execute` hook applies this to the backend packages — it only rewrites `version` fields
 * in JSON, while the peer range must track the lockstep version. Throws when the package does not
 * already declare the peer dependency.
 */
export function updatePeerRange(pkg: unknown, version: string): void {
  const peer = isRecord(pkg) ? pkg["peerDependencies"] : undefined;
  if (!isRecord(peer) || !(CORE_PACKAGE in peer)) {
    throw new Error(`missing "${CORE_PACKAGE}" peerDependency`);
  }
  peer[CORE_PACKAGE] = peerRange(version);
}

/**
 * Lockstep check: every published workspace package's `version` must equal
 * `[workspace.package].version`, every workspace crate manifest must inherit it via
 * `version.workspace`, every internal `crates/` path dependency must pin `=<version>`, and the
 * version string may appear nowhere else in Cargo.toml (bumpp rewrites every occurrence). Private
 * packages are ignored; crate directories excluded by the root workspace (e.g. crates/interop) are
 * standalone projects and take no part.
 *
 * Any package other than the core package that references it must do so through `peerDependencies`
 * with the {@link peerRange} caret of the lockstep version; it must not appear in `dependencies`.
 */
export function checkVersion(
  packages: PackageEntry[],
  cargoToml: unknown,
  cargoText: string,
  crates: CrateEntry[],
): string[] {
  const errors: string[] = [];
  const workspace = asRecord(asRecord(cargoToml)["workspace"]);
  const { version: cargoVersion } = asRecord(workspace["package"]);

  if (typeof cargoVersion !== "string") {
    errors.push("Cargo.toml: missing string [workspace.package].version");
  }

  for (const { path, pkg } of packages) {
    const manifest = asRecord(pkg);
    if (manifest["private"] === true) {
      continue;
    }
    const { version } = manifest;
    if (typeof version !== "string") {
      errors.push(`${path}: missing string "version"`);
      continue;
    }
    if (typeof cargoVersion === "string" && version !== cargoVersion) {
      errors.push(`version mismatch: ${path} has ${version}, Cargo.toml has ${cargoVersion}`);
    }

    const { name } = manifest;
    if (name === CORE_PACKAGE || typeof cargoVersion !== "string") {
      continue;
    }
    const references = ["dependencies", "peerDependencies", "devDependencies"].some(
      (section) => CORE_PACKAGE in asRecord(manifest[section]),
    );
    if (!references) {
      continue;
    }
    const expected = peerRange(cargoVersion);
    const peer = asRecord(manifest["peerDependencies"])[CORE_PACKAGE];
    if (peer !== expected) {
      errors.push(
        `${path}: ${CORE_PACKAGE} must be a peerDependency "${expected}", got ${JSON.stringify(peer)}`,
      );
    }
    if (CORE_PACKAGE in asRecord(manifest["dependencies"])) {
      errors.push(`${path}: ${CORE_PACKAGE} must not appear in "dependencies" (peer only)`);
    }
  }

  for (const { path, manifest } of crates) {
    const crate = asRecord(asRecord(manifest)["package"]);
    const { version } = crate;
    if (isRecord(version) && version["workspace"] === true) {
      continue;
    }
    errors.push(`${path}: package version must be "version.workspace = true"`);
  }

  let internalDeps = 0;
  const dependencies = asRecord(workspace["dependencies"]);
  for (const [name, spec] of Object.entries(dependencies)) {
    const entry = asRecord(spec);
    const { path } = entry;
    if (typeof path !== "string" || !path.startsWith("crates/")) {
      continue;
    }
    internalDeps += 1;
    const expected = `=${typeof cargoVersion === "string" ? cargoVersion : ""}`;
    if (entry["version"] !== expected) {
      errors.push(
        `Cargo.toml: internal dependency "${name}" must use version "${expected}", got ${JSON.stringify(entry["version"])}`,
      );
    }
  }

  if (typeof cargoVersion === "string") {
    const occurrences =
      cargoText.match(new RegExp(`\\b${escapeRegExp(cargoVersion)}\\b`, "g"))?.length ?? 0;
    const expected = 1 + internalDeps;
    if (occurrences !== expected) {
      errors.push(
        `Cargo.toml: "${cargoVersion}" appears ${occurrences} times, expected ${expected} ([workspace.package] plus internal path dependencies)`,
      );
    }
  }

  return errors;
}

if (import.meta.main) {
  const packages: PackageEntry[] = readdirSync("packages", { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => {
      const path = join("packages", entry.name, "package.json");
      return { path, pkg: JSON.parse(readFileSync(path, "utf8")) as unknown };
    });
  const cargoText = readFileSync("Cargo.toml", "utf8");
  const excludeList = asRecord(asRecord(Bun.TOML.parse(cargoText))["workspace"])["exclude"];
  const excluded = new Set(
    (Array.isArray(excludeList) ? excludeList : [])
      .filter((v): v is string => typeof v === "string")
      .map((v) => v.replace(/^crates\//, "")),
  );
  const crates: CrateEntry[] = readdirSync("crates", { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && !excluded.has(entry.name))
    .flatMap((entry) => {
      const path = join("crates", entry.name, "Cargo.toml");
      try {
        return [{ path, manifest: Bun.TOML.parse(readFileSync(path, "utf8")) }];
      } catch {
        return [];
      }
    });
  const errors = checkVersion(packages, Bun.TOML.parse(cargoText), cargoText, crates);
  for (const error of errors) {
    console.error(`check-version: ${error}`);
  }
  if (errors.length > 0) {
    process.exitCode = 1;
  }
}
