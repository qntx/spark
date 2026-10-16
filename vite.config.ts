import { builtinModules } from "node:module";

import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

import { fmt } from "@qntx/oxfmt";
import { config as lintPreset, merge } from "@qntx/oxlint";

// The library runs on Node, browsers, and Hermes: Node builtins must not be
// imported from src.
const platformNeutralImports = {
  paths: builtinModules.map((name) => ({
    name,
    message: "Node builtin — the library must stay platform-neutral",
  })),
  patterns: [
    {
      group: ["node:*"],
      message: "Node builtin — the library must stay platform-neutral",
    },
  ],
};

// One-directional layering inside packages/spark/src (AGENTS.md). Every layer
// may import only the layers listed here; a layer not listed may not be
// imported at all.
const LAYERS = {
  errors: [],
  proto: [],
  crypto: ["errors"],
  core: ["errors", "proto"],
  signer: ["crypto", "core", "proto", "errors"],
  connection: ["core", "proto", "errors"],
  ssp: ["core", "errors"],
  services: ["connection", "ssp", "core", "proto", "errors"],
  lnurl: ["core", "errors"],
  client: ["services", "connection", "ssp", "core", "proto", "errors"],
  server: ["client", "lnurl"],
} as const;

// Layers reachable through `import type` only. The signer implementation
// (createSparkSigner in signer/local.ts) must never reach these layers.
const TYPE_ONLY: Partial<Record<keyof typeof LAYERS, ReadonlyArray<keyof typeof LAYERS>>> = {
  services: ["signer"],
  client: ["signer"],
};

const LAYER_NAMES = Object.keys(LAYERS).filter(
  (name): name is keyof typeof LAYERS => name in LAYERS,
);

// Relative import specifiers that would reach the package-root index from a
// layer file.
const PACKAGE_ROOT = ["..", "../", "../index", "../index.ts"];

// eslint/no-restricted-imports options that forbid a layer from importing any
// layer outside its allow list or the package root. The platform-neutral
// restrictions still apply on top: oxlint replaces (not merges) a rule's
// config per override, so the layer overrides re-add them explicitly.
function layerImports(layer: keyof typeof LAYERS) {
  const allowed: ReadonlyArray<string> = LAYERS[layer];
  const typeOnly: ReadonlyArray<string> = TYPE_ONLY[layer] ?? [];
  const message =
    allowed.length > 0
      ? `${layer} may only import ${allowed.join(", ")} (AGENTS.md layering)`
      : `${layer} is the leaf layer (AGENTS.md layering)`;
  const forbidden = LAYER_NAMES.filter(
    (name) => name !== layer && !allowed.includes(name) && !typeOnly.includes(name),
  );
  return {
    paths: [],
    patterns: [
      {
        group: [...PACKAGE_ROOT, ...forbidden.flatMap((name) => [`../${name}`, `../${name}/**`])],
        message,
      },
      // The signer implementation module is reachable only through the
      // package entry — not even as a type import.
      {
        group: ["../signer/local", "../signer/local.*", "../signer/local/**"],
        message: "the signer implementation is reachable only through @qntx/spark/signer",
      },
      ...typeOnly.map((name) => ({
        group: [`../${name}`, `../${name}/**`],
        allowTypeImports: true,
        message: `${layer} may only use import type from ${name} (AGENTS.md layering)`,
      })),
    ],
  };
}

type OxlintOverride = (typeof lintPreset)["overrides"][number];

const layerOverrides: OxlintOverride[] = LAYER_NAMES.map((layer) => ({
  files: [`packages/spark/src/${layer}/**`],
  rules: {
    "eslint/no-restricted-imports": [
      "error",
      {
        paths: platformNeutralImports.paths,
        patterns: [...platformNeutralImports.patterns, ...layerImports(layer).patterns],
      },
    ],
  },
}));

const config: UserConfig = defineConfig({
  defaultPackage: {
    pack: "./packages/spark",
  },
  staged: { "*": "vp check --fix" },
  fmt: {
    ...fmt,
    ignorePatterns: [
      ...fmt.ignorePatterns,
      "target/**",
      "bun.lock",
      // TOML is owned by taplo (.taplo.toml, align_entries); shared vectors
      // stay byte-frozen.
      "**/*.toml",
      "vectors/**",
      "fuzz/**",
    ],
  },
  lint: merge(lintPreset, {
    // merge() concatenates arrays onto the preset's own ignorePatterns.
    // tests/hermes imports the packed dist/ builds, which do not exist until
    // `vp pack` runs — lint runs before build in CI.
    ignorePatterns: [
      "target/**",
      "packages/spark/.hermes-smoke*",
      "packages/spark/tests/hermes/**",
    ],
    jsPlugins: [{ name: "vite-plus", specifier: "vite-plus/oxlint-plugin" }],
    rules: {
      "vite-plus/prefer-vite-plus-imports": "error",
      // Vite idiom: CSS is imported for side effects.
      "import/no-unassigned-import": ["error", { allow: ["**/*.css"] }],
      // oxfmt canonicalizes hex digits to lowercase; this rule demands uppercase, so fmt always wins.
      "unicorn/number-literal-case": "off",
    },
    overrides: [
      {
        // Bit manipulation is intrinsic to the cryptographic code.
        files: ["packages/spark/src/**", "packages/spark/tests/**"],
        rules: { "eslint/no-bitwise": "off" },
      },
      {
        files: ["packages/spark/scripts/**", "scripts/**"],
        rules: {
          // Maintenance scripts print their results.
          "eslint/no-console": "off",
        },
      },
      {
        files: ["packages/*/src/**"],
        rules: {
          // Hermes V1 (what React Native ships) has no ES2023 immutable array
          // methods, so the library must sort/reverse copies in place.
          "unicorn/no-array-sort": "off",
          "unicorn/no-array-reverse": "off",
          // @types/node is in the program via tests and scripts, so Node-only
          // globals would typecheck silently; browser-only globals are equally
          // absent on Hermes. Both sets are banned — library code must use
          // globalThis lookups instead.
          "eslint/no-restricted-globals": [
            "error",
            { name: "Buffer", message: "Node-only global — use Uint8Array" },
            { name: "process", message: "Node-only global — not available in browsers or Hermes" },
            { name: "global", message: "Node-only global — use globalThis" },
            { name: "require", message: "CJS-only — use import" },
            { name: "module", message: "CJS-only global" },
            { name: "__dirname", message: "CJS-only global" },
            { name: "__filename", message: "CJS-only global" },
            { name: "setImmediate", message: "Node-only global — use setTimeout" },
            { name: "clearImmediate", message: "Node-only global — use clearTimeout" },
            { name: "window", message: "browser-only global — use globalThis" },
            { name: "document", message: "browser-only global — use globalThis" },
            { name: "navigator", message: "browser-only global — use globalThis" },
            { name: "location", message: "browser-only global — use globalThis" },
            { name: "localStorage", message: "browser-only global — inject a store" },
            { name: "sessionStorage", message: "browser-only global — inject a store" },
          ],
          "eslint/no-restricted-imports": ["error", platformNeutralImports],
        },
      },
      ...layerOverrides,
    ],
  }),
  run: { cache: process.env["CI"] === undefined || process.env["CI"] === "" },
  test: {
    include: ["scripts/**/*.test.ts"],
  },
});

export default config;
