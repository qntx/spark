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

// The SparkCrypto backend packages (spark-wasm, later spark-native) may reach
// into @qntx/spark only through the crypto leaf.
const sparkCryptoOnlyImports = {
  paths: [
    {
      name: "@qntx/spark",
      message: "the backend packages may only import @qntx/spark/crypto",
    },
  ],
  patterns: [
    {
      group: ["@qntx/spark/**", "!@qntx/spark/crypto"],
      message: "the backend packages may only import @qntx/spark/crypto",
    },
  ],
};

// Node- and browser-only globals banned from library source (@types/node
// would otherwise let them typecheck silently). URL and URLSearchParams are
// added per-file-set below: React Native's URL polyfill
// (Libraries/Blob/URL.js) does not validate input and never writes
// searchParams mutations back to href, so library code must use a strict
// parser — but the wasm loaders legitimately resolve assets with a real URL.
const platformNeutralGlobals = [
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
];

const restrictedUrlGlobals = [
  {
    name: "URL",
    message:
      "React Native's URL polyfill (Libraries/Blob/URL.js) is a regex stub that does not validate and ignores searchParams mutations — parse strictly instead",
  },
  {
    name: "URLSearchParams",
    message:
      "React Native's URLSearchParams is not linked to its URL's href — parse strictly instead",
  },
];

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
      // stay byte-frozen. Generated protobuf output is never formatted.
      "**/*.toml",
      "vectors/**",
      // Nitrogen spec DSL: oxfmt canonicalizes `interface X extends
      // HybridObject` into an intersection type, which nitrogen cannot parse.
      "packages/spark-native/src/specs/**",
      "fuzz/**",
      "packages/spark/src/proto/gen/**",
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
      "packages/spark/src/proto/gen/**",
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
        // Bit manipulation is intrinsic to the cryptographic code (the u32
        // wasm ABI included).
        files: [
          "packages/spark/src/**",
          "packages/spark/tests/**",
          "packages/spark-wasm/src/abi.ts",
          "packages/spark-wasm/tests/**",
        ],
        rules: { "eslint/no-bitwise": "off" },
      },
      {
        files: ["packages/spark/tests/**"],
        rules: {
          // Signature-shape assertions live in named test helpers.
          "vitest/expect-expect": [
            "error",
            {
              assertFunctionNames: [
                "expect",
                "expectTypeOf",
                "assert",
                "assertType",
                "expectDerSignature",
              ],
            },
          ],
        },
      },
      {
        // Test helpers are test infrastructure: they get the same relaxations
        // the preset grants *.test.* files (RPC result casts, console
        // diagnostics, null in decoded JSON types).
        files: ["packages/spark/tests/support/**"],
        rules: {
          "eslint/no-console": "off",
          "eslint/no-promise-executor-return": "off",
          "typescript/no-restricted-types": "off",
          "typescript/no-unsafe-type-assertion": "off",
          "typescript/restrict-template-expressions": "off",
          "typescript/strict-void-return": "off",
        },
      },
      {
        files: ["packages/*/scripts/**", "scripts/**"],
        rules: {
          // Maintenance scripts print their results.
          "eslint/no-console": "off",
        },
      },
      {
        // Nitrogen parses `interface` + method signatures; the preset's
        // type-alias and property-signature styles would break the generated
        // glue. react-native.config.js is the RN CLI's CJS hook.
        files: [
          "packages/spark-native/src/specs/**",
          "packages/spark-native/react-native.config.js",
        ],
        rules: {
          "typescript/consistent-type-definitions": "off",
          "typescript/method-signature-style": "off",
          "unicorn/prefer-module": "off",
          "import/no-commonjs": "off",
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
            ...platformNeutralGlobals,
            ...restrictedUrlGlobals,
          ],
          "eslint/no-restricted-imports": ["error", platformNeutralImports],
        },
      },
      {
        files: ["packages/spark-wasm/src/**"],
        rules: {
          "eslint/no-restricted-imports": [
            "error",
            {
              paths: [...platformNeutralImports.paths, ...sparkCryptoOnlyImports.paths],
              patterns: [...platformNeutralImports.patterns, ...sparkCryptoOnlyImports.patterns],
            },
          ],
        },
      },
      {
        // Platform shims: the wasm loaders resolve the .wasm asset through a
        // real WHATWG URL (Node and browsers both ship one), and the Node
        // loader legitimately needs builtins (still bound to the
        // @qntx/spark/crypto boundary).
        files: ["packages/spark-wasm/src/load.ts", "packages/spark-wasm/src/load.browser.ts"],
        rules: {
          "eslint/no-restricted-globals": ["error", ...platformNeutralGlobals],
        },
      },
      {
        files: ["packages/spark-wasm/src/load.ts"],
        rules: {
          "eslint/no-restricted-imports": ["error", sparkCryptoOnlyImports],
        },
      },
    ],
  }),
  run: { cache: process.env["CI"] === undefined || process.env["CI"] === "" },
  test: {
    include: ["scripts/**/*.test.ts"],
  },
});

export default config;
