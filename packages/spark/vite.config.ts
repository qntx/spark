import path from "node:path";

import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

const config: UserConfig = defineConfig({
  test: {
    // Development resolution for the workspace siblings: signer tests drive
    // @qntx/spark-wasm sources directly against this package's crypto entry
    // without requiring a prior pack build of either package.
    alias: [
      {
        find: /^@qntx\/spark\/crypto$/,
        replacement: path.resolve("src/crypto/index.ts"),
      },
      {
        find: /^@qntx\/spark-wasm$/,
        replacement: path.resolve("../spark-wasm/src/load.ts"),
      },
    ],
    include: ["tests/**/*.test.ts"],
  },
  pack: {
    dts: {},
    // ESM-only sugar flattens to a string; keep types/import/default for pack entries.
    exports: {
      customExports(exports) {
        for (const [key, value] of Object.entries(exports)) {
          if (typeof value === "string" && value.endsWith(".mjs")) {
            exports[key] = {
              types: value.replace(/\.mjs$/, ".d.mts"),
              import: value,
              default: value,
            };
          }
        }
        return exports;
      },
    },
    entry: {
      index: "src/index.ts",
      crypto: "src/crypto/index.ts",
      signer: "src/signer/index.ts",
    },
  },
});

export default config;
