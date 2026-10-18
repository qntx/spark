import path from "node:path";

import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

const config: UserConfig = defineConfig({
  test: {
    // Development resolution for the workspace siblings without a prior pack
    // build; the fake HybridObject in tests delegates to the wasm backend's
    // sources so the shared vectors verify real output.
    alias: [
      {
        find: /^@qntx\/spark\/crypto$/,
        replacement: path.resolve("../spark/src/crypto/index.ts"),
      },
    ],
    include: ["tests/**/*.test.ts"],
  },
  pack: {
    entry: {
      index: "src/index.ts",
    },
    dts: {
      generator: "tsgo",
      // Without the dev `paths` mapping: @qntx/spark/* resolves to the built
      // package, not ../spark/src — otherwise tsgo emits stray .d.ts there.
      tsconfig: "tsconfig.pack.json",
    },
    deps: {
      neverBundle: ["@qntx/spark", "react-native", "react-native-nitro-modules"],
    },
    sourcemap: true,
  },
});

export default config;
