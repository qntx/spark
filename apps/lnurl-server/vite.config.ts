import path from "node:path";

import { defineConfig } from "vite-plus";
import type { UserConfig } from "vite-plus";

const config: UserConfig = defineConfig({
  test: {
    // Development resolution for the workspace siblings: tests drive the
    // library sources directly without a prior pack build.
    alias: [
      {
        find: /^@qntx\/spark\/server$/,
        replacement: path.resolve("../../packages/spark/src/server/index.ts"),
      },
      {
        find: /^@qntx\/spark\/signer$/,
        replacement: path.resolve("../../packages/spark/src/signer/index.ts"),
      },
      {
        find: /^@qntx\/spark\/lnurl$/,
        replacement: path.resolve("../../packages/spark/src/lnurl/index.ts"),
      },
      {
        find: /^@qntx\/spark\/crypto$/,
        replacement: path.resolve("../../packages/spark/src/crypto/index.ts"),
      },
      {
        find: /^@qntx\/spark$/,
        replacement: path.resolve("../../packages/spark/src/index.ts"),
      },
      // No alias for @qntx/spark-wasm: tests resolve its built dist so the default loader's
      // bundled spark.wasm path resolution works exactly as in production.
    ],
    include: ["tests/**/*.test.ts"],
  },
});

export default config;
