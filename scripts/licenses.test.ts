import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

const root = join(import.meta.dirname, "..");

const cases: string[][] = readdirSync(join(root, "packages"), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .flatMap((entry) => ["LICENSE", "NOTICE"].map((file) => [`packages/${entry.name}`, file]));

describe("package license files", () => {
  test.each(cases)("%s/%s is byte-identical to the root copy", (dir, file) => {
    expect(readFileSync(join(root, dir, file))).toStrictEqual(readFileSync(join(root, file)));
  });
});
