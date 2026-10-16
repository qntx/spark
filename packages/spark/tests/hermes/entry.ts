/**
 * Bundle entry for the Hermes smoke test: bundled to a single classic script and run on the Hermes
 * V1 CLI that React Native ships. The OK line is the pass contract — Hermes exits 0 even for
 * unhandled errors, so the runner asserts the marker appears in stdout.
 */
import { main } from "./smoke.ts";

declare function print(msg: string): void;
declare function quit(code: number): void;

try {
  main();
  print("HERMES_SMOKE_OK");
} catch (error) {
  print(
    `HERMES_SMOKE_FAIL: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`,
  );
  quit(1);
}
