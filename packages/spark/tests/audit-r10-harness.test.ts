import { expect, test } from "vite-plus/test";

import { h1Iteration, h2Iteration, pickIterations } from "./support/audit-r10.ts";

// Bounded port of the external round-10 disagreement harnesses H1 (h1_leaves_delete_sweep.ts)
// and H2 (h2_stored_chain_delete.ts), with the attack assertions reversed: under the fix, stored
// exit chains survive every message-level corruption the harness mutates — no balance/leaf-set
// drift, no chain disappearance, no deletion that lacks operator-endorsed evidence. The pinned
// iterations are the report's violation rounds (H1: 87 = seed 3302644519, 750 = seed
// 2256962702; H2: 1 = seed 2246822519 round 1, 5 = round 5); the rest are a seeded sample of the
// same iteration space.

test("H1: no message-level mutation on any single party inflates balances or loses stored chains", async () => {
  const violations: string[] = [];
  for (const iteration of pickIterations(0x51_50, 2000, 120, [87, 750])) {
    // oxlint-disable-next-line no-await-in-loop -- iterations are sequential by design
    violations.push(...(await h1Iteration(iteration)));
  }
  expect(violations).toStrictEqual([]);
}, 300_000);

test("H2: a coordinator that rewrites commit responses cannot make unrelated chains disappear", async () => {
  const violations: string[] = [];
  for (const iteration of pickIterations(0x48_47, 4000, 80, [1, 5])) {
    // oxlint-disable-next-line no-await-in-loop -- iterations are sequential by design
    violations.push(...(await h2Iteration(iteration)));
  }
  expect(violations).toStrictEqual([]);
}, 300_000);
