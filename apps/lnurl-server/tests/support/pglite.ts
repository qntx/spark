// PGlite-backed `Sql` for tests — same surface as the production `pg.Pool` adapter.

import { PGlite } from "@electric-sql/pglite";

import type { Sql } from "../../src/store.ts";

export async function createTestSql(): Promise<{ sql: Sql; close: () => Promise<void> }> {
  const db = new PGlite();
  await db.waitReady;
  const sql: Sql = {
    // oxlint-disable-next-line typescript/no-unnecessary-type-parameters
    query: async <Row>(text: string, params?: ReadonlyArray<unknown>) => {
      const result = await db.query<Row>(text, params === undefined ? [] : [...params]);
      return { rows: result.rows };
    },
    transaction: async <T>(fn: (tx: Pick<Sql, "query">) => Promise<T>) =>
      db.transaction(async (tx) =>
        fn({
          // oxlint-disable-next-line typescript/no-unnecessary-type-parameters
          query: async <Row>(text: string, params?: ReadonlyArray<unknown>) => {
            const result = await tx.query(text, params === undefined ? [] : [...params]);
            // oxlint-disable-next-line typescript/no-unsafe-type-assertion
            return { rows: result.rows as Row[] };
          },
        }),
      ),
  };
  return {
    sql,
    close: async () => {
      await db.close();
    },
  };
}
