// Production `Sql` over node-postgres: a `pg.Pool` for queries; a transaction checks out one
// client, runs BEGIN/COMMIT/ROLLBACK and always releases it.

import type { Pool } from "pg";

import type { Sql } from "./store.ts";

export function createPgSql(pool: Pool): Sql {
  return {
    // oxlint-disable-next-line typescript/no-unnecessary-type-parameters
    query: async <Row>(text: string, params?: ReadonlyArray<unknown>) => {
      const result = await pool.query(text, params === undefined ? [] : [...params]);
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion
      return { rows: result.rows as Row[] };
    },
    transaction: async <T>(fn: (tx: Pick<Sql, "query">) => Promise<T>) => {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const tx: Pick<Sql, "query"> = {
          // oxlint-disable-next-line typescript/no-unnecessary-type-parameters
          query: async <Row>(text: string, params?: ReadonlyArray<unknown>) => {
            const result = await client.query(text, params === undefined ? [] : [...params]);
            // oxlint-disable-next-line typescript/no-unsafe-type-assertion
            return { rows: result.rows as Row[] };
          },
        };
        const value = await fn(tx);
        await client.query("COMMIT");
        return value;
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      } finally {
        client.release();
      }
    },
  };
}
