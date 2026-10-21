import type { CallOptions, Client } from "@connectrpc/connect";
import { equalBytes } from "@noble/curves/utils.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { sparkNetworkProto } from "../core/network.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SparkError } from "../errors/index.ts";
import { Direction } from "../proto/gen/spark_pb.ts";
import type { SparkTokenService } from "../proto/gen/spark_token_pb.ts";
import { mapTokenOutput } from "./model.ts";
import type { SparkTokenOutput } from "./model.ts";

const PAGE_SIZE = 100;
const MAX_PAGES = 1000;

/**
 * `query_token_outputs` — outputs owned by the identity, optionally narrowed to the given token
 * identifiers. Follows `pageResponse.nextCursor` until the last page; the cursor must strictly
 * advance on every continued page and the walk is bounded — endless or repeating cursors throw.
 */
export async function queryTokenOutputs(options: {
  readonly token: Client<typeof SparkTokenService>;
  readonly ownerPublicKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly tokenIdentifiers?: ReadonlyArray<Uint8Array>;
  readonly call?: CallOptions;
}): Promise<SparkTokenOutput[]> {
  const outputs: SparkTokenOutput[] = [];
  let cursor = "";
  for (let pageIndex = 0; pageIndex < MAX_PAGES; pageIndex++) {
    // oxlint-disable-next-line no-await-in-loop -- pages are sequential by definition
    const response = await options.token.query_token_outputs(
      {
        ownerPublicKeys: [options.ownerPublicKey],
        tokenIdentifiers: [...(options.tokenIdentifiers ?? [])],
        network: sparkNetworkProto(options.network),
        pageRequest: {
          pageSize: PAGE_SIZE,
          cursor,
          direction: Direction.NEXT,
        },
      },
      options.call,
    );
    for (const row of response.outputsWithPreviousTransactionData) {
      outputs.push(mapTokenOutput(row));
    }
    const page = response.pageResponse;
    if (page === undefined || !page.hasNextPage) {
      return outputs;
    }
    const { nextCursor } = page;
    if (nextCursor === "" || nextCursor === cursor) {
      throw new SparkError("query token outputs: coordinator returned a non-advancing cursor");
    }
    cursor = nextCursor;
  }
  throw new SparkError("query token outputs: coordinator did not stop returning full pages");
}

/**
 * Stable cross-operator identity of an output: its creating outpoint. `output.id` is an SO-local
 * UUID and differs across operators (upstream token_outputs.proto marks the field deprecated for
 * that reason), so it can never be part of an agreement check.
 */
function tokenOutputKey(output: SparkTokenOutput): string {
  return `${bytesToHex(output.prevTransactionHash)}:${output.prevTransactionVout}`;
}

/** Rows that agree on every spend-relevant field; `id` is SO-local and intentionally absent. */
function sameTokenOutput(a: SparkTokenOutput, b: SparkTokenOutput): boolean {
  return (
    equalBytes(a.tokenIdentifier, b.tokenIdentifier) &&
    a.amount === b.amount &&
    equalBytes(a.ownerPublicKey, b.ownerPublicKey) &&
    a.prevTransactionVout === b.prevTransactionVout &&
    equalBytes(a.prevTransactionHash, b.prevTransactionHash) &&
    a.status === b.status
  );
}

/**
 * Cross-operator `query_token_outputs`: every operator is paged independently (cursors are
 * SO-local) and an output counts only when the coordinator and every other operator serve exactly
 * one row for its outpoint and all rows agree on owner, token identifier, amount, previous
 * transaction hash/vout and status. A row only the coordinator serves, a key any operator is
 * missing or duplicates, or any field disagreement excludes the output — a coordinator that
 * inflates or rewrites balances gets nothing counted. Unmappable rows simply never endorse a key.
 * Any operator query error fails the whole query: token reads fail closed like leaf sync.
 */
export async function queryVerifiedTokenOutputs(options: {
  readonly coordinator: Client<typeof SparkTokenService>;
  readonly operators: ReadonlyArray<Client<typeof SparkTokenService>>;
  readonly ownerPublicKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly tokenIdentifiers?: ReadonlyArray<Uint8Array>;
  readonly call?: CallOptions;
}): Promise<SparkTokenOutput[]> {
  const query = async (token: Client<typeof SparkTokenService>): Promise<SparkTokenOutput[]> =>
    queryTokenOutputs({
      token,
      ownerPublicKey: options.ownerPublicKey,
      network: options.network,
      ...(options.tokenIdentifiers === undefined
        ? {}
        : { tokenIdentifiers: options.tokenIdentifiers }),
      ...(options.call === undefined ? {} : { call: options.call }),
    });
  const [coordinatorRows, ...operatorRows] = await Promise.all(
    [options.coordinator, ...options.operators].map(query),
  );
  if (coordinatorRows === undefined) {
    throw new SparkError("query token outputs: coordinator response missing");
  }

  const keyToOperatorRows = operatorRows.map((rows) => {
    const byKey = new Map<string, SparkTokenOutput[]>();
    for (const row of rows) {
      const key = tokenOutputKey(row);
      byKey.set(key, [...(byKey.get(key) ?? []), row]);
    }
    return byKey;
  });

  const endorsed: SparkTokenOutput[] = [];
  const coordinatorKeys = new Map<string, SparkTokenOutput>();
  const conflicted = new Set<string>();
  for (const row of coordinatorRows) {
    const key = tokenOutputKey(row);
    const prior = coordinatorKeys.get(key);
    if (prior !== undefined) {
      // Identical duplicates collapse (a buggy SO repeating a row); conflicting duplicates
      // quarantine the outpoint — it can never be endorsed.
      if (!sameTokenOutput(prior, row)) {
        conflicted.add(key);
      }
      continue;
    }
    coordinatorKeys.set(key, row);
  }
  for (const [key, row] of coordinatorKeys) {
    if (conflicted.has(key)) {
      continue;
    }
    const agreed = keyToOperatorRows.every((byKey) => {
      const rows = byKey.get(key);
      return (
        rows !== undefined &&
        rows.length > 0 &&
        rows.every((operatorRow) => sameTokenOutput(row, operatorRow))
      );
    });
    if (agreed) {
      endorsed.push(row);
    }
  }
  return endorsed;
}
