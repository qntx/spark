import type { CallOptions, Client } from "@connectrpc/connect";

import { sparkNetworkProto } from "../core/network.ts";
import type { SparkNetwork } from "../core/network.ts";
import { Direction } from "../proto/gen/spark_pb.ts";
import type { SparkTokenService } from "../proto/gen/spark_token_pb.ts";
import { mapTokenOutput } from "./model.ts";
import type { SparkTokenOutput } from "./model.ts";

const PAGE_SIZE = 100;

/**
 * `query_token_outputs` — outputs owned by the identity, optionally narrowed to the given token
 * identifiers. Follows `pageResponse.nextCursor` until the last page.
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
  for (;;) {
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
    cursor = page.nextCursor;
  }
}
