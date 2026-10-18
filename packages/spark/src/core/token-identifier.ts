import { bech32m } from "@scure/base";

import { SparkInputError } from "../errors/index.ts";
import type { SparkNetwork } from "./network.ts";

// Upstream reference: sdks/js/packages/spark-sdk/src/utils/token-identifier.ts
// (buildonspark/spark@0b3a32a). Token identifiers are bech32m over the raw
// 32-byte identifier with a 500-character limit.

const BECH32M_LIMIT = 500;
const TOKEN_IDENTIFIER_LENGTH = 32;

const TOKEN_PREFIX: Record<SparkNetwork, string> = {
  mainnet: "btkn",
  regtest: "btknrt",
};

const PREFIX_TO_NETWORK: Record<string, SparkNetwork> = {
  btkn: "mainnet",
  btknrt: "regtest",
};

export type SparkTokenIdentifierData = {
  readonly tokenIdentifier: Uint8Array;
  readonly network: SparkNetwork;
};

/** Encodes a raw 32-byte token identifier as `btkn1…`/`btknrt1…` bech32m. */
export function encodeTokenIdentifier(tokenIdentifier: Uint8Array, network: SparkNetwork): string {
  if (tokenIdentifier.length !== TOKEN_IDENTIFIER_LENGTH) {
    throw new SparkInputError(`tokenIdentifier: must be ${TOKEN_IDENTIFIER_LENGTH} bytes`);
  }
  const prefix = TOKEN_PREFIX[network];
  if (prefix === undefined) {
    throw new SparkInputError("network: must be 'mainnet' or 'regtest'");
  }
  return bech32m.encode(prefix, bech32m.toWords(tokenIdentifier), BECH32M_LIMIT);
}

/**
 * Decodes a bech32m token identifier. Only the `btkn` (mainnet) and `btknrt` (regtest) prefixes are
 * accepted; the prefix selects the network. Throws {@link SparkInputError} on malformed input.
 */
export function decodeTokenIdentifier(text: string): SparkTokenIdentifierData {
  let decoded: { prefix: string; words: number[] };
  try {
    decoded = bech32m.decode(text, BECH32M_LIMIT);
  } catch (error) {
    throw new SparkInputError("token identifier: invalid bech32m encoding", { cause: error });
  }
  const network = PREFIX_TO_NETWORK[decoded.prefix];
  if (network === undefined) {
    throw new SparkInputError(
      "token identifier: unsupported network prefix (expected btkn or btknrt)",
    );
  }
  const tokenIdentifier = bech32m.fromWords(decoded.words);
  if (tokenIdentifier.length !== TOKEN_IDENTIFIER_LENGTH) {
    throw new SparkInputError(
      `token identifier: payload must decode to ${TOKEN_IDENTIFIER_LENGTH} bytes`,
    );
  }
  return { tokenIdentifier, network };
}
