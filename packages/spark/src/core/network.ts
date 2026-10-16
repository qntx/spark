import { hexToBytes } from "@noble/hashes/utils.js";

import { SparkInputError } from "../errors/index.ts";
import { Network } from "../proto/gen/spark_pb.ts";

/** Spark networks: Bitcoin mainnet, or the public regtest deployment. */
export type SparkNetwork = "mainnet" | "regtest";

/** One Spark signing operator. Values come from the upstream wallet configuration. */
export type SparkOperatorConfig = {
  readonly id: number;
  /** 64 lowercase hex characters; the FROST identifier scalar. */
  readonly identifier: string;
  readonly address: string;
  /** 33-byte compressed secp256k1 public key. */
  readonly identityPublicKey: Uint8Array;
};

export type SparkNetworkConfig = {
  readonly network: SparkNetwork;
  readonly operators: ReadonlyArray<SparkOperatorConfig>;
  readonly threshold: number;
  /** Identifier of the coordinator operator (the `…01` identifier upstream). */
  readonly coordinator: string;
  readonly ssp: {
    readonly baseUrl: string;
    /** 33-byte compressed secp256k1 public key of the SSP service. */
    readonly identityPublicKey: Uint8Array;
    /** GraphQL path appended to `baseUrl` by the SSP client (upstream schema endpoint). */
    readonly graphqlPath: string;
  };
};

const SSP_GRAPHQL_PATH = "graphql/spark/2025-03-19";

// Upstream getSigningOperators() serves the same three operators on mainnet and
// regtest (services/wallet-config.ts, buildonspark/spark@0b3a32a).
const OPERATORS: ReadonlyArray<SparkOperatorConfig> = [
  {
    id: 0,
    identifier: "0000000000000000000000000000000000000000000000000000000000000001",
    address: "https://0.spark.lightspark.com",
    identityPublicKey: hexToBytes(
      "03dfbdff4b6332c220f8fa2ba8ed496c698ceada563fa01b67d9983bfc5c95e763",
    ),
  },
  {
    id: 1,
    identifier: "0000000000000000000000000000000000000000000000000000000000000002",
    address: "https://spark-operator.breez.technology",
    identityPublicKey: hexToBytes(
      "03e625e9768651c9be268e287245cc33f96a68ce9141b0b4769205db027ee8ed77",
    ),
  },
  {
    id: 2,
    identifier: "0000000000000000000000000000000000000000000000000000000000000003",
    address: "https://2.spark.flashnet.xyz",
    identityPublicKey: hexToBytes(
      "022eda13465a59205413086130a65dc0ed1b8f8e51937043161f8be0c369b1a410",
    ),
  },
];

const COORDINATOR = "0000000000000000000000000000000000000000000000000000000000000001";

const CONFIGS: Record<SparkNetwork, SparkNetworkConfig> = {
  mainnet: {
    network: "mainnet",
    operators: OPERATORS,
    threshold: 2,
    coordinator: COORDINATOR,
    ssp: {
      baseUrl: "https://api.lightspark.com",
      identityPublicKey: hexToBytes(
        "023e33e2920326f64ea31058d44777442d97d7d5cbfcf54e3060bc1695e5261c93",
      ),
      graphqlPath: SSP_GRAPHQL_PATH,
    },
  },
  regtest: {
    network: "regtest",
    operators: OPERATORS,
    threshold: 2,
    coordinator: COORDINATOR,
    ssp: {
      baseUrl: "https://api.lightspark.com",
      identityPublicKey: hexToBytes(
        "022bf283544b16c0622daecb79422007d167eca6ce9f0c98c0c49833b1f7170bfe",
      ),
      graphqlPath: SSP_GRAPHQL_PATH,
    },
  },
};

/** Static network parameters for `network`. Throws {@link SparkInputError} on an unknown name. */
export function sparkNetworkConfig(network: SparkNetwork): SparkNetworkConfig {
  const config = CONFIGS[network];
  if (config === undefined) {
    throw new SparkInputError("network: must be 'mainnet' or 'regtest'");
  }
  return config;
}

const PROTO_NETWORK: Record<SparkNetwork, Network> = {
  mainnet: Network.MAINNET,
  regtest: Network.REGTEST,
};

/** Maps a {@link SparkNetwork} onto the protobuf `spark.Network` enum. */
export function sparkNetworkProto(network: SparkNetwork): Network {
  return PROTO_NETWORK[network];
}
