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
  /** Token output parameters stamped on every token transaction (upstream wallet-config defaults). */
  readonly tokens: {
    readonly withdrawBondSats: number;
    readonly withdrawRelativeBlockLocktime: number;
    readonly validityDurationSeconds: number;
  };
};

const SSP_GRAPHQL_PATH = "graphql/spark/2025-03-19";

const COORDINATOR = "0000000000000000000000000000000000000000000000000000000000000001";

// Upstream getSigningOperators() serves the same three operators on mainnet and regtest
// (services/wallet-config.ts, buildonspark/spark@0b3a32a). Keys stay hex so the module never
// shares a mutable Uint8Array across callers — each sparkNetworkConfig() builds fresh arrays.
const OPERATORS: ReadonlyArray<{
  readonly id: number;
  readonly identifier: string;
  readonly address: string;
  readonly identityPublicKey: string;
}> = [
  {
    id: 0,
    identifier: "0000000000000000000000000000000000000000000000000000000000000001",
    address: "https://0.spark.lightspark.com",
    identityPublicKey: "03dfbdff4b6332c220f8fa2ba8ed496c698ceada563fa01b67d9983bfc5c95e763",
  },
  {
    id: 1,
    identifier: "0000000000000000000000000000000000000000000000000000000000000002",
    address: "https://spark-operator.breez.technology",
    identityPublicKey: "03e625e9768651c9be268e287245cc33f96a68ce9141b0b4769205db027ee8ed77",
  },
  {
    id: 2,
    identifier: "0000000000000000000000000000000000000000000000000000000000000003",
    address: "https://2.spark.flashnet.xyz",
    identityPublicKey: "022eda13465a59205413086130a65dc0ed1b8f8e51937043161f8be0c369b1a410",
  },
];

const SSP_IDENTITY_KEY: Record<SparkNetwork, string> = {
  mainnet: "023e33e2920326f64ea31058d44777442d97d7d5cbfcf54e3060bc1695e5261c93",
  regtest: "022bf283544b16c0622daecb79422007d167eca6ce9f0c98c0c49833b1f7170bfe",
};

/**
 * Static network parameters for `network`. Each call builds a fresh config — fresh `Uint8Array`
 * keys — so callers can never corrupt shared module state. Throws {@link SparkInputError} on an
 * unknown name.
 */
export function sparkNetworkConfig(network: SparkNetwork): SparkNetworkConfig {
  const sspKey = SSP_IDENTITY_KEY[network];
  if (sspKey === undefined) {
    throw new SparkInputError("network: must be 'mainnet' or 'regtest'");
  }
  return {
    network,
    operators: OPERATORS.map((operator) => ({
      id: operator.id,
      identifier: operator.identifier,
      address: operator.address,
      identityPublicKey: hexToBytes(operator.identityPublicKey),
    })),
    threshold: 2,
    coordinator: COORDINATOR,
    ssp: {
      baseUrl: "https://api.lightspark.com",
      identityPublicKey: hexToBytes(sspKey),
      graphqlPath: SSP_GRAPHQL_PATH,
    },
    // services/wallet-config.ts: expectedWithdrawBondSats,
    // expectedWithdrawRelativeBlockLocktime, tokenValidityDurationSeconds.
    tokens: {
      withdrawBondSats: 10_000,
      withdrawRelativeBlockLocktime: 1000,
      validityDurationSeconds: 180,
    },
  };
}

const PROTO_NETWORK: Record<SparkNetwork, Network> = {
  mainnet: Network.MAINNET,
  regtest: Network.REGTEST,
};

/** Maps a {@link SparkNetwork} onto the protobuf `spark.Network` enum. */
export function sparkNetworkProto(network: SparkNetwork): Network {
  return PROTO_NETWORK[network];
}

/** Maps a protobuf `spark.Network` enum value back onto {@link SparkNetwork}. */
export function sparkNetworkFromProto(network: Network): SparkNetwork {
  switch (network) {
    case Network.MAINNET:
      return "mainnet";
    case Network.REGTEST:
      return "regtest";
    default:
      throw new SparkInputError("unknown proto network");
  }
}
