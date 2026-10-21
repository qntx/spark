import type { Client } from "@connectrpc/connect";

import type { SparkNetwork, SparkOperatorConfig } from "../core/network.ts";
import type { SparkService } from "../proto/gen/spark_pb.ts";
import type { SparkSigner } from "../signer/types.ts";
import type { SspClient } from "../ssp/index.ts";

/** Dependencies shared by the Lightning receive/send/status flows. */
export type LightningDeps = {
  /** Coordinator `spark` client. */
  readonly spark: Client<typeof SparkService>;
  /** One client per non-coordinator operator — committed transfers are cross-verified on all. */
  readonly operatorSparks: ReadonlyArray<Client<typeof SparkService>>;
  readonly ssp: SspClient;
  readonly sspIdentityPublicKey: Uint8Array;
  readonly signer: SparkSigner;
  readonly network: SparkNetwork;
  readonly operators: ReadonlyArray<SparkOperatorConfig>;
  readonly threshold: number;
  readonly random: (length: number) => Uint8Array;
  readonly now: () => number;
};
