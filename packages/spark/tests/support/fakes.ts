import { create } from "@bufbuild/protobuf";
import { createRouterTransport } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";

import { createSparkClientWith } from "../../src/client/index.ts";
import type { SparkClient } from "../../src/client/index.ts";
import {
  createCurrentTimelockRefundTxs,
  p2trScriptFromPublicKey,
} from "../../src/core/bitcoin/index.ts";
import type { SparkNetwork, SparkOperatorConfig } from "../../src/core/network.ts";
import { SparkError } from "../../src/errors/index.ts";
import { createMemorySparkStore } from "../../src/exit/store.ts";
import type { SparkStore } from "../../src/exit/store.ts";
import {
  ChallengeSchema,
  GetChallengeResponseSchema,
  ProtectedChallengeSchema,
  SparkAuthnService,
  VerifyChallengeResponseSchema,
} from "../../src/proto/gen/spark_authn_pb.ts";
import type {
  GetChallengeResponse,
  VerifyChallengeResponse,
} from "../../src/proto/gen/spark_authn_pb.ts";
import { RequestedSigningCommitmentsSchema, SparkService } from "../../src/proto/gen/spark_pb.ts";
import type { RequestedSigningCommitments } from "../../src/proto/gen/spark_pb.ts";
import { SparkTokenService } from "../../src/proto/gen/spark_token_pb.ts";
import type { SparkSigner } from "../../src/signer/index.ts";
import type { SparkLeaf } from "../../src/tree/index.ts";
import { be32 } from "./frost.ts";

export const OPERATOR_SECRETS = [
  new Uint8Array(32).fill(9),
  new Uint8Array(32).fill(8),
  new Uint8Array(32).fill(3),
];

export const OPERATORS: ReadonlyArray<SparkOperatorConfig> = OPERATOR_SECRETS.map((secret, id) => ({
  id,
  identifier: `${"0".repeat(62)}0${id + 1}`,
  address: `https://op${id}.test`,
  identityPublicKey: secp256k1.getPublicKey(secret, true),
}));

export const THRESHOLD = 2;

/** Fabricated SO keyshare; a leaf's verifying key is `share + user signing key`. */
export const SHARE_SECRET = 0x5ea5n;
export const SHARE_PUB = secp256k1.Point.BASE.multiply(SHARE_SECRET).toBytes(true);

export function verifyingKeyFor(signingPublicKey: Uint8Array): Uint8Array {
  return secp256k1.Point.fromBytes(SHARE_PUB)
    .add(secp256k1.Point.fromBytes(signingPublicKey))
    .toBytes(true);
}

/** Unwraps values a fake or the router captures — a missing capture is a test bug, not a branch. */
export function required<T>(value: T | null | undefined, name: string): T {
  if (value === null || value === undefined) {
    throw new Error(`${name} missing`);
  }
  return value;
}

export function requiredIdentifier(value: Uint8Array | undefined): Uint8Array {
  if (value === undefined) {
    throw new SparkError("create broadcast did not return a token identifier");
  }
  return value;
}

/** Deterministic byte stream for signers and uuidv7. */
export function fixedRandom(): (length: number) => Uint8Array {
  let counter = 0;
  return (length) => {
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      counter = (counter + 1) % 251;
      out[i] = counter;
    }
    return out;
  };
}

/** Deterministic byte stream of sha256(seed ‖ counter) blocks. */
export function seededRandom(seed: Uint8Array): (length: number) => Uint8Array {
  let counter = 0;
  return (length) => {
    const out = new Uint8Array(length);
    for (let offset = 0; offset < length; offset += 32) {
      const block = sha256(concatBytes(seed, be32(BigInt(counter))));
      counter += 1;
      out.set(block.subarray(0, Math.min(32, length - offset)), offset);
    }
    return out;
  };
}

/** Deterministic byte stream of sha256(`${label}-${counter}`) blocks — 32-byte windows never repeat. */
export function hashedRandom(label: string): (length: number) => Uint8Array {
  let counter = 0;
  return (length) => {
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i += 32) {
      const block = sha256(utf8ToBytes(`${label}-${counter}`));
      counter += 1;
      out.set(block.subarray(0, Math.min(32, length - i)), i);
    }
    return out;
  };
}

export function operatorCommitments(): Record<string, { hiding: Uint8Array; binding: Uint8Array }> {
  return Object.fromEntries(
    OPERATORS.map((op, i) => [
      op.identifier,
      {
        hiding: secp256k1.Point.BASE.toBytes(true),
        binding: secp256k1.Point.BASE.multiply(BigInt(i + 2)).toBytes(true),
      },
    ]),
  );
}

export function commitmentGroup(count: number): RequestedSigningCommitments[] {
  return Array.from({ length: count }, () =>
    create(RequestedSigningCommitmentsSchema, {
      signingNonceCommitments: operatorCommitments(),
    }),
  );
}

/** The authn stub every scripted transport registers: any challenge verifies to `so-tok`. */
export const authnServiceImpl = {
  get_challenge: (req: { publicKey: Uint8Array }): GetChallengeResponse =>
    create(GetChallengeResponseSchema, {
      protectedChallenge: create(ProtectedChallengeSchema, {
        challenge: create(ChallengeSchema, {
          version: 1,
          timestamp: BigInt(Math.floor(Date.now() / 1000)),
          nonce: new Uint8Array(4),
          publicKey: req.publicKey,
        }),
        serverHmac: new Uint8Array(4),
      }),
    }),
  verify_challenge: (): VerifyChallengeResponse =>
    create(VerifyChallengeResponseSchema, {
      sessionToken: "so-tok",
      expirationTimestamp: BigInt(Math.floor(Date.now() / 1000) + 600),
    }),
};

export type TestServiceImpls = {
  readonly spark?: object;
  readonly token?: object;
};

const noFetch: typeof globalThis.fetch = () => {
  throw new Error("no fetch");
};

/**
 * A regtest SparkClient whose SO transports are in-process routers: the authn stub plus the
 * scripted Spark/SparkToken impls. `operatorImpls` swaps in a different impl per operator
 * identifier; `services` registers additional services on every operator's router.
 */
export function makeTestClient(options: {
  signer: SparkSigner;
  spark?: object;
  token?: object;
  operatorImpls?: Record<string, TestServiceImpls>;
  network?: SparkNetwork;
  operators?: ReadonlyArray<SparkOperatorConfig>;
  store?: SparkStore;
  fetch?: typeof globalThis.fetch;
  random?: (length: number) => Uint8Array;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  ssp?: { baseUrl: string; graphqlPath: string; identityPublicKey: Uint8Array };
}): SparkClient {
  return createSparkClientWith(
    {
      network: options.network ?? "regtest",
      signer: options.signer,
      fetch: options.fetch ?? noFetch,
      random: options.random ?? fixedRandom(),
      operators: options.operators ?? OPERATORS,
      store: options.store ?? createMemorySparkStore(),
      ...(options.now === undefined ? {} : { now: options.now }),
      ...(options.sleep === undefined ? {} : { sleep: options.sleep }),
      ...(options.ssp === undefined ? {} : { ssp: options.ssp }),
    },
    {
      transportFactory: (interceptors, operator) =>
        createRouterTransport(
          (router) => {
            router.service(SparkAuthnService, authnServiceImpl);
            const impls = options.operatorImpls?.[operator.identifier] ?? options;
            if (impls.spark !== undefined) {
              router.service(SparkService, impls.spark);
            }
            if (impls.token !== undefined) {
              router.service(SparkTokenService, impls.token);
            }
          },
          { transport: { interceptors: [...interceptors] } },
        ),
    },
  );
}

/**
 * A leaf with parseable transactions: a synthetic node tx (one P2TR output) and the timelocked CPFP
 * refund the SO would have issued for it.
 */
export function fabricateLeaf(options: {
  leafId: string;
  signingPublicKey: Uint8Array;
  ownerIdentityPublicKey: Uint8Array;
  valueSats?: bigint;
  /** Node tx input sequence; nonzero marks a live timelock so direct refunds are built. */
  nodeSequence?: number;
  /** Refund timelock; below 200 the leaf is stale and renews before leaving the wallet. */
  refundSequence?: number;
}): { leaf: SparkLeaf; nodeTx: Uint8Array; refundTx: Uint8Array; verifyingKey: Uint8Array } {
  const verifyingKey = verifyingKeyFor(options.signingPublicKey);
  const nodeTx = new Transaction({ allowUnknownOutputs: true });
  nodeTx.addInput({
    txid: new Uint8Array(32).fill(7),
    index: 0,
    sequence: options.nodeSequence ?? 0,
  });
  nodeTx.addOutput({
    script: p2trScriptFromPublicKey(verifyingKey, "regtest"),
    amount: options.valueSats ?? 100_000n,
  });
  const nodeTxBytes = nodeTx.toBytes(true);
  const refundTx = createCurrentTimelockRefundTxs({
    nodeTx: nodeTxBytes,
    sequence: options.refundSequence ?? 2000,
    receivingPublicKey: options.signingPublicKey,
    network: "regtest",
  }).cpfpRefund.txBytes;
  return {
    leaf: {
      id: options.leafId,
      treeId: `tree-${options.leafId}`,
      valueSats: Number(options.valueSats ?? 100_000n),
      status: "AVAILABLE",
      nodeTx: nodeTxBytes,
      refundTx,
      verifyingPublicKey: verifyingKey,
      ownerIdentityPublicKey: options.ownerIdentityPublicKey,
      ownerSigningPublicKey: options.signingPublicKey,
      signingKeyshare: {
        ownerIdentifiers: OPERATORS.map((op) => op.identifier),
        threshold: THRESHOLD,
        publicKey: SHARE_PUB,
      },
      vout: 0,
    },
    nodeTx: nodeTxBytes,
    refundTx,
    verifyingKey,
  };
}

/**
 * `fabricateLeaf` keyed off the signer's own `LEAF{id}` key and identity, with an optional direct
 * (sequence-0) node tx for the direct-refund paths.
 */
export async function fabricateSignedLeaf(
  signer: SparkSigner,
  options: {
    leafId: string;
    valueSats?: bigint;
    directNodeTx?: boolean;
    nodeSequence?: number;
    refundSequence?: number;
  },
): Promise<SparkLeaf> {
  const signingPublicKeys = await signer.publicKeys([{ type: "leaf", leafId: options.leafId }]);
  const signingPublicKey = required(signingPublicKeys[0], "leaf signing key");
  const ownerIdentityPublicKey = await signer.identityPublicKey();
  const { leaf } = fabricateLeaf({
    leafId: options.leafId,
    signingPublicKey,
    ownerIdentityPublicKey,
    ...(options.valueSats === undefined ? {} : { valueSats: options.valueSats }),
    ...(options.nodeSequence === undefined ? {} : { nodeSequence: options.nodeSequence }),
    ...(options.refundSequence === undefined ? {} : { refundSequence: options.refundSequence }),
  });
  if (options.directNodeTx !== true) {
    return leaf;
  }
  const direct = new Transaction({ allowUnknownOutputs: true });
  direct.addInput({ txid: new Uint8Array(32).fill(7), index: 0, sequence: 0 });
  direct.addOutput({
    script: p2trScriptFromPublicKey(leaf.verifyingPublicKey, "regtest"),
    amount: (options.valueSats ?? 100_000n) - 330n,
  });
  return { ...leaf, directTx: direct.toBytes(true) };
}
