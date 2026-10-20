import { create, toBinary } from "@bufbuild/protobuf";
import { Code, ConnectError, createClient, createRouterTransport } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import { createSparkClientWith } from "../src/client/index.ts";
import {
  createCurrentTimelockRefundTxs,
  createDecrementedTimelockRefundTxs,
  p2trScriptFromPublicKey,
} from "../src/core/bitcoin/index.ts";
import {
  claimPackageDigest,
  sendLeafSigningDigest,
  transferPackageDigest,
} from "../src/core/hashing/statements.ts";
import type { SparkOperatorConfig } from "../src/core/network.ts";
import { SparkInputError, SparkRequestError } from "../src/errors/index.ts";
import { createMemorySparkStore } from "../src/exit/store.ts";
import type { SparkExitChain, SparkStore } from "../src/exit/store.ts";
import { SignatureScheme, SignatureSchema } from "../src/proto/gen/common_pb.ts";
import {
  ChallengeSchema,
  ProtectedChallengeSchema,
  SparkAuthnService,
} from "../src/proto/gen/spark_authn_pb.ts";
import {
  ClaimTransferResponseSchema,
  GetSigningCommitmentsResponseSchema,
  HashVariant,
  InitiateSwapPrimaryTransferResponseSchema,
  LeafRefundTxSigningResultSchema,
  SigningResultSchema,
  SparkService,
  Network,
  QueryNodesResponseSchema,
  QueryTransfersResponseSchema,
  RequestedSigningCommitmentsSchema,
  StartTransferResponseSchema,
  SigningKeyshareSchema,
  TransferLeafSchema,
  TransferReceiverSchema,
  TransferReceiverStatus,
  TransferSchema,
  TransferStatus,
  TransferType,
  TreeNodeSchema,
  TreeNodeStatus,
} from "../src/proto/gen/spark_pb.ts";
import type {
  ClaimTransferRequest,
  GetSigningCommitmentsRequest,
  InitiateSwapPrimaryTransferRequest,
  QueryNodesRequest,
  StartTransferRequest,
  StartTransferV3Request,
  Transfer,
  TransferLeaf,
} from "../src/proto/gen/spark_pb.ts";
import { ProtectedChallengeSchema as SspProtectedChallengeSchema } from "../src/proto/gen/ssp_authn_pb.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import type { SparkSigner } from "../src/signer/index.ts";
import type { SspClient, SspSwapRequest } from "../src/ssp/index.ts";
import {
  assertCommittedTransfer,
  mapTransfer,
  sendTransfer,
  swapLeaves,
} from "../src/transfer/index.ts";
import type { SparkTransfer } from "../src/transfer/index.ts";
import type { SparkLeaf } from "../src/tree/index.ts";
import { loadWasmBackend } from "./support/backend.ts";

const OPERATOR_SECRETS = [
  new Uint8Array(32).fill(9),
  new Uint8Array(32).fill(8),
  new Uint8Array(32).fill(3),
];
const OPERATORS: ReadonlyArray<SparkOperatorConfig> = OPERATOR_SECRETS.map((secret, id) => ({
  id,
  identifier: `${"0".repeat(62)}0${id + 1}`,
  address: `https://op${id}.test`,
  identityPublicKey: secp256k1.getPublicKey(secret, true),
}));
const THRESHOLD = 2;
const LEAF_ID = "01989abc-def0-7abc-89ab-cdef01234567";
const TRANSFER_ID = "01989abc-def0-7000-8000-abcdef012345";

/** Unwraps values the router captures — a missing capture is a test bug, not a branch. */
function required<T>(value: T | undefined, name: string): T {
  if (value === undefined) {
    throw new Error(`${name} was not captured`);
  }
  return value;
}

/** Deterministic byte stream for the signer and uuidv7. */
function fixedRandom(): (length: number) => Uint8Array {
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

async function testSigner(): Promise<SparkSigner> {
  return createSparkSigner({
    crypto: await loadWasmBackend(),
    accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
    network: "regtest",
    random: fixedRandom(),
  });
}

const RECEIVER_SECRET = new Uint8Array(32).fill(77);
const SENDER_SECRET = new Uint8Array(32).fill(55);

/** Fabricated SO keyshare; the leaf verifying key is `share + user signing key`. */
const SHARE_SECRET = 0x5ea5n;
const SHARE_PUB = secp256k1.Point.BASE.multiply(SHARE_SECRET).toBytes(true);
function verifyingKeyFor(signingPublicKey: Uint8Array): Uint8Array {
  return secp256k1.Point.fromBytes(SHARE_PUB)
    .add(secp256k1.Point.fromBytes(signingPublicKey))
    .toBytes(true);
}

/**
 * A leaf with parseable transactions: a synthetic node tx (sequence-0 input, one P2TR output) and
 * the initial-timelock CPFP refund (sequence 2000) the SO would have issued for it.
 */
function fabricateLeaf(options: {
  leafId: string;
  signingPublicKey: Uint8Array;
  ownerIdentityPublicKey: Uint8Array;
  valueSats?: bigint;
}): { leaf: SparkLeaf; nodeTx: Uint8Array; refundTx: Uint8Array; verifyingKey: Uint8Array } {
  const verifyingKey = verifyingKeyFor(options.signingPublicKey);
  const nodeTx = new Transaction({ allowUnknownOutputs: true });
  nodeTx.addInput({ txid: new Uint8Array(32).fill(7), index: 0, sequence: 0 });
  nodeTx.addOutput({
    script: p2trScriptFromPublicKey(verifyingKey, "regtest"),
    amount: options.valueSats ?? 100_000n,
  });
  const nodeTxBytes = nodeTx.toBytes(true);
  const refundTx = createCurrentTimelockRefundTxs({
    nodeTx: nodeTxBytes,
    sequence: 2000,
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

function operatorCommitments(): Record<string, { hiding: Uint8Array; binding: Uint8Array }> {
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

function commitmentGroup(count: number) {
  return Array.from({ length: count }, () =>
    create(RequestedSigningCommitmentsSchema, {
      signingNonceCommitments: operatorCommitments(),
    }),
  );
}

type SparkImpl = Partial<{
  query_nodes: (req: unknown) => unknown;
  query_pending_transfers: (req: unknown) => unknown;
  get_signing_commitments: (req: GetSigningCommitmentsRequest) => unknown;
  start_transfer_v2: (req: StartTransferRequest) => unknown;
  start_transfer_v3: (req: StartTransferV3Request) => unknown;
  claim_transfer: (req: ClaimTransferRequest) => unknown;
  query_transfers_by_id: (req: unknown) => unknown;
  initiate_swap_primary_transfer: (req: InitiateSwapPrimaryTransferRequest) => unknown;
}>;

function makeClient(
  signer: SparkSigner,
  sparkImpl: SparkImpl,
  store?: SparkStore,
  sspFetch?: typeof globalThis.fetch,
  sspIdentity?: Uint8Array,
) {
  return createSparkClientWith(
    {
      network: "regtest",
      signer,
      fetch: sspFetch ?? (async () => Promise.reject(new Error("no fetch"))),
      random: fixedRandom(),
      operators: OPERATORS,
      ...(store === undefined ? {} : { store }),
      ...(sspIdentity === undefined
        ? {}
        : {
            ssp: {
              baseUrl: "https://ssp.test",
              graphqlPath: "graphql",
              identityPublicKey: sspIdentity,
            },
          }),
    },
    {
      transportFactory: (interceptors) =>
        createRouterTransport(
          (router) => {
            router.service(SparkAuthnService, {
              get_challenge: (req) => ({
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
              verify_challenge: () => ({
                sessionToken: "so-tok",
                expirationTimestamp: BigInt(Math.floor(Date.now() / 1000) + 600),
              }),
            });
            router.service(SparkService, sparkImpl as never);
          },
          { transport: { interceptors: [...interceptors] } },
        ),
    },
  );
}

/**
 * The leaf a real `claim_transfer` response carries: same node id, but finalized under the
 * receiver's `LEAF{leafId}` signing key with the operators' share keyshare.
 */
async function claimedLeaf(signer: SparkSigner, leaf: TransferLeaf): Promise<TransferLeaf> {
  const inner = required(leaf.leaf, "leaf");
  const [newKey] = await signer.publicKeys([{ type: "leaf", leafId: inner.id }]);
  if (newKey === undefined) {
    throw new Error("signer returned no leaf key");
  }
  return create(TransferLeafSchema, {
    ...leaf,
    leaf: create(TreeNodeSchema, {
      ...inner,
      verifyingPublicKey: verifyingKeyFor(newKey),
      ownerSigningPublicKey: newKey,
      signingKeyshare: create(SigningKeyshareSchema, {
        ownerIdentifiers: OPERATORS.map((op) => op.identifier),
        threshold: THRESHOLD,
        publicKey: SHARE_PUB,
        publicShares: {},
      }),
    }),
  });
}

async function claimedLeaves(
  signer: SparkSigner,
  leaves: ReadonlyArray<TransferLeaf>,
): Promise<TransferLeaf[]> {
  return Promise.all(leaves.map(async (leaf) => claimedLeaf(signer, leaf)));
}

function nodesResponse(nodes: Array<ReturnType<typeof create<typeof TreeNodeSchema>>>) {
  return create(QueryNodesResponseSchema, {
    nodes: Object.fromEntries(nodes.map((node) => [node.id, node])),
    offset: 0n,
  });
}

/** `query_transfers_by_id` answering with the queued responses in order, then empty. */
function byIdQueue(responses: ReadonlyArray<ReadonlyArray<Transfer>>) {
  const queue = responses.map((transfers) =>
    create(QueryTransfersResponseSchema, { transfers: [...transfers] }),
  );
  return () => queue.shift() ?? create(QueryTransfersResponseSchema);
}

describe("transfers.send", () => {
  test("sends a leaf with a V2 transfer package and three signed jobs", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const { leaf } = fabricateLeaf({
      leafId: LEAF_ID,
      signingPublicKey: required(leafKey, "leaf public key"),
      ownerIdentityPublicKey: identity,
    });
    const node = create(TreeNodeSchema, {
      id: leaf.id,
      treeId: leaf.treeId,
      value: 100_000n,
      nodeTx: leaf.nodeTx,
      refundTx: leaf.refundTx,
      vout: 0,
      verifyingPublicKey: leaf.verifyingPublicKey,
      ownerIdentityPublicKey: identity,
      ownerSigningPublicKey: leaf.ownerSigningPublicKey,
      signingKeyshare: {
        ownerIdentifiers: OPERATORS.map((op) => op.identifier),
        threshold: THRESHOLD,
        publicKey: leaf.signingKeyshare.publicKey,
        publicShares: {},
      },
      status: "AVAILABLE",
      network: Network.REGTEST,
      treenodeStatus: TreeNodeStatus.AVAILABLE,
    });

    const receiverIdentity = secp256k1.getPublicKey(RECEIVER_SECRET, true);
    let commitmentsReq: GetSigningCommitmentsRequest | undefined;
    let startReq: StartTransferRequest | undefined;
    const client = makeClient(signer, {
      query_nodes: () => nodesResponse([node]),
      get_signing_commitments: (req) => {
        commitmentsReq = req;
        return create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3),
        });
      },
      start_transfer_v2: (req) => {
        startReq = req;
        return create(StartTransferResponseSchema, {
          transfer: create(TransferSchema, {
            id: req.transferId,
            senderIdentityPublicKey: req.ownerIdentityPublicKey,
            receiverIdentityPublicKey: req.receiverIdentityPublicKey,
            status: TransferStatus.SENDER_INITIATED,
            type: TransferType.TRANSFER,
            network: Network.REGTEST,
            totalValue: 100_000n,
          }),
        });
      },
    });

    const transfer = await client.transfers.send({
      receiver: receiverIdentity,
      amountSats: 100_000,
    });
    const start = required(startReq, "start_transfer_v2 request");
    expect(transfer.id).toBe(start.transferId);

    const commitments = required(commitmentsReq, "get_signing_commitments request");
    expect(commitments.nodeIds).toStrictEqual([LEAF_ID]);
    expect(commitments.count).toBe(3);

    expect(start.ownerIdentityPublicKey).toStrictEqual(identity);
    expect(start.receiverIdentityPublicKey).toStrictEqual(receiverIdentity);
    const pkg = required(start.transferPackage, "transfer package");
    expect(pkg.hashVariant).toBe(HashVariant.V2);
    expect(Object.keys(pkg.keyTweakPackage).toSorted()).toStrictEqual(
      OPERATORS.map((op) => op.identifier).toSorted(),
    );
    for (const ciphertext of Object.values(pkg.keyTweakPackage)) {
      expect(ciphertext.length).toBeGreaterThan(0);
    }
    expect(pkg.directLeavesToSend).toHaveLength(0);
    expect(pkg.directFromCpfpLeavesToSend).toHaveLength(1);

    const expected = createDecrementedTimelockRefundTxs({
      nodeTx: leaf.nodeTx,
      sequence: 2000,
      receivingPublicKey: receiverIdentity,
      network: "regtest",
    });
    const cpfpJob = required(pkg.leavesToSend[0], "cpfp signing job");
    const directFromCpfpJob = required(
      pkg.directFromCpfpLeavesToSend[0],
      "direct-from-cpfp signing job",
    );
    expect(cpfpJob.leafId).toBe(LEAF_ID);
    expect(bytesToHex(cpfpJob.rawTx)).toBe(bytesToHex(expected.cpfpRefund.txBytes));
    expect(bytesToHex(directFromCpfpJob.rawTx)).toBe(
      bytesToHex(expected.directFromCpfpRefund.txBytes),
    );
    for (const job of [cpfpJob, directFromCpfpJob]) {
      expect(bytesToHex(job.signingPublicKey)).toBe(bytesToHex(leafKey!));
      expect(job.userSignature).toHaveLength(32);
      expect(required(job.signingNonceCommitment, "nonce commitment").hiding).toHaveLength(33);
      const map = required(job.signingCommitments, "signing commitments");
      expect(Object.keys(map.signingCommitments).toSorted()).toStrictEqual(
        OPERATORS.map((op) => op.identifier).toSorted(),
      );
    }

    // userSignature is a DER identity signature over the V2 package digest.
    const digest = transferPackageDigest(start.transferId, pkg);
    expect(
      secp256k1.verify(pkg.userSignature, digest, identity, { format: "der", prehash: false }),
    ).toBe(true);
    signer.dispose();
  });

  test("rejects amounts above the available balance", async () => {
    const signer = await testSigner();
    const client = makeClient(signer, {
      query_nodes: () => nodesResponse([]),
    });
    await expect(
      client.transfers.send({
        receiver: secp256k1.getPublicKey(RECEIVER_SECRET, true),
        amountSats: 50_000,
      }),
    ).rejects.toThrow("insufficient");
    signer.dispose();
  });

  test("rejects when the coordinator returns too few signing commitments", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const { leaf } = fabricateLeaf({
      leafId: LEAF_ID,
      signingPublicKey: required(leafKey, "leaf public key"),
      ownerIdentityPublicKey: identity,
    });
    const node = create(TreeNodeSchema, {
      id: leaf.id,
      treeId: leaf.treeId,
      value: 100_000n,
      nodeTx: leaf.nodeTx,
      refundTx: leaf.refundTx,
      vout: 0,
      verifyingPublicKey: leaf.verifyingPublicKey,
      ownerIdentityPublicKey: identity,
      ownerSigningPublicKey: leaf.ownerSigningPublicKey,
      signingKeyshare: {
        ownerIdentifiers: OPERATORS.map((op) => op.identifier),
        threshold: THRESHOLD,
        publicKey: leaf.signingKeyshare.publicKey,
        publicShares: {},
      },
      status: "AVAILABLE",
      network: Network.REGTEST,
      treenodeStatus: TreeNodeStatus.AVAILABLE,
    });
    const client = makeClient(signer, {
      query_nodes: () => nodesResponse([node]),
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(2),
        }),
    });
    await expect(
      client.transfers.send({
        receiver: secp256k1.getPublicKey(RECEIVER_SECRET, true),
        amountSats: 100_000,
      }),
    ).rejects.toThrow("expected 3 signing commitments, got 2");
    signer.dispose();
  });

  test("rejects when the signer returns too few commitments or shares", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const { leaf } = fabricateLeaf({
      leafId: LEAF_ID,
      signingPublicKey: required(leafKey, "leaf public key"),
      ownerIdentityPublicKey: identity,
    });
    const node = create(TreeNodeSchema, {
      id: leaf.id,
      treeId: leaf.treeId,
      value: 100_000n,
      nodeTx: leaf.nodeTx,
      refundTx: leaf.refundTx,
      vout: 0,
      verifyingPublicKey: leaf.verifyingPublicKey,
      ownerIdentityPublicKey: identity,
      ownerSigningPublicKey: leaf.ownerSigningPublicKey,
      signingKeyshare: {
        ownerIdentifiers: OPERATORS.map((op) => op.identifier),
        threshold: THRESHOLD,
        publicKey: leaf.signingKeyshare.publicKey,
        publicShares: {},
      },
      status: "AVAILABLE",
      network: Network.REGTEST,
      treenodeStatus: TreeNodeStatus.AVAILABLE,
    });
    const sparkImpl: SparkImpl = {
      query_nodes: () => nodesResponse([node]),
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3),
        }),
    };
    const receiver = secp256k1.getPublicKey(RECEIVER_SECRET, true);

    const shortCommitments = makeClient(
      { ...signer, newCommitments: async () => Promise.resolve([]) },
      sparkImpl,
    );
    await expect(
      shortCommitments.transfers.send({ receiver, amountSats: 100_000 }),
    ).rejects.toThrow("signer returned fewer commitments than requested");

    const shortShares = makeClient(
      { ...signer, signFrost: async () => Promise.resolve([]) },
      sparkImpl,
    );
    await expect(shortShares.transfers.send({ receiver, amountSats: 100_000 })).rejects.toThrow(
      "signer returned fewer shares than requested",
    );
    signer.dispose();
  });
});

const OTHER_LEAF_ID = "01989abc-def0-7abc-89ab-0000000000ff";
const OTHER_IDENTITY_SECRET = new Uint8Array(32).fill(66);

describe("transfers.claim", () => {
  /** A pending transfer leaf whose `secretCipher` seals `receivedSecret` to `receiverIdentity`. */
  async function pendingLeaf(options: {
    receiverIdentity: Uint8Array;
    receivedSecret: Uint8Array;
    leafId?: string;
    leafOwnerKey?: Uint8Array;
    corruptSig?: boolean;
    typedSig?: boolean;
    legacySignature?: "der" | "malformed";
    transferReceiverId?: string;
  }) {
    const leafId = options.leafId ?? LEAF_ID;
    const receivedPublicKey = secp256k1.getPublicKey(options.receivedSecret, true);
    const crypto = await loadWasmBackend();
    const secretCipher = crypto.eciesEncrypt(
      options.receiverIdentity,
      options.receivedSecret,
      new Uint8Array(32).fill(6),
    );
    const ownerKey = options.leafOwnerKey ?? receivedPublicKey;
    const { nodeTx, verifyingKey } = fabricateLeaf({
      leafId,
      signingPublicKey: ownerKey,
      ownerIdentityPublicKey: options.receiverIdentity,
    });
    // Intermediate refund at the decremented sequence (1900) — the leaf's state after send.
    const intermediateRefundTx = createCurrentTimelockRefundTxs({
      nodeTx,
      sequence: 1900,
      receivingPublicKey: receivedPublicKey,
      network: "regtest",
    }).cpfpRefund.txBytes;
    const digest = sendLeafSigningDigest(leafId, TRANSFER_ID, secretCipher);
    const signature = secp256k1.sign(
      options.corruptSig === true ? sha256(digest) : digest,
      SENDER_SECRET,
      { prehash: false, lowS: true },
    );
    const legacyValue =
      options.legacySignature === "der"
        ? secp256k1.Signature.fromBytes(signature, "compact").toBytes("der")
        : options.legacySignature === "malformed"
          ? new Uint8Array(70).fill(0xab)
          : signature;
    const sig =
      options.typedSig === true
        ? {
            case: "typedSignature" as const,
            value: create(SignatureSchema, {
              scheme: SignatureScheme.ECDSA,
              signature: secp256k1.Signature.fromBytes(signature, "compact").toBytes("der"),
            }),
          }
        : { case: "signature" as const, value: legacyValue };
    return create(TransferLeafSchema, {
      leaf: create(TreeNodeSchema, {
        id: leafId,
        treeId: `tree-${leafId}`,
        value: 100_000n,
        nodeTx,
        refundTx: intermediateRefundTx,
        vout: 0,
        verifyingPublicKey: verifyingKey,
        ownerIdentityPublicKey: options.receiverIdentity,
        ownerSigningPublicKey: ownerKey,
        signingKeyshare: {
          ownerIdentifiers: OPERATORS.map((op) => op.identifier),
          threshold: THRESHOLD,
          publicKey: SHARE_PUB,
          publicShares: {},
        },
        status: "AVAILABLE",
        network: Network.REGTEST,
        treenodeStatus: TreeNodeStatus.AVAILABLE,
      }),
      secretCipher,
      sig,
      intermediateRefundTx,
      ...(options.transferReceiverId === undefined
        ? {}
        : { transferReceiverId: options.transferReceiverId }),
    });
  }

  /** A pending transfer (single-receiver V2 by default) addressed to the receiver signer. */
  async function pendingTransfer(options: {
    receiverSigner: SparkSigner;
    receivedSecret: Uint8Array;
    leafOwnerKey?: Uint8Array;
    corruptSig?: boolean;
    typedSig?: boolean;
    legacySignature?: "der" | "malformed";
    status?: TransferStatus;
    receiverIdentityPublicKey?: Uint8Array;
    receivers?: ReadonlyArray<{ id: string; identityPublicKey: Uint8Array }>;
    extraLeaves?: ReadonlyArray<TransferLeaf>;
    transferReceiverId?: string;
  }) {
    const receiverIdentity = await options.receiverSigner.identityPublicKey();
    const leaf = await pendingLeaf({
      receiverIdentity,
      receivedSecret: options.receivedSecret,
      ...(options.leafOwnerKey === undefined ? {} : { leafOwnerKey: options.leafOwnerKey }),
      ...(options.corruptSig === undefined ? {} : { corruptSig: options.corruptSig }),
      ...(options.typedSig === undefined ? {} : { typedSig: options.typedSig }),
      ...(options.legacySignature === undefined
        ? {}
        : { legacySignature: options.legacySignature }),
      ...(options.transferReceiverId === undefined
        ? {}
        : { transferReceiverId: options.transferReceiverId }),
    });
    return create(TransferSchema, {
      id: TRANSFER_ID,
      senderIdentityPublicKey: secp256k1.getPublicKey(SENDER_SECRET, true),
      receiverIdentityPublicKey: options.receiverIdentityPublicKey ?? receiverIdentity,
      status: options.status ?? TransferStatus.SENDER_KEY_TWEAKED,
      type: TransferType.TRANSFER,
      network: Network.REGTEST,
      totalValue: 100_000n,
      leaves: [leaf, ...(options.extraLeaves ?? [])],
      receivers: (options.receivers ?? []).map((receiver) =>
        create(TransferReceiverSchema, {
          id: receiver.id,
          identityPublicKey: receiver.identityPublicKey,
          status: TransferReceiverStatus.KEY_TWEAKED,
        }),
      ),
    });
  }

  test("claims with a V2 claim package at the current timelock", async () => {
    const receiver = await testSigner();
    const receivedSecret = new Uint8Array(32).fill(88);
    const pending = await pendingTransfer({ receiverSigner: receiver, receivedSecret });
    const [newLeafKey] = await receiver.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);

    let commitmentsReq: GetSigningCommitmentsRequest | undefined;
    let claimReq: ClaimTransferRequest | undefined;
    const client = makeClient(receiver, {
      query_pending_transfers: () => create(QueryTransfersResponseSchema, { transfers: [pending] }),
      get_signing_commitments: (req) => {
        commitmentsReq = req;
        return create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3),
        });
      },
      claim_transfer: async (req) => {
        claimReq = req;
        return create(ClaimTransferResponseSchema, {
          transfer: create(TransferSchema, {
            id: req.transferId,
            status: TransferStatus.COMPLETED,
            type: TransferType.TRANSFER,
            network: Network.REGTEST,
            leaves: await claimedLeaves(receiver, [required(pending.leaves[0], "pending leaf")]),
          }),
        });
      },
    });

    const claimed = await client.transfers.claimPending();
    expect(claimed).toHaveLength(1);
    expect(claimed[0]?.id).toBe(LEAF_ID);

    const commitments = required(commitmentsReq, "get_signing_commitments request");
    expect(commitments.nodeIdCount).toBe(1);
    expect(commitments.count).toBe(3);

    const claim = required(claimReq, "claim_transfer request");
    expect(claim.transferId).toBe(TRANSFER_ID);
    const pkg = required(claim.claimPackage, "claim package");
    expect(pkg.hashVariant).toBe(HashVariant.V2);
    expect(Object.keys(pkg.keyTweakPackage).toSorted()).toStrictEqual(
      OPERATORS.map((op) => op.identifier).toSorted(),
    );
    expect(pkg.directLeavesToClaim).toHaveLength(0);
    expect(pkg.directFromCpfpLeavesToClaim).toHaveLength(1);

    // Current timelock: the intermediate refund's 1900 sequence is preserved, not decremented.
    const leafProto = required(pending.leaves[0], "transfer leaf").leaf;
    const expected = createCurrentTimelockRefundTxs({
      nodeTx: required(leafProto, "leaf").nodeTx,
      sequence: 1900,
      receivingPublicKey: required(newLeafKey, "new leaf key"),
      network: "regtest",
    });
    const claimJob = required(pkg.leavesToClaim[0], "claim signing job");
    expect(claimJob.leafId).toBe(LEAF_ID);
    expect(bytesToHex(claimJob.rawTx)).toBe(bytesToHex(expected.cpfpRefund.txBytes));
    expect(bytesToHex(claimJob.signingPublicKey)).toBe(bytesToHex(newLeafKey!));

    const claimDigest = claimPackageDigest(claim.transferId, pkg.keyTweakPackage);
    const receiverIdentity = await receiver.identityPublicKey();
    expect(
      secp256k1.verify(pkg.userSignature, claimDigest, receiverIdentity, {
        format: "der",
        prehash: false,
      }),
    ).toBe(true);
    receiver.dispose();
  });

  test("rejects a transfer whose sender signature is invalid", async () => {
    const receiver = await testSigner();
    const pending = await pendingTransfer({
      receiverSigner: receiver,
      receivedSecret: new Uint8Array(32).fill(88),
      corruptSig: true,
    });
    const client = makeClient(receiver, {});
    await expect(client.transfers.claim(mapTransfer(pending))).rejects.toThrow(
      "sender signature verification failed",
    );
    receiver.dispose();
  });

  test("rejects a leaf whose cipher does not decrypt to the leaf signing key", async () => {
    const receiver = await testSigner();
    const pending = await pendingTransfer({
      receiverSigner: receiver,
      receivedSecret: new Uint8Array(32).fill(88),
      leafOwnerKey: secp256k1.getPublicKey(new Uint8Array(32).fill(99), true),
    });
    const client = makeClient(receiver, {});
    await expect(client.transfers.claim(mapTransfer(pending))).rejects.toThrow(
      "secret_cipher does not decrypt",
    );
    receiver.dispose();
  });

  test("accepts a scheme-tagged ECDSA sender signature", async () => {
    const receiver = await testSigner();
    const pending = await pendingTransfer({
      receiverSigner: receiver,
      receivedSecret: new Uint8Array(32).fill(88),
      typedSig: true,
    });
    const client = makeClient(receiver, {
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3),
        }),
      claim_transfer: async (req) =>
        create(ClaimTransferResponseSchema, {
          transfer: create(TransferSchema, {
            id: req.transferId,
            status: TransferStatus.COMPLETED,
            type: TransferType.TRANSFER,
            network: Network.REGTEST,
            leaves: await claimedLeaves(receiver, [required(pending.leaves[0], "pending leaf")]),
          }),
        }),
    });
    const claimed = await client.transfers.claim(mapTransfer(pending));
    expect(claimed[0]?.id).toBe(LEAF_ID);
    receiver.dispose();
  });

  const legacyClaimFakes = (pending: Transfer, receiver: SparkSigner) => ({
    get_signing_commitments: () =>
      create(GetSigningCommitmentsResponseSchema, {
        signingCommitments: commitmentGroup(3),
      }),
    claim_transfer: async (req: ClaimTransferRequest) =>
      create(ClaimTransferResponseSchema, {
        transfer: create(TransferSchema, {
          id: req.transferId,
          status: TransferStatus.COMPLETED,
          type: TransferType.TRANSFER,
          network: Network.REGTEST,
          leaves: await claimedLeaves(receiver, [required(pending.leaves[0], "pending leaf")]),
        }),
      }),
  });

  test("accepts a legacy compact sender signature", async () => {
    const receiver = await testSigner();
    const pending = await pendingTransfer({
      receiverSigner: receiver,
      receivedSecret: new Uint8Array(32).fill(88),
    });
    const client = makeClient(receiver, legacyClaimFakes(pending, receiver));
    const claimed = await client.transfers.claim(mapTransfer(pending));
    expect(claimed[0]?.id).toBe(LEAF_ID);
    receiver.dispose();
  });

  test("accepts a legacy DER sender signature", async () => {
    const receiver = await testSigner();
    const pending = await pendingTransfer({
      receiverSigner: receiver,
      receivedSecret: new Uint8Array(32).fill(88),
      legacySignature: "der",
    });
    const client = makeClient(receiver, legacyClaimFakes(pending, receiver));
    const claimed = await client.transfers.claim(mapTransfer(pending));
    expect(claimed[0]?.id).toBe(LEAF_ID);
    receiver.dispose();
  });

  test("rejects malformed legacy signature bytes", async () => {
    const receiver = await testSigner();
    const pending = await pendingTransfer({
      receiverSigner: receiver,
      receivedSecret: new Uint8Array(32).fill(88),
      legacySignature: "malformed",
    });
    const client = makeClient(receiver, {});
    await expect(client.transfers.claim(mapTransfer(pending))).rejects.toThrow(
      "sender signature verification failed",
    );
    receiver.dispose();
  });

  test("rejects a transfer whose status is not claimable", async () => {
    const receiver = await testSigner();
    const pending = await pendingTransfer({
      receiverSigner: receiver,
      receivedSecret: new Uint8Array(32).fill(88),
      status: TransferStatus.SENDER_INITIATED,
    });
    const client = makeClient(receiver, {});
    await expect(client.transfers.claim(mapTransfer(pending))).rejects.toThrow("not claimable");
    receiver.dispose();
  });

  test("claimPending skips transfers whose status is not claimable", async () => {
    const receiver = await testSigner();
    const pending = await pendingTransfer({
      receiverSigner: receiver,
      receivedSecret: new Uint8Array(32).fill(88),
      status: TransferStatus.SENDER_INITIATED,
    });
    let claimCalls = 0;
    const client = makeClient(receiver, {
      query_pending_transfers: () => create(QueryTransfersResponseSchema, { transfers: [pending] }),
      claim_transfer: () => {
        claimCalls += 1;
        return create(ClaimTransferResponseSchema, {});
      },
    });
    await expect(client.transfers.claimPending()).resolves.toStrictEqual([]);
    expect(claimCalls).toBe(0);
    receiver.dispose();
  });

  test("rejects a transfer that names a different receiver (fail closed)", async () => {
    const receiver = await testSigner();
    const otherIdentity = secp256k1.getPublicKey(OTHER_IDENTITY_SECRET, true);
    const foreign = await pendingTransfer({
      receiverSigner: receiver,
      receivedSecret: new Uint8Array(32).fill(88),
      receiverIdentityPublicKey: otherIdentity,
    });
    const client = makeClient(receiver, {});
    await expect(client.transfers.claim(mapTransfer(foreign))).rejects.toThrow(
      "not addressed to this identity",
    );

    const anonymous = await pendingTransfer({
      receiverSigner: receiver,
      receivedSecret: new Uint8Array(32).fill(88),
      receiverIdentityPublicKey: new Uint8Array(),
    });
    await expect(client.transfers.claim(mapTransfer(anonymous))).rejects.toThrow(
      "not addressed to this identity",
    );
    receiver.dispose();
  });

  test("claims a single-receiver transfer via receivers[0] when the top-level key is empty", async () => {
    const receiver = await testSigner();
    const self = await receiver.identityPublicKey();
    const pending = await pendingTransfer({
      receiverSigner: receiver,
      receivedSecret: new Uint8Array(32).fill(88),
      receiverIdentityPublicKey: new Uint8Array(),
      receivers: [{ id: "r-self", identityPublicKey: self }],
      transferReceiverId: "r-self",
    });
    const client = makeClient(receiver, {
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3),
        }),
      claim_transfer: async (req) =>
        create(ClaimTransferResponseSchema, {
          transfer: create(TransferSchema, {
            id: req.transferId,
            status: TransferStatus.COMPLETED,
            type: TransferType.TRANSFER,
            network: Network.REGTEST,
            leaves: await claimedLeaves(receiver, [required(pending.leaves[0], "pending leaf")]),
          }),
        }),
    });
    const claimed = await client.transfers.claim(mapTransfer(pending));
    expect(claimed[0]?.id).toBe(LEAF_ID);
    receiver.dispose();
  });

  test("claims only the caller's receiver edge on a multi-receiver transfer", async () => {
    const receiver = await testSigner();
    const self = await receiver.identityPublicKey();
    const otherIdentity = secp256k1.getPublicKey(OTHER_IDENTITY_SECRET, true);
    const otherLeaf = await pendingLeaf({
      receiverIdentity: otherIdentity,
      receivedSecret: new Uint8Array(32).fill(44),
      leafId: OTHER_LEAF_ID,
      transferReceiverId: "r-other",
    });
    const pending = await pendingTransfer({
      receiverSigner: receiver,
      receivedSecret: new Uint8Array(32).fill(88),
      transferReceiverId: "r-self",
      receivers: [
        { id: "r-self", identityPublicKey: self },
        { id: "r-other", identityPublicKey: otherIdentity },
      ],
      extraLeaves: [otherLeaf],
    });

    let commitmentsReq: GetSigningCommitmentsRequest | undefined;
    let claimReq: ClaimTransferRequest | undefined;
    const client = makeClient(receiver, {
      get_signing_commitments: (req) => {
        commitmentsReq = req;
        return create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3),
        });
      },
      claim_transfer: async (req) => {
        claimReq = req;
        // The SO response carries every receiver's leaves; only ours may be claimed.
        return create(ClaimTransferResponseSchema, {
          transfer: create(TransferSchema, {
            id: req.transferId,
            status: TransferStatus.COMPLETED,
            type: TransferType.TRANSFER,
            network: Network.REGTEST,
            leaves: [
              await claimedLeaf(receiver, required(pending.leaves[0], "own leaf")),
              otherLeaf,
            ],
          }),
        });
      },
    });

    const claimed = await client.transfers.claim(mapTransfer(pending));
    expect(claimed.map((leaf) => leaf.id)).toStrictEqual([LEAF_ID]);
    expect(required(commitmentsReq, "get_signing_commitments request").nodeIdCount).toBe(1);
    const pkg = required(
      required(claimReq, "claim_transfer request").claimPackage,
      "claim package",
    );
    expect(pkg.leavesToClaim).toHaveLength(1);
    expect(pkg.leavesToClaim[0]?.leafId).toBe(LEAF_ID);
    receiver.dispose();
  });

  describe("claim recovery after already_exists", () => {
    test("returns the receiver leaves when the claim already completed", async () => {
      const receiver = await testSigner();
      const pending = await pendingTransfer({
        receiverSigner: receiver,
        receivedSecret: new Uint8Array(32).fill(88),
      });
      const completed = create(TransferSchema, {
        ...pending,
        status: TransferStatus.COMPLETED,
        leaves: await claimedLeaves(receiver, pending.leaves),
      });
      const client = makeClient(receiver, {
        get_signing_commitments: () =>
          create(GetSigningCommitmentsResponseSchema, {
            signingCommitments: commitmentGroup(3),
          }),
        claim_transfer: () => {
          throw new ConnectError("leaf already claimed", Code.AlreadyExists);
        },
        query_transfers_by_id: () =>
          create(QueryTransfersResponseSchema, { transfers: [completed] }),
      });
      const claimed = await client.transfers.claim(mapTransfer(pending));
      expect(claimed.map((leaf) => leaf.id)).toStrictEqual([LEAF_ID]);
      receiver.dispose();
    });

    test("rethrows when the leg is not complete", async () => {
      const receiver = await testSigner();
      const pending = await pendingTransfer({
        receiverSigner: receiver,
        receivedSecret: new Uint8Array(32).fill(88),
      });
      const client = makeClient(receiver, {
        get_signing_commitments: () =>
          create(GetSigningCommitmentsResponseSchema, {
            signingCommitments: commitmentGroup(3),
          }),
        claim_transfer: () => {
          throw new ConnectError("leaf already claimed", Code.AlreadyExists);
        },
        query_transfers_by_id: () => create(QueryTransfersResponseSchema, { transfers: [pending] }),
      });
      await expect(client.transfers.claim(mapTransfer(pending))).rejects.toThrow(
        "leaf already claimed",
      );
      receiver.dispose();
    });

    test("rethrows when the transfer is not found", async () => {
      const receiver = await testSigner();
      const pending = await pendingTransfer({
        receiverSigner: receiver,
        receivedSecret: new Uint8Array(32).fill(88),
      });
      const client = makeClient(receiver, {
        get_signing_commitments: () =>
          create(GetSigningCommitmentsResponseSchema, {
            signingCommitments: commitmentGroup(3),
          }),
        claim_transfer: () => {
          throw new ConnectError("leaf already claimed", Code.AlreadyExists);
        },
        query_transfers_by_id: () => create(QueryTransfersResponseSchema, { transfers: [] }),
      });
      await expect(client.transfers.claim(mapTransfer(pending))).rejects.toThrow(
        "leaf already claimed",
      );
      receiver.dispose();
    });

    test("scopes recovered leaves to the caller's receiver edge", async () => {
      const receiver = await testSigner();
      const receiverIdentity = await receiver.identityPublicKey();
      const otherIdentity = secp256k1.getPublicKey(OTHER_IDENTITY_SECRET, true);
      const ownLeaf = await pendingLeaf({
        receiverIdentity,
        receivedSecret: new Uint8Array(32).fill(88),
        transferReceiverId: "r-self",
      });
      const otherLeaf = await pendingLeaf({
        receiverIdentity: otherIdentity,
        receivedSecret: new Uint8Array(32).fill(77),
        leafId: OTHER_LEAF_ID,
        transferReceiverId: "r-other",
      });
      const pending = create(TransferSchema, {
        id: TRANSFER_ID,
        senderIdentityPublicKey: secp256k1.getPublicKey(SENDER_SECRET, true),
        status: TransferStatus.SENDER_KEY_TWEAKED,
        type: TransferType.TRANSFER,
        network: Network.REGTEST,
        totalValue: 200_000n,
        leaves: [ownLeaf, otherLeaf],
        receivers: [
          create(TransferReceiverSchema, {
            id: "r-self",
            identityPublicKey: receiverIdentity,
            status: TransferReceiverStatus.KEY_TWEAKED,
          }),
          create(TransferReceiverSchema, {
            id: "r-other",
            identityPublicKey: otherIdentity,
            status: TransferReceiverStatus.KEY_TWEAKED,
          }),
        ],
      });
      // Own leg completed while the whole transfer is still in flight.
      const updated = create(TransferSchema, {
        ...pending,
        status: TransferStatus.SENDER_KEY_TWEAKED,
        leaves: [await claimedLeaf(receiver, ownLeaf), otherLeaf],
        receivers: [
          create(TransferReceiverSchema, {
            id: "r-self",
            identityPublicKey: receiverIdentity,
            status: TransferReceiverStatus.COMPLETED,
          }),
          create(TransferReceiverSchema, {
            id: "r-other",
            identityPublicKey: otherIdentity,
            status: TransferReceiverStatus.KEY_TWEAKED,
          }),
        ],
      });
      const client = makeClient(receiver, {
        get_signing_commitments: () =>
          create(GetSigningCommitmentsResponseSchema, {
            signingCommitments: commitmentGroup(3),
          }),
        claim_transfer: () => {
          throw new ConnectError("leaf already claimed", Code.AlreadyExists);
        },
        query_transfers_by_id: () => create(QueryTransfersResponseSchema, { transfers: [updated] }),
      });
      const claimed = await client.transfers.claim(mapTransfer(pending));
      expect(claimed.map((leaf) => leaf.id)).toStrictEqual([LEAF_ID]);
      receiver.dispose();
    });
  });

  test("rejects a multi-receiver transfer this identity does not receive", async () => {
    const receiver = await testSigner();
    const pending = await pendingTransfer({
      receiverSigner: receiver,
      receivedSecret: new Uint8Array(32).fill(88),
      receivers: [
        {
          id: "r-a",
          identityPublicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(44), true),
        },
        { id: "r-b", identityPublicKey: secp256k1.getPublicKey(OTHER_IDENTITY_SECRET, true) },
      ],
    });
    const client = makeClient(receiver, {});
    await expect(client.transfers.claim(mapTransfer(pending))).rejects.toThrow(
      "not a receiver of this multi-receiver transfer",
    );
    receiver.dispose();
  });

  test("claimPending puts a chain for each returned leaf", async () => {
    const receiver = await testSigner();
    const receivedSecret = new Uint8Array(32).fill(88);
    const pending = await pendingTransfer({ receiverSigner: receiver, receivedSecret });
    const store = createMemorySparkStore();
    const client = makeClient(
      receiver,
      {
        query_pending_transfers: () =>
          create(QueryTransfersResponseSchema, { transfers: [pending] }),
        get_signing_commitments: () =>
          create(GetSigningCommitmentsResponseSchema, {
            signingCommitments: commitmentGroup(3),
          }),
        claim_transfer: async (req) =>
          create(ClaimTransferResponseSchema, {
            transfer: create(TransferSchema, {
              id: req.transferId,
              status: TransferStatus.COMPLETED,
              type: TransferType.TRANSFER,
              network: Network.REGTEST,
              leaves: await claimedLeaves(receiver, [required(pending.leaves[0], "pending leaf")]),
            }),
          }),
      },
      store,
    );

    const claimed = await client.transfers.claimPending();
    const chains = await store.exitChains();
    expect(chains.map((chain) => chain.leafId)).toStrictEqual([
      required(claimed[0], "claimed leaf").id,
    ]);
    receiver.dispose();
  });

  /**
   * Fakes for the leaves()/claim race: `node1` is always reported, the claimed leaf appears in
   * query_nodes only once its claim committed (as the real coordinator would report it), and the
   * store's stale-check read waits a bounded window for a concurrently committing claim to store
   * its fresh chains first — under the leaf lock the window never matters either way.
   */
  async function claimRaceSetup(receiver: SparkSigner, receivedSecret: Uint8Array) {
    const pending = await pendingTransfer({ receiverSigner: receiver, receivedSecret });
    const { node: node1 } = await fabricatedNode(receiver, MULTI_LEAF_A, 100_000n);
    const claimed = await claimedLeaves(receiver, [required(pending.leaves[0], "pending leaf")]);
    const claimedNode = required(claimed[0]?.leaf, "claimed leaf node");
    let claimCommitted = false;

    const inner = createMemorySparkStore();
    let releaseChainWait: () => void = () => undefined;
    const chainStored = new Promise<void>((resolve) => {
      releaseChainWait = resolve;
    });
    const store: SparkStore = {
      exitChains: async () => {
        await Promise.race([
          chainStored,
          new Promise<void>((resolve) => {
            setTimeout(resolve, 150);
          }),
        ]);
        return inner.exitChains();
      },
      putExitChains: async (chains) => {
        await inner.putExitChains(chains);
        if (chains.some((chain) => chain.leafId === claimedNode.id)) {
          releaseChainWait();
        }
      },
      deleteExitChains: async (leafIds) => inner.deleteExitChains(leafIds),
    };

    const impl: SparkImpl = {
      query_nodes: (req) => {
        const request = req as QueryNodesRequest;
        if (request.source.case === "nodeIds") {
          const nodes: Record<string, typeof node1> = {};
          for (const id of request.source.value.nodeIds) {
            if (id === node1.id) {
              nodes[id] = node1;
            }
            if (id === claimedNode.id) {
              nodes[id] = claimedNode;
            }
          }
          return create(QueryNodesResponseSchema, { nodes, offset: 0n });
        }
        const nodes: Record<string, typeof node1> = { [node1.id]: node1 };
        if (claimCommitted) {
          nodes[claimedNode.id] = claimedNode;
        }
        return create(QueryNodesResponseSchema, { nodes, offset: 0n });
      },
      get_signing_commitments: (req) =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3 * Math.max(req.nodeIds.length, req.nodeIdCount)),
        }),
      claim_transfer: (req) => {
        claimCommitted = true;
        return create(ClaimTransferResponseSchema, {
          transfer: create(TransferSchema, {
            id: req.transferId,
            status: TransferStatus.COMPLETED,
            type: TransferType.TRANSFER,
            network: Network.REGTEST,
            leaves: claimed,
          }),
        });
      },
      query_transfers_by_id: () => create(QueryTransfersResponseSchema),
    };
    return { pending, node1, inner, store, impl };
  }

  test("a leaves() sync racing a claim keeps the claimed leaf's fresh exit chain", async () => {
    const receiver = await testSigner();
    const { pending, node1, inner, store, impl } = await claimRaceSetup(
      receiver,
      new Uint8Array(32).fill(88),
    );
    const client = makeClient(receiver, impl, store);

    const [leavesResult, claimedResult] = await Promise.all([
      client.leaves(),
      client.transfers.claim(mapTransfer(pending)),
    ]);
    expect(claimedResult.map((leaf) => leaf.id)).toContain(LEAF_ID);
    // Whichever ran first, the claimed leaf's chain must still be there: a sync that queried
    // before the commit must not delete chains stored after its query.
    const stored = await inner.exitChains();
    const storedIds = stored.map((chain) => chain.leafId);
    expect(storedIds.toSorted()).toStrictEqual([LEAF_ID, node1.id].toSorted());
    expect(leavesResult.length).toBeGreaterThan(0);
    receiver.dispose();
  });
});

function storedChain(leafId: string): SparkExitChain {
  return {
    leafId,
    nodes: [{ nodeId: leafId, nodeTx: new Uint8Array([1]) }],
    refundTx: new Uint8Array([2]),
  };
}

describe("transfer stores exit chains", () => {
  test("send deletes the chains of the leaves it spent", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const { leaf } = fabricateLeaf({
      leafId: LEAF_ID,
      signingPublicKey: required(leafKey, "leaf public key"),
      ownerIdentityPublicKey: identity,
    });
    const node = create(TreeNodeSchema, {
      id: leaf.id,
      treeId: leaf.treeId,
      value: 100_000n,
      nodeTx: leaf.nodeTx,
      refundTx: leaf.refundTx,
      vout: 0,
      verifyingPublicKey: leaf.verifyingPublicKey,
      ownerIdentityPublicKey: identity,
      ownerSigningPublicKey: leaf.ownerSigningPublicKey,
      signingKeyshare: {
        ownerIdentifiers: OPERATORS.map((op) => op.identifier),
        threshold: THRESHOLD,
        publicKey: leaf.signingKeyshare.publicKey,
        publicShares: {},
      },
      status: "AVAILABLE",
      network: Network.REGTEST,
      treenodeStatus: TreeNodeStatus.AVAILABLE,
    });

    const store = createMemorySparkStore();
    await store.putExitChains([storedChain(LEAF_ID)]);
    const client = makeClient(
      signer,
      {
        query_nodes: () => nodesResponse([node]),
        get_signing_commitments: () =>
          create(GetSigningCommitmentsResponseSchema, {
            signingCommitments: commitmentGroup(3),
          }),
        start_transfer_v2: (req) =>
          create(StartTransferResponseSchema, {
            transfer: create(TransferSchema, {
              id: req.transferId,
              senderIdentityPublicKey: req.ownerIdentityPublicKey,
              receiverIdentityPublicKey: req.receiverIdentityPublicKey,
              status: TransferStatus.SENDER_INITIATED,
              type: TransferType.TRANSFER,
              network: Network.REGTEST,
              totalValue: 100_000n,
            }),
          }),
      },
      store,
    );

    await client.transfers.send({
      receiver: secp256k1.getPublicKey(RECEIVER_SECRET, true),
      amountSats: 100_000,
    });
    await expect(store.exitChains()).resolves.toStrictEqual([]);
    signer.dispose();
  });
});

const SSP_SECRET = new Uint8Array(32).fill(0x53);
const SSP_IDENTITY = secp256k1.getPublicKey(SSP_SECRET, true);
const INBOUND_ID = "01989abc-def0-7000-8000-00000000000a";
const SWAP_LEAF_ID = "01989abc-def0-7abc-89ab-0000000000bb";
const CHANGE_LEAF_ID = "01989abc-def0-7abc-89ab-0000000000cc";

describe("transfers.swap", () => {
  /** One inbound swap leaf: sealed to `receiverIdentity`, sender-signed by the SSP key. */
  async function sspInboundLeaf(leafId: string, valueSats: bigint, receiverIdentity: Uint8Array) {
    const receivedSecret = sha256(new TextEncoder().encode(leafId));
    const receivedPublicKey = secp256k1.getPublicKey(receivedSecret, true);
    const crypto = await loadWasmBackend();
    const secretCipher = crypto.eciesEncrypt(
      receiverIdentity,
      receivedSecret,
      new Uint8Array(32).fill(6),
    );
    const { nodeTx, verifyingKey } = fabricateLeaf({
      leafId,
      signingPublicKey: receivedPublicKey,
      ownerIdentityPublicKey: receiverIdentity,
      valueSats,
    });
    const intermediateRefundTx = createCurrentTimelockRefundTxs({
      nodeTx,
      sequence: 1900,
      receivingPublicKey: receivedPublicKey,
      network: "regtest",
    }).cpfpRefund.txBytes;
    const digest = sendLeafSigningDigest(leafId, INBOUND_ID, secretCipher);
    const signature = secp256k1.sign(digest, SSP_SECRET, { prehash: false, lowS: true });
    return create(TransferLeafSchema, {
      leaf: create(TreeNodeSchema, {
        id: leafId,
        treeId: `tree-${leafId}`,
        value: valueSats,
        nodeTx,
        refundTx: intermediateRefundTx,
        vout: 0,
        verifyingPublicKey: verifyingKey,
        ownerIdentityPublicKey: receiverIdentity,
        ownerSigningPublicKey: receivedPublicKey,
        signingKeyshare: {
          ownerIdentifiers: OPERATORS.map((op) => op.identifier),
          threshold: THRESHOLD,
          publicKey: SHARE_PUB,
          publicShares: {},
        },
        status: "AVAILABLE",
        network: Network.REGTEST,
        treenodeStatus: TreeNodeStatus.AVAILABLE,
      }),
      secretCipher,
      sig: { case: "signature" as const, value: signature },
      intermediateRefundTx,
    });
  }

  /** The SSP's counter transfer to us: SSP sender, leaves sealed to our identity. */
  async function sspInboundTransfer(
    receiverIdentity: Uint8Array,
    leaves: ReadonlyArray<{ leafId: string; valueSats: bigint }>,
    options?: { senderIdentity?: Uint8Array },
  ) {
    const transferLeaves = await Promise.all(
      leaves.map(async (leaf) => sspInboundLeaf(leaf.leafId, leaf.valueSats, receiverIdentity)),
    );
    let totalValue = 0n;
    for (const leaf of leaves) {
      totalValue += leaf.valueSats;
    }
    return create(TransferSchema, {
      id: INBOUND_ID,
      senderIdentityPublicKey: options?.senderIdentity ?? SSP_IDENTITY,
      receiverIdentityPublicKey: receiverIdentity,
      status: TransferStatus.SENDER_KEY_TWEAKED,
      type: TransferType.COUNTER_SWAP_V3,
      network: Network.REGTEST,
      totalValue,
      leaves: transferLeaves,
    });
  }

  function fakeSsp(response?: { status: string; inboundTransferId: string; feeSats: number }) {
    const requests: SspSwapRequest[] = [];
    const ssp: SspClient = {
      swapFeeEstimate: async () => Promise.resolve(0),
      requestSwap: async (request) => {
        requests.push(request);
        if (response === undefined) {
          return Promise.reject(
            new SparkRequestError("ssp leaves swap failed", { code: "swap_failed" }),
          );
        }
        return Promise.resolve(response);
      },
      requestLightningReceive: async () =>
        Promise.reject(new SparkRequestError("ssp: requestLightningReceive not stubbed")),
      requestLightningSend: async () =>
        Promise.reject(new SparkRequestError("ssp: requestLightningSend not stubbed")),
      lightningSendFeeEstimate: async () =>
        Promise.reject(new SparkRequestError("ssp: lightningSendFeeEstimate not stubbed")),
      lightningSendRequest: async () =>
        Promise.reject(new SparkRequestError("ssp: lightningSendRequest not stubbed")),
      lightningReceiveRequest: async () =>
        Promise.reject(new SparkRequestError("ssp: lightningReceiveRequest not stubbed")),
      coopExitFeeQuote: async () =>
        Promise.reject(new SparkRequestError("ssp: coopExitFeeQuote not stubbed")),
      requestCoopExit: async () =>
        Promise.reject(new SparkRequestError("ssp: requestCoopExit not stubbed")),
      completeCoopExit: async () =>
        Promise.reject(new SparkRequestError("ssp: completeCoopExit not stubbed")),
      coopExitRequest: async () =>
        Promise.reject(new SparkRequestError("ssp: coopExitRequest not stubbed")),
      staticDepositQuote: async () =>
        Promise.reject(new SparkRequestError("ssp: staticDepositQuote not stubbed")),
      claimStaticDeposit: async () =>
        Promise.reject(new SparkRequestError("ssp: claimStaticDeposit not stubbed")),
    };
    return { ssp, requests };
  }

  function swapSpark(impl: SparkImpl) {
    const transport = createRouterTransport((router) => {
      router.service(SparkService, impl as never);
    });
    return createClient(SparkService, transport);
  }

  function signingResult(leafId: string, verifyingKey: Uint8Array) {
    return create(LeafRefundTxSigningResultSchema, {
      leafId,
      verifyingKey,
      refundTxSigningResult: create(SigningResultSchema, {
        signatureShares: Object.fromEntries(
          OPERATORS.map((op) => [op.identifier, new Uint8Array(32).fill(1)]),
        ),
        signingNonceCommitments: operatorCommitments(),
        publicKeys: Object.fromEntries(
          OPERATORS.map((op) => [op.identifier, new Uint8Array(33).fill(2)]),
        ),
      }),
    });
  }

  /** SSP GraphQL stub: challenge/verify plus a SUCCEEDED RequestSwap pointing at INBOUND_ID. */
  function sspFetch(operations: string[], identity: Uint8Array): typeof globalThis.fetch {
    const protectedChallenge = base64.encode(
      toBinary(SspProtectedChallengeSchema, {
        $typeName: "ssp_authn.ProtectedChallenge",
        version: 1,
        challenge: {
          $typeName: "ssp_authn.Challenge",
          version: 1,
          timestamp: 1_786_974_052n,
          nonce: new Uint8Array(32).fill(9),
          publicKey: identity,
        },
        serverHmac: new Uint8Array(32).fill(7),
      }),
    );
    return async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as { operationName: string };
      operations.push(body.operationName);
      const json = async (data: unknown) => Promise.resolve(Response.json({ data }));
      switch (body.operationName) {
        case "GetChallenge":
          return json({
            get_challenge: {
              get_challenge_output_protected_challenge: protectedChallenge,
            },
          });
        case "VerifyChallenge":
          return json({
            verify_challenge: {
              verify_challenge_output_session_token: "ssp-tok",
              verify_challenge_output_valid_until: new Date(Date.now() + 600_000).toISOString(),
            },
          });
        case "RequestSwap":
          return json({
            request_swap: {
              request: {
                leaves_swap_request_status: "SUCCEEDED",
                leaves_swap_request_swap_leaves: [{ swap_leaf_leaf_id: "swap-leaf-1" }],
                leaves_swap_request_inbound_transfer: { transfer_spark_id: INBOUND_ID },
                leaves_swap_request_fee: {
                  currency_amount_original_value: 0,
                  currency_amount_original_unit: "SATOSHI",
                },
              },
            },
          });
        default:
          return Promise.resolve(new Response("not found", { status: 404 }));
      }
    };
  }

  /** Query_nodes handler: owner queries get `owner`, nodeIds queries get `byId`. */
  function nodesHandler(
    owner: ReturnType<typeof nodesResponse>,
    byId: ReturnType<typeof nodesResponse>,
  ) {
    return (req: unknown) => ((req as QueryNodesRequest).source.case === "nodeIds" ? byId : owner);
  }

  /** A fabricated initiate_swap_primary_transfer response for one input leaf. */
  function swapResponse(
    req: InitiateSwapPrimaryTransferRequest,
    leaf: SparkLeaf,
    overrides?: { verifyingKey?: Uint8Array },
  ) {
    const result = signingResult(leaf.id, overrides?.verifyingKey ?? leaf.verifyingPublicKey);
    const transfer = required(req.transfer, "swap request transfer");
    return create(InitiateSwapPrimaryTransferResponseSchema, {
      transfer: create(TransferSchema, {
        id: transfer.transferId,
        senderIdentityPublicKey: transfer.ownerIdentityPublicKey,
        receiverIdentityPublicKey: transfer.receiverIdentityPublicKey,
        status: TransferStatus.SENDER_INITIATED,
        type: TransferType.PRIMARY_SWAP_V3,
        network: Network.REGTEST,
        totalValue: BigInt(leaf.valueSats),
      }),
      signingResults: [result],
    });
  }

  test("swaps a leaf: adaptor-signed primary transfer, SSP request, inbound claim", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const { leaf } = fabricateLeaf({
      leafId: LEAF_ID,
      signingPublicKey: required(leafKey, "leaf public key"),
      ownerIdentityPublicKey: identity,
    });
    const inbound = await sspInboundTransfer(identity, [
      { leafId: SWAP_LEAF_ID, valueSats: 100_000n },
    ]);

    // The fake SO cannot produce real operator shares; aggregateFrost is wrapped to capture the
    // jobs and return stand-in signatures. Real FROST adaptor math is covered by frost vectors.
    let aggregateJobs: Parameters<SparkSigner["aggregateFrost"]>[0] | undefined;
    const wrapped: SparkSigner = {
      ...signer,
      aggregateFrost: async (jobs) => {
        aggregateJobs = jobs;
        return Promise.resolve(jobs.map(() => new Uint8Array(64).fill(0x42)));
      },
    };

    let swapReq: InitiateSwapPrimaryTransferRequest | undefined;
    const { ssp, requests: sspRequests } = fakeSsp({
      status: "SUCCEEDED",
      inboundTransferId: INBOUND_ID,
      feeSats: 0,
    });
    const spark = swapSpark({
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3),
        }),
      initiate_swap_primary_transfer: (req: InitiateSwapPrimaryTransferRequest) => {
        swapReq = req;
        return swapResponse(req, leaf);
      },
      query_transfers_by_id: () => create(QueryTransfersResponseSchema, { transfers: [inbound] }),
      claim_transfer: async (req: ClaimTransferRequest) =>
        create(ClaimTransferResponseSchema, {
          transfer: create(TransferSchema, {
            id: req.transferId,
            status: TransferStatus.COMPLETED,
            type: TransferType.COUNTER_SWAP_V3,
            network: Network.REGTEST,
            leaves: await claimedLeaves(signer, inbound.leaves),
          }),
        }),
    });

    const claimed = await swapLeaves({
      spark,
      signer: wrapped,
      network: "regtest",
      operators: OPERATORS,
      threshold: THRESHOLD,
      ssp,
      sspIdentityPublicKey: SSP_IDENTITY,
      transferId: TRANSFER_ID,
      leaves: [leaf],
      targetAmountsSats: [100_000],
      random: fixedRandom(),
    });
    expect(claimed).toHaveLength(1);
    expect(claimed[0]?.id).toBe(SWAP_LEAF_ID);

    const request = required(swapReq, "initiate_swap_primary_transfer request");
    expect(request.transfer?.transferId).toBe(TRANSFER_ID);
    expect(request.transfer?.ownerIdentityPublicKey).toStrictEqual(identity);
    expect(request.transfer?.receiverIdentityPublicKey).toStrictEqual(SSP_IDENTITY);
    const adaptorKey = request.adaptorPublicKeys?.adaptorPublicKey;
    expect(adaptorKey).toHaveLength(33);
    const pkg = required(request.transfer?.transferPackage, "transfer package");
    expect(pkg.hashVariant).toBe(HashVariant.V2);
    expect(pkg.leavesToSend.map((job) => job.leafId)).toStrictEqual([LEAF_ID]);
    expect(pkg.directLeavesToSend).toHaveLength(0);
    expect(pkg.directFromCpfpLeavesToSend).toHaveLength(0);

    const sspRequest = required(sspRequests[0], "requestSwap input");
    expect(sspRequest.adaptorPublicKey).toStrictEqual(adaptorKey);
    expect(sspRequest.totalAmountSats).toBe(100_000);
    expect(sspRequest.targetAmountsSats).toStrictEqual([100_000]);
    expect(sspRequest.feeSats).toBe(0);
    expect(sspRequest.userOutboundTransferId).toBe(TRANSFER_ID);
    const userLeaf = required(sspRequest.userLeaves[0], "user leaf");
    expect(userLeaf.leafId).toBe(LEAF_ID);
    const cpfpJob = required(pkg.leavesToSend[0], "cpfp job");
    expect(userLeaf.rawUnsignedRefundTransaction).toStrictEqual(cpfpJob.rawTx);
    expect(userLeaf.adaptorAddedSignature).toHaveLength(64);

    const job = required(aggregateJobs?.[0], "aggregate job");
    expect(job.adaptorPublicKey).toStrictEqual(adaptorKey);
    expect(job.verifyingKey).toStrictEqual(leaf.verifyingPublicKey);
    expect(job.signatureShare).toStrictEqual(cpfpJob.userSignature);
    expect(job.commitment).toStrictEqual(cpfpJob.signingNonceCommitment);
    expect(job.operators.map((op) => op.identifier).toSorted()).toStrictEqual(
      OPERATORS.map((op) => op.identifier).toSorted(),
    );
    signer.dispose();
  });

  test("rejects a missing refund signing result", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const { leaf } = fabricateLeaf({
      leafId: LEAF_ID,
      signingPublicKey: required(leafKey, "leaf public key"),
      ownerIdentityPublicKey: identity,
    });
    const spark = swapSpark({
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3),
        }),
      initiate_swap_primary_transfer: (req: InitiateSwapPrimaryTransferRequest) => {
        const res = swapResponse(req, leaf);
        res.signingResults = [];
        return res;
      },
    });
    const { ssp } = fakeSsp();
    await expect(
      swapLeaves({
        spark,
        signer,
        network: "regtest",
        operators: OPERATORS,
        threshold: THRESHOLD,
        ssp,
        sspIdentityPublicKey: SSP_IDENTITY,
        transferId: TRANSFER_ID,
        leaves: [leaf],
        targetAmountsSats: [100_000],
        random: fixedRandom(),
      }),
    ).rejects.toThrow("expected 1 signing results");
    signer.dispose();
  });

  test("rejects a verifying-key mismatch in the signing result", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const { leaf } = fabricateLeaf({
      leafId: LEAF_ID,
      signingPublicKey: required(leafKey, "leaf public key"),
      ownerIdentityPublicKey: identity,
    });
    const spark = swapSpark({
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3),
        }),
      initiate_swap_primary_transfer: (req: InitiateSwapPrimaryTransferRequest) =>
        swapResponse(req, leaf, { verifyingKey: new Uint8Array(33).fill(9) }),
    });
    const { ssp } = fakeSsp();
    await expect(
      swapLeaves({
        spark,
        signer,
        network: "regtest",
        operators: OPERATORS,
        threshold: THRESHOLD,
        ssp,
        sspIdentityPublicKey: SSP_IDENTITY,
        transferId: TRANSFER_ID,
        leaves: [leaf],
        targetAmountsSats: [100_000],
        random: fixedRandom(),
      }),
    ).rejects.toThrow("verifying key mismatch");
    signer.dispose();
  });

  test("propagates an SSP swap failure", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const { leaf } = fabricateLeaf({
      leafId: LEAF_ID,
      signingPublicKey: required(leafKey, "leaf public key"),
      ownerIdentityPublicKey: identity,
    });
    const spark = swapSpark({
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3),
        }),
      initiate_swap_primary_transfer: (req: InitiateSwapPrimaryTransferRequest) =>
        swapResponse(req, leaf),
    });
    const { ssp } = fakeSsp();
    await expect(
      swapLeaves({
        spark,
        signer,
        network: "regtest",
        operators: OPERATORS,
        threshold: THRESHOLD,
        ssp,
        sspIdentityPublicKey: SSP_IDENTITY,
        transferId: TRANSFER_ID,
        leaves: [leaf],
        targetAmountsSats: [100_000],
        random: fixedRandom(),
      }),
    ).rejects.toMatchObject({ code: "swap_failed" });
    signer.dispose();
  });

  test("rejects an inbound transfer not sent by the SSP", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const { leaf } = fabricateLeaf({
      leafId: LEAF_ID,
      signingPublicKey: required(leafKey, "leaf public key"),
      ownerIdentityPublicKey: identity,
    });
    const inbound = await sspInboundTransfer(
      identity,
      [{ leafId: SWAP_LEAF_ID, valueSats: 100_000n }],
      { senderIdentity: secp256k1.getPublicKey(new Uint8Array(32).fill(0x77), true) },
    );
    const spark = swapSpark({
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3),
        }),
      initiate_swap_primary_transfer: (req: InitiateSwapPrimaryTransferRequest) =>
        swapResponse(req, leaf),
      query_transfers_by_id: () => create(QueryTransfersResponseSchema, { transfers: [inbound] }),
    });
    const { ssp } = fakeSsp({ status: "SUCCEEDED", inboundTransferId: INBOUND_ID, feeSats: 0 });
    await expect(
      swapLeaves({
        spark,
        signer,
        network: "regtest",
        operators: OPERATORS,
        threshold: THRESHOLD,
        ssp,
        sspIdentityPublicKey: SSP_IDENTITY,
        transferId: TRANSFER_ID,
        leaves: [leaf],
        targetAmountsSats: [100_000],
        random: fixedRandom(),
      }),
    ).rejects.toThrow("sender is not the SSP");
    signer.dispose();
  });

  test("rejects a claimed total that does not match inputs minus fee", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const { leaf } = fabricateLeaf({
      leafId: LEAF_ID,
      signingPublicKey: required(leafKey, "leaf public key"),
      ownerIdentityPublicKey: identity,
    });
    const inbound = await sspInboundTransfer(identity, [
      { leafId: SWAP_LEAF_ID, valueSats: 50_000n },
    ]);
    const spark = swapSpark({
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3),
        }),
      initiate_swap_primary_transfer: (req: InitiateSwapPrimaryTransferRequest) =>
        swapResponse(req, leaf),
      query_transfers_by_id: () => create(QueryTransfersResponseSchema, { transfers: [inbound] }),
      claim_transfer: async (req: ClaimTransferRequest) =>
        create(ClaimTransferResponseSchema, {
          transfer: create(TransferSchema, {
            id: req.transferId,
            status: TransferStatus.COMPLETED,
            type: TransferType.COUNTER_SWAP_V3,
            network: Network.REGTEST,
            leaves: await claimedLeaves(signer, inbound.leaves),
          }),
        }),
    });
    const { ssp } = fakeSsp({ status: "SUCCEEDED", inboundTransferId: INBOUND_ID, feeSats: 0 });
    await expect(
      swapLeaves({
        spark,
        signer,
        network: "regtest",
        operators: OPERATORS,
        threshold: THRESHOLD,
        ssp,
        sspIdentityPublicKey: SSP_IDENTITY,
        transferId: TRANSFER_ID,
        leaves: [leaf],
        targetAmountsSats: [100_000],
        random: fixedRandom(),
      }),
    ).rejects.toThrow("already ours");
    signer.dispose();
  });

  test("rejects when the SSP declares a fee different from the requested one", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const { leaf } = fabricateLeaf({
      leafId: LEAF_ID,
      signingPublicKey: required(leafKey, "leaf public key"),
      ownerIdentityPublicKey: identity,
    });
    const inbound = await sspInboundTransfer(identity, [
      { leafId: SWAP_LEAF_ID, valueSats: 100_000n },
    ]);
    const spark = swapSpark({
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3),
        }),
      initiate_swap_primary_transfer: (req: InitiateSwapPrimaryTransferRequest) =>
        swapResponse(req, leaf),
      query_transfers_by_id: () => create(QueryTransfersResponseSchema, { transfers: [inbound] }),
      claim_transfer: async (req: ClaimTransferRequest) =>
        create(ClaimTransferResponseSchema, {
          transfer: create(TransferSchema, {
            id: req.transferId,
            status: TransferStatus.COMPLETED,
            type: TransferType.COUNTER_SWAP_V3,
            network: Network.REGTEST,
            leaves: await claimedLeaves(signer, inbound.leaves),
          }),
        }),
    });
    const { ssp } = fakeSsp({ status: "SUCCEEDED", inboundTransferId: INBOUND_ID, feeSats: 5 });
    await expect(
      swapLeaves({
        spark,
        signer,
        network: "regtest",
        operators: OPERATORS,
        threshold: THRESHOLD,
        ssp,
        sspIdentityPublicKey: SSP_IDENTITY,
        transferId: TRANSFER_ID,
        leaves: [leaf],
        targetAmountsSats: [100_000],
        random: fixedRandom(),
      }),
    ).rejects.toThrow("declared a fee of 5");
    signer.dispose();
  });

  test("sendSats swaps leaves first when no exact combination exists", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const { leaf } = fabricateLeaf({
      leafId: LEAF_ID,
      signingPublicKey: required(leafKey, "leaf public key"),
      ownerIdentityPublicKey: identity,
    });
    const node = create(TreeNodeSchema, {
      id: leaf.id,
      treeId: leaf.treeId,
      value: 100_000n,
      nodeTx: leaf.nodeTx,
      refundTx: leaf.refundTx,
      vout: 0,
      verifyingPublicKey: leaf.verifyingPublicKey,
      ownerIdentityPublicKey: identity,
      ownerSigningPublicKey: leaf.ownerSigningPublicKey,
      signingKeyshare: {
        ownerIdentifiers: OPERATORS.map((op) => op.identifier),
        threshold: THRESHOLD,
        publicKey: leaf.signingKeyshare.publicKey,
        publicShares: {},
      },
      status: "AVAILABLE",
      network: Network.REGTEST,
      treenodeStatus: TreeNodeStatus.AVAILABLE,
    });
    const inbound = await sspInboundTransfer(identity, [
      { leafId: SWAP_LEAF_ID, valueSats: 60_000n },
      { leafId: CHANGE_LEAF_ID, valueSats: 40_000n },
    ]);
    const inboundClaimed = await claimedLeaves(signer, inbound.leaves);
    const claimedNodes = inboundClaimed.map((entry) => required(entry.leaf, "inbound leaf"));

    let swapReq: InitiateSwapPrimaryTransferRequest | undefined;
    let startReq: StartTransferRequest | undefined;
    const operations: string[] = [];
    const store = createMemorySparkStore();
    await store.putExitChains([storedChain(LEAF_ID)]);
    const client = makeClient(
      signer,
      {
        query_nodes: nodesHandler(nodesResponse([node]), nodesResponse([node, ...claimedNodes])),
        get_signing_commitments: (req) =>
          create(GetSigningCommitmentsResponseSchema, {
            signingCommitments: commitmentGroup(3 * Math.max(req.nodeIds.length, req.nodeIdCount)),
          }),
        initiate_swap_primary_transfer: (req) => {
          swapReq = req;
          return swapResponse(req, leaf);
        },
        query_transfers_by_id: () => create(QueryTransfersResponseSchema, { transfers: [inbound] }),
        claim_transfer: async (req) =>
          create(ClaimTransferResponseSchema, {
            transfer: create(TransferSchema, {
              id: req.transferId,
              status: TransferStatus.COMPLETED,
              type: TransferType.COUNTER_SWAP_V3,
              network: Network.REGTEST,
              leaves: await claimedLeaves(signer, inbound.leaves),
            }),
          }),
        start_transfer_v2: (req) => {
          startReq = req;
          return create(StartTransferResponseSchema, {
            transfer: create(TransferSchema, {
              id: req.transferId,
              senderIdentityPublicKey: req.ownerIdentityPublicKey,
              receiverIdentityPublicKey: req.receiverIdentityPublicKey,
              status: TransferStatus.SENDER_INITIATED,
              type: TransferType.TRANSFER,
              network: Network.REGTEST,
              totalValue: 60_000n,
            }),
          });
        },
      },
      store,
      sspFetch(operations, await signer.identityPublicKey()),
      SSP_IDENTITY,
    );

    const receiver = secp256k1.getPublicKey(RECEIVER_SECRET, true);
    const sent = await client.transfers.send({ receiver, amountSats: 60_000 });
    expect(sent.status).toBe("SENDER_INITIATED");
    expect(operations).toContain("RequestSwap");

    const swapRequest = required(swapReq, "initiate_swap_primary_transfer request");
    expect(swapRequest.adaptorPublicKeys?.adaptorPublicKey).toHaveLength(33);
    expect(swapRequest.transfer?.receiverIdentityPublicKey).toStrictEqual(SSP_IDENTITY);

    const start = required(startReq, "start_transfer_v2 request");
    const sendPackage = required(start.transferPackage, "send transfer package");
    expect(sendPackage.leavesToSend.map((job) => job.leafId)).toStrictEqual([SWAP_LEAF_ID]);
    expect(start.receiverIdentityPublicKey).toStrictEqual(receiver);

    // The swap input and the sent leaf chains are gone; the change leaf's chain stays.
    const chains = await store.exitChains();
    expect(chains.map((chain) => chain.leafId)).toStrictEqual([CHANGE_LEAF_ID]);
    signer.dispose();
  });
});

const MULTI_LEAF_A = "01989abc-def0-7abc-89ab-0000000000b1";
const MULTI_LEAF_B = "01989abc-def0-7abc-89ab-0000000000c2";
const RECEIVER_B_SECRET = new Uint8Array(32).fill(0xb1);
const RECEIVER_C_SECRET = new Uint8Array(32).fill(0xc2);

/** A fabricated leaf plus the `query_nodes` TreeNode the wallet would see for it. */
async function fabricatedNode(signer: SparkSigner, leafId: string, valueSats: bigint) {
  const identity = await signer.identityPublicKey();
  const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId }]);
  const { leaf } = fabricateLeaf({
    leafId,
    signingPublicKey: required(leafKey, "leaf public key"),
    ownerIdentityPublicKey: identity,
    valueSats,
  });
  const node = create(TreeNodeSchema, {
    id: leaf.id,
    treeId: leaf.treeId,
    value: valueSats,
    nodeTx: leaf.nodeTx,
    refundTx: leaf.refundTx,
    vout: 0,
    verifyingPublicKey: leaf.verifyingPublicKey,
    ownerIdentityPublicKey: identity,
    ownerSigningPublicKey: leaf.ownerSigningPublicKey,
    signingKeyshare: {
      ownerIdentifiers: OPERATORS.map((op) => op.identifier),
      threshold: THRESHOLD,
      publicKey: leaf.signingKeyshare.publicKey,
      publicShares: {},
    },
    status: "AVAILABLE",
    network: Network.REGTEST,
    treenodeStatus: TreeNodeStatus.AVAILABLE,
  });
  return { leaf, node };
}

describe("transfers.sendMany", () => {
  test("routes a two-receiver send through start_transfer_v3 with a full receiver map", async () => {
    const signer = await testSigner();
    const a = await fabricatedNode(signer, MULTI_LEAF_A, 60_000n);
    const b = await fabricatedNode(signer, MULTI_LEAF_B, 40_000n);
    const receiverB = secp256k1.getPublicKey(RECEIVER_B_SECRET, true);
    const receiverC = secp256k1.getPublicKey(RECEIVER_C_SECRET, true);

    let v3Req: StartTransferV3Request | undefined;
    let v2Called = false;
    const client = makeClient(signer, {
      query_nodes: () => nodesResponse([a.node, b.node]),
      get_signing_commitments: (req) =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3 * req.nodeIds.length),
        }),
      start_transfer_v2: () => {
        v2Called = true;
        return create(StartTransferResponseSchema);
      },
      start_transfer_v3: (req) => {
        v3Req = req;
        return create(StartTransferResponseSchema, {
          transfer: create(TransferSchema, {
            id: req.transferId,
            senderIdentityPublicKey: required(req.senderPackages[0], "sender package")
              .ownerIdentityPublicKey,
            status: TransferStatus.SENDER_INITIATED,
            type: TransferType.TRANSFER,
            network: Network.REGTEST,
            totalValue: 100_000n,
            receivers: [
              create(TransferReceiverSchema, {
                id: "r-b",
                identityPublicKey: receiverB,
                amountSats: 60_000n,
                status: TransferReceiverStatus.INITIATED,
              }),
              create(TransferReceiverSchema, {
                id: "r-c",
                identityPublicKey: receiverC,
                amountSats: 40_000n,
                status: TransferReceiverStatus.INITIATED,
              }),
            ],
          }),
        });
      },
    });

    const sent = await client.transfers.sendMany({
      receivers: [
        { receiver: receiverB, amountSats: 60_000 },
        { receiver: receiverC, amountSats: 40_000 },
      ],
    });
    expect(v2Called).toBe(false);
    const req = required(v3Req, "start_transfer_v3 request");
    const senderPackage = required(req.senderPackages[0], "sender package");
    const pkg = required(senderPackage.transferPackage, "transfer package");

    const receiverMap = senderPackage.receiverIdentityPublicKeys;
    expect(Object.keys(receiverMap).toSorted()).toStrictEqual(
      [MULTI_LEAF_A, MULTI_LEAF_B].toSorted(),
    );
    expect(receiverMap[MULTI_LEAF_A]).toStrictEqual(receiverB);
    expect(receiverMap[MULTI_LEAF_B]).toStrictEqual(receiverC);

    // Every signing job's leaf id is covered by the receiver map.
    const jobLeafIds = [
      ...pkg.leavesToSend,
      ...pkg.directLeavesToSend,
      ...pkg.directFromCpfpLeavesToSend,
    ].map((job) => job.leafId);
    for (const leafId of jobLeafIds) {
      expect(receiverMap[leafId]).toBeDefined();
    }

    // Each leaf's refund pays that leaf's own receiver.
    const expectedA = createDecrementedTimelockRefundTxs({
      nodeTx: a.leaf.nodeTx,
      sequence: 2000,
      receivingPublicKey: receiverB,
      network: "regtest",
    });
    const expectedB = createDecrementedTimelockRefundTxs({
      nodeTx: b.leaf.nodeTx,
      sequence: 2000,
      receivingPublicKey: receiverC,
      network: "regtest",
    });
    const cpfpByLeafId = new Map(pkg.leavesToSend.map((job) => [job.leafId, job.rawTx]));
    expect(bytesToHex(required(cpfpByLeafId.get(MULTI_LEAF_A), "cpfp job a"))).toBe(
      bytesToHex(expectedA.cpfpRefund.txBytes),
    );
    expect(bytesToHex(required(cpfpByLeafId.get(MULTI_LEAF_B), "cpfp job b"))).toBe(
      bytesToHex(expectedB.cpfpRefund.txBytes),
    );
    expect(sent.receivers.map((receiver) => receiver.amountSats)).toStrictEqual([60_000, 40_000]);
    signer.dispose();
  });

  test("rejects duplicate receivers after address decoding", async () => {
    const signer = await testSigner();
    const receiver = secp256k1.getPublicKey(RECEIVER_B_SECRET, true);
    const client = makeClient(signer, {});
    await expect(
      client.transfers.sendMany({
        receivers: [
          { receiver, amountSats: 100 },
          { receiver: new Uint8Array(receiver), amountSats: 200 },
        ],
      }),
    ).rejects.toThrow("duplicate receiver");
    signer.dispose();
  });

  test("rejects empty receiver lists and non-positive amounts", async () => {
    const signer = await testSigner();
    const receiver = secp256k1.getPublicKey(RECEIVER_B_SECRET, true);
    const client = makeClient(signer, {});
    await expect(client.transfers.sendMany({ receivers: [] })).rejects.toThrow(SparkInputError);
    await expect(
      client.transfers.sendMany({ receivers: [{ receiver, amountSats: 0 }] }),
    ).rejects.toThrow(/positive safe integer/);
    await expect(
      client.transfers.sendMany({
        receivers: [
          { receiver, amountSats: 1 },
          {
            receiver: secp256k1.getPublicKey(RECEIVER_C_SECRET, true),
            amountSats: Number.MAX_SAFE_INTEGER,
          },
        ],
      }),
    ).rejects.toThrow(/safe integer range/);
    signer.dispose();
  });

  test("sendTransfer rejects an invoice on a multi-receiver transfer and reused leaf ids", async () => {
    const signer = await testSigner();
    const a = await fabricatedNode(signer, MULTI_LEAF_A, 60_000n);
    const receiverB = secp256k1.getPublicKey(RECEIVER_B_SECRET, true);
    const receiverC = secp256k1.getPublicKey(RECEIVER_C_SECRET, true);
    // The rejections fire before any RPC, so the spark client is never touched.
    const coordinator = {
      spark: {} as never,
      signer,
      network: "regtest" as const,
      operators: OPERATORS,
      threshold: THRESHOLD,
    };
    const allocations = [
      { receiverIdentityPublicKey: receiverB, leaves: [a.leaf] },
      { receiverIdentityPublicKey: receiverC, leaves: [a.leaf] },
    ];
    await expect(
      sendTransfer({ ...coordinator, transferId: TRANSFER_ID, allocations }),
    ).rejects.toThrow(/appears twice/);
    await expect(
      sendTransfer({
        ...coordinator,
        transferId: TRANSFER_ID,
        allocations: [
          { receiverIdentityPublicKey: receiverB, leaves: [a.leaf] },
          { receiverIdentityPublicKey: receiverC, leaves: [a.leaf, { ...a.leaf, id: "other" }] },
        ],
        sparkInvoice: "sparkrt1test",
      }),
    ).rejects.toThrow(/cannot carry an invoice/);
    await expect(
      sendTransfer({ ...coordinator, transferId: TRANSFER_ID, allocations: [] }),
    ).rejects.toThrow(/must not be empty/);
    signer.dispose();
  });
});

describe("committed-transfer predicate", () => {
  const keyA = secp256k1.getPublicKey(new Uint8Array(32).fill(0xa1), true);
  const keyB = secp256k1.getPublicKey(new Uint8Array(32).fill(0xa2), true);
  const keyC = secp256k1.getPublicKey(new Uint8Array(32).fill(0xa3), true);

  function transfer(overrides: Partial<SparkTransfer>): SparkTransfer {
    return {
      id: TRANSFER_ID,
      senderIdentityPublicKey: keyA,
      receiverIdentityPublicKey: keyB,
      receivers: [],
      status: "SENDER_INITIATED",
      type: "TRANSFER",
      network: "regtest",
      totalValueSats: 100,
      leaves: [],
      ...overrides,
    };
  }

  const expectation = {
    type: TransferType.TRANSFER,
    senderIdentityPublicKey: keyA,
    receiverIdentityPublicKeys: [keyB],
  };

  test("accepts the exact receiver set and rejects supersets and missing receivers", () => {
    const receiver = (key: Uint8Array, amountSats = 0) => ({
      id: `r-${key[0]}`,
      identityPublicKey: key,
      amountSats,
      status: "TRANSFER_RECEIVER_STATUS_INITIATED",
    });
    assertCommittedTransfer(transfer({}), expectation, "test");
    assertCommittedTransfer(transfer({ receivers: [receiver(keyB)] }), expectation, "test");
    // An extra receiver, or a different receiver entirely, fails closed.
    expect(() =>
      assertCommittedTransfer(
        transfer({ receivers: [receiver(keyB), receiver(keyC)] }),
        expectation,
        "test",
      ),
    ).toThrow(/not ours/);
    expect(() =>
      assertCommittedTransfer(transfer({ receivers: [receiver(keyC)] }), expectation, "test"),
    ).toThrow(/not ours/);
    // Two expected receivers cannot be satisfied by the empty-receivers fallback.
    expect(() =>
      assertCommittedTransfer(
        transfer({}),
        { ...expectation, receiverIdentityPublicKeys: [keyB, keyC] },
        "test",
      ),
    ).toThrow(/not ours/);
  });

  test("checks per-receiver amounts and the total when expectations carry them", () => {
    const receiver = (key: Uint8Array, amountSats: number) => ({
      id: `r-${key[0]}`,
      identityPublicKey: key,
      amountSats,
      status: "TRANSFER_RECEIVER_STATUS_INITIATED",
    });
    const expected = {
      ...expectation,
      receiverIdentityPublicKeys: [keyB, keyC],
      receiverAmountsSats: [
        { receiverIdentityPublicKey: keyB, amountSats: 60 },
        { receiverIdentityPublicKey: keyC, amountSats: 40 },
      ],
    };
    const matching = transfer({
      receivers: [receiver(keyC, 40), receiver(keyB, 60)],
      totalValueSats: 100,
    });
    assertCommittedTransfer(matching, expected, "test");
    // A swapped amount fails the per-receiver check.
    expect(() =>
      assertCommittedTransfer(
        transfer({
          receivers: [receiver(keyC, 60), receiver(keyB, 40)],
          totalValueSats: 100,
        }),
        expected,
        "test",
      ),
    ).toThrow(/not ours/);
    // Matching edges but a different total fails.
    expect(() =>
      assertCommittedTransfer(
        transfer({
          receivers: [receiver(keyB, 60), receiver(keyC, 40)],
          totalValueSats: 99,
        }),
        expected,
        "test",
      ),
    ).toThrow(/not ours/);
  });

  test("rejects duplicate receiver edges and binds a single edge by the total", () => {
    const receiver = (key: Uint8Array, amountSats = 0) => ({
      id: `r-${key[0]}`,
      identityPublicKey: key,
      amountSats,
      status: "TRANSFER_RECEIVER_STATUS_INITIATED",
    });
    // [B, B] against expected {B, C}: equal length but B is duplicated and C missing.
    expect(() =>
      assertCommittedTransfer(
        transfer({ receivers: [receiver(keyB), receiver(keyB)] }),
        { ...expectation, receiverIdentityPublicKeys: [keyB, keyC] },
        "test",
      ),
    ).toThrow(/not ours/);
    // A single edge may leave amountSats unset; totalValueSats carries the amount check.
    const singleExpected = {
      ...expectation,
      receiverAmountsSats: [{ receiverIdentityPublicKey: keyB, amountSats: 100 }],
    };
    assertCommittedTransfer(
      transfer({ receivers: [receiver(keyB)], totalValueSats: 100 }),
      singleExpected,
      "test",
    );
    expect(() =>
      assertCommittedTransfer(
        transfer({ receivers: [receiver(keyB)], totalValueSats: 99 }),
        singleExpected,
        "test",
      ),
    ).toThrow(/not ours/);
  });
});

describe("send idempotent retries", () => {
  test("a committed transfer under the caller's transfer id returns without touching leaves", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const receiver = secp256k1.getPublicKey(RECEIVER_B_SECRET, true);
    const committed = create(TransferSchema, {
      id: TRANSFER_ID,
      senderIdentityPublicKey: identity,
      receiverIdentityPublicKey: receiver,
      status: TransferStatus.SENDER_INITIATED,
      type: TransferType.TRANSFER,
      network: Network.REGTEST,
      totalValue: 60_000n,
      receivers: [
        create(TransferReceiverSchema, {
          id: "r-b",
          identityPublicKey: receiver,
          amountSats: 60_000n,
          status: TransferReceiverStatus.INITIATED,
        }),
      ],
    });
    let nodeQueries = 0;
    const client = makeClient(signer, {
      query_nodes: () => {
        nodeQueries += 1;
        return nodesResponse([]);
      },
      query_transfers_by_id: () => create(QueryTransfersResponseSchema, { transfers: [committed] }),
      start_transfer_v2: () => {
        throw new Error("start_transfer_v2 must not run when the probe hits");
      },
    });
    const sent = await client.transfers.send({
      receiver,
      amountSats: 60_000,
      transferId: TRANSFER_ID,
    });
    expect(sent.id).toBe(TRANSFER_ID);
    // The probe hit short-circuits before leaf selection — query_nodes never ran.
    expect(nodeQueries).toBe(0);
    signer.dispose();
  });

  test("a committed transfer under different terms rejects the reused id", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const receiver = secp256k1.getPublicKey(RECEIVER_B_SECRET, true);
    const foreign = create(TransferSchema, {
      id: TRANSFER_ID,
      senderIdentityPublicKey: identity,
      receiverIdentityPublicKey: secp256k1.getPublicKey(RECEIVER_C_SECRET, true),
      status: TransferStatus.SENDER_INITIATED,
      type: TransferType.TRANSFER,
      network: Network.REGTEST,
      totalValue: 60_000n,
    });
    const client = makeClient(signer, {
      query_transfers_by_id: () => create(QueryTransfersResponseSchema, { transfers: [foreign] }),
      start_transfer_v2: () => {
        throw new Error("start_transfer_v2 must not run on a mismatched probe");
      },
    });
    await expect(
      client.transfers.send({ receiver, amountSats: 60_000, transferId: TRANSFER_ID }),
    ).rejects.toThrow(/committed transfer is not ours/);
    signer.dispose();
  });

  test("a lost start_transfer response recovers the committed transfer", async () => {
    const signer = await testSigner();
    const a = await fabricatedNode(signer, MULTI_LEAF_A, 60_000n);
    const identity = await signer.identityPublicKey();
    const receiver = secp256k1.getPublicKey(RECEIVER_B_SECRET, true);
    const committed = create(TransferSchema, {
      id: TRANSFER_ID,
      senderIdentityPublicKey: identity,
      receiverIdentityPublicKey: receiver,
      status: TransferStatus.SENDER_INITIATED,
      type: TransferType.TRANSFER,
      network: Network.REGTEST,
      totalValue: 60_000n,
    });
    // First probe (before the send) misses; the post-failure probe finds the committed transfer.
    const client = makeClient(signer, {
      query_nodes: () => nodesResponse([a.node]),
      get_signing_commitments: (req) =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3 * req.nodeIds.length),
        }),
      query_transfers_by_id: byIdQueue([[], [committed]]),
      start_transfer_v2: () => {
        throw new SparkRequestError("start response lost", { code: "unavailable" });
      },
    });
    const sent = await client.transfers.send({
      receiver,
      amountSats: 60_000,
      transferId: TRANSFER_ID,
    });
    expect(sent.id).toBe(TRANSFER_ID);
    signer.dispose();
  });
});

describe("concurrent sends", () => {
  /**
   * Fakes for the concurrent-send race: the coordinator stops reporting a leaf once its transfer
   * committed, `start_transfer_v2` sleeps mid-commit so a lock-free second send would overlap it,
   * and the leaf ids each call carried are recorded.
   */
  function concurrentSendImpl(
    first: Awaited<ReturnType<typeof fabricatedNode>>,
    second: Awaited<ReturnType<typeof fabricatedNode>>,
    sentLeafIds: Set<string>,
    started: string[][],
    track: { inFlight: number; maxInFlight: number },
  ): SparkImpl {
    const byId = new Map([
      [first.leaf.id, first.node],
      [second.leaf.id, second.node],
    ]);
    return {
      query_nodes: (req) => {
        const request = req as QueryNodesRequest;
        const nodes: Record<string, typeof first.node> = {};
        if (request.source.case === "nodeIds") {
          for (const id of request.source.value.nodeIds) {
            const node = byId.get(id);
            if (node !== undefined) {
              nodes[id] = node;
            }
          }
        } else {
          for (const [id, node] of byId) {
            if (!sentLeafIds.has(id)) {
              nodes[id] = node;
            }
          }
        }
        return create(QueryNodesResponseSchema, { nodes, offset: 0n });
      },
      get_signing_commitments: (req) =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3 * Math.max(req.nodeIds.length, req.nodeIdCount)),
        }),
      start_transfer_v2: async (req) => {
        const ids = (req.transferPackage?.leavesToSend ?? []).map((job) => job.leafId);
        started.push(ids);
        track.inFlight += 1;
        track.maxInFlight = Math.max(track.maxInFlight, track.inFlight);
        await new Promise<void>((resolve) => {
          setTimeout(resolve, 15);
        });
        track.inFlight -= 1;
        for (const id of ids) {
          sentLeafIds.add(id);
        }
        return create(StartTransferResponseSchema, {
          transfer: create(TransferSchema, {
            id: req.transferId,
            senderIdentityPublicKey: req.ownerIdentityPublicKey,
            receiverIdentityPublicKey: req.receiverIdentityPublicKey,
            status: TransferStatus.SENDER_INITIATED,
            type: TransferType.TRANSFER,
            network: Network.REGTEST,
            totalValue: 100_000n,
            leaves: ids.map((id) =>
              create(TransferLeafSchema, {
                leaf: byId.get(id),
                transferReceiverId: "r-1",
              }),
            ),
            receivers: [
              create(TransferReceiverSchema, {
                id: "r-1",
                identityPublicKey: req.receiverIdentityPublicKey,
                amountSats: 100_000n,
                status: TransferReceiverStatus.KEY_TWEAKED,
              }),
            ],
          }),
        });
      },
      query_transfers_by_id: () => create(QueryTransfersResponseSchema),
    };
  }

  test("two sends under one client never start a transfer over the same leaf", async () => {
    const signer = await testSigner();
    const first = await fabricatedNode(signer, MULTI_LEAF_A, 100_000n);
    const second = await fabricatedNode(signer, MULTI_LEAF_B, 100_000n);
    const receiver = secp256k1.getPublicKey(RECEIVER_SECRET, true);
    const sentLeafIds = new Set<string>();
    const started: string[][] = [];
    const track = { inFlight: 0, maxInFlight: 0 };
    const client = makeClient(
      signer,
      concurrentSendImpl(first, second, sentLeafIds, started, track),
    );

    const [sendA, sendB] = await Promise.all([
      client.transfers.send({ receiver, amountSats: 100_000 }),
      client.transfers.send({ receiver, amountSats: 100_000 }),
    ]);
    expect(sendA.status).toBe("SENDER_INITIATED");
    expect(sendB.status).toBe("SENDER_INITIATED");
    // Serialized under the leaf lock: no overlapping commits and disjoint inputs.
    expect(track.maxInFlight).toBe(1);
    expect(started).toHaveLength(2);
    expect(new Set(started.flat()).size).toBe(2);
    signer.dispose();
  });
});
