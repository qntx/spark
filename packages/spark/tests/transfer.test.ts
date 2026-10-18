import { create } from "@bufbuild/protobuf";
import { createRouterTransport } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
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
  SparkService,
  Network,
  QueryNodesResponseSchema,
  QueryTransfersResponseSchema,
  RequestedSigningCommitmentsSchema,
  StartTransferResponseSchema,
  TransferLeafSchema,
  TransferSchema,
  TransferStatus,
  TransferType,
  TreeNodeSchema,
  TreeNodeStatus,
} from "../src/proto/gen/spark_pb.ts";
import type {
  ClaimTransferRequest,
  GetSigningCommitmentsRequest,
  StartTransferRequest,
} from "../src/proto/gen/spark_pb.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import type { SparkSigner } from "../src/signer/index.ts";
import { mapTransfer } from "../src/transfer/index.ts";
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
function verifyingKeyFor(signingPublicKey: Uint8Array): Uint8Array {
  return secp256k1.Point.BASE.multiply(SHARE_SECRET)
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
        publicKey: verifyingKey,
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
  claim_transfer: (req: ClaimTransferRequest) => unknown;
}>;

function makeClient(signer: SparkSigner, sparkImpl: SparkImpl) {
  return createSparkClientWith(
    {
      network: "regtest",
      signer,
      fetch: async () => Promise.reject(new Error("no fetch")),
      random: fixedRandom(),
      operators: OPERATORS,
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

function nodesResponse(nodes: Array<ReturnType<typeof create<typeof TreeNodeSchema>>>) {
  return create(QueryNodesResponseSchema, {
    nodes: Object.fromEntries(nodes.map((node) => [node.id, node])),
    offset: 0n,
  });
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
        publicKey: leaf.verifyingPublicKey,
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

  test("rejects amounts without an exact leaf combination", async () => {
    const signer = await testSigner();
    const client = makeClient(signer, {
      query_nodes: () => nodesResponse([]),
    });
    await expect(
      client.transfers.send({
        receiver: secp256k1.getPublicKey(RECEIVER_SECRET, true),
        amountSats: 50_000,
      }),
    ).rejects.toThrow("no leaf combination sums exactly");
    signer.dispose();
  });
});

describe("transfers.claim", () => {
  /** A pending transfer whose leaf the receiver can open: cipher seals `receivedSecret`. */
  async function pendingTransfer(options: {
    receiverSigner: SparkSigner;
    receivedSecret: Uint8Array;
    leafOwnerKey?: Uint8Array;
    corruptSig?: boolean;
    typedSig?: boolean;
  }) {
    const receiverIdentity = await options.receiverSigner.identityPublicKey();
    const receivedPublicKey = secp256k1.getPublicKey(options.receivedSecret, true);
    const crypto = await loadWasmBackend();
    const secretCipher = crypto.eciesEncrypt(
      receiverIdentity,
      options.receivedSecret,
      new Uint8Array(32).fill(6),
    );
    const ownerKey = options.leafOwnerKey ?? receivedPublicKey;
    const { nodeTx, verifyingKey } = fabricateLeaf({
      leafId: LEAF_ID,
      signingPublicKey: ownerKey,
      ownerIdentityPublicKey: receiverIdentity,
    });
    // Intermediate refund at the decremented sequence (1900) — the leaf's state after send.
    const intermediateRefundTx = createCurrentTimelockRefundTxs({
      nodeTx,
      sequence: 1900,
      receivingPublicKey: receivedPublicKey,
      network: "regtest",
    }).cpfpRefund.txBytes;
    const digest = sendLeafSigningDigest(LEAF_ID, TRANSFER_ID, secretCipher);
    const signature = secp256k1.sign(
      options.corruptSig === true ? sha256(digest) : digest,
      SENDER_SECRET,
      { prehash: false, lowS: true },
    );
    const sig =
      options.typedSig === true
        ? {
            case: "typedSignature" as const,
            value: create(SignatureSchema, {
              scheme: SignatureScheme.ECDSA,
              signature: secp256k1.Signature.fromBytes(signature, "compact").toBytes("der"),
            }),
          }
        : { case: "signature" as const, value: signature };
    return create(TransferSchema, {
      id: TRANSFER_ID,
      senderIdentityPublicKey: secp256k1.getPublicKey(SENDER_SECRET, true),
      receiverIdentityPublicKey: receiverIdentity,
      status: TransferStatus.SENDER_KEY_TWEAKED,
      type: TransferType.TRANSFER,
      network: Network.REGTEST,
      totalValue: 100_000n,
      leaves: [
        create(TransferLeafSchema, {
          leaf: create(TreeNodeSchema, {
            id: LEAF_ID,
            treeId: `tree-${LEAF_ID}`,
            value: 100_000n,
            nodeTx,
            refundTx: intermediateRefundTx,
            vout: 0,
            verifyingPublicKey: verifyingKey,
            ownerIdentityPublicKey: receiverIdentity,
            ownerSigningPublicKey: ownerKey,
            signingKeyshare: {
              ownerIdentifiers: OPERATORS.map((op) => op.identifier),
              threshold: THRESHOLD,
              publicKey: verifyingKey,
              publicShares: {},
            },
            status: "AVAILABLE",
            network: Network.REGTEST,
            treenodeStatus: TreeNodeStatus.AVAILABLE,
          }),
          secretCipher,
          sig,
          intermediateRefundTx,
        }),
      ],
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
      claim_transfer: (req) => {
        claimReq = req;
        return create(ClaimTransferResponseSchema, {
          transfer: create(TransferSchema, {
            id: req.transferId,
            status: TransferStatus.COMPLETED,
            type: TransferType.TRANSFER,
            network: Network.REGTEST,
            leaves: [required(pending.leaves[0], "pending leaf")],
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
      claim_transfer: (req) =>
        create(ClaimTransferResponseSchema, {
          transfer: create(TransferSchema, {
            id: req.transferId,
            status: TransferStatus.COMPLETED,
            type: TransferType.TRANSFER,
            network: Network.REGTEST,
            leaves: [required(pending.leaves[0], "pending leaf")],
          }),
        }),
    });
    const claimed = await client.transfers.claim(mapTransfer(pending));
    expect(claimed[0]?.id).toBe(LEAF_ID);
    receiver.dispose();
  });
});
