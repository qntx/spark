import { create } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { createRouterTransport } from "@connectrpc/connect";
import { mod } from "@noble/curves/abstract/modular.js";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import { createSparkClientWith } from "../src/client/index.ts";
import {
  addressToScript,
  createInitialTimelockRefundTxs,
  createRootNodeTx,
  p2trAddressFromPublicKey,
} from "../src/core/bitcoin/index.ts";
import { proofOfPossessionDigest } from "../src/core/hashing/statements.ts";
import type { SparkOperatorConfig } from "../src/core/network.ts";
import { SparkInputError } from "../src/errors/index.ts";
import {
  ChallengeSchema,
  ProtectedChallengeSchema,
  SparkAuthnService,
} from "../src/proto/gen/spark_authn_pb.ts";
import {
  AddressSchema,
  DepositAddressProofSchema,
  DepositAddressQueryResultSchema,
  FinalizeDepositTreeCreationResponseSchema,
  GenerateDepositAddressResponseSchema,
  GetSigningCommitmentsResponseSchema,
  Network,
  QueryUnusedDepositAddressesResponseSchema,
  RequestedSigningCommitmentsSchema,
  SparkService,
  TreeNodeSchema,
  TreeNodeStatus,
} from "../src/proto/gen/spark_pb.ts";
import type {
  FinalizeDepositTreeCreationRequest,
  GenerateDepositAddressRequest,
  GetSigningCommitmentsRequest,
} from "../src/proto/gen/spark_pb.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import type { SparkSigner } from "../src/signer/index.ts";
import { loadWasmBackend } from "./support/backend.ts";
import { be32, taprootTweakedKey } from "./support/frost.ts";

const COORDINATOR_ID = "0000000000000000000000000000000000000000000000000000000000000001";
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
// Operator 0 is the coordinator — its address signature is skipped for single-use addresses.

/** Unwraps values the router captures — a missing capture is a test bug, not a branch. */
function required<T>(value: T | undefined, name: string): T {
  if (value === undefined) {
    throw new Error(`${name} was not captured`);
  }
  return value;
}

/** Full first page of 100, then a short page with one entry. */
function pageBatch(offset: number): number[] {
  if (offset === 0) {
    return Array.from({ length: 100 }, (_, i) => i);
  }
  return [100];
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

/** The operator keyshare secret the fabricated SO holds for the deposit address. */
const SHARE_SECRET = 0x5ea5n;

function fabricateDepositAddress(options: {
  signingPublicKey: Uint8Array;
  identityPublicKey: Uint8Array;
  corruptProof?: boolean;
  skipOperator?: string;
}): {
  address: string;
  verifyingKey: Uint8Array;
  proofOfPossessionSignature: Uint8Array;
  addressSignatures: Record<string, Uint8Array>;
} {
  const sharePoint = secp256k1.Point.BASE.multiply(SHARE_SECRET);
  const sharePublicKey = sharePoint.toBytes(true);
  const verifyingKey = sharePoint
    .add(secp256k1.Point.fromBytes(options.signingPublicKey))
    .toBytes(true);
  const address = p2trAddressFromPublicKey(verifyingKey, "regtest");
  const digest = proofOfPossessionDigest(options.identityPublicKey, sharePublicKey, address);
  const { tweak } = taprootTweakedKey(sharePublicKey);
  const evenSecret =
    (sharePoint.toAffine().y & 1n) === 0n ? SHARE_SECRET : secp256k1.Point.Fn.ORDER - SHARE_SECRET;
  const tweakedSecret = mod(evenSecret + tweak, secp256k1.Point.Fn.ORDER);
  const proofOfPossessionSignature = schnorr.sign(
    options.corruptProof === true ? sha256(digest) : digest,
    be32(tweakedSecret),
    new Uint8Array(32).fill(4),
  );
  const addressHash = sha256(utf8ToBytes(address));
  const addressSignatures: Record<string, Uint8Array> = {};
  for (const operator of OPERATORS) {
    if (operator.identifier === COORDINATOR_ID || operator.identifier === options.skipOperator) {
      continue;
    }
    addressSignatures[operator.identifier] = secp256k1.sign(
      addressHash,
      OPERATOR_SECRETS[operator.id]!,
      { format: "der", prehash: false },
    );
  }
  return { address, verifyingKey, proofOfPossessionSignature, addressSignatures };
}

type SparkImpl = Partial<{
  generate_deposit_address: (req: GenerateDepositAddressRequest) => unknown;
  query_unused_deposit_addresses: (req: unknown) => unknown;
  get_signing_commitments: (req: GetSigningCommitmentsRequest) => unknown;
  finalize_deposit_tree_creation: (req: FinalizeDepositTreeCreationRequest) => unknown;
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

function depositTxTo(address: string, sats: bigint, extraOutputs: string[] = []): Uint8Array {
  const tx = new Transaction({ allowUnknownOutputs: true });
  tx.addInput({ txid: new Uint8Array(32).fill(7), index: 0, sequence: 0 });
  tx.addOutput({ script: addressToScript(address), amount: sats });
  for (const extra of extraOutputs) {
    tx.addOutput({ script: addressToScript(extra), amount: sats });
  }
  return tx.toBytes(true);
}

function fakeLeaf(id: string) {
  return create(TreeNodeSchema, {
    id,
    treeId: `tree-${id}`,
    value: 100_000n,
    nodeTx: new Uint8Array([1, 2]),
    refundTx: new Uint8Array([3, 4]),
    vout: 0,
    verifyingPublicKey: new Uint8Array(33).fill(5),
    ownerIdentityPublicKey: new Uint8Array(33).fill(6),
    ownerSigningPublicKey: new Uint8Array(33).fill(6),
    signingKeyshare: {
      ownerIdentifiers: OPERATORS.map((op) => op.identifier),
      threshold: 2,
      publicKey: new Uint8Array(33).fill(7),
      publicShares: {},
    },
    status: "AVAILABLE",
    network: Network.REGTEST,
    treenodeStatus: TreeNodeStatus.AVAILABLE,
    createdTime: timestampFromMs(1_700_000_000_000),
    updatedTime: timestampFromMs(1_700_000_000_000),
  });
}

describe("deposits.newAddress", () => {
  test("returns a verified deposit address and binds the leaf signing key", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    let captured: GenerateDepositAddressRequest | undefined;
    const client = makeClient(signer, {
      generate_deposit_address: (req) => {
        captured = req;
        const fabricated = fabricateDepositAddress({
          signingPublicKey: req.signingPublicKey,
          identityPublicKey: req.identityPublicKey,
        });
        return create(GenerateDepositAddressResponseSchema, {
          depositAddress: create(AddressSchema, {
            address: fabricated.address,
            verifyingKey: fabricated.verifyingKey,
            depositAddressProof: create(DepositAddressProofSchema, {
              addressSignatures: fabricated.addressSignatures,
              proofOfPossessionSignature: fabricated.proofOfPossessionSignature,
            }),
          }),
        });
      },
    });
    const address = await client.deposits.newAddress();
    const request = required(captured, "generate_deposit_address request");
    expect(request.hashVariant).toBe(1);
    expect(request.network).toBe(Network.REGTEST);
    expect(bytesToHex(request.identityPublicKey)).toBe(bytesToHex(identity));
    const leafId = required(request.leafId, "request leafId");
    expect(leafId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId }]);
    expect(bytesToHex(request.signingPublicKey)).toBe(
      bytesToHex(required(leafKey, "leaf public key")),
    );
    expect(address.startsWith("bcrt1")).toBe(true);
    signer.dispose();
  });

  test("rejects a bad proof-of-possession signature", async () => {
    const signer = await testSigner();
    const client = makeClient(signer, {
      generate_deposit_address: (req) => {
        const fabricated = fabricateDepositAddress({
          signingPublicKey: req.signingPublicKey,
          identityPublicKey: req.identityPublicKey,
          corruptProof: true,
        });
        return create(GenerateDepositAddressResponseSchema, {
          depositAddress: create(AddressSchema, {
            address: fabricated.address,
            verifyingKey: fabricated.verifyingKey,
            depositAddressProof: create(DepositAddressProofSchema, {
              addressSignatures: fabricated.addressSignatures,
              proofOfPossessionSignature: fabricated.proofOfPossessionSignature,
            }),
          }),
        });
      },
    });
    await expect(client.deposits.newAddress()).rejects.toThrow("proof of possession is invalid");
    signer.dispose();
  });

  test("rejects a missing non-coordinator operator signature", async () => {
    const signer = await testSigner();
    const missing = OPERATORS[1]!.identifier;
    const client = makeClient(signer, {
      generate_deposit_address: (req) => {
        const fabricated = fabricateDepositAddress({
          signingPublicKey: req.signingPublicKey,
          identityPublicKey: req.identityPublicKey,
          skipOperator: missing,
        });
        return create(GenerateDepositAddressResponseSchema, {
          depositAddress: create(AddressSchema, {
            address: fabricated.address,
            verifyingKey: fabricated.verifyingKey,
            depositAddressProof: create(DepositAddressProofSchema, {
              addressSignatures: fabricated.addressSignatures,
              proofOfPossessionSignature: fabricated.proofOfPossessionSignature,
            }),
          }),
        });
      },
    });
    await expect(client.deposits.newAddress()).rejects.toThrow(
      `missing signature from operator ${missing}`,
    );
    signer.dispose();
  });
});

describe("deposits.unused", () => {
  test("pages query_unused_deposit_addresses until a short page", async () => {
    const signer = await testSigner();
    let pages = 0;
    const client = makeClient(signer, {
      query_unused_deposit_addresses: (req) => {
        pages += 1;
        const offset = Number((req as { offset: bigint }).offset);
        const batch = pageBatch(offset);
        return create(QueryUnusedDepositAddressesResponseSchema, {
          depositAddresses: batch.map((i) =>
            create(DepositAddressQueryResultSchema, {
              depositAddress: `bcrt1paddr${i}`,
              userSigningPublicKey: new Uint8Array(33).fill(1),
              verifyingPublicKey: new Uint8Array(33).fill(2),
              leafId: `leaf-${i}`,
            }),
          ),
          offset: BigInt(offset + batch.length),
        });
      },
    });
    const unused = await client.deposits.unused();
    expect(pages).toBe(2);
    expect(unused).toHaveLength(101);
    expect(unused[0]).toStrictEqual({
      address: "bcrt1paddr0",
      leafId: "leaf-0",
      verifyingPublicKey: new Uint8Array(33).fill(2),
    });
    signer.dispose();
  });
});

describe("deposits.claim", () => {
  const LEAF_ID = "01989abc-def0-7abc-89ab-cdef01234567";

  function buildClaimFixture() {
    const sharePub = secp256k1.Point.BASE.multiply(SHARE_SECRET).toBytes(true);
    const verifyingKeyFor = (signingPub: Uint8Array): Uint8Array =>
      secp256k1.Point.BASE.multiply(SHARE_SECRET)
        .add(secp256k1.Point.fromBytes(signingPub))
        .toBytes(true);
    return { sharePub, verifyingKeyFor };
  }

  test("signs the three jobs and finalizes tree creation", async () => {
    const signer = await testSigner();
    const [signingPublicKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const { verifyingKeyFor } = buildClaimFixture();
    const verifyingKey = verifyingKeyFor(signingPublicKey!);
    const address = p2trAddressFromPublicKey(verifyingKey, "regtest");
    const transaction = depositTxTo(address, 100_000n);

    let commitmentsReq: GetSigningCommitmentsRequest | undefined;
    let finalizeReq: FinalizeDepositTreeCreationRequest | undefined;
    const opCommitments = Object.fromEntries(
      OPERATORS.map((op, i) => [
        op.identifier,
        {
          hiding: secp256k1.Point.BASE.toBytes(true),
          binding: secp256k1.Point.BASE.multiply(BigInt(i + 2)).toBytes(true),
        },
      ]),
    );
    const client = makeClient(signer, {
      query_unused_deposit_addresses: () =>
        create(QueryUnusedDepositAddressesResponseSchema, {
          depositAddresses: [
            create(DepositAddressQueryResultSchema, {
              depositAddress: address,
              userSigningPublicKey: signingPublicKey!,
              verifyingPublicKey: verifyingKey,
              leafId: LEAF_ID,
            }),
          ],
          offset: 1n,
        }),
      get_signing_commitments: (req) => {
        commitmentsReq = req;
        return create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: [0, 1, 2].map(() =>
            create(RequestedSigningCommitmentsSchema, {
              signingNonceCommitments: opCommitments,
            }),
          ),
        });
      },
      finalize_deposit_tree_creation: (req) => {
        finalizeReq = req;
        return create(FinalizeDepositTreeCreationResponseSchema, {
          rootNode: fakeLeaf("claimed-1"),
        });
      },
    });

    const leaf = await client.deposits.claim({ transaction });
    expect(leaf.id).toBe("claimed-1");

    const commitments = required(commitmentsReq, "get_signing_commitments request");
    expect(commitments.count).toBe(3);
    expect(commitments.nodeIdCount).toBe(1);

    const finalize = required(finalizeReq, "finalize_deposit_tree_creation request");
    const utxo = required(finalize.onChainUtxo, "onChainUtxo");
    expect(utxo.vout).toBe(0);
    expect(bytesToHex(utxo.rawTx)).toBe(bytesToHex(transaction));
    expect(utxo.network).toBe(Network.REGTEST);

    const expected = createRootNodeTx(transaction, 0, "regtest");
    const refunds = createInitialTimelockRefundTxs({
      nodeTx: expected.cpfp.txBytes,
      receivingPublicKey: signingPublicKey!,
      network: "regtest",
    });
    const jobs = [
      finalize.rootTxSigningJob,
      finalize.refundTxSigningJob,
      finalize.directFromCpfpRefundTxSigningJob,
    ];
    const expectedRaw = [
      expected.cpfp.txBytes,
      refunds.cpfpRefund.txBytes,
      refunds.directFromCpfpRefund.txBytes,
    ];
    for (const [i, job] of jobs.entries()) {
      const signingJob = required(job, "signing job");
      expect(bytesToHex(signingJob.rawTx)).toBe(bytesToHex(expectedRaw[i]!));
      expect(bytesToHex(signingJob.signingPublicKey)).toBe(bytesToHex(signingPublicKey!));
      expect(signingJob.userSignature.length).toBeGreaterThan(0);
      const commitmentMap = required(signingJob.signingCommitments, "signing commitments");
      expect(Object.keys(commitmentMap.signingCommitments)).toStrictEqual(
        OPERATORS.map((op) => op.identifier),
      );
    }
    signer.dispose();
  });

  test("rejects when the coordinator returns fewer than three commitments", async () => {
    const signer = await testSigner();
    const [signingPublicKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const { verifyingKeyFor } = buildClaimFixture();
    const verifyingKey = verifyingKeyFor(signingPublicKey!);
    const address = p2trAddressFromPublicKey(verifyingKey, "regtest");
    const transaction = depositTxTo(address, 100_000n);
    const client = makeClient(signer, {
      query_unused_deposit_addresses: () =>
        create(QueryUnusedDepositAddressesResponseSchema, {
          depositAddresses: [
            create(DepositAddressQueryResultSchema, {
              depositAddress: address,
              userSigningPublicKey: signingPublicKey!,
              verifyingPublicKey: verifyingKey,
              leafId: LEAF_ID,
            }),
          ],
          offset: 1n,
        }),
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: [0, 1].map(() =>
            create(RequestedSigningCommitmentsSchema, {
              signingNonceCommitments: {},
            }),
          ),
        }),
    });
    await expect(client.deposits.claim({ transaction })).rejects.toThrow(
      "fewer than three commitments",
    );
    signer.dispose();
  });

  test("rejects a transaction paying to none of the unused addresses", async () => {
    const signer = await testSigner();
    const client = makeClient(signer, {
      query_unused_deposit_addresses: () =>
        create(QueryUnusedDepositAddressesResponseSchema, {
          depositAddresses: [
            create(DepositAddressQueryResultSchema, {
              depositAddress: "bcrt1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3z6qj",
              userSigningPublicKey: new Uint8Array(33).fill(1),
              verifyingPublicKey: new Uint8Array(33).fill(2),
              leafId: LEAF_ID,
            }),
          ],
          offset: 1n,
        }),
    });
    const other = p2trAddressFromPublicKey(secp256k1.Point.BASE.toBytes(true), "regtest");
    await expect(
      client.deposits.claim({ transaction: depositTxTo(other, 100_000n) }),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  });

  test("requires vout when several outputs pay to unused addresses", async () => {
    const signer = await testSigner();
    const [signingPublicKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const { verifyingKeyFor } = buildClaimFixture();
    const addrA = p2trAddressFromPublicKey(verifyingKeyFor(signingPublicKey!), "regtest");
    const addrB = p2trAddressFromPublicKey(
      secp256k1.Point.BASE.multiply(0x99n).toBytes(true),
      "regtest",
    );
    let finalizedVout = -1;
    const client = makeClient(signer, {
      query_unused_deposit_addresses: () =>
        create(QueryUnusedDepositAddressesResponseSchema, {
          depositAddresses: [addrA, addrB].map((depositAddress, i) =>
            create(DepositAddressQueryResultSchema, {
              depositAddress,
              userSigningPublicKey: new Uint8Array(33).fill(1),
              verifyingPublicKey: new Uint8Array(33).fill(2),
              leafId: `leaf-${i}`,
            }),
          ),
          offset: 2n,
        }),
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: [0, 1, 2].map(() =>
            create(RequestedSigningCommitmentsSchema, {
              signingNonceCommitments: Object.fromEntries(
                OPERATORS.map((op, i) => [
                  op.identifier,
                  {
                    hiding: secp256k1.Point.BASE.toBytes(true),
                    binding: secp256k1.Point.BASE.multiply(BigInt(i + 2)).toBytes(true),
                  },
                ]),
              ),
            }),
          ),
        }),
      finalize_deposit_tree_creation: (req) => {
        finalizedVout = required(req.onChainUtxo, "onChainUtxo").vout;
        return create(FinalizeDepositTreeCreationResponseSchema, {
          rootNode: fakeLeaf("claimed-vout"),
        });
      },
    });
    const transaction = depositTxTo(addrA, 100_000n, [addrB]);
    await expect(client.deposits.claim({ transaction })).rejects.toThrow(
      "more than one unused address",
    );
    await expect(client.deposits.claim({ transaction, vout: 1 })).resolves.toBeDefined();
    expect(finalizedVout).toBe(1);
    signer.dispose();
  });
});
