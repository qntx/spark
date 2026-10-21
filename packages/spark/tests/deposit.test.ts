import { create } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { createClient, createRouterTransport } from "@connectrpc/connect";
import { mod } from "@noble/curves/abstract/modular.js";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import { createSparkClientWith } from "../src/client/index.ts";
import { u64ToSats } from "../src/core/assert.ts";
import {
  addressToScript,
  createInitialTimelockRefundTxs,
  createMultiInputRootTx,
  p2trAddressFromPublicKey,
  parseTransaction,
  taprootKeySpendSighash,
} from "../src/core/bitcoin/index.ts";
import { proofOfPossessionDigest } from "../src/core/hashing/statements.ts";
import type { SparkOperatorConfig } from "../src/core/network.ts";
import { queryUnusedDepositAddresses } from "../src/deposit/index.ts";
import { SparkInputError } from "../src/errors/index.ts";
import { createMemorySparkStore } from "../src/exit/store.ts";
import type { SparkStore } from "../src/exit/store.ts";
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
  QueryNodesResponseSchema,
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
  InputSigningData,
  QueryNodesRequest,
  TreeNode,
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

/**
 * A `query_unused_deposit_addresses` handler serving `pageBatch` indices with the SO's offset
 * semantics: a full 100-entry page advances, a short one ends the walk with -1.
 */
function pagedUnusedAddresses(entryAddress: string, entryKey: Uint8Array) {
  return (req: unknown) => {
    const offset = Number((req as { offset: bigint }).offset);
    const batch = pageBatch(offset);
    return create(QueryUnusedDepositAddressesResponseSchema, {
      depositAddresses: batch.map((i) =>
        create(DepositAddressQueryResultSchema, {
          depositAddress: entryAddress,
          userSigningPublicKey: new Uint8Array(33).fill(1),
          verifyingPublicKey: entryKey,
          leafId: `leaf-${i}`,
        }),
      ),
      offset: batch.length === 100 ? BigInt(offset + batch.length) : -1n,
    });
  };
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
  /** When set, the returned address pays to this key instead of `verifyingKey`. */
  addressOfKey?: Uint8Array;
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
  const address = p2trAddressFromPublicKey(options.addressOfKey ?? verifyingKey, "regtest");
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
  query_nodes: (req: unknown) => unknown;
  get_signing_commitments: (req: GetSigningCommitmentsRequest) => unknown;
  finalize_deposit_tree_creation: (req: FinalizeDepositTreeCreationRequest) => unknown;
}>;

/** `query_nodes` fake over `served()`: nodeIds lookups match by id, anything else returns all. */
function nodesQuery(served: () => ReadonlyArray<TreeNode>) {
  return (req: unknown) => {
    const request = req as QueryNodesRequest;
    const all = served();
    if (request.source.case === "nodeIds") {
      const wanted = new Set(request.source.value.nodeIds);
      return create(QueryNodesResponseSchema, {
        nodes: Object.fromEntries(all.filter((node) => wanted.has(node.id)).map((n) => [n.id, n])),
        offset: -1n,
      });
    }
    return create(QueryNodesResponseSchema, {
      nodes: Object.fromEntries(all.map((n) => [n.id, n])),
      offset: -1n,
    });
  };
}

function makeClient(signer: SparkSigner, sparkImpl: SparkImpl, store?: SparkStore) {
  return createSparkClientWith(
    {
      network: "regtest",
      signer,
      fetch: async () => Promise.reject(new Error("no fetch")),
      random: fixedRandom(),
      operators: OPERATORS,
      ...(store === undefined ? {} : { store }),
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

function depositTxTo(
  address: string,
  sats: bigint,
  extraOutputs: string[] = [],
  inputFill = 7,
): Uint8Array {
  const tx = new Transaction({ allowUnknownOutputs: true });
  tx.addInput({ txid: new Uint8Array(32).fill(inputFill), index: 0, sequence: 0 });
  tx.addOutput({ script: addressToScript(address), amount: sats });
  for (const extra of extraOutputs) {
    tx.addOutput({ script: addressToScript(extra), amount: sats });
  }
  return tx.toBytes(true);
}

function fakeLeaf(
  id: string,
  overrides: {
    nodeTx?: Uint8Array;
    refundTx?: Uint8Array;
    verifyingPublicKey?: Uint8Array;
  } = {},
) {
  return create(TreeNodeSchema, {
    id,
    treeId: `tree-${id}`,
    value: 100_000n,
    nodeTx: overrides.nodeTx ?? new Uint8Array([1, 2]),
    refundTx: overrides.refundTx ?? new Uint8Array([3, 4]),
    vout: 0,
    verifyingPublicKey: overrides.verifyingPublicKey ?? new Uint8Array(33).fill(5),
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

  test("rejects an address that does not pay to its verifying key", async () => {
    const signer = await testSigner();
    const client = makeClient(signer, {
      generate_deposit_address: (req) => {
        const fabricated = fabricateDepositAddress({
          signingPublicKey: req.signingPublicKey,
          identityPublicKey: req.identityPublicKey,
          addressOfKey: secp256k1.Point.BASE.toBytes(true),
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
    await expect(client.deposits.newAddress()).rejects.toThrow("does not pay to its verifying key");
    signer.dispose();
  });
});

describe("deposits.unused", () => {
  test("pages query_unused_deposit_addresses until a short page", async () => {
    const signer = await testSigner();
    let pages = 0;
    const entryKey = secp256k1.getPublicKey(new Uint8Array(32).fill(2), true);
    const entryAddress = p2trAddressFromPublicKey(entryKey, "regtest");
    const serve = pagedUnusedAddresses(entryAddress, entryKey);
    const client = makeClient(signer, {
      query_unused_deposit_addresses: (req) => {
        pages += 1;
        return serve(req);
      },
    });
    const unused = await client.deposits.unused();
    expect(pages).toBe(2);
    expect(unused).toHaveLength(101);
    expect(unused[0]).toStrictEqual({
      address: entryAddress,
      leafId: "leaf-0",
      verifyingPublicKey: entryKey,
    });
    signer.dispose();
  });

  test("unused throws when the coordinator never stops returning full pages", async () => {
    const signer = await testSigner();
    let pages = 0;
    const entryKey = secp256k1.getPublicKey(new Uint8Array(32).fill(2), true);
    const entryAddress = p2trAddressFromPublicKey(entryKey, "regtest");
    // Every page full and advancing — the walk must give up at its page bound instead of
    // paginating forever. Three pages stand in for MAX_PAGES: the per-entry script checks
    // are the slow part of a real 1000-page walk, not the loop.
    const spark = createClient(
      SparkService,
      createRouterTransport((router) => {
        router.service(SparkService, {
          query_unused_deposit_addresses: (req: { offset: bigint }) => {
            pages += 1;
            const offset = Number(req.offset);
            return create(QueryUnusedDepositAddressesResponseSchema, {
              depositAddresses: Array.from({ length: 100 }, (_, i) =>
                create(DepositAddressQueryResultSchema, {
                  depositAddress: entryAddress,
                  userSigningPublicKey: new Uint8Array(33).fill(1),
                  verifyingPublicKey: entryKey,
                  leafId: `leaf-${offset + i}`,
                }),
              ),
              offset: BigInt(offset + 100),
            });
          },
        });
      }),
    );
    await expect(
      queryUnusedDepositAddresses({
        spark,
        signer,
        network: "regtest",
        operators: OPERATORS,
        coordinatorIdentifier: COORDINATOR_ID,
        maxPages: 3,
      }),
    ).rejects.toThrow("did not stop returning full pages");
    expect(pages).toBe(3);
    signer.dispose();
  });

  test("unused throws when the coordinator's offset does not advance", async () => {
    const signer = await testSigner();
    const entryKey = secp256k1.getPublicKey(new Uint8Array(32).fill(2), true);
    const entryAddress = p2trAddressFromPublicKey(entryKey, "regtest");
    const client = makeClient(signer, {
      // A full page whose offset rewinds would otherwise paginate forever.
      query_unused_deposit_addresses: () =>
        create(QueryUnusedDepositAddressesResponseSchema, {
          depositAddresses: Array.from({ length: 100 }, (_, i) =>
            create(DepositAddressQueryResultSchema, {
              depositAddress: entryAddress,
              userSigningPublicKey: new Uint8Array(33).fill(1),
              verifyingPublicKey: entryKey,
              leafId: `leaf-${i}`,
            }),
          ),
          offset: 0n,
        }),
    });
    await expect(client.deposits.unused()).rejects.toThrow("non-advancing offset");
    signer.dispose();
  });

  test("rejects an entry whose address does not pay to its verifying key", async () => {
    const signer = await testSigner();
    const address = p2trAddressFromPublicKey(
      secp256k1.getPublicKey(new Uint8Array(32).fill(2), true),
      "regtest",
    );
    const client = makeClient(signer, {
      query_unused_deposit_addresses: () =>
        create(QueryUnusedDepositAddressesResponseSchema, {
          depositAddresses: [
            create(DepositAddressQueryResultSchema, {
              depositAddress: address,
              userSigningPublicKey: new Uint8Array(33).fill(1),
              verifyingPublicKey: secp256k1.Point.BASE.toBytes(true),
              leafId: "leaf-0",
            }),
          ],
          offset: -1n,
        }),
    });
    await expect(client.deposits.unused()).rejects.toThrow("does not pay to its verifying key");
    signer.dispose();
  });
});

describe("deposits.claim", () => {
  const LEAF_ID = "01989abc-def0-7abc-89ab-cdef01234567";

  // The fake SO holds the full aggregate secret of the deposit verifying key, like the real
  // operators' keyshares add up to it — that is what lets it produce the aggregated BIP-340
  // signature a finalized root/refund tx carries.
  const VERIFYING_SECRET = 0xdeadn;
  const OTHER_SECRET = 0x99n;
  const VERIFYING_KEY = secp256k1.Point.BASE.multiply(VERIFYING_SECRET).toBytes(true);
  const OTHER_KEY = secp256k1.Point.BASE.multiply(OTHER_SECRET).toBytes(true);

  /**
   * Attaches to every input of `txBytes` the BIP-340 key-path signature the aggregate would carry,
   * each over its own sighash committing to all `prevouts`. `corruptInput` produces an invalid
   * signature for that one input.
   */
  function signedFinalizedTx(
    txBytes: Uint8Array,
    prevouts: ReadonlyArray<{ script: Uint8Array; amount: number }>,
    secret: bigint,
    verifyingKey: Uint8Array,
    corruptInput?: number,
  ): Uint8Array {
    const point = secp256k1.Point.fromBytes(verifyingKey);
    const evenSecret =
      (point.toAffine().y & 1n) === 0n ? secret : secp256k1.Point.Fn.ORDER - secret;
    const { tweak } = taprootTweakedKey(verifyingKey);
    const tweakedSecret = mod(evenSecret + tweak, secp256k1.Point.Fn.ORDER);
    const tx = Transaction.fromRaw(txBytes, { allowUnknownOutputs: true });
    for (let i = 0; i < tx.inputsLength; i++) {
      const sighash = taprootKeySpendSighash({ transaction: txBytes, inputIndex: i, prevouts });
      tx.updateInput(i, {
        finalScriptWitness: [
          schnorr.sign(
            sighash,
            be32(i === corruptInput ? secret : tweakedSecret),
            new Uint8Array(32).fill(4),
          ),
        ],
      });
    }
    return tx.toBytes(true, true);
  }

  /** Emulates the coordinator: rebuilds the multi-input root from the request, signs it back. */
  function finalizedRootNode(
    req: FinalizeDepositTreeCreationRequest,
    options: {
      secret: bigint;
      verifyingKey: Uint8Array;
      wrongTx?: boolean;
      /** Index of the root input whose signature is invalid. */
      badSigInput?: number;
    },
    id = LEAF_ID,
  ) {
    const utxos = [required(req.onChainUtxo, "onChainUtxo"), ...req.additionalOnChainUtxos];
    const rootTxBytes = createMultiInputRootTx(utxos.map((u) => ({ tx: u.rawTx, vout: u.vout })));
    const refunds = createInitialTimelockRefundTxs({
      nodeTx: rootTxBytes,
      receivingPublicKey: required(req.rootTxSigningJob, "root signing job").signingPublicKey,
      network: "regtest",
    });
    const depositPrevouts = utxos.map((u) => {
      const output = parseTransaction(u.rawTx).getOutput(u.vout);
      return {
        script: required(output.script, "utxo script"),
        amount: u64ToSats(required(output.amount, "utxo amount"), "utxo"),
      };
    });
    const rootOut = parseTransaction(rootTxBytes).getOutput(0);
    const refundPrevouts = [
      {
        script: required(rootOut.script, "root output script"),
        amount: u64ToSats(required(rootOut.amount, "root output amount"), "root output"),
      },
    ];
    return fakeLeaf(id, {
      nodeTx:
        options.wrongTx === true
          ? refunds.directFromCpfpRefund.txBytes
          : signedFinalizedTx(
              rootTxBytes,
              depositPrevouts,
              options.secret,
              options.verifyingKey,
              options.badSigInput,
            ),
      refundTx: signedFinalizedTx(
        refunds.cpfpRefund.txBytes,
        refundPrevouts,
        options.secret,
        options.verifyingKey,
      ),
      verifyingPublicKey: options.verifyingKey,
    });
  }

  test("signs the three jobs and finalizes tree creation", async () => {
    const signer = await testSigner();
    const [signingPublicKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const verifyingKey = VERIFYING_KEY;
    const address = p2trAddressFromPublicKey(verifyingKey, "regtest");
    const transaction = depositTxTo(address, 100_000n);

    let commitmentsReq: GetSigningCommitmentsRequest | undefined;
    let finalizeReq: FinalizeDepositTreeCreationRequest | undefined;
    const served: TreeNode[] = [];
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
      query_nodes: nodesQuery(() => served),
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
          offset: -1n,
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
        const rootNode = finalizedRootNode(req, { secret: VERIFYING_SECRET, verifyingKey });
        served.push(rootNode);
        return create(FinalizeDepositTreeCreationResponseSchema, { rootNode });
      },
    });

    const leaf = await client.deposits.claim({ transaction });
    expect(leaf.id).toBe(LEAF_ID);

    const commitments = required(commitmentsReq, "get_signing_commitments request");
    expect(commitments.count).toBe(3);
    expect(commitments.nodeIdCount).toBe(1);

    const finalize = required(finalizeReq, "finalize_deposit_tree_creation request");
    const utxo = required(finalize.onChainUtxo, "onChainUtxo");
    expect(utxo.vout).toBe(0);
    expect(bytesToHex(utxo.rawTx)).toBe(bytesToHex(transaction));
    expect(utxo.network).toBe(Network.REGTEST);

    const expectedRootTx = createMultiInputRootTx([{ tx: transaction, vout: 0 }]);
    const refunds = createInitialTimelockRefundTxs({
      nodeTx: expectedRootTx,
      receivingPublicKey: signingPublicKey!,
      network: "regtest",
    });
    const jobs = [
      finalize.rootTxSigningJob,
      finalize.refundTxSigningJob,
      finalize.directFromCpfpRefundTxSigningJob,
    ];
    const expectedRaw = [
      expectedRootTx,
      refunds.cpfpRefund.txBytes,
      refunds.directFromCpfpRefund.txBytes,
    ];
    for (const [i, job] of jobs.entries()) {
      const signingJob = required(job, "signing job");
      expect(bytesToHex(signingJob.rawTx)).toBe(
        bytesToHex(required(expectedRaw[i], "expected raw tx")),
      );
      expect(bytesToHex(signingJob.signingPublicKey)).toBe(bytesToHex(signingPublicKey!));
      expect(signingJob.userSignature.length).toBeGreaterThan(0);
      const commitmentMap = required(signingJob.signingCommitments, "signing commitments");
      expect(Object.keys(commitmentMap.signingCommitments)).toStrictEqual(
        OPERATORS.map((op) => op.identifier),
      );
    }
    signer.dispose();
  });

  test("stores the claimed exit chain in the client store", async () => {
    const signer = await testSigner();
    const [signingPublicKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const verifyingKey = VERIFYING_KEY;
    const address = p2trAddressFromPublicKey(verifyingKey, "regtest");
    const transaction = depositTxTo(address, 100_000n);

    const store = createMemorySparkStore();
    const served: TreeNode[] = [];
    const client = makeClient(
      signer,
      {
        query_nodes: nodesQuery(() => served),
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
            offset: -1n,
          }),
        get_signing_commitments: () =>
          create(GetSigningCommitmentsResponseSchema, {
            signingCommitments: [0, 1, 2].map(() =>
              create(RequestedSigningCommitmentsSchema, {
                signingNonceCommitments: {},
              }),
            ),
          }),
        finalize_deposit_tree_creation: (req) => {
          const rootNode = finalizedRootNode(req, { secret: VERIFYING_SECRET, verifyingKey });
          served.push(rootNode);
          return create(FinalizeDepositTreeCreationResponseSchema, { rootNode });
        },
      },
      store,
    );

    const leaf = await client.deposits.claim({ transaction });
    expect(leaf.id).toBe(LEAF_ID);
    const chains = await store.exitChains();
    expect(chains.map((chain) => chain.leafId)).toStrictEqual([LEAF_ID]);
    signer.dispose();
  });

  test("rejects when the coordinator returns fewer than three commitments", async () => {
    const signer = await testSigner();
    const [signingPublicKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const verifyingKey = VERIFYING_KEY;
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
          offset: -1n,
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
      "fewer than 3 commitments",
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
              depositAddress: p2trAddressFromPublicKey(VERIFYING_KEY, "regtest"),
              userSigningPublicKey: new Uint8Array(33).fill(1),
              verifyingPublicKey: VERIFYING_KEY,
              leafId: LEAF_ID,
            }),
          ],
          offset: -1n,
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
    const addrA = p2trAddressFromPublicKey(VERIFYING_KEY, "regtest");
    const addrB = p2trAddressFromPublicKey(OTHER_KEY, "regtest");
    let finalizedVout = -1;
    const served: TreeNode[] = [];
    const client = makeClient(signer, {
      query_nodes: nodesQuery(() => served),
      query_unused_deposit_addresses: () =>
        create(QueryUnusedDepositAddressesResponseSchema, {
          depositAddresses: [
            { depositAddress: addrA, verifyingPublicKey: VERIFYING_KEY },
            { depositAddress: addrB, verifyingPublicKey: OTHER_KEY },
          ].map((entry, i) =>
            create(DepositAddressQueryResultSchema, {
              depositAddress: entry.depositAddress,
              userSigningPublicKey: new Uint8Array(33).fill(1),
              verifyingPublicKey: entry.verifyingPublicKey,
              leafId: `leaf-${i}`,
            }),
          ),
          offset: -1n,
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
        const rootNode = finalizedRootNode(
          req,
          { secret: OTHER_SECRET, verifyingKey: OTHER_KEY },
          "leaf-1",
        );
        served.push(rootNode);
        return create(FinalizeDepositTreeCreationResponseSchema, { rootNode });
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

  /** A claim whose fake coordinator behaves until `finalize_deposit_tree_creation`. */
  async function claimWith(finalize: (req: FinalizeDepositTreeCreationRequest) => unknown) {
    const signer = await testSigner();
    const address = p2trAddressFromPublicKey(VERIFYING_KEY, "regtest");
    const transaction = depositTxTo(address, 100_000n);
    const client = makeClient(signer, {
      query_unused_deposit_addresses: () =>
        create(QueryUnusedDepositAddressesResponseSchema, {
          depositAddresses: [
            create(DepositAddressQueryResultSchema, {
              depositAddress: address,
              userSigningPublicKey: new Uint8Array(33).fill(1),
              verifyingPublicKey: VERIFYING_KEY,
              leafId: LEAF_ID,
            }),
          ],
          offset: -1n,
        }),
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: [0, 1, 2].map(() =>
            create(RequestedSigningCommitmentsSchema, {
              signingNonceCommitments: {},
            }),
          ),
        }),
      finalize_deposit_tree_creation: finalize,
    });
    return { signer, client, transaction };
  }

  test("rejects a finalized root node carrying another verifying key", async () => {
    const { signer, client, transaction } = await claimWith((req) =>
      create(FinalizeDepositTreeCreationResponseSchema, {
        rootNode: finalizedRootNode(req, { secret: OTHER_SECRET, verifyingKey: OTHER_KEY }),
      }),
    );
    await expect(client.deposits.claim({ transaction })).rejects.toThrow(
      "unexpected verifying key",
    );
    signer.dispose();
  });

  test("rejects a finalized root node that is not the transaction we built", async () => {
    const { signer, client, transaction } = await claimWith((req) =>
      create(FinalizeDepositTreeCreationResponseSchema, {
        rootNode: finalizedRootNode(req, {
          secret: VERIFYING_SECRET,
          verifyingKey: VERIFYING_KEY,
          wrongTx: true,
        }),
      }),
    );
    await expect(client.deposits.claim({ transaction })).rejects.toThrow(
      "not the transaction we built",
    );
    signer.dispose();
  });

  test("rejects a finalized root node with an invalid taproot signature", async () => {
    const { signer, client, transaction } = await claimWith((req) =>
      create(FinalizeDepositTreeCreationResponseSchema, {
        rootNode: finalizedRootNode(req, {
          secret: VERIFYING_SECRET,
          verifyingKey: VERIFYING_KEY,
          badSigInput: 0,
        }),
      }),
    );
    await expect(client.deposits.claim({ transaction })).rejects.toThrow(
      "invalid taproot signature",
    );
    signer.dispose();
  });

  /** Operator commitments that differ per commitment index, so input ordering is observable. */
  function opCommitmentsAt(index: number) {
    return Object.fromEntries(
      OPERATORS.map((op) => [
        op.identifier,
        {
          hiding: secp256k1.Point.BASE.toBytes(true),
          binding: secp256k1.Point.BASE.multiply(BigInt(index + 2)).toBytes(true),
        },
      ]),
    );
  }

  /** A claimMany fake SO reporting `addresses` as unused, each bound to `leafId`. */
  function claimManyClient(
    signer: SparkSigner,
    addresses: ReadonlyArray<{ address: string; verifyingKey: Uint8Array; leafId: string }>,
    hooks: {
      onCommitments?: (req: GetSigningCommitmentsRequest) => void;
      onFinalize?: (req: FinalizeDepositTreeCreationRequest) => void;
      commitmentCount?: number;
      leafId?: string;
    } = {},
  ) {
    const served: TreeNode[] = [];
    return makeClient(signer, {
      query_nodes: nodesQuery(() => served),
      query_unused_deposit_addresses: () =>
        create(QueryUnusedDepositAddressesResponseSchema, {
          depositAddresses: addresses.map((entry) =>
            create(DepositAddressQueryResultSchema, {
              depositAddress: entry.address,
              userSigningPublicKey: new Uint8Array(33).fill(1),
              verifyingPublicKey: entry.verifyingKey,
              leafId: entry.leafId,
            }),
          ),
          offset: -1n,
        }),
      get_signing_commitments: (req) => {
        hooks.onCommitments?.(req);
        return create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: Array.from({ length: hooks.commitmentCount ?? 8 }, (_, i) =>
            create(RequestedSigningCommitmentsSchema, {
              signingNonceCommitments: opCommitmentsAt(i),
            }),
          ),
        });
      },
      finalize_deposit_tree_creation: (req) => {
        hooks.onFinalize?.(req);
        const rootNode = finalizedRootNode(req, {
          secret: VERIFYING_SECRET,
          verifyingKey: VERIFYING_KEY,
        });
        served.push(rootNode);
        return create(FinalizeDepositTreeCreationResponseSchema, { rootNode });
      },
    });
  }

  test("claimMany consolidates two UTXOs of one address into one leaf", async () => {
    const signer = await testSigner();
    const address = p2trAddressFromPublicKey(VERIFYING_KEY, "regtest");
    const txA = depositTxTo(address, 60_000n, [], 7);
    const txB = depositTxTo(address, 40_000n, [], 8);
    let commitmentsReq: GetSigningCommitmentsRequest | undefined;
    let finalizeReq: FinalizeDepositTreeCreationRequest | undefined;
    const client = claimManyClient(
      signer,
      [{ address, verifyingKey: VERIFYING_KEY, leafId: LEAF_ID }],
      {
        onCommitments: (req) => {
          commitmentsReq = req;
        },
        onFinalize: (req) => {
          finalizeReq = req;
        },
      },
    );

    const leaf = await client.deposits.claimMany({
      outputs: [{ transaction: txA }, { transaction: txB }],
    });
    expect(leaf.id).toBe(LEAF_ID);

    // N root inputs + 2 refund jobs = 4 commitments, in the SO's order.
    expect(required(commitmentsReq, "commitments request").count).toBe(4);

    const finalize = required(finalizeReq, "finalize request");
    const primary = required(finalize.onChainUtxo, "onChainUtxo");
    expect(primary.vout).toBe(0);
    expect(bytesToHex(primary.rawTx)).toBe(bytesToHex(txA));
    // The rest of the UTXOs ride additional_on_chain_utxos in caller order.
    expect(finalize.additionalOnChainUtxos).toHaveLength(1);
    const [additionalUtxo] = finalize.additionalOnChainUtxos;
    expect(additionalUtxo?.vout).toBe(0);
    expect(bytesToHex(required(additionalUtxo, "additional utxo").rawTx)).toBe(bytesToHex(txB));

    const rootJob = required(finalize.rootTxSigningJob, "root signing job");
    expect(parseTransaction(rootJob.rawTx).inputsLength).toBe(2);
    // Root input 0 rides the job's fields with commitments index 0; input 1 rides
    // additional_inputs with commitments index 1 — order proves the mapping.
    const bindings = (job: Pick<InputSigningData, "signingCommitments">) =>
      Object.fromEntries(
        Object.entries(
          required(job.signingCommitments, "signing commitments").signingCommitments,
        ).map(([identifier, commitment]) => [identifier, bytesToHex(commitment.binding)]),
      );
    const bindingsAt = (index: number) =>
      Object.fromEntries(
        OPERATORS.map((op) => [
          op.identifier,
          bytesToHex(secp256k1.Point.BASE.multiply(BigInt(index + 2)).toBytes(true)),
        ]),
      );
    expect(bindings(rootJob)).toStrictEqual(bindingsAt(0));
    expect(rootJob.additionalInputs).toHaveLength(1);
    const [additional] = rootJob.additionalInputs;
    expect(bindings(required(additional, "additional input"))).toStrictEqual(bindingsAt(1));
    // The fake signed each input over its own sighash committing to BOTH deposit prevouts;
    // the client's post-finalize verification just proved its targets did the same.
    signer.dispose();
  });

  test("claimMany rejects outputs paying different addresses", async () => {
    const signer = await testSigner();
    const addressA = p2trAddressFromPublicKey(VERIFYING_KEY, "regtest");
    const addressB = p2trAddressFromPublicKey(OTHER_KEY, "regtest");
    const client = claimManyClient(signer, [
      { address: addressA, verifyingKey: VERIFYING_KEY, leafId: LEAF_ID },
      { address: addressB, verifyingKey: OTHER_KEY, leafId: "leaf-b" },
    ]);
    await expect(
      client.deposits.claimMany({
        outputs: [
          { transaction: depositTxTo(addressA, 60_000n, [], 7) },
          { transaction: depositTxTo(addressB, 40_000n, [], 8) },
        ],
      }),
    ).rejects.toThrow("different deposit addresses");
    signer.dispose();
  });

  test("claimMany rejects a duplicate outpoint", async () => {
    const signer = await testSigner();
    const address = p2trAddressFromPublicKey(VERIFYING_KEY, "regtest");
    const transaction = depositTxTo(address, 60_000n);
    const client = claimManyClient(signer, [
      { address, verifyingKey: VERIFYING_KEY, leafId: LEAF_ID },
    ]);
    await expect(
      client.deposits.claimMany({ outputs: [{ transaction }, { transaction }] }),
    ).rejects.toThrow("duplicate deposit outpoint");
    signer.dispose();
  });

  test("claimMany rejects an empty outputs list", async () => {
    const signer = await testSigner();
    const client = claimManyClient(signer, []);
    await expect(client.deposits.claimMany({ outputs: [] })).rejects.toThrow("must not be empty");
    signer.dispose();
  });

  test("claimMany rejects more than 11 outputs", async () => {
    const signer = await testSigner();
    const address = p2trAddressFromPublicKey(VERIFYING_KEY, "regtest");
    const transaction = depositTxTo(address, 60_000n);
    const client = claimManyClient(signer, [
      { address, verifyingKey: VERIFYING_KEY, leafId: LEAF_ID },
    ]);
    await expect(
      client.deposits.claimMany({
        outputs: Array.from({ length: 12 }, () => ({ transaction })),
      }),
    ).rejects.toThrow("at most 11 outputs");
    signer.dispose();
  });

  test("claimMany rejects an output paying no unused address", async () => {
    const signer = await testSigner();
    const address = p2trAddressFromPublicKey(VERIFYING_KEY, "regtest");
    const stranger = p2trAddressFromPublicKey(OTHER_KEY, "regtest");
    const client = claimManyClient(signer, [
      { address, verifyingKey: VERIFYING_KEY, leafId: LEAF_ID },
    ]);
    await expect(
      client.deposits.claimMany({
        outputs: [
          { transaction: depositTxTo(address, 60_000n, [], 7) },
          { transaction: depositTxTo(stranger, 40_000n, [], 8) },
        ],
      }),
    ).rejects.toThrow("none of the unused addresses");
    signer.dispose();
  });

  test("claimMany rejects a deposit address without a leafId", async () => {
    const signer = await testSigner();
    const address = p2trAddressFromPublicKey(VERIFYING_KEY, "regtest");
    const client = claimManyClient(signer, [{ address, verifyingKey: VERIFYING_KEY, leafId: "" }]);
    await expect(
      client.deposits.claimMany({ outputs: [{ transaction: depositTxTo(address, 60_000n) }] }),
    ).rejects.toThrow("not a single-use leaf deposit address");
    signer.dispose();
  });

  test("claimMany rejects a finalized root with a bad signature on input 1", async () => {
    const signer = await testSigner();
    const address = p2trAddressFromPublicKey(VERIFYING_KEY, "regtest");
    const client = makeClient(signer, {
      query_unused_deposit_addresses: () =>
        create(QueryUnusedDepositAddressesResponseSchema, {
          depositAddresses: [
            create(DepositAddressQueryResultSchema, {
              depositAddress: address,
              userSigningPublicKey: new Uint8Array(33).fill(1),
              verifyingPublicKey: VERIFYING_KEY,
              leafId: LEAF_ID,
            }),
          ],
          offset: -1n,
        }),
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: [0, 1, 2, 3].map((i) =>
            create(RequestedSigningCommitmentsSchema, {
              signingNonceCommitments: opCommitmentsAt(i),
            }),
          ),
        }),
      finalize_deposit_tree_creation: (req) =>
        create(FinalizeDepositTreeCreationResponseSchema, {
          rootNode: finalizedRootNode(req, {
            secret: VERIFYING_SECRET,
            verifyingKey: VERIFYING_KEY,
            badSigInput: 1,
          }),
        }),
    });
    await expect(
      client.deposits.claimMany({
        outputs: [
          { transaction: depositTxTo(address, 60_000n, [], 7) },
          { transaction: depositTxTo(address, 40_000n, [], 8) },
        ],
      }),
    ).rejects.toThrow("nodeTx input 1 has an invalid taproot signature");
    signer.dispose();
  });
});
