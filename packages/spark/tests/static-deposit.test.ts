import { create, toBinary } from "@bufbuild/protobuf";
import { timestampFromMs } from "@bufbuild/protobuf/wkt";
import { createRouterTransport, createClient } from "@connectrpc/connect";
import { mod } from "@noble/curves/abstract/modular.js";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import type { ClientContext } from "../src/client/context.ts";
import { claimInboundTransfer } from "../src/client/deposits.ts";
import { createSparkClientWith } from "../src/client/index.ts";
import {
  createCurrentTimelockRefundTxs,
  p2trAddressFromPublicKey,
  p2trScriptFromPublicKey,
  parseTransaction,
  taprootKeySpendSighash,
  txId,
  verifyFinalizedTaprootSignature,
} from "../src/core/bitcoin/index.ts";
import {
  proofOfPossessionDigest,
  sendLeafSigningDigest,
  staticDepositStatementDigest,
} from "../src/core/hashing/statements.ts";
import { createMutex } from "../src/core/mutex.ts";
import type { SparkOperatorConfig } from "../src/core/network.ts";
import type { DepositCoordinator } from "../src/deposit/index.ts";
import {
  claimStaticDeposit,
  generateStaticDepositAddress,
  MIN_STATIC_REFUND_FEE_SATS,
  queryStaticDepositUtxos,
  refundStaticDeposit,
} from "../src/deposit/static.ts";
import { SparkError, SparkInputError } from "../src/errors/index.ts";
import { createMemorySparkStore } from "../src/exit/store.ts";
import {
  ChallengeSchema,
  ProtectedChallengeSchema,
  SparkAuthnService,
} from "../src/proto/gen/spark_authn_pb.ts";
import {
  AddressSchema,
  ClaimTransferResponseSchema,
  DepositAddressProofSchema,
  DepositAddressQueryResultSchema,
  GenerateStaticDepositAddressResponseSchema,
  GetSigningCommitmentsResponseSchema,
  GetUtxosForAddressResponseSchema,
  InitiateStaticDepositUtxoRefundResponseSchema,
  Network,
  QueryTransfersResponseSchema,
  RequestedSigningCommitmentsSchema,
  SigningKeyshareSchema,
  SigningResultSchema,
  SparkService,
  TransferLeafSchema,
  TransferSchema,
  TransferStatus,
  TransferType,
  TreeNodeSchema,
  TreeNodeStatus,
  UTXOSchema,
} from "../src/proto/gen/spark_pb.ts";
import type {
  ClaimTransferRequest,
  GenerateStaticDepositAddressRequest,
  InitiateStaticDepositUtxoRefundRequest,
  Transfer,
  TransferLeaf,
} from "../src/proto/gen/spark_pb.ts";
import { ProtectedChallengeSchema as SspProtectedChallengeSchema } from "../src/proto/gen/ssp_authn_pb.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import type { SparkSigner } from "../src/signer/index.ts";
import type { SspClient, SspClaimStaticDepositRequest } from "../src/ssp/index.ts";
import { loadWasmBackend } from "./support/backend.ts";
import {
  be32,
  frostGroup,
  lagrangeCoefficient,
  operatorSetup,
  operatorSignatureShares,
  taprootTweakedKey,
} from "./support/frost.ts";

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
const THRESHOLD = 2;
const SHARE_PUB = secp256k1.Point.BASE.multiply(0x5ea5n).toBytes(true);
const TRANSFER_ID = "01989abc-def0-7000-8000-abcdef012345";
const STATIC_LEAF_ID = "01989abc-def0-7abc-89ab-cdef01234567";

/** Unwraps values the router captures — a missing capture is a test bug, not a branch. */
function required<T>(value: T | undefined, name: string): T {
  if (value === undefined) {
    throw new Error(`${name} was not captured`);
  }
  return value;
}

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

const STATIC_PUB_SLOT = { type: "static-deposit", index: 0 } as const;

const SSP_SECRET = new Uint8Array(32).fill(77);
const SSP_IDENTITY = secp256k1.getPublicKey(SSP_SECRET, true);

async function staticPublicKey(signer: SparkSigner): Promise<Uint8Array> {
  const keys = await signer.publicKeys([STATIC_PUB_SLOT]);
  return required(keys[0], "static-deposit public key");
}

/**
 * The operator share `verifyingKey − signingPublicKey` signs the proof of possession under its
 * taproot-tweaked secret — same construction as the single-use deposit fixture.
 */
function proofOfPossession(options: {
  shareSecret: bigint;
  identityPublicKey: Uint8Array;
  address: string;
}): Uint8Array {
  const sharePoint = secp256k1.Point.BASE.multiply(options.shareSecret);
  const digest = proofOfPossessionDigest(
    options.identityPublicKey,
    sharePoint.toBytes(true),
    options.address,
  );
  const { tweak } = taprootTweakedKey(sharePoint.toBytes(true));
  const evenSecret =
    (sharePoint.toAffine().y & 1n) === 0n
      ? options.shareSecret
      : secp256k1.Point.Fn.ORDER - options.shareSecret;
  const tweakedSecret = mod(evenSecret + tweak, secp256k1.Point.Fn.ORDER);
  return schnorr.sign(digest, be32(tweakedSecret), new Uint8Array(32).fill(4));
}

/**
 * A fabricated static-deposit Address proto: `verifyingKey = share + signing`, P2TR address, PoP
 * under the tweaked share, and per-operator `sha256(address)` ECDSA signatures — the coordinator's
 * included unless `skipOperator` names it (static addresses verify it).
 */
function fabricateStaticAddress(options: {
  signingPublicKey: Uint8Array;
  identityPublicKey: Uint8Array;
  shareSecret?: bigint;
  verifyingKey?: Uint8Array;
  address?: string;
  corruptProof?: boolean;
  skipOperator?: string;
}): {
  address: string;
  verifyingKey: Uint8Array;
  proofOfPossessionSignature: Uint8Array;
  addressSignatures: Record<string, Uint8Array>;
} {
  const shareSecret = options.shareSecret ?? 0x5ea5n;
  const verifyingKey =
    options.verifyingKey ??
    secp256k1.Point.BASE.multiply(shareSecret)
      .add(secp256k1.Point.fromBytes(options.signingPublicKey))
      .toBytes(true);
  const address = options.address ?? p2trAddressFromPublicKey(verifyingKey, "regtest");
  let pop = proofOfPossession({
    shareSecret,
    identityPublicKey: options.identityPublicKey,
    address,
  });
  if (options.corruptProof === true) {
    pop = schnorr.sign(sha256(pop), new Uint8Array(32).fill(3), new Uint8Array(32).fill(4));
  }
  const addressHash = sha256(utf8ToBytes(address));
  const addressSignatures: Record<string, Uint8Array> = {};
  for (const operator of OPERATORS) {
    if (operator.identifier === options.skipOperator) {
      continue;
    }
    addressSignatures[operator.identifier] = secp256k1.sign(
      addressHash,
      OPERATOR_SECRETS[operator.id]!,
      { format: "der", prehash: false },
    );
  }
  return { address, verifyingKey, proofOfPossessionSignature: pop, addressSignatures };
}

function staticAddressResponse(fabricated: {
  address: string;
  verifyingKey: Uint8Array;
  proofOfPossessionSignature: Uint8Array;
  addressSignatures: Record<string, Uint8Array>;
}) {
  return create(GenerateStaticDepositAddressResponseSchema, {
    depositAddress: create(AddressSchema, {
      address: fabricated.address,
      verifyingKey: fabricated.verifyingKey,
      isStatic: true,
      depositAddressProof: create(DepositAddressProofSchema, {
        addressSignatures: fabricated.addressSignatures,
        proofOfPossessionSignature: fabricated.proofOfPossessionSignature,
      }),
    }),
  });
}

/** A synthetic confirmed transaction paying `script` — what a coop-exit payout would look like. */
function txPaying(script: Uint8Array, sats: bigint, extraScript?: Uint8Array): Uint8Array {
  const tx = new Transaction({ allowUnknownOutputs: true });
  tx.addInput({ txid: new Uint8Array(32).fill(7), index: 0, sequence: 0 });
  tx.addOutput({ script, amount: sats });
  if (extraScript !== undefined) {
    tx.addOutput({ script: extraScript, amount: sats });
  }
  return tx.toBytes(true);
}

type SparkImpl = Partial<{
  generate_static_deposit_address: (req: GenerateStaticDepositAddressRequest) => unknown;
  get_utxos_for_address: (req: {
    address: string;
    offset: bigint;
    limit: bigint;
    excludeClaimed: boolean;
  }) => unknown;
  initiate_static_deposit_utxo_refund: (req: InitiateStaticDepositUtxoRefundRequest) => unknown;
  get_signing_commitments: (req: unknown) => unknown;
  query_transfers_by_id: (req: unknown) => unknown;
  query_pending_transfers: (req: unknown) => unknown;
  claim_transfer: (req: ClaimTransferRequest) => unknown;
}>;

function fakeSpark(impl: SparkImpl) {
  const transport = createRouterTransport((router) => {
    router.service(SparkService, impl as never);
  });
  return createClient(SparkService, transport);
}

function coordinator(signer: SparkSigner, impl: SparkImpl): DepositCoordinator {
  return {
    spark: fakeSpark(impl),
    signer,
    network: "regtest",
    operators: OPERATORS,
    coordinatorIdentifier: COORDINATOR_ID,
  };
}

function unstubbedSsp(): SspClient {
  const reject = async () => Promise.reject(new Error("unstubbed"));
  return {
    swapFeeEstimate: reject,
    requestSwap: reject,
    requestLightningReceive: reject,
    requestLightningSend: reject,
    lightningSendFeeEstimate: reject,
    lightningSendRequest: reject,
    lightningReceiveRequest: reject,
    coopExitFeeQuote: reject,
    requestCoopExit: reject,
    completeCoopExit: reject,
    coopExitRequest: reject,
    staticDepositQuote: reject,
    claimStaticDeposit: reject,
  };
}

function fakeSsp(handlers: {
  quoteCredit?: number;
  quoteSignature?: string;
  claimTransferId?: string;
}): {
  ssp: SspClient;
  quoteRequests: Array<{ transactionId: string; outputIndex: number; network: string }>;
  claimRequests: SspClaimStaticDepositRequest[];
} {
  const quoteRequests: Array<{ transactionId: string; outputIndex: number; network: string }> = [];
  const claimRequests: SspClaimStaticDepositRequest[] = [];
  return {
    ssp: {
      ...unstubbedSsp(),
      staticDepositQuote: async (request) => {
        quoteRequests.push(request);
        return Promise.resolve({
          creditAmountSats: handlers.quoteCredit ?? 0,
          signature: handlers.quoteSignature ?? "cd".repeat(64),
        });
      },
      claimStaticDeposit: async (request) => {
        claimRequests.push(request);
        return Promise.resolve(
          handlers.claimTransferId === undefined ? {} : { transferId: handlers.claimTransferId },
        );
      },
    },
    quoteRequests,
    claimRequests,
  };
}

/** The static address fixture for one signer — handler for generate_static_deposit_address. */
async function staticFixture(
  signer: SparkSigner,
  overrides?: {
    shareSecret?: bigint;
    verifyingKey?: Uint8Array;
    address?: string;
    corruptProof?: boolean;
    skipOperator?: string;
  },
) {
  const signingPublicKey = await staticPublicKey(signer);
  const identityPublicKey = await signer.identityPublicKey();
  const fabricated = fabricateStaticAddress({
    signingPublicKey,
    identityPublicKey,
    ...(overrides?.shareSecret === undefined ? {} : { shareSecret: overrides.shareSecret }),
    ...(overrides?.verifyingKey === undefined ? {} : { verifyingKey: overrides.verifyingKey }),
    ...(overrides?.address === undefined ? {} : { address: overrides.address }),
    ...(overrides?.corruptProof === undefined ? {} : { corruptProof: overrides.corruptProof }),
    ...(overrides?.skipOperator === undefined ? {} : { skipOperator: overrides.skipOperator }),
  });
  const script = p2trScriptFromPublicKey(fabricated.verifyingKey, "regtest");
  return { signingPublicKey, identityPublicKey, fabricated, script };
}

function staticAddressHandler(fabricated: ReturnType<typeof fabricateStaticAddress>) {
  return () => staticAddressResponse(fabricated);
}

describe("deposits.staticAddress", () => {
  test("returns the coordinator-validated static address", async () => {
    const signer = await testSigner();
    const { signingPublicKey, identityPublicKey, fabricated } = await staticFixture(signer);
    let captured: GenerateStaticDepositAddressRequest | undefined;
    const result = await generateStaticDepositAddress(
      coordinator(signer, {
        generate_static_deposit_address: (req) => {
          captured = req;
          return staticAddressResponse(fabricated);
        },
      }),
    );
    expect(result).toBe(fabricated.address);
    const request = required(captured, "generate_static_deposit_address request");
    expect(request.hashVariant).toBe(1); // HashVariant.V2
    expect(request.network).toBe(Network.REGTEST);
    expect(bytesToHex(request.signingPublicKey)).toBe(bytesToHex(signingPublicKey));
    expect(bytesToHex(request.identityPublicKey)).toBe(bytesToHex(identityPublicKey));
    signer.dispose();
  });

  test("rejects a bad proof of possession", async () => {
    const signer = await testSigner();
    const { fabricated } = await staticFixture(signer, { corruptProof: true });
    await expect(
      generateStaticDepositAddress(
        coordinator(signer, { generate_static_deposit_address: staticAddressHandler(fabricated) }),
      ),
    ).rejects.toThrow("proof of possession is invalid");
    signer.dispose();
  });

  test("rejects a missing coordinator address signature", async () => {
    const signer = await testSigner();
    const { fabricated } = await staticFixture(signer, { skipOperator: COORDINATOR_ID });
    await expect(
      generateStaticDepositAddress(
        coordinator(signer, { generate_static_deposit_address: staticAddressHandler(fabricated) }),
      ),
    ).rejects.toThrow(`missing signature from operator ${COORDINATOR_ID}`);
    signer.dispose();
  });

  test("rejects an address that does not pay its verifying key", async () => {
    const signer = await testSigner();
    const other = p2trAddressFromPublicKey(secp256k1.Point.BASE.toBytes(true), "regtest");
    const { fabricated } = await staticFixture(signer, { address: other });
    await expect(
      generateStaticDepositAddress(
        coordinator(signer, { generate_static_deposit_address: staticAddressHandler(fabricated) }),
      ),
    ).rejects.toThrow("does not pay to its verifying key");
    signer.dispose();
  });
});

describe("deposits.staticUtxos", () => {
  test("pages get_utxos_for_address and validates returned raw transactions", async () => {
    const signer = await testSigner();
    const { fabricated, script } = await staticFixture(signer);
    const depositTx = txPaying(script, 5000n);
    const txid = txId(depositTx);
    const fillerScript = p2trScriptFromPublicKey(secp256k1.Point.BASE.toBytes(true), "regtest");
    const pages: number[] = [];
    const utxos = await queryStaticDepositUtxos(
      coordinator(signer, {
        generate_static_deposit_address: staticAddressHandler(fabricated),
        get_utxos_for_address: (req) => {
          const all = [
            create(UTXOSchema, {
              txid: hexToBytes(txid),
              vout: 0,
              network: Network.REGTEST,
              rawTx: depositTx,
            }),
            ...Array.from({ length: 99 }, () =>
              create(UTXOSchema, {
                txid: hexToBytes(txId(txPaying(fillerScript, 1000n, undefined))),
                vout: 0,
                network: Network.REGTEST,
              }),
            ),
            create(UTXOSchema, {
              txid: hexToBytes("ef".repeat(32)),
              vout: 1,
              network: Network.REGTEST,
            }),
          ];
          pages.push(Number(req.offset));
          const batch = all.slice(Number(req.offset), Number(req.offset) + 100);
          return create(GetUtxosForAddressResponseSchema, {
            utxos: batch,
            offset: req.offset + BigInt(batch.length),
          });
        },
      }),
    );
    expect(pages).toStrictEqual([0, 100]);
    expect(utxos).toHaveLength(101);
    expect(utxos[0]).toStrictEqual({
      txid,
      vout: 0,
      amountSats: 5000,
      rawTx: depositTx,
    });
    expect(utxos[100]).toStrictEqual({ txid: "ef".repeat(32), vout: 1 });
    signer.dispose();
  });

  test("rejects a returned raw transaction whose txid does not match", async () => {
    const signer = await testSigner();
    const { fabricated, script } = await staticFixture(signer);
    await expect(
      queryStaticDepositUtxos(
        coordinator(signer, {
          generate_static_deposit_address: staticAddressHandler(fabricated),
          get_utxos_for_address: () =>
            create(GetUtxosForAddressResponseSchema, {
              utxos: [
                create(UTXOSchema, {
                  txid: hexToBytes("ab".repeat(32)),
                  vout: 0,
                  network: Network.REGTEST,
                  rawTx: txPaying(script, 5000n),
                }),
              ],
              offset: 1n,
            }),
        }),
      ),
    ).rejects.toThrow(SparkError);
    signer.dispose();
  });

  test("rejects a returned raw transaction that does not pay the static address", async () => {
    const signer = await testSigner();
    const { fabricated } = await staticFixture(signer);
    const foreign = txPaying(
      p2trScriptFromPublicKey(secp256k1.Point.BASE.toBytes(true), "regtest"),
      5000n,
    );
    await expect(
      queryStaticDepositUtxos(
        coordinator(signer, {
          generate_static_deposit_address: staticAddressHandler(fabricated),
          get_utxos_for_address: () =>
            create(GetUtxosForAddressResponseSchema, {
              utxos: [
                create(UTXOSchema, {
                  txid: hexToBytes(txId(foreign)),
                  vout: 0,
                  network: Network.REGTEST,
                  rawTx: foreign,
                }),
              ],
              offset: 1n,
            }),
        }),
      ),
    ).rejects.toThrow("does not pay the static address");
    signer.dispose();
  });

  test("throws when the coordinator never stops returning full pages", async () => {
    const signer = await testSigner();
    const { fabricated } = await staticFixture(signer);
    // Every page full and advancing — the walk must give up at its page bound instead of
    // paginating forever. Three pages stand in for MAX_PAGES.
    let pages = 0;
    await expect(
      queryStaticDepositUtxos({
        ...coordinator(signer, {
          generate_static_deposit_address: staticAddressHandler(fabricated),
          get_utxos_for_address: (req) => {
            pages += 1;
            return create(GetUtxosForAddressResponseSchema, {
              utxos: Array.from({ length: 100 }, (_, i) =>
                create(UTXOSchema, {
                  txid: hexToBytes("ab".repeat(32)),
                  vout: i,
                  network: Network.REGTEST,
                }),
              ),
              offset: req.offset + 100n,
            });
          },
        }),
        maxPages: 3,
      }),
    ).rejects.toThrow("did not stop returning full pages");
    expect(pages).toBe(3);
    signer.dispose();
  });

  test("throws when the coordinator's offset does not advance", async () => {
    const signer = await testSigner();
    const { fabricated } = await staticFixture(signer);
    await expect(
      queryStaticDepositUtxos(
        coordinator(signer, {
          generate_static_deposit_address: staticAddressHandler(fabricated),
          // A full page whose offset rewinds would otherwise paginate forever.
          get_utxos_for_address: () =>
            create(GetUtxosForAddressResponseSchema, {
              utxos: Array.from({ length: 100 }, (_, i) =>
                create(UTXOSchema, {
                  txid: hexToBytes("ab".repeat(32)),
                  vout: i,
                  network: Network.REGTEST,
                }),
              ),
              offset: 0n,
            }),
        }),
      ),
    ).rejects.toThrow("non-advancing offset");
    signer.dispose();
  });
});

describe("claimStaticDeposit", () => {
  const UTXO_SATS = 5000n;
  const QUOTE_CREDIT = 4800;

  async function claimFixture(signer: SparkSigner) {
    const { fabricated, script, signingPublicKey, identityPublicKey } = await staticFixture(signer);
    const depositTx = txPaying(script, UTXO_SATS);
    const txid = txId(depositTx);
    return { fabricated, script, signingPublicKey, identityPublicKey, depositTx, txid };
  }

  function claimCoordinator(
    signer: SparkSigner,
    fabricated: ReturnType<typeof fabricateStaticAddress>,
    utxos?: Array<{ txid: string; vout: number; rawTx?: Uint8Array }>,
  ) {
    return coordinator(signer, {
      generate_static_deposit_address: staticAddressHandler(fabricated),
      get_utxos_for_address: () =>
        create(GetUtxosForAddressResponseSchema, {
          utxos: (utxos ?? []).map((utxo) =>
            create(UTXOSchema, {
              txid: hexToBytes(utxo.txid),
              vout: utxo.vout,
              network: Network.REGTEST,
              rawTx: utxo.rawTx ?? new Uint8Array(0),
            }),
          ),
          offset: BigInt(utxos?.length ?? 0),
        }),
    });
  }

  test("quotes, signs the claim statement, and sends the sealed secret key", async () => {
    const signer = await testSigner();
    const { fabricated, txid, depositTx, identityPublicKey, signingPublicKey } =
      await claimFixture(signer);
    const ssp = fakeSsp({ quoteCredit: QUOTE_CREDIT, claimTransferId: "ssp-transfer-1" });
    let sealed: Uint8Array | undefined;
    let claimCalls = 0;
    const spied: SparkSigner = {
      ...signer,
      claimStaticDeposit: async (request) => {
        claimCalls += 1;
        expect(request.sspIdentityPublicKey).toStrictEqual(SSP_IDENTITY);
        const result = await signer.claimStaticDeposit(request);
        sealed = new Uint8Array(result.encryptedSecretKey);
        return result;
      },
    };
    const result = await claimStaticDeposit(
      { ...claimCoordinator(spied, fabricated), ssp: ssp.ssp, sspIdentityPublicKey: SSP_IDENTITY },
      { txid, vout: 0, maxFeeSats: 500, rawTx: depositTx },
    );
    expect(claimCalls).toBe(1);
    expect(result).toStrictEqual({
      creditAmountSats: QUOTE_CREDIT,
      feeSats: Number(UTXO_SATS) - QUOTE_CREDIT,
      transferId: "ssp-transfer-1",
    });
    const quote = required(ssp.quoteRequests[0], "static deposit quote request");
    expect(quote.transactionId).toBe(txid);
    expect(quote.outputIndex).toBe(0);
    const claim = required(ssp.claimRequests[0], "claim_static_deposit request");
    expect(claim.creditAmountSats).toBe(QUOTE_CREDIT);
    // The identity signature covers the exact claim statement the SSP expects.
    const digest = staticDepositStatementDigest({
      transactionId: txid,
      outputIndex: 0,
      network: "regtest",
      requestType: "fixed",
      creditAmountSats: QUOTE_CREDIT,
      payload: hexToBytes(claim.quoteSignature),
    });
    expect(
      secp256k1.verify(hexToBytes(claim.signature), digest, identityPublicKey, {
        format: "der",
        prehash: false,
      }),
    ).toBe(true);
    // The request carries the ECIES-sealed key: decrypting it with the SSP secret yields the
    // static-deposit key — the signer test proves the signer-side plaintext wipe.
    const ciphertext = required(sealed, "sealed secret key");
    const crypto = await loadWasmBackend();
    const secret = crypto.eciesDecrypt(SSP_SECRET, ciphertext);
    try {
      expect(secret).toHaveLength(32);
      expect(secp256k1.getPublicKey(secret, true)).toStrictEqual(signingPublicKey);
    } finally {
      secret.fill(0);
    }
    expect(claim.encryptedSecretKey).toBe(bytesToHex(ciphertext));
    signer.dispose();
  });

  test("rejects a malformed quote signature before asking the signer for the key", async () => {
    const signer = await testSigner();
    const { fabricated, txid, depositTx } = await claimFixture(signer);
    let claimCalls = 0;
    const spied: SparkSigner = {
      ...signer,
      claimStaticDeposit: async (request) => {
        claimCalls += 1;
        return signer.claimStaticDeposit(request);
      },
    };
    await expect(
      claimStaticDeposit(
        {
          ...claimCoordinator(spied, fabricated),
          ssp: fakeSsp({ quoteCredit: QUOTE_CREDIT, quoteSignature: "zz" }).ssp,
          sspIdentityPublicKey: SSP_IDENTITY,
        },
        { txid, vout: 0, maxFeeSats: 500, rawTx: depositTx },
      ),
    ).rejects.toMatchObject({ code: "unexpected_response" });
    expect(claimCalls).toBe(0);
    signer.dispose();
  });

  test("rejects a non-positive credit quote before asking the signer for the key", async () => {
    const signer = await testSigner();
    const { fabricated, txid, depositTx } = await claimFixture(signer);
    let claimCalls = 0;
    const spied: SparkSigner = {
      ...signer,
      claimStaticDeposit: async (request) => {
        claimCalls += 1;
        return signer.claimStaticDeposit(request);
      },
    };
    await expect(
      claimStaticDeposit(
        {
          ...claimCoordinator(spied, fabricated),
          ssp: fakeSsp({ quoteCredit: 0 }).ssp,
          sspIdentityPublicKey: SSP_IDENTITY,
        },
        { txid, vout: 0, maxFeeSats: 500, rawTx: depositTx },
      ),
    ).rejects.toThrow("credits 0 sats");
    expect(claimCalls).toBe(0);
    signer.dispose();
  });

  test("rejects a fee over maxFeeSats before asking the signer for the key", async () => {
    const signer = await testSigner();
    const { fabricated, txid, depositTx } = await claimFixture(signer);
    let claimCalls = 0;
    const spied: SparkSigner = {
      ...signer,
      claimStaticDeposit: async (request) => {
        claimCalls += 1;
        return signer.claimStaticDeposit(request);
      },
    };
    await expect(
      claimStaticDeposit(
        {
          ...claimCoordinator(spied, fabricated),
          ssp: fakeSsp({ quoteCredit: QUOTE_CREDIT }).ssp,
          sspIdentityPublicKey: SSP_IDENTITY,
        },
        { txid, vout: 0, maxFeeSats: 199, rawTx: depositTx },
      ),
    ).rejects.toThrow("exceeds maxFeeSats 199");
    expect(claimCalls).toBe(0);
    signer.dispose();
  });

  test("rejects a caller rawTx whose txid does not match", async () => {
    const signer = await testSigner();
    const { fabricated, script } = await claimFixture(signer);
    const other = txPaying(script, UTXO_SATS);
    await expect(
      claimStaticDeposit(
        {
          ...claimCoordinator(signer, fabricated),
          ssp: fakeSsp({}).ssp,
          sspIdentityPublicKey: SSP_IDENTITY,
        },
        { txid: "ab".repeat(32), vout: 0, maxFeeSats: 500, rawTx: other },
      ),
    ).rejects.toThrow("is not transaction");
    signer.dispose();
  });

  test("rejects a caller rawTx whose output does not pay the static address", async () => {
    const signer = await testSigner();
    const { fabricated } = await claimFixture(signer);
    const foreign = txPaying(
      p2trScriptFromPublicKey(secp256k1.Point.BASE.toBytes(true), "regtest"),
      UTXO_SATS,
    );
    await expect(
      claimStaticDeposit(
        {
          ...claimCoordinator(signer, fabricated),
          ssp: fakeSsp({}).ssp,
          sspIdentityPublicKey: SSP_IDENTITY,
        },
        { txid: txId(foreign), vout: 0, maxFeeSats: 500, rawTx: foreign },
      ),
    ).rejects.toThrow("does not pay our static address");
    signer.dispose();
  });

  test("asks for rawTx when neither the caller nor the SO can supply the transaction", async () => {
    const signer = await testSigner();
    const { fabricated, txid } = await claimFixture(signer);
    await expect(
      claimStaticDeposit(
        {
          ...claimCoordinator(signer, fabricated, [{ txid, vout: 0 }]),
          ssp: fakeSsp({}).ssp,
          sspIdentityPublicKey: SSP_IDENTITY,
        },
        { txid, vout: 0, maxFeeSats: 500 },
      ),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  });

  test("throws when the SO keeps returning full UTXO pages without the output", async () => {
    const signer = await testSigner();
    const { fabricated, txid } = await claimFixture(signer);
    // Every page full, advancing, and never carrying the requested txid — the scan must give
    // up at its page bound instead of paginating forever.
    let pages = 0;
    await expect(
      claimStaticDeposit(
        {
          ...coordinator(signer, {
            generate_static_deposit_address: staticAddressHandler(fabricated),
            get_utxos_for_address: (req) => {
              pages += 1;
              return create(GetUtxosForAddressResponseSchema, {
                utxos: Array.from({ length: 100 }, (_, i) =>
                  create(UTXOSchema, {
                    txid: hexToBytes("cd".repeat(32)),
                    vout: i,
                    network: Network.REGTEST,
                  }),
                ),
                offset: req.offset + 100n,
              });
            },
          }),
          ssp: fakeSsp({}).ssp,
          sspIdentityPublicKey: SSP_IDENTITY,
          maxPages: 3,
        },
        { txid, vout: 0, maxFeeSats: 500 },
      ),
    ).rejects.toThrow("did not stop returning full pages");
    expect(pages).toBe(3);
    signer.dispose();
  });

  test("uses the SO's raw_tx for an unlisted caller-less claim", async () => {
    const signer = await testSigner();
    const { fabricated, txid, depositTx } = await claimFixture(signer);
    const ssp = fakeSsp({ quoteCredit: QUOTE_CREDIT });
    const result = await claimStaticDeposit(
      {
        ...claimCoordinator(signer, fabricated, [{ txid, vout: 0, rawTx: depositTx }]),
        ssp: ssp.ssp,
        sspIdentityPublicKey: SSP_IDENTITY,
      },
      { txid, vout: 0, maxFeeSats: 500 },
    );
    expect(result.feeSats).toBe(Number(UTXO_SATS) - QUOTE_CREDIT);
    signer.dispose();
  });
});

describe("claimInboundTransfer", () => {
  const CREDIT = 4800;

  /** A pending SSP→identity transfer whose only distinguishing claim fixture is the leaf id. */
  function inboundTransfer(options: {
    id: string;
    leafId: string;
    receiverIdentity: Uint8Array;
    sender?: Uint8Array;
    totalSats?: bigint;
    createdMs?: number;
    status?: TransferStatus;
  }): Transfer {
    return create(TransferSchema, {
      id: options.id,
      senderIdentityPublicKey: options.sender ?? SSP_IDENTITY,
      receiverIdentityPublicKey: options.receiverIdentity,
      status: options.status ?? TransferStatus.SENDER_KEY_TWEAKED,
      type: TransferType.TRANSFER,
      network: Network.REGTEST,
      totalValue: options.totalSats ?? BigInt(CREDIT),
      createdTime: timestampFromMs(options.createdMs ?? 1),
      leaves: [
        create(TransferLeafSchema, {
          leaf: create(TreeNodeSchema, {
            id: options.leafId,
            treeId: `tree-${options.leafId}`,
            value: BigInt(CREDIT),
            nodeTx: new Uint8Array(4),
            refundTx: new Uint8Array(4),
            verifyingPublicKey: new Uint8Array(33).fill(5),
            ownerIdentityPublicKey: options.receiverIdentity,
            ownerSigningPublicKey: new Uint8Array(33).fill(6),
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
          secretCipher: new Uint8Array(8),
          sig: { case: "signature" as const, value: new Uint8Array(64) },
        }),
      ],
    });
  }

  function inboundContext(signer: SparkSigner, impl: SparkImpl): ClientContext {
    return {
      coordinatorConnection: { spark: fakeSpark(impl) },
      signer,
      network: "regtest",
      config: { ssp: { identityPublicKey: SSP_IDENTITY } },
      leafLock: createMutex(),
      sleep: async () => Promise.resolve(),
      transferCoordinator: {
        spark: fakeSpark(impl),
        signer,
        network: "regtest",
        operators: OPERATORS,
        threshold: THRESHOLD,
      },
      storeChainsFor: async () => Promise.resolve(),
    } as unknown as ClientContext;
  }

  test("claims the oldest SSP transfer whose total matches the credit", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const pending = [
      // Newer matching transfer first — selection must sort by created time, not response order.
      inboundTransfer({
        id: "t-new",
        leafId: "leaf-new",
        receiverIdentity: identity,
        createdMs: 200,
      }),
      inboundTransfer({
        id: "t-old",
        leafId: "leaf-old",
        receiverIdentity: identity,
        createdMs: 100,
      }),
      // Distractors the credit amount and sender rule out.
      inboundTransfer({
        id: "t-other-total",
        leafId: "leaf-other",
        receiverIdentity: identity,
        totalSats: 9999n,
        createdMs: 50,
      }),
      inboundTransfer({
        id: "t-other-sender",
        leafId: "leaf-other-sender",
        receiverIdentity: identity,
        sender: new Uint8Array(33).fill(8),
        createdMs: 40,
      }),
    ];
    const context = inboundContext(signer, {
      query_pending_transfers: () =>
        create(QueryTransfersResponseSchema, { transfers: pending, offset: -1n }),
    });
    // The selected transfer reaches claimTransfer and fails there on its (stub) leaf signature —
    // the leaf id in the error proves the oldest matching candidate was picked.
    await expect(claimInboundTransfer(context, CREDIT)).rejects.toThrow("leaf leaf-old");
    signer.dispose();
  });

  test("returns no leaves when no pending transfer matches the credit", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const context = inboundContext(signer, {
      query_pending_transfers: () =>
        create(QueryTransfersResponseSchema, {
          transfers: [
            inboundTransfer({
              id: "t-1",
              leafId: "leaf-1",
              receiverIdentity: identity,
              totalSats: 100n,
            }),
          ],
          offset: -1n,
        }),
    });
    await expect(claimInboundTransfer(context, CREDIT)).resolves.toStrictEqual([]);
    signer.dispose();
  });

  test("rejects a reported transfer whose total differs from the credit", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const context = inboundContext(signer, {
      query_transfers_by_id: () =>
        create(QueryTransfersResponseSchema, {
          transfers: [
            inboundTransfer({
              id: "t-reported",
              leafId: "leaf-reported",
              receiverIdentity: identity,
              totalSats: 100n,
            }),
          ],
        }),
    });
    await expect(claimInboundTransfer(context, CREDIT, "t-reported")).rejects.toThrow(
      "does not match the credited 4800 sats",
    );
    signer.dispose();
  });

  test("rejects a reported transfer that is not the SSP's payment to us", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const context = inboundContext(signer, {
      query_transfers_by_id: () =>
        create(QueryTransfersResponseSchema, {
          transfers: [
            inboundTransfer({
              id: "t-reported",
              leafId: "leaf-reported",
              receiverIdentity: identity,
              sender: new Uint8Array(33).fill(8),
            }),
          ],
        }),
    });
    await expect(claimInboundTransfer(context, CREDIT, "t-reported")).rejects.toThrow(
      "not the SSP's payment to us",
    );
    signer.dispose();
  });

  test("accepts a reported transfer that matches id, sender and credit", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const context = inboundContext(signer, {
      query_transfers_by_id: () =>
        create(QueryTransfersResponseSchema, {
          transfers: [
            inboundTransfer({
              id: "t-reported",
              leafId: "leaf-reported",
              receiverIdentity: identity,
            }),
          ],
        }),
    });
    // Validation passed — the claim itself fails on the stub leaf signature, naming its leaf.
    await expect(claimInboundTransfer(context, CREDIT, "t-reported")).rejects.toThrow(
      "leaf leaf-reported",
    );
    signer.dispose();
  });
});

describe("refundStaticDeposit", () => {
  const UTXO_SATS = 10_000n;

  /** A real FROST group where the signer's static-deposit secret is the user share. */
  async function frostFixture(signer: SparkSigner) {
    const statement = {
      kind: "static-deposit-claim" as const,
      network: "regtest" as const,
      txid: new Uint8Array(32),
      vout: 0,
      creditAmountSats: 1,
      sspSignature: hexToBytes("cd".repeat(64)),
    };
    const { encryptedSecretKey } = await signer.claimStaticDeposit({
      index: 0,
      statement,
      sspIdentityPublicKey: SSP_IDENTITY,
    });
    const crypto = await loadWasmBackend();
    const secretKey = crypto.eciesDecrypt(SSP_SECRET, encryptedSecretKey);
    const userSecret = bytesToNumberBE(secretKey);
    secretKey.fill(0);
    const group = frostGroup(
      userSecret,
      [11111n, 44444n, 77777n],
      [
        [22222n, 33333n],
        [55555n, 66666n],
        [88888n, 99999n],
      ],
    );
    return group;
  }

  /** The operator share behind `verifyingKey − static signing key` — for the PoP fixture. */
  function shareSecretOf(group: { operators: ReadonlyArray<{ id: bigint; secret: bigint }> }) {
    const xs = group.operators.map((o) => o.id);
    let acc = 0n;
    for (const o of group.operators) {
      acc = mod(acc + lagrangeCoefficient(o.id, xs) * o.secret, secp256k1.Point.Fn.ORDER);
    }
    return acc;
  }

  async function refundFixture(signer: SparkSigner) {
    const group = await frostFixture(signer);
    const shareSecret = shareSecretOf(group);
    const signingPublicKey = await staticPublicKey(signer);
    const identityPublicKey = await signer.identityPublicKey();
    const fabricated = fabricateStaticAddress({
      signingPublicKey,
      identityPublicKey,
      shareSecret,
      verifyingKey: group.verifyingKey,
    });
    const script = p2trScriptFromPublicKey(group.verifyingKey, "regtest");
    const depositTx = txPaying(script, UTXO_SATS);
    const txid = txId(depositTx);
    return { group, fabricated, script, depositTx, txid, identityPublicKey };
  }

  /**
   * The SO side of `initiate_static_deposit_utxo_refund`: real FROST operator shares over the
   * refund sighash so the signer's aggregate produces a signature that verifies.
   */
  function refundHandlers(options: {
    fabricated: ReturnType<typeof fabricateStaticAddress>;
    group: {
      operators: ReadonlyArray<{
        id: bigint;
        secret: bigint;
        hidingNonce: bigint;
        bindingNonce: bigint;
      }>;
      verifyingKey: Uint8Array;
    };
    script: Uint8Array;
    amountSats: bigint;
    capture?: { request?: InitiateStaticDepositUtxoRefundRequest };
    verifyingKey?: Uint8Array;
  }): SparkImpl {
    const fixtures = operatorSetup(options.group.operators);
    return {
      generate_static_deposit_address: staticAddressHandler(options.fabricated),
      initiate_static_deposit_utxo_refund: (req) => {
        if (options.capture !== undefined) {
          options.capture.request = req;
        }
        const job = required(req.refundTxSigningJob, "refund tx signing job");
        const sighash = taprootKeySpendSighash({
          transaction: job.rawTx,
          inputIndex: 0,
          prevouts: [{ script: options.script, amount: Number(options.amountSats) }],
        });
        const shares = operatorSignatureShares({
          operators: options.group.operators,
          verifyingKey: options.group.verifyingKey,
          userCommitment: required(job.signingNonceCommitment, "signing nonce commitment"),
          message: sighash,
        });
        return create(InitiateStaticDepositUtxoRefundResponseSchema, {
          refundTxSigningResult: create(SigningResultSchema, {
            publicKeys: Object.fromEntries(fixtures.map((f) => [f.identifier, f.publicKey])),
            signingNonceCommitments: Object.fromEntries(
              fixtures.map((f) => [f.identifier, f.commitment]),
            ),
            signatureShares: Object.fromEntries(fixtures.map((f, i) => [f.identifier, shares[i]!])),
          }),
          depositAddress: create(DepositAddressQueryResultSchema, {
            depositAddress: options.fabricated.address,
            userSigningPublicKey: new Uint8Array(33).fill(2),
            verifyingPublicKey: options.verifyingKey ?? options.group.verifyingKey,
          }),
        });
      },
    };
  }

  function destinationScript(): Uint8Array {
    return p2trScriptFromPublicKey(secp256k1.Point.BASE.multiply(0xdeadn).toBytes(true), "regtest");
  }

  test("builds a v3 one-in one-out refund and returns a verifying signature", async () => {
    const signer = await testSigner();
    const { group, fabricated, script, depositTx, txid, identityPublicKey } =
      await refundFixture(signer);
    const capture: { request?: InitiateStaticDepositUtxoRefundRequest } = {};
    const destination = p2trAddressFromPublicKey(
      secp256k1.Point.BASE.multiply(0xdeadn).toBytes(true),
      "regtest",
    );
    const result = await refundStaticDeposit(
      coordinator(
        signer,
        refundHandlers({
          fabricated,
          group,
          script,
          amountSats: UTXO_SATS,
          capture,
        }),
      ),
      {
        txid,
        vout: 0,
        destinationAddress: destination,
        feeRateSatPerVbyte: 1,
        rawTx: depositTx,
      },
    );

    // Signed transaction shape: v3, one input spending the deposit output, one destination output.
    const signed = parseTransaction(result.transaction);
    expect(result.txid).toBe(signed.id);
    expect(signed.version).toBe(3);
    expect(signed.inputsLength).toBe(1);
    expect(signed.outputsLength).toBe(1);
    const input = signed.getInput(0);
    expect(bytesToHex(required(input.txid, "refund input txid"))).toBe(txid);
    expect(input.index).toBe(0);
    expect(required(input.finalScriptWitness, "refund witness")).toHaveLength(1);
    const output = signed.getOutput(0);
    const expectedFee = MIN_STATIC_REFUND_FEE_SATS; // ceil(1 × estimateVbytes(1,1))
    expect(output.amount).toBe(UTXO_SATS - BigInt(expectedFee));
    expect(output.script).toStrictEqual(destinationScript());

    // The RPC request carries display-order txid bytes, the unsigned v3 tx and UNSPECIFIED
    // hash variant (the legacy concat digest upstream's JS SDK also sends).
    const request = required(capture.request, "initiate_static_deposit_utxo_refund request");
    expect(request.hashVariant).toBe(0);
    const utxo = required(request.onChainUtxo, "onChainUtxo");
    expect(bytesToHex(utxo.txid)).toBe(txid);
    expect(utxo.vout).toBe(0);
    expect(utxo.network).toBe(Network.REGTEST);
    const job = required(request.refundTxSigningJob, "refund tx signing job");
    expect(bytesToHex(job.signingPublicKey)).toBe(bytesToHex(await staticPublicKey(signer)));
    const unsigned = parseTransaction(job.rawTx);
    expect(unsigned.version).toBe(3);
    expect(unsigned.getInput(0).finalScriptWitness).toBeUndefined();

    // The user signature is the identity's DER signature over the refund statement.
    const sighash = taprootKeySpendSighash({
      transaction: job.rawTx,
      inputIndex: 0,
      prevouts: [{ script, amount: Number(UTXO_SATS) }],
    });
    const digest = staticDepositStatementDigest({
      transactionId: txid,
      outputIndex: 0,
      network: "regtest",
      requestType: "refund",
      creditAmountSats: Number(UTXO_SATS) - expectedFee,
      payload: sighash,
    });
    expect(
      secp256k1.verify(request.userSignature, digest, identityPublicKey, {
        format: "der",
        prehash: false,
      }),
    ).toBe(true);

    // The returned signature verifies under the tweaked verifying key — the same check
    // refundStaticDeposit runs before returning.
    expect(
      verifyFinalizedTaprootSignature(result.transaction, sighash, group.verifyingKey, 0),
    ).toBe(true);
    signer.dispose();
  });

  test("floors the fee below which a refund cannot relay", async () => {
    const signer = await testSigner();
    const { group, fabricated, script, depositTx, txid } = await refundFixture(signer);
    await expect(
      refundStaticDeposit(
        coordinator(signer, refundHandlers({ fabricated, group, script, amountSats: UTXO_SATS })),
        {
          txid,
          vout: 0,
          destinationAddress: p2trAddressFromPublicKey(
            secp256k1.Point.BASE.multiply(0xdeadn).toBytes(true),
            "regtest",
          ),
          feeRateSatPerVbyte: 0.5,
          rawTx: depositTx,
        },
      ),
    ).rejects.toThrow("below the 194 sat minimum");
    signer.dispose();
  });

  test("rejects a refund output below the destination dust limit", async () => {
    const signer = await testSigner();
    const { group, fabricated, script } = await refundFixture(signer);
    // 194 fee + 306 output < the 330-sat P2TR dust limit.
    const dustyTx = txPaying(script, 500n);
    await expect(
      refundStaticDeposit(
        coordinator(signer, refundHandlers({ fabricated, group, script, amountSats: 500n })),
        {
          txid: txId(dustyTx),
          vout: 0,
          destinationAddress: p2trAddressFromPublicKey(
            secp256k1.Point.BASE.multiply(0xdeadn).toBytes(true),
            "regtest",
          ),
          feeRateSatPerVbyte: 1,
          rawTx: dustyTx,
        },
      ),
    ).rejects.toThrow("dust limit");
    signer.dispose();
  });

  test("rejects a destination address for another network", async () => {
    const signer = await testSigner();
    const { group, fabricated, script, depositTx, txid } = await refundFixture(signer);
    const mainnetAddress = p2trAddressFromPublicKey(
      secp256k1.Point.BASE.multiply(0xdeadn).toBytes(true),
      "mainnet",
    );
    await expect(
      refundStaticDeposit(
        coordinator(signer, refundHandlers({ fabricated, group, script, amountSats: UTXO_SATS })),
        {
          txid,
          vout: 0,
          destinationAddress: mainnetAddress,
          feeRateSatPerVbyte: 1,
          rawTx: depositTx,
        },
      ),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  });

  test("rejects a returned verifying key that does not bind the deposit output", async () => {
    const signer = await testSigner();
    const { group, fabricated, script, depositTx, txid } = await refundFixture(signer);
    const foreign = secp256k1.Point.BASE.multiply(0xbeefn).toBytes(true);
    await expect(
      refundStaticDeposit(
        coordinator(
          signer,
          refundHandlers({
            fabricated,
            group,
            script,
            amountSats: UTXO_SATS,
            verifyingKey: foreign,
          }),
        ),
        {
          txid,
          vout: 0,
          destinationAddress: p2trAddressFromPublicKey(
            secp256k1.Point.BASE.multiply(0xdeadn).toBytes(true),
            "regtest",
          ),
          feeRateSatPerVbyte: 1,
          rawTx: depositTx,
        },
      ),
    ).rejects.toThrow("does not bind the deposit output");
    signer.dispose();
  });
});

describe("deposits.claimStatic via the client", () => {
  const UTXO_SATS = 5000n;
  const CREDIT_SATS = 4800;

  /** A valid ssp_authn.ProtectedChallenge issued to `publicKey`, base64-encoded. */
  function protectedChallengeFor(publicKey: Uint8Array): string {
    return base64.encode(
      toBinary(SspProtectedChallengeSchema, {
        $typeName: "ssp_authn.ProtectedChallenge",
        version: 1,
        challenge: {
          $typeName: "ssp_authn.Challenge",
          version: 1,
          timestamp: 1_786_974_052n,
          nonce: new Uint8Array(32).fill(9),
          publicKey,
        },
        serverHmac: new Uint8Array(32).fill(7),
      }),
    );
  }

  /** Minimal SSP GraphQL responder: auth, static_deposit_quote, claim_static_deposit. */
  function sspFetch(
    identity: Uint8Array,
    options: { transferId?: string | null },
    captured: Array<{ operationName: string; variables: Record<string, unknown> }>,
  ): typeof globalThis.fetch {
    return async (_input, init) => {
      const body = JSON.parse(String(init?.body)) as {
        operationName: string;
        variables: Record<string, unknown>;
      };
      captured.push({ operationName: body.operationName, variables: body.variables });
      const json = async (data: unknown) => Promise.resolve(Response.json({ data }));
      switch (body.operationName) {
        case "GetChallenge":
          return json({
            get_challenge: {
              get_challenge_output_protected_challenge: protectedChallengeFor(identity),
            },
          });
        case "VerifyChallenge":
          return json({
            verify_challenge: {
              verify_challenge_output_session_token: "ssp-token-1",
              verify_challenge_output_valid_until: new Date(
                Date.now() + 30 * 60 * 1000,
              ).toISOString(),
            },
          });
        case "StaticDepositQuote":
          return json({
            static_deposit_quote: {
              __typename: "StaticDepositQuoteOutput",
              static_deposit_quote_output_transaction_id: body.variables["transaction_id"],
              static_deposit_quote_output_output_index: body.variables["output_index"],
              static_deposit_quote_output_network: "REGTEST",
              static_deposit_quote_output_credit_amount_sats: CREDIT_SATS,
              static_deposit_quote_output_signature: "cd".repeat(70),
            },
          });
        case "ClaimStaticDeposit":
          return json({
            claim_static_deposit: {
              __typename: "ClaimStaticDepositOutput",
              claim_static_deposit_output_transfer_id:
                options.transferId === undefined ? TRANSFER_ID : options.transferId,
            },
          });
        default:
          return new Response("not found", { status: 404 });
      }
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

  function verifyingKeyFor(signingPublicKey: Uint8Array): Uint8Array {
    return secp256k1.Point.fromBytes(SHARE_PUB)
      .add(secp256k1.Point.fromBytes(signingPublicKey))
      .toBytes(true);
  }

  /** An inbound SSP transfer whose leaf cipher seals a fresh secret to our identity. */
  async function sspTransfer(signer: SparkSigner): Promise<Transfer> {
    const identity = await signer.identityPublicKey();
    const receivedSecret = new Uint8Array(32).fill(88);
    const receivedPublicKey = secp256k1.getPublicKey(receivedSecret, true);
    const crypto = await loadWasmBackend();
    const secretCipher = crypto.eciesEncrypt(identity, receivedSecret, new Uint8Array(32).fill(6));
    const verifyingKey = verifyingKeyFor(receivedPublicKey);
    const nodeTx = new Transaction({ allowUnknownOutputs: true });
    nodeTx.addInput({ txid: new Uint8Array(32).fill(7), index: 0, sequence: 0 });
    nodeTx.addOutput({
      script: p2trScriptFromPublicKey(verifyingKey, "regtest"),
      amount: BigInt(CREDIT_SATS),
    });
    const nodeTxBytes = nodeTx.toBytes(true);
    const intermediateRefundTx = createCurrentTimelockRefundTxs({
      nodeTx: nodeTxBytes,
      sequence: 1900,
      receivingPublicKey: receivedPublicKey,
      network: "regtest",
    }).cpfpRefund.txBytes;
    const signature = secp256k1.sign(
      sendLeafSigningDigest(STATIC_LEAF_ID, TRANSFER_ID, secretCipher),
      SSP_SECRET,
      { prehash: false, lowS: true },
    );
    const leaf = create(TransferLeafSchema, {
      leaf: create(TreeNodeSchema, {
        id: STATIC_LEAF_ID,
        treeId: `tree-${STATIC_LEAF_ID}`,
        value: BigInt(CREDIT_SATS),
        nodeTx: nodeTxBytes,
        refundTx: intermediateRefundTx,
        vout: 0,
        verifyingPublicKey: verifyingKey,
        ownerIdentityPublicKey: identity,
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
        createdTime: timestampFromMs(1_700_000_000_000),
        updatedTime: timestampFromMs(1_700_000_000_000),
      }),
      secretCipher,
      sig: { case: "signature", value: signature },
      intermediateRefundTx,
    });
    return create(TransferSchema, {
      id: TRANSFER_ID,
      senderIdentityPublicKey: SSP_IDENTITY,
      receiverIdentityPublicKey: identity,
      status: TransferStatus.SENDER_KEY_TWEAKED,
      type: TransferType.TRANSFER,
      network: Network.REGTEST,
      totalValue: BigInt(CREDIT_SATS),
      leaves: [leaf],
    });
  }

  /** The leaf a real claim_transfer response carries, finalized under our LEAF key. */
  async function claimedLeaf(signer: SparkSigner, leaf: TransferLeaf): Promise<TransferLeaf> {
    const inner = required(leaf.leaf, "leaf");
    const [newKey] = await signer.publicKeys([{ type: "leaf", leafId: inner.id }]);
    const leafKey = required(newKey, "leaf key");
    return create(TransferLeafSchema, {
      ...leaf,
      leaf: create(TreeNodeSchema, {
        ...inner,
        // The finalized leaf's refund is the one the receiver signed — it pays the new LEAF key.
        refundTx: createCurrentTimelockRefundTxs({
          nodeTx: inner.nodeTx,
          sequence: 1900,
          receivingPublicKey: leafKey,
          network: "regtest",
        }).cpfpRefund.txBytes,
        verifyingPublicKey: verifyingKeyFor(leafKey),
        ownerSigningPublicKey: leafKey,
        signingKeyshare: create(SigningKeyshareSchema, {
          ownerIdentifiers: OPERATORS.map((op) => op.identifier),
          threshold: THRESHOLD,
          publicKey: SHARE_PUB,
          publicShares: {},
        }),
      }),
    });
  }

  function makeClient(
    signer: SparkSigner,
    sparkImpl: SparkImpl,
    sspFetchImpl: typeof globalThis.fetch,
    store = createMemorySparkStore(),
    sleeps?: number[],
  ) {
    return {
      store,
      client: createSparkClientWith(
        {
          network: "regtest",
          signer,
          fetch: sspFetchImpl,
          random: fixedRandom(),
          operators: OPERATORS,
          store,
          ssp: {
            baseUrl: "https://ssp.test",
            graphqlPath: "graphql",
            identityPublicKey: SSP_IDENTITY,
          },
          ...(sleeps === undefined
            ? {}
            : {
                sleep: async (ms) => {
                  sleeps.push(ms);
                  return Promise.resolve();
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
      ),
    };
  }

  test("claims the UTXO then claims and stores the SSP's inbound transfer", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const pending = await sspTransfer(signer);
    const { fabricated, script } = await staticFixture(signer);
    const depositTx = txPaying(script, UTXO_SATS);
    const txid = txId(depositTx);
    const sspRequests: Array<{ operationName: string; variables: Record<string, unknown> }> = [];
    let claimReq: ClaimTransferRequest | undefined;
    const { client, store } = makeClient(
      signer,
      {
        generate_static_deposit_address: staticAddressHandler(fabricated),
        query_transfers_by_id: () => create(QueryTransfersResponseSchema, { transfers: [pending] }),
        get_signing_commitments: () =>
          create(GetSigningCommitmentsResponseSchema, {
            signingCommitments: commitmentGroup(3),
          }),
        claim_transfer: async (req) => {
          claimReq = req;
          return create(ClaimTransferResponseSchema, {
            transfer: create(TransferSchema, {
              id: req.transferId,
              senderIdentityPublicKey: SSP_IDENTITY,
              receiverIdentityPublicKey: identity,
              status: TransferStatus.COMPLETED,
              type: TransferType.TRANSFER,
              network: Network.REGTEST,
              leaves: [await claimedLeaf(signer, required(pending.leaves[0], "leaf"))],
            }),
          });
        },
      },
      sspFetch(identity, {}, sspRequests),
    );

    const result = await client.deposits.claimStatic({
      txid,
      vout: 0,
      maxFeeSats: 500,
      rawTx: depositTx,
    });
    expect(result.creditAmountSats).toBe(CREDIT_SATS);
    expect(result.feeSats).toBe(Number(UTXO_SATS) - CREDIT_SATS);
    expect(result.transferId).toBe(TRANSFER_ID);
    expect(result.leaves.map((leaf) => leaf.id)).toStrictEqual([STATIC_LEAF_ID]);

    const claimCall = required(
      sspRequests.find((r) => r.operationName === "ClaimStaticDeposit"),
      "claim_static_deposit call",
    );
    expect(claimCall.variables["request_type"]).toBeUndefined();
    expect(claimCall.variables["deposit_secret_key"]).toBeUndefined();
    expect(claimCall.variables["encrypted_deposit_secret_key"]).toBeTypeOf("string");
    expect(claimCall.variables["transaction_id"]).toBe(txid);
    expect(claimCall.variables["output_index"]).toBe(0);
    expect(claimCall.variables["credit_amount_sats"]).toBe(CREDIT_SATS);

    const claim = required(claimReq, "claim_transfer request");
    expect(claim.transferId).toBe(TRANSFER_ID);
    const chains = await store.exitChains();
    expect(chains.map((chain) => chain.leafId)).toContain(STATIC_LEAF_ID);
    signer.dispose();
  });

  test("falls back to query_pending_transfers when the claim output has no transfer id", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const pending = await sspTransfer(signer);
    const { fabricated, script } = await staticFixture(signer);
    const depositTx = txPaying(script, UTXO_SATS);
    const txid = txId(depositTx);
    const sspRequests: Array<{ operationName: string; variables: Record<string, unknown> }> = [];
    const sleeps: number[] = [];
    let pendingQueries = 0;
    let claimCalls = 0;
    const { client } = makeClient(
      signer,
      {
        generate_static_deposit_address: staticAddressHandler(fabricated),
        query_pending_transfers: () => {
          pendingQueries += 1;
          return create(QueryTransfersResponseSchema, { transfers: [pending], offset: -1n });
        },
        get_signing_commitments: () =>
          create(GetSigningCommitmentsResponseSchema, {
            signingCommitments: commitmentGroup(3),
          }),
        claim_transfer: async (req) => {
          claimCalls += 1;
          return create(ClaimTransferResponseSchema, {
            transfer: create(TransferSchema, {
              id: req.transferId,
              senderIdentityPublicKey: SSP_IDENTITY,
              receiverIdentityPublicKey: identity,
              status: TransferStatus.COMPLETED,
              type: TransferType.TRANSFER,
              network: Network.REGTEST,
              leaves: [await claimedLeaf(signer, required(pending.leaves[0], "leaf"))],
            }),
          });
        },
      },
      sspFetch(identity, { transferId: null }, sspRequests),
      undefined,
      sleeps,
    );

    const result = await client.deposits.claimStatic({
      txid,
      vout: 0,
      maxFeeSats: 500,
      rawTx: depositTx,
    });
    expect(result.leaves.map((leaf) => leaf.id)).toStrictEqual([STATIC_LEAF_ID]);
    expect(pendingQueries).toBe(1);
    expect(claimCalls).toBe(1);
    expect(sleeps).toHaveLength(0);
    signer.dispose();
  });

  test("returns without leaves when no inbound transfer appears within the bound", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const { fabricated, script } = await staticFixture(signer);
    const depositTx = txPaying(script, UTXO_SATS);
    const txid = txId(depositTx);
    const sleeps: number[] = [];
    let claimCalls = 0;
    const { client } = makeClient(
      signer,
      {
        generate_static_deposit_address: staticAddressHandler(fabricated),
        query_pending_transfers: () =>
          create(QueryTransfersResponseSchema, { transfers: [], offset: -1n }),
        claim_transfer: () => {
          claimCalls += 1;
          return create(ClaimTransferResponseSchema, {});
        },
      },
      sspFetch(identity, { transferId: null }, []),
      undefined,
      sleeps,
    );

    const result = await client.deposits.claimStatic({
      txid,
      vout: 0,
      maxFeeSats: 500,
      rawTx: depositTx,
    });
    expect(result.creditAmountSats).toBe(CREDIT_SATS);
    expect(result.leaves).toHaveLength(0);
    expect(claimCalls).toBe(0);
    expect(sleeps).toHaveLength(6);
    signer.dispose();
  });
});
