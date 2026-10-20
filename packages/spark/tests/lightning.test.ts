import { create } from "@bufbuild/protobuf";
import { EmptySchema } from "@bufbuild/protobuf/wkt";
import type { Transport } from "@connectrpc/connect";
import { createClient } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import {
  createCurrentTimelockRefundTxs,
  createRefundTxsForLightning,
  getNextHTLCTransactionSequence,
  p2trScriptFromPublicKey,
} from "../src/core/bitcoin/index.ts";
import type { SparkOperatorConfig } from "../src/core/network.ts";
import { SparkError, SparkInputError, SparkRequestError } from "../src/errors/index.ts";
import {
  createLightningInvoice,
  lightningReceiveStatus,
  lightningSendStatus,
  payLightningInvoice,
} from "../src/lightning/index.ts";
import type { LightningDeps } from "../src/lightning/index.ts";
import { decryptSuccessAction } from "../src/lnurl/index.ts";
import {
  GetSigningCommitmentsResponseSchema,
  InitiatePreimageSwapRequest_Reason,
  InitiatePreimageSwapResponseSchema,
  Network,
  QueryTransfersResponseSchema,
  RequestedSigningCommitmentsSchema,
  SparkService,
  TransferLeafSchema,
  TransferSchema,
  TransferStatus,
  TransferType,
  TreeNodeSchema,
} from "../src/proto/gen/spark_pb.ts";
import type { Transfer } from "../src/proto/gen/spark_pb.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import type { SparkSigner } from "../src/signer/index.ts";
import type {
  SspClient,
  SspLightningReceiveRequest,
  SspLightningSendRequest,
  SspLightningSendResult,
} from "../src/ssp/index.ts";
import type { SparkLeaf } from "../src/tree/index.ts";
import { loadWasmBackend } from "./support/backend.ts";
import { encodeTestBolt11 } from "./support/bolt11.ts";

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
const SSP_SECRET = new Uint8Array(32).fill(21);
const SSP_IDENTITY = secp256k1.getPublicKey(SSP_SECRET, true);
const INVOICE_SECRET = new Uint8Array(32).fill(66);
const SPARK_SCID = hexToBytes("f42400f424000001");

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

let signerPromise: Promise<SparkSigner> | undefined;
async function testSigner(): Promise<SparkSigner> {
  signerPromise ??= (async () =>
    createSparkSigner({
      crypto: await loadWasmBackend(),
      accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
      network: "regtest",
      random: fixedRandom(),
    }))();
  return signerPromise;
}

const SHARE_SECRET = 0x5ea5n;
const SHARE_PUB = secp256k1.Point.BASE.multiply(SHARE_SECRET).toBytes(true);
function verifyingKeyFor(signingPublicKey: Uint8Array): Uint8Array {
  return secp256k1.Point.fromBytes(SHARE_PUB)
    .add(secp256k1.Point.fromBytes(signingPublicKey))
    .toBytes(true);
}

/** A leaf with parseable node/refund txs, like transfer.test.ts's fixture. */
async function fabricateLeaf(
  signer: SparkSigner,
  options: {
    leafId: string;
    valueSats?: bigint;
    directNodeTx?: boolean;
  },
): Promise<SparkLeaf> {
  const signingPublicKeys = await signer.publicKeys([{ type: "leaf", leafId: options.leafId }]);
  const signingPublicKey = required(signingPublicKeys[0], "leaf signing key");
  const ownerIdentityPublicKey = await signer.identityPublicKey();
  const verifyingKey = verifyingKeyFor(signingPublicKey);
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
    receivingPublicKey: signingPublicKey,
    network: "regtest",
  }).cpfpRefund.txBytes;
  let directTx: Uint8Array | undefined;
  if (options.directNodeTx === true) {
    const direct = new Transaction({ allowUnknownOutputs: true });
    direct.addInput({ txid: new Uint8Array(32).fill(7), index: 0, sequence: 0 });
    direct.addOutput({
      script: p2trScriptFromPublicKey(verifyingKey, "regtest"),
      amount: (options.valueSats ?? 100_000n) - 330n,
    });
    directTx = direct.toBytes(true);
  }
  return {
    id: options.leafId,
    treeId: `tree-${options.leafId}`,
    valueSats: Number(options.valueSats ?? 100_000n),
    status: "AVAILABLE",
    nodeTx: nodeTxBytes,
    refundTx,
    ...(directTx === undefined ? {} : { directTx }),
    verifyingPublicKey: verifyingKey,
    ownerIdentityPublicKey,
    ownerSigningPublicKey: signingPublicKey,
    signingKeyshare: {
      ownerIdentifiers: OPERATORS.map((op) => op.identifier),
      threshold: THRESHOLD,
      publicKey: SHARE_PUB,
    },
    vout: 0,
  };
}

function commitments(count: number) {
  return Array.from({ length: count }, () =>
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
  );
}

/** A `query_transfers_by_id` lookup answering with the queued transfers in order, then none. */
function queuedTransfers(responses: ReadonlyArray<Transfer | undefined>) {
  const queue = [...responses];
  return () => queue.shift();
}

function transferProto(options: {
  id: string;
  sender: Uint8Array;
  receiver: Uint8Array;
  type?: TransferType;
  status?: TransferStatus;
  leaves?: ReadonlyArray<SparkLeaf>;
  totalValue?: bigint;
}): Transfer {
  return create(TransferSchema, {
    id: options.id,
    senderIdentityPublicKey: options.sender,
    receiverIdentityPublicKey: options.receiver,
    status: options.status ?? TransferStatus.SENDER_KEY_TWEAKED,
    type: options.type ?? TransferType.PREIMAGE_SWAP,
    network: Network.REGTEST,
    totalValue: options.totalValue ?? 0n,
    leaves: (options.leaves ?? []).map((leaf) =>
      create(TransferLeafSchema, {
        leaf: create(TreeNodeSchema, {
          id: leaf.id,
          treeId: leaf.treeId,
          value: BigInt(leaf.valueSats),
          nodeTx: leaf.nodeTx,
          refundTx: leaf.refundTx,
          ...(leaf.directTx === undefined ? {} : { directTx: leaf.directTx }),
          vout: leaf.vout,
          verifyingPublicKey: leaf.verifyingPublicKey,
          ownerIdentityPublicKey: leaf.ownerIdentityPublicKey,
          ownerSigningPublicKey: leaf.ownerSigningPublicKey,
          signingKeyshare: {
            ownerIdentifiers: [...leaf.signingKeyshare.ownerIdentifiers],
            threshold: leaf.signingKeyshare.threshold,
            publicKey: leaf.signingKeyshare.publicKey,
            publicShares: {},
          },
          status: "AVAILABLE",
          network: Network.REGTEST,
        }),
        secretCipher: new Uint8Array(10),
        sig: { case: "signature" as const, value: new Uint8Array(64) },
        transferReceiverId: "",
      }),
    ),
  });
}

type CapturedCall = {
  method: string;
  header: Headers;
  input: Record<string, unknown>;
};

/**
 * Direct Transport over the Spark service methods the lightning flows call. `input` arrives as the
 * message-init shape the client passed — fields are readable without a schema.
 */
function fakeSpark(handlers: {
  initiate_preimage_swap_v3?: (
    input: Record<string, unknown>,
  ) => Promise<{ transfer?: Transfer }> | { transfer?: Transfer };
  query_transfers_by_id?: (input: Record<string, unknown>) => { transfers?: Transfer[] };
  store_preimage_share_v2?: () => void;
}): { spark: ReturnType<typeof createClient<typeof SparkService>>; calls: CapturedCall[] } {
  const calls: CapturedCall[] = [];
  const respond = async (method: { name: string }, message: unknown) =>
    Promise.resolve({
      stream: false as const,
      service: SparkService,
      method,
      header: new Headers(),
      trailer: new Headers(),
      message,
    });
  const transport = {
    unary: async (
      method: { name: string },
      _signal: unknown,
      _timeoutMs: unknown,
      header: unknown,
      input: unknown,
    ) => {
      calls.push({
        method: method.name,
        header: new Headers(header as ConstructorParameters<typeof Headers>[0]),
        input: input as never,
      });
      switch (method.name) {
        case "get_signing_commitments": {
          const req = input as { nodeIds?: string[] };
          return respond(
            method,
            create(GetSigningCommitmentsResponseSchema, {
              signingCommitments: commitments(3 * (req.nodeIds?.length ?? 1)),
            }),
          );
        }
        case "initiate_preimage_swap_v3": {
          const handler = handlers.initiate_preimage_swap_v3;
          if (handler === undefined) {
            throw new Error("initiate_preimage_swap_v3 not stubbed");
          }
          const result = await handler(input as Record<string, unknown>);
          return respond(
            method,
            create(InitiatePreimageSwapResponseSchema, {
              preimage: new Uint8Array(),
              transfer: result.transfer,
            }),
          );
        }
        case "query_transfers_by_id": {
          const result = handlers.query_transfers_by_id?.(input as Record<string, unknown>);
          return respond(
            method,
            create(QueryTransfersResponseSchema, { transfers: result?.transfers ?? [] }),
          );
        }
        case "store_preimage_share_v2":
          handlers.store_preimage_share_v2?.();
          return respond(method, create(EmptySchema));

        default:
          throw new Error(`unexpected call ${method.name}`);
      }
    },
    stream: async () => Promise.reject(new Error("unimplemented")),
  } as unknown as Transport;
  return { spark: createClient(SparkService, transport), calls };
}

function fakeSsp(handlers: {
  requestLightningReceive?: (req: SspLightningReceiveRequest) => {
    id?: string;
    status?: string;
    invoice: string;
  };
  lightningSendFeeEstimate?: (invoice: string, amountSats?: number) => number;
  requestLightningSend?: (req: SspLightningSendRequest) => Partial<SspLightningSendResult>;
  lightningSendRequest?: (id: string) => Partial<SspLightningSendResult> & { status: string };
  lightningReceiveRequest?: (id: string) => { status: string; transferId?: string };
}): {
  ssp: SspClient;
  receiveRequests: SspLightningReceiveRequest[];
  sendRequests: SspLightningSendRequest[];
  feeEstimates: Array<{ invoice: string; amountSats?: number }>;
} {
  const receiveRequests: SspLightningReceiveRequest[] = [];
  const sendRequests: SspLightningSendRequest[] = [];
  const feeEstimates: Array<{ invoice: string; amountSats?: number }> = [];
  const ssp: SspClient = {
    swapFeeEstimate: async () => Promise.reject(new Error("unstubbed")),
    requestSwap: async () => Promise.reject(new Error("unstubbed")),
    requestLightningReceive: async (req) => {
      receiveRequests.push(req);
      const result = required(
        handlers.requestLightningReceive,
        "requestLightningReceive handler",
      )(req);
      return Promise.resolve({
        id: result.id ?? "recv-1",
        status: result.status ?? "LIGHTNING_PAYMENT_CREATED",
        invoice: result.invoice,
      });
    },
    requestLightningSend: async (req) => {
      sendRequests.push(req);
      const result = required(handlers.requestLightningSend, "requestLightningSend handler")(req);
      return Promise.resolve({
        id: result.id ?? "send-1",
        status: result.status ?? "LIGHTNING_PAYMENT_INITIATED",
        encodedInvoice: result.encodedInvoice ?? req.encodedInvoice,
        feeSats: result.feeSats ?? 0,
        ...(result.transferId === undefined ? {} : { transferId: result.transferId }),
        ...(result.paymentPreimage === undefined
          ? {}
          : { paymentPreimage: result.paymentPreimage }),
      });
    },
    lightningSendFeeEstimate: async (invoice, amountSats) => {
      feeEstimates.push({ invoice, ...(amountSats === undefined ? {} : { amountSats }) });
      return Promise.resolve(
        required(handlers.lightningSendFeeEstimate, "feeEstimate")(invoice, amountSats),
      );
    },
    lightningSendRequest: async (id) => {
      const result = required(handlers.lightningSendRequest, "lightningSendRequest")(id);
      return Promise.resolve({
        id,
        status: result.status,
        encodedInvoice: result.encodedInvoice ?? "",
        feeSats: result.feeSats ?? 0,
        ...(result.transferId === undefined ? {} : { transferId: result.transferId }),
        ...(result.paymentPreimage === undefined
          ? {}
          : { paymentPreimage: result.paymentPreimage }),
      });
    },
    lightningReceiveRequest: async (id) => {
      const result = required(handlers.lightningReceiveRequest, "lightningReceiveRequest")(id);
      return Promise.resolve({
        id,
        status: result.status,
        invoice: "",
        ...(result.transferId === undefined ? {} : { transferId: result.transferId }),
      });
    },
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
  return { ssp, receiveRequests, sendRequests, feeEstimates };
}

const NOW_MS = 1_700_000_000_000;

async function lightningDeps(options: {
  ssp: SspClient;
  spark?: LightningDeps["spark"];
}): Promise<LightningDeps> {
  return {
    spark: options.spark ?? fakeSpark({}).spark,
    ssp: options.ssp,
    sspIdentityPublicKey: SSP_IDENTITY,
    signer: await testSigner(),
    network: "regtest",
    operators: OPERATORS,
    threshold: THRESHOLD,
    random: fixedRandom(),
    now: () => NOW_MS,
  };
}

type MutableInvoiceOptions = {
  -readonly [K in keyof Parameters<typeof encodeTestBolt11>[0]]: Parameters<
    typeof encodeTestBolt11
  >[0][K];
};

/** The invoice the SSP "returns": built from the request fields, then mutated per test. */
function sspInvoice(
  request: SspLightningReceiveRequest,
  identityPublicKey: Uint8Array,
  mutate?: (options: MutableInvoiceOptions) => void,
): string {
  const options: MutableInvoiceOptions = {
    secretKey: INVOICE_SECRET,
    network: request.network === "mainnet" ? "mainnet" : "regtest",
    paymentHash: request.paymentHash,
    amountMsat: request.amountSats > 0 ? BigInt(request.amountSats) * 1000n : undefined,
    descriptionHash: request.descriptionHash,
    routeHints:
      request.includeSparkAddress === true
        ? [[{ publicKey: identityPublicKey, shortChannelId: SPARK_SCID }]]
        : [],
  };
  mutate?.(options);
  return encodeTestBolt11(options);
}

describe("createLightningInvoice", () => {
  async function setup(mutate?: (options: MutableInvoiceOptions) => void): Promise<{
    deps: LightningDeps;
    receiveRequests: SspLightningReceiveRequest[];
    stored: { count: number };
  }> {
    const signer = await testSigner();
    const identityPublicKey = await signer.identityPublicKey();
    const stored = { count: 0 };
    const { spark } = fakeSpark({ store_preimage_share_v2: () => stored.count++ });
    const { ssp, receiveRequests } = fakeSsp({
      requestLightningReceive: (req) => ({
        invoice: sspInvoice(req, identityPublicKey, mutate),
      }),
    });
    const deps = await lightningDeps({ ssp, spark });
    return { deps, receiveRequests, stored };
  }

  test("happy path: invoice fields, spark address, preimage shares stored", async () => {
    const { deps, receiveRequests, stored } = await setup();
    const invoice = await createLightningInvoice(deps, {
      amountSats: 1000,
      memo: "test invoice",
      includeSparkAddress: true,
    });
    const request = required(receiveRequests[0], "receive request");
    expect(request.amountSats).toBe(1000);
    expect(request.expirySecs).toBe(30 * 24 * 60 * 60);
    expect(request.memo).toBe("test invoice");
    expect(bytesToHex(request.receiverIdentityPublicKey)).toBe(
      bytesToHex(await deps.signer.identityPublicKey()),
    );
    expect(invoice.id).toBe("recv-1");
    expect(invoice.invoice.startsWith("lnbcrt")).toBe(true);
    expect(invoice.amountSats).toBe(1000);
    expect(bytesToHex(invoice.paymentHash)).toBe(bytesToHex(request.paymentHash));
    expect(invoice.expiresAtMs).toBeGreaterThan(0);
    expect(stored.count).toBe(1);
  });

  const failures: Array<{
    name: string;
    create: Parameters<typeof createLightningInvoice>[1];
    mutate?: (options: MutableInvoiceOptions) => void;
    error: string;
  }> = [
    {
      name: "payment hash mismatch",
      create: { amountSats: 1000 },
      mutate: (o) => {
        o.paymentHash = new Uint8Array(32).fill(0xaa);
      },
      error: "payment hash",
    },
    {
      name: "network mismatch",
      create: { amountSats: 1000 },
      mutate: (o) => {
        o.network = "mainnet";
      },
      error: "network",
    },
    {
      name: "fixed amount mismatch",
      create: { amountSats: 1000 },
      mutate: (o) => {
        o.amountMsat = 2_000_000n;
      },
      error: "amount",
    },
    {
      name: "amountless invoice for a fixed request",
      create: { amountSats: 1000 },
      mutate: (o) => {
        o.amountMsat = undefined;
      },
      error: "amount",
    },
    {
      name: "fixed invoice for an amountless request",
      create: { amountSats: 0 },
      mutate: (o) => {
        o.amountMsat = 1_000_000n;
      },
      error: "amount",
    },
    {
      name: "description hash mismatch",
      create: { amountSats: 1000, descriptionHash: new Uint8Array(32).fill(5) },
      mutate: (o) => {
        o.descriptionHash = new Uint8Array(32).fill(6);
      },
      error: "description hash",
    },
    {
      name: "spark address requested but absent",
      create: { amountSats: 1000, includeSparkAddress: true },
      mutate: (o) => {
        o.routeHints = [];
      },
      error: "missing the requested spark address",
    },
    {
      name: "spark address present but unrequested",
      create: { amountSats: 1000 },
      mutate: (o) => {
        o.routeHints = [[{ publicKey: new Uint8Array(33).fill(2), shortChannelId: SPARK_SCID }]];
      },
      error: "not requested",
    },
    {
      name: "spark address belongs to another identity",
      create: { amountSats: 1000, includeSparkAddress: true },
      mutate: (o) => {
        o.routeHints = [
          [
            {
              publicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(44), true),
              shortChannelId: SPARK_SCID,
            },
          ],
        ];
      },
      error: "does not match our identity",
    },
    {
      name: "a second spark hop belongs to another identity",
      create: { amountSats: 1000, includeSparkAddress: true },
      mutate: (o) => {
        // Our hop comes first — a first-match scan would accept this; every hop must be ours.
        o.routeHints = [
          [
            ...required(o.routeHints?.[0], "spark hint"),
            {
              publicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(45), true),
              shortChannelId: SPARK_SCID,
            },
          ],
        ];
      },
      error: "does not match our identity",
    },
  ];

  test.each(failures)("rejects an invoice with $name and stores nothing", async (failure) => {
    const { deps, stored } = await setup(failure.mutate);
    await expect(createLightningInvoice(deps, failure.create)).rejects.toThrow(failure.error);
    expect(stored.count).toBe(0);
  });

  test("rejects malformed options before the signer and the ssp are touched", async () => {
    const { deps, receiveRequests, stored } = await setup();
    await expect(
      createLightningInvoice(deps, { amountSats: 1000, descriptionHash: new Uint8Array(31) }),
    ).rejects.toThrow("descriptionHash must be 32 bytes");
    await expect(createLightningInvoice(deps, { amountSats: -1 })).rejects.toThrow(SparkInputError);
    await expect(createLightningInvoice(deps, { amountSats: 1.5 })).rejects.toThrow(
      SparkInputError,
    );
    await expect(createLightningInvoice(deps, { amountSats: 1000, expirySecs: 0 })).rejects.toThrow(
      SparkInputError,
    );
    expect(receiveRequests).toHaveLength(0);
    expect(stored.count).toBe(0);
  });
});

const PREIMAGE = new Uint8Array(32).fill(0x42);
const PAYMENT_HASH = sha256(PREIMAGE);

/** The `transferRequest` the SO sees inside `initiate_preimage_swap_v3`. */
function swapRequestOf(call: CapturedCall): {
  transferId: string;
  expiryTimeMs: number;
  receiverIdentityPublicKey: Uint8Array;
  transferPackage: {
    leavesToSend: Array<{ leafId: string; rawTx: Uint8Array }>;
    directLeavesToSend: Array<{ leafId: string; rawTx: Uint8Array }>;
    directFromCpfpLeavesToSend: Array<{ leafId: string; rawTx: Uint8Array }>;
  };
} {
  const transferRequest = (call.input as Record<string, any>)["transferRequest"] as Record<
    string,
    any
  >;
  return {
    transferId: transferRequest["transferId"],
    expiryTimeMs: Number(transferRequest["expiryTime"].seconds) * 1000,
    receiverIdentityPublicKey: transferRequest["receiverIdentityPublicKey"],
    transferPackage: transferRequest["transferPackage"],
  };
}

async function sendDeps(overrides: {
  leaves: ReadonlyArray<SparkLeaf>;
  /** Leaves the SO-returned transfer carries — defaults to `leaves`. */
  transferLeaves?: ReadonlyArray<SparkLeaf>;
  feeSats?: number;
  initiate?: (
    input: Record<string, unknown>,
  ) => Promise<{ transfer?: Transfer }> | { transfer?: Transfer };
  /**
   * Recovered transfer for the `query_transfers_by_id` probe — or a per-call lookup (default: none
   * found).
   */
  recoveredTransfer?: Transfer | (() => Transfer | undefined);
  /** Override the SSP send-request response (defaults to echoing the invoice back). */
  requestLightningSend?: (req: SspLightningSendRequest) => Partial<SspLightningSendResult>;
  deleted?: string[][];
}): Promise<{
  deps: Parameters<typeof payLightningInvoice>[0];
  calls: CapturedCall[];
  sendRequests: SspLightningSendRequest[];
  feeEstimates: Array<{ invoice: string; amountSats?: number }>;
  deleted: string[][];
}> {
  const signer = await testSigner();
  const identityPublicKey = await signer.identityPublicKey();
  const deleted = overrides.deleted ?? [];
  const { spark, calls } = fakeSpark({
    initiate_preimage_swap_v3:
      overrides.initiate ??
      ((input) => {
        const transferId = String(
          (input["transferRequest"] as Record<string, unknown>)["transferId"],
        );
        return {
          transfer: transferProto({
            id: transferId,
            sender: identityPublicKey,
            receiver: SSP_IDENTITY,
            leaves: overrides.transferLeaves ?? overrides.leaves,
          }),
        };
      }),
    query_transfers_by_id: () => {
      const recovered =
        typeof overrides.recoveredTransfer === "function"
          ? overrides.recoveredTransfer()
          : overrides.recoveredTransfer;
      return recovered === undefined ? {} : { transfers: [recovered] };
    },
  });
  const { ssp, sendRequests, feeEstimates } = fakeSsp({
    lightningSendFeeEstimate: () => overrides.feeSats ?? 7,
    requestLightningSend:
      overrides.requestLightningSend ??
      (() => ({ id: "send-req-1", status: "LIGHTNING_PAYMENT_INITIATED" })),
  });
  const deps = await lightningDeps({ ssp, spark });
  return {
    deps: {
      ...deps,
      selectLeaves: async () => Promise.resolve(overrides.leaves),
      deleteExitChains: async (leafIds) => {
        deleted.push([...leafIds]);
        return Promise.resolve();
      },
    },
    calls,
    sendRequests,
    feeEstimates,
    deleted,
  };
}

describe("payLightningInvoice", () => {
  test("happy path: initiate fields, idempotency header, HTLC refund txs", async () => {
    const signer = await testSigner();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1", valueSats: 150_000n });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
      timestamp: Math.floor(NOW_MS / 1000) - 60,
    });
    const { deps, calls, sendRequests, deleted } = await sendDeps({ leaves: [leaf] });
    const payment = await payLightningInvoice(deps, { invoice, maxFeeSats: 200 });

    const initiate = required(
      calls.find((call) => call.method === "initiate_preimage_swap_v3"),
      "initiate call",
    );
    expect(initiate.header.get("x-idempotency-key")).toBe(payment.transferId);
    const input = initiate.input as Record<string, any>;
    expect(bytesToHex(input["paymentHash"])).toBe(bytesToHex(PAYMENT_HASH));
    expect(input["reason"]).toBe(InitiatePreimageSwapRequest_Reason.SEND);
    const invoiceAmount = input["invoiceAmount"] as Record<string, any>;
    expect(invoiceAmount["valueSats"]).toBe(1000n);
    expect(invoiceAmount["invoiceAmountProof"]["bolt11Invoice"]).toBe(invoice);
    expect(input["feeSats"]).toBe(7n);
    expect(bytesToHex(input["receiverIdentityPublicKey"])).toBe(bytesToHex(SSP_IDENTITY));

    const swapRequest = swapRequestOf(initiate);
    expect(swapRequest.transferId).toBe(payment.transferId);
    expect(bytesToHex(swapRequest.receiverIdentityPublicKey)).toBe(bytesToHex(SSP_IDENTITY));
    // ~16-day expiry window around `now`.
    const expiryDelta = swapRequest.expiryTimeMs - NOW_MS;
    expect(expiryDelta).toBeGreaterThan(15.9 * 24 * 60 * 60 * 1000);
    expect(expiryDelta).toBeLessThan(16.1 * 24 * 60 * 60 * 1000);

    // The CPFP refund job carries the HTLC: hash-lock → SSP, sequence-lock → us.
    const job = required(swapRequest.transferPackage.leavesToSend[0], "cpfp job");
    expect(job.leafId).toBe("leaf-1");
    const { nextSequence, nextDirectSequence } = getNextHTLCTransactionSequence(2000);
    const expected = createRefundTxsForLightning({
      nodeTx: leaf.nodeTx,
      directNodeTx: leaf.directTx,
      vout: 0,
      sequence: nextSequence,
      directSequence: nextDirectSequence,
      paymentHash: PAYMENT_HASH,
      hashLockDestinationPublicKey: SSP_IDENTITY,
      sequenceLockDestinationPublicKey: await signer.identityPublicKey(),
    });
    expect(bytesToHex(job.rawTx)).toBe(bytesToHex(expected.cpfpRefundTx.txBytes));
    const parsedSequence = Transaction.fromRaw(expected.cpfpRefundTx.txBytes, {
      allowUnknownOutputs: true,
    }).getInput(0).sequence;
    expect(parsedSequence).toBe(nextSequence);
    expect(swapRequest.transferPackage.directLeavesToSend).toHaveLength(0);
    const dfJob = required(
      swapRequest.transferPackage.directFromCpfpLeavesToSend[0],
      "direct-from-cpfp job",
    );
    expect(bytesToHex(dfJob.rawTx)).toBe(bytesToHex(expected.directFromCpfpRefundTx.txBytes));

    const sendRequest = required(sendRequests[0], "send request");
    expect(sendRequest.encodedInvoice).toBe(invoice);
    expect(sendRequest.amountSats).toBeUndefined(); // fixed invoice: no amount override
    expect(sendRequest.userOutboundTransferExternalId).toBe(payment.transferId);
    expect(sendRequest).not.toHaveProperty("idempotencyKey");
    expect(deleted).toStrictEqual([["leaf-1"]]);
    expect(payment.requestId).toBe("send-req-1");
    expect(payment.amountSats).toBe(1000);
    expect(payment.feeSats).toBe(7);
  });

  test("leaf with a direct tx signs all three HTLC refund variants", async () => {
    const signer = await testSigner();
    const leaf = await fabricateLeaf(signer, {
      leafId: "leaf-d",
      valueSats: 150_000n,
      directNodeTx: true,
    });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
    });
    const { deps, calls } = await sendDeps({ leaves: [leaf] });
    await payLightningInvoice(deps, { invoice, maxFeeSats: 200 });
    const swapRequest = swapRequestOf(
      required(
        calls.find((call) => call.method === "initiate_preimage_swap_v3"),
        "initiate",
      ),
    );
    const { nextSequence, nextDirectSequence } = getNextHTLCTransactionSequence(2000);
    const expected = createRefundTxsForLightning({
      nodeTx: leaf.nodeTx,
      directNodeTx: leaf.directTx,
      vout: 0,
      sequence: nextSequence,
      directSequence: nextDirectSequence,
      paymentHash: PAYMENT_HASH,
      hashLockDestinationPublicKey: SSP_IDENTITY,
      sequenceLockDestinationPublicKey: await signer.identityPublicKey(),
    });
    const directJob = required(swapRequest.transferPackage.directLeavesToSend[0], "direct job");
    expect(bytesToHex(directJob.rawTx)).toBe(
      bytesToHex(required(expected.directRefundTx, "direct refund").txBytes),
    );
  });

  test("caller-supplied transferId is reused (retry idempotency)", async () => {
    const signer = await testSigner();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1" });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
    });
    const { deps, calls } = await sendDeps({ leaves: [leaf] });
    const payment = await payLightningInvoice(deps, {
      invoice,
      maxFeeSats: 200,
      transferId: "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
    });
    expect(payment.transferId).toBe("0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee");
    const initiate = required(
      calls.find((call) => call.method === "initiate_preimage_swap_v3"),
      "initiate",
    );
    expect(initiate.header.get("x-idempotency-key")).toBe("0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee");
  });

  test("fixed invoice rejects amountSats", async () => {
    const signer = await testSigner();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1" });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
    });
    const { deps, feeEstimates } = await sendDeps({ leaves: [leaf] });
    await expect(
      payLightningInvoice(deps, { invoice, maxFeeSats: 200, amountSats: 500 }),
    ).rejects.toThrow(SparkInputError);
    expect(feeEstimates).toHaveLength(0);
  });

  test("amountless invoice requires amountSats and forwards it", async () => {
    const signer = await testSigner();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1" });
    const invoice = encodeTestBolt11({ secretKey: INVOICE_SECRET, paymentHash: PAYMENT_HASH });
    const { deps, feeEstimates } = await sendDeps({ leaves: [leaf] });
    await expect(payLightningInvoice(deps, { invoice, maxFeeSats: 200 })).rejects.toThrow(
      "amountSats is required",
    );
    expect(feeEstimates).toHaveLength(0);

    const { deps: deps2, feeEstimates: fees2, sendRequests } = await sendDeps({ leaves: [leaf] });
    const payment = await payLightningInvoice(deps2, {
      invoice,
      maxFeeSats: 200,
      amountSats: 500,
    });
    expect(fees2[0]?.amountSats).toBe(500);
    expect(sendRequests[0]?.amountSats).toBe(500);
    expect(payment.amountSats).toBe(500);
  });

  test("msat invoice amounts round up to sats", async () => {
    const signer = await testSigner();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1" });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_500n, // 1000.5 sats
    });
    const { deps, calls } = await sendDeps({ leaves: [leaf] });
    const payment = await payLightningInvoice(deps, { invoice, maxFeeSats: 200 });
    expect(payment.amountSats).toBe(1001);
    const input = required(
      calls.find((call) => call.method === "initiate_preimage_swap_v3"),
      "initiate",
    ).input as Record<string, any>;
    expect((input["invoiceAmount"] as Record<string, any>)["valueSats"]).toBe(1001n);
  });

  test("expired invoice is rejected before the fee estimate", async () => {
    const signer = await testSigner();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1" });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
      timestamp: Math.floor(NOW_MS / 1000) - 4000,
      expirySeconds: 3600,
    });
    const { deps, feeEstimates } = await sendDeps({ leaves: [leaf] });
    await expect(payLightningInvoice(deps, { invoice, maxFeeSats: 200 })).rejects.toThrow(
      "expired",
    );
    expect(feeEstimates).toHaveLength(0);
  });

  test("fee estimate above maxFeeSats is rejected before any signing", async () => {
    const signer = await testSigner();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1" });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
    });
    const { deps, calls } = await sendDeps({ leaves: [leaf], feeSats: 500 });
    await expect(payLightningInvoice(deps, { invoice, maxFeeSats: 200 })).rejects.toThrow(
      "exceeds maxFeeSats",
    );
    expect(calls.find((call) => call.method === "initiate_preimage_swap_v3")).toBeUndefined();
  });

  test("a lost initiate response recovers the committed transfer", async () => {
    const signer = await testSigner();
    const identityPublicKey = await signer.identityPublicKey();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1" });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
    });
    const transferId = "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee";
    const committed = transferProto({
      id: transferId,
      sender: identityPublicKey,
      receiver: SSP_IDENTITY,
      type: TransferType.PREIMAGE_SWAP,
      leaves: [leaf],
    });
    const { deps, sendRequests, deleted, calls } = await sendDeps({
      leaves: [leaf],
      // The pre-send probe misses; the post-failure probe finds the committed transfer.
      recoveredTransfer: queuedTransfers([undefined, committed]),
      initiate: () => {
        throw new SparkRequestError("initiate response lost", { code: "unavailable" });
      },
    });
    const payment = await payLightningInvoice(deps, { invoice, maxFeeSats: 200, transferId });
    // The committed transfer's id keys the SSP send request.
    expect(payment.transferId).toBe(transferId);
    expect(sendRequests[0]?.userOutboundTransferExternalId).toBe(transferId);
    expect(deleted).toStrictEqual([["leaf-1"]]);
    expect(calls.filter((call) => call.method === "query_transfers_by_id")).toHaveLength(2);
  });

  test("a non-committed initiate failure rethrows the original error", async () => {
    const signer = await testSigner();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1" });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
    });
    const { deps, sendRequests } = await sendDeps({
      leaves: [leaf],
      initiate: () => {
        throw new SparkRequestError("initiate response lost", { code: "unavailable" });
      },
    });
    await expect(payLightningInvoice(deps, { invoice, maxFeeSats: 200 })).rejects.toThrow(
      "initiate response lost",
    );
    expect(sendRequests).toHaveLength(0);
  });

  test("a committed swap under the caller's transfer id resumes without initiating", async () => {
    const signer = await testSigner();
    const identityPublicKey = await signer.identityPublicKey();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1", valueSats: 150_000n });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
    });
    const committed = transferProto({
      id: "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
      sender: identityPublicKey,
      receiver: SSP_IDENTITY,
      type: TransferType.PREIMAGE_SWAP,
      leaves: [leaf],
      totalValue: 1007n, // 1000 sats amount + 7 sats committed fee
    });
    const { deps, calls, sendRequests, feeEstimates, deleted } = await sendDeps({
      leaves: [leaf],
      recoveredTransfer: committed,
      initiate: () => {
        throw new Error("initiate_preimage_swap_v3 must not run when the probe hits");
      },
    });
    const payment = await payLightningInvoice(deps, {
      invoice,
      maxFeeSats: 200,
      transferId: "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
    });
    // The probe hit skips the fee estimate, selection and package building entirely.
    expect(calls.map((call) => call.method)).toStrictEqual(["query_transfers_by_id"]);
    expect(feeEstimates).toHaveLength(0);
    expect(payment.feeSats).toBe(7);
    expect(sendRequests).toHaveLength(1);
    expect(sendRequests[0]!.userOutboundTransferExternalId).toBe(
      "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
    );
    expect(deleted).toStrictEqual([["leaf-1"]]);
    expect(payment.requestId).toBe("send-req-1");
    expect(payment.transferId).toBe("0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee");
  });

  test("a probed swap whose committed fee exceeds maxFeeSats is rejected", async () => {
    const signer = await testSigner();
    const identityPublicKey = await signer.identityPublicKey();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1", valueSats: 150_000n });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
    });
    const committed = transferProto({
      id: "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
      sender: identityPublicKey,
      receiver: SSP_IDENTITY,
      type: TransferType.PREIMAGE_SWAP,
      leaves: [leaf],
      totalValue: 1201n, // implies a 201-sat fee, above maxFeeSats
    });
    const { deps, sendRequests, feeEstimates } = await sendDeps({
      leaves: [leaf],
      recoveredTransfer: committed,
      initiate: () => {
        throw new Error("initiate_preimage_swap_v3 must not run when the probe hits");
      },
    });
    await expect(
      payLightningInvoice(deps, {
        invoice,
        maxFeeSats: 200,
        transferId: "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
      }),
    ).rejects.toThrow(/committed transfer fee 201 exceeds maxFeeSats 200/);
    expect(feeEstimates).toHaveLength(0);
    expect(sendRequests).toHaveLength(0);
  });

  test("a probed transfer under someone else's sender key is rejected", async () => {
    const signer = await testSigner();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1" });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
    });
    const foreign = transferProto({
      id: "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
      sender: secp256k1.getPublicKey(new Uint8Array(32).fill(77), true),
      receiver: SSP_IDENTITY,
      type: TransferType.PREIMAGE_SWAP,
      leaves: [leaf],
    });
    const { deps, sendRequests } = await sendDeps({
      leaves: [leaf],
      recoveredTransfer: foreign,
      initiate: () => {
        throw new SparkRequestError("initiate response lost", { code: "unavailable" });
      },
    });
    await expect(
      payLightningInvoice(deps, {
        invoice,
        maxFeeSats: 200,
        transferId: "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
      }),
    ).rejects.toThrow("committed transfer is not ours");
    expect(sendRequests).toHaveLength(0);
  });

  test("exit chains are deleted for the returned transfer's leaves, not the selection", async () => {
    const signer = await testSigner();
    const selected = await fabricateLeaf(signer, { leafId: "selected-1" });
    const returned = await fabricateLeaf(signer, { leafId: "returned-9" });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
    });
    const { deps, deleted } = await sendDeps({ leaves: [selected], transferLeaves: [returned] });
    await payLightningInvoice(deps, { invoice, maxFeeSats: 200 });
    expect(deleted).toStrictEqual([["returned-9"]]);
  });

  test("exit chains are deleted before the ssp send request runs", async () => {
    const signer = await testSigner();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1" });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
    });
    const deleted: string[][] = [];
    let deletedAtSend = -1;
    const { deps } = await sendDeps({
      leaves: [leaf],
      deleted,
      requestLightningSend: () => {
        deletedAtSend = deleted.length;
        return {};
      },
    });
    await payLightningInvoice(deps, { invoice, maxFeeSats: 200 });
    expect(deletedAtSend).toBe(1);
  });

  test("a committed transfer to another receiver is rejected", async () => {
    const signer = await testSigner();
    const identityPublicKey = await signer.identityPublicKey();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1" });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
    });
    const foreign = secp256k1.getPublicKey(new Uint8Array(32).fill(88), true);
    const { deps, sendRequests } = await sendDeps({
      leaves: [leaf],
      initiate: (input) => ({
        transfer: transferProto({
          id: String((input["transferRequest"] as Record<string, unknown>)["transferId"]),
          sender: identityPublicKey,
          receiver: foreign,
          leaves: [leaf],
        }),
      }),
    });
    await expect(payLightningInvoice(deps, { invoice, maxFeeSats: 200 })).rejects.toThrow(
      "committed transfer is not ours",
    );
    expect(sendRequests).toHaveLength(0);
  });

  test("a committed transfer from another sender is rejected", async () => {
    const signer = await testSigner();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1" });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
    });
    const foreign = secp256k1.getPublicKey(new Uint8Array(32).fill(88), true);
    const { deps, sendRequests } = await sendDeps({
      leaves: [leaf],
      initiate: (input) => ({
        transfer: transferProto({
          id: String((input["transferRequest"] as Record<string, unknown>)["transferId"]),
          sender: foreign,
          receiver: SSP_IDENTITY,
          leaves: [leaf],
        }),
      }),
    });
    await expect(payLightningInvoice(deps, { invoice, maxFeeSats: 200 })).rejects.toThrow(
      "committed transfer is not ours",
    );
    expect(sendRequests).toHaveLength(0);
  });

  test("a probed transfer to another receiver does not count", async () => {
    const signer = await testSigner();
    const identityPublicKey = await signer.identityPublicKey();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1" });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
    });
    const foreignReceiver = transferProto({
      id: "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
      sender: identityPublicKey,
      receiver: secp256k1.getPublicKey(new Uint8Array(32).fill(88), true),
      type: TransferType.PREIMAGE_SWAP,
      leaves: [leaf],
    });
    const { deps } = await sendDeps({
      leaves: [leaf],
      recoveredTransfer: foreignReceiver,
      initiate: () => {
        throw new SparkRequestError("initiate response lost", { code: "unavailable" });
      },
    });
    await expect(
      payLightningInvoice(deps, {
        invoice,
        maxFeeSats: 200,
        transferId: "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
      }),
    ).rejects.toThrow("committed transfer is not ours");
  });

  test("an ssp send request echoing a different invoice is rejected", async () => {
    const signer = await testSigner();
    const leaf = await fabricateLeaf(signer, { leafId: "leaf-1" });
    const invoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: PAYMENT_HASH,
      amountMsat: 1_000_000n,
    });
    const { deps, deleted } = await sendDeps({
      leaves: [leaf],
      requestLightningSend: () => ({
        encodedInvoice: "lnbcrt20n1pother",
      }),
    });
    await expect(payLightningInvoice(deps, { invoice, maxFeeSats: 200 })).rejects.toThrow(
      "different invoice",
    );
    // The leaves are already committed under HTLC refunds — the chains stay deleted.
    expect(deleted).toStrictEqual([["leaf-1"]]);
  });
});

describe("lightningSendStatus", () => {
  const PAID_INVOICE = encodeTestBolt11({
    secretKey: INVOICE_SECRET,
    paymentHash: PAYMENT_HASH,
    amountMsat: 1_000_000n,
  });
  const request = { requestId: "req-1", paymentHash: PAYMENT_HASH };

  test("returns the verified preimage once settled", async () => {
    const { ssp } = fakeSsp({
      lightningSendRequest: () => ({
        status: "LIGHTNING_PAYMENT_SUCCEEDED",
        encodedInvoice: PAID_INVOICE,
        paymentPreimage: PREIMAGE,
      }),
    });
    const status = await lightningSendStatus(ssp, request);
    expect(status.status).toBe("LIGHTNING_PAYMENT_SUCCEEDED");
    expect(bytesToHex(required(status.preimage, "preimage"))).toBe(bytesToHex(PREIMAGE));
  });

  test("omits the preimage while pending", async () => {
    const { ssp } = fakeSsp({
      lightningSendRequest: () => ({
        status: "LIGHTNING_PAYMENT_INITIATED",
        encodedInvoice: PAID_INVOICE,
      }),
    });
    const status = await lightningSendStatus(ssp, request);
    expect(status.preimage).toBeUndefined();
  });

  test("rejects a preimage that does not hash to the paid payment hash", async () => {
    const { ssp } = fakeSsp({
      lightningSendRequest: () => ({
        status: "LIGHTNING_PAYMENT_SUCCEEDED",
        encodedInvoice: PAID_INVOICE,
        paymentPreimage: new Uint8Array(32).fill(0x99),
      }),
    });
    await expect(lightningSendStatus(ssp, request)).rejects.toThrow(SparkError);
    await expect(lightningSendStatus(ssp, request)).rejects.toThrow(
      "does not match the paid payment hash",
    );
  });

  test("rejects a status row for a different payment, preimage and all", async () => {
    // The SSP's answer is self-consistent — invoice hash H2, preimage → H2 — but it is not the
    // payment we made (H1): a self-consistent answer must still not pass as proof of ours.
    const otherPreimage = new Uint8Array(32).fill(0x77);
    const otherInvoice = encodeTestBolt11({
      secretKey: INVOICE_SECRET,
      paymentHash: sha256(otherPreimage),
      amountMsat: 1_000_000n,
    });
    const { ssp } = fakeSsp({
      lightningSendRequest: () => ({
        status: "LIGHTNING_PAYMENT_SUCCEEDED",
        encodedInvoice: otherInvoice,
        paymentPreimage: otherPreimage,
      }),
    });
    await expect(lightningSendStatus(ssp, request)).rejects.toThrow("not the invoice we paid");
  });
});

describe("lightningReceiveStatus", () => {
  test("returns status and the inbound transfer id", async () => {
    const { ssp } = fakeSsp({
      lightningReceiveRequest: () => ({
        status: "TRANSFER_COMPLETED",
        transferId: "transfer-abc",
      }),
    });
    const status = await lightningReceiveStatus(ssp, "req-2");
    expect(status.status).toBe("TRANSFER_COMPLETED");
    expect(status.transferId).toBe("transfer-abc");
  });
});

describe("decryptSuccessAction (LUD-10)", () => {
  // Independent implementation: node:crypto AES-256-CBC produces the reference ciphertext.
  test("round-trips a node:crypto AES-256-CBC vector", async () => {
    const { createCipheriv, createDecipheriv, randomBytes } = await import("node:crypto");
    const key = randomBytes(32);
    const iv = randomBytes(16);
    const plaintext = "Paid. That was fast!";
    const cipher = createCipheriv("aes-256-cbc", key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const action = {
      tag: "aes" as const,
      description: "receipt",
      iv: iv.toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
    expect(decryptSuccessAction(action, key)).toBe(plaintext);
    // Cross-check the independent path: decrypt our fixture with node:crypto too.
    const decipher = createDecipheriv("aes-256-cbc", key, iv);
    expect(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8")).toBe(
      plaintext,
    );
  });

  test("rejects malformed inputs", () => {
    const action = {
      tag: "aes" as const,
      description: "x",
      iv: Buffer.alloc(16).toString("base64"),
      ciphertext: Buffer.alloc(16).toString("base64"),
    };
    expect(() => decryptSuccessAction(action, new Uint8Array(31))).toThrow(
      "preimage must be 32 bytes",
    );
    expect(() => decryptSuccessAction({ ...action, iv: "!!!!" }, new Uint8Array(32))).toThrow(
      SparkInputError,
    );
    expect(() =>
      decryptSuccessAction(
        { ...action, iv: Buffer.alloc(8).toString("base64") },
        new Uint8Array(32),
      ),
    ).toThrow("iv is not 16 bytes");
    expect(() =>
      decryptSuccessAction(
        { ...action, ciphertext: Buffer.alloc(5000).toString("base64") },
        new Uint8Array(32),
      ),
    ).toThrow("4 KiB");
    // A non-block-multiple ciphertext cannot be valid AES-CBC.
    expect(() =>
      decryptSuccessAction(
        { ...action, ciphertext: Buffer.alloc(24).toString("base64") },
        new Uint8Array(32),
      ),
    ).toThrow(SparkInputError);
    // Zero-key decryption of 16 zero bytes yields invalid PKCS#7 padding or non-UTF-8 output.
    expect(() => decryptSuccessAction(action, new Uint8Array(32))).toThrow(SparkInputError);
  });
});
