import { create } from "@bufbuild/protobuf";
import type { Transport } from "@connectrpc/connect";
import { createClient } from "@connectrpc/connect";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { Address, OutScript, Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import type { ClientContext } from "../src/client/context.ts";
import { createWithdrawals } from "../src/client/withdrawals.ts";
import {
  btcNetwork,
  createCurrentTimelockRefundTxs,
  EPHEMERAL_ANCHOR_SCRIPT,
  p2trScriptFromPublicKey,
  p2trAddressFromPublicKey,
  taprootKeySpendSighash,
  txId,
  txIdBytes,
  parseTransaction,
} from "../src/core/bitcoin/index.ts";
import { createMutex } from "../src/core/mutex.ts";
import { sparkNetworkConfig } from "../src/core/network.ts";
import type { SparkOperatorConfig } from "../src/core/network.ts";
import { SparkInputError, SparkRequestError } from "../src/errors/index.ts";
import {
  cooperativeExit,
  cooperativeExitStatus,
  COOP_EXIT_TRANSFER_EXPIRY_MS,
  quoteCooperativeExit,
} from "../src/exit/coop.ts";
import type { CoopExitDeps } from "../src/exit/coop.ts";
import { createMemorySparkStore } from "../src/exit/store.ts";
import {
  CooperativeExitResponseSchema,
  GetSigningCommitmentsResponseSchema,
  Network,
  QueryTransfersResponseSchema,
  RenewLeafResponseSchema,
  RequestedSigningCommitmentsSchema,
  SparkService,
  TransferLeafSchema,
  TransferSchema,
  TransferStatus,
  TransferType,
  TreeNodeSchema,
} from "../src/proto/gen/spark_pb.ts";
import type { RenewLeafRequest, Transfer } from "../src/proto/gen/spark_pb.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import type { SparkSigner, FrostSignJob } from "../src/signer/index.ts";
import type { SspClient, SspCoopExitRequest, SspCoopExitResult } from "../src/ssp/index.ts";
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
const SSP_SECRET = new Uint8Array(32).fill(21);
const SSP_IDENTITY = secp256k1.getPublicKey(SSP_SECRET, true);
const WITHDRAW_KEY = secp256k1.getPublicKey(new Uint8Array(32).fill(77), true);
const WITHDRAW_ADDRESS = p2trAddressFromPublicKey(WITHDRAW_KEY, "regtest");
const NOW_MS = 1_700_000_000_000;

function jobLeafId(job: FrostSignJob): string {
  if (job.key.type !== "leaf") {
    throw new Error("expected a leaf job");
  }
  return job.key.leafId;
}

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

const SHARE_SECRET = 0x5ea5n;
const SHARE_PUB = secp256k1.Point.BASE.multiply(SHARE_SECRET).toBytes(true);
function verifyingKeyFor(signingPublicKey: Uint8Array): Uint8Array {
  return secp256k1.Point.fromBytes(SHARE_PUB)
    .add(secp256k1.Point.fromBytes(signingPublicKey))
    .toBytes(true);
}

/** A leaf with parseable node/refund txs, like lightning.test.ts's fixture. */
async function fabricateLeaf(
  signer: SparkSigner,
  options: {
    leafId: string;
    valueSats?: bigint;
    directNodeTx?: boolean;
    /** A non-zero node timelock is what makes a direct refund exist for the leaf. */
    nodeSequence?: number;
    /** Refund timelock; below 200 the leaf is stale and renews before leaving the wallet. */
    refundSequence?: number;
  },
): Promise<SparkLeaf> {
  const signingPublicKeys = await signer.publicKeys([{ type: "leaf", leafId: options.leafId }]);
  const signingPublicKey = required(signingPublicKeys[0], "leaf signing key");
  const ownerIdentityPublicKey = await signer.identityPublicKey();
  const verifyingKey = verifyingKeyFor(signingPublicKey);
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

/** A payout transaction paying `amountSats` to `address` — the SSP's raw_coop_exit_transaction. */
function payoutTxFor(address: string, amountSats: number): Uint8Array {
  const tx = new Transaction({ allowUnknownInputs: true, allowUnknownOutputs: true });
  tx.addInput({ txid: new Uint8Array(32).fill(5), index: 0, sequence: 0 });
  tx.addOutput({
    script: OutScript.encode(Address(btcNetwork("regtest")).decode(address)),
    amount: BigInt(amountSats),
  });
  return tx.toBytes(true);
}

/**
 * The SSP's connector: input 0 spends the payout tx at vout 0, then `outputCount` outputs — the
 * leaf-bound outputs first (per-leaf script/amount) plus the trailing anchor.
 */
function connectorTxFor(
  payoutTxid: string,
  outputCount: number,
  options?: { parentTxid?: Uint8Array; leafScript?: Uint8Array; amount?: bigint },
): Uint8Array {
  const tx = new Transaction({ allowUnknownInputs: true, allowUnknownOutputs: true });
  tx.addInput({ txid: options?.parentTxid ?? hexToBytes(payoutTxid), index: 0 });
  for (let i = 0; i < outputCount; i++) {
    tx.addOutput({
      script:
        i < outputCount - 1
          ? (options?.leafScript ?? p2trScriptFromPublicKey(SSP_IDENTITY, "regtest"))
          : EPHEMERAL_ANCHOR_SCRIPT,
      amount: i < outputCount - 1 ? (options?.amount ?? 330n) : 0n,
    });
  }
  return tx.toBytes(true);
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

/** A zero-timelock renew_leaf response whose node echoes the txs the client just signed. */
function renewZeroTimelockResult(
  leaf: SparkLeaf,
  input: Record<string, unknown>,
): { response: unknown; nodeTx: Uint8Array } {
  const jobs = (input as unknown as RenewLeafRequest).signingJobs;
  if (jobs.case !== "renewNodeZeroTimelockSigningJob") {
    throw new Error(`expected zero-timelock renewal, got ${jobs.case}`);
  }
  const nodeTx = required(jobs.value.nodeTxSigningJob?.rawTx, "renewed node tx");
  const node = create(TreeNodeSchema, {
    id: leaf.id,
    treeId: leaf.treeId,
    value: BigInt(leaf.valueSats),
    nodeTx,
    refundTx: required(jobs.value.refundTxSigningJob?.rawTx, "renewed refund tx"),
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
  });
  return {
    response: create(RenewLeafResponseSchema, {
      renewResult: { case: "renewNodeZeroTimelockResult", value: { node } },
    }),
    nodeTx,
  };
}

function transferProto(options: {
  id: string;
  sender: Uint8Array;
  receiver: Uint8Array;
  type?: TransferType;
  leaves?: ReadonlyArray<SparkLeaf>;
}): Transfer {
  return create(TransferSchema, {
    id: options.id,
    senderIdentityPublicKey: options.sender,
    receiverIdentityPublicKey: options.receiver,
    status: TransferStatus.SENDER_KEY_TWEAKED,
    type: options.type ?? TransferType.COOPERATIVE_EXIT,
    network: Network.REGTEST,
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

/** Direct Transport over the Spark service methods the coop-exit flow calls. */
function fakeSpark(handlers: {
  cooperative_exit_v2?: (
    input: Record<string, unknown>,
  ) => Promise<{ transfer?: Transfer }> | { transfer?: Transfer };
  query_transfers_by_id?: (input: Record<string, unknown>) => { transfers?: Transfer[] };
  renew_leaf?: (input: Record<string, unknown>) => unknown;
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
          const req = input as { nodeIds?: string[]; count?: number };
          return respond(
            method,
            create(GetSigningCommitmentsResponseSchema, {
              signingCommitments: commitments((req.count ?? 3) * (req.nodeIds?.length ?? 1)),
            }),
          );
        }
        case "renew_leaf": {
          const handler = handlers.renew_leaf;
          if (handler === undefined) {
            throw new Error("renew_leaf not stubbed");
          }
          return respond(method, handler(input as Record<string, unknown>));
        }
        case "cooperative_exit_v2": {
          const handler = handlers.cooperative_exit_v2;
          if (handler === undefined) {
            throw new Error("cooperative_exit_v2 not stubbed");
          }
          const result = await handler(input as Record<string, unknown>);
          return respond(
            method,
            create(CooperativeExitResponseSchema, { transfer: result.transfer }),
          );
        }
        case "query_transfers_by_id": {
          const result = handlers.query_transfers_by_id?.(input as Record<string, unknown>);
          return respond(
            method,
            create(QueryTransfersResponseSchema, { transfers: result?.transfers ?? [] }),
          );
        }
        default:
          throw new Error(`unexpected call ${method.name}`);
      }
    },
    stream: async () => Promise.reject(new Error("unimplemented")),
  } as unknown as Transport;
  return { spark: createClient(SparkService, transport), calls };
}

function fakeSsp(handlers: {
  coopExitFeeQuote?: (
    leafIds: ReadonlyArray<string>,
    address: string,
  ) => { id?: string; expiresAtMs?: number; fees: { fast: number; medium: number; slow: number } };
  requestCoopExit?: (req: SspCoopExitRequest) => Partial<SspCoopExitResult>;
  completeCoopExit?: (req: {
    coopExitRequestId: string;
    userOutboundTransferExternalId: string;
  }) => { id?: string; status: string } | Promise<{ id?: string; status: string }>;
  coopExitRequest?: (id: string) => { id?: string; status: string; transferId?: string };
}): {
  ssp: SspClient;
  quotes: Array<{ leafIds: string[]; address: string }>;
  exitRequests: SspCoopExitRequest[];
  completions: Array<{ coopExitRequestId: string; userOutboundTransferExternalId: string }>;
  statusReads: string[];
} {
  const quotes: Array<{ leafIds: string[]; address: string }> = [];
  const exitRequests: SspCoopExitRequest[] = [];
  const completions: Array<{
    coopExitRequestId: string;
    userOutboundTransferExternalId: string;
  }> = [];
  const statusReads: string[] = [];
  const ssp: SspClient = {
    swapFeeEstimate: async () => Promise.reject(new Error("unstubbed")),
    requestSwap: async () => Promise.reject(new Error("unstubbed")),
    requestLightningReceive: async () => Promise.reject(new Error("unstubbed")),
    requestLightningSend: async () => Promise.reject(new Error("unstubbed")),
    lightningSendFeeEstimate: async () => Promise.reject(new Error("unstubbed")),
    lightningSendRequest: async () => Promise.reject(new Error("unstubbed")),
    lightningReceiveRequest: async () => Promise.reject(new Error("unstubbed")),
    coopExitFeeQuote: async (leafIds, address) => {
      quotes.push({ leafIds: [...leafIds], address });
      const result = required(handlers.coopExitFeeQuote, "coopExitFeeQuote handler")(
        leafIds,
        address,
      );
      return Promise.resolve({
        id: result.id ?? "quote-1",
        expiresAtMs: result.expiresAtMs ?? NOW_MS + 60_000,
        fees: result.fees,
      });
    },
    requestCoopExit: async (req) => {
      exitRequests.push(req);
      const result = required(handlers.requestCoopExit, "requestCoopExit handler")(req);
      return Promise.resolve({
        id: result.id ?? "exit-1",
        status: result.status ?? "TX_SIGNED",
        rawCoopExitTransaction: required(result.rawCoopExitTransaction, "rawCoopExitTransaction"),
        coopExitTxid: required(result.coopExitTxid, "coopExitTxid"),
        rawConnectorTransaction: required(
          result.rawConnectorTransaction,
          "rawConnectorTransaction",
        ),
      });
    },
    completeCoopExit: async (req) => {
      completions.push(req);
      const result = required(handlers.completeCoopExit, "completeCoopExit handler")(req);
      const resolved = await result;
      return { id: resolved.id ?? "exit-1", status: resolved.status };
    },
    coopExitRequest: async (id) => {
      statusReads.push(id);
      const result = required(handlers.coopExitRequest, "coopExitRequest handler")(id);
      return Promise.resolve({
        id: result.id ?? "exit-1",
        status: result.status,
        ...(result.transferId === undefined ? {} : { transferId: result.transferId }),
      });
    },
    staticDepositQuote: async () =>
      Promise.reject(new SparkRequestError("ssp: staticDepositQuote not stubbed")),
    claimStaticDeposit: async () =>
      Promise.reject(new SparkRequestError("ssp: claimStaticDeposit not stubbed")),
  };
  return { ssp, quotes, exitRequests, completions, statusReads };
}

type Setup = {
  deps: Parameters<typeof cooperativeExit>[0];
  calls: CapturedCall[];
  exitRequests: SspCoopExitRequest[];
  completions: Array<{ coopExitRequestId: string; userOutboundTransferExternalId: string }>;
  statusReads: string[];
  deleted: string[][];
  sleeps: number[];
  /** The `amountSats` each `spendLeaves` call selected for (undefined = all leaves). */
  spendAmounts: Array<number | undefined>;
  events: string[];
  frostJobs: FrostSignJob[][];
  payoutTx: Uint8Array;
  connectorTx: Uint8Array;
  coopExitTxid: string;
};

async function exitDeps(overrides: {
  leaves: SparkLeaf[];
  /** SSP-returned transactions; defaults built against `payoutSats`/`leaves.length`. */
  payoutTx?: Uint8Array;
  connectorTx?: Uint8Array;
  payoutSats?: number;
  coopExitTxid?: string;
  fees?: { fast: number; medium: number; slow: number };
  cooperative_exit_v2?: (
    input: Record<string, unknown>,
  ) => Promise<{ transfer?: Transfer }> | { transfer?: Transfer };
  recoveredTransfer?: Transfer;
  complete?: (req: {
    coopExitRequestId: string;
    userOutboundTransferExternalId: string;
  }) => { status: string } | Promise<{ status: string }>;
  exitStatus?: (id: string) => { status: string };
  identityPublicKey?: Uint8Array;
}): Promise<Setup> {
  const base = createSparkSigner({
    crypto: await loadWasmBackend(),
    accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
    network: "regtest",
    random: fixedRandom(),
  });
  const identityPublicKey = await base.identityPublicKey();
  const frostJobs: FrostSignJob[][] = [];
  const signer: SparkSigner = {
    ...base,
    signFrost: async (jobs) => {
      frostJobs.push([...jobs]);
      return base.signFrost(jobs);
    },
  };
  const events: string[] = [];
  const totalSats = overrides.leaves.reduce((sum, leaf) => sum + leaf.valueSats, 0);
  const payoutSats = overrides.payoutSats ?? Math.max(0, totalSats - (overrides.fees?.slow ?? 10));
  const payoutTx = overrides.payoutTx ?? payoutTxFor(WITHDRAW_ADDRESS, payoutSats);
  const coopExitTxid = overrides.coopExitTxid ?? txId(payoutTx);
  const connectorTx =
    overrides.connectorTx ?? connectorTxFor(coopExitTxid, overrides.leaves.length + 1);
  const { spark, calls } = fakeSpark({
    cooperative_exit_v2:
      overrides.cooperative_exit_v2 ??
      ((input) => {
        events.push("commit");
        const transfer = (input["transfer"] as Record<string, unknown>)["transferId"];
        return {
          transfer: transferProto({
            id: String(transfer),
            sender: overrides.identityPublicKey ?? identityPublicKey,
            receiver: SSP_IDENTITY,
            leaves: overrides.leaves,
          }),
        };
      }),
    query_transfers_by_id: () =>
      overrides.recoveredTransfer === undefined ? {} : { transfers: [overrides.recoveredTransfer] },
  });
  const { ssp, exitRequests, completions, statusReads } = fakeSsp({
    coopExitFeeQuote: () => ({ fees: overrides.fees ?? { fast: 100, medium: 50, slow: 10 } }),
    requestCoopExit: () => ({
      rawCoopExitTransaction: payoutTx,
      coopExitTxid,
      rawConnectorTransaction: connectorTx,
    }),
    completeCoopExit:
      overrides.complete ??
      (() => {
        events.push("complete");
        return { status: "TX_BROADCASTED" };
      }),
    coopExitRequest: overrides.exitStatus ?? (() => ({ status: "INITIATED" })),
  });
  const deleted: string[][] = [];
  const sleeps: number[] = [];
  const spendAmounts: Array<number | undefined> = [];
  const deps: CoopExitDeps & {
    spendLeaves: <T>(
      amountSats: number | undefined,
      use: (leaves: ReadonlyArray<SparkLeaf>) => Promise<T>,
    ) => Promise<T>;
    deleteExitChains: (leafIds: ReadonlyArray<string>) => Promise<void>;
  } = {
    spark,
    ssp,
    sspIdentityPublicKey: SSP_IDENTITY,
    signer,
    network: "regtest",
    operators: OPERATORS,
    threshold: THRESHOLD,
    random: fixedRandom(),
    now: () => NOW_MS,
    sleep: async (ms) => {
      sleeps.push(ms);
      return Promise.resolve();
    },
    spendLeaves: async <T>(
      amountSats: number | undefined,
      use: (leaves: ReadonlyArray<SparkLeaf>) => Promise<T>,
    ): Promise<T> => {
      spendAmounts.push(amountSats);
      const result = await use(overrides.leaves);
      events.push("use-resolved");
      return result;
    },
    deleteExitChains: async (leafIds) => {
      events.push("delete");
      deleted.push([...leafIds]);
      return Promise.resolve();
    },
  };
  return {
    deps,
    calls,
    exitRequests,
    completions,
    statusReads,
    deleted,
    sleeps,
    spendAmounts,
    events,
    frostJobs,
    payoutTx,
    connectorTx,
    coopExitTxid,
  };
}

describe("quoteCooperativeExit", () => {
  test("rejects a bad address, a bad amount and empty leaves before the ssp call", async () => {
    const { ssp, quotes } = fakeSsp({
      coopExitFeeQuote: () => ({ fees: { fast: 1, medium: 1, slow: 1 } }),
    });
    const deps = {
      ssp,
      network: "regtest" as const,
      selectLeaves: async () => Promise.resolve([] as SparkLeaf[]),
    };
    await expect(quoteCooperativeExit(deps, { address: "not an address" })).rejects.toBeInstanceOf(
      SparkInputError,
    );
    await expect(
      quoteCooperativeExit(deps, { address: WITHDRAW_ADDRESS, amountSats: 0 }),
    ).rejects.toBeInstanceOf(SparkInputError);
    await expect(quoteCooperativeExit(deps, { address: WITHDRAW_ADDRESS })).rejects.toBeInstanceOf(
      SparkInputError,
    );
    expect(quotes).toStrictEqual([]);
  });

  test("forwards the selected leaf ids and returns the quote", async () => {
    const base = createSparkSigner({
      crypto: await loadWasmBackend(),
      accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
      network: "regtest",
      random: fixedRandom(),
    });
    const leaf = await fabricateLeaf(base, { leafId: "leaf-q" });
    const { ssp, quotes } = fakeSsp({
      coopExitFeeQuote: () => ({ fees: { fast: 101, medium: 67, slow: 33 } }),
    });
    const quote = await quoteCooperativeExit(
      {
        ssp,
        network: "regtest",
        selectLeaves: async (amountSats) => {
          expect(amountSats).toBe(3000);
          return Promise.resolve([leaf]);
        },
      },
      { address: WITHDRAW_ADDRESS, amountSats: 3000 },
    );
    expect(quotes).toStrictEqual([{ leafIds: ["leaf-q"], address: WITHDRAW_ADDRESS }]);
    expect(quote.fees).toStrictEqual({ fast: 101, medium: 67, slow: 33 });
  });
});

describe("cooperativeExit", () => {
  test("happy path: two leaves, signed connector refunds, completion accepted", async () => {
    const signer0 = createSparkSigner({
      crypto: await loadWasmBackend(),
      accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
      network: "regtest",
      random: fixedRandom(),
    });
    const leaf1 = await fabricateLeaf(signer0, { leafId: "leaf-1", valueSats: 60_000n });
    const leaf2 = await fabricateLeaf(signer0, {
      leafId: "leaf-2",
      valueSats: 40_000n,
      directNodeTx: true,
      nodeSequence: 2000,
    });
    const {
      deps,
      calls,
      exitRequests,
      completions,
      deleted,
      spendAmounts,
      events,
      frostJobs,
      payoutTx,
      connectorTx,
      coopExitTxid,
    } = await exitDeps({ leaves: [leaf1, leaf2] });
    const result = await cooperativeExit(deps, {
      address: WITHDRAW_ADDRESS,
      speed: "SLOW",
      maxFeeSats: 10_000,
    });

    expect(result.requestId).toBe("exit-1");
    expect(result.coopExitTxid).toBe(coopExitTxid);
    expect(result.payoutSats).toBe(60_000 + 40_000 - 10);
    expect(result.feeSats).toBe(10);
    expect(result.status).toBe("TX_BROADCASTED");

    // The SSP saw the leaf ids in order, withdraw_all, and the transfer id as the external id.
    expect(exitRequests).toStrictEqual([
      {
        leafIds: ["leaf-1", "leaf-2"],
        withdrawalAddress: WITHDRAW_ADDRESS,
        exitSpeed: "SLOW",
        withdrawAll: true,
        userOutboundTransferExternalId: result.transferId,
      },
    ]);

    const call = required(
      calls.find((c) => c.method === "cooperative_exit_v2"),
      "cooperative_exit_v2 call",
    );
    const input = call.input as Record<string, any>;
    const transfer = input["transfer"] as Record<string, any>;
    expect(transfer["transferId"]).toBe(result.transferId);
    const identity = await deps.signer.identityPublicKey();
    expect(bytesToHex(transfer["ownerIdentityPublicKey"])).toBe(bytesToHex(identity));
    expect(bytesToHex(transfer["receiverIdentityPublicKey"])).toBe(bytesToHex(SSP_IDENTITY));
    // Internal (wire) byte order — the SO's primary comparison, matching the
    // serialized outpoint convention; upstream's accept-either check tolerates both.
    expect(input["exitTxid"]).toStrictEqual(txIdBytes(payoutTx));
    expect(input["connectorTx"]).toStrictEqual(connectorTx);
    const expiryDelta = Number(transfer["expiryTime"].seconds) * 1000 - NOW_MS;
    expect(expiryDelta).toBe(COOP_EXIT_TRANSFER_EXPIRY_MS["regtest"]);

    // Every refund job: two inputs (leaf prevout + connector outpoint i) committed by the sighash.
    const jobs = required(frostJobs[0], "frost jobs");
    const parsedConnector = parseTransaction(connectorTx);
    const leafIndexById = new Map([
      ["leaf-1", 0],
      ["leaf-2", 1],
    ]);
    // leaf1 has no direct tx: cpfp×2 + direct×1 + direct-from-cpfp×2.
    expect(jobs).toHaveLength(5);
    for (const job of jobs) {
      const leafIndex = required(leafIndexById.get(jobLeafId(job)), "job leaf");
      expect(job.target.inputIndex).toBe(0);
      expect(job.target.prevouts).toHaveLength(2);
      const [, connectorPrevout] = job.target.prevouts;
      const expected = parsedConnector.getOutput(leafIndex);
      expect(connectorPrevout?.script).toStrictEqual(expected.script);
      expect(connectorPrevout?.amount).toBe(Number(expected.amount));
      const refund = parseTransaction(job.target.transaction);
      expect(refund.inputsLength).toBe(2);
      const connectorInput = refund.getInput(1);
      expect(connectorInput.index).toBe(leafIndex);
      // Input 1 is the connector-tx outpoint bound to this leaf — the connector
      // tx's own txid, not the coop-exit (payout) txid.
      expect(bytesToHex(required(connectorInput.txid, "connector input txid"))).toBe(
        txId(connectorTx),
      );
      // No adaptor signatures — plain key-spend jobs only.
      expect(job.adaptorPublicKey).toBeUndefined();
      // The sighash commits to both prevouts.
      const sighash = taprootKeySpendSighash({
        transaction: job.target.transaction,
        inputIndex: 0,
        prevouts: job.target.prevouts,
      });
      expect(sighash).toHaveLength(32);
    }
    // The refund pays the SSP identity (receiving key) at output 0.
    const firstRefund = parseTransaction(jobs[0]!.target.transaction);
    expect(firstRefund.getOutput(0).script).toStrictEqual(
      p2trScriptFromPublicKey(SSP_IDENTITY, "regtest"),
    );

    // The exit committed inside `use` (under the client's lock), chains went right after, and
    // the SSP completion ran only once `use` resolved — with all leaves selected (no amount).
    expect(spendAmounts).toStrictEqual([undefined]);
    expect(events).toStrictEqual(["commit", "delete", "use-resolved", "complete"]);
    expect(deleted).toStrictEqual([["leaf-1", "leaf-2"]]);
    expect(completions).toStrictEqual([
      { coopExitRequestId: "exit-1", userOutboundTransferExternalId: result.transferId },
    ]);
  });

  test("rejects before the ssp: bad address, bad fee cap, bad amount, no leaves", async () => {
    const { ssp, quotes, exitRequests } = fakeSsp({});
    const { deps } = await exitDeps({ leaves: [] });
    const base = { address: WITHDRAW_ADDRESS, speed: "SLOW" as const, maxFeeSats: 1000 };
    // A well-formed mainnet address is still wrong on regtest.
    const mainnetAddress = p2trAddressFromPublicKey(WITHDRAW_KEY, "mainnet");
    await expect(
      cooperativeExit(deps, { ...base, address: mainnetAddress }),
    ).rejects.toBeInstanceOf(SparkInputError);
    await expect(
      cooperativeExit(deps, { ...base, address: "not an address" }),
    ).rejects.toBeInstanceOf(SparkInputError);
    await expect(cooperativeExit(deps, { ...base, maxFeeSats: -1 })).rejects.toBeInstanceOf(
      SparkInputError,
    );
    await expect(cooperativeExit(deps, { ...base, amountSats: 3.5 })).rejects.toBeInstanceOf(
      SparkInputError,
    );
    await expect(cooperativeExit(deps, base)).rejects.toThrow("no leaves");
    expect(quotes).toStrictEqual([]);
    expect(exitRequests).toStrictEqual([]);
    void ssp;
  });

  test("enforces maxFeeSats and a positive payout against the speed's quoted fee", async () => {
    const signer0 = createSparkSigner({
      crypto: await loadWasmBackend(),
      accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
      network: "regtest",
      random: fixedRandom(),
    });
    const leaf = await fabricateLeaf(signer0, { leafId: "leaf-f", valueSats: 60n });
    const { deps, exitRequests } = await exitDeps({
      leaves: [leaf],
      fees: { fast: 100, medium: 50, slow: 10 },
    });
    // MEDIUM fee 50 exceeds the cap of 40.
    await expect(
      cooperativeExit(deps, {
        address: WITHDRAW_ADDRESS,
        speed: "MEDIUM",
        maxFeeSats: 40,
      }),
    ).rejects.toThrow("exceeds maxFeeSats");
    // SLOW fee 10 equals the 60-sat leaf total minus... 10 < 60 fine, but fee >= total fails.
    const { deps: deps2 } = await exitDeps({
      leaves: [await fabricateLeaf(signer0, { leafId: "leaf-g", valueSats: 50n })],
      fees: { fast: 100, medium: 50, slow: 50 },
    });
    await expect(
      cooperativeExit(deps2, {
        address: WITHDRAW_ADDRESS,
        speed: "SLOW",
        maxFeeSats: 100,
      }),
    ).rejects.toThrow("leaves no payout");
    expect(exitRequests).toStrictEqual([]);
  });

  test("rejects an inconsistent ssp response: wrong txid, wrong payee, underpay", async () => {
    const signer0 = createSparkSigner({
      crypto: await loadWasmBackend(),
      accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
      network: "regtest",
      random: fixedRandom(),
    });
    const leaf = await fabricateLeaf(signer0, { leafId: "leaf-v", valueSats: 100_000n });
    const options = { address: WITHDRAW_ADDRESS, speed: "SLOW" as const, maxFeeSats: 100 };

    const otherTx = payoutTxFor(WITHDRAW_ADDRESS, 99_990);
    const mismatched = await exitDeps({
      leaves: [leaf],
      coopExitTxid: "00".repeat(32),
      connectorTx: connectorTxFor(txId(otherTx), 2),
    });
    await expect(cooperativeExit(mismatched.deps, options)).rejects.toThrow(
      "does not match rawCoopExitTransaction",
    );

    const wrongPayee = await exitDeps({
      leaves: [leaf],
      payoutTx: payoutTxFor(
        p2trAddressFromPublicKey(
          secp256k1.getPublicKey(new Uint8Array(32).fill(78), true),
          "regtest",
        ),
        99_990,
      ),
    });
    await expect(cooperativeExit(wrongPayee.deps, options)).rejects.toThrow(
      "no output pays the requested address",
    );

    const underpay = await exitDeps({
      leaves: [leaf],
      payoutTx: payoutTxFor(WITHDRAW_ADDRESS, 50_000),
    });
    await expect(cooperativeExit(underpay.deps, options)).rejects.toThrow(
      "no output pays the requested address",
    );
  });

  test("rejects a connector that does not spend the payout or has the wrong shape", async () => {
    const signer0 = createSparkSigner({
      crypto: await loadWasmBackend(),
      accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
      network: "regtest",
      random: fixedRandom(),
    });
    const leaf = await fabricateLeaf(signer0, { leafId: "leaf-c", valueSats: 100_000n });
    const options = { address: WITHDRAW_ADDRESS, speed: "SLOW" as const, maxFeeSats: 100 };

    const wrongParent = await exitDeps({
      leaves: [leaf],
      connectorTx: connectorTxFor("11".repeat(32), 2),
    });
    await expect(cooperativeExit(wrongParent.deps, options)).rejects.toThrow(
      "does not spend coopExitTxId",
    );

    // One leaf expects two connector outputs (leaf output + anchor); a third output shifts the
    // leaf↔output mapping. The connector still spends its own payout — only the count is wrong.
    const payout = payoutTxFor(WITHDRAW_ADDRESS, 99_990);
    const wrongCount = await exitDeps({
      leaves: [leaf],
      payoutTx: payout,
      connectorTx: connectorTxFor(txId(payout), 3),
    });
    await expect(cooperativeExit(wrongCount.deps, options)).rejects.toThrow(
      "outputs, expected 1 + anchor",
    );

    const malformed = await exitDeps({
      leaves: [leaf],
      connectorTx: new Uint8Array([0xde, 0xad]),
    });
    await expect(cooperativeExit(malformed.deps, options)).rejects.toThrow(SparkInputError);
  });

  test("rejects a committed transfer that is not ours to the SSP", async () => {
    const signer0 = createSparkSigner({
      crypto: await loadWasmBackend(),
      accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
      network: "regtest",
      random: fixedRandom(),
    });
    const leaf = await fabricateLeaf(signer0, { leafId: "leaf-t", valueSats: 100_000n });
    const identity = await signer0.identityPublicKey();
    const { deps } = await exitDeps({
      leaves: [leaf],
      cooperative_exit_v2: (input) => ({
        transfer: transferProto({
          id: String((input["transfer"] as Record<string, unknown>)["transferId"]),
          sender: identity,
          receiver: secp256k1.getPublicKey(new Uint8Array(32).fill(42), true),
          leaves: [leaf],
        }),
      }),
    });
    await expect(
      cooperativeExit(deps, { address: WITHDRAW_ADDRESS, speed: "SLOW", maxFeeSats: 100 }),
    ).rejects.toThrow("committed transfer is not ours");
  });

  test("recovers a lost cooperative_exit_v2 response by transfer id", async () => {
    const signer0 = createSparkSigner({
      crypto: await loadWasmBackend(),
      accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
      network: "regtest",
      random: fixedRandom(),
    });
    const leaf = await fabricateLeaf(signer0, { leafId: "leaf-r", valueSats: 100_000n });
    const identity = await signer0.identityPublicKey();
    const recovered = transferProto({
      id: "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
      sender: identity,
      receiver: SSP_IDENTITY,
      leaves: [leaf],
    });
    const { deps, deleted, completions } = await exitDeps({
      leaves: [leaf],
      cooperative_exit_v2: async () => Promise.reject(new SparkRequestError("response lost")),
      recoveredTransfer: recovered,
    });
    const result = await cooperativeExit(deps, {
      address: WITHDRAW_ADDRESS,
      speed: "SLOW",
      maxFeeSats: 100,
      transferId: recovered.id,
    });
    expect(result.transferId).toBe(recovered.id);
    expect(deleted).toStrictEqual([["leaf-r"]]);
    expect(completions[0]?.userOutboundTransferExternalId).toBe(recovered.id);
  });

  test("rethrows the original error when nothing committed", async () => {
    const signer0 = createSparkSigner({
      crypto: await loadWasmBackend(),
      accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
      network: "regtest",
      random: fixedRandom(),
    });
    const leaf = await fabricateLeaf(signer0, { leafId: "leaf-x", valueSats: 100_000n });
    const { deps } = await exitDeps({
      leaves: [leaf],
      cooperative_exit_v2: async () => Promise.reject(new SparkRequestError("response lost")),
    });
    await expect(
      cooperativeExit(deps, { address: WITHDRAW_ADDRESS, speed: "SLOW", maxFeeSats: 100 }),
    ).rejects.toThrow("response lost");
  });

  test("a recovered transfer of another type does not continue", async () => {
    const signer0 = createSparkSigner({
      crypto: await loadWasmBackend(),
      accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
      network: "regtest",
      random: fixedRandom(),
    });
    const leaf = await fabricateLeaf(signer0, { leafId: "leaf-w", valueSats: 100_000n });
    const identity = await signer0.identityPublicKey();
    const { deps } = await exitDeps({
      leaves: [leaf],
      cooperative_exit_v2: async () => Promise.reject(new SparkRequestError("response lost")),
      recoveredTransfer: transferProto({
        id: "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee",
        sender: identity,
        receiver: SSP_IDENTITY,
        type: TransferType.TRANSFER,
        leaves: [leaf],
      }),
    });
    await expect(
      cooperativeExit(deps, { address: WITHDRAW_ADDRESS, speed: "SLOW", maxFeeSats: 100 }),
    ).rejects.toThrow("response lost");
  });

  test("a failed completion retries on status: accepted resolves, failed throws, unknown retries out", async () => {
    const signer0 = createSparkSigner({
      crypto: await loadWasmBackend(),
      accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
      network: "regtest",
      random: fixedRandom(),
    });
    const leaf = await fabricateLeaf(signer0, { leafId: "leaf-s", valueSats: 100_000n });
    const options = { address: WITHDRAW_ADDRESS, speed: "SLOW" as const, maxFeeSats: 100 };

    // First completion fails; the status read shows the SSP already accepted the request.
    const accepted = await exitDeps({
      leaves: [leaf],
      complete: () => {
        throw new SparkRequestError("complete failed");
      },
      exitStatus: () => ({ status: "SUCCEEDED" }),
    });
    await expect(cooperativeExit(accepted.deps, options)).resolves.toMatchObject({
      status: "SUCCEEDED",
    });
    expect(accepted.sleeps).toStrictEqual([2000]);
    expect(accepted.statusReads).toStrictEqual(["exit-1"]);

    // Terminal failure on the status read — thrown, not retried into a second completion.
    const failed = await exitDeps({
      leaves: [leaf],
      complete: () => {
        throw new SparkRequestError("complete failed");
      },
      exitStatus: () => ({ status: "FAILED" }),
    });
    await expect(cooperativeExit(failed.deps, options)).rejects.toThrow("ssp reports FAILED");
    expect(failed.completions).toHaveLength(1);

    // Still pending after every status read: three completions, then the last error surfaces.
    const pending = await exitDeps({
      leaves: [leaf],
      complete: () => {
        throw new SparkRequestError("complete failed");
      },
      exitStatus: () => ({ status: "INITIATED" }),
    });
    await expect(cooperativeExit(pending.deps, options)).rejects.toThrow("complete failed");
    expect(pending.completions).toHaveLength(3);
    expect(pending.sleeps).toStrictEqual([2000, 2000]);
  });

  test("an all-leaves exit renews a stale leaf before building connector refunds", async () => {
    const signer0 = createSparkSigner({
      crypto: await loadWasmBackend(),
      accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
      network: "regtest",
      random: fixedRandom(),
    });
    const identityPublicKey = await signer0.identityPublicKey();
    // Refund timelock 100 is below the renewal threshold; the node timelock is already zero,
    // so the leaf takes the zero-timelock renewal path.
    const staleLeaf = await fabricateLeaf(signer0, {
      leafId: "leaf-stale",
      valueSats: 60_000n,
      refundSequence: 100,
    });
    let renewedNodeTx: Uint8Array | undefined;
    const { spark, calls } = fakeSpark({
      renew_leaf: (input) => {
        const result = renewZeroTimelockResult(staleLeaf, input);
        renewedNodeTx = result.nodeTx;
        return result.response;
      },
      cooperative_exit_v2: (input) => ({
        transfer: transferProto({
          id: String((input["transfer"] as Record<string, unknown>)["transferId"]),
          sender: identityPublicKey,
          receiver: SSP_IDENTITY,
          leaves: [staleLeaf],
        }),
      }),
    });
    const payoutTx = payoutTxFor(WITHDRAW_ADDRESS, 60_000 - 10);
    const coopExitTxid = txId(payoutTx);
    const { ssp, exitRequests } = fakeSsp({
      coopExitFeeQuote: () => ({ fees: { fast: 100, medium: 50, slow: 10 } }),
      requestCoopExit: () => ({
        rawCoopExitTransaction: payoutTx,
        coopExitTxid,
        rawConnectorTransaction: connectorTxFor(coopExitTxid, 2),
      }),
      completeCoopExit: () => ({ status: "TX_BROADCASTED" }),
    });
    const regtest = sparkNetworkConfig("regtest");
    const context: ClientContext = {
      coordinatorConnection: {
        operator: required(OPERATORS[0], "coordinator operator"),
        spark,
        token: undefined as never,
        invalidateSession: () => {},
      },
      otherConnections: [],
      signer: signer0,
      network: "regtest",
      config: {
        ...regtest,
        operators: OPERATORS,
        threshold: THRESHOLD,
        ssp: { ...regtest.ssp, identityPublicKey: SSP_IDENTITY },
      },
      operators: OPERATORS,
      store: createMemorySparkStore(),
      random: fixedRandom(),
      now: () => NOW_MS,
      sleep: async () => Promise.resolve(),
      transferCoordinator: {
        spark,
        signer: signer0,
        network: "regtest",
        operators: OPERATORS,
        threshold: THRESHOLD,
      },
      depositCoordinator: {
        spark,
        signer: signer0,
        network: "regtest",
        operators: OPERATORS,
        coordinatorIdentifier: required(OPERATORS[0], "coordinator").identifier,
      },
      sspClient: ssp,
      leafLock: createMutex(),
      tokenLock: createMutex(),
      storeChainsFor: async () => Promise.resolve(),
      syncLeaves: async () => Promise.resolve([staleLeaf]),
      leaves: async () => Promise.resolve([staleLeaf]),
      receiverIdentityKey: () => {
        throw new Error("receiverIdentityKey not stubbed");
      },
      tokenIdentifierForNetwork: () => {
        throw new Error("tokenIdentifierForNetwork not stubbed");
      },
    };
    const result = await createWithdrawals(context).cooperativeExit({
      address: WITHDRAW_ADDRESS,
      speed: "SLOW",
      maxFeeSats: 10_000,
    });
    expect(result.status).toBe("TX_BROADCASTED");
    expect(exitRequests[0]?.leafIds).toStrictEqual(["leaf-stale"]);

    const methods = calls.map((call) => call.method);
    const renewed = required(renewedNodeTx, "renewed node tx");
    // The renewal RPC ran before the commit, and the connector refunds were signed over the
    // renewed node tx — proof the stale leaf was renewed before refund construction.
    expect(methods.indexOf("renew_leaf")).toBeGreaterThanOrEqual(0);
    expect(methods.indexOf("renew_leaf")).toBeLessThan(methods.indexOf("cooperative_exit_v2"));
    const commit = required(
      calls.find((call) => call.method === "cooperative_exit_v2"),
      "cooperative_exit_v2 call",
    );
    const transfer = commit.input["transfer"] as {
      transferPackage?: { leavesToSend?: Array<{ rawTx?: Uint8Array }> };
    };
    const firstJob = required(transfer.transferPackage?.leavesToSend?.[0], "refund job");
    const refundInput = parseTransaction(required(firstJob.rawTx, "refund rawTx")).getInput(0);
    expect(bytesToHex(required(refundInput.txid, "refund input txid"))).toBe(txId(renewed));
  });
});

test("cooperativeExitStatus proxies the user_request lookup", async () => {
  const { ssp, statusReads } = fakeSsp({
    coopExitRequest: () => ({ status: "ON_CHAIN_TX_CONFIRMED", transferId: "tr-9" }),
  });
  const status = await cooperativeExitStatus({ ssp }, "exit-9");
  expect(status).toStrictEqual({
    id: "exit-1",
    status: "ON_CHAIN_TX_CONFIRMED",
    transferId: "tr-9",
  });
  expect(statusReads).toStrictEqual(["exit-9"]);
});
