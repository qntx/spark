import { create } from "@bufbuild/protobuf";
import type { Client } from "@connectrpc/connect";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { numberToBytesBE, numberToVarBytesBE } from "@noble/curves/utils.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { encodeSparkAddress } from "../src/core/address.ts";
import { encodeInvoiceFields } from "../src/core/invoice.ts";
import type { SparkInvoiceFields } from "../src/core/invoice.ts";
import { finalizeTokenInvoice, prepareTokenInvoice } from "../src/core/token-invoice.ts";
import { SparkError, SparkInputError } from "../src/errors/index.ts";
import { createSatsInvoice, createTokensInvoice, parseSparkInvoice } from "../src/invoice/index.ts";
import {
  GetSigningCommitmentsResponseSchema,
  HashVariant,
  InvoiceStatus,
  Network,
  QueryNodesResponseSchema,
  QuerySparkInvoicesResponseSchema,
  QueryTransfersResponseSchema,
  StartTransferResponseSchema,
  TransferSchema,
  TransferStatus,
  TransferType,
  TreeNodeSchema,
  TreeNodeStatus,
} from "../src/proto/gen/spark_pb.ts";
import type {
  GetSigningCommitmentsRequest,
  QuerySparkInvoicesRequest,
  StartTransferRequest,
  Transfer,
} from "../src/proto/gen/spark_pb.ts";
import { CommitStatus, TokenOutputStatus } from "../src/proto/gen/spark_token_pb.ts";
import type {
  BroadcastTransactionRequest,
  BroadcastTransactionResponse,
  QueryTokenOutputsResponse,
  SparkTokenService,
} from "../src/proto/gen/spark_token_pb.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import type { SparkSigner } from "../src/signer/index.ts";
import { buildTransferPartial, broadcastPartialTokenTransaction } from "../src/tokens/index.ts";
import type { TokenNetworkParams } from "../src/tokens/index.ts";
import type { SparkLeaf } from "../src/tree/index.ts";
import { loadWasmBackend } from "./support/backend.ts";
import {
  commitmentGroup,
  fabricateLeaf,
  fixedRandom,
  makeTestClient,
  OPERATORS,
  required,
  SHARE_PUB,
  THRESHOLD,
} from "./support/fakes.ts";

const LEAF_ID = "01989abc-def0-7abc-89ab-cdef01234567";
const NOW = 1_700_000_000_000;
const TOKEN_ID = hexToBytes("ab".repeat(32));

const TOKENS: TokenNetworkParams = {
  withdrawBondSats: 10_000,
  withdrawRelativeBlockLocktime: 1000,
  validityDurationSeconds: 180,
};

async function testSigner(secretFill: number): Promise<SparkSigner> {
  return createSparkSigner({
    crypto: await loadWasmBackend(),
    accountKey: sparkAccountKey(new Uint8Array(32).fill(secretFill), "regtest"),
    network: "regtest",
    random: fixedRandom(),
  });
}

function leafNode(leaf: SparkLeaf) {
  return create(TreeNodeSchema, {
    id: leaf.id,
    treeId: leaf.treeId,
    value: 100_000n,
    nodeTx: leaf.nodeTx,
    refundTx: leaf.refundTx,
    vout: 0,
    verifyingPublicKey: leaf.verifyingPublicKey,
    ownerIdentityPublicKey: leaf.ownerIdentityPublicKey,
    ownerSigningPublicKey: leaf.ownerSigningPublicKey,
    signingKeyshare: {
      ownerIdentifiers: OPERATORS.map((op) => op.identifier),
      threshold: THRESHOLD,
      publicKey: SHARE_PUB,
      publicShares: {},
    },
    status: "AVAILABLE",
    network: Network.REGTEST,
    treenodeStatus: TreeNodeStatus.AVAILABLE,
  });
}

type SparkImpl = Partial<{
  query_nodes: (req: unknown) => unknown;
  get_signing_commitments: (req: GetSigningCommitmentsRequest) => unknown;
  start_transfer_v2: (req: StartTransferRequest) => unknown;
  query_spark_invoices: (req: QuerySparkInvoicesRequest) => unknown;
}>;

type TokenImpl = Partial<{
  query_token_outputs: (req: { tokenIdentifiers: Uint8Array[] }) => QueryTokenOutputsResponse;
  broadcast_transaction: (req: BroadcastTransactionRequest) => BroadcastTransactionResponse;
}>;

function makeClient(signer: SparkSigner, sparkImpl: SparkImpl, tokenImpl?: TokenImpl) {
  return makeTestClient({
    signer,
    spark: sparkImpl,
    token: {
      query_token_outputs: (req: { tokenIdentifiers: Uint8Array[] }) =>
        tokenImpl?.query_token_outputs?.(req) ?? {
          $typeName: "spark_token.QueryTokenOutputsResponse",
          outputsWithPreviousTransactionData: [],
        },
      broadcast_transaction: (req: BroadcastTransactionRequest) =>
        tokenImpl?.broadcast_transaction?.(req) ?? {
          $typeName: "spark_token.BroadcastTransactionResponse",
          commitStatus: CommitStatus.COMMIT_FINALIZED,
        },
    },
    now: () => NOW,
  });
}

/** Wraps a signer to capture the invoice bytes it was asked to sign. */
function capturing(base: SparkSigner): {
  signer: SparkSigner;
  signed: () => Uint8Array | undefined;
} {
  const box: { value: Uint8Array | undefined } = { value: undefined };
  return {
    signer: {
      ...base,
      signIdentity: async (statement) => {
        if (statement.kind === "spark-invoice") {
          box.value = statement.invoice;
        }
        return base.signIdentity(statement);
      },
    },
    signed: () => box.value,
  };
}

describe("createSatsInvoice", () => {
  test("creates a signed invoice that parses back with the same fields and signed bytes", async () => {
    const base = await testSigner(11);
    const { signer, signed } = capturing(base);
    const identity = await base.identityPublicKey();
    const sender = secp256k1.getPublicKey(new Uint8Array(32).fill(44), true);
    const invoice = await createSatsInvoice({
      signer,
      network: "regtest",
      random: fixedRandom(),
      now: () => NOW,
      amountSats: 5000,
      memo: "lunch",
      senderPublicKey: sender,
      expiresAtMs: NOW + 60_000,
    });
    const parsed = parseSparkInvoice(invoice, { network: "regtest", now: NOW });
    expect(parsed.signed).toBe(true);
    expect(parsed.receiverIdentityPublicKey).toStrictEqual(identity);
    expect(parsed.fields.version).toBe(1);
    expect(parsed.fields.payment).toStrictEqual({ type: "sats", amount: 5000 });
    expect(parsed.fields.memo).toBe("lunch");
    expect(parsed.fields.senderPublicKey).toStrictEqual(sender);
    expect(parsed.fields.expiresAt).toBe(NOW + 60_000);
    // The address embeds exactly the bytes the signer was asked to sign.
    expect(encodeInvoiceFields(parsed.fields)).toStrictEqual(required(signed(), "invoice bytes"));
    base.dispose();
  });

  test("creates an open-amount invoice", async () => {
    const signer = await testSigner(11);
    const invoice = await createSatsInvoice({
      signer,
      network: "regtest",
      random: fixedRandom(),
      now: () => NOW,
    });
    const parsed = parseSparkInvoice(invoice, { network: "regtest", now: NOW });
    expect(parsed.fields.payment).toStrictEqual({ type: "sats", amount: undefined });
    signer.dispose();
  });
});

describe("createTokensInvoice", () => {
  test("creates a signed token invoice that parses back with the same fields and signed bytes", async () => {
    const base = await testSigner(22);
    const { signer, signed } = capturing(base);
    const invoice = await createTokensInvoice({
      signer,
      network: "regtest",
      random: fixedRandom(),
      now: () => NOW,
      tokenIdentifier: TOKEN_ID,
      amount: 400n,
      memo: "token sale",
    });
    const parsed = parseSparkInvoice(invoice, { network: "regtest", now: NOW });
    expect(parsed.signed).toBe(true);
    expect(parsed.fields.payment).toStrictEqual({
      type: "tokens",
      tokenIdentifier: TOKEN_ID,
      amount: numberToVarBytesBE(400n),
    });
    expect(encodeInvoiceFields(parsed.fields)).toStrictEqual(required(signed(), "invoice bytes"));
    base.dispose();
  });

  test("encodes the token amount as minimal big-endian bytes and bounds it to uint128", async () => {
    const signer = await testSigner(22);
    const invoice = await createTokensInvoice({
      signer,
      network: "regtest",
      random: fixedRandom(),
      now: () => NOW,
      tokenIdentifier: TOKEN_ID,
      amount: 400n,
    });
    const parsed = parseSparkInvoice(invoice, { network: "regtest", now: NOW });
    // 400n encodes as 0x0190 — minimal, not the 16-byte wire form.
    expect(parsed.fields.payment).toStrictEqual({
      type: "tokens",
      tokenIdentifier: TOKEN_ID,
      amount: hexToBytes("0190"),
    });
    await expect(
      createTokensInvoice({
        signer,
        network: "regtest",
        random: fixedRandom(),
        now: () => NOW,
        tokenIdentifier: TOKEN_ID,
        amount: 0n,
      }),
    ).rejects.toThrow(SparkInputError);
    await expect(
      createTokensInvoice({
        signer,
        network: "regtest",
        random: fixedRandom(),
        now: () => NOW,
        tokenIdentifier: TOKEN_ID,
        amount: 1n << 128n,
      }),
    ).rejects.toThrow(SparkInputError);
    signer.dispose();
  });

  test("the signer's digest equals prepared.invoiceHash", async () => {
    const signer = await testSigner(22);
    const identity = await signer.identityPublicKey();
    const prepared = prepareTokenInvoice({
      receiverIdentityPublicKey: identity,
      network: "regtest",
      tokenIdentifier: TOKEN_ID,
      tokenAmount: numberToVarBytesBE(7n),
      random: fixedRandom(),
      now: () => NOW,
    });
    const signature = await signer.signIdentity({
      kind: "spark-invoice",
      invoice: prepared.invoiceFieldsBytes,
    });
    expect(schnorr.verify(signature, prepared.invoiceHash, identity.slice(1))).toBe(true);
    const address = finalizeTokenInvoice({
      receiverIdentityPublicKey: identity,
      network: "regtest",
      invoiceFieldsBytes: prepared.invoiceFieldsBytes,
      signature,
    });
    expect(parseSparkInvoice(address, { network: "regtest", now: NOW }).signed).toBe(true);
    signer.dispose();
  });
});

describe("parseSparkInvoice", () => {
  test("rejects a non-invoice address", async () => {
    const signer = await testSigner(11);
    const address = encodeSparkAddress({
      network: "regtest",
      identityPublicKey: await signer.identityPublicKey(),
    });
    expect(() => parseSparkInvoice(address, { network: "regtest", now: NOW })).toThrow(
      SparkInputError,
    );
    signer.dispose();
  });

  test("rejects an invoice for another network", async () => {
    const signer = await testSigner(11);
    const invoice = await createSatsInvoice({
      signer,
      network: "regtest",
      random: fixedRandom(),
      now: () => NOW,
      amountSats: 1,
    });
    expect(() => parseSparkInvoice(invoice, { network: "mainnet", now: NOW })).toThrow(
      SparkInputError,
    );
    signer.dispose();
  });

  test("rejects an invoice with an invalid signature", async () => {
    const signer = await testSigner(11);
    const identity = await signer.identityPublicKey();
    const fields: SparkInvoiceFields = {
      version: 1,
      id: "01989abc-def0-7abc-89ab-cdef01234567",
      payment: { type: "sats", amount: 1 },
    };
    const address = encodeSparkAddress({
      network: "regtest",
      identityPublicKey: identity,
      invoice: fields,
      signature: new Uint8Array(64).fill(7),
    });
    expect(() => parseSparkInvoice(address, { network: "regtest", now: NOW })).toThrow(
      SparkInputError,
    );
    signer.dispose();
  });

  test("rejects an expired invoice", async () => {
    const signer = await testSigner(11);
    const invoice = await createSatsInvoice({
      signer,
      network: "regtest",
      random: fixedRandom(),
      now: () => NOW - 120_000,
      amountSats: 1,
      expiresAtMs: NOW - 60_000,
    });
    expect(() => parseSparkInvoice(invoice, { network: "regtest", now: NOW })).toThrow(
      SparkInputError,
    );
    signer.dispose();
  });
});

describe("client.invoices", () => {
  async function leafNodeFor(signer: SparkSigner) {
    const identity = await signer.identityPublicKey();
    const [leafKey] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const { leaf } = fabricateLeaf({
      leafId: LEAF_ID,
      signingPublicKey: required(leafKey, "leaf public key"),
      ownerIdentityPublicKey: identity,
    });
    return leafNode(leaf);
  }

  function sparkSendImpl(
    node: ReturnType<typeof leafNode>,
    capture: { value: StartTransferRequest | undefined },
  ) {
    const served: Transfer[] = [];
    return {
      query_nodes: () =>
        create(QueryNodesResponseSchema, {
          nodes: { [node.id]: node },
          offset: -1n,
        }),
      get_signing_commitments: () =>
        create(GetSigningCommitmentsResponseSchema, {
          signingCommitments: commitmentGroup(3),
        }),
      start_transfer_v2: (req: StartTransferRequest) => {
        capture.value = req;
        const transfer = create(TransferSchema, {
          id: req.transferId,
          senderIdentityPublicKey: req.ownerIdentityPublicKey,
          receiverIdentityPublicKey: req.receiverIdentityPublicKey,
          status: TransferStatus.SENDER_INITIATED,
          type: TransferType.TRANSFER,
          network: Network.REGTEST,
          totalValue: 100_000n,
        });
        served.push(transfer);
        return create(StartTransferResponseSchema, { transfer });
      },
      query_transfers_by_id: () => create(QueryTransfersResponseSchema, { transfers: [...served] }),
    };
  }

  test("pay passes the invoice string to start_transfer_v2", async () => {
    const payer = await testSigner(11);
    const receiver = await testSigner(22);
    const node = await leafNodeFor(payer);
    const invoice = await createSatsInvoice({
      signer: receiver,
      network: "regtest",
      random: fixedRandom(),
      now: () => NOW,
      amountSats: 100_000,
    });
    const capture: { value: StartTransferRequest | undefined } = { value: undefined };
    const client = makeClient(payer, sparkSendImpl(node, capture));
    const paid = await client.invoices.pay(invoice);
    const request = required(capture.value, "start_transfer_v2 request");
    expect(request.sparkInvoice).toBe(invoice);
    expect(request.receiverIdentityPublicKey).toStrictEqual(await receiver.identityPublicKey());
    const pkg = required(request.transferPackage, "transfer package");
    expect(pkg.hashVariant).toBe(HashVariant.V2);
    expect(paid).toBeTypeOf("object");
    client.close();
    payer.dispose();
    receiver.dispose();
  });

  test("pay rejects a mismatched amount on a fixed sats invoice", async () => {
    const payer = await testSigner(11);
    const receiver = await testSigner(22);
    const invoice = await createSatsInvoice({
      signer: receiver,
      network: "regtest",
      random: fixedRandom(),
      now: () => NOW,
      amountSats: 100_000,
    });
    const client = makeClient(payer, {});
    await expect(client.invoices.pay(invoice, { amount: 99_999 })).rejects.toThrow(SparkInputError);
    client.close();
    payer.dispose();
    receiver.dispose();
  });

  test("pay requires an amount on an open sats invoice", async () => {
    const payer = await testSigner(11);
    const receiver = await testSigner(22);
    const invoice = await createSatsInvoice({
      signer: receiver,
      network: "regtest",
      random: fixedRandom(),
      now: () => NOW,
    });
    const client = makeClient(payer, {});
    await expect(client.invoices.pay(invoice)).rejects.toThrow(SparkInputError);
    await expect(client.invoices.pay(invoice, { amount: 0 })).rejects.toThrow(SparkInputError);
    await expect(client.invoices.pay(invoice, { amount: 1.5 })).rejects.toThrow(SparkInputError);
    client.close();
    payer.dispose();
    receiver.dispose();
  });

  test("pay rejects an invoice restricted to a different sender", async () => {
    const payer = await testSigner(11);
    const receiver = await testSigner(22);
    const other = secp256k1.getPublicKey(new Uint8Array(32).fill(44), true);
    const invoice = await createSatsInvoice({
      signer: receiver,
      network: "regtest",
      random: fixedRandom(),
      now: () => NOW,
      amountSats: 1,
      senderPublicKey: other,
    });
    const client = makeClient(payer, {});
    await expect(client.invoices.pay(invoice)).rejects.toThrow(SparkInputError);
    client.close();
    payer.dispose();
    receiver.dispose();
  });

  test("pay rejects a token invoice without a token identifier", async () => {
    const payer = await testSigner(11);
    const receiver = await testSigner(22);
    const invoice = await createTokensInvoice({
      signer: receiver,
      network: "regtest",
      random: fixedRandom(),
      now: () => NOW,
      amount: 5n,
    });
    const client = makeClient(payer, {});
    await expect(client.invoices.pay(invoice)).rejects.toThrow(SparkInputError);
    client.close();
    payer.dispose();
    receiver.dispose();
  });

  function tokenRow(id: string, amount: bigint, ownerPublicKey: Uint8Array) {
    return {
      $typeName: "spark_token.OutputWithPreviousTransactionData" as const,
      output: {
        $typeName: "spark_token.TokenOutput" as const,
        id,
        ownerPublicKey,
        tokenIdentifier: TOKEN_ID,
        tokenAmount: numberToBytesBE(amount, 16),
        status: TokenOutputStatus.AVAILABLE,
      },
      previousTransactionHash: hexToBytes("ee".repeat(32)),
      previousTransactionVout: 0,
    };
  }

  test("pay attaches the invoice to the token transaction and returns the final hash", async () => {
    const payer = await testSigner(11);
    const receiver = await testSigner(22);
    const owner = await payer.identityPublicKey();
    const invoice = await createTokensInvoice({
      signer: receiver,
      network: "regtest",
      random: fixedRandom(),
      now: () => NOW,
      tokenIdentifier: TOKEN_ID,
    });
    const capture: { value: BroadcastTransactionRequest | undefined } = { value: undefined };
    const client = makeClient(
      payer,
      {},
      {
        query_token_outputs: () => ({
          $typeName: "spark_token.QueryTokenOutputsResponse",
          outputsWithPreviousTransactionData: [tokenRow("o1", 100n, owner)],
        }),
        broadcast_transaction: (req) => {
          capture.value = req;
          const partial = required(req.partialTokenTransaction, "partial token transaction");
          return {
            $typeName: "spark_token.BroadcastTransactionResponse",
            commitStatus: CommitStatus.COMMIT_FINALIZED,
            finalTokenTransaction: {
              $typeName: "spark_token.FinalTokenTransaction",
              version: partial.version,
              tokenTransactionMetadata: partial.tokenTransactionMetadata,
              tokenInputs: partial.tokenInputs,
              finalTokenOutputs: required(partial.partialTokenOutputs, "partial outputs").map(
                (output) => ({
                  $typeName: "spark_token.FinalTokenOutput" as const,
                  partialTokenOutput: output,
                  revocationCommitment: new Uint8Array(33).fill(2),
                }),
              ),
            },
          };
        },
      },
    );
    const hash = await client.invoices.pay(invoice, { amount: 40n });
    expect(hash).toBeTypeOf("string");
    const request = required(capture.value, "broadcast request");
    const metadata = required(
      request.partialTokenTransaction?.tokenTransactionMetadata,
      "token transaction metadata",
    );
    expect(metadata.invoiceAttachments.map((a) => a.sparkInvoice)).toStrictEqual([invoice]);
    client.close();
    payer.dispose();
    receiver.dispose();
  });

  test("status maps coordinator invoice statuses", async () => {
    const payer = await testSigner(11);
    const transferId = hexToBytes("12".repeat(16));
    const tokenHash = hexToBytes("34".repeat(32));
    const client = makeClient(payer, {
      query_spark_invoices: () =>
        create(QuerySparkInvoicesResponseSchema, {
          invoiceStatuses: [
            {
              invoice: "inv-a",
              status: InvoiceStatus.FINALIZED,
              transferType: { case: "satsTransfer", value: { transferId } },
            },
            {
              invoice: "inv-b",
              status: InvoiceStatus.PENDING,
              transferType: {
                case: "tokenTransfer",
                value: { finalTokenTransactionHash: tokenHash },
              },
            },
            { invoice: "inv-c", status: InvoiceStatus.NOT_FOUND },
          ],
        }),
    });
    const statuses = await client.invoices.status(["inv-a", "inv-b", "inv-c"]);
    expect(statuses).toStrictEqual([
      {
        invoice: "inv-a",
        status: "FINALIZED",
        satsTransferId: bytesToHex(transferId),
      },
      {
        invoice: "inv-b",
        status: "PENDING",
        tokenTransactionHash: bytesToHex(tokenHash),
      },
      { invoice: "inv-c", status: "NOT_FOUND" },
    ]);
    client.close();
    payer.dispose();
  });
});

describe("token invoice attachments", () => {
  const OWNER = secp256k1.getPublicKey(new Uint8Array(32).fill(3), true);
  const RECEIVER = secp256k1.getPublicKey(new Uint8Array(32).fill(4), true);

  function partialWithAttachments(attachments: string[]) {
    return buildTransferPartial({
      selectedOutputs: [
        {
          id: "a",
          tokenIdentifier: TOKEN_ID,
          amount: 100n,
          prevTransactionHash: hexToBytes("ee".repeat(32)),
          prevTransactionVout: 0,
          ownerPublicKey: OWNER,
        },
      ],
      receiverPublicKey: RECEIVER,
      tokenIdentifier: TOKEN_ID,
      amount: 40n,
      senderPublicKey: OWNER,
      network: "regtest",
      operators: OPERATORS,
      tokens: TOKENS,
      now: () => NOW,
      invoiceAttachments: attachments,
    });
  }

  test("sorts attachments by plain string order", () => {
    const partial = partialWithAttachments(["inv-z", "inv-a", "inv-m"]);
    expect(
      partial.tokenTransactionMetadata?.invoiceAttachments.map((a) => a.sparkInvoice),
    ).toStrictEqual(["inv-a", "inv-m", "inv-z"]);
  });

  test("rejects a final transaction with different attachments", async () => {
    const payer = await testSigner(11);
    const partial = partialWithAttachments(["inv-a"]);
    const token = {
      broadcast_transaction: async () => {
        await Promise.resolve();
        return {
          $typeName: "spark_token.BroadcastTransactionResponse" as const,
          commitStatus: CommitStatus.COMMIT_FINALIZED,
          finalTokenTransaction: {
            $typeName: "spark_token.FinalTokenTransaction" as const,
            version: partial.version,
            tokenTransactionMetadata: {
              ...required(partial.tokenTransactionMetadata, "metadata"),
              invoiceAttachments: [
                { $typeName: "spark_token.InvoiceAttachment" as const, sparkInvoice: "inv-other" },
              ],
            },
            tokenInputs: partial.tokenInputs,
            finalTokenOutputs: partial.partialTokenOutputs.map((output) => ({
              $typeName: "spark_token.FinalTokenOutput" as const,
              partialTokenOutput: output,
              revocationCommitment: new Uint8Array(33).fill(2),
            })),
          },
        };
      },
    } as unknown as Client<typeof SparkTokenService>;
    await expect(
      broadcastPartialTokenTransaction({
        token,
        signer: payer,
        partial,
        network: "regtest",
        operators: OPERATORS,
        tokens: TOKENS,
      }),
    ).rejects.toThrow(SparkError);
    payer.dispose();
  });
});
