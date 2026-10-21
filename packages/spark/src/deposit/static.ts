import { create } from "@bufbuild/protobuf";
import type { CallOptions } from "@connectrpc/connect";
import { equalBytes } from "@noble/curves/utils.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { Address as BitcoinAddress, OutScript, Transaction } from "@scure/btc-signer";

import { assertU32, u64ToSats } from "../core/assert.ts";
import {
  assertFeeRate,
  btcNetwork,
  dustLimit,
  estimateVbytes,
  finalizeKeySpend,
  parseTransaction,
  taprootKeySpendSighash,
  txId,
  verifyFinalizedTaprootSignature,
} from "../core/bitcoin/index.ts";
import { sparkNetworkProto } from "../core/network.ts";
import { SparkError, SparkInputError, SparkRequestError } from "../errors/index.ts";
import { HashVariant, SigningJobSchema } from "../proto/gen/spark_pb.ts";
import type { SigningTarget } from "../signer/types.ts";
import type { SspClient } from "../ssp/index.ts";
import { cosignSingleJob } from "../tree/signing.ts";
import { depositAddressScript, depositScript, validateDepositAddress } from "./index.ts";
import type { DepositCoordinator } from "./index.ts";

// Static deposits: upstream spark-wallet.ts getStaticDepositAddress/
// getUtxosForDepositAddress/claimStaticDepositWithMaxFee/refundStaticDeposit and
// Breez services/deposit.rs. The claim seals the static-deposit secret key to
// the SSP inside the signer — the only flow where the key leaves key storage at
// all — so every check that can run before that happens runs first.

/** Upstream binds every static deposit address to static-deposit key index 0. */
export const STATIC_DEPOSIT_INDEX = 0;

/** Upstream's minimum spend-tx fee (spark-wallet.ts MIN_SPEND_TX_FEE_SATS). */
export const MIN_STATIC_REFUND_FEE_SATS = 194;

const UTXO_PAGE_SIZE = 100;

/**
 * Hard bound on coordinator-driven pagination, same as `query_nodes`/`query_unused_deposit_
 * addresses`: a hostile SO can keep returning full pages forever, so the walk must terminate.
 */
const MAX_PAGES = 1000;

export type StaticDepositUtxo = {
  /** Display-order hex txid. */
  readonly txid: string;
  readonly vout: number;
  /** Amount from the SO's `raw_tx`; absent when the SO does not return it. */
  readonly amountSats?: number;
  /** The deposit transaction when the SO returns it. */
  readonly rawTx?: Uint8Array;
};

export type StaticDepositClaim = {
  readonly creditAmountSats: number;
  /** `utxo amount − creditAmountSats`. */
  readonly feeSats: number;
  /** The SSP's inbound transfer id, when the claim response carries one. */
  readonly transferId?: string;
};

export type StaticDepositRefund = {
  /** The signed refund transaction (not broadcast — broadcasting is the caller's job). */
  readonly transaction: Uint8Array;
  /** Display-order txid of the signed transaction. */
  readonly txid: string;
};

/** The SO keeps one static address per signing key: regenerate = same address. */
async function staticDepositAddress(options: DepositCoordinator): Promise<{
  address: string;
  verifyingKey: Uint8Array;
  script: Uint8Array;
}> {
  const [signingPublicKey] = await options.signer.publicKeys([
    { type: "static-deposit", index: STATIC_DEPOSIT_INDEX },
  ]);
  if (signingPublicKey === undefined) {
    throw new SparkError("static deposit: signer returned no static-deposit key");
  }
  const identityPublicKey = await options.signer.identityPublicKey();
  const response = await options.spark.generate_static_deposit_address({
    signingPublicKey,
    identityPublicKey,
    network: sparkNetworkProto(options.network),
    hashVariant: HashVariant.V2,
  });
  const deposit = response.depositAddress;
  if (deposit === undefined) {
    throw new SparkError("static deposit: coordinator returned no address");
  }
  // Upstream verifies the coordinator's own address signature for static addresses
  // (validateDepositAddress's verifyCoordinatorProof); single-use ones skip it.
  validateDepositAddress(deposit, signingPublicKey, identityPublicKey, {
    ...options,
    verifyCoordinatorProof: true,
  });
  const script = depositScript(deposit.verifyingKey, options.network);
  if (!equalBytes(depositAddressScript(deposit.address, options.network), script)) {
    throw new SparkError("static deposit address does not pay to its verifying key");
  }
  return { address: deposit.address, verifyingKey: deposit.verifyingKey, script };
}

/** `generate_static_deposit_address` — the identity's reusable deposit address. */
export async function generateStaticDepositAddress(options: DepositCoordinator): Promise<string> {
  const deposit = await staticDepositAddress(options);
  return deposit.address;
}

/** One `get_utxos_for_address` page. */
async function utxoPage(
  options: DepositCoordinator & { readonly call?: CallOptions },
  address: string,
  offset: number,
) {
  return options.spark.get_utxos_for_address(
    {
      address,
      network: sparkNetworkProto(options.network),
      limit: BigInt(UTXO_PAGE_SIZE),
      offset: BigInt(offset),
      excludeClaimed: true,
    },
    options.call,
  );
}

/** Parses one returned UTXO, verifying any `raw_tx` against txid + static script. */
function mapUtxo(
  utxo: {
    txid: Uint8Array;
    vout: number;
    rawTx: Uint8Array;
  },
  staticScript: Uint8Array,
): StaticDepositUtxo {
  if (utxo.txid.length !== 32) {
    throw new SparkError("static deposit: SO returned a utxo whose txid is not 32 bytes");
  }
  const txid = bytesToHex(utxo.txid);
  const entry: { txid: string; vout: number; rawTx?: Uint8Array; amountSats?: number } = {
    txid,
    vout: utxo.vout,
  };
  if (utxo.rawTx.length > 0) {
    const tx = parseTransaction(utxo.rawTx);
    if (tx.id !== txid) {
      throw new SparkError(`static deposit: utxo raw tx is not ${txid}`);
    }
    if (!Number.isSafeInteger(utxo.vout) || utxo.vout >= tx.outputsLength) {
      throw new SparkError(`static deposit: utxo ${txid}:${utxo.vout} is out of range`);
    }
    const output = tx.getOutput(utxo.vout);
    if (output.script === undefined || output.amount === undefined) {
      throw new SparkError(`static deposit: utxo ${txid}:${utxo.vout} has no script or amount`);
    }
    if (!equalBytes(output.script, staticScript)) {
      throw new SparkError(
        `static deposit: utxo ${txid}:${utxo.vout} does not pay the static address`,
      );
    }
    entry.rawTx = utxo.rawTx;
    entry.amountSats = u64ToSats(output.amount, "static deposit utxo amount");
  }
  return entry;
}

/**
 * Confirmed, unclaimed UTXOs at the static deposit address (`get_utxos_for_address`,
 * `exclude_claimed`, pages of 100 until a short page). The SO does not return `raw_tx` today, so
 * `amountSats`/`rawTx` are usually absent; entries are still safe to pass to
 * `claimStatic`/`refundStatic` alongside a caller-supplied `rawTx`.
 */
export async function queryStaticDepositUtxos(
  options: DepositCoordinator & {
    readonly call?: CallOptions;
    /** Page bound override, for focused tests; walks default to {@link MAX_PAGES}. */
    readonly maxPages?: number;
  },
): Promise<StaticDepositUtxo[]> {
  const { address, script } = await staticDepositAddress(options);
  const utxos: StaticDepositUtxo[] = [];
  let offset = 0;
  for (let pageIndex = 0; pageIndex < (options.maxPages ?? MAX_PAGES); pageIndex++) {
    // oxlint-disable-next-line no-await-in-loop -- pages are sequential by definition
    const response = await utxoPage(options, address, offset);
    for (const utxo of response.utxos) {
      utxos.push(mapUtxo(utxo, script));
    }
    if (response.utxos.length < UTXO_PAGE_SIZE) {
      return utxos;
    }
    const nextOffset = Number(response.offset);
    if (!Number.isSafeInteger(nextOffset) || nextOffset <= offset) {
      throw new SparkError("static deposit: coordinator returned a non-advancing offset");
    }
    offset = nextOffset;
  }
  throw new SparkError("static deposit: coordinator did not stop returning full pages");
}

function checkUtxoRef(txid: string, vout: number): void {
  if (!/^[0-9a-fA-F]{64}$/.test(txid)) {
    throw new SparkInputError("static deposit: txid must be a 64-char hex string");
  }
  assertU32(vout, "vout");
}

/**
 * The deposit UTXO's raw transaction, script and amount. `rawTx` comes from the caller or the SO's
 * utxo listing; either way its txid must match and output `vout` must pay the static address
 * (P2TR(verifyingKey)).
 */
async function resolveStaticUtxo(
  options: DepositCoordinator & {
    readonly call?: CallOptions;
    readonly maxPages?: number;
  },
  request: { readonly txid: string; readonly vout: number; readonly rawTx?: Uint8Array },
  deposit: { readonly address: string; readonly script: Uint8Array },
): Promise<{ rawTx: Uint8Array; script: Uint8Array; amountSats: number }> {
  let { rawTx } = request;
  if (rawTx === undefined) {
    let offset = 0;
    let done = false;
    for (let pageIndex = 0; pageIndex < (options.maxPages ?? MAX_PAGES) && !done; pageIndex++) {
      // oxlint-disable-next-line no-await-in-loop -- pages are sequential by definition
      const response = await utxoPage(options, deposit.address, offset);
      const found = response.utxos.find(
        (utxo) => bytesToHex(utxo.txid) === request.txid && utxo.vout === request.vout,
      );
      if (found !== undefined && found.rawTx.length > 0) {
        ({ rawTx } = found);
      }
      done = found !== undefined || response.utxos.length < UTXO_PAGE_SIZE;
      if (!done) {
        const nextOffset = Number(response.offset);
        if (!Number.isSafeInteger(nextOffset) || nextOffset <= offset) {
          throw new SparkError("static deposit: coordinator returned a non-advancing offset");
        }
        offset = nextOffset;
      }
    }
    if (!done) {
      throw new SparkError("static deposit: coordinator did not stop returning full pages");
    }
  }
  if (rawTx === undefined) {
    throw new SparkInputError(
      "static deposit: pass rawTx — the SO does not return the deposit transaction",
    );
  }
  const tx = parseTransaction(rawTx);
  if (tx.id !== request.txid) {
    throw new SparkInputError(`static deposit: rawTx is not transaction ${request.txid}`);
  }
  if (request.vout >= tx.outputsLength) {
    throw new SparkInputError(
      `static deposit: vout ${request.vout} is out of range for the deposit transaction`,
    );
  }
  const output = tx.getOutput(request.vout);
  if (output.script === undefined || output.amount === undefined) {
    throw new SparkInputError("static deposit: deposit output is missing script or amount");
  }
  if (!equalBytes(output.script, deposit.script)) {
    throw new SparkInputError("static deposit: the output does not pay our static address");
  }
  return { rawTx, script: output.script, amountSats: u64ToSats(output.amount, "utxo amount") };
}

/**
 * Claims a confirmed static-deposit UTXO through the SSP: quotes the credit amount, rejects `credit
 * <= 0` and fees over `maxFeeSats` before touching the signer, then authorizes the swap with the
 * `static-deposit-claim` statement, and seals the static key to the SSP — the only protocol step
 * where the key leaves key storage at all.
 */
export async function claimStaticDeposit(
  options: DepositCoordinator & {
    readonly ssp: SspClient;
    readonly call?: CallOptions;
    /** Page bound override for the UTXO lookup, for focused tests. */
    readonly maxPages?: number;
  },
  request: {
    readonly txid: string;
    readonly vout: number;
    readonly maxFeeSats: number;
    readonly rawTx?: Uint8Array;
  },
): Promise<StaticDepositClaim> {
  const { network, signer } = options;
  checkUtxoRef(request.txid, request.vout);
  if (!Number.isSafeInteger(request.maxFeeSats) || request.maxFeeSats < 0) {
    throw new SparkInputError("claimStatic: maxFeeSats must be a non-negative integer");
  }

  const deposit = await staticDepositAddress(options);
  const utxo = await resolveStaticUtxo(options, request, deposit);

  const quote = await options.ssp.staticDepositQuote({
    transactionId: request.txid,
    outputIndex: request.vout,
    network,
  });
  const { creditAmountSats } = quote;
  if (creditAmountSats <= 0) {
    throw new SparkError(`claimStatic: SSP quote credits ${creditAmountSats} sats`);
  }
  const feeSats = utxo.amountSats - creditAmountSats;
  if (feeSats < 0) {
    throw new SparkError("claimStatic: SSP quote exceeds the deposit amount");
  }
  if (feeSats > request.maxFeeSats) {
    throw new SparkInputError(
      `claimStatic: quoted fee ${feeSats} exceeds maxFeeSats ${request.maxFeeSats}`,
    );
  }

  let quoteSignatureBytes: Uint8Array;
  try {
    quoteSignatureBytes = hexToBytes(quote.signature);
  } catch (error) {
    throw new SparkRequestError("ssp response: quote signature is not hex", {
      code: "unexpected_response",
      cause: error,
    });
  }
  if (quoteSignatureBytes.length === 0) {
    throw new SparkRequestError("ssp response: quote signature is empty", {
      code: "unexpected_response",
    });
  }

  const { encryptedSecretKey, signature } = await signer.claimStaticDeposit({
    index: STATIC_DEPOSIT_INDEX,
    statement: {
      kind: "static-deposit-claim",
      network,
      txid: hexToBytes(request.txid),
      vout: request.vout,
      creditAmountSats,
      sspSignature: quoteSignatureBytes,
    },
  });
  const claim = await options.ssp.claimStaticDeposit({
    transactionId: request.txid,
    outputIndex: request.vout,
    network,
    creditAmountSats,
    encryptedSecretKey: bytesToHex(encryptedSecretKey),
    signature: bytesToHex(signature),
    quoteSignature: quote.signature,
  });
  return {
    creditAmountSats,
    feeSats,
    ...(claim.transferId === undefined ? {} : { transferId: claim.transferId }),
  };
}

/**
 * Builds, user-authorizes and SO-signs a v3 refund spending `txid:vout` to `destinationAddress`
 * (fee = `feeRateSatPerVbyte × estimateVbytes(1,1)`, floored at upstream's 194 sats; the output
 * must clear dust). The SO picks the verifying key, so it is checked against the deposit output
 * before signing; the aggregated signature is verified before the transaction is returned. Not
 * broadcast.
 */
export async function refundStaticDeposit(
  options: DepositCoordinator & {
    readonly call?: CallOptions;
    /** Page bound override for the UTXO lookup, for focused tests. */
    readonly maxPages?: number;
  },
  request: {
    readonly txid: string;
    readonly vout: number;
    readonly destinationAddress: string;
    readonly feeRateSatPerVbyte: number;
    readonly rawTx?: Uint8Array;
  },
): Promise<StaticDepositRefund> {
  const { spark, signer, network } = options;
  checkUtxoRef(request.txid, request.vout);
  assertFeeRate(request.feeRateSatPerVbyte);
  let destinationScript: Uint8Array;
  try {
    destinationScript = OutScript.encode(
      BitcoinAddress(btcNetwork(network)).decode(request.destinationAddress),
    );
  } catch (error) {
    throw new SparkInputError(`refundStatic: invalid destination address for ${network}`, {
      cause: error,
    });
  }

  const deposit = await staticDepositAddress(options);
  const utxo = await resolveStaticUtxo(options, request, deposit);

  const feeSats = Math.ceil(request.feeRateSatPerVbyte * estimateVbytes(1, 1));
  if (feeSats < MIN_STATIC_REFUND_FEE_SATS) {
    throw new SparkInputError(
      `refundStatic: fee ${feeSats} sats is below the ${MIN_STATIC_REFUND_FEE_SATS} sat minimum`,
    );
  }
  const creditAmountSats = utxo.amountSats - feeSats;
  const dust = dustLimit(destinationScript);
  if (creditAmountSats < dust) {
    throw new SparkInputError(
      `refundStatic: output ${creditAmountSats} sats is below the ${dust} sat dust limit`,
    );
  }

  const refundTx = new Transaction({
    version: 3,
    lockTime: 0,
    allowUnknownInputs: true,
    allowUnknownOutputs: true,
  });
  refundTx.addInput({ txid: hexToBytes(request.txid), index: request.vout });
  refundTx.addOutput({ script: destinationScript, amount: BigInt(creditAmountSats) });
  const transaction = refundTx.toBytes(true);
  const target: SigningTarget = {
    transaction,
    inputIndex: 0,
    prevouts: [{ script: utxo.script, amount: utxo.amountSats }],
  };

  const [commitment] = await signer.newCommitments(1);
  if (commitment === undefined) {
    throw new SparkError("refundStatic: signer returned no signing commitment");
  }
  const [signingPublicKey] = await signer.publicKeys([
    { type: "static-deposit", index: STATIC_DEPOSIT_INDEX },
  ]);
  if (signingPublicKey === undefined) {
    throw new SparkError("refundStatic: signer returned no static-deposit key");
  }
  const userSignature = await signer.signIdentity({
    kind: "static-deposit-refund",
    network,
    txid: hexToBytes(request.txid),
    vout: request.vout,
    amount: creditAmountSats,
    target,
  });

  const response = await spark.initiate_static_deposit_utxo_refund(
    {
      onChainUtxo: {
        txid: hexToBytes(request.txid),
        vout: request.vout,
        network: sparkNetworkProto(network),
      },
      refundTxSigningJob: create(SigningJobSchema, {
        signingPublicKey,
        rawTx: transaction,
        signingNonceCommitment: commitment,
      }),
      userSignature,
      // The signed statement is the legacy concat digest — V2 is the hashstructure form.
      hashVariant: HashVariant.UNSPECIFIED,
    },
    options.call,
  );
  const result = response.refundTxSigningResult;
  const returnedAddress = response.depositAddress;
  if (result === undefined || returnedAddress === undefined) {
    throw new SparkError("refundStatic: coordinator returned an incomplete response");
  }
  const verifyingKey = returnedAddress.verifyingPublicKey;
  // The SO picks the key the refund signs under — tie it to the output being spent
  // (Breez validate_output_pays_to_verifying_key).
  if (!equalBytes(depositScript(verifyingKey, network), utxo.script)) {
    throw new SparkError("refundStatic: returned verifying key does not bind the deposit output");
  }

  const key = { type: "static-deposit", index: STATIC_DEPOSIT_INDEX } as const;
  const signature = await cosignSingleJob(signer, {
    key,
    target,
    verifyingKey,
    commitment,
    result,
    context: "refundStatic",
  });

  const signed = finalizeKeySpend(transaction, signature);
  if (!verifyFinalizedTaprootSignature(signed, taprootKeySpendSighash(target), verifyingKey, 0)) {
    throw new SparkError("refundStatic: the aggregated signature does not verify");
  }
  return { transaction: signed, txid: txId(signed) };
}
