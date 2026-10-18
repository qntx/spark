import { create, toBinary } from "@bufbuild/protobuf";
import { timestampDate } from "@bufbuild/protobuf/wkt";
import type { Timestamp } from "@bufbuild/protobuf/wkt";
import type { CallOptions, Client } from "@connectrpc/connect";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { equalBytes } from "@noble/curves/utils.js";

import { u64ToSats } from "../core/assert.ts";
import {
  createCurrentTimelockRefundTxs,
  createDecrementedTimelockRefundTxs,
  parseTransaction,
} from "../core/bitcoin/index.ts";
import type { RefundTxTrio } from "../core/bitcoin/index.ts";
import { sendLeafSigningDigest } from "../core/hashing/statements.ts";
import { sparkNetworkFromProto, sparkNetworkProto } from "../core/network.ts";
import type { SparkNetwork, SparkOperatorConfig } from "../core/network.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import { SignatureScheme } from "../proto/gen/common_pb.ts";
import type { Signature } from "../proto/gen/common_pb.ts";
import {
  ClaimPackageSchema,
  HashVariant,
  TransferPackageSchema,
  TransferReceiverStatus,
  TransferStatus,
  TransferType,
} from "../proto/gen/spark_pb.ts";
import type {
  RequestedSigningCommitments,
  SparkService,
  Transfer,
  TransferLeaf,
  UserSignedTxSigningJob,
} from "../proto/gen/spark_pb.ts";
import type { SparkSigner } from "../signer/types.ts";
import { mapTreeNode } from "../tree/index.ts";
import type { SparkLeaf } from "../tree/index.ts";
import { signUserJobs } from "../tree/signing.ts";
import type { UserSigningSpec } from "../tree/signing.ts";

export type SparkTransferLeaf = {
  readonly leaf: SparkLeaf;
  /** ECIES(receiver identity) ciphertext sealing the leaf key the sender generated. */
  readonly secretCipher: Uint8Array;
  /** Sender's per-leaf authorization: legacy bare signature or scheme-tagged `common.Signature`. */
  readonly sig:
    | { readonly case: "signature"; readonly value: Uint8Array }
    | { readonly case: "typedSignature"; readonly value: Signature }
    | undefined;
  /** Receiver-edge id that owns this leaf on multi-receiver transfers ("" when unset). */
  readonly transferReceiverId: string;
  /** Receiver-side refund txs captured at send time; they are the leaf's current refund state. */
  readonly intermediateRefundTx: Uint8Array;
  readonly intermediateDirectRefundTx: Uint8Array;
  readonly intermediateDirectFromCpfpRefundTx: Uint8Array;
};

export type SparkTransferReceiver = {
  readonly id: string;
  readonly identityPublicKey: Uint8Array;
  readonly status: string;
};

export type SparkTransfer = {
  readonly id: string;
  readonly senderIdentityPublicKey: Uint8Array;
  readonly receiverIdentityPublicKey: Uint8Array;
  readonly receivers: ReadonlyArray<SparkTransferReceiver>;
  readonly status: string;
  readonly type: string;
  readonly network: SparkNetwork;
  readonly totalValueSats: number;
  readonly expiryTimeMs?: number;
  readonly createdTimeMs?: number;
  readonly updatedTimeMs?: number;
  readonly sparkInvoice?: string;
  readonly leaves: ReadonlyArray<SparkTransferLeaf>;
};

/**
 * Whole-transfer statuses a receiver can claim on (mirrors upstream
 * `partitionClaimablePendingTransfers`).
 */
export const CLAIMABLE_TRANSFER_STATUSES: ReadonlyArray<string> = [
  "SENDER_KEY_TWEAKED",
  "RECEIVER_KEY_TWEAK_LOCKED",
  "RECEIVER_KEY_TWEAK_APPLIED",
  "RECEIVER_KEY_TWEAKED",
  "RECEIVER_REFUND_SIGNED",
];

function enumName(table: Record<string, number>, value: number): string {
  for (const [name, v] of Object.entries(table)) {
    if (v === value) {
      return name;
    }
  }
  return String(value);
}

function millis(timestamp: Timestamp | undefined): number | undefined {
  if (timestamp === undefined) {
    return undefined;
  }
  return timestampDate(timestamp).getTime();
}

function mapTransferLeaf(leaf: TransferLeaf): SparkTransferLeaf | undefined {
  if (leaf.leaf === undefined) {
    return undefined;
  }
  return {
    leaf: mapTreeNode(leaf.leaf),
    secretCipher: leaf.secretCipher,
    sig:
      leaf.sig.case === "signature"
        ? { case: "signature", value: leaf.sig.value }
        : leaf.sig.case === "typedSignature"
          ? { case: "typedSignature", value: leaf.sig.value }
          : undefined,
    transferReceiverId: leaf.transferReceiverId,
    intermediateRefundTx: leaf.intermediateRefundTx,
    intermediateDirectRefundTx: leaf.intermediateDirectRefundTx,
    intermediateDirectFromCpfpRefundTx: leaf.intermediateDirectFromCpfpRefundTx,
  };
}

export function mapTransfer(transfer: Transfer): SparkTransfer {
  const leaves: SparkTransferLeaf[] = [];
  for (const leaf of transfer.leaves) {
    const mapped = mapTransferLeaf(leaf);
    if (mapped !== undefined) {
      leaves.push(mapped);
    }
  }
  const out: SparkTransfer = {
    id: transfer.id,
    senderIdentityPublicKey: transfer.senderIdentityPublicKey,
    receiverIdentityPublicKey: transfer.receiverIdentityPublicKey,
    receivers: transfer.receivers.map((receiver) => ({
      id: receiver.id,
      identityPublicKey: receiver.identityPublicKey,
      status: enumName(TransferReceiverStatus, receiver.status),
    })),
    status: enumName(TransferStatus, transfer.status),
    type: enumName(TransferType, transfer.type),
    network: sparkNetworkFromProto(transfer.network),
    totalValueSats: u64ToSats(transfer.totalValue, "transfer total value"),
    leaves,
  };
  const expiry = millis(transfer.expiryTime);
  const created = millis(transfer.createdTime);
  const updated = millis(transfer.updatedTime);
  return {
    ...out,
    ...(expiry === undefined ? {} : { expiryTimeMs: expiry }),
    ...(created === undefined ? {} : { createdTimeMs: created }),
    ...(updated === undefined ? {} : { updatedTimeMs: updated }),
    ...(transfer.sparkInvoice === "" ? {} : { sparkInvoice: transfer.sparkInvoice }),
  };
}

/** `query_pending_transfers` — transfers awaiting this identity as receiver. */
export async function queryPendingTransfers(options: {
  readonly spark: Client<typeof SparkService>;
  readonly identityPublicKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly call?: CallOptions;
}): Promise<SparkTransfer[]> {
  const response = await options.spark.query_pending_transfers(
    {
      participant: {
        case: "receiverIdentityPublicKey",
        value: options.identityPublicKey,
      },
      network: sparkNetworkProto(options.network),
    },
    options.call,
  );
  return response.transfers.map(mapTransfer);
}

/** `query_all_transfers` — transfers where the identity is sender or receiver. */
export async function queryAllTransfers(options: {
  readonly spark: Client<typeof SparkService>;
  readonly identityPublicKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly limit?: number;
  readonly offset?: number;
  readonly call?: CallOptions;
}): Promise<SparkTransfer[]> {
  const response = await options.spark.query_all_transfers(
    {
      participant: {
        case: "senderOrReceiverIdentityPublicKey",
        value: options.identityPublicKey,
      },
      network: sparkNetworkProto(options.network),
      limit: BigInt(options.limit ?? 100),
      offset: BigInt(options.offset ?? 0),
    },
    options.call,
  );
  return response.transfers.map(mapTransfer);
}

/** Coordinator context shared by the transfer RPCs (the coordinator fans out to the other SOs). */
export type TransferCoordinator = {
  readonly spark: Client<typeof SparkService>;
  readonly signer: SparkSigner;
  readonly network: SparkNetwork;
  /** Every signing operator, coordinator included. */
  readonly operators: ReadonlyArray<SparkOperatorConfig>;
  readonly threshold: number;
};

/** One refund signing spec: the leaf it covers, its SO commitments and the signing target. */
type RefundJobSpec = UserSigningSpec & { readonly leafId: string };

function prevout(
  txBytes: Uint8Array,
  vout: number,
  context: string,
): { readonly script: Uint8Array; readonly amount: number } {
  const output = parseTransaction(txBytes).getOutput(vout);
  if (output.script === undefined || output.amount === undefined) {
    throw new SparkError(`${context}: transaction has no output ${vout}`);
  }
  return { script: output.script, amount: u64ToSats(output.amount, `${context} output`) };
}

function refundTxSequence(refundTxBytes: Uint8Array, context: string): number {
  const { sequence } = parseTransaction(refundTxBytes).getInput(0);
  if (sequence === undefined) {
    throw new SparkError(`${context}: refund tx input has no sequence`);
  }
  return sequence;
}

/**
 * Builds the three refund signing-job groups (CPFP, direct, direct-from-CPFP) for `leaves`,
 * mirroring upstream `signRefundsCore`: the CPFP and direct-from-CPFP refunds spend the node tx
 * output 0, the direct refund spends the direct node tx output 0 and exists only when the leaf
 * carries a direct tx. `signingCommitments` must hold exactly `3 * leaves.length` entries, sliced
 * per group (CPFP first, then direct, then direct-from-CPFP).
 */
function refundJobGroups(
  leaves: ReadonlyArray<{
    leaf: SparkLeaf;
    refundTx: Uint8Array;
    signingPublicKey: Uint8Array;
    receivingPublicKey: Uint8Array;
  }>,
  createRefundTxs: typeof createDecrementedTimelockRefundTxs,
  signingCommitments: ReadonlyArray<RequestedSigningCommitments>,
  network: SparkNetwork,
  context: string,
): {
  cpfp: RefundJobSpec[];
  direct: RefundJobSpec[];
  directFromCpfp: RefundJobSpec[];
} {
  const count = leaves.length;
  if (signingCommitments.length !== 3 * count) {
    throw new SparkError(
      `${context}: expected ${3 * count} signing commitments, got ${signingCommitments.length}`,
    );
  }
  const cpfp: RefundJobSpec[] = [];
  const direct: RefundJobSpec[] = [];
  const directFromCpfp: RefundJobSpec[] = [];
  for (const [i, entry] of leaves.entries()) {
    const nodeOutput = prevout(entry.leaf.nodeTx, 0, `${context} leaf ${entry.leaf.id} node tx`);
    const refunds: RefundTxTrio = createRefundTxs({
      nodeTx: entry.leaf.nodeTx,
      directNodeTx: entry.leaf.directTx,
      sequence: refundTxSequence(entry.refundTx, context),
      receivingPublicKey: entry.receivingPublicKey,
      network,
    });
    const commitments = signingCommitments[i];
    const directCommitment = signingCommitments[count + i];
    const directFromCpfpCommitment = signingCommitments[2 * count + i];
    if (
      commitments === undefined ||
      directCommitment === undefined ||
      directFromCpfpCommitment === undefined
    ) {
      throw new SparkError(`${context}: signing commitment bookkeeping failure`);
    }
    cpfp.push({
      leafId: entry.leaf.id,
      key: { type: "leaf", leafId: entry.leaf.id },
      signingPublicKey: entry.signingPublicKey,
      verifyingKey: entry.leaf.verifyingPublicKey,
      target: {
        transaction: refunds.cpfpRefund.txBytes,
        inputIndex: 0,
        prevouts: [nodeOutput],
      },
      commitments,
    });
    if (refunds.directRefund !== undefined) {
      const directOutput = prevout(
        entry.leaf.directTx ?? new Uint8Array(),
        0,
        `${context} leaf ${entry.leaf.id} direct node tx`,
      );
      direct.push({
        leafId: entry.leaf.id,
        key: { type: "leaf", leafId: entry.leaf.id },
        signingPublicKey: entry.signingPublicKey,
        verifyingKey: entry.leaf.verifyingPublicKey,
        target: {
          transaction: refunds.directRefund.txBytes,
          inputIndex: 0,
          prevouts: [directOutput],
        },
        commitments: directCommitment,
      });
    }
    directFromCpfp.push({
      leafId: entry.leaf.id,
      key: { type: "leaf", leafId: entry.leaf.id },
      signingPublicKey: entry.signingPublicKey,
      verifyingKey: entry.leaf.verifyingPublicKey,
      target: {
        transaction: refunds.directFromCpfpRefund.txBytes,
        inputIndex: 0,
        prevouts: [nodeOutput],
      },
      commitments: directFromCpfpCommitment,
    });
  }
  return { cpfp, direct, directFromCpfp };
}

/** One batched `signFrost` over all specs; returns the wire `UserSignedTxSigningJob`s per group. */
async function signRefundJobs(
  signer: SparkSigner,
  groups: { cpfp: RefundJobSpec[]; direct: RefundJobSpec[]; directFromCpfp: RefundJobSpec[] },
): Promise<{
  cpfp: UserSignedTxSigningJob[];
  direct: UserSignedTxSigningJob[];
  directFromCpfp: UserSignedTxSigningJob[];
}> {
  const jobs = await signUserJobs(signer, [
    ...groups.cpfp,
    ...groups.direct,
    ...groups.directFromCpfp,
  ]);
  return {
    cpfp: jobs.slice(0, groups.cpfp.length),
    direct: jobs.slice(groups.cpfp.length, groups.cpfp.length + groups.direct.length),
    directFromCpfp: jobs.slice(groups.cpfp.length + groups.direct.length),
  };
}

/**
 * `start_transfer_v2` — single-receiver send. Every leaf gets a fresh recipient key inside the
 * signer (`prepareTransfer`), the three refund transactions per leaf are rebuilt one timelock
 * interval below the leaf's current refund sequence and signed in one `signFrost` batch, and the
 * `TransferPackage` carries the identity-key signature over the V2 signing payload.
 */
export async function sendTransfer(
  options: TransferCoordinator & {
    readonly transferId: string;
    readonly leaves: ReadonlyArray<SparkLeaf>;
    readonly receiverIdentityPublicKey: Uint8Array;
    readonly call?: CallOptions;
  },
): Promise<SparkTransfer> {
  const { spark, signer, network, operators, threshold } = options;
  if (options.leaves.length === 0) {
    throw new SparkInputError("sendTransfer: leaves must not be empty");
  }

  const prepared = await signer.prepareTransfer({
    transferId: options.transferId,
    receiverIdentityPublicKey: options.receiverIdentityPublicKey,
    leaves: options.leaves.map((leaf) => ({
      leafId: leaf.id,
      key: { type: "leaf", leafId: leaf.id },
    })),
    operators,
    threshold,
  });

  const signingCommitments = await spark.get_signing_commitments(
    {
      nodeIds: options.leaves.map((leaf) => leaf.id),
      count: 3,
    },
    options.call,
  );

  const signingPublicKeys = await signer.publicKeys(
    options.leaves.map((leaf) => ({ type: "leaf", leafId: leaf.id })),
  );

  const groups = refundJobGroups(
    options.leaves.map((leaf, i) => {
      const signingPublicKey = signingPublicKeys[i];
      if (signingPublicKey === undefined) {
        throw new SparkError("sendTransfer: signer returned fewer public keys than requested");
      }
      return {
        leaf,
        refundTx: leaf.refundTx,
        signingPublicKey,
        receivingPublicKey: options.receiverIdentityPublicKey,
      };
    }),
    createDecrementedTimelockRefundTxs,
    signingCommitments.signingCommitments,
    network,
    "sendTransfer",
  );

  const jobs = await signRefundJobs(signer, groups);

  const transferPackage = create(TransferPackageSchema, {
    leavesToSend: jobs.cpfp,
    keyTweakPackage: prepared.operatorPackages,
    userSignature: new Uint8Array(),
    directLeavesToSend: jobs.direct,
    directFromCpfpLeavesToSend: jobs.directFromCpfp,
    hashVariant: HashVariant.V2,
  });
  transferPackage.userSignature = await signer.signIdentity({
    kind: "transfer-package",
    transferId: options.transferId,
    package: toBinary(TransferPackageSchema, transferPackage),
  });

  const response = await spark.start_transfer_v2(
    {
      transferId: options.transferId,
      ownerIdentityPublicKey: await signer.identityPublicKey(),
      receiverIdentityPublicKey: options.receiverIdentityPublicKey,
      transferPackage,
    },
    options.call,
  );
  if (response.transfer === undefined) {
    throw new SparkError("sendTransfer: coordinator returned no transfer");
  }
  return mapTransfer(response.transfer);
}

/**
 * Verifies one pending leaf's sender signature: a legacy bare ECDSA signature (compact or DER) or a
 * scheme-tagged `common.Signature` (DER ECDSA or BIP-340 over the x-only sender key). Ported from
 * upstream `verifyTypedSignature`; anything unrecognized fails closed.
 */
function verifyLeafSignature(
  digest: Uint8Array,
  senderPublicKey: Uint8Array,
  sig: SparkTransferLeaf["sig"],
): boolean {
  if (digest.length !== 32 || senderPublicKey.length !== 33) {
    return false;
  }
  try {
    if (sig?.case === "typedSignature") {
      if (sig.value.signature.length === 0) {
        return false;
      }
      if (sig.value.scheme === SignatureScheme.ECDSA) {
        return secp256k1.verify(sig.value.signature, digest, senderPublicKey, {
          format: "der",
          prehash: false,
        });
      }
      if (sig.value.scheme === SignatureScheme.SCHNORR) {
        const [prefix] = senderPublicKey;
        if (prefix !== 0x02 && prefix !== 0x03) {
          return false;
        }
        return schnorr.verify(sig.value.signature, digest, senderPublicKey.subarray(1));
      }
      return false;
    }
    if (sig?.case === "signature") {
      return secp256k1.verify(sig.value, digest, senderPublicKey, { prehash: false });
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * `claim_transfer` — receiver claim. Verifies the sender's per-leaf signature over
 * `sendLeafSigningDigest` and that each `secret_cipher` decrypts (inside the signer) to the key
 * whose public key the leaf was tweaked to, re-signs the refund transactions at their current
 * timelock with the derived `LEAF{leafId}` keys, then submits the `ClaimPackage`.
 */
export async function claimTransfer(
  options: TransferCoordinator & {
    readonly transfer: SparkTransfer;
    readonly call?: CallOptions;
  },
): Promise<SparkLeaf[]> {
  const { spark, signer, network, operators, threshold } = options;
  const { transfer } = options;
  if (!CLAIMABLE_TRANSFER_STATUSES.includes(transfer.status)) {
    throw new SparkInputError(`claimTransfer: transfer status ${transfer.status} is not claimable`);
  }
  if (transfer.leaves.length === 0) {
    throw new SparkInputError("claimTransfer: transfer has no leaves");
  }

  // Multi-receiver transfers carry every receiver's leaves; claim only our receiver edge
  // (upstream `scopeTransferLeavesToReceiver`). Single-receiver and legacy transfers must
  // name this identity — fail closed.
  const self = await signer.identityPublicKey();
  let claimLeaves = transfer.leaves;
  let receiverId: string | undefined;
  if (transfer.receivers.length > 1) {
    const own = transfer.receivers.find((receiver) => equalBytes(receiver.identityPublicKey, self));
    if (own === undefined || own.id === "") {
      throw new SparkInputError("claimTransfer: not a receiver of this multi-receiver transfer");
    }
    claimLeaves = transfer.leaves.filter((leaf) => leaf.transferReceiverId === own.id);
    if (claimLeaves.length === 0) {
      throw new SparkInputError("claimTransfer: no leaves assigned to this receiver edge");
    }
    receiverId = own.id;
  } else {
    const receiverKey =
      transfer.receivers[0]?.identityPublicKey ?? transfer.receiverIdentityPublicKey;
    if (!equalBytes(receiverKey, self)) {
      throw new SparkInputError("claimTransfer: transfer is not addressed to this identity");
    }
  }

  for (const leaf of claimLeaves) {
    const digest = sendLeafSigningDigest(leaf.leaf.id, transfer.id, leaf.secretCipher);
    if (!verifyLeafSignature(digest, transfer.senderIdentityPublicKey, leaf.sig)) {
      throw new SparkInputError(
        `claimTransfer: sender signature verification failed for leaf ${leaf.leaf.id}`,
      );
    }
  }

  const receivedKeys = await signer.receivedPublicKeys(
    claimLeaves.map((leaf) => leaf.secretCipher),
  );
  for (const [i, leaf] of claimLeaves.entries()) {
    const received = receivedKeys[i];
    if (received === undefined) {
      throw new SparkError("claimTransfer: signer returned fewer public keys than requested");
    }
    if (!equalBytes(received, leaf.leaf.ownerSigningPublicKey)) {
      throw new SparkInputError(
        `claimTransfer: secret_cipher does not decrypt to the signing key of leaf ${leaf.leaf.id}`,
      );
    }
  }

  const prepared = await signer.prepareClaim({
    transferId: transfer.id,
    leaves: claimLeaves.map((leaf) => ({
      leafId: leaf.leaf.id,
      secretCipher: leaf.secretCipher,
    })),
    operators,
    threshold,
  });

  const signingCommitments = await spark.get_signing_commitments(
    {
      nodeIdCount: claimLeaves.length,
      count: 3,
    },
    options.call,
  );

  const newLeafKeys = await signer.publicKeys(
    claimLeaves.map((leaf) => ({ type: "leaf", leafId: leaf.leaf.id })),
  );

  const groups = refundJobGroups(
    claimLeaves.map((leaf, i) => {
      const signingPublicKey = newLeafKeys[i];
      if (signingPublicKey === undefined) {
        throw new SparkError("claimTransfer: signer returned fewer public keys than requested");
      }
      return {
        leaf: {
          ...leaf.leaf,
          refundTx: leaf.intermediateRefundTx,
          directRefundTx: leaf.intermediateDirectRefundTx,
          directFromCpfpRefundTx: leaf.intermediateDirectFromCpfpRefundTx,
        },
        refundTx: leaf.intermediateRefundTx,
        signingPublicKey,
        receivingPublicKey: signingPublicKey,
      };
    }),
    createCurrentTimelockRefundTxs,
    signingCommitments.signingCommitments,
    network,
    "claimTransfer",
  );

  const jobs = await signRefundJobs(signer, groups);

  const claimPackage = create(ClaimPackageSchema, {
    leavesToClaim: jobs.cpfp,
    keyTweakPackage: prepared.operatorPackages,
    userSignature: new Uint8Array(),
    directLeavesToClaim: jobs.direct,
    directFromCpfpLeavesToClaim: jobs.directFromCpfp,
    hashVariant: HashVariant.V2,
  });
  claimPackage.userSignature = await signer.signIdentity({
    kind: "claim-package",
    transferId: transfer.id,
    package: toBinary(ClaimPackageSchema, claimPackage),
  });

  const response = await spark.claim_transfer(
    {
      transferId: transfer.id,
      ownerIdentityPublicKey: self,
      claimPackage,
    },
    options.call,
  );
  if (response.transfer === undefined) {
    throw new SparkError("claimTransfer: coordinator returned no transfer");
  }
  // Scope the response to our receiver edge: claim responses may carry every receiver's
  // leaves, and only ours become our leaves.
  const claimed: SparkLeaf[] = [];
  for (const leaf of response.transfer.leaves) {
    if (
      leaf.leaf !== undefined &&
      (receiverId === undefined || leaf.transferReceiverId === receiverId)
    ) {
      claimed.push(mapTreeNode(leaf.leaf));
    }
  }
  return claimed;
}

/**
 * Picks AVAILABLE leaves whose values sum exactly to `amountSats` (depth-first over leaves sorted
 * descending, memoizing dead ends). No exact subset → `SparkInputError`; leaf swaps arrive with
 * S8.
 */
export function selectLeavesExact(
  leaves: ReadonlyArray<SparkLeaf>,
  amountSats: number,
): SparkLeaf[] {
  if (!Number.isSafeInteger(amountSats) || amountSats <= 0) {
    throw new SparkInputError("send: amountSats must be a positive safe integer");
  }
  // `filter` returns a fresh array, so sorting it in place is safe (Hermes has no toSorted).
  const sorted = leaves
    .filter((leaf) => leaf.status === "AVAILABLE")
    .sort((a, b) => b.valueSats - a.valueSats);
  const chosen: SparkLeaf[] = [];
  const dead = new Set<string>();
  const search = (index: number, remaining: number): boolean => {
    if (remaining === 0) {
      return true;
    }
    if (remaining < 0 || index === sorted.length) {
      return false;
    }
    const key = `${index}:${remaining}`;
    if (dead.has(key)) {
      return false;
    }
    const leaf = sorted[index];
    if (leaf === undefined) {
      return false;
    }
    chosen.push(leaf);
    if (search(index + 1, remaining - leaf.valueSats)) {
      return true;
    }
    chosen.pop();
    if (search(index + 1, remaining)) {
      return true;
    }
    dead.add(key);
    return false;
  };
  if (!search(0, amountSats)) {
    throw new SparkInputError(
      `send: no leaf combination sums exactly to ${amountSats} sats — leaf swaps land with S8`,
    );
  }
  return chosen;
}
