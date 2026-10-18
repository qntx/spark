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
  TransferStatus,
  TransferType,
  UserSignedTxSigningJobSchema,
} from "../proto/gen/spark_pb.ts";
import type {
  RequestedSigningCommitments,
  SparkService,
  Transfer,
  TransferLeaf,
  UserSignedTxSigningJob,
} from "../proto/gen/spark_pb.ts";
import type { FrostSignJob, SigningTarget, SparkSigner } from "../signer/types.ts";
import { mapTreeNode } from "../tree/index.ts";
import type { SparkLeaf } from "../tree/index.ts";

export type SparkTransferLeaf = {
  readonly leaf: SparkLeaf;
  /** ECIES(receiver identity) ciphertext sealing the leaf key the sender generated. */
  readonly secretCipher: Uint8Array;
  /** Sender's per-leaf authorization: legacy bare signature or scheme-tagged `common.Signature`. */
  readonly sig:
    | { readonly case: "signature"; readonly value: Uint8Array }
    | { readonly case: "typedSignature"; readonly value: Signature }
    | undefined;
  /** Receiver-side refund txs captured at send time; they are the leaf's current refund state. */
  readonly intermediateRefundTx: Uint8Array;
  readonly intermediateDirectRefundTx: Uint8Array;
  readonly intermediateDirectFromCpfpRefundTx: Uint8Array;
};

export type SparkTransfer = {
  readonly id: string;
  readonly senderIdentityPublicKey: Uint8Array;
  readonly receiverIdentityPublicKey: Uint8Array;
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

/** One refund signing job: the leaf it covers, its SO commitments and the signing target. */
type RefundJobSpec = {
  readonly leafId: string;
  readonly signingPublicKey: Uint8Array;
  readonly verifyingKey: Uint8Array;
  readonly rawTx: Uint8Array;
  readonly target: SigningTarget;
  readonly commitments: RequestedSigningCommitments;
};

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

function operatorCommitments(
  commitments: RequestedSigningCommitments,
): FrostSignJob["operatorCommitments"] {
  return Object.entries(commitments.signingNonceCommitments).map(([identifier, commitment]) => ({
    identifier,
    commitment,
  }));
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
      signingPublicKey: entry.signingPublicKey,
      verifyingKey: entry.leaf.verifyingPublicKey,
      rawTx: refunds.cpfpRefund.txBytes,
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
        signingPublicKey: entry.signingPublicKey,
        verifyingKey: entry.leaf.verifyingPublicKey,
        rawTx: refunds.directRefund.txBytes,
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
      signingPublicKey: entry.signingPublicKey,
      verifyingKey: entry.leaf.verifyingPublicKey,
      rawTx: refunds.directFromCpfpRefund.txBytes,
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

/** One batched `signFrost` over all specs; returns the wire `UserSignedTxSigningJob`s. */
async function signRefundJobs(
  signer: SparkSigner,
  keyFor: (leafId: string) => { readonly type: "leaf"; readonly leafId: string },
  groups: { cpfp: RefundJobSpec[]; direct: RefundJobSpec[]; directFromCpfp: RefundJobSpec[] },
): Promise<{
  cpfp: UserSignedTxSigningJob[];
  direct: UserSignedTxSigningJob[];
  directFromCpfp: UserSignedTxSigningJob[];
}> {
  const specs = [...groups.cpfp, ...groups.direct, ...groups.directFromCpfp];
  const commitments = await signer.newCommitments(specs.length);
  if (commitments.length !== specs.length) {
    throw new SparkError("signRefunds: signer returned fewer commitments than requested");
  }
  const shares = await signer.signFrost(
    specs.map((spec, i) => {
      const commitment = commitments[i];
      if (commitment === undefined) {
        throw new SparkError("signRefunds: commitment bookkeeping failure");
      }
      return {
        key: keyFor(spec.leafId),
        target: spec.target,
        verifyingKey: spec.verifyingKey,
        commitment,
        operatorCommitments: operatorCommitments(spec.commitments),
      };
    }),
  );
  if (shares.length !== specs.length) {
    throw new SparkError("signRefunds: signer returned fewer shares than requested");
  }
  const jobs = specs.map((spec, i) => {
    const commitment = commitments[i];
    const share = shares[i];
    if (commitment === undefined || share === undefined) {
      throw new SparkError("signRefunds: signing job bookkeeping failure");
    }
    return create(UserSignedTxSigningJobSchema, {
      leafId: spec.leafId,
      signingPublicKey: spec.signingPublicKey,
      rawTx: spec.rawTx,
      signingNonceCommitment: commitment,
      userSignature: share,
      signingCommitments: { signingCommitments: spec.commitments.signingNonceCommitments },
    });
  });
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

  const jobs = await signRefundJobs(signer, (leafId) => ({ type: "leaf", leafId }), groups);

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
  if (transfer.leaves.length === 0) {
    throw new SparkInputError("claimTransfer: transfer has no leaves");
  }
  if (transfer.receiverIdentityPublicKey.length > 0) {
    const self = await signer.identityPublicKey();
    if (!equalBytes(self, transfer.receiverIdentityPublicKey)) {
      throw new SparkInputError("claimTransfer: transfer is not addressed to this identity");
    }
  }

  for (const leaf of transfer.leaves) {
    const digest = sendLeafSigningDigest(leaf.leaf.id, transfer.id, leaf.secretCipher);
    if (!verifyLeafSignature(digest, transfer.senderIdentityPublicKey, leaf.sig)) {
      throw new SparkInputError(
        `claimTransfer: sender signature verification failed for leaf ${leaf.leaf.id}`,
      );
    }
  }

  const receivedKeys = await signer.receivedPublicKeys(
    transfer.leaves.map((leaf) => leaf.secretCipher),
  );
  for (const [i, leaf] of transfer.leaves.entries()) {
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
    leaves: transfer.leaves.map((leaf) => ({
      leafId: leaf.leaf.id,
      secretCipher: leaf.secretCipher,
    })),
    operators,
    threshold,
  });

  const signingCommitments = await spark.get_signing_commitments(
    {
      nodeIdCount: transfer.leaves.length,
      count: 3,
    },
    options.call,
  );

  const newLeafKeys = await signer.publicKeys(
    transfer.leaves.map((leaf) => ({ type: "leaf", leafId: leaf.leaf.id })),
  );

  const groups = refundJobGroups(
    transfer.leaves.map((leaf, i) => {
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

  const jobs = await signRefundJobs(signer, (leafId) => ({ type: "leaf", leafId }), groups);

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
      ownerIdentityPublicKey: await signer.identityPublicKey(),
      claimPackage,
    },
    options.call,
  );
  if (response.transfer === undefined) {
    throw new SparkError("claimTransfer: coordinator returned no transfer");
  }
  const claimed: SparkLeaf[] = [];
  for (const leaf of response.transfer.leaves) {
    if (leaf.leaf !== undefined) {
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
