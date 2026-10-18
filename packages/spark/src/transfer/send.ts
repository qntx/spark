import { create, toBinary } from "@bufbuild/protobuf";
import type { CallOptions } from "@connectrpc/connect";

import { createDecrementedTimelockRefundTxs } from "../core/bitcoin/index.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import { HashVariant, TransferPackageSchema } from "../proto/gen/spark_pb.ts";
import type { SparkLeaf } from "../tree/index.ts";
import { mapTransfer } from "./model.ts";
import type { SparkTransfer, TransferCoordinator } from "./model.ts";
import { refundJobGroups, signRefundJobs } from "./refunds.ts";

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
    /** The invoice address string this transfer pays, forwarded to `start_transfer_v2`. */
    readonly sparkInvoice?: string;
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
      sparkInvoice: options.sparkInvoice ?? "",
    },
    options.call,
  );
  if (response.transfer === undefined) {
    throw new SparkError("sendTransfer: coordinator returned no transfer");
  }
  return mapTransfer(response.transfer);
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
