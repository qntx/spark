/**
 * Signer-side outflow derivation: the signer independently computes what an authorized signature
 * sends out, without trusting the caller. Authorization happens at two points, each backed by what
 * the SO enforces:
 *
 * - `signFrost` per-job whitelist: a multi-input target whose inputs spend a foreign prevout script
 *   is a connector (cooperative-exit) candidate — its outputs are not checked (they pay the SSP),
 *   the job must carry the SSP's `{connectorTx, exitTx}` pair, the pair's txid must match the
 *   foreign input, connectorTx input 0 must spend exitTx, and every exit job in the batch must
 *   carry the same pair. Otherwise every output must be whitelisted: an ephemeral anchor, the spent
 *   prevout's own script (intra-tree node transactions), a P2TR to the signer's own identity, a
 *   P2TR to a pending prepared transfer's recorded receiver for that leaf, or — for
 *   `leaf`/`static-deposit` keys only — a P2TR to the job's own signing key. A single-input target
 *   outside the whitelist is a lightning (HTLC) candidate; a multi-input same-script target outside
 *   it fails. Exit and lightning candidates are authorized BEFORE any share is produced — the same
 *   signed package can be paired with any shares the signer ever issued, so HTLC/connector shares
 *   must never be issuable unchecked; a batch mixing the two kinds, or carrying more than one HTLC
 *   script or connector txid, is rejected outright.
 * - `signIdentity({kind:"transfer-package"})`: the package's `key_tweak_package` must be byte-equal
 *   to this session's recorded `prepareTransfer`, every leaf needs a recorded refund signature
 *   (amount = per-pubkey max prevout), and the receivers decide `transfer`/`swap` — or no further
 *   authorization when a `signFrost` service authorization already covered the leaves (all
 *   receivers the bound SSP).
 *
 * Non-package outflows (onchain spends with `inputSats` for fee derivation, token transactions) are
 * decoded from the transaction being signed. `authorize` runs before every outflow signature; a
 * throw aborts it without consuming commitments.
 *
 * Upstream reference: sdks/js/packages/spark-sdk signer.ts / services/transfer.ts and
 * so/handler/transfer_package_validation.go — buildonspark/spark@0b3a32a.
 */
import { fromBinary } from "@bufbuild/protobuf";
import { bytesToNumberBE } from "@noble/curves/utils.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import type { Transaction } from "@scure/btc-signer";

import { lightningHtlcOutputScript } from "../core/bitcoin/htlc.ts";
import { EPHEMERAL_ANCHOR_SCRIPT, p2trScriptFromPublicKey } from "../core/bitcoin/script.ts";
import { parseTransaction } from "../core/bitcoin/sighash.ts";
import type { SigningTarget } from "../core/bitcoin/sighash.ts";
import { txIdInputBytes } from "../core/bitcoin/transactions.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SparkInputError } from "../errors/index.ts";
import { TransferPackageSchema } from "../proto/gen/spark_pb.ts";
import { PartialTokenTransactionSchema } from "../proto/gen/spark_token_pb.ts";
import type { PartialTokenTransaction } from "../proto/gen/spark_token_pb.ts";
import type { SparkKey, SparkLeafKey } from "./types.ts";

/** What an authorized signature sends out, derived inside the signer (never caller-supplied). */
export type SparkOutflow =
  | {
      readonly kind: "transfer";
      readonly transferId: string;
      readonly totalSats: number;
      readonly receivers: ReadonlyArray<{
        readonly identityPublicKey: Uint8Array;
        readonly amountSats: number;
      }>;
    }
  | {
      readonly kind: "lightning";
      readonly htlcOutputScript: Uint8Array;
      readonly totalSats: number;
      readonly leaves: ReadonlyArray<{
        readonly publicKey: Uint8Array;
        readonly amountSats: number;
      }>;
    }
  | {
      readonly kind: "exit";
      readonly connectorTxid: Uint8Array;
      readonly totalSats: number;
      readonly leaves: ReadonlyArray<{
        readonly publicKey: Uint8Array;
        readonly amountSats: number;
      }>;
      /** Every output of the SSP-provided coop-exit payout transaction. */
      readonly exitOutputs: ReadonlyArray<{
        readonly script: Uint8Array;
        readonly amountSats: number;
      }>;
    }
  | { readonly kind: "swap"; readonly transferId: string; readonly totalSats: number }
  | {
      readonly kind: "onchain";
      readonly source:
        | "static-deposit-refund"
        | "watchtower-recovery"
        | "htlc-timeout"
        | "key-spend";
      readonly totalSats: number;
      readonly inputSats: number;
      readonly outputs: ReadonlyArray<{
        readonly script: Uint8Array;
        readonly amountSats: number;
      }>;
    }
  | {
      readonly kind: "token";
      readonly outputs: ReadonlyArray<{
        readonly tokenIdentifier: Uint8Array;
        readonly ownerPublicKey: Uint8Array;
        readonly amount: bigint;
      }>;
    };

/**
 * The output-0 script of a lightning send's HTLC refund: hash lock to the SSP, sequence lock to the
 * sender identity — the same script `createRefundTxsForLightning` commits to.
 */
export function lightningSendHtlcScript(options: {
  readonly paymentHash: Uint8Array;
  readonly sspIdentityPublicKey: Uint8Array;
  readonly identityPublicKey: Uint8Array;
}): Uint8Array {
  return lightningHtlcOutputScript(
    options.paymentHash,
    options.sspIdentityPublicKey,
    options.identityPublicKey,
  );
}

export type AuthorizeOutflow = (outflow: SparkOutflow) => Promise<void>;

const MAX_SIGNING_KEYS = 4096;
const MAX_TRANSFERS = 256;

type SigningRecord = {
  maxAmount: number;
};

type PreparedLeaf = {
  readonly leafId: string;
  readonly key: SparkLeafKey;
  readonly receiverIdentityPublicKey: Uint8Array;
  readonly publicKey: Uint8Array;
};

type TransferRecord = {
  readonly leaves: ReadonlyArray<PreparedLeaf>;
  readonly operatorPackages: Record<string, Uint8Array>;
};

const eq = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, i) => byte === b[i]);

function outputScripts(tx: Transaction): Uint8Array[] {
  const scripts: Uint8Array[] = [];
  for (let i = 0; i < tx.outputsLength; i++) {
    const output = tx.getOutput(i);
    if (output.script === undefined) {
      throw new SparkInputError("transaction: output carries no script");
    }
    scripts.push(output.script);
  }
  return scripts;
}

/**
 * `onchain` outflow decoded from the transaction being signed; `inputSats` = the spent prevout
 * amounts (one per input) so the consumer can derive the fee.
 */
export function onchainOutflow(
  source: "static-deposit-refund" | "watchtower-recovery" | "htlc-timeout" | "key-spend",
  target: SigningTarget,
): SparkOutflow {
  const tx = parseTransaction(target.transaction);
  if (target.prevouts.length !== tx.inputsLength) {
    throw new SparkInputError(
      "transaction: prevouts must contain one entry per input to account the spend",
    );
  }
  const outputs: Array<{ script: Uint8Array; amountSats: number }> = [];
  for (let i = 0; i < tx.outputsLength; i++) {
    const output = tx.getOutput(i);
    if (output.script === undefined || output.amount === undefined) {
      throw new SparkInputError("transaction: output carries no script or amount");
    }
    outputs.push({ script: output.script, amountSats: Number(output.amount) });
  }
  return {
    kind: "onchain",
    source,
    outputs,
    inputSats: target.prevouts.reduce((sum, p) => sum + p.amount, 0),
    totalSats: outputs.reduce((sum, o) => sum + o.amountSats, 0),
  };
}

/** `token` outflow decoded from a PartialTokenTransaction: owner, identifier, u128 amount. */
export function tokenOutflow(partialTransaction: Uint8Array): SparkOutflow {
  let partial: PartialTokenTransaction;
  try {
    partial = fromBinary(PartialTokenTransactionSchema, partialTransaction);
  } catch (error) {
    throw new SparkInputError("token transaction: failed to decode protobuf", { cause: error });
  }
  return {
    kind: "token",
    outputs: partial.partialTokenOutputs.map((output) => ({
      tokenIdentifier: output.tokenIdentifier,
      ownerPublicKey: output.ownerPublicKey,
      amount: bytesToNumberBE(output.tokenAmount),
    })),
  };
}

export type OutflowTracker = {
  /**
   * Whitelist check for one signFrost batch. Returns the `lightning`/`exit` outflow to authorize,
   * or undefined when every output is whitelisted. Throws SparkInputError on malformed targets or
   * mixed exit/lightning candidates.
   */
  readonly evaluateJobs: (
    jobs: ReadonlyArray<{
      readonly key: SparkKey;
      readonly publicKey: Uint8Array;
      readonly target: SigningTarget;
      readonly exit?: { readonly connectorTx: Uint8Array; readonly exitTx: Uint8Array };
    }>,
  ) => Extract<SparkOutflow, { readonly kind: "lightning" | "exit" }> | undefined;
  readonly markServiceAuthorized: (publicKeys: ReadonlyArray<Uint8Array>) => void;
  readonly recordSign: (signingPublicKey: Uint8Array, target: SigningTarget) => void;
  readonly recordPrepare: (
    transferId: string,
    leaves: ReadonlyArray<PreparedLeaf>,
    operatorPackages: Record<string, Uint8Array>,
  ) => void;
  /**
   * The package-time outflow to authorize, or undefined when a `signFrost` authorization already
   * covered this transfer's leaves. Throws on mismatched or unrecorded evidence.
   */
  readonly packageOutflow: (
    transferId: string,
    packageBytes: Uint8Array,
  ) => SparkOutflow | undefined;
  readonly drop: (transferId: string) => void;
  readonly wipe: () => void;
};

export function createOutflowTracker(
  sspIdentityPublicKey: Uint8Array,
  network: SparkNetwork,
  identityPublicKey: Uint8Array,
): OutflowTracker {
  const signs = new Map<string, SigningRecord>();
  const transfers = new Map<string, TransferRecord>();
  // leaf signing pubkey → receivers recorded for it across pending transfers (counted for drop).
  const leafReceivers = new Map<string, Map<string, number>>();
  const receiverScripts = new Map<string, Uint8Array>();
  const serviceAuthorized = new Set<string>();
  const identityScript = p2trScriptFromPublicKey(identityPublicKey, network);

  const evaluateJobs: OutflowTracker["evaluateJobs"] = (jobs) => {
    const exits = new Map<string, Uint8Array>();
    const lightnings = new Map<string, Uint8Array>();
    let batchExit: { connectorTx: Uint8Array; exitTx: Uint8Array } | undefined;
    const leaves = new Map<string, { publicKey: Uint8Array; amountSats: number }>();
    for (const job of jobs) {
      const prevout = job.target.prevouts[job.target.inputIndex];
      if (prevout === undefined) {
        throw new SparkInputError("signFrost: inputIndex out of range for prevouts");
      }
      const tx = parseTransaction(job.target.transaction);
      const key = bytesToHex(job.publicKey);

      // Connector (cooperative-exit) refunds spend a foreign connector input alongside the
      // leaf — detected by inputs, before outputs: their outputs pay the SSP and are not
      // whitelist-checked. Foreign = a prevout script different from the spent input's.
      if (tx.inputsLength > 1) {
        const foreign = new Map<string, Uint8Array>();
        for (let i = 0; i < tx.inputsLength; i++) {
          const otherPrevout = job.target.prevouts[i];
          if (otherPrevout === undefined) {
            throw new SparkInputError("signFrost: prevouts must cover every input");
          }
          if (!eq(otherPrevout.script, prevout.script)) {
            const { txid } = tx.getInput(i);
            if (txid === undefined) {
              throw new SparkInputError("signFrost: foreign input carries no prevout txid");
            }
            foreign.set(bytesToHex(txid), txid);
          }
        }
        if (foreign.size > 0) {
          if (foreign.size !== 1) {
            throw new SparkInputError(
              "signFrost: foreign inputs carry more than one connector txid",
            );
          }
          const txid = foreign.values().next().value;
          if (txid === undefined) {
            throw new SparkInputError("signFrost: malformed input set");
          }
          // Connector refunds must carry the SSP's connector tx plus the coop-exit payout tx
          // it spends — the signature is bound to a disclosed destination (G-SV).
          if (job.exit === undefined) {
            throw new SparkInputError(
              "signFrost: connector refund job missing its connector/exit transaction pair",
            );
          }
          const connectorTx = parseTransaction(job.exit.connectorTx);
          if (!eq(txIdInputBytes(job.exit.connectorTx), txid)) {
            throw new SparkInputError(
              "signFrost: connectorTx txid does not match the foreign input",
            );
          }
          const parentTxid = connectorTx.getInput(0).txid;
          if (parentTxid === undefined) {
            throw new SparkInputError("signFrost: connectorTx has no input 0 txid");
          }
          if (!eq(parentTxid, txIdInputBytes(job.exit.exitTx))) {
            throw new SparkInputError("signFrost: connectorTx input 0 does not spend exitTx");
          }
          if (batchExit === undefined) {
            batchExit = job.exit;
          } else if (
            !eq(batchExit.connectorTx, job.exit.connectorTx) ||
            !eq(batchExit.exitTx, job.exit.exitTx)
          ) {
            throw new SparkInputError(
              "signFrost: exit jobs in one batch carry different transaction pairs",
            );
          }
          const entry = leaves.get(key) ?? { publicKey: job.publicKey, amountSats: 0 };
          entry.amountSats = Math.max(entry.amountSats, prevout.amount);
          leaves.set(key, entry);
          exits.set(bytesToHex(txid), txid);
          continue;
        }
      }

      const allowedReceivers = leafReceivers.get(key);
      const violations = outputScripts(tx).filter((script) => {
        if (eq(script, EPHEMERAL_ANCHOR_SCRIPT) || eq(script, prevout.script)) {
          return false;
        }
        if (eq(script, identityScript)) {
          return false;
        }
        // Signer-derived keys only: leaf and static-deposit keys this wallet alone can spend —
        // a received key is known to its sender and must not whitelist an output paying it.
        if (
          (job.key.type === "leaf" || job.key.type === "static-deposit") &&
          eq(script, p2trScriptFromPublicKey(job.publicKey, network))
        ) {
          return false;
        }
        if (allowedReceivers !== undefined) {
          for (const receiver of allowedReceivers.keys()) {
            const accepted = receiverScripts.get(receiver);
            if (accepted !== undefined && eq(script, accepted)) {
              return false;
            }
          }
        }
        return true;
      });
      if (violations.length === 0) {
        if (job.exit !== undefined) {
          throw new SparkInputError("signFrost: connector/exit pair on a non-exit job");
        }
        continue;
      }
      if (job.exit !== undefined) {
        throw new SparkInputError("signFrost: connector/exit pair on a non-exit job");
      }
      const entry = leaves.get(key) ?? { publicKey: job.publicKey, amountSats: 0 };
      entry.amountSats = Math.max(entry.amountSats, prevout.amount);
      leaves.set(key, entry);
      if (tx.inputsLength === 1) {
        const distinct = new Map<string, Uint8Array>();
        for (const script of violations) {
          distinct.set(bytesToHex(script), script);
        }
        if (distinct.size !== 1) {
          throw new SparkInputError("signFrost: job carries multiple non-whitelisted outputs");
        }
        const script = distinct.values().next().value;
        if (script === undefined) {
          throw new SparkInputError("signFrost: malformed output set");
        }
        lightnings.set(bytesToHex(script), script);
      } else {
        throw new SparkInputError(
          `signFrost: non-whitelisted output on a ${tx.inputsLength}-input transaction`,
        );
      }
    }
    if (exits.size > 0 && lightnings.size > 0) {
      throw new SparkInputError("signFrost: batch mixes connector and HTLC refunds");
    }
    const leafList = [...leaves.values()];
    const totalSats = leafList.reduce((sum, l) => sum + l.amountSats, 0);
    if (exits.size > 1 || lightnings.size > 1) {
      throw new SparkInputError(
        "signFrost: inconsistent connector txids or HTLC scripts in one batch",
      );
    }
    const connectorTxid = exits.values().next().value;
    if (connectorTxid !== undefined) {
      if (batchExit === undefined) {
        throw new SparkInputError("signFrost: exit candidates without their transaction pair");
      }
      const exitTx = parseTransaction(batchExit.exitTx);
      const exitOutputs: Array<{ script: Uint8Array; amountSats: number }> = [];
      for (let i = 0; i < exitTx.outputsLength; i++) {
        const output = exitTx.getOutput(i);
        if (output.script === undefined || output.amount === undefined) {
          throw new SparkInputError("signFrost: exitTx output carries no script or amount");
        }
        exitOutputs.push({ script: output.script, amountSats: Number(output.amount) });
      }
      return { kind: "exit", connectorTxid, leaves: leafList, totalSats, exitOutputs };
    }
    const htlcOutputScript = lightnings.values().next().value;
    if (htlcOutputScript !== undefined) {
      return { kind: "lightning", htlcOutputScript, leaves: leafList, totalSats };
    }
    return undefined;
  };

  const recordSign = (signingPublicKey: Uint8Array, target: SigningTarget): void => {
    const prevout = target.prevouts[target.inputIndex];
    if (prevout === undefined) {
      throw new SparkInputError("signFrost: inputIndex out of range for prevouts");
    }
    const key = bytesToHex(signingPublicKey);
    let record = signs.get(key);
    if (record === undefined) {
      if (signs.size >= MAX_SIGNING_KEYS) {
        const oldest = signs.keys().next().value;
        if (oldest !== undefined) {
          signs.delete(oldest);
        }
      }
      record = { maxAmount: 0 };
      signs.set(key, record);
    }
    if (prevout.amount > record.maxAmount) {
      record.maxAmount = prevout.amount;
    }
  };

  const recordPrepare: OutflowTracker["recordPrepare"] = (transferId, leaves, operatorPackages) => {
    if (!transfers.has(transferId) && transfers.size >= MAX_TRANSFERS) {
      const oldest = transfers.keys().next().value;
      if (oldest !== undefined) {
        transfers.delete(oldest);
      }
    }
    for (const leaf of leaves) {
      const pk = bytesToHex(leaf.publicKey);
      let receivers = leafReceivers.get(pk);
      if (receivers === undefined) {
        receivers = new Map();
        leafReceivers.set(pk, receivers);
      }
      const receiver = bytesToHex(leaf.receiverIdentityPublicKey);
      receivers.set(receiver, (receivers.get(receiver) ?? 0) + 1);
      receiverScripts.set(
        receiver,
        p2trScriptFromPublicKey(leaf.receiverIdentityPublicKey, network),
      );
    }
    // Copy every byte array the host could transfer out of process — a detached buffer in the
    // recorded request would read as length-0 at package time and reject a valid signature.
    transfers.set(transferId, {
      leaves: leaves.map((leaf) => ({
        ...leaf,
        key: { ...leaf.key },
        publicKey: new Uint8Array(leaf.publicKey),
        receiverIdentityPublicKey: new Uint8Array(leaf.receiverIdentityPublicKey),
      })),
      operatorPackages: Object.fromEntries(
        Object.entries(operatorPackages).map(([id, pkg]) => [id, new Uint8Array(pkg)]),
      ),
    });
  };

  const packageOutflow: OutflowTracker["packageOutflow"] = (transferId, packageBytes) => {
    const prepared = transfers.get(transferId);
    if (prepared === undefined) {
      throw new SparkInputError(
        "transfer package: no recorded prepareTransfer for this transferId",
      );
    }
    const keyTweakPackage = (() => {
      try {
        return fromBinary(TransferPackageSchema, packageBytes).keyTweakPackage;
      } catch (error) {
        throw new SparkInputError("transfer package: failed to decode protobuf", {
          cause: error,
        });
      }
    })();
    // The package must be exactly what this signer prepared: same operators, same bytes.
    const expected = Object.keys(prepared.operatorPackages).sort();
    const actual = Object.keys(keyTweakPackage).sort();
    if (
      expected.length !== actual.length ||
      !expected.every((id, i) => id === actual[i]) ||
      !expected.every((id) => {
        const value = keyTweakPackage[id];
        const recorded = prepared.operatorPackages[id];
        return value !== undefined && recorded !== undefined && eq(recorded, value);
      })
    ) {
      throw new SparkInputError(
        "transfer package: key_tweak_package does not match the recorded operator packages",
      );
    }

    // Every leaf needs a recorded refund signature; the amount is the maximum prevout amount
    // that pubkey signed this session (the SO enforces it end-to-end).
    const leafAmounts = prepared.leaves.map((leaf) => {
      const record = signs.get(bytesToHex(leaf.publicKey));
      if (record === undefined) {
        throw new SparkInputError(
          `transfer package: no recorded refund signature for leaf ${leaf.leafId}`,
        );
      }
      return record.maxAmount;
    });
    const totalSats = leafAmounts.reduce((sum, amount) => sum + amount, 0);

    const ssp = prepared.leaves.map((leaf) =>
      eq(leaf.receiverIdentityPublicKey, sspIdentityPublicKey),
    );
    const sspCount = ssp.filter(Boolean).length;
    if (sspCount > 0 && sspCount !== prepared.leaves.length) {
      throw new SparkInputError("transfer package: SSP and non-SSP receivers in one transfer");
    }
    if (sspCount > 0) {
      const authorized = prepared.leaves.filter((leaf) =>
        serviceAuthorized.has(bytesToHex(leaf.publicKey)),
      ).length;
      if (authorized === prepared.leaves.length) {
        // Every leaf's HTLC/connector shares were already authorized at signFrost.
        return undefined;
      }
      if (authorized !== 0) {
        throw new SparkInputError(
          "transfer package: SSP transfer mixes service-authorized and unauthorized leaves",
        );
      }
      return { kind: "swap", transferId, totalSats };
    }
    const receivers = new Map<string, { identityPublicKey: Uint8Array; amountSats: number }>();
    for (const [i, leaf] of prepared.leaves.entries()) {
      const key = bytesToHex(leaf.receiverIdentityPublicKey);
      const amount = leafAmounts[i];
      if (amount === undefined) {
        throw new SparkInputError("transfer package: leaf amount out of range");
      }
      const entry = receivers.get(key);
      if (entry === undefined) {
        receivers.set(key, {
          identityPublicKey: leaf.receiverIdentityPublicKey,
          amountSats: amount,
        });
      } else {
        entry.amountSats += amount;
      }
    }
    return {
      kind: "transfer",
      transferId,
      totalSats,
      receivers: [...receivers.values()],
    };
  };

  const drop = (transferId: string): void => {
    const prepared = transfers.get(transferId);
    if (prepared !== undefined) {
      for (const leaf of prepared.leaves) {
        const pk = bytesToHex(leaf.publicKey);
        const receivers = leafReceivers.get(pk);
        const receiver = bytesToHex(leaf.receiverIdentityPublicKey);
        if (receivers !== undefined) {
          const count = receivers.get(receiver);
          if (count !== undefined) {
            if (count > 1) {
              receivers.set(receiver, count - 1);
            } else {
              receivers.delete(receiver);
              if (receivers.size === 0) {
                leafReceivers.delete(pk);
              }
            }
          }
        }
      }
      transfers.delete(transferId);
    }
  };

  return {
    evaluateJobs,
    markServiceAuthorized: (publicKeys) => {
      for (const pk of publicKeys) {
        serviceAuthorized.add(bytesToHex(pk));
      }
    },
    recordSign,
    recordPrepare,
    packageOutflow,
    drop,
    wipe: () => {
      signs.clear();
      transfers.clear();
      leafReceivers.clear();
      serviceAuthorized.clear();
      receiverScripts.clear();
    },
  };
}
