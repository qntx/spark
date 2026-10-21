import { create } from "@bufbuild/protobuf";
import { createClient, createRouterTransport } from "@connectrpc/connect";
import type { Client } from "@connectrpc/connect";
import { mod } from "@noble/curves/abstract/modular.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import { u64ToSats } from "../src/core/assert.ts";
import {
  p2trScriptFromPublicKey,
  parseTransaction,
  taprootKeySpendSighash,
  txId,
  txIdInputBytes,
  verifyFinalizedTaprootSignature,
} from "../src/core/bitcoin/index.ts";
import {
  queryWatchtowerExitedLeaves,
  recoverWatchtowerExit,
  resolveRecoverableOutput,
} from "../src/exit/watchtower.ts";
import {
  Network,
  QueryNodesResponseSchema,
  RecoverWatchtowerExitedLeafResponseSchema,
  SigningResultSchema,
  SparkService,
  TreeNodeSchema,
  TreeNodeStatus,
} from "../src/proto/gen/spark_pb.ts";
import type {
  QueryNodesRequest,
  RecoverWatchtowerExitedLeafRequest,
  TreeNode,
} from "../src/proto/gen/spark_pb.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import type { SparkSigner } from "../src/signer/index.ts";
import { loadWasmBackend } from "./support/backend.ts";
import { required } from "./support/fakes.ts";
import { lagrangeCoefficient, operatorSetup, operatorSignatureShares } from "./support/frost.ts";
import type { FrostTestOperator } from "./support/frost.ts";

const LEAF_ID = "01989abc-def0-7abc-89ab-cdef01234567";
const PARENT_ID = "01989abc-def0-7abc-89ab-0000000000aa";
const GRANDPARENT_ID = "01989abc-def0-7abc-89ab-0000000000bb";
const FOREIGN_KEY = secp256k1.Point.BASE.multiply(0x77n).toBytes(true);
const DESTINATION_SCRIPT = p2trScriptFromPublicKey(
  secp256k1.Point.BASE.multiply(0xdeadn).toBytes(true),
  "regtest",
);

async function testSigner(): Promise<SparkSigner> {
  let counter = 0;
  return createSparkSigner({
    crypto: await loadWasmBackend(),
    accountKey: sparkAccountKey(new Uint8Array(32).fill(11), "regtest"),
    network: "regtest",
    random: (length) => {
      const out = new Uint8Array(length);
      for (let i = 0; i < length; i++) {
        counter = (counter + 1) % 251;
        out[i] = counter;
      }
      return out;
    },
  });
}

/** A fake ancestor transaction paying `script` at `payIndex`, padded with filler outputs. */
function ancestorTx(options: {
  readonly inputLabel: number;
  readonly script: Uint8Array;
  readonly sats: bigint;
  readonly payIndex?: number;
  readonly totalOutputs?: number;
}): Uint8Array {
  const total = options.totalOutputs ?? (options.payIndex ?? 0) + 1;
  const payIndex = options.payIndex ?? 0;
  const filler = p2trScriptFromPublicKey(
    secp256k1.Point.BASE.multiply(0x555n).toBytes(true),
    "regtest",
  );
  const tx = new Transaction({ allowUnknownOutputs: true });
  const txid = new Uint8Array(32).fill(options.inputLabel);
  tx.addInput({ txid, index: 0, sequence: 0 });
  for (let i = 0; i < total; i++) {
    tx.addOutput({
      script: i === payIndex ? options.script : filler,
      amount: i === payIndex ? options.sats : 1000n,
    });
  }
  return tx.toBytes(true);
}

function statusName(status: TreeNodeStatus): string {
  return Object.entries(TreeNodeStatus).find(([, value]) => value === status)?.[0] ?? "UNSPECIFIED";
}

function nodeProto(options: {
  readonly id: string;
  readonly parentNodeId?: string;
  readonly treenodeStatus: TreeNodeStatus;
  readonly directTx?: Uint8Array;
  readonly refundTx?: Uint8Array;
  readonly verifyingPublicKey?: Uint8Array;
  readonly ownerIdentityPublicKey?: Uint8Array;
  readonly ownerSigningPublicKey?: Uint8Array;
  readonly value?: bigint;
}): TreeNode {
  return create(TreeNodeSchema, {
    id: options.id,
    treeId: "tree-1",
    value: options.value ?? 50_000n,
    nodeTx: new Uint8Array([1, 2]),
    refundTx: options.refundTx ?? new Uint8Array([3, 4]),
    vout: 0,
    verifyingPublicKey: options.verifyingPublicKey ?? FOREIGN_KEY,
    ownerIdentityPublicKey: options.ownerIdentityPublicKey ?? new Uint8Array(33).fill(6),
    ownerSigningPublicKey: options.ownerSigningPublicKey ?? new Uint8Array(33).fill(6),
    signingKeyshare: { ownerIdentifiers: [], threshold: 1, publicKey: new Uint8Array(33).fill(7) },
    status: statusName(options.treenodeStatus),
    network: Network.REGTEST,
    treenodeStatus: options.treenodeStatus,
    directTx: options.directTx ?? new Uint8Array(0),
    ...(options.parentNodeId === undefined ? {} : { parentNodeId: options.parentNodeId }),
  });
}

/** Narrows a query_nodes request to its nodeIds source, failing the test on any other case. */
function nodeIdsFrom(req: QueryNodesRequest): ReadonlyArray<string> {
  if (req.source.case !== "nodeIds") {
    throw new Error(`unexpected query_nodes source: ${req.source.case}`);
  }
  return required(req.source.value, "nodeIds source").nodeIds;
}

/** Serves `nodes` from query_nodes for both the owner and the nodeIds sources. */
function sparkServing(
  nodes: ReadonlyArray<TreeNode>,
  hooks?: { readonly onQueryNodes?: (req: QueryNodesRequest) => void },
): Client<typeof SparkService> {
  const transport = createRouterTransport((router) => {
    router.service(SparkService, {
      query_nodes: (req: QueryNodesRequest) => {
        hooks?.onQueryNodes?.(req);
        const byId = Object.fromEntries(nodes.map((node) => [node.id, node]));
        return create(QueryNodesResponseSchema, { nodes: byId, offset: -1n });
      },
    });
  });
  return createClient(SparkService, transport);
}

describe("resolveRecoverableOutput", () => {
  const LEAF_KEY = secp256k1.Point.BASE.multiply(0x42n).toBytes(true);
  const script = p2trScriptFromPublicKey(LEAF_KEY, "regtest");

  function chain(parentStatus: TreeNodeStatus, grandStatus: TreeNodeStatus) {
    const parentTx = ancestorTx({ inputLabel: 0x21, script, sats: 40_000n });
    const grandTx = ancestorTx({ inputLabel: 0x31, script, sats: 60_000n, payIndex: 1 });
    const leaf = nodeProto({
      id: "leaf",
      parentNodeId: "parent",
      treenodeStatus: TreeNodeStatus.WATCHTOWER_EXITED,
      verifyingPublicKey: LEAF_KEY,
    });
    const parent = nodeProto({
      id: "parent",
      parentNodeId: "grand",
      treenodeStatus: parentStatus,
      directTx: parentTx,
    });
    const grand = nodeProto({ id: "grand", treenodeStatus: grandStatus, directTx: grandTx });
    return { leaf, parent, grand, parentTx, grandTx };
  }

  test("nearest ON_CHAIN generation wins; non-ON_CHAIN ancestors are skipped", () => {
    const { leaf, parent, grand, grandTx } = chain(
      TreeNodeStatus.WATCHTOWER_EXITED,
      TreeNodeStatus.ON_CHAIN,
    );
    const resolved = resolveRecoverableOutput(leaf, [leaf, parent, grand], "regtest");
    expect(resolved?.txid).toBe(txId(grandTx));
    expect(resolved?.outputIndex).toBe(1);
    expect(resolved?.valueSats).toBe(60_000);
  });

  test("the nearest ON_CHAIN ancestor wins over an older one", () => {
    const { leaf, parent, grand, parentTx } = chain(
      TreeNodeStatus.ON_CHAIN,
      TreeNodeStatus.ON_CHAIN,
    );
    const resolved = resolveRecoverableOutput(leaf, [leaf, parent, grand], "regtest");
    // Generation order is load bearing: only the nearest ON_CHAIN generation's output can be
    // unspent — a later watchtower broadcast spends every older one.
    expect(resolved?.txid).toBe(txId(parentTx));
    expect(resolved?.valueSats).toBe(40_000);
  });

  test("the leaf's own direct tx is gated out by its WATCHTOWER_EXITED status", () => {
    // The leaf's direct tx conflict-spends the very output being recovered; it only qualifies
    // via an explicit recoveryTxid — matching the SE's findRecoverySourceNode gate.
    const { leaf, parent, grand, parentTx } = chain(
      TreeNodeStatus.ON_CHAIN,
      TreeNodeStatus.ON_CHAIN,
    );
    const leafTx = ancestorTx({ inputLabel: 0x11, script, sats: 50_000n });
    const leafWithDirect = create(TreeNodeSchema, { ...leaf, directTx: leafTx });
    const resolved = resolveRecoverableOutput(
      leafWithDirect,
      [leafWithDirect, parent, grand],
      "regtest",
    );
    expect(resolved?.txid).toBe(txId(parentTx));
    expect(resolveRecoverableOutput(leafWithDirect, [leafWithDirect], "regtest")).toBeUndefined();
  });

  test("no direct tx anywhere resolves to undefined", () => {
    const { leaf, parent, grand } = chain(
      TreeNodeStatus.WATCHTOWER_EXITED,
      TreeNodeStatus.WATCHTOWER_EXITED,
    );
    expect(resolveRecoverableOutput(leaf, [leaf, parent, grand], "regtest")).toBeUndefined();
  });

  test("an explicit recoveryTxid takes a non-ON_CHAIN generation at its word", () => {
    const { leaf, parent, grand, parentTx } = chain(
      TreeNodeStatus.WATCHTOWER_EXITED,
      TreeNodeStatus.ON_CHAIN,
    );
    const resolved = resolveRecoverableOutput(
      leaf,
      [leaf, parent, grand],
      "regtest",
      txId(parentTx),
    );
    expect(resolved?.txid).toBe(txId(parentTx));
    expect(resolved?.valueSats).toBe(40_000);
  });

  test("an unmatched recoveryTxid resolves nothing", () => {
    const { leaf, parent, grand } = chain(
      TreeNodeStatus.WATCHTOWER_EXITED,
      TreeNodeStatus.ON_CHAIN,
    );
    expect(
      resolveRecoverableOutput(leaf, [leaf, parent, grand], "regtest", "00".repeat(64)),
    ).toBeUndefined();
  });

  test("an explicit outputIndex is re-checked against the leaf script", () => {
    const { leaf, parent, grand } = chain(
      TreeNodeStatus.WATCHTOWER_EXITED,
      TreeNodeStatus.ON_CHAIN,
    );
    // Index 0 of the grandparent tx is filler paying another key.
    expect(
      resolveRecoverableOutput(leaf, [leaf, parent, grand], "regtest", undefined, 0),
    ).toBeUndefined();
    const resolved = resolveRecoverableOutput(leaf, [leaf, parent, grand], "regtest", undefined, 1);
    expect(resolved?.outputIndex).toBe(1);
  });

  test("an out-of-range outputIndex resolves nothing", () => {
    const { leaf, parent, grand } = chain(
      TreeNodeStatus.WATCHTOWER_EXITED,
      TreeNodeStatus.ON_CHAIN,
    );
    expect(
      resolveRecoverableOutput(leaf, [leaf, parent, grand], "regtest", undefined, 99),
    ).toBeUndefined();
  });

  test("a parent cycle terminates instead of spinning", () => {
    const leaf = nodeProto({
      id: "leaf",
      parentNodeId: "parent",
      treenodeStatus: TreeNodeStatus.WATCHTOWER_EXITED,
      verifyingPublicKey: LEAF_KEY,
    });
    const parent = nodeProto({
      id: "parent",
      parentNodeId: "leaf",
      treenodeStatus: TreeNodeStatus.ON_CHAIN,
      directTx: ancestorTx({ inputLabel: 0x41, script, sats: 30_000n }),
    });
    const resolved = resolveRecoverableOutput(leaf, [leaf, parent], "regtest");
    expect(resolved?.valueSats).toBe(30_000);
  });
});

describe("queryWatchtowerExitedLeaves", () => {
  test("filters to owned leaves with refunds and resolves the recovery output", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const script = p2trScriptFromPublicKey(FOREIGN_KEY, "regtest");
    const grandTx = ancestorTx({ inputLabel: 0x31, script, sats: 60_000n });
    let captured: QueryNodesRequest | undefined;
    const spark = sparkServing(
      [
        nodeProto({
          id: "leaf-ours",
          parentNodeId: "grand",
          treenodeStatus: TreeNodeStatus.WATCHTOWER_EXITED,
          verifyingPublicKey: FOREIGN_KEY,
          ownerIdentityPublicKey: identity,
        }),
        nodeProto({
          id: "leaf-recovered",
          treenodeStatus: TreeNodeStatus.WATCHTOWER_EXIT_RECOVERED,
          verifyingPublicKey: FOREIGN_KEY,
          ownerIdentityPublicKey: identity,
        }),
        nodeProto({
          id: "leaf-foreign",
          treenodeStatus: TreeNodeStatus.WATCHTOWER_EXITED,
          verifyingPublicKey: FOREIGN_KEY,
          ownerIdentityPublicKey: FOREIGN_KEY,
        }),
        // Ancestor of leaf-ours: no refund tx, so it is not listed — but its direct tx
        // carries the recoverable output.
        nodeProto({
          id: "grand",
          treenodeStatus: TreeNodeStatus.ON_CHAIN,
          directTx: grandTx,
          refundTx: new Uint8Array(0),
        }),
      ],
      {
        onQueryNodes: (req) => {
          captured = req;
        },
      },
    );
    const listed = await queryWatchtowerExitedLeaves({
      spark,
      identityPublicKey: identity,
      network: "regtest",
    });
    const query = required(captured, "query_nodes request");
    expect(query.source.case).toBe("ownerIdentityPubkey");
    expect(query.includeParents).toBe(true);
    expect(query.statuses).toStrictEqual([
      TreeNodeStatus.WATCHTOWER_EXITED,
      TreeNodeStatus.WATCHTOWER_EXIT_RECOVERED,
    ]);
    expect(listed.map((entry) => entry.leafId).toSorted()).toStrictEqual([
      "leaf-ours",
      "leaf-recovered",
    ]);
    const [ours, recovered] = listed.toSorted((a, b) => a.leafId.localeCompare(b.leafId));
    expect(ours?.status).toBe("WATCHTOWER_EXITED");
    expect(ours?.valueSats).toBe(50_000);
    expect(ours?.recovery?.txid).toBe(txId(grandTx));
    expect(recovered?.status).toBe("WATCHTOWER_EXIT_RECOVERED");
    // leaf-recovered has no ancestors — no resolvable output, still listed.
    expect(recovered?.recovery).toBeUndefined();
    signer.dispose();
  });

  test("accepts a final page holding more entries than the page size", async () => {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    // The SO merges includeParents ancestors into the response map after computing the page's
    // next offset, so an explicit -1 offset may accompany a map larger than the 50-row page.
    const spark = sparkServing([
      nodeProto({
        id: "leaf-ours",
        treenodeStatus: TreeNodeStatus.WATCHTOWER_EXITED,
        verifyingPublicKey: FOREIGN_KEY,
        ownerIdentityPublicKey: identity,
      }),
      ...Array.from({ length: 60 }, (_, i) =>
        nodeProto({ id: `other-${i}`, treenodeStatus: TreeNodeStatus.WATCHTOWER_EXITED }),
      ),
    ]);
    const listed = await queryWatchtowerExitedLeaves({
      spark,
      identityPublicKey: identity,
      network: "regtest",
    });
    expect(listed.map((entry) => entry.leafId)).toStrictEqual(["leaf-ours"]);
    signer.dispose();
  });
});

describe("recoverWatchtowerExit", () => {
  const OPERATOR_SECRETS = [11111n, 44444n, 77777n] as const;
  const OPERATOR_NONCES: ReadonlyArray<readonly [bigint, bigint]> = [
    [22222n, 33333n],
    [55555n, 66666n],
    [88888n, 99999n],
  ];
  const { ORDER } = secp256k1.Point.Fn;

  /**
   * The FROST group for a leaf the real signer owns: `verifyingKey = leafPub + Σλ_i·s_i·G`, even-Y
   * enforced by bumping the last share — `frostGroup` with the leaf's public key standing in for
   * `userSecret·G`.
   */
  function leafFrostGroup(leafPublicKey: Uint8Array): {
    operators: FrostTestOperator[];
    verifyingKey: Uint8Array;
  } {
    for (let bump = 0n; ; bump++) {
      const operators = OPERATOR_SECRETS.map((secret, i) => {
        const pair = required(OPERATOR_NONCES[i], "operator nonce pair");
        return {
          id: BigInt(i + 1),
          secret: i === OPERATOR_SECRETS.length - 1 ? secret + bump : secret,
          hidingNonce: pair[0],
          bindingNonce: pair[1],
        };
      });
      const xs = operators.map((o) => o.id);
      let key = secp256k1.Point.fromBytes(leafPublicKey);
      for (const operator of operators) {
        key = key.add(
          secp256k1.Point.BASE.multiply(
            mod(lagrangeCoefficient(operator.id, xs) * mod(operator.secret, ORDER), ORDER),
          ),
        );
      }
      if ((key.toAffine().y & 1n) === 0n) {
        return { operators, verifyingKey: key.toBytes(true) };
      }
    }
  }

  async function fixture(options?: {
    readonly ownerIdentityPublicKey?: Uint8Array;
    readonly ownerSigningPublicKey?: Uint8Array;
    readonly leafStatus?: TreeNodeStatus;
    readonly includeAncestors?: boolean;
  }) {
    const signer = await testSigner();
    const identity = await signer.identityPublicKey();
    const [leafPub] = await signer.publicKeys([{ type: "leaf", leafId: LEAF_ID }]);
    const signingPublicKey = required(leafPub, "leaf public key");
    const { operators, verifyingKey } = leafFrostGroup(signingPublicKey);
    const script = p2trScriptFromPublicKey(verifyingKey, "regtest");
    const directTx = ancestorTx({ inputLabel: 0x31, script, sats: 60_000n, payIndex: 1 });
    const leaf = nodeProto({
      id: LEAF_ID,
      parentNodeId: PARENT_ID,
      treenodeStatus: options?.leafStatus ?? TreeNodeStatus.WATCHTOWER_EXITED,
      verifyingPublicKey: verifyingKey,
      ownerIdentityPublicKey: options?.ownerIdentityPublicKey ?? identity,
      ownerSigningPublicKey: options?.ownerSigningPublicKey ?? signingPublicKey,
    });
    const parent = nodeProto({
      id: PARENT_ID,
      parentNodeId: GRANDPARENT_ID,
      treenodeStatus: TreeNodeStatus.WATCHTOWER_EXITED,
    });
    const grand = nodeProto({
      id: GRANDPARENT_ID,
      treenodeStatus: TreeNodeStatus.ON_CHAIN,
      directTx,
    });
    const nodes = options?.includeAncestors === false ? [leaf] : [leaf, parent, grand];
    return {
      signer,
      identity,
      signingPublicKey,
      operators,
      verifyingKey,
      script,
      directTx,
      leaf,
      nodes,
    };
  }

  function sparkFor(
    f: Awaited<ReturnType<typeof fixture>>,
    overrides?: {
      readonly verifyingKey?: Uint8Array;
      readonly corruptShares?: boolean;
      readonly captureQuery?: (req: QueryNodesRequest) => void;
      readonly captureRequest?: (req: RecoverWatchtowerExitedLeafRequest) => void;
    },
  ): Client<typeof SparkService> {
    const fixtures = operatorSetup(f.operators);
    const sourceOutput = parseTransaction(f.directTx).getOutput(1);
    const prevout = {
      script: required(sourceOutput.script, "source script"),
      amount: u64ToSats(required(sourceOutput.amount, "source amount"), "source amount"),
    };
    const transport = createRouterTransport((router) => {
      router.service(SparkService, {
        query_nodes: (req: QueryNodesRequest) => {
          overrides?.captureQuery?.(req);
          return create(QueryNodesResponseSchema, {
            nodes: Object.fromEntries(f.nodes.map((node) => [node.id, node])),
            offset: -1n,
          });
        },
        recover_watchtower_exited_leaf: (req: RecoverWatchtowerExitedLeafRequest) => {
          overrides?.captureRequest?.(req);
          const job = required(req.recoveryTxSigningJob, "recovery tx signing job");
          const sighash = taprootKeySpendSighash({
            transaction: job.rawTx,
            inputIndex: 0,
            prevouts: [prevout],
          });
          const shares = operatorSignatureShares({
            operators: f.operators,
            verifyingKey: f.verifyingKey,
            userCommitment: required(job.signingNonceCommitment, "nonce commitment"),
            message: sighash,
          });
          if (overrides?.corruptShares === true) {
            const [first] = shares;
            if (first !== undefined) {
              first[0] = (first[0] ?? 0) ^ 0xff;
            }
          }
          return create(RecoverWatchtowerExitedLeafResponseSchema, {
            recoveryTxSigningResult: create(SigningResultSchema, {
              publicKeys: Object.fromEntries(fixtures.map((fx) => [fx.identifier, fx.publicKey])),
              signingNonceCommitments: Object.fromEntries(
                fixtures.map((fx) => [fx.identifier, fx.commitment]),
              ),
              signatureShares: Object.fromEntries(
                fixtures.map((fx, i) => [fx.identifier, shares[i] ?? new Uint8Array(32)]),
              ),
            }),
            verifyingKey: overrides?.verifyingKey ?? f.verifyingKey,
          });
        },
      });
    });
    return createClient(SparkService, transport);
  }

  test("signs a recovery of the nearest ON_CHAIN ancestor output", async () => {
    const f = await fixture();
    let query: QueryNodesRequest | undefined;
    let request: RecoverWatchtowerExitedLeafRequest | undefined;
    const spark = sparkFor(f, {
      captureQuery: (req) => {
        query = req;
      },
      captureRequest: (req) => {
        request = req;
      },
    });
    const { transaction, txid } = await recoverWatchtowerExit(
      { spark, signer: f.signer, network: "regtest" },
      { leafId: LEAF_ID, destinationScript: DESTINATION_SCRIPT, feeRateSatPerVbyte: 2 },
    );
    f.signer.dispose();

    const req = required(query, "query_nodes request");
    expect(nodeIdsFrom(req)).toStrictEqual([LEAF_ID]);
    expect(req.includeParents).toBe(true);

    const job = required(required(request, "recover request").recoveryTxSigningJob, "job");
    expect(job.signingPublicKey).toStrictEqual(f.signingPublicKey);
    expect(required(request, "recover request").userSignature.length).toBeGreaterThan(0);

    // The signed tx spends the grandparent's direct-tx output 1 paying the leaf key.
    const signed = parseTransaction(transaction);
    const input = signed.getInput(0);
    expect(input.txid).toStrictEqual(txIdInputBytes(f.directTx));
    expect(input.index).toBe(1);
    expect(txid).toBe(txId(transaction));
    expect(
      verifyFinalizedTaprootSignature(
        transaction,
        taprootKeySpendSighash({
          transaction,
          inputIndex: 0,
          prevouts: [
            {
              script: required(parseTransaction(f.directTx).getOutput(1).script, "prevout script"),
              amount: 60_000,
            },
          ],
        }),
        f.verifyingKey,
        0,
      ),
    ).toBe(true);
  });

  test("rejects a leaf that is not ours", async () => {
    const f = await fixture({ ownerIdentityPublicKey: FOREIGN_KEY });
    const spark = sparkFor(f);
    await expect(
      recoverWatchtowerExit(
        { spark, signer: f.signer, network: "regtest" },
        { leafId: LEAF_ID, destinationScript: DESTINATION_SCRIPT, feeRateSatPerVbyte: 2 },
      ),
    ).rejects.toThrow("is not ours");
    f.signer.dispose();
  });

  test("rejects a leaf that is not watchtower-exited", async () => {
    const f = await fixture({ leafStatus: TreeNodeStatus.AVAILABLE });
    const spark = sparkFor(f);
    await expect(
      recoverWatchtowerExit(
        { spark, signer: f.signer, network: "regtest" },
        { leafId: LEAF_ID, destinationScript: DESTINATION_SCRIPT, feeRateSatPerVbyte: 2 },
      ),
    ).rejects.toThrow("expected a watchtower-exited status");
    f.signer.dispose();
  });

  test("rejects when no ancestor holds a recoverable output", async () => {
    const f = await fixture({ includeAncestors: false });
    const spark = sparkFor(f);
    await expect(
      recoverWatchtowerExit(
        { spark, signer: f.signer, network: "regtest" },
        { leafId: LEAF_ID, destinationScript: DESTINATION_SCRIPT, feeRateSatPerVbyte: 2 },
      ),
    ).rejects.toThrow("no confirmed ancestor transaction");
    f.signer.dispose();
  });

  test("rejects when the signer key is not the leaf's owner signing key", async () => {
    const f = await fixture({ ownerSigningPublicKey: FOREIGN_KEY });
    const spark = sparkFor(f);
    await expect(
      recoverWatchtowerExit(
        { spark, signer: f.signer, network: "regtest" },
        { leafId: LEAF_ID, destinationScript: DESTINATION_SCRIPT, feeRateSatPerVbyte: 2 },
      ),
    ).rejects.toThrow("does not match leaf");
    f.signer.dispose();
  });

  test("rejects a coordinator verifying key that is not the leaf's", async () => {
    const f = await fixture();
    const spark = sparkFor(f, { verifyingKey: FOREIGN_KEY });
    await expect(
      recoverWatchtowerExit(
        { spark, signer: f.signer, network: "regtest" },
        { leafId: LEAF_ID, destinationScript: DESTINATION_SCRIPT, feeRateSatPerVbyte: 2 },
      ),
    ).rejects.toThrow("unexpected verifying key");
    f.signer.dispose();
  });

  test("rejects tampered operator shares before the tx is returned", async () => {
    // aggregateFrost validates each share cryptographically, so a tampered share fails inside
    // the backend — the local verifyFinalizedTaprootSignature is the second fence behind it.
    const f = await fixture();
    const spark = sparkFor(f, { corruptShares: true });
    await expect(
      recoverWatchtowerExit(
        { spark, signer: f.signer, network: "regtest" },
        { leafId: LEAF_ID, destinationScript: DESTINATION_SCRIPT, feeRateSatPerVbyte: 2 },
      ),
    ).rejects.toThrow(/./);
    f.signer.dispose();
  });
});
