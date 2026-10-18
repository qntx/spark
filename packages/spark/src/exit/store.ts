// SparkStore persists each leaf's unilateral-exit chain so a wallet can still
// broadcast its pre-signed node/refund transactions if the operators go dark —
// the chain is captured the moment the leaf is claimed or synced, before the
// exit is ever needed.

/** Every pre-signed transaction needed to exit one leaf unilaterally. */
export type SparkExitChain = {
  readonly leafId: string;
  /** Root → leaf. */
  readonly nodes: ReadonlyArray<{
    readonly nodeId: string;
    readonly nodeTx: Uint8Array;
    readonly directTx?: Uint8Array;
  }>;
  readonly refundTx: Uint8Array;
  readonly directRefundTx?: Uint8Array;
  readonly directFromCpfpRefundTx?: Uint8Array;
};

export type SparkStore = {
  readonly exitChains: () => Promise<ReadonlyArray<SparkExitChain>>;
  /** Upsert by leafId. */
  readonly putExitChains: (chains: ReadonlyArray<SparkExitChain>) => Promise<void>;
  readonly deleteExitChains: (leafIds: ReadonlyArray<string>) => Promise<void>;
};

function copyBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function copyChain(chain: SparkExitChain): SparkExitChain {
  return {
    leafId: chain.leafId,
    nodes: chain.nodes.map((node) => ({
      nodeId: node.nodeId,
      nodeTx: copyBytes(node.nodeTx),
      ...(node.directTx === undefined ? {} : { directTx: copyBytes(node.directTx) }),
    })),
    refundTx: copyBytes(chain.refundTx),
    ...(chain.directRefundTx === undefined
      ? {}
      : { directRefundTx: copyBytes(chain.directRefundTx) }),
    ...(chain.directFromCpfpRefundTx === undefined
      ? {}
      : { directFromCpfpRefundTx: copyBytes(chain.directFromCpfpRefundTx) }),
  };
}

/**
 * In-memory `SparkStore` — the default when no persistence is injected. Byte arrays are copied on
 * write and on read so callers can never alias stored state.
 */
export function createMemorySparkStore(): SparkStore {
  const chains = new Map<string, SparkExitChain>();
  return {
    exitChains: async () => {
      await Promise.resolve();
      return [...chains.values()].map((chain) => copyChain(chain));
    },
    putExitChains: async (put) => {
      for (const chain of put) {
        chains.set(chain.leafId, copyChain(chain));
      }
      await Promise.resolve();
    },
    deleteExitChains: async (leafIds) => {
      for (const leafId of leafIds) {
        chains.delete(leafId);
      }
      await Promise.resolve();
    },
  };
}
