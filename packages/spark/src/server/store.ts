// Storage for the Lightning Address server: registered names, spent signed
// statements (replay protection), and issued invoices awaiting settlement.

export type LightningAddressUser = {
  /** Lowercase LUD-16 local-part. */
  readonly name: string;
  /** The owner's compressed secp256k1 identity public key, lowercase hex. */
  readonly pubkeyHex: string;
  /** The registration description — verbatim into the payRequest `text/plain` metadata. */
  readonly description: string;
};

export type LightningAddressInvoice = {
  /** Lowercase hex payment hash of the BOLT-11 invoice. */
  readonly paymentHash: string;
  /** The SSP lightning-receive request id — the settlement status is polled through it. */
  readonly requestId: string;
  /** The registered name the invoice was issued to. */
  readonly name: string;
  /** The payee's compressed identity public key, lowercase hex. */
  readonly pubkeyHex: string;
  /** The encoded BOLT-11 invoice handed to the payer. */
  readonly invoice: string;
  readonly expiresAtMs: number;
  /** The raw zap-request event JSON (NIP-57), when the payer sent one. */
  readonly zapRequest?: string;
  readonly comment?: string;
  /** Lowercase hex settled preimage — present only once settled. */
  readonly preimageHex?: string;
};

/**
 * The persistence the server handlers need. A pubkey holds at most one name: registering a new name
 * releases the old one.
 */
export type LightningAddressStore = {
  readonly userByName: (name: string) => Promise<LightningAddressUser | undefined>;
  readonly userByPublicKey: (pubkeyHex: string) => Promise<LightningAddressUser | undefined>;
  /**
   * Registers `user.name` for `user.pubkeyHex`. Returns `false` when another pubkey already holds
   * the name; otherwise removes the pubkey's previous name and stores the record.
   */
  readonly putUser: (user: LightningAddressUser) => Promise<boolean>;
  /** Removes the name only when it is still held by `pubkeyHex`. */
  readonly deleteUser: (pubkeyHex: string, name: string) => Promise<boolean>;
  /**
   * Claims a signed statement for replay protection: `false` when the hash was already claimed,
   * else records it with `expiresAtMs` (after which the record may be dropped) and returns `true`.
   */
  readonly claimStatement: (hashHex: string, expiresAtMs: number) => Promise<boolean>;
  readonly putInvoice: (invoice: LightningAddressInvoice) => Promise<void>;
  readonly invoiceByPaymentHash: (hashHex: string) => Promise<LightningAddressInvoice | undefined>;
  /** Unsettled invoices whose expiry has not passed at `nowMs`. */
  readonly pendingInvoices: (nowMs: number) => Promise<ReadonlyArray<LightningAddressInvoice>>;
  readonly settleInvoice: (
    hashHex: string,
    preimageHex: string,
  ) => Promise<LightningAddressInvoice | undefined>;
};

/** In-memory {@link LightningAddressStore} — a reference implementation and the test store. */
export function createMemoryLightningAddressStore(): LightningAddressStore {
  const byName = new Map<string, LightningAddressUser>();
  const byPubkey = new Map<string, LightningAddressUser>();
  const claimed = new Map<string, number>();
  const invoices = new Map<string, LightningAddressInvoice>();
  return {
    userByName: async (name) => {
      await Promise.resolve();
      return byName.get(name);
    },
    userByPublicKey: async (pubkeyHex) => {
      await Promise.resolve();
      return byPubkey.get(pubkeyHex);
    },
    putUser: async (user) => {
      await Promise.resolve();
      const holder = byName.get(user.name);
      if (holder !== undefined && holder.pubkeyHex !== user.pubkeyHex) {
        return false;
      }
      const previous = byPubkey.get(user.pubkeyHex);
      if (previous !== undefined && previous.name !== user.name) {
        byName.delete(previous.name);
      }
      byName.set(user.name, user);
      byPubkey.set(user.pubkeyHex, user);
      return true;
    },
    deleteUser: async (pubkeyHex, name) => {
      await Promise.resolve();
      const held = byName.get(name);
      if (held === undefined || held.pubkeyHex !== pubkeyHex) {
        return false;
      }
      byName.delete(name);
      byPubkey.delete(pubkeyHex);
      return true;
    },
    claimStatement: async (hashHex, expiresAtMs) => {
      await Promise.resolve();
      if (claimed.has(hashHex)) {
        return false;
      }
      claimed.set(hashHex, expiresAtMs);
      return true;
    },
    putInvoice: async (invoice) => {
      await Promise.resolve();
      invoices.set(invoice.paymentHash, invoice);
    },
    invoiceByPaymentHash: async (hashHex) => {
      await Promise.resolve();
      return invoices.get(hashHex);
    },
    pendingInvoices: async (nowMs) => {
      await Promise.resolve();
      return [...invoices.values()].filter(
        (invoice) => invoice.preimageHex === undefined && invoice.expiresAtMs > nowMs,
      );
    },
    settleInvoice: async (hashHex, preimageHex) => {
      await Promise.resolve();
      const invoice = invoices.get(hashHex);
      if (invoice === undefined) {
        return undefined;
      }
      const settled = { ...invoice, preimageHex };
      invoices.set(hashHex, settled);
      return settled;
    },
  };
}
