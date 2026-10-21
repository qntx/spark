import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { HDKey } from "@scure/bip32";

import { SparkError, SparkInputError } from "../errors/index.ts";
import { ready } from "./backend.ts";
import { ecdsaSign } from "./statements.ts";

// LUD-05 (lnurl/luds 05.md): a `hashingKey` at m/138'/0 HMAC-SHA256s the
// service's full domain name; the first 16 bytes of the MAC become four
// big-endian u32 path elements and the service-specific linkingKey is
// m/138'/<l1>/<l2>/<l3>/<l4>. Elements >= 2^31 derive hardened children,
// matching rust-bitcoin's ChildNumber::from(u32).
// Upstream reference: breez-spark-sdk crates/breez-sdk/common/src/lnurl/
// auth.rs (get_derivation_path) @956ff90.

const PURPOSE_138 = "m/138'";
const HOST_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const SECRET_KEY_LENGTH = 32;

function pathElement(mac: Uint8Array, offset: number): number {
  return new DataView(mac.buffer, mac.byteOffset, mac.byteLength).getUint32(offset);
}

function checkDomain(domain: string): void {
  if (domain !== domain.toLowerCase()) {
    throw new SparkInputError("lnurl-auth domain: must be lowercase");
  }
  if (domain.length === 0 || domain.length > 253) {
    throw new SparkInputError("lnurl-auth domain: invalid hostname length");
  }
  for (const label of domain.split(".")) {
    if (!HOST_LABEL.test(label)) {
      throw new SparkInputError("lnurl-auth domain: invalid hostname label");
    }
  }
}

function wipeNodes(nodes: ReadonlyArray<HDKey>): void {
  for (const node of nodes) {
    node.wipePrivateData();
  }
}

function leafKeyOf(nodes: ReadonlyArray<HDKey>): Uint8Array {
  const leaf = nodes.at(-1);
  if (leaf === undefined || leaf.privateKey === null) {
    throw new SparkError("lnurl-auth: linking-key derivation produced no private key");
  }
  return leaf.privateKey;
}

/**
 * The 64-byte extended private key (private key ‖ chain code) at `m/138'` — the input
 * {@link createLnurlAuthSigner} expects. The caller wipes the result when it is done holding the
 * material.
 */
export function lnurlAuthRootKey(seed: Uint8Array): Uint8Array {
  let master: HDKey;
  try {
    master = HDKey.fromMasterSeed(seed);
  } catch (error) {
    throw new SparkInputError("seed: invalid BIP-32 master seed", { cause: error });
  }
  const node = master.derive(PURPOSE_138);
  if (node.privateKey === null || node.chainCode === null) {
    throw new SparkInputError("seed: linking-key derivation produced no private key");
  }
  const key = concatBytes(node.privateKey, node.chainCode);
  master.wipePrivateData();
  node.wipePrivateData();
  return key;
}

/**
 * A signer that derives LUD-05 domain-specific linking keys and signs LUD-04 `k1` challenges with
 * them. `domain` must already be lowercase — the LNURL layer lowercases the host when parsing; an
 * uppercase input here means the caller skipped that step.
 */
export type LnurlAuthSigner = {
  /** Compressed linking public key for `domain` (lowercase host). */
  readonly linkingKey: (domain: string) => Promise<Uint8Array>;
  /** DER ECDSA over the raw 32-byte k1 with the domain's linking key. */
  readonly sign: (request: {
    readonly domain: string;
    readonly k1: Uint8Array;
  }) => Promise<{ readonly linkingKey: Uint8Array; readonly signature: Uint8Array }>;
  /** Wipes the root key and cached material; later calls reject. */
  readonly dispose: () => void;
};

/** Creates the signer from a `m/138'` extended private key produced by {@link lnurlAuthRootKey}. */
export function createLnurlAuthSigner(options: { readonly rootKey: Uint8Array }): LnurlAuthSigner {
  if (options.rootKey.length !== 64) {
    throw new SparkInputError("rootKey: must be 64 bytes (private key ‖ chain code)");
  }
  const privateHalf = options.rootKey.slice(0, SECRET_KEY_LENGTH);
  let root: HDKey;
  try {
    if (!secp256k1.utils.isValidSecretKey(privateHalf)) {
      throw new SparkInputError("rootKey: private key half is not a valid secp256k1 scalar");
    }
    root = new HDKey({
      privateKey: privateHalf,
      chainCode: options.rootKey.slice(SECRET_KEY_LENGTH),
    });
  } catch (error) {
    privateHalf.fill(0);
    throw error;
  }

  let disposed = false;

  function ensureAlive(): void {
    if (disposed) {
      throw new SparkError("lnurl-auth signer: disposed");
    }
  }

  // Derives m/138'/l1/l2/l3/l4 for the domain, returning every intermediate
  // node so the caller can wipe them all.
  function linkingNodes(domain: string): HDKey[] {
    checkDomain(domain);
    const hashing = root.deriveChild(0);
    const nodes: HDKey[] = [hashing];
    try {
      const hashingPrivate = hashing.privateKey;
      if (hashingPrivate === null) {
        throw new SparkInputError("lnurl-auth: hashing-key derivation produced no private key");
      }
      const mac = hmac(sha256, hashingPrivate, utf8ToBytes(domain));
      let node = root;
      try {
        for (let i = 0; i < 4; i += 1) {
          node = node.deriveChild(pathElement(mac, i * 4));
          nodes.push(node);
        }
        return nodes;
      } finally {
        mac.fill(0);
      }
    } catch (error) {
      wipeNodes(nodes);
      throw error;
    }
  }

  const linkingKey = async (domain: string): Promise<Uint8Array> => {
    ensureAlive();
    await ready;
    const nodes = linkingNodes(domain);
    try {
      return secp256k1.getPublicKey(leafKeyOf(nodes), true);
    } finally {
      wipeNodes(nodes);
    }
  };

  const sign = async (request: {
    readonly domain: string;
    readonly k1: Uint8Array;
  }): Promise<{ readonly linkingKey: Uint8Array; readonly signature: Uint8Array }> => {
    ensureAlive();
    await ready;
    if (request.k1.length !== 32) {
      throw new SparkInputError("lnurl-auth k1: must be 32 bytes");
    }
    const nodes = linkingNodes(request.domain);
    try {
      const privateKey = leafKeyOf(nodes);
      return {
        linkingKey: secp256k1.getPublicKey(privateKey, true),
        signature: ecdsaSign(request.k1, privateKey, "der"),
      };
    } finally {
      wipeNodes(nodes);
    }
  };

  const dispose = (): void => {
    if (disposed) {
      return;
    }
    disposed = true;
    root.wipePrivateData();
    privateHalf.fill(0);
  };

  return { linkingKey, sign, dispose };
}
