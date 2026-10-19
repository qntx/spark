import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { HDKey } from "@scure/bip32";

import type { SparkNetwork } from "../core/network.ts";
import type { SparkCrypto } from "../crypto/index.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import { backendCall, SECRET_KEY_LENGTH, unreachable } from "./backend.ts";
import type { SparkKey, SparkLeafKey } from "./types.ts";

const HARDENED_OFFSET = 0x80_00_00_00;
const SPARK_PURPOSE = "m/8797555'";

const DEFAULT_ACCOUNT: Record<SparkNetwork, number> = {
  mainnet: 1,
  regtest: 0,
};

/**
 * The 64-byte extended private key (private key ‖ chain code) at `m/8797555'/account'` — the input
 * {@link createSparkSigner} expects. The default account matches the official SDK: mainnet 1,
 * regtest 0.
 */
export function sparkAccountKey(
  seed: Uint8Array,
  network: SparkNetwork,
  account?: number,
): Uint8Array {
  const resolvedAccount = account ?? DEFAULT_ACCOUNT[network];
  if (
    !Number.isSafeInteger(resolvedAccount) ||
    resolvedAccount < 0 ||
    resolvedAccount >= HARDENED_OFFSET
  ) {
    throw new SparkInputError("account: must be a non-negative safe integer below 2^31");
  }
  let master: HDKey;
  try {
    master = HDKey.fromMasterSeed(seed);
  } catch (error) {
    throw new SparkInputError("seed: invalid BIP-32 master seed", { cause: error });
  }
  const node = master.derive(`${SPARK_PURPOSE}/${resolvedAccount}'`);
  if (node.privateKey === null || node.chainCode === null) {
    throw new SparkInputError("seed: account derivation produced no private key");
  }
  const key = concatBytes(node.privateKey, node.chainCode);
  master.wipePrivateData();
  node.wipePrivateData();
  return key;
}

/**
 * The signer's derived private-key material: the `m/8797555'/a'` extended key expanded into the
 * identity (`0'`), signing (`1'`), deposit (`2'`) and static-deposit (`3'`) nodes. All references
 * held on this object are live private material — `resolve` hands out copies the caller wipes; the
 * identity fields must never be wiped by callers. `wipe` zeroizes everything.
 */
export type SignerKeys = {
  /** Identity private key — live reference; sign with it, never wipe it. */
  readonly identityPrivateKey: Uint8Array;
  /** Identity compressed public key. */
  readonly identityPublicKey: Uint8Array;
  readonly identityPoint: ReturnType<typeof secp256k1.Point.fromBytes>;
  /** The `m/8797555'/a'` private half — feeds the FROST nonce hedge. */
  readonly accountPrivate: Uint8Array;
  /** Resolves a key descriptor to a private-key copy the caller wipes after use. */
  readonly resolve: (key: SparkKey) => Uint8Array;
  /** The hardened `index` child of the static-deposit root — fresh derivation owned by the caller. */
  readonly staticDepositPrivateKey: (index: number) => Uint8Array;
  /** Compressed public keys for the given descriptors, in order. */
  readonly publicKeys: (keys: ReadonlyArray<SparkLeafKey>) => ReadonlyArray<Uint8Array>;
  /** Public keys of ECIES-sealed ("received") keys, decrypted with the identity key. */
  readonly receivedPublicKeys: (
    ciphertexts: ReadonlyArray<Uint8Array>,
  ) => ReadonlyArray<Uint8Array>;
  readonly wipe: () => void;
};

export function openKeys(accountKey: Uint8Array, crypto: SparkCrypto): SignerKeys {
  if (accountKey.length !== 64) {
    throw new SparkInputError("accountKey: must be 64 bytes (private key ‖ chain code)");
  }
  const privateHalf = accountKey.slice(0, SECRET_KEY_LENGTH);
  let root: HDKey;
  let identityNode: HDKey;
  let signingRoot: HDKey;
  let depositNode: HDKey;
  let staticRoot: HDKey;
  try {
    if (!secp256k1.utils.isValidSecretKey(privateHalf)) {
      throw new SparkInputError("accountKey: private key half is not a valid secp256k1 scalar");
    }
    // HDKey does not validate chain codes; a zero chain code still derives correctly.
    root = new HDKey({
      privateKey: privateHalf,
      chainCode: accountKey.slice(SECRET_KEY_LENGTH),
    });
    identityNode = root.deriveChild(HARDENED_OFFSET);
    signingRoot = root.deriveChild(HARDENED_OFFSET + 1);
    depositNode = root.deriveChild(HARDENED_OFFSET + 2);
    staticRoot = root.deriveChild(HARDENED_OFFSET + 3);
  } catch (error) {
    privateHalf.fill(0);
    throw error;
  }

  const identityPrivateKey = requiredPrivateKey(identityNode, "identity");
  const depositPrivateKey = requiredPrivateKey(depositNode, "deposit");
  const identityPublicKey = secp256k1.getPublicKey(identityPrivateKey, true);
  const identityPoint = secp256k1.Point.fromBytes(identityPublicKey);
  const leafKeyCache = new Map<string, Uint8Array>();

  function leafPrivateKey(leafId: string): Uint8Array {
    const cached = leafKeyCache.get(leafId);
    if (cached !== undefined) {
      return cached;
    }
    const hash = sha256(utf8ToBytes(leafId));
    const index =
      new DataView(hash.buffer, hash.byteOffset, hash.byteLength).getUint32(0, false) %
      HARDENED_OFFSET;
    const priv = requiredPrivateKey(signingRoot.deriveChild(HARDENED_OFFSET + index), "leaf key");
    leafKeyCache.set(leafId, priv);
    return priv;
  }

  function staticDepositPrivateKey(index: number): Uint8Array {
    if (!Number.isSafeInteger(index) || index < 0 || index >= HARDENED_OFFSET) {
      throw new SparkInputError("index: must be a non-negative safe integer below 2^31");
    }
    return requiredPrivateKey(
      staticRoot.deriveChild(HARDENED_OFFSET + index),
      "static deposit key",
    );
  }

  function decryptReceivedKey(ciphertext: Uint8Array): Uint8Array {
    const plain = backendCall(() => crypto.eciesDecrypt(identityPrivateKey, ciphertext));
    if (plain.length !== SECRET_KEY_LENGTH || !secp256k1.utils.isValidSecretKey(plain)) {
      plain.fill(0);
      throw new SparkError(
        "received key: decrypted payload is not a 32-byte secp256k1 private key",
      );
    }
    return plain;
  }

  /** Resolves a key descriptor to a private-key copy the caller wipes after use. */
  function resolve(key: SparkKey): Uint8Array {
    if (key.type === "identity") {
      return new Uint8Array(identityPrivateKey);
    }
    if (key.type === "leaf") {
      return new Uint8Array(leafPrivateKey(key.leafId));
    }
    if (key.type === "deposit") {
      return new Uint8Array(depositPrivateKey);
    }
    if (key.type === "static-deposit") {
      // Fresh derivation each call — the returned reference is owned by the caller.
      return staticDepositPrivateKey(key.index);
    }
    if (key.type === "received") {
      return decryptReceivedKey(key.ciphertext);
    }
    return unreachable("unexpected key type");
  }

  return {
    identityPrivateKey,
    identityPublicKey,
    identityPoint,
    accountPrivate: privateHalf,
    resolve,
    staticDepositPrivateKey,
    publicKeys(descriptors) {
      return descriptors.map((descriptor) => {
        const priv = resolve(descriptor);
        try {
          return secp256k1.getPublicKey(priv, true);
        } finally {
          priv.fill(0);
        }
      });
    },
    receivedPublicKeys(ciphertexts) {
      return ciphertexts.map((ciphertext) => {
        const priv = decryptReceivedKey(ciphertext);
        try {
          return secp256k1.getPublicKey(priv, true);
        } finally {
          priv.fill(0);
        }
      });
    },
    wipe() {
      for (const priv of leafKeyCache.values()) {
        priv.fill(0);
      }
      leafKeyCache.clear();
      privateHalf.fill(0);
      staticRoot.wipePrivateData();
      depositNode.wipePrivateData();
      signingRoot.wipePrivateData();
      identityNode.wipePrivateData();
      root.wipePrivateData();
    },
  };
}

function requiredPrivateKey(node: HDKey, name: string): Uint8Array {
  if (node.privateKey === null) {
    throw new SparkError(`${name}: derivation produced no private key`);
  }
  return node.privateKey;
}
