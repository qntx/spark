import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bech32 } from "@scure/base";

import { SparkInputError } from "../errors/index.ts";

// BOLT #11 invoice decoding. Reference: lightning/bolts 11-payment-encoding.md
// @ 1aadb719. Bech32 (not bech32m) with the BIP-0173 length limit removed; the
// data part is timestamp + tagged fields + a 65-byte recoverable signature.

export type Bolt11Network = "mainnet" | "regtest" | "testnet" | "signet";

export type Bolt11RouteHintHop = {
  /** 33-byte compressed public key of the node starting the channel. */
  readonly publicKey: Uint8Array;
  /** 8-byte short channel id. */
  readonly shortChannelId: Uint8Array;
  readonly feeBaseMsat: number;
  readonly feeProportionalMillionths: number;
  readonly cltvExpiryDelta: number;
};

/** Raw `f` field: witness versions 0–16, 17 = P2PKH, 18 = P2SH. */
export type Bolt11FallbackAddress = {
  readonly version: number;
  readonly program: Uint8Array;
};

export type Bolt11Invoice = {
  readonly network: Bolt11Network;
  /** Amount in millisatoshis; absent for "any amount" invoices. */
  readonly amountMsat?: bigint | undefined;
  /** Seconds since the unix epoch. */
  readonly timestamp: number;
  readonly paymentHash: Uint8Array;
  readonly paymentSecret: Uint8Array;
  readonly description?: string | undefined;
  readonly descriptionHash?: Uint8Array | undefined;
  readonly expirySeconds: number;
  readonly minFinalCltvExpiry: number;
  /** 33-byte payee public key: verified `n` field, or recovered from the signature. */
  readonly payee: Uint8Array;
  /** Raw big-endian feature bitfield of the `9` field. */
  readonly features?: Uint8Array | undefined;
  /** One entry per `r` field; each is an ordered list of private-route hops. */
  readonly routeHints: ReadonlyArray<ReadonlyArray<Bolt11RouteHintHop>>;
  readonly fallbackAddresses: ReadonlyArray<Bolt11FallbackAddress>;
  /** Raw `m` field. */
  readonly metadata?: Uint8Array | undefined;
};

const TAG_PAYMENT_HASH = 1;
const TAG_ROUTE_HINT = 3;
const TAG_FEATURES = 5;
const TAG_EXPIRY = 6;
const TAG_FALLBACK = 9;
const TAG_DESCRIPTION = 13;
const TAG_PAYMENT_SECRET = 16;
const TAG_PAYEE = 19;
const TAG_DESCRIPTION_HASH = 23;
const TAG_MIN_FINAL_CLTV = 24;
const TAG_METADATA = 27;

const TIMESTAMP_WORDS = 7;
const SIGNATURE_WORDS = 104;
const HASH_WORDS = 52; // 32 bytes + 4 padding bits
const PAYEE_WORDS = 53; // 33 bytes
const ROUTE_HOP_WORDS = 82; // 51 bytes

const DEFAULT_EXPIRY_SECONDS = 3600;
const DEFAULT_MIN_FINAL_CLTV = 18;

const NETWORK_PREFIX: Record<string, Bolt11Network> = {
  bc: "mainnet",
  bcrt: "regtest",
  tb: "testnet",
  tbs: "signet",
};

// Even feature bits assigned by BOLT #9. An unknown set even bit requires the
// reader to fail the payment ("it's ok to be odd").
const KNOWN_EVEN_FEATURES = new Set([
  0, 4, 6, 8, 10, 12, 14, 16, 18, 22, 24, 26, 28, 34, 36, 38, 40, 42, 44, 46, 48, 50, 60, 62, 66,
]);

function fail(message: string): never {
  throw new SparkInputError(`invoice: ${message}`);
}

/** 5-bit words → bytes, big-endian, dropping the incomplete trailing group. */
function wordsToBytes(words: ReadonlyArray<number>): Uint8Array {
  return wordsToBytesImpl(words, false);
}

/** 5-bit words → bytes, big-endian, zero-padding the last partial byte. */
function wordsToBytesPadded(words: ReadonlyArray<number>): Uint8Array {
  return wordsToBytesImpl(words, true);
}

function wordsToBytesImpl(words: ReadonlyArray<number>, pad: boolean): Uint8Array {
  const total = pad ? Math.ceil((words.length * 5) / 8) : Math.floor((words.length * 5) / 8);
  const out = new Uint8Array(total);
  let acc = 0;
  let bits = 0;
  let index = 0;
  for (const word of words) {
    acc = ((acc << 5) | word) & 0xffffffff;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out[index] = (acc >>> bits) & 0xff;
      index++;
    }
    acc &= (1 << bits) - 1;
  }
  if (pad && bits > 0) {
    out[index] = (acc << (8 - bits)) & 0xff;
  }
  return out;
}

function wordsToInt(words: ReadonlyArray<number>): number {
  let value = 0;
  for (const word of words) {
    value = value * 32 + word;
    if (value > Number.MAX_SAFE_INTEGER) {
      fail("integer field overflows a safe integer");
    }
  }
  return value;
}

/** Feature bit `n` of a big-endian bitfield expressed as 5-bit words (bit 0 = LSB). */
function hasFeatureBit(words: ReadonlyArray<number>, bit: number): boolean {
  const index = words.length - 1 - Math.floor(bit / 5);
  const word = index < 0 ? undefined : words[index];
  if (word === undefined) {
    return false;
  }
  return ((word >>> (bit % 5)) & 1) === 1;
}

function maxFeatureBit(words: ReadonlyArray<number>): number {
  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    if (word === undefined || word === 0) {
      continue;
    }
    const fromEnd = words.length - 1 - i;
    let highest = 4;
    while (highest > 0 && ((word >>> highest) & 1) === 0) {
      highest--;
    }
    return fromEnd * 5 + highest;
  }
  return -1;
}

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

function parseAmount(hrpAmount: string): bigint | undefined {
  if (hrpAmount === "") {
    return undefined;
  }
  const match = /^([0-9]+)([munp]?)$/.exec(hrpAmount);
  if (match === null) {
    fail("amount: not a decimal integer with optional m/u/n/p multiplier");
  }
  const digits = match[1] ?? "";
  const multiplier = match[2] ?? "";
  if (digits.length > 1 && digits.startsWith("0")) {
    fail("amount: leading zeros are not allowed");
  }
  const value = BigInt(digits);
  switch (multiplier) {
    case "":
      return value * 100_000_000_000n;
    case "m":
      return value * 100_000_000n;
    case "u":
      return value * 100_000n;
    case "n":
      return value * 100n;
    case "p":
      if (value % 10n !== 0n) {
        fail("amount: pico-BTC value must be a multiple of 10 (whole millisatoshis)");
      }
      return value / 10n;
    default:
      return fail("amount: invalid multiplier");
  }
}

function parseRouteHint(words: ReadonlyArray<number>): Bolt11RouteHintHop[] {
  if (words.length === 0 || words.length % ROUTE_HOP_WORDS !== 0) {
    fail("route hint: data is not a multiple of the 51-byte entry size");
  }
  const hops: Bolt11RouteHintHop[] = [];
  for (let offset = 0; offset < words.length; offset += ROUTE_HOP_WORDS) {
    const entry = wordsToBytes(words.slice(offset, offset + ROUTE_HOP_WORDS));
    hops.push({
      publicKey: entry.slice(0, 33),
      shortChannelId: entry.slice(33, 41),
      feeBaseMsat: new DataView(entry.buffer, entry.byteOffset + 41, 8).getUint32(0),
      feeProportionalMillionths: new DataView(entry.buffer, entry.byteOffset + 41, 8).getUint32(4),
      cltvExpiryDelta: new DataView(entry.buffer, entry.byteOffset + 49, 2).getUint16(0),
    });
  }
  return hops;
}

/**
 * Decodes a BOLT-11 payment request. Throws {@link SparkInputError} on malformed input: bad bech32,
 * unknown prefix, bad amount, missing required fields, unknown even feature bits, or a signature
 * that fails verification/recovery.
 */
export function decodeBolt11(invoice: string): Bolt11Invoice {
  if (/[a-z]/.test(invoice) && /[A-Z]/.test(invoice)) {
    fail("mixed case");
  }
  let decoded;
  try {
    decoded = bech32.decode(invoice.toLowerCase(), false);
  } catch (error) {
    throw new SparkInputError("invoice: invalid bech32", { cause: error });
  }
  const { prefix: hrp, words } = decoded;
  if (!hrp.startsWith("ln")) {
    fail("prefix: expected 'ln'");
  }
  const letters = /^[a-z]+/.exec(hrp.slice(2))?.[0];
  const network = letters === undefined ? undefined : NETWORK_PREFIX[letters];
  if (network === undefined) {
    fail("prefix: unknown currency code");
  }
  const amountMsat = parseAmount(hrp.slice(2 + (letters?.length ?? 0)));

  const taggedEnd = words.length - SIGNATURE_WORDS;
  if (taggedEnd < TIMESTAMP_WORDS) {
    fail("too short");
  }
  const timestamp = wordsToInt(words.slice(0, TIMESTAMP_WORDS));

  let paymentHash: Uint8Array | undefined;
  let paymentSecret: Uint8Array | undefined;
  let description: string | undefined;
  let descriptionHash: Uint8Array | undefined;
  let payeeNode: Uint8Array | undefined;
  let expirySeconds = DEFAULT_EXPIRY_SECONDS;
  let minFinalCltvExpiry = DEFAULT_MIN_FINAL_CLTV;
  let featuresWords: ReadonlyArray<number> | undefined;
  const routeHints: Array<ReadonlyArray<Bolt11RouteHintHop>> = [];
  const fallbackAddresses: Bolt11FallbackAddress[] = [];
  let metadata: Uint8Array | undefined;

  for (let i = TIMESTAMP_WORDS; i < taggedEnd;) {
    if (i + 3 > taggedEnd) {
      fail("tagged field: truncated header");
    }
    const tag = words[i];
    const lengthHi = words[i + 1];
    const lengthLo = words[i + 2];
    if (tag === undefined || lengthHi === undefined || lengthLo === undefined) {
      fail("tagged field: truncated header");
    }
    const length = lengthHi * 32 + lengthLo;
    const field = words.slice(i + 3, i + 3 + length);
    if (field.length !== length || i + 3 + length > taggedEnd) {
      fail("tagged field: data overruns the signature");
    }
    switch (tag) {
      case TAG_PAYMENT_HASH:
      case TAG_PAYMENT_SECRET:
      case TAG_DESCRIPTION_HASH:
      case TAG_PAYEE: {
        const expected = tag === TAG_PAYEE ? PAYEE_WORDS : HASH_WORDS;
        // Fixed-length fields with a wrong length are skipped (the spec's own
        // "fields which must be ignored" invoice carries such duplicates); the
        // first field with the correct length wins.
        if (field.length !== expected) {
          break;
        }
        const value = wordsToBytes(field);
        if (tag === TAG_PAYMENT_HASH && paymentHash === undefined) {
          paymentHash = value;
        } else if (tag === TAG_PAYMENT_SECRET && paymentSecret === undefined) {
          paymentSecret = value;
        } else if (tag === TAG_DESCRIPTION_HASH && descriptionHash === undefined) {
          descriptionHash = value;
        } else if (tag === TAG_PAYEE && payeeNode === undefined) {
          payeeNode = value;
        }
        break;
      }
      case TAG_DESCRIPTION:
        try {
          description ??= UTF8_DECODER.decode(wordsToBytes(field));
        } catch (error) {
          throw new SparkInputError("invoice: description: invalid UTF-8", { cause: error });
        }
        break;
      case TAG_EXPIRY:
        if (field[0] === 0) {
          fail("expiry: non-minimal data_length");
        }
        expirySeconds = wordsToInt(field);
        break;
      case TAG_MIN_FINAL_CLTV:
        if (field[0] === 0) {
          fail("min_final_cltv_expiry: non-minimal data_length");
        }
        minFinalCltvExpiry = wordsToInt(field);
        break;
      case TAG_FEATURES:
        if (field[0] === 0) {
          fail("features: non-minimal data_length");
        }
        featuresWords = field;
        break;
      case TAG_FALLBACK: {
        if (field.length === 0) {
          fail("fallback: missing version");
        }
        const version = field[0] ?? 0;
        // Unknown versions (19–31) are skipped; 0–16 witness, 17 P2PKH, 18 P2SH.
        if (version <= 18) {
          fallbackAddresses.push({ version, program: wordsToBytes(field.slice(1)) });
        }
        break;
      }
      case TAG_ROUTE_HINT:
        routeHints.push(parseRouteHint(field));
        break;
      case TAG_METADATA:
        metadata ??= wordsToBytes(field);
        break;
      default:
        break; // unknown tags are ignored
    }
    i += 3 + length;
  }

  if (paymentHash === undefined) {
    fail("missing payment hash (p)");
  }
  if (paymentSecret === undefined) {
    fail("missing payment secret (s)");
  }
  if (description === undefined && descriptionHash === undefined) {
    fail("missing description (d) and description hash (h)");
  }
  if (description !== undefined && descriptionHash !== undefined) {
    fail("both description (d) and description hash (h) present");
  }
  if (featuresWords !== undefined) {
    const top = maxFeatureBit(featuresWords);
    for (let bit = 0; bit <= top; bit += 2) {
      if (!KNOWN_EVEN_FEATURES.has(bit) && hasFeatureBit(featuresWords, bit)) {
        fail(`features: unknown required feature bit ${bit}`);
      }
    }
  }

  const signature = wordsToBytes(words.slice(taggedEnd));
  const compact = signature.slice(0, 64);
  const [recoveryId] = signature.subarray(64, 65);
  if (recoveryId === undefined || recoveryId > 3) {
    fail("signature: recovery id must be 0..3");
  }

  // The signed preimage is the UTF-8 HRP plus the data words before the
  // signature, 5→8-bit packed with zero padding to the byte boundary.
  const preimage = new Uint8Array(hrp.length + Math.ceil((taggedEnd * 5) / 8));
  for (let i = 0; i < hrp.length; i++) {
    preimage[i] = hrp.codePointAt(i) ?? 0;
  }
  preimage.set(wordsToBytesPadded(words.slice(0, taggedEnd)), hrp.length);
  const messageHash = sha256(preimage);

  let payee: Uint8Array;
  if (payeeNode !== undefined && isValidPoint(payeeNode)) {
    // With a valid `n` field the signature is verified (low-S required); no recovery.
    let ok: boolean;
    try {
      ok = secp256k1.verify(compact, messageHash, payeeNode, { prehash: false, lowS: true });
    } catch {
      ok = false;
    }
    if (!ok) {
      fail("signature: does not verify against the n field");
    }
    payee = payeeNode;
  } else {
    // Otherwise (no n field, or an invalid one) recover the payee; high-S is
    // accepted in the recovery path per BOLT-11.
    // noble's "recovered" format is recovery-byte first; BOLT-11 appends it last.
    const recoverable = new Uint8Array(65);
    recoverable[0] = recoveryId;
    recoverable.set(compact, 1);
    try {
      payee = secp256k1.recoverPublicKey(recoverable, messageHash, { prehash: false });
    } catch (error) {
      throw new SparkInputError("invoice: signature is not recoverable", { cause: error });
    }
    if (payee.length !== 33) {
      payee = secp256k1.Point.fromBytes(payee).toBytes(true);
    }
  }

  return {
    network,
    amountMsat,
    timestamp,
    paymentHash,
    paymentSecret,
    description,
    descriptionHash,
    expirySeconds,
    minFinalCltvExpiry,
    payee,
    features: featuresWords === undefined ? undefined : wordsToBytes(featuresWords),
    routeHints,
    fallbackAddresses,
    metadata,
  };
}

function isValidPoint(bytes: Uint8Array): boolean {
  try {
    secp256k1.Point.fromBytes(bytes);
    return true;
  } catch {
    return false;
  }
}

/** True once `timestamp + expirySeconds` has passed at `nowMs` (unix milliseconds). */
export function isExpired(invoice: Bolt11Invoice, nowMs: number): boolean {
  return nowMs > (invoice.timestamp + invoice.expirySeconds) * 1000;
}
