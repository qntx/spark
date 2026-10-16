import { expand_message_xmd } from "@noble/curves/abstract/hash-to-curve.js";
import { mod } from "@noble/curves/abstract/modular.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

/**
 * Test-side implementation of the operator role of FROST(secp256k1, SHA-256) in the taproot variant
 * (`frost-secp256k1-tr` @ lightsparkdev/frost 997427e): produces signature shares that
 * `qs_frost_aggregate` accepts, so tests can drive a full sign → aggregate round trip through the
 * signer without a dealer. The user role always signs via the real signer/backend.
 *
 * Mirrored protocol details (spark-crypto `frost.rs` + the fork's `round2`/`aggregate` paths):
 *
 * - The "user" identifier is `HID("user")` (XMD-SHA256 expand-to-scalar, DST = context ‖ "id");
 * - Identifiers serialize as 32-byte big-endian scalars and order numerically;
 * - The key package is taproot-tweaked with an empty merkle root: every participant signs under
 *   `vk_tweaked = even(vk) + t·G` with `t = TapTweak(xonly(even(vk)))`, and each operator's share
 *   embeds the tweak via `λ_i·(s_i + t)·c` (the user's share carries no tweak term — it is composed
 *   in the backend exactly like the upstream role == USER path);
 * - Signing shares are even-Y normalized twice: once against the untweaked combined key, then by
 *   `pre_sign`/`pre_aggregate` against the tweaked key;
 * - Binding factor `ρ_i = H1(vk_tw_even33 ‖ H4(msg) ‖ H5(commitmentList) ‖ id_i)` where the verifying
 *   key in the prefix is the even-Y-normalized tweaked key;
 * - The challenge is the tagged BIP0340/challenge hash over `R.x ‖ vk_tweaked.x ‖ message`;
 * - When the raw group commitment R is odd-Y, every participant negates its nonce contribution;
 * - Lagrange coefficients are computed within each signer's own participant group: the user is a
 *   singleton group (λ = 1), operators interpolate over the operator identifier set.
 */

const CONTEXT: Uint8Array = utf8ToBytes("FROST-secp256k1-SHA256-TR-v1");
const Fn: typeof secp256k1.Point.Fn = secp256k1.Point.Fn;
const Point: typeof secp256k1.Point = secp256k1.Point;
const ORDER: bigint = Fn.ORDER;
const USER_ID_SCALAR: bigint = xmdScalar("id", utf8ToBytes("user"));

export type FrostTestOperator = {
  /** Nonzero identifier scalar. */
  readonly id: bigint;
  /** The operator's FROST secret share. */
  readonly secret: bigint;
  /** Hiding and binding nonce scalars for this signing session. */
  readonly hidingNonce: bigint;
  readonly bindingNonce: bigint;
};

export const be32 = (x: bigint): Uint8Array => Fn.toBytes(Fn.create(mod(x, ORDER)));

function xmdScalar(tag: string, msg: Uint8Array): bigint {
  const okm = expand_message_xmd(msg, concatBytes(CONTEXT, utf8ToBytes(tag)), 48, sha256);
  return mod(bytesToNumberBE(okm), ORDER);
}

function h4(msg: Uint8Array): Uint8Array {
  return sha256(concatBytes(CONTEXT, utf8ToBytes("msg"), msg));
}

function h5(msg: Uint8Array): Uint8Array {
  return sha256(concatBytes(CONTEXT, utf8ToBytes("com"), msg));
}

const CHALLENGE_TAG_HASH = sha256(utf8ToBytes("BIP0340/challenge"));
const TAPTWEAK_TAG_HASH = sha256(utf8ToBytes("TapTweak"));

function challengeScalar(msg: Uint8Array): bigint {
  return mod(
    bytesToNumberBE(sha256(concatBytes(CHALLENGE_TAG_HASH, CHALLENGE_TAG_HASH, msg))),
    ORDER,
  );
}

const evenY = (point: typeof Point.ZERO): typeof Point.ZERO =>
  (point.toAffine().y & 1n) === 0n ? point : point.negate();

/** The BIP-341 taproot tweak of `even(vk)` with an empty merkle root, and the tweaked key. */
export function taprootTweakedKey(verifyingKey: Uint8Array): {
  readonly tweak: bigint;
  readonly point: typeof Point.ZERO;
} {
  const base = evenY(Point.fromBytes(verifyingKey));
  const tweak = mod(
    bytesToNumberBE(
      sha256(concatBytes(TAPTWEAK_TAG_HASH, TAPTWEAK_TAG_HASH, be32(base.toAffine().x))),
    ),
    ORDER,
  );
  return { tweak, point: base.add(Point.BASE.multiply(tweak)) };
}

/** The 64-hex identifier string of the built-in "user" FROST participant. */
export function userIdentifier(): string {
  return bytesToHex(be32(USER_ID_SCALAR));
}

/** FROST Lagrange coefficient of `xi` evaluated at 0 over `xs`. */
export function lagrangeCoefficient(xi: bigint, xs: ReadonlyArray<bigint>): bigint {
  let num = 1n;
  let den = 1n;
  for (const xj of xs) {
    if (xj === xi) {
      continue;
    }
    num = Fn.mul(num, xj);
    den = Fn.mul(den, xj - xi);
  }
  return Fn.mul(num, Fn.inv(den));
}

/** The group verifying key (33-byte compressed) for `userSecret` and `operators`, even-y. */
export function frostVerifyingKey(
  userSecret: bigint,
  operators: ReadonlyArray<FrostTestOperator>,
): Uint8Array {
  const xs = operators.map((o) => o.id);
  let key = Point.BASE.multiply(mod(userSecret, ORDER));
  for (const operator of operators) {
    key = key.add(
      Point.BASE.multiply(
        mod(lagrangeCoefficient(operator.id, xs) * mod(operator.secret, ORDER), ORDER),
      ),
    );
  }
  if ((key.toAffine().y & 1n) !== 0n) {
    throw new Error("frostVerifyingKey: resample operator secrets — the combined key is odd-y");
  }
  return key.toBytes(true);
}

/**
 * Builds a complete simulated operator group for `userSecret`, bumping the last operator's secret
 * share until the combined verifying key is even-Y (the coordinator-side normalization the
 * ciphersuite applies makes odd-Y fixtures unusable).
 */
export function frostGroup(
  userSecret: bigint,
  secrets: ReadonlyArray<bigint>,
  nonces: ReadonlyArray<readonly [bigint, bigint]>,
): { operators: FrostTestOperator[]; verifyingKey: Uint8Array } {
  for (let bump = 0n; ; bump++) {
    const operators = secrets.map((secret, i) => {
      const noncePair = nonces[i];
      if (noncePair === undefined) {
        throw new Error("frostGroup: missing nonce pair");
      }
      return {
        id: BigInt(i + 1),
        secret: i === secrets.length - 1 ? secret + bump : secret,
        hidingNonce: noncePair[0],
        bindingNonce: noncePair[1],
      };
    });
    try {
      return { operators, verifyingKey: frostVerifyingKey(userSecret, operators) };
    } catch {
      // odd-Y combined key — bump the last share and retry
    }
  }
}

export type FrostOperatorFixture = {
  readonly identifier: string;
  readonly commitment: { readonly hiding: Uint8Array; readonly binding: Uint8Array };
  readonly publicKey: Uint8Array;
};

/** Commitments and verifying shares for the simulated operators. */
export function operatorSetup(operators: ReadonlyArray<FrostTestOperator>): FrostOperatorFixture[] {
  return operators.map((operator) => ({
    identifier: bytesToHex(be32(operator.id)),
    commitment: {
      hiding: Point.BASE.multiply(mod(operator.hidingNonce, ORDER)).toBytes(true),
      binding: Point.BASE.multiply(mod(operator.bindingNonce, ORDER)).toBytes(true),
    },
    publicKey: Point.BASE.multiply(mod(operator.secret, ORDER)).toBytes(true),
  }));
}

/**
 * Computes every simulated operator's signature share for `message`, given the user's commitment
 * produced by `newCommitments`. Returns 32-byte shares aligned with `operators`.
 */
export function operatorSignatureShares({
  operators,
  verifyingKey,
  userCommitment,
  message,
}: {
  readonly operators: ReadonlyArray<FrostTestOperator>;
  readonly verifyingKey: Uint8Array;
  readonly userCommitment: { readonly hiding: Uint8Array; readonly binding: Uint8Array };
  readonly message: Uint8Array;
}): Uint8Array[] {
  const { tweak, point: tweakedPoint } = taprootTweakedKey(verifyingKey);
  const tweakedEven = evenY(tweakedPoint);
  const flipped = tweakedPoint !== tweakedEven;

  const parties = [
    { id: USER_ID_SCALAR, hiding: userCommitment.hiding, binding: userCommitment.binding },
    ...operators.map((operator) => ({
      id: operator.id,
      hiding: Point.BASE.multiply(mod(operator.hidingNonce, ORDER)).toBytes(true),
      binding: Point.BASE.multiply(mod(operator.bindingNonce, ORDER)).toBytes(true),
    })),
  ].toSorted((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const commitmentList = concatBytes(
    ...parties.map((p) => concatBytes(be32(p.id), p.hiding, p.binding)),
  );
  const prefix = concatBytes(tweakedEven.toBytes(true), h4(message), h5(commitmentList));
  const rho = (id: bigint): bigint => xmdScalar("rho", concatBytes(prefix, be32(id)));

  let groupCommitment = Point.ZERO;
  for (const p of parties) {
    groupCommitment = groupCommitment
      .add(Point.fromBytes(p.hiding))
      .add(Point.fromBytes(p.binding).multiply(rho(p.id)));
  }
  const evenR = (groupCommitment.toAffine().y & 1n) === 0n;
  const challenge = challengeScalar(
    concatBytes(be32(groupCommitment.toAffine().x), be32(tweakedPoint.toAffine().x), message),
  );

  const xs = operators.map((o) => o.id);
  return operators.map((operator) => {
    let z = mod(operator.hidingNonce + rho(operator.id) * operator.bindingNonce, ORDER);
    if (!evenR) {
      z = mod(-z, ORDER);
    }
    let secret = mod(operator.secret + tweak, ORDER);
    if (flipped) {
      secret = mod(-secret, ORDER);
    }
    z = mod(z + lagrangeCoefficient(operator.id, xs) * secret * challenge, ORDER);
    return be32(z);
  });
}
