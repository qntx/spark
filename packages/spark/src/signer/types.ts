/**
 * A statement the signer signs with the identity key. The signer computes the digest itself from
 * the statement content — there is no sign-arbitrary-hash method. The interface grows with each
 * stage; only the variants the protocol uses are listed.
 *
 * - `so-challenge`: `challenge` is the serialized `spark_authn.Challenge`; the signer decodes it
 *   strictly, checks it targets the identity key, and signs `authnChallengeDigest` (DER ECDSA).
 * - `ssp-challenge`: `protectedChallenge` is the base64 challenge string the SSP issued; the signer
 *   validates the base64 and signs `sspChallengeDigest` (DER ECDSA).
 */
export type IdentityStatement =
  | { readonly kind: "so-challenge"; readonly challenge: Uint8Array }
  | { readonly kind: "ssp-challenge"; readonly protectedChallenge: string };

/**
 * The signer's identity surface. Private keys never leave the signer; every method returns protocol
 * values only (Uint8Array, strings, safe integers, plain objects) so an implementation may live
 * behind a binding boundary.
 */
export type SparkSigner = {
  /** The 33-byte compressed secp256k1 identity public key. */
  readonly identityPublicKey: () => Promise<Uint8Array>;
  /** Signs a protocol statement with the identity key. Returns the signature bytes. */
  readonly signIdentity: (statement: IdentityStatement) => Promise<Uint8Array>;
};
