import { SPARK_ABI_VERSION, SparkCryptoError, SparkError } from "@qntx/spark/crypto";
import type { SparkCrypto } from "@qntx/spark/crypto";

import type { SparkNative } from "./specs/spark-native.nitro.ts";

function asArrayBuffer(view: Uint8Array): ArrayBuffer {
  const { buffer, byteOffset, byteLength } = view;
  if (buffer instanceof ArrayBuffer && byteOffset === 0 && byteLength === buffer.byteLength) {
    return buffer;
  }
  return new Uint8Array(view).buffer;
}

/**
 * Maps `qntx_spark:<code>` errors raised by the C++ side to `SparkCryptoError`. Nitro rethrows C++
 * exceptions as `funcName + ": " + e.what()` (HybridFunction.hpp), so the code may sit at the end
 * of the message after the function prefix.
 */
function call<T>(invoke: () => T): T {
  try {
    return invoke();
  } catch (error) {
    if (error instanceof Error) {
      const code = /(?:^|: )qntx_spark:(\d+)$/.exec(error.message)?.[1];
      if (code !== undefined) {
        throw new SparkCryptoError(Number(code));
      }
    }
    throw error;
  }
}

function wipe(buffer: ArrayBuffer): void {
  new Uint8Array(buffer).fill(0);
}

/**
 * Inputs that hold private key material: when the caller's `Uint8Array` is a view into a larger
 * buffer, the wrapper copies it into a fresh `ArrayBuffer` for the C++ call — wipe that copy (but
 * never the caller's own backing buffer) once the call returns.
 */
function wipeIfCopy(view: Uint8Array, buffer: ArrayBuffer): void {
  if (buffer !== view.buffer) {
    wipe(buffer);
  }
}

/**
 * Binds a `SparkNative` HybridObject to the {@link SparkCrypto} contract: `Uint8Array` in/out and
 * `SparkCryptoError` on any nonzero ABI code. Throws `SparkError` when the loaded library reports a
 * different ABI version.
 */
export function bindSparkNative(native: SparkNative): SparkCrypto {
  const abiVersion = native.abiVersion();
  if (abiVersion !== SPARK_ABI_VERSION) {
    throw new SparkError(
      `spark-native ABI version ${abiVersion} does not match SPARK_ABI_VERSION ${SPARK_ABI_VERSION}`,
    );
  }
  return {
    abiVersion,
    frostCommit: (hedge, random) =>
      new Uint8Array(call(() => native.frostCommit(asArrayBuffer(hedge), asArrayBuffer(random)))),
    frostSign: (request) => {
      const requestBuffer = asArrayBuffer(request);
      try {
        return new Uint8Array(call(() => native.frostSign(requestBuffer)));
      } finally {
        wipeIfCopy(request, requestBuffer);
      }
    },
    frostAggregate: (request) =>
      new Uint8Array(call(() => native.frostAggregate(asArrayBuffer(request)))),
    eciesEncrypt: (publicKey, plaintext, random) =>
      new Uint8Array(
        call(() =>
          native.eciesEncrypt(
            asArrayBuffer(publicKey),
            asArrayBuffer(plaintext),
            asArrayBuffer(random),
          ),
        ),
      ),
    eciesDecrypt: (privateKey, ciphertext) => {
      const privateKeyBuffer = asArrayBuffer(privateKey);
      try {
        return new Uint8Array(
          call(() => native.eciesDecrypt(privateKeyBuffer, asArrayBuffer(ciphertext))),
        );
      } finally {
        wipeIfCopy(privateKey, privateKeyBuffer);
      }
    },
    splitSecretWithProofs: (secret, threshold, shares, random) => {
      const secretBuffer = asArrayBuffer(secret);
      try {
        return new Uint8Array(
          call(() =>
            native.splitSecretWithProofs(secretBuffer, threshold, shares, asArrayBuffer(random)),
          ),
        );
      } finally {
        wipeIfCopy(secret, secretBuffer);
      }
    },
  };
}
