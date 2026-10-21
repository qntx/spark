import { SPARK_ABI_VERSION, SparkCryptoError, SparkError } from "@qntx/spark/crypto";

/**
 * Byte ABI exported by `spark.wasm` (the wasm32 build of `crates/spark-ffi`, `qntx_spark.h`).
 * Inputs are `(pointer, len)` regions allocated through `qs_alloc`; outputs come back through
 * `(uint8_t **out, size_t *out_len)` out-params written only on success and released with
 * `qs_free`. Error codes: 0 ok, 1 length, 2 invalid scalar, 3 invalid point, 4 protobuf decode, 5
 * argument range, 6 frost, 7 auth, 8 internal.
 */
/** A wasm-exported i32 function; results arrive as `unknown` until narrowed. */
export type WasmFn = (...args: number[]) => unknown;

export type SparkWasmExports = {
  memory: WebAssembly.Memory;
  qs_abi_version: WasmFn;
  qs_alloc: WasmFn;
  qs_free: WasmFn;
  qs_frost_commit: WasmFn;
  qs_frost_sign: WasmFn;
  qs_frost_aggregate: WasmFn;
  qs_ecies_encrypt: WasmFn;
  qs_ecies_decrypt: WasmFn;
  qs_split_secret_with_proofs: WasmFn;
};

const OUT_PARAMS_LEN = 8;
const INTERNAL_ERROR = 8;

function requireMemory(value: WebAssembly.ExportValue | undefined): WebAssembly.Memory {
  if (!(value instanceof WebAssembly.Memory)) {
    throw new SparkError("spark.wasm missing memory export");
  }
  return value;
}

function requireFn(value: WebAssembly.ExportValue | undefined, name: string): WasmFn {
  if (typeof value !== "function") {
    throw new SparkError(`spark.wasm missing ${name} export`);
  }
  return value;
}

export function sparkWasmExports(raw: WebAssembly.Exports): SparkWasmExports {
  return {
    memory: requireMemory(raw["memory"]),
    qs_abi_version: requireFn(raw["qs_abi_version"], "qs_abi_version"),
    qs_alloc: requireFn(raw["qs_alloc"], "qs_alloc"),
    qs_free: requireFn(raw["qs_free"], "qs_free"),
    qs_frost_commit: requireFn(raw["qs_frost_commit"], "qs_frost_commit"),
    qs_frost_sign: requireFn(raw["qs_frost_sign"], "qs_frost_sign"),
    qs_frost_aggregate: requireFn(raw["qs_frost_aggregate"], "qs_frost_aggregate"),
    qs_ecies_encrypt: requireFn(raw["qs_ecies_encrypt"], "qs_ecies_encrypt"),
    qs_ecies_decrypt: requireFn(raw["qs_ecies_decrypt"], "qs_ecies_decrypt"),
    qs_split_secret_with_proofs: requireFn(
      raw["qs_split_secret_with_proofs"],
      "qs_split_secret_with_proofs",
    ),
  };
}

/**
 * Copies `bytes` into a fresh `qs_alloc` region. Empty inputs return 0 — the C side treats `(NULL,
 * 0)` as an empty slice.
 */
function copyIn(exports: SparkWasmExports, bytes: Uint8Array): number {
  const len = bytes.length;
  if (len === 0) {
    return 0;
  }
  const ptr = Number(exports.qs_alloc(len)) >>> 0;
  if (ptr === 0) {
    throw new SparkCryptoError(INTERNAL_ERROR);
  }
  new Uint8Array(exports.memory.buffer, ptr, len).set(bytes);
  return ptr;
}

/** Wipes then releases a region allocated by {@link copyIn}. */
function freeIn(exports: SparkWasmExports, ptr: number, len: number): void {
  if (ptr === 0 || len === 0) {
    return;
  }
  new Uint8Array(exports.memory.buffer, ptr, len).fill(0);
  exports.qs_free(ptr, len);
}

/**
 * Runs `invoke(out, outLen)` with the 8-byte out-param region and returns the output bytes. The
 * region views are taken fresh after the call because the module may grow memory inside it.
 */
function callOut(
  exports: SparkWasmExports,
  invoke: (out: number, outLen: number) => unknown,
): Uint8Array {
  const params = Number(exports.qs_alloc(OUT_PARAMS_LEN)) >>> 0;
  if (params === 0) {
    throw new SparkCryptoError(INTERNAL_ERROR);
  }
  try {
    const code = Number(invoke(params, params + 4));
    if (code !== 0) {
      throw new SparkCryptoError(code);
    }
    const view = new DataView(exports.memory.buffer, params, OUT_PARAMS_LEN);
    const outPtr = view.getUint32(0, true) >>> 0;
    const outLen = view.getUint32(4, true) >>> 0;
    if (outPtr === 0) {
      return new Uint8Array(0);
    }
    const result = new Uint8Array(outLen);
    result.set(new Uint8Array(exports.memory.buffer, outPtr, outLen));
    exports.qs_free(outPtr, outLen);
    return result;
  } finally {
    freeIn(exports, params, OUT_PARAMS_LEN);
  }
}

export function wasmFrostCommit(
  exports: SparkWasmExports,
  hedge: Uint8Array,
  random: Uint8Array,
): Uint8Array {
  const hedgePtr = copyIn(exports, hedge);
  const randomPtr = copyIn(exports, random);
  try {
    return callOut(exports, (out, outLen) =>
      exports.qs_frost_commit(hedgePtr, hedge.length, randomPtr, random.length, out, outLen),
    );
  } finally {
    freeIn(exports, hedgePtr, hedge.length);
    freeIn(exports, randomPtr, random.length);
  }
}

export function wasmFrostSign(exports: SparkWasmExports, request: Uint8Array): Uint8Array {
  const requestPtr = copyIn(exports, request);
  try {
    return callOut(exports, (out, outLen) =>
      exports.qs_frost_sign(requestPtr, request.length, out, outLen),
    );
  } finally {
    freeIn(exports, requestPtr, request.length);
  }
}

export function wasmFrostAggregate(exports: SparkWasmExports, request: Uint8Array): Uint8Array {
  const requestPtr = copyIn(exports, request);
  try {
    return callOut(exports, (out, outLen) =>
      exports.qs_frost_aggregate(requestPtr, request.length, out, outLen),
    );
  } finally {
    freeIn(exports, requestPtr, request.length);
  }
}

export function wasmEciesEncrypt(
  exports: SparkWasmExports,
  publicKey: Uint8Array,
  plaintext: Uint8Array,
  random: Uint8Array,
): Uint8Array {
  const pkPtr = copyIn(exports, publicKey);
  const msgPtr = copyIn(exports, plaintext);
  const randomPtr = copyIn(exports, random);
  try {
    return callOut(exports, (out, outLen) =>
      exports.qs_ecies_encrypt(
        pkPtr,
        publicKey.length,
        msgPtr,
        plaintext.length,
        randomPtr,
        random.length,
        out,
        outLen,
      ),
    );
  } finally {
    freeIn(exports, pkPtr, publicKey.length);
    freeIn(exports, msgPtr, plaintext.length);
    freeIn(exports, randomPtr, random.length);
  }
}

export function wasmEciesDecrypt(
  exports: SparkWasmExports,
  privateKey: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const skPtr = copyIn(exports, privateKey);
  const ctPtr = copyIn(exports, ciphertext);
  try {
    return callOut(exports, (out, outLen) =>
      exports.qs_ecies_decrypt(skPtr, privateKey.length, ctPtr, ciphertext.length, out, outLen),
    );
  } finally {
    freeIn(exports, skPtr, privateKey.length);
    freeIn(exports, ctPtr, ciphertext.length);
  }
}

/**
 * Mirrors the native `toUint32` guard: a JS `number` arrives as a double and the wasm ABI coerces
 * it to i32, truncating fractions and wrapping values past 2^32 — reject them first.
 */
function checkUint32(value: number, name: string): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new SparkError(`${name} must be an integer in [0, 2^32)`);
  }
}

export function wasmSplitSecretWithProofs(
  exports: SparkWasmExports,
  secret: Uint8Array,
  threshold: number,
  shares: number,
  random: Uint8Array,
): Uint8Array {
  checkUint32(threshold, "threshold");
  checkUint32(shares, "shares");
  const secretPtr = copyIn(exports, secret);
  const randomPtr = copyIn(exports, random);
  try {
    return callOut(exports, (out, outLen) =>
      exports.qs_split_secret_with_proofs(
        secretPtr,
        secret.length,
        threshold,
        shares,
        randomPtr,
        random.length,
        out,
        outLen,
      ),
    );
  } finally {
    freeIn(exports, secretPtr, secret.length);
    freeIn(exports, randomPtr, random.length);
  }
}

/**
 * Compiles and instantiates `spark.wasm`. The module must declare no imports and must implement ABI
 * version {@link SPARK_ABI_VERSION} — a mismatch means the artifact predates or postdates this
 * loader and instantiation fails.
 */
export async function instantiateSparkWasm(bytes: BufferSource): Promise<SparkWasmExports> {
  const module = await WebAssembly.compile(bytes);
  const imports = WebAssembly.Module.imports(module);
  if (imports.length > 0) {
    throw new SparkError(`spark.wasm module must not declare imports (got ${imports.length})`);
  }
  const instance = await WebAssembly.instantiate(module, {});
  const version = Number(requireFn(instance.exports["qs_abi_version"], "qs_abi_version")());
  if (version !== SPARK_ABI_VERSION) {
    throw new SparkError(
      `spark.wasm ABI version ${version} does not match loader ABI version ${SPARK_ABI_VERSION}`,
    );
  }
  return sparkWasmExports(instance.exports);
}
