# @qntx/spark-wasm

`spark.wasm` SparkCrypto backend — `crates/spark-ffi` compiled to WebAssembly behind a C ABI —
for use with [`@qntx/spark`](../spark). Platform-neutral: the default entry loads the artifact
from disk-friendly bundlers, the `browser` export fetches it over HTTP.

Status: **pre-release**. See the [repository](https://github.com/qntx/spark) and
[CHANGELOG](https://github.com/qntx/spark/blob/main/CHANGELOG.md).

## Usage

```ts
import { loadSparkWasm } from "@qntx/spark-wasm";

const crypto = await loadSparkWasm();
```

Every call compiles a fresh `SparkCrypto` instance the caller owns.

## Verifying the artifact (Worker / fetch SRI)

`SPARK_WASM_INTEGRITY` is the build-time Subresource Integrity hash (`sha256-<base64>`) of the
shipped `spark.wasm`. A host that fetches the artifact itself — e.g. a Wallet Worker — can pin
it at fetch time and pass the verified bytes to `loadSparkWasm`:

```ts
import { loadSparkWasm, SPARK_WASM_INTEGRITY } from "@qntx/spark-wasm";

const res = await fetch(wasmUrl, { integrity: SPARK_WASM_INTEGRITY });
const crypto = await loadSparkWasm({ module: await res.arrayBuffer() });
```

`loadSparkWasm()` without `module` loads `spark.wasm` itself and does **not** verify the hash —
callers that need SRI enforcement must fetch with `integrity` as above. The constant is
reproduced by the pinned `linux/amd64` Docker build (`bun run build:wasm`) and checked against
the packed artifact in tests.
