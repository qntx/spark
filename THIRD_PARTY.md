# Third-Party Notices

`crates/spark-crypto` ports code from the projects below, and `crates/interop` runs
differential tests against their upstream crates. Their license texts are reproduced
verbatim.

## Spark

- Repository: <https://github.com/buildonspark/spark>
- License: Apache-2.0
- Copyright: Lightspark Group, Inc.
- Used by: `crates/spark-crypto` ports the user-side FROST, ECIES and VSS code of
  `signer/spark-frost`; `crates/interop` replays shared vectors against the upstream
  crate. Modified files carry a notice stating the upstream path, commit and changes
  (see NOTICE).

The Apache License, Version 2.0 text is in [LICENSE](LICENSE).

## frost (lightsparkdev fork of ZF FROST)

- Repository: <https://github.com/lightsparkdev/frost> (fork of
  <https://github.com/ZcashFoundation/frost>)
- License: MIT OR Apache-2.0
- Used by: `crates/spark-crypto` depends on `frost-secp256k1-tr` and `frost-core` from
  the fork at the pinned commit.

```text
Copyright 2019-2021 Zcash Foundation

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Breez Spark SDK

- Repository: <https://github.com/breez/spark-sdk>
- License: MIT
- Copyright: Breez
- Used by: `proto/ssp/ssp_authn.proto` vendors Breez's transcription of the SSP
  authentication challenge schema (`crates/spark/protos/ssp/ssp_authn.proto`,
  pinned commit 956ff90), and the challenge validation that consumes it follows
  `crates/spark/src/ssp/challenge.rs`. The MIT license text is reproduced in the
  `frost` section above.
