# Changelog

## Unreleased

### Security

- Lightning receive rejects an SSP invoice carrying any `f` fallback field —
  on-chain addresses and version-31 embedded Spark invoices could redirect the
  payer away from the terms we requested.
