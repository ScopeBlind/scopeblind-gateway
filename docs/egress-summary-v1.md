# Signed Egress Summary v1

`scopeblind.egress_summary.v1` is the only artifact sent by the optional hosted
dashboard bridge. It is a separate signed Acta envelope, not a stripped copy of
a receipt. The normal `/receipts` endpoint remains for full signed receipts and
is a local loopback endpoint only. Hosted raw-receipt ingestion is retired and
is not weakened or reused.

## What may leave a machine

The pre-signing schema is closed. It contains only:

- a SHA-256 commitment to the full local receipt
- local HMAC-SHA-256 pseudonyms for request, policy, action, and output references
- decision, normalized reason code, coarse tool category, and mode enums
- bounded counts

It excludes raw prompts, tool inputs, outputs, recipients, paths, hostnames,
amounts, positions, raw request ids, policy labels, and private keys. The bridge
creates a random 32-byte local key per tenant and destination, stores it at mode
`0600`, and uses it to HMAC every potentially identifying reference before egress.
The hosted service never receives that key. `SCOPEBLIND_EGRESS_HMAC_KEY` can
instead supply an organization-managed base64url key.

The bridge requires a working local signer. If it cannot sign the summary, it
drops it rather than emitting unsigned telemetry. The Worker re-verifies the
Ed25519 envelope and pins the first authenticated tenant key; implicit key
rotation is rejected.

## Linkage and limits

A party holding the local receipt recomputes its canonical receipt hash and
compares it with `source_receipt_commitment`. The dashboard proves only that it
received a signed summary bound to that receipt. It cannot reconstruct or verify
the full local receipt, and it is not the source of truth for the action.

The receipt commitment deliberately remains `sha256:<digest>` so offline linkage
does not need a secret. The other references are visibly typed as
`hmac-sha256:<digest>`. They are stable only within the local tenant scope and
cannot be dictionary-checked by a hosted database without the local key.
