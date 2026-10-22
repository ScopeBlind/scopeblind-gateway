# Receipts, disclosure and anchoring

[Back to the quickstart](../README.md#try-it-without-an-agent)

Use an independently obtained public key to verify receipts. A signature binds
bytes to a key; it does not establish complete action coverage, execution or a
claim’s truth. The gateway operator remains part of the trust model.

## Optional digest anchoring

Local receipt creation and verification do not require a hosted account. The
optional registry adapter can submit digests to a separately operated service.
A service acknowledgment records that service’s statement about the digest and
time; it does not establish that every action was recorded.

```bash
# Create or refresh a local org identity and public-key directory.
npx protect-mcp registry init --org "Meridian Global Macro" --billing-account acct_meridian

# Local preview: writes a digest registry and shareable static verifier page.
npx protect-mcp registry anchor

# Hosted mode: uploads receipt digests only for independent anchoring.
SCOPEBLIND_TOKEN=... npx protect-mcp registry anchor \
  --hosted \
  --endpoint https://api.scopeblind.com \
  --verifier-base https://scopeblind.com
```

The local preview is deliberately labeled `local-preview-not-independent`.
Hosted mode anchors receipt hashes, request ids, org public keys, and
billing metadata. It does not upload raw receipts or sensitive context.

## Generated demonstration: shadow to policy to proof

`protect-mcp killer-demo` generates a local demonstration pack:

```bash
npx protect-mcp killer-demo --dir ./scopeblind-demo
```

It creates mock filesystem, GitHub, email, and PMS activity; shows risky calls in
shadow mode; applies a policy pack; requires approval for a sensitive PMS booking;
executes through the gateway; writes a signed receipt; proves the original
receipt verifies; proves a tampered receipt fails; and creates a selective
disclosure package that hides sensitive context while showing the minimum proof.

Open the generated `DEMO-RUNBOOK.md` first. Then run the printed dashboard
command to inspect the generated sequence.

## Selective disclosure v0

Commitment-mode receipts can carry a `committed_fields_root` instead of exposing
every field in cleartext. Later, the holder can disclose selected fields only:

```bash
npx protect-mcp verify-disclosure \
  --receipt ./receipts/selective-disclosure.receipt.json \
  --disclosure ./receipts/selective-disclosure.tool-only.json
```

The verifier checks the parent receipt hash, Ed25519 signature, commitment root,
and each disclosed field's Merkle proof. It then explains which fields were
disclosed and which committed fields remain hidden. This is salted commitment
disclosure, not full zero-knowledge, but it makes the privacy claim concrete:
auditors can verify selected facts without receiving the full tool payload or
sensitive desk context.

## Claims over the disclosed record

Create an attestation of a predicate over the supplied record. It discloses
per-decision categories (a receipt digest, verdict and capability tags), rather
than tool inputs and outputs. Those categories and their completeness still
depend on what the gateway recorded:

```bash
# Check that the disclosed record has no net.egress capability:
npx protect-mcp claim --no net.egress

# other predicates:
#   --only fs.read,fs.write     all actions were confined to these capabilities
#   --no-verdict blocked        no action was blocked
#   --count blocked             how many were blocked
```

Anyone verifies it offline, seeing only the categories, never the content:

```bash
npx protect-mcp verify-claim claim-<id>.json
```

The verifier recomputes a Merkle root over the disclosed set and recomputes the
predicate independently, so the issuer cannot lie about the claim given the
disclosure. Add `--anchor` to record the claim's digest in the public,
append-only ScopeBlind transparency log, to bind later disclosure to the same published commitment. This detects a
changed committed set; it cannot reveal omitted actions or a withheld suffix
without an independently known expected checkpoint:

```bash
npx protect-mcp claim --no net.egress --anchor
```

This is an accountable, position-blind attestation, not full zero-knowledge: it
reveals the shape, not the content.
