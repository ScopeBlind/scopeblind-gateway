# Capgate policy digest interop

This note defines the narrow bridge between a static MCP capability compiler such as Capgate and `protect-mcp` runtime receipts.

The split is intentional:

- Capgate is declare-before-execute: an MCP server manifest is lowered to policy artifacts such as Cedar, bwrap arguments, egress allowlists, and environment injection rules.
- `protect-mcp` is sign-after-execute: every runtime decision can emit an Ed25519-signed receipt containing the policy decision and input/output digests.
- `policy_digest` is the join key between the declared contract and the runtime evidence.

## Digest contract

For cross-tool stability, the digest should be computed over a normalized capability IR, not over a rendered Cedar file or sandbox argv string.

Recommended v1 construction:

```text
policy_digest = "sha256:" + SHA-256(
  UTF8("scopeblind:policy-digest:v1") || 0x00 || JCS(normalized_capability_ir)
)
```

Rules:

- The normalized capability IR MUST use deterministic key ordering under RFC 8785/JCS.
- The digest input MUST include the domain label `scopeblind:policy-digest:v1` followed by `0x00` before the canonical IR bytes.
- Rendered policy artifacts SHOULD carry the digest as metadata or comments, but MUST NOT define the digest by hashing their rendered bytes.
- Runtime receipts SHOULD include the exact `policy_digest` that was admitted for the session.

This keeps digest stability independent of Cedar formatting, sandbox argument ordering, or emitter implementation details.

## Minimal v1 capability surface

The first interop target should stay small:

| Capability | Example | Lowering target |
| --- | --- | --- |
| filesystem | `fs:read,write:/workspace/**` | Cedar resource path rule + sandbox mount rule |
| network | `net:connect:api.github.com:443` | Cedar host rule + egress allowlist |
| process | `exec:spawn:chromium?nestedSandbox=true` | Cedar binary rule + sandbox exec rule |
| environment | `env:inject:GITHUB_TOKEN` | Cedar context/env rule + env injection allowlist |

## Artifact flow

```text
manifest
  -> normalized capability IR
  -> policy_digest
  -> Cedar / bwrap / egress artifacts
  -> protect-mcp admission
  -> signed decision receipts containing policy_digest
```

A verifier can then join:

```text
normalized IR hash == receipt.payload.policy_digest
```

and independently inspect whether the runtime decision was made under the declared capability contract.

## Example fixture

See `examples/capgate/`:

- `normalized-capability-ir.json` is the pretty-printed normalized IR.
- `canonical-capability-ir.json` is the canonical digest input after recursive key sorting.
- `policy-digest.txt` is the computed digest.
- `policy.cedar` is an illustrative Cedar lowering target.
- `example-receipt.json` shows the receipt fields `protect-mcp` should emit.

The fixture is intentionally illustrative. It does not claim Capgate emits this exact IR today; it defines the smallest useful target for interop discussion.
