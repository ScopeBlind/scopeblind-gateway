# Managed Mandate Continuity Anchor

A local managed-mandate registry detects tampering by parties that cannot forge
the gate key. It cannot alone defeat a host operator who controls both local
storage and the gate key: they could rewrite a self-consistent history.

Use the continuity checkpoint to create a signed commitment to the registry
identity, complete registry digest, active policy digest, transition count, and
latest transition receipt hash:

```sh
protect-mcp mandate continuity --cedar ./cedar --anchor --require-anchor
```

The command writes a local checkpoint and, with `--anchor`, submits its signed
commitment to the public append-only log. A later registry must be checked
against the witness sidecar before relying on it. `--require-anchor` is suitable
for a scheduled pilot run because it exits non-zero when the external witness is
unavailable.

Only lifecycle commitments leave the host. Policy source, prompts, tool payloads,
portfolio data, controller credential material, and receipts do not.

This is external relative to the managed host. The default ScopeBlind log is not
independent of ScopeBlind itself. Customers requiring resilience to a ScopeBlind
operator must configure or obtain a genuinely independent witness and verify its
inclusion proof; that multi-witness mode is not implemented here.
