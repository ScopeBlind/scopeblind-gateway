# verify-mcp (Claude Code plugin)

Adds the offline verifier as an MCP server inside Claude Code. Four read-only tools:

- `self_test` — verify the packaged sample receipt and bundle, to prove the verifier works
- `verify_receipt` — verify one signed artifact (decision receipt, restraint receipt, passport)
- `verify_bundle` — verify every receipt in an audit bundle
- `explain_artifact` — inspect an artifact's claims without a key

No accounts, no network calls: verification is Ed25519 over canonical JSON, offline.
Source and tests: https://github.com/ScopeBlind/verify-mcp

Companion to the `protect-mcp` plugin in this marketplace: protect-mcp is the local
policy gate that signs decisions, verify-mcp checks them with the operator's software removed.
