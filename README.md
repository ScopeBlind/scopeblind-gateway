# protect-mcp

Security gateway for MCP servers. Shadow-mode logs by default, per-tool policies, optional local Ed25519 receipts, and verification-friendly audit output.

**Current CLI path:** wrap any stdio MCP server as a transparent proxy. In shadow mode it logs every `tools/call` request and allows everything through. Add a policy file to enforce per-tool rules. Run `protect-mcp init` to generate local signing keys and config so the gateway can also emit signed receipts.

## Quick Start

```bash
# Wrap an existing OpenClaw / MCP config into a usable pack
npx @scopeblind/passport wrap --runtime openclaw --config ./openclaw.json --policy email-safe

# Shadow mode — log every tool call, enforce nothing
npx protect-mcp -- node my-server.js

# Generate keys + config template for local signing
npx protect-mcp init

# Shadow mode with local signing enabled
npx protect-mcp --policy protect-mcp.json -- node my-server.js

# Enforce mode
npx protect-mcp --policy protect-mcp.json --enforce -- node my-server.js

# Export an offline-verifiable audit bundle
npx protect-mcp bundle --output audit.json
```

## What It Does

protect-mcp sits between your MCP client and server as a stdio proxy:

```
MCP Client ←stdin/stdout→ protect-mcp ←stdin/stdout→ your MCP server
```

It intercepts `tools/call` JSON-RPC requests and:
- **Shadow mode** (default): logs every tool call and allows everything through
- **Enforce mode**: applies per-tool policy rules such as `block`, `rate_limit`, and `min_tier`
- **Optional local signing**: when signing is configured, emits an Ed25519-signed receipt alongside the structured log

All other MCP messages (`initialize`, `tools/list`, notifications) pass through transparently.

## What Ships Today

- **Per-tool policies** — block destructive tools, rate-limit expensive ones, and attach minimum-tier requirements
- **Structured decision logs** — every decision is emitted to `stderr` with `[PROTECT_MCP]`
- **Optional local signed receipts** — generated when you run with a policy containing `signing.key_path`, persisted to `.protect-mcp-receipts.jsonl`, and exposed at `http://127.0.0.1:9876/receipts`
- **Offline verification** — verify receipts or bundles with `npx @veritasacta/verify`
- **No account required** — local keys, local policy, local process

## Current Capability Boundaries

These are important before you roll this out or talk to users:

- **Signing is not automatic on the bare `npx protect-mcp -- ...` path.** That path logs decisions in shadow mode. For local signing, run `npx protect-mcp init` and then start the gateway with the generated policy file.
- **Tier-aware policy checks are live, but manifest admission is not wired into the default CLI/stdio path.** The CLI defaults sessions to `unknown` unless a host integration calls the admission API programmatically.
- **Credential config currently validates env-backed credential references and records credential labels in logs/receipts.** Generic per-call injection into arbitrary stdio tools is adapter-specific and is not performed by the default proxy path.
- **External PDP adapters and audit bundle helpers exist as exported utilities.** They are not yet fully wired into the default CLI path.

## Policy File

```json
{
  "default_tier": "unknown",
  "tools": {
    "dangerous_tool": { "block": true },
    "admin_tool": { "min_tier": "signed-known", "rate_limit": "5/hour" },
    "read_tool": { "require": "any", "rate_limit": "100/hour" },
    "*": { "rate_limit": "500/hour" }
  },
  "signing": {
    "key_path": "./keys/gateway.json",
    "issuer": "protect-mcp",
    "enabled": true
  },
  "credentials": {
    "internal_api": {
      "inject": "env",
      "name": "INTERNAL_API_KEY",
      "value_env": "INTERNAL_API_KEY"
    }
  }
}
```

### Policy Rules

| Field | Values | Description |
|-------|--------|-------------|
| `block` | `true` | Explicitly block this tool |
| `require` | `"any"`, `"none"` | Basic access requirement |
| `min_tier` | `"unknown"`, `"signed-known"`, `"evidenced"`, `"privileged"` | Minimum tier required if your host sets admission state |
| `rate_limit` | `"N/unit"` | Rate limit (e.g. `"5/hour"`, `"100/day"`) |

Tool names match exactly, with `"*"` as a wildcard fallback.

## MCP Client Configuration

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "my-protected-server": {
      "command": "npx",
      "args": [
        "-y", "protect-mcp",
        "--policy", "/path/to/protect-mcp.json",
        "--enforce",
        "--", "node", "my-server.js"
      ]
    }
  }
}
```

### Cursor / VS Code

Same pattern — replace the server command with `protect-mcp` wrapping it.

## CLI Options

```
protect-mcp [options] -- <command> [args...]
protect-mcp init

Commands:
  init              Generate Ed25519 keypair + config template
  status            Show decision stats and local passport identity
  digest            Generate a local human-readable summary
  receipts          Show recent persisted signed receipts
  bundle            Export an offline-verifiable audit bundle

Options:
  --policy <path>   Policy/config JSON file
  --slug <slug>     Service identifier for logs/receipts
  --enforce         Enable enforcement mode (default: shadow)
  --verbose         Enable debug logging
  --help            Show help
```

## Programmatic Hooks

The library also exposes the primitives that are not yet wired into the default CLI path:

```typescript
import {
  ProtectGateway,
  loadPolicy,
  evaluateTier,
  meetsMinTier,
  resolveCredential,
  initSigning,
  signDecision,
  queryExternalPDP,
  buildDecisionContext,
  createAuditBundle,
} from 'protect-mcp';
```

Use these if you want to add:
- manifest admission before a session starts
- an external PDP (OPA, Cerbos, or a generic HTTP webhook)
- custom credential-brokered integrations
- audit bundle export around your own receipt store

## Decision Logs and Receipts

Every tool call emits structured JSON to `stderr`:

```json
[PROTECT_MCP] {"v":2,"tool":"read_file","decision":"allow","reason_code":"observe_mode","policy_digest":"none","mode":"shadow","timestamp":1710000000}
```

When signing is configured, a signed receipt follows:

```json
[PROTECT_MCP_RECEIPT] {"v":2,"type":"decision_receipt","algorithm":"ed25519","kid":"...","issuer":"protect-mcp","issued_at":"2026-03-22T00:00:00Z","payload":{"tool":"read_file","decision":"allow","policy_digest":"...","mode":"shadow","request_id":"..."},"signature":"..."}
```

Verify with the CLI: `npx @veritasacta/verify receipt.json`
Verify in browser: [scopeblind.com/verify](https://scopeblind.com/verify)

## Audit Bundles

The package exports a helper for self-contained audit bundles:

```json
{
  "format": "scopeblind:audit-bundle",
  "version": 1,
  "tenant": "my-service",
  "receipts": ["..."],
  "verification": {
    "algorithm": "ed25519",
    "signing_keys": ["..."]
  }
}
```

Use `createAuditBundle()` around your own collected signed receipts.

## Philosophy

- **Shadow first.** See what agents are doing before you enforce anything.
- **Receipts beat dashboard-only logs.** Signed artifacts should be independently verifiable.
- **Keep the claims tight.** The default CLI path does not yet do everything the long-term architecture will support.
- **Layer on top of existing auth.** Don't rip out your stack just to add control and evidence.

## Incident-Anchored Policy Packs

Ship with protect-mcp — each prevents a real attack:

| Policy | Incident | OWASP Categories |
|--------|----------|-----------------|
| `clinejection.json` | CVE-2025-6514: MCP OAuth proxy hijack (437K environments) | A01, A03 |
| `terraform-destroy.json` | Autonomous Terraform agent destroys production | A05, A06 |
| `github-mcp-hijack.json` | Prompt injection via crafted GitHub issue | A01, A02, A03 |
| `data-exfiltration.json` | Agent data theft via outbound tool abuse | A02, A04 |
| `financial-safe.json` | Unauthorized financial transaction | A05, A06 |

```bash
npx protect-mcp --policy node_modules/protect-mcp/policies/clinejection.json -- node server.js
```

Full OWASP Agentic Top 10 mapping: [scopeblind.com/docs/owasp](https://scopeblind.com/docs/owasp)

## BYOPE: External Policy Engines

Supports OPA, Cerbos, Cedar (AWS AgentCore), and generic HTTP endpoints:

```json
{
  "policy_engine": "hybrid",
  "external": {
    "endpoint": "http://localhost:8181/v1/data/mcp/allow",
    "format": "cedar",
    "timeout_ms": 200,
    "fallback": "deny"
  }
}
```

## Standards & IP

- **IETF Internet-Draft**: [draft-farley-acta-signed-receipts-00](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) — Signed Decision Receipts for Machine-to-Machine Access Control
- **Patent Status**: 4 Australian provisional patents pending (2025-2026) covering decision receipts with configurable disclosure, tool-calling gateway, agent manifests, and portable identity
- **Verification**: MIT-licensed — `npx @veritasacta/verify --self-test`

## License

MIT — free to use, modify, distribute, and build upon without restriction.

[scopeblind.com](https://scopeblind.com) · [npm](https://www.npmjs.com/package/protect-mcp) · [GitHub](https://github.com/scopeblind/ScopeBlindD2) · [IETF Draft](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)
