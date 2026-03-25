<p align="center">
  <img src="https://www.scopeblind.com/scopeblind-logo-solarin.png" width="48" />
</p>

<h1 align="center">ScopeBlind</h1>

<p align="center">
  Security gateway for MCP servers.<br/>
  Shadow-mode logs. Per-tool policies. Optional signed receipts.
</p>

<p align="center">
  <a href="https://scopeblind.com">Website</a> &middot;
  <a href="https://scopeblind.com/docs">Docs</a> &middot;
  <a href="https://www.npmjs.com/package/protect-mcp">npm</a> &middot;
  <a href="https://scopeblind.com/verify">Verify a Receipt</a>
</p>

<p align="center">
  <img alt="License" src="https://img.shields.io/badge/license-FSL--1.1--MIT-blue.svg" />
  <img alt="npm protect-mcp" src="https://img.shields.io/npm/v/protect-mcp?label=protect-mcp&color=cb3837&logo=npm" />
  <img alt="TypeScript" src="https://img.shields.io/badge/TypeScript-5.6-3178C6?logo=typescript&logoColor=white" />
</p>

[![protect-mcp MCP server](https://glama.ai/mcp/servers/tomjwxf/scopeblind-gateway/badges/card.svg)](https://glama.ai/mcp/servers/tomjwxf/scopeblind-gateway)

---

## protect-mcp — MCP Server Security Gateway

Wrap any stdio MCP server in one line. Start in shadow mode to see every tool call. Add a policy file to enforce per-tool rules. Generate local keys with `protect-mcp init` if you want signed receipts.

```bash
# Shadow mode — log every tool call, enforce nothing
npx protect-mcp -- node your-mcp-server.js

# Generate local signing keys + config template
npx protect-mcp init

# Run with policy + local signing
npx protect-mcp --policy protect-mcp.json -- node your-mcp-server.js

# Try the built-in demo
npx protect-mcp demo
```

### What ships today

- **Shadow mode** (default) — logs every tool invocation with structured decision entries. Blocks nothing.
- **Enforce mode** — applies per-tool policies: `block`, `rate_limit`, `min_tier`.
- **Optional local signing** — when signing is configured, emits Ed25519-signed receipts alongside decision logs.
- **Demo command** — `npx protect-mcp demo` runs a built-in 5-tool MCP server wrapped with the gateway.
- **Status command** — `npx protect-mcp status` shows tool call stats from the local decision log.
- **Evidence store** — file-based receipt history per agent for trust tier promotion.
- **Verification** — receipts verify offline with `npx @veritasacta/verify` or at [scopeblind.com/verify](https://scopeblind.com/verify).
- **No account required** — local process, local config, local keys.

### Current capability boundaries

- The bare `npx protect-mcp -- ...` path emits logs, not signed receipts. Run `protect-mcp init` for signing.
- Tier-aware policy checks are live, but manifest admission is not wired into the default CLI path. CLI sessions default to `unknown` unless a host integration sets admission state programmatically.
- Credential config validates env-backed references and records credential labels in logs/receipts. Generic per-call injection is adapter-specific.
- External PDP adapters (OPA, Cerbos, generic) and audit bundle helpers are exported as programmatic hooks, not fully wired into the default CLI path.

### Example policy

```json
{
  "default_tier": "unknown",
  "tools": {
    "delete_database": { "block": true },
    "write_file": { "min_tier": "signed-known", "rate_limit": "10/minute" },
    "read_file": { "rate_limit": "50/minute" },
    "*": { "rate_limit": "100/hour" }
  },
  "signing": {
    "key_path": "./keys/gateway.json",
    "issuer": "protect-mcp",
    "enabled": true
  }
}
```

### Claude Desktop / Cursor config

```json
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": ["protect-mcp", "--policy", "protect-mcp.json", "--enforce", "--", "node", "my-server.js"]
    }
  }
}
```

Works with Claude Desktop, Cursor, VS Code — any client that speaks MCP over stdio.

---

## The Bigger Picture

ScopeBlind produces signed, portable receipts for machine access decisions. Each receipt contains the decision, policy digest, trust tier, and timestamp — signed with Ed25519 and verifiable by anyone without calling ScopeBlind.

**protect-mcp** is the free, open-source entry point for MCP servers. The **ScopeBlind platform** adds managed signing, a real-time dashboard, and edge enforcement.

*Machines need receipts. Receipts shouldn't require surveillance.*

## Packages

| Package | npm | Purpose |
|---------|-----|---------|
| `protect-mcp` | [![npm](https://img.shields.io/npm/v/protect-mcp)](https://www.npmjs.com/package/protect-mcp) | MCP server security gateway |
| `@veritasacta/verify` | [![npm](https://img.shields.io/npm/v/@veritasacta/verify)](https://www.npmjs.com/package/@veritasacta/verify) | Offline receipt/bundle verification CLI |
| `@veritasacta/artifacts` | [![npm](https://img.shields.io/npm/v/@veritasacta/artifacts)](https://www.npmjs.com/package/@veritasacta/artifacts) | Ed25519 signing + JCS canonicalization |
| `@scopeblind/passport` | [![npm](https://img.shields.io/npm/v/@scopeblind/passport)](https://www.npmjs.com/package/@scopeblind/passport) | Agent identity, signed manifests |

## Architecture

```
MCP Client (Claude, Cursor, VS Code)
  → protect-mcp (stdio proxy)
    → Intercept tools/call JSON-RPC
    → Evaluate policy (allow / block / rate_limit)
    → Log decision to stderr ([PROTECT_MCP] prefix)
    → Sign receipt if signing configured ([PROTECT_MCP_RECEIPT] prefix)
    → Forward allowed calls to wrapped MCP server
```

## License

> **Source-available under the [Functional Source License (FSL-1.1-MIT)](https://fsl.software).**
> You may use, modify, and self-host this freely for your own projects or internal company use.
> You may not offer ScopeBlind (or a substantially similar service) as a hosted/managed product to third parties.
> After 2 years, each version automatically converts to the MIT license.

---

<p align="center">
  Built by <a href="https://github.com/tomjwxf">Tom Farley</a> in Sydney, Australia.
</p>