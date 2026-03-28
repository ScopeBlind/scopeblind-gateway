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
  <a href="https://scopeblind.com/docs/mcp">MCP Docs</a> &middot;
  <a href="https://www.npmjs.com/package/protect-mcp">npm</a> &middot;
  <a href="https://scopeblind.com/verify">Verify a Receipt</a> &middot;
  <a href="https://scopeblind.com/stack">The Stack</a>
</p>

<p align="center">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green.svg" />
  <img alt="npm protect-mcp" src="https://img.shields.io/npm/v/protect-mcp?label=protect-mcp&color=cb3837&logo=npm" />
  <img alt="Tests" src="https://img.shields.io/badge/tests-471%20passing-brightgreen" />
  <a href="https://glama.ai/mcp/servers/tomjwxf/scopeblind-gateway"><img alt="Glama" src="https://glama.ai/mcp/servers/tomjwxf/scopeblind-gateway/badges/score.svg" /></a>
</p>

<p align="center">
  <a href="https://smithery.ai/servers/scopeblind/protect-mcp">Smithery</a> &middot;
  <a href="https://glama.ai/mcp/servers/tomjwxf/scopeblind-gateway">Glama</a> &middot;
  <a href="https://clawhub.ai/skills/scopeblind-passport">ClawHub</a> &middot;
  <a href="https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/">IETF Draft</a>
</p>

---

## Progressive Adoption

Start with visibility. Add control when ready. Sign when you want proof. Each step is independently valuable.

```bash
# 1. Shadow — see what's happening (blocks nothing)
npx protect-mcp -- node your-server.js

# 2. Simulate — test a policy against recorded tool calls
npx protect-mcp simulate --policy strict.json

# 3. Enforce — apply the policy
npx protect-mcp --policy strict.json --enforce -- node your-server.js

# 4. Sign — generate keys, produce signed receipts
npx protect-mcp init

# 5. Report — generate a compliance report
npx protect-mcp report --period 30d --format md --output report.md

# 6. Verify — prove it to anyone, offline
npx @veritasacta/verify --self-test
```

---

## What ships today

- **Shadow mode** (default) — logs every tool call, blocks nothing
- **Enforce mode** — per-tool policies: `block`, `rate_limit`, `min_tier`, `require_approval`
- **Approval gates** — high-risk tools pause for human approval (non-blocking, request_id scoped)
- **Optional local signing** — Ed25519-signed receipts for every decision
- **Simulate** — dry-run a policy against your recorded log before enforcing
- **Report** — compliance report from receipts (JSON or Markdown)
- **Bundle export** — self-contained audit bundles with embedded verification keys
- **Demo** — `npx protect-mcp demo` runs a built-in MCP server with the gateway
- **Verification** — `npx @veritasacta/verify --self-test` (MIT, offline, no accounts)

### Capability boundaries

- Bare `npx protect-mcp -- ...` logs decisions without signing. Run `protect-mcp init` for signed receipts.
- Trust tiers are live but manifest admission defaults to `unknown` unless set programmatically.
- External PDP adapters (OPA, Cerbos) and credential vault are exported as programmatic hooks.

### Policy file

```json
{
  "tools": {
    "delete_database": { "block": true },
    "send_email": { "require_approval": true },
    "write_file": { "min_tier": "signed-known", "rate_limit": "10/minute" },
    "*": { "rate_limit": "100/hour" }
  },
  "signing": {
    "key_path": "./keys/gateway.json",
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

Works with Claude Desktop, Cursor, VS Code, OpenClaw — any client that speaks MCP over stdio.

---

## The Trust Stack

ScopeBlind is part of a three-layer evidence infrastructure. Each layer is independently useful and survives the failure of every other layer.

| Layer | What | License |
|-------|------|---------|
| **BlindLLM** | Coordination lab — blind AI battles, agent studio | [blindllm.com](https://blindllm.com) |
| **ScopeBlind** | Commercial enforcement — policies, receipts, approval gates | MIT |
| **Veritas Acta** | Open evidence protocol — format, verifier, constitution | MIT |

[See the full stack &rarr;](https://scopeblind.com/stack)

## Packages

| Package | npm | Purpose |
|---------|-----|---------|
| `protect-mcp` | [![npm](https://img.shields.io/npm/v/protect-mcp)](https://www.npmjs.com/package/protect-mcp) | MCP security gateway |
| `@scopeblind/passport` | [![npm](https://img.shields.io/npm/v/@scopeblind/passport)](https://www.npmjs.com/package/@scopeblind/passport) | Agent identity + pack builder |
| `@scopeblind/red-team` | [![npm](https://img.shields.io/npm/v/@scopeblind/red-team)](https://www.npmjs.com/package/@scopeblind/red-team) | Policy benchmark runner |
| `@veritasacta/protocol` | [![npm](https://img.shields.io/npm/v/@veritasacta/protocol)](https://www.npmjs.com/package/@veritasacta/protocol) | Evidence protocol (12 receipt types) |
| `@veritasacta/verify` | [![npm](https://img.shields.io/npm/v/@veritasacta/verify)](https://www.npmjs.com/package/@veritasacta/verify) | MIT offline verifier |
| `@scopeblind/verify-mcp` | [![npm](https://img.shields.io/npm/v/@scopeblind/verify-mcp)](https://www.npmjs.com/package/@scopeblind/verify-mcp) | MCP server for verification |

## HTTP/SSE Transport

Deploy protect-mcp as an HTTP server for remote MCP clients, Smithery, ChatGPT, and Glama:

```bash
npx protect-mcp --http --port 3000 -- node your-server.js
```

Endpoints: `POST /mcp` (Streamable HTTP), `GET /mcp/sse` (SSE), `GET /health`, `DELETE /mcp`.

## Cedar Policy Engine

Use AWS Cedar policies as an alternative to JSON:

```bash
npx protect-mcp --cedar ./policies/cedar/ --enforce -- node your-server.js
```

Local WASM evaluation — same engine as AWS Verified Permissions. All three policy engines (JSON, Cedar, external PDP) produce the same signed Acta receipts.

## Install

```bash
# npm (Node.js)
npx protect-mcp -- node your-server.js

# pip (Python)
pip install protect-mcp && protect-mcp -- node your-server.js
```

## Notifications (SMS, Slack, PagerDuty)

Get notified when agents need approval:

```bash
# Slack webhook
export SCOPEBLIND_WEBHOOK_URL="https://hooks.slack.com/services/..."
export SCOPEBLIND_WEBHOOK_TEMPLATE="slack"

# SMS via Twilio
export SCOPEBLIND_SMS_TO="+1234567890"
export TWILIO_ACCOUNT_SID="..."
export TWILIO_AUTH_TOKEN="..."

npx protect-mcp --policy policy.json --enforce -- node server.js
```

## OpenTelemetry Export

Receipts in your existing Datadog/Grafana:

```bash
npm install @scopeblind/otel-exporter
```

See [@scopeblind/otel-exporter](https://npmjs.com/package/@scopeblind/otel-exporter).

## Example Integrations

- [Karpathy's autoresearch](https://github.com/tomjwxf/ScopeBlindD2/tree/main/examples/autoresearch) — safety policy for ML experiment agents
- [Meta HyperAgents](https://github.com/tomjwxf/ScopeBlindD2/tree/main/examples/hyperagents) — sandbox constraints for self-modifying agents
- [Slack integration](https://github.com/tomjwxf/ScopeBlindD2/tree/main/examples/slack-integration) — 2-minute webhook setup

## Ecosystem

| Package | Purpose |
|---------|---------|
| [protect-mcp](https://npmjs.com/package/protect-mcp) | MCP security gateway |
| [@scopeblind/otel-exporter](https://npmjs.com/package/@scopeblind/otel-exporter) | Receipts in Datadog/Grafana |
| [create-scopeblind-agent](https://npmjs.com/package/create-scopeblind-agent) | Scaffold governed agents |
| [@veritasacta/verify](https://npmjs.com/package/@veritasacta/verify) | Offline receipt verifier |
| [acta-sql](https://pypi.org/project/acta-sql/) | Query receipts with SQL (Python) |

## License

MIT — free to use, modify, and redistribute.

## Standards & IP

- **IETF Internet-Draft**: [draft-farley-acta-signed-receipts-00](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) — Signed Decision Receipts for Machine-to-Machine Access Control
- **Patent Status**: Australian provisional patents pending (2025-2026)
- **Compliance**: [SOC 2](https://scopeblind.com/docs/soc2) · [EU AI Act](https://scopeblind.com/docs/eu-ai-act) · [OWASP Agentic Top 10](https://scopeblind.com/docs/owasp)
- **Verification**: MIT-licensed — `npx @veritasacta/verify --self-test`

---

<p align="center">
  Built by <a href="https://github.com/tomjwxf">tomjwxf</a>
</p>
