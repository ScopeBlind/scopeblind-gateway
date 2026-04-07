[![npm version](https://img.shields.io/npm/v/protect-mcp)](https://www.npmjs.com/package/protect-mcp)
[![npm downloads](https://img.shields.io/npm/dm/protect-mcp)](https://www.npmjs.com/package/protect-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![IETF Draft](https://img.shields.io/badge/IETF-draft--farley--acta--signed--receipts--01-blue)](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)
[![MCP Registry](https://img.shields.io/badge/MCP_Registry-com.scopeblind%2Fprotect--mcp-green)](https://registry.modelcontextprotocol.io)
[![PyPI: protect-mcp-adk](https://img.shields.io/pypi/v/protect-mcp-adk?label=protect-mcp-adk)](https://pypi.org/project/protect-mcp-adk/)

# protect-mcp

Enterprise security gateway for MCP servers and Claude Code hooks. Signed receipts, Cedar policies, and swarm-aware audit trails.

**Integrated into [Microsoft Agent Governance Toolkit](https://github.com/AzureAI-Foundry/agent-governance-toolkit/pull/667)** | **[IETF Internet-Draft](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)** | **[Live demo: acta.today/wiki](https://acta.today/wiki)**

## Quick Start — Claude Code

Two commands. Every tool call is receipted.

```bash
# 1. Generate hooks, keys, Cedar policy, and /verify-receipt skill
npx protect-mcp init-hooks

# 2. Start the hook server
npx protect-mcp serve
```

Open Claude Code in the same project. Every tool call is now intercepted, evaluated, and signed.

### What `init-hooks` creates

| File | Purpose |
|------|---------|
| `.claude/settings.json` | Hook config (PreToolUse, PostToolUse, + 9 lifecycle events) |
| `keys/gateway.json` | Ed25519 signing keypair (auto-gitignored) |
| `policies/agent.cedar` | Starter Cedar policy — customize to your needs |
| `protect-mcp.json` | JSON policy with signing + rate limits |
| `.claude/skills/verify-receipt/SKILL.md` | `/verify-receipt` skill for Claude Code |

### Architecture

```
Claude Code  →  POST /hook  →  protect-mcp (Cedar + sign)  →  response
                                    ↓
                            .protect-mcp-log.jsonl
                            .protect-mcp-receipts.jsonl
```

- **PreToolUse**: synchronous Cedar policy check → deny blocks the tool
- **PostToolUse**: async receipt signing → zero latency impact
- **deny is architecturally final** — it cannot be overridden by the model or other hooks

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST   | `/hook` | Claude Code hook endpoint |
| GET    | `/health` | Server status, policy info, signer info |
| GET    | `/receipts` | Recent signed receipts |
| GET    | `/receipts/latest` | Most recent receipt |
| GET    | `/suggestions` | Auto-generated Cedar policy fix suggestions |
| GET    | `/alerts` | Config tamper detection alerts |

### Verify receipts

```bash
# Inside Claude Code:
/verify-receipt

# From terminal:
curl http://127.0.0.1:9377/receipts/latest | jq .
npx protect-mcp receipts

# Check policy suggestions:
curl http://127.0.0.1:9377/suggestions | jq .
```

## Quick Start — MCP Server Wrapper

Wrap any stdio MCP server as a transparent proxy:

```bash
# Shadow mode — log every tool call, enforce nothing
npx protect-mcp -- node my-server.js

# Enforce mode with policy
npx protect-mcp --policy protect-mcp.json --enforce -- node my-server.js

# Generate keys + config template
npx protect-mcp init
```

## How It Works

protect-mcp evaluates every tool call against a policy (JSON, Cedar, or external PDP), signs the decision as an Ed25519 receipt, and logs the result.

**Two integration modes:**

| Mode | Transport | Use Case |
|------|-----------|----------|
| Hook Server | HTTP (`npx protect-mcp serve`) | Claude Code, agent swarms |
| Stdio Proxy | stdin/stdout (`npx protect-mcp -- ...`) | Claude Desktop, Cursor, any MCP client |

**Three policy engines:**

| Engine | Config | Notes |
|--------|--------|-------|
| JSON | `--policy policy.json` | Simple per-tool rules |
| Cedar | `--cedar ./policies/` | Local WASM evaluation via `@cedar-policy/cedar-wasm` |
| External PDP | `policy_engine: "external"` | OPA, Cerbos, or any HTTP PDP |

## Swarm Tracking

In multi-agent sessions, protect-mcp automatically tracks the swarm topology.

**11 hook events handled:**

| Event | Type | Description |
|-------|------|-------------|
| `PreToolUse` | Sync | Cedar/policy evaluation before tool execution |
| `PostToolUse` | Async | Receipt signing after tool execution |
| `SubagentStart` / `SubagentStop` | Lifecycle | Worker agent spawn/completion |
| `TaskCreated` / `TaskCompleted` | Lifecycle | Coordinator task assignment |
| `SessionStart` / `SessionEnd` | Lifecycle | Session lifecycle with sandbox detection |
| `TeammateIdle` | Lifecycle | Agent utilization monitoring |
| `ConfigChange` | Security | Tamper detection for `.claude/settings.json` |
| `Stop` | Lifecycle | Finalization + policy suggestion summary |

Each receipt includes:
- `swarm.agent_id`, `swarm.agent_type`, `swarm.team_name`
- `timing.tool_duration_ms`, `timing.hook_latency_ms`
- `payload_digest` (SHA-256 hash for payloads >1KB)
- `deny_iteration` (retry count after denial)
- `sandbox_state` (enabled/disabled/unavailable)
- OpenTelemetry `otel_trace_id` and `otel_span_id`

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
  }
}
```

### Cedar Policies

Cedar deny decisions are **authoritative** — they cannot be overridden.

```cedar
// Allow read-only tools
permit(
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"Read"
);

// Block destructive tools
forbid(
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"delete_file"
);
```

When a tool is denied, protect-mcp auto-suggests the minimal Cedar `permit()` rule via `GET /suggestions`.

## CVE-Anchored Policy Packs

Each prevents a real attack:

| Policy | Incident | OWASP |
|--------|----------|-------|
| `clinejection.json` | CVE-2025-6514: MCP OAuth proxy hijack (437K environments) | A01, A03 |
| `terraform-destroy.json` | Autonomous Terraform agent destroys production | A05, A06 |
| `github-mcp-hijack.json` | Prompt injection via crafted GitHub issue | A01, A02, A03 |
| `data-exfiltration.json` | Agent data theft via outbound tool abuse | A02, A04 |
| `financial-safe.json` | Unauthorized financial transaction | A05, A06 |

Cedar equivalents available in `policies/cedar/`.

## MCP Client Configuration

### Claude Desktop

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

## CLI Commands

```
Commands:
  serve             Start HTTP hook server for Claude Code (port 9377)
  init-hooks        Generate Claude Code hook config + skill + sample Cedar policy
  quickstart        Zero-config onboarding: init + demo + show receipts
  init              Generate Ed25519 keypair + config template
  demo              Start a demo server wrapped with protect-mcp
  doctor            Check your setup: keys, policies, verifier, connectivity
  trace <id>        Visualize the receipt DAG from a given receipt_id
  status            Show tool call statistics from the decision log
  digest            Generate a human-readable summary of agent activity
  receipts          Show recent persisted signed receipts
  bundle            Export an offline-verifiable audit bundle
  simulate          Dry-run a policy against recorded tool calls
  report            Generate a compliance report from an audit bundle

Options:
  --policy <path>   Policy/config JSON file
  --cedar <dir>     Cedar policy directory
  --enforce         Enable enforcement mode (default: shadow)
  --port <port>     HTTP server port (default: 9377 for serve)
  --verbose         Enable debug logging
```

## Decision Logs

Every tool call emits structured JSON to `stderr`:

```json
[PROTECT_MCP] {"v":2,"tool":"read_file","decision":"allow","reason_code":"cedar_allow","policy_digest":"a1b2c3...","mode":"enforce","hook_event":"PreToolUse","timing":{"hook_latency_ms":1},"otel_trace_id":"..."}
```

When signing is configured, a signed receipt is persisted to `.protect-mcp-receipts.jsonl`.

## Audit Bundles

```bash
npx protect-mcp bundle --output audit.json
```

Self-contained offline-verifiable bundle with receipts + signing keys. Verify with `npx @veritasacta/verify`.

## Verified Knowledge Base (acta.today/wiki)

protect-mcp's receipt signing powers the world's first verified multi-model knowledge base at [acta.today/wiki](https://acta.today/wiki).

Every Knowledge Unit is produced by 4 frontier models deliberating in 3 adversarial rounds, with Ed25519 receipts on every model response. The current roster:

| Model | Provider | Origin |
|-------|----------|--------|
| Claude Opus 4.6 | Anthropic | US |
| GPT-5.4 | OpenAI | US |
| Grok 4.20 | xAI | US |
| Gemini 3.1 Pro | Google | US |
| DeepSeek V3.2 | DeepSeek | CN |
| MiniMax M2.7 | MiniMax | CN |
| Kimi K2.5 | Moonshot | CN |
| Qwen 2.5 72B | Alibaba | CN |

Every KU is independently verifiable: `npx @veritasacta/verify receipt.json`

## Ecosystem Integrations

| Project | Stars | Integration | Status |
|---------|-------|-------------|--------|
| [Microsoft Agent Governance Toolkit](https://github.com/AzureAI-Foundry/agent-governance-toolkit) | 600+ | Cedar policy bridge + receipt signing | Merged (PR #667) |
| [Mission Control](https://github.com/builderz-labs/mission-control) | 3,700+ | Ed25519 receipt signing for MCP audit pipeline | PR #556 submitted |
| [Assay](https://github.com/Rul1an/assay) | — | Signed receipts as evidence source | Active discussion (#1029) |
| [Hermes Agent](https://github.com/NousResearch/hermes-agent) | 24,500+ | Cryptographic audit trail for skill execution | Issue #5041 |
| [DeerFlow](https://github.com/bytedance/deer-flow) | 57,600+ | Cryptographic integrity for persistence layer | Discussion #1855 |
| [Pro-Workflow](https://github.com/rohitg00/pro-workflow) | 1,500+ | MCP config recommendation | PR #41 |
| [Zeroshot](https://github.com/covibes/zeroshot) | 1,400+ | Cryptographic receipts for validator verdicts | Issue #464 |

## Standards & IP

- **IETF Internet-Drafts**:
  - [draft-farley-acta-signed-receipts-01](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/) — Signed Decision Receipts for Machine-to-Machine Access Control
  - [draft-farley-acta-knowledge-units-00](https://datatracker.ietf.org/doc/draft-farley-acta-knowledge-units/) — Knowledge Units for Multi-Model Deliberation
  - Source: [VeritasActa/drafts](https://github.com/VeritasActa/drafts)
- **Patent Status**: 4 Australian provisional patents pending (2025-2026) covering decision receipts with configurable disclosure, tool-calling gateway, agent manifests, and portable identity
- **Verification**: Apache-2.0 — `npx @veritasacta/verify --self-test`
- **Microsoft AGT Integration**: [PR #667](https://github.com/microsoft/agent-governance-toolkit/pull/667) — Cedar policy bridge for Agent Governance Toolkit

## Related Repositories

| Repository | Description |
|-----------|-------------|
| [VeritasActa/Acta](https://github.com/VeritasActa/Acta) | Open protocol for contestable public records (Apache-2.0) |
| [VeritasActa/drafts](https://github.com/VeritasActa/drafts) | IETF Internet-Draft source files |
| [ScopeBlind/examples](https://github.com/ScopeBlind/examples) | Integration examples: Claude Code hooks, Express API, MCP server signing |
| [@veritasacta/verify](https://www.npmjs.com/package/@veritasacta/verify) | Offline receipt verifier (Apache-2.0) |
| [@scopeblind/passport](https://www.npmjs.com/package/@scopeblind/passport) | Agent identity SDK (Apache-2.0) |
| [protect-mcp-adk](https://pypi.org/project/protect-mcp-adk/) | Google ADK receipt signing plugin (MIT, Python) |

## Contributing

Issues and pull requests are welcome. Please open an issue first for significant changes.

- **Bug reports**: Include the protect-mcp version, Node.js version, and steps to reproduce
- **Cedar policies**: Share reusable policies via PR to the `policies/cedar/` directory
- **Integration examples**: Add to [ScopeBlind/examples](https://github.com/ScopeBlind/examples)

## License

MIT — free to use, modify, distribute, and build upon without restriction.

[scopeblind.com](https://scopeblind.com) · [npm](https://www.npmjs.com/package/protect-mcp) · [veritasacta.com](https://veritasacta.com) · [IETF Drafts](https://github.com/VeritasActa/drafts)
