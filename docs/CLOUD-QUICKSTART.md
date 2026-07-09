# Gate a cloud agent in 5 minutes

Cloud agent platforms give you agents in someone else's cloud, with the
vendor's access controls and the vendor's logs. Both live inside one trust
boundary: the platform grades its own homework. This guide puts a policy
gate you control between any cloud agent and its tools, so every tool call
is evaluated against your policy and every decision (including every
denial) becomes a signed receipt that verifies offline, with no trust in
the platform or in us.

Requires protect-mcp >= 0.10.1. Works with any agent that accepts a custom
MCP server URL (Streamable HTTP), which is the norm for cloud agent
platforms.

## 1. One-time setup (30 seconds)

In an empty directory on any Node 18+ host (a VM, a container in your VPC,
your laptop):

```bash
npx -y protect-mcp@latest init
mkdir -p cedar && cat > cedar/mandate.cedar <<'EOF'
// Allow everything except destructive tools.
permit(principal, action == Action::"MCP::Tool::call", resource);
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"delete_file");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"deploy");
EOF
```

`init` generates your signing key (`keys/gateway.json`) and config. The
Cedar file is your mandate: edit the tool names to match the tools your
agent actually uses (`protect-mcp policy deny <ToolName>` appends rules
for you).

## 2. Start the gate (one command)

The gate wraps your real MCP tool server and serves it over Streamable
HTTP. Everything after `--` is the command that starts the server being
wrapped:

```bash
npx -y protect-mcp@latest --http --port 3000 --enforce -- npx -y @modelcontextprotocol/server-filesystem /data
```

Or containerized, same thing:

```bash
docker run --rm -p 3000:3000 -v "$PWD":/gate -w /gate node:22-alpine \
  npx -y protect-mcp@latest --http --port 3000 --enforce -- npx -y @modelcontextprotocol/server-filesystem /data
```

Startup logs confirm the posture; if you do not see both lines, the gate
is not doing its job:

```
[PROTECT_MCP] Cedar policy engine: loaded 1 policies from cedar (digest: sha256:...)
[PROTECT_MCP] Signing config loaded from protect-mcp.json (receipts enabled)
```

To wrap a tool server that is itself remote, bridge it as the child:
`-- npx -y mcp-remote https://your-upstream-server.example/mcp`.

## 3. Point your cloud agent through the gate

In your agent platform's MCP settings, register the gate's URL instead of
the tool server's:

```
https://<your-gate-host>:3000/mcp
```

That is the whole integration. The agent sees the same tools; every call
now passes through your policy first. Allowed calls forward to the real
server. Forbidden calls come back as errors before they execute:

```
Tool "delete_file" denied by Cedar policy
```

## 4. The evidence

Every decision appends a signed receipt to `.protect-mcp-receipts.jsonl`
in the gate's working directory: a draft-farley-acta-signed-receipts-02
envelope, Ed25519 over the canonical payload, hash-chained to the previous
line so omission is detectable, carrying the digest of the exact policy in
force. Denials are receipts too; that is the point. A log that only
records what an agent did cannot show that the controls ever fired.

## 5. Verify offline, with our code nowhere in the loop

```bash
npx -y @veritasacta/verify --replay-chain .protect-mcp-receipts.jsonl \
  --key "$(node -p "JSON.parse(require('fs').readFileSync('keys/gateway.json')).publicKey")"
```

The verifier is a separate open package: it re-derives every signature
from the receipt bytes and your published public key, recomputes every
chain link, and exits nonzero on any tamper, reorder, or omission. Hand
the jsonl file and the public key to an auditor and they can run the same
command with no access to your gate, your agent platform, or us.

To let a third party confirm which policy governed the decisions, publish
the policy bundle the receipts commit to:

```bash
npx -y protect-mcp@latest policy publish
```

This writes `.well-known/acta-policies/<digest>.json`: the exact policy
bytes plus the preimage spec, addressed by the same `policy_digest` the
receipts carry, recomputable from the bundle bytes alone. Host it on your
domain. (Live example: `https://legate.scopeblind.com/.well-known/acta-policies/`.)

## What this does and does not prove

A valid receipt chain proves which tool calls your policy allowed and
denied, under exactly which policy, signed at decision time by a key you
control, with no gaps. It does not prove the allowed calls' side effects
were safe, and it cannot see tool calls that bypass the gate: routing ALL
of the agent's tool access through the gate is your deployment's job.
`--enforce` refuses to run permissive when the policy fails to load; in
shadow mode (the default without `--enforce`) violations are logged and
receipted but not blocked.

Every command above was executed end to end against a live gate before
this document was written: one allow, one deny, chained receipts, replayed
offline with zero chain breaks.
