# protect-mcp

Fail-closed Cedar policy gate plus signed receipts for AI agent tool calls.

[![npm version](https://img.shields.io/npm/v/protect-mcp)](https://www.npmjs.com/package/protect-mcp)
[![downloads](https://img.shields.io/npm/dm/protect-mcp)](https://www.npmjs.com/package/protect-mcp)
[![license](https://img.shields.io/npm/l/protect-mcp)](https://www.npmjs.com/package/protect-mcp)
[![node](https://img.shields.io/node/v/protect-mcp)](https://www.npmjs.com/package/protect-mcp)

`protect-mcp` is a gate that sits in front of an AI agent's tool calls. It evaluates
each call against a [Cedar](https://www.cedarpolicy.com/) policy (the same language
AWS uses for IAM), blocks what breaks the rules before it runs, and signs an
offline-verifiable Ed25519 receipt of every decision. It runs locally, sends no
telemetry of your decisions anywhere, and is MIT licensed.

## Why it is different

- **Fail-closed by default.** On any policy error, a missing engine, or an
  evaluation failure, the decision is DENY. The gate never silently allows. An
  observe mode exists for shadow rollout, but even there a call that would be
  blocked is flagged `would_deny: true`, so a failure is never silent.
- **It proves its own restraint.** `serve --enforce` and `doctor` run a startup
  self-test and refuse to arm the gate unless they can show that a known-forbidden
  action is actually denied. A gate that cannot prove it denies does not start.
- **Every decision is a receipt anyone can verify.** Decisions are Ed25519-signed
  and verifiable offline with [`@veritasacta/verify`](https://www.npmjs.com/package/@veritasacta/verify).
  No vendor trust required: the math does not care who runs it.

## Quickstart: install to first useful proof

```bash
# 1. Generate an Ed25519 keypair, config template, and sample policy.
npx protect-mcp init

# 2. Wrap any MCP server in shadow mode. Nothing is blocked yet; calls are logged.
npx protect-mcp wrap -- node your-mcp-server.js

# 3. Inspect the local-only dashboard: tool inventory, risk, approvals, receipts.
npx protect-mcp dashboard --open

# 4. Draft a reviewable policy from observed calls.
npx protect-mcp recommend --write

# 5. When reviewed, restart the wrapper in enforce mode with that policy.
npx protect-mcp --policy protect-mcp.recommended.json --enforce -- node your-mcp-server.js
```

For Claude Desktop, run a dry-run config patch first, then apply it:

```bash
npx protect-mcp wrap --claude-desktop
npx protect-mcp wrap --claude-desktop --write
npx protect-mcp dashboard --open
```

The dashboard binds to `127.0.0.1`, reads only local log/receipt files, and does
not upload anything. Use `npx protect-mcp connect` only if you explicitly want a
hosted ScopeBlind dashboard.

### Local Action Dashboard

`protect-mcp dashboard` is the operator view for moving from visibility to
enforcement:

- **Tool inventory:** every observed tool, call count, high/medium/low risk, and
  whether the active policy has an exact rule, a wildcard fallback, or no rule.
- **Policy coverage:** one-click local policy edits for `Require approval`,
  `Block`, or `Observe`. Restart the wrapper after reviewing changes.
- **Exact-action approval queue:** the exact tool, action, destination, redacted
  payload preview, payload hash, policy basis, and reason capture before a human
  approves, denies, edits, or takes over.
- **Receipt chain:** request ids correlated with signed receipt hashes, so an
  audit reviewer can see which decisions have cryptographic proof.
- **Audit export:** downloads the offline-verifiable audit bundle when signed
  receipts exist. If only unsigned local logs exist, the dashboard explains that
  signing must be enabled first.

For live desktop fallback approvals, start the dashboard with the local gateway
approval endpoint and nonce printed by the wrapper:

```bash
npx protect-mcp dashboard --open \
  --approval-endpoint http://127.0.0.1:9876 \
  --approval-nonce "$PROTECT_MCP_APPROVAL_NONCE"
```

`Approve` forwards to the live local gateway when those flags are present.
`Deny`, `Edit`, and `Take over` are recorded locally as approval-resolution
records; use them as the operator instruction and rerun the tool when needed.

### Paid Boundary MVP: digest anchoring, not data upload

Local self-signed receipts stay free and offline-verifiable. The paid boundary is
independent evidence that ScopeBlind saw a receipt digest at a time, under an org
identity, without receiving the raw prompt, tool payload, output, private key, or
raw receipt.

```bash
# Create or refresh a local org identity and public-key directory.
npx protect-mcp registry init --org "Meridian Global Macro" --billing-account acct_meridian

# Local preview: writes a digest registry and shareable static verifier page.
npx protect-mcp registry anchor

# Hosted mode: uploads receipt digests only for independent anchoring.
SCOPEBLIND_TOKEN=... npx protect-mcp registry anchor \
  --hosted \
  --endpoint https://api.scopeblind.com \
  --verifier-base https://legate.scopeblind.com
```

The local preview is deliberately labeled `local-preview-not-independent`.
Hosted mode anchors only receipt hashes, request ids, org public keys, and
billing metadata. It does not upload raw receipts or sensitive context.

### Killer Demo: shadow to policy to proof

`protect-mcp killer-demo` generates a complete three-minute sales/demo pack:

```bash
npx protect-mcp killer-demo --dir ./scopeblind-demo
```

It creates mock filesystem, GitHub, email, and PMS activity; shows risky calls in
shadow mode; applies a policy pack; requires approval for a sensitive PMS booking;
executes through the gateway; writes a signed receipt; proves the original
receipt verifies; proves a tampered receipt fails; and creates a selective
disclosure package that hides sensitive context while showing the minimum proof.

Open the generated `DEMO-RUNBOOK.md` first. Then run the printed dashboard
command to walk a customer through the exact sequence.

### Selective Disclosure v0

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

### Prove a claim over the record (position-blind attestations)

You can prove a CLAIM over your record without revealing it. Mint a signed,
position-blind attestation over the whole record that discloses only per-decision
categories (a receipt digest, the verdict, capability tags), never your tool
inputs, outputs, or data:

```bash
# "No action reached the network across the record":
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
append-only ScopeBlind transparency log, so a counterparty who does not trust you
can confirm the disclosed set is complete and was not quietly re-cut (only the
hash is sent; the record stays local):

```bash
npx protect-mcp claim --no net.egress --anchor
```

This is an accountable, position-blind attestation, not full zero-knowledge: it
reveals the shape, not the content.

## Claude Code hook quickstart

```bash
# Generate hook config and a sample Cedar policy.
npx protect-mcp init-hooks

# Serve the Claude Code hook gate in enforce mode. It runs a restraint self-test
# first and refuses to start if it cannot prove it denies a forbidden vector.
npx protect-mcp serve --enforce --cedar ./cedar
```

One-shot evaluation, the way a PreToolUse hook calls it. Exit code 2 means deny
(the tool is blocked); exit 0 means allow:

```bash
npx protect-mcp evaluate --cedar ./cedar --tool Bash --input '{"command":"rm"}'
echo $?   # 2  -> denied, fail-closed

npx protect-mcp evaluate --cedar ./cedar --tool Read --input '{"path":"README.md"}'
echo $?   # 0  -> allowed
```

A missing or unloadable policy denies (exit 2) unless you explicitly pass
`--fail-on-missing-policy false`.

## Claude Code hooks

`protect-mcp init-hooks` writes a `.claude/settings.json` for you. To wire the
gate by hand, the two verbs you need are `evaluate` (PreToolUse, blocks on exit 2)
and `sign` (PostToolUse, records a receipt). Pin the version so a Claude Code
session always runs the gate you tested:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "npx protect-mcp@0.9.1 evaluate --cedar ./cedar --tool \"$TOOL_NAME\" --input \"$TOOL_INPUT\""
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "npx protect-mcp@0.9.1 sign --tool \"$TOOL_NAME\" --receipts ./receipts --key ./keys/gateway.json"
          }
        ]
      }
    ]
  }
}
```

`evaluate` exits 2 on deny so Claude Code blocks the tool call, and 0 on allow.
`sign` is best-effort: it appends an Ed25519-signed receipt when a key is
configured, and if no signer is available it records an honest unsigned line
(`"signed": false`) rather than failing the tool.

## Use it in other agents (Codex, Cursor, Gemini, Hermes)

The same fail-closed gate runs as a tool hook in any agent that supports them. Add
`--format <host>` so the verb reads that host's hook payload from stdin and denies
in its contract:

```bash
# the PreToolUse / before-tool command for each host
npx -y protect-mcp@latest evaluate --format codex  --cedar ./cedar   # OpenAI Codex
npx -y protect-mcp@latest evaluate --format gemini --cedar ./cedar   # Gemini CLI BeforeTool
npx -y protect-mcp@latest evaluate --format cursor --cedar ./cedar   # Cursor beforeShellExecution
npx -y protect-mcp@latest evaluate --format hermes --cedar ./cedar   # Hermes pre_tool_call
```

Pair each with `sign --format <host>` on the post-tool event for receipts. The
important case is **Hermes**, which ignores hook exit codes and reads the verdict
from stdout, so `--format hermes` denies via `{"decision":"block"}` rather than
exit 2 (a raw exit-2 would silently fail open there). Without `--format`, the
verbs read `--tool`/`--input` flags exactly as in the Claude Code section above.

## Write a policy

Cedar policies live in a directory you point at with `--cedar`. A `forbid` rule
denies, a `permit` rule allows. To match against a value in the tool input, use
the `.contains()` idiom:

```cedar
// Allow read-only tools.
permit(
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"Read"
);

// Deny dangerous shell commands by matching the command against a list.
forbid(
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"Bash"
) when {
  ["rm", "dd", "mkfs"].contains(context.command)
};

// Block destructive tools outright.
forbid(
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"delete_file"
);
```

> **Hazard:** do NOT write `context.command in ["rm", "dd"]` to match a string
> against a list. `in` is for entity hierarchies, not string membership. Cedar
> treats the expression as a type error and silently discards the whole `forbid`
> rule, which (under a fail-open gate) leaves a residual `permit` standing. This
> is the exact defect behind the advisory below. Use `[...].contains(context.command)`
> instead. From 0.7.0 the gate denies on that error rather than permitting, and a
> CI tripwire test fails the build if the pattern is reintroduced into a shipped
> policy. See [GHSA-hm46-7j72-rpv9](https://github.com/ScopeBlind/scopeblind-gateway/security/advisories/GHSA-hm46-7j72-rpv9).

### Starter policy packs

Most teams should not write Cedar from scratch on day one. Install a starter
pack, run in shadow mode, inspect receipts, then tighten or enforce:

```bash
npx protect-mcp policy-packs list
npx protect-mcp policy-packs show secrets-safe
npx protect-mcp policy-packs install filesystem-safe --dir ./cedar
npx protect-mcp policy-packs install all --dir ./cedar
npx protect-mcp serve --cedar ./cedar
```

Built-in packs:

- `filesystem-safe`: destructive file actions and secret-like path reads.
- `git-safe`: force pushes, hard resets, destructive cleanup, repo deletion.
- `email-safe`: allow drafting, block unattended sends.
- `database-safe`: read-oriented DB posture, block write/admin SQL.
- `cloud-spend-safe`: obvious cloud spend creation and infrastructure destruction.
- `secrets-safe`: common file, env, shell, and cloud secret exfiltration.
- `finance-mandate-safe`: restricted-list and concentration breaches in booking flows.

## Verify a receipt

Receipts are signed and verifiable offline by anyone with the public key. No
network, no vendor, no trust in ScopeBlind:

```bash
npx @veritasacta/verify ./receipts/receipts.jsonl --format jsonl
# Exit 0 = valid, non-zero = tampered or malformed
```

`npx protect-mcp bundle --output audit.json` exports a self-contained,
offline-verifiable audit bundle of your receipts plus the public signing key.

## Security

`protect-mcp` 0.7.0 fails closed by design. On any policy-evaluation error, a
missing engine, or a policy that errored at evaluation, the decision is DENY,
not allow. `serve --enforce` and `doctor` run a boot self-test that proves the
gate denies a known-forbidden vector before it is trusted, and refuse to arm if
it cannot.

**Affected versions: 0.5.x and 0.6.x.** Those lines fail open (they return ALLOW
on evaluation error) and do not evaluate Cedar correctly against the pinned
engine, so a `forbid` rule could fail to block. **Upgrade to >= 0.7.0.**

Details and remediation: [GHSA-hm46-7j72-rpv9](https://github.com/ScopeBlind/scopeblind-gateway/security/advisories/GHSA-hm46-7j72-rpv9).
To report a vulnerability, see [SECURITY.md](./SECURITY.md).

## Commands

| Command | Description |
|---------|-------------|
| `serve` | Start the HTTP hook server for Claude Code (port 9377). `--enforce` runs the restraint self-test first; `--cedar <dir>` and `--policy <path>` select the policy. |
| `init` | Generate an Ed25519 keypair (`keys/gateway.json`), a config template, and a sample policy. |
| `wrap` | Print a protected MCP command or patch Claude Desktop MCP servers. Dry-run by default; use `--write` to update Claude Desktop config. |
| `dashboard` | Start a local-only dashboard on `127.0.0.1` showing tool inventory, risk, policy coverage, exact-action approvals, receipt chains, and audit export. |
| `recommend` | Draft a reviewable JSON policy from observed local calls. Dry-run by default; use `--write` to create `protect-mcp.recommended.json`. |
| `registry` | Create an org identity, anchor receipt digests, and write a static verifier page. Hosted mode uploads digests only. |
| `record` | Open a local, searchable viewer over your receipts (`--live` streams as the agent runs): capability tags, a provenance tree, and one-click signed export. All local, nothing uploaded. |
| `claim` | Mint a signed, position-blind attestation of a predicate over the record (`--no <cap>`, `--only <c1,c2>`, `--no-verdict <verdict>`, `--count <verdict>`), disclosing only decision categories. Add `--anchor` to record the claim digest in the public transparency log. |
| `verify-claim` | Verify a claim pack offline: signature, recomputed Merkle root, and independently recomputed predicate. Reveals the shape, not the content. |
| `killer-demo` | Generate a complete shadow-mode to policy to approval to signed-receipt demo pack. |
| `verify-disclosure` | Verify a `scopeblind.selective_disclosure.v0` package and explain disclosed versus hidden fields. |
| `policy-packs` | List, inspect, and install starter Cedar policy packs. |
| `evaluate` | Evaluate one tool call against a Cedar policy (PreToolUse gate). Exit 2 = deny (fail-closed), exit 0 = allow. |
| `sign` | Sign one tool call into a receipt (PostToolUse). Best-effort: records an honest unsigned line if no key. |
| `simulate` | Dry-run a policy against a recorded decision log to see what it would have blocked. |
| `demo` | Start a built-in demo server wrapped with the gate, to see receipts instantly. |
| `doctor` | Check your setup (keys, policies, Cedar engine, verifier) and run the restraint self-test. |
| `bundle` | Export an offline-verifiable audit bundle of receipts plus the public key. |
| `report` | Generate a compliance report (Markdown or JSON) from the decision log and receipts. |

Run `npx protect-mcp --help` for the full flag reference.

## Links

- Protocol (IETF): [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)
- [CHANGELOG](./CHANGELOG.md)
- [npm](https://www.npmjs.com/package/protect-mcp)
- [scopeblind.com](https://scopeblind.com)

MIT licensed. Built by [ScopeBlind](https://scopeblind.com).
