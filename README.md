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

## Quickstart (30 seconds)

```bash
# 1. Generate an Ed25519 keypair, a config template, and a sample policy.
npx protect-mcp init

# 2. Put a Cedar policy in ./cedar (see "Write a policy" below), then serve
#    the Claude Code hook gate in enforce mode. It runs a restraint self-test
#    first and refuses to start if it cannot prove it denies a forbidden vector.
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
            "command": "npx protect-mcp@0.7.3 evaluate --cedar ./cedar --tool \"$TOOL_NAME\" --input \"$TOOL_INPUT\""
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
            "command": "npx protect-mcp@0.7.3 sign --tool \"$TOOL_NAME\" --receipts ./receipts --key ./keys/gateway.json"
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

Ready-to-use Cedar packs ship in `policies/cedar/` (Clinejection / CVE-2025-6514,
Terraform destroy, secret-file exfiltration, spending authority).

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
