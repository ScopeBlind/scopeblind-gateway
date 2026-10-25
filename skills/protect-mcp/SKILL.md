---
name: protect-mcp
description: >
  Configure or troubleshoot protect-mcp's local Cedar policy gate and verify
  its signed receipts. Use for protect-mcp setup, its MCP wrapper or coding-agent
  hooks, and verification of protect-mcp records; not for general security,
  compliance or audit requests.
allowed-tools:
  - Bash
  - Read
---

# protect-mcp

protect-mcp evaluates tool calls routed through it against Cedar policies and
can sign the resulting decision records. A receipt authenticates signed bytes
under the expected key. It does not establish that a tool executed, that the
record includes every action, or that the signer was entitled to approve it.

## Choose the installation path

If this skill came from the enabled protect-mcp plugin, follow the
[plugin setup](../../docs/claude-plugin.md). The plugin already registers its
hooks. Do not run `init-hooks` as well: duplicate hooks create duplicate
decisions. Start its local gate from the intended project, then verify a real
host call. Require Claude Code 2.1.295 or later for blocking hook failures.

For a standalone project installation without the plugin, use the steps below.
Do not change the user's existing installation path without checking it first.

## Set up standalone Claude Code hooks

Run from the intended project directory. Inspect existing configuration before
changing it, and preserve the user's policy and signing keys.

```sh
npx --yes protect-mcp@0.32.3 init-hooks --dry-run
npx --yes protect-mcp@0.32.3 init-hooks
npx --yes protect-mcp@0.32.3 doctor
```

The installer merges its HTTP hooks into `.claude/settings.json`. It creates
`policies/agent.cedar`, `keys/gateway.json` and `protect-mcp.json` when absent,
and records which hook entries it owns. Existing policies and keys are kept.
The starter allows calls except for its named forbid rules; read and adapt it
before relying on it. Cedar is an authorization policy engine, not AWS IAM.

Start the server in a terminal that stays open:

```sh
npx --yes protect-mcp@0.32.3 serve --enforce --cedar ./policies --policy ./protect-mcp.json
```

Reload the project's hooks in Claude Code, then make a harmless tool call such
as reading `README.md`. Check that a new event appears in the local record.
`doctor` checks local configuration and the installed evaluator; a passing
result does not establish that the host loaded or invoked its hooks. HTTP-hook
failure behavior also depends on the host. Keep its native permissions enabled.

For an existing MCP server, use the separate [MCP wrapper guide](../../docs/local-gateway.md#connect-your-mcp-server).
`wrap` prints configuration and exits; the launch command is
`protect-mcp [options] -- <server-command>`. Do not install additional hooks or
hosted integrations when the user asked only to verify an existing record.

To remove the installed hook entries:

```sh
npx --yes protect-mcp@0.32.3 init-hooks --uninstall
```

Uninstall removes unchanged entries tracked by the installer. It preserves
custom edits, policies, keys and recorded evidence; inspect its report.

## Verify records

For the HTTP hook setup above, `.protect-mcp-log.jsonl` is the decision log and
`.protect-mcp-receipts.jsonl` contains receipts. A command-hook setup using
`sign --receipts ./receipts` instead writes `./receipts/receipts.jsonl`.
Identify the actual producer and paths before choosing the input.

Obtain the **expected public key independently of the supplied receipt**. For
the user's own local setup, read only the public member of the key they generated:

```sh
PROTECT_MCP_PUBLIC_KEY=$(node -p 'JSON.parse(require("node:fs").readFileSync("keys/gateway.json", "utf8")).publicKey')
npx --yes @veritasacta/verify@0.11.0 --replay-chain .protect-mcp-receipts.jsonl --key "$PROTECT_MCP_PUBLIC_KEY" --json
```

For someone else's receipts, use the key obtained through a separate trusted
channel. Never accept an embedded key as its own authority or print the private
key file. For one receipt, replace `--replay-chain <log>` with its JSON filename.

The first `npx` invocation may download the verifier. Once installed, verification
is local and needs no ScopeBlind account. Exit codes: **0 valid, 1 invalid,
2 not checked/error**. Explain an unavailable key or malformed input as such;
do not turn an error into a tampering claim.

Current receipts have a signed `payload` and a separate `signature` object.
Preserve their original bytes and historical formats. Report the checks actually
performed, the expected key, and any unsigned or unsupported entries. Valid
chain links do not prove that the supplied history is complete.

## Policy changes

Use the project's actual Cedar action model. Runtime policies normally use
`Action::"MCP::Tool::call"` and `Tool::"<tool-name>"`, with arguments under
`context.input`. Some conformance examples instead require `--action-model tool`.
Test a permitted input, a denied input and a harmless look-alike before applying
a new rule. Shell string matching is a guardrail, not process isolation.

## References

- [Local setup, policies and supported hook formats](../../docs/local-gateway.md)
- [Command reference](../../docs/commands.md)
- [Receipt format and disclosure](../../docs/receipts.md)
- [Security boundary and private reporting](../../SECURITY.md)
- [Acta individual Internet-Draft](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)
