# protect-mcp

Local policy enforcement and signed decision receipts for AI agent tool calls.

[![npm version](https://img.shields.io/npm/v/protect-mcp)](https://www.npmjs.com/package/protect-mcp)
[![Package checks](https://github.com/ScopeBlind/scopeblind-gateway/actions/workflows/validate-release.yml/badge.svg)](https://github.com/ScopeBlind/scopeblind-gateway/actions/workflows/validate-release.yml)
[![MIT license](https://img.shields.io/npm/l/protect-mcp)](LICENSE)

Put the gateway between an MCP client and its tool server, or use its hooks in a
coding agent. Review a [Cedar](https://www.cedarpolicy.com/) policy, enable
enforcement, and keep a signed record of the decisions. Local evaluation and
verification need no ScopeBlind account and send no decision telemetry.

- **Enforce at the tool boundary.** Cedar denies on missing policies, engine
  errors or evaluation errors in fail-closed mode. Shadow mode is the default
  for the MCP wrapper: use `--enforce` when ready to block.
- **Check what was signed.** Ed25519 receipts include the decision and policy
  digest. A separate verifier checks the bytes against the public key you trust.
- **Start with existing tools.** Use MCP stdio, the HTTP gateway or coding-agent
  hooks. Optional [hosted collaboration](docs/hosted-coordination.md) has its own
  permissions and data flows.

A gateway covers calls routed through it. It is not an OS sandbox, and a signed
receipt does not establish that an action executed or that no action was omitted.
The [security policy](SECURITY.md) describes the boundary and reporting process.

## Try it without an agent

Use Node.js 22 and npm in a new directory. Install the pinned gateway and verifier:

```sh
mkdir protect-mcp-demo
cd protect-mcp-demo
npm init -y
npm install --save-exact protect-mcp@0.31.1 @veritasacta/verify@0.10.27
```

This example evaluates two proposed calls and signs their decisions. It does not
execute either tool or run `git push`. Everything after installation is local.

<!-- readme-smoke:start -->
```sh
# Create a starter policy and a private signing key.
npx --no-install protect-mcp init --starter

# A normal read is allowed; a force-push to main is denied (exit 2).
npx --no-install protect-mcp evaluate --policy ./protect.cedar --tool Read --input '{"path":"README.md"}'
npx --no-install protect-mcp evaluate --policy ./protect.cedar --tool Bash --input '{"command":"git push --force origin main"}' || test "$?" -eq 2

# Evaluate again at signing time and record both decisions, in order.
npx --no-install protect-mcp sign --cedar builtin:starter --tool Read --input '{"path":"README.md"}' --key ./protect-mcp.key --receipts ./receipts
npx --no-install protect-mcp sign --cedar builtin:starter --tool Bash --input '{"command":"git push --force origin main"}' --key ./protect-mcp.key --receipts ./receipts

# Take only the public key from the key you generated, not from the receipt.
PROTECT_MCP_PUBLIC_KEY=$(node -p 'JSON.parse(require("fs").readFileSync("protect-mcp.key", "utf8")).publicKey')
npx --no-install verify --replay-chain ./receipts/receipts.jsonl --key "$PROTECT_MCP_PUBLIC_KEY" --json

# Change the signed deny to allow. The original receipt log stays intact.
node -e 'const fs=require("fs");const r=JSON.parse(fs.readFileSync("receipts/receipts.jsonl","utf8").trim().split("\n")[1]);r.payload.decision="allow";fs.writeFileSync("tampered.json",JSON.stringify(r))'
npx --no-install verify tampered.json --key "$PROTECT_MCP_PUBLIC_KEY" --json || test "$?" -eq 1
```
<!-- readme-smoke:end -->

Expected: `allow`, then `deny`; both original receipt signatures and their link
verify; the modified receipt reports `invalid_signature`. Keep `protect-mcp.key`
private. To verify someone else's record, obtain their expected public key
through an independent trusted channel.

Verifier exit codes are **0: valid**, **1: invalid**, **2: not checked/error**.
An invalid result is not necessarily tampering: the wrong expected key can also
fail verification. Chain replay checks the supplied links; it does not establish
that you received the entire history.

CI runs this exact example against the packed candidate and the pinned published
verifier. See [validation and releases](docs/releases.md).

## Connect your agent

Choose the integration that matches your host:

| Use case | Start here |
|---|---|
| Wrap an existing MCP server | [MCP setup and shadow-to-enforce workflow](docs/local-gateway.md#connect-your-mcp-server) |
| Claude Code hooks | [Hook setup](docs/local-gateway.md#claude-code-hook-quickstart) |
| Codex, Cursor, Gemini or Hermes hooks | [Host payload formats](docs/local-gateway.md#use-it-in-other-agents-codex-cursor-gemini-hermes) |
| Call the policy evaluator as MCP tools | [The gate as an MCP server](docs/local-gateway.md#the-gate-as-an-mcp-server) |
| Host an HTTP gateway | [HTTP deployment notes](docs/CLOUD-QUICKSTART.md) |

For an existing MCP server, initialize its configuration in a separate directory
from the example above, then run the wrapper with your server command:

```sh
npx --yes protect-mcp@0.31.1 init
npx --yes protect-mcp@0.31.1 --policy ./protect-mcp.json -- node your-mcp-server.js
```

This starts in **shadow mode**. Review the observed calls and policy before
adding `--enforce`. `wrap` prints client configuration and exits; it is not the
launch command. [Full setup instructions](docs/local-gateway.md).

Starter shell rules inspect command text. They are useful guardrails, but can
miss alternate command spellings and can match harmless quoted text. Review the
[starter policy's coverage and limits](docs/local-gateway.md#start-with-the-starter-policy)
before relying on it.

## Documentation

- [Local gateway guide](docs/local-gateway.md): policies, hooks, dashboard,
  credentials and receipt compatibility.
- [Receipt and disclosure guide](docs/receipts.md): local records, selective
  disclosure and optional hosted digest anchoring.
- [Command reference](docs/commands.md).
- [Hosted coordination](docs/hosted-coordination.md): separate human approvals,
  invoice sandbox and repository review workflows.
- [Release validation and provenance](docs/releases.md).
- [Changes by version](CHANGELOG.md).

## Contribute

Bug reports, minimal reproductions, documentation fixes and compatibility tests
are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and checks, and
[GOVERNANCE.md](GOVERNANCE.md) for maintainership. Report vulnerabilities privately
through [SECURITY.md](SECURITY.md), not a public issue.

The [shared conformance corpus](https://github.com/ScopeBlind/agent-governance-testvectors)
records compatibility results across receipt producers. A passing corpus is
bounded interoperability evidence, not a security certification.

MIT licensed; see [LICENSE](LICENSE) and the existing [patent notice](PATENTS.md).
Maintained by [Tom Farley](https://github.com/tomjwxf) at
[ScopeBlind](https://scopeblind.com). Receipt format:
[Acta individual Internet-Draft](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/).
