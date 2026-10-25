# Local gateway guide

[Back to the quickstart](../README.md) · [Command reference](commands.md)

## Connect your MCP server

```bash
# 1. Generate an Ed25519 keypair, config template, and sample policy.
npx protect-mcp init

# 2. Print a shadow-mode client configuration, then apply it in your MCP host.
#    This command prints configuration and exits; it does not launch the server.
npx protect-mcp wrap -- node your-mcp-server.js

# 3. Reopen the host and use its tools, then inspect the local-only dashboard.
npx protect-mcp dashboard --open

# 4. Draft a reviewable policy from observed calls.
npx protect-mcp recommend --write

# 5. When reviewed, restart the wrapper in enforce mode with that policy.
npx protect-mcp --policy protect-mcp.recommended.json --enforce -- node your-mcp-server.js
```

In enforce mode the wrapper refuses to start when the policy configures signing
but `keys/gateway.json` is missing or unreadable, and refuses any allowed call
whose receipt cannot be signed. `init` writes the key 0600; for a key made by an
earlier version, run `chmod 600 keys/gateway.json`.

For Claude Desktop, run a dry-run config patch first, then apply it:

```bash
npx protect-mcp wrap --claude-desktop
npx protect-mcp wrap --claude-desktop --write
npx protect-mcp dashboard --open
```

The dashboard binds to `127.0.0.1`, reads only local log/receipt files, and does
not upload anything. Use `npx protect-mcp connect` only if you explicitly want a
hosted ScopeBlind dashboard.

## The gate as an MCP server

If you would rather call the gate as tools than wire the Claude Code hooks, run
it as an MCP server:

```bash
npx protect-mcp mcp
```

It speaks MCP over stdio and exposes four tools that evaluate and produce
artifacts without executing the proposed actions:

- **`evaluate_action`**: decide a proposed tool call against an inline Cedar policy, fail-closed (any policy error is DENY). Returns `{ allowed, decision, reason, policy_digest }`.
- **`sign_decision`**: turn a decision into an Ed25519 signed receipt (a denial signs a `gateway_restraint`, an allow a `decision_receipt`). Returns the receipt and its public key; generates an ephemeral key if you do not supply one.
- **`verify_receipt`**: verify a signed receipt offline against a public key. Returns `{ valid, error, type, kid, issuer }`.
- **`self_test`**: prove it, no inputs. A known-forbidden action is denied, then a signed receipt round-trips and a tampered copy fails.

Point any MCP host at it, for example Claude Desktop:

```json
{
  "mcpServers": {
    "protect-mcp": { "command": "npx", "args": ["-y", "protect-mcp", "mcp"] }
  }
}
```

Receipts are byte-compatible with the ones the gate signs at runtime, so a
receipt minted here uses the same Acta envelope. Verification capabilities and
canonicalization compatibility depend on the verifier version; use the gateway's
`verifyReceipt` API for the conformance behavior described below.

### Receipt canonicalization compatibility

This source tree fixes the integer-key ordering defect present through 0.14.0: signatures and
chain hashes now use direct JCS member emission, retaining the gateway's ASCII
object-key profile. Numeric-looking keys such as `"10"` precede `"2"`, including
inside nested objects. Non-JSON values and invalid Unicode are rejected.

Ordinary JSON receipts whose encodings are unchanged continue to verify.
Historical receipts signed with the old numeric-key order are reported as
`legacy_non_jcs_signature`; strict verification does not call them valid JCS.
For an explicit historical compatibility check, use
`verifyReceipt(receipt, publicKey, { allowLegacyNumericKeys: true })` and inspect
the `canonicalization` and `warning` fields. Its `hash` is then the original
historical hash. Preserve original receipts and chain links: recomputing an old
numeric-key receipt with `receiptHash` now produces its JCS hash and can break
the historical chain. These changes are included in `0.15.0`.
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

The dashboard answers only requests addressed to 127.0.0.1 or localhost on its
port, and accepts a change only from its own page: the same origin, a JSON body
and the per-launch token the page carries. A script that posted to its API must
send the same.
## Explore a labelled sample record

Create a local sample record, then inspect and verify it with your own copy of
the tools:

```bash
npx protect-mcp sample     # seed a labeled sample record (8 decisions: 1 blocked, 2 payments)
npx protect-mcp record     # open it: signatures verified in your browser

npx protect-mcp claim --payment-under 100 --output payments-under-100.json
npx protect-mcp verify-claim payments-under-100.json
```

Drop the generated `demo-tampered.jsonl` into the record page to watch a
post-signing edit get caught. `sample` refuses to touch an existing record, so
run it in an empty folder. When you are ready for the real thing, wire the gate
below and the same commands run against your agent's own record.

## Start with the starter policy

Most coding-agent setups want the same few things blocked and everything else
left alone. `init --starter` writes that policy to `./protect.cedar` and creates
the signing key the Claude Code plugin's receipts use:

```bash
npx protect-mcp@0.32.2 init --starter
```

It writes `protect.cedar` (never over an existing one without `--force`),
creates `protect-mcp.key` (an Ed25519 key, mode 0600, never replaced, even with
`--force`), lists the key in `.gitignore`, and prints the rules in plain words.
The starter is seven forbid rules over a default allow, each with an `@id` and
an `@reason`:

| Rule | Blocks |
|---|---|
| `starter.delete-root-or-home` | `rm -rf` or `rm -fr` of `/`, `/*`, `~`, `~/*`, `$HOME` or `..`, with the target straight after the flags |
| `starter.force-push-main` | a force-push to `main` or `master` (after `origin`, as `+main` or as `HEAD:main`), or one that names no branch |
| `starter.read-secret-file` | Read of `.env*`, `~/.ssh`, `~/.aws`, `.netrc`, `.npmrc`, docker, kube and gh credentials, `~/.gnupg` or the signing key; not `*.pub` or `*.example` |
| `starter.grep-secret-path` | Grep inside `.env*`, `~/.ssh` or `~/.aws` |
| `starter.shell-reads-secret` | `cat`, `grep`, `head`, `tail` or six other readers, in a line that names `.env`, an SSH key or a credential file |
| `starter.pipe-network-to-shell` | `curl` or `wget` into `sh`, `bash` or `zsh`, or `bash <(curl`, `sh -c "$(curl`, `eval "$(curl` |
| `starter.write-sensitive-location` | writes to system folders, shell profiles, LaunchAgents, `~/.ssh`, `~/.aws`, credential files, Claude and Codex settings, `protect.cedar`, the signing key, or through `/../` |

The text ships as [`policies/starter.cedar`](../policies/starter.cedar) and is
yours to edit. Shell rules match the raw command text with Cedar `like`, so they
are a guardrail for an agent working in good faith, not a sandbox. They can fire
on text that only mentions a command (a heredoc body, a commit message), and a
reworded command gets past them: `rm -r -f`, a variable or glob target,
`find -delete`, another remote name, a secret read by another program. Keychain
and token lookups are not covered, and nothing is held for a person: a rule
denies.

To use it without a file, name it as a built-in:

```bash
npx protect-mcp@0.32.2 evaluate --policy builtin:starter --tool Bash \
  --input '{"command":"git push --force origin main"}'
echo $?   # 2
```

`builtin:starter` evaluates the bundled text, and its `policy_digest` is the one
`--policy ./protect.cedar` reports for a file with the same bytes, so receipts
read the same either way. `evaluate --cedar builtin:starter` and `sign --cedar
builtin:starter` take it too; `serve` and the MCP gateway read a policy
directory, so give them the file `init --starter` writes or the
`coding-starter` pack. Versions before 0.31.0 read the name as a missing file
and deny every call, so pin `protect-mcp@0.31.0` or later wherever you use it. The same text is the `coding-starter` policy pack, the policy `init-hooks`
writes, and an `onboard` scenario.

### Keep writes inside this folder (`--contain`)

```bash
npx protect-mcp@0.32.2 init --starter --contain
```

adds two opt-in rules with this folder's absolute path filled in and escaped
for Cedar. `starter.write-outside-project` blocks Write, Edit and MultiEdit
outside the folder, `/tmp`, `/var/folders` and Claude's memory and plans.
`starter.delete-outside-project` blocks an `rm -rf` whose first target is an
absolute path, `~/` or `$HOME/` outside them. They are opt-in because a folder
is not a project for anyone who works across worktrees. The delete rule checks
only the first target after `rm -rf`. `--contain` refuses `/` and the home
folder as a project; add `--force` to rewrite an existing `protect.cedar`.

### Deny reasons name the rule

A deny names each forbid rule that matched, by its `@id`, with its `@reason`:

```
protect-mcp denied: cedar_deny: starter.force-push-main: Force-push to main or master, or a force-push that names no branch. Push a named feature branch instead.
```

On a deny, `evaluate` writes that one line to stderr in every mode, flag mode
(`--policy ... --tool ... --input ...`) included, and exits 2 (with `--format
hermes` the verdict is on stdout and the exit is 0, as Hermes expects). The same
`reason` is in the JSON on stdout, and in the receipt when `sign --cedar`
records the decision. Claude Code shows the agent a hook's stderr, so the agent
learns which rule stopped it and can change its plan. A
rule without an `@id` is named by Cedar's position for it (`policy2`), and a
call no rule permitted reads `cedar_deny: no permit matched (default deny)`.
Give your own rules an `@id` and an `@reason`:

```cedar
@id("team.no-prod-deploy")
@reason("Production deploys go through the release pipeline. Open a pull request instead.")
forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash")
when { context has input && context.input has command && context.input.command like "*deploy --prod*" };
```

### How a policy sees numbers

Cedar has no null, no fractions and no integers beyond 64 bits, and before
0.31.0 a call whose input carried one (`{"coordinate":[100.5,200]}`,
`"zoom":1.5`, a `null`) was denied under every policy, permit-all included.
The gate now makes the input Cedar-safe before Cedar sees it:

- A whole number inside Cedar's 64-bit range stays a number, so
  `context.input.amount > 1000` decides as before.
- Any other number becomes the text JavaScript writes for it: `1.5` is `"1.5"`,
  `0.5` is `"0.5"`, `1e20` is `"100000000000000000000"`.
- A `null` is dropped, in a record or a list, so `context.input has offset` is
  false for `"offset": null`.
- `__entity`, `__extn` and `__expr` keys are dropped, so tool input is never
  read as a Cedar entity reference or extension value.

Match a fraction as text (`context.input.zoom == "1.5"`), or compare it with
`decimal(context.input.zoom).greaterThan(decimal("1.25"))` when it has at most
four decimal places. A numeric comparison on it (`context.input.zoom > 1`) is a
policy error, and the gate denies on any policy error. A whole number written
with a decimal point (`100.0`) is a whole number to JavaScript and stays a
number. A receipt's input digest is still computed over the input as the agent
sent it, not over the Cedar-safe copy.

## Claude Code hook quickstart

```bash
# Generate hook config and the starter policy (policies/agent.cedar).
npx protect-mcp init-hooks

# Serve the Claude Code hook gate in enforce mode. It runs a restraint self-test
# first and refuses to start if it cannot prove it denies a forbidden vector.
npx protect-mcp serve --enforce --cedar ./policies
```

One-shot evaluation, the way a PreToolUse hook calls it. Exit code 2 means deny
(the tool is blocked); exit 0 means allow:

```bash
npx protect-mcp evaluate --cedar ./policies --tool Bash --input '{"command":"git push --force origin main"}'
echo $?   # 2  -> denied, fail-closed

npx protect-mcp evaluate --cedar ./policies --tool Read --input '{"path":"README.md"}'
echo $?   # 0  -> allowed
```

A missing or unloadable policy denies (exit 2) unless you explicitly pass
`--fail-on-missing-policy false`.

## Claude Code hooks

`protect-mcp init-hooks` writes a `.claude/settings.json` for you. To wire the
gate by hand, the two verbs you need are `evaluate` (PreToolUse, blocks on exit 2)
and `sign` (PostToolUse, records a receipt). Claude Code hands a hook the call
as JSON on stdin and sets no `TOOL_NAME` or `TOOL_INPUT` variables, so pass
`--format claude` and nothing else about the call: the gate reads `tool_name`
and `tool_input` from the payload, and on a deny it returns the reason to the
model as `hookSpecificOutput.permissionDecisionReason` as well as exit 2. Pin
the version so a Claude Code session always runs the gate you tested:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "npx protect-mcp@0.32.2 evaluate --cedar ./cedar --format claude"
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
            "command": "npx protect-mcp@0.32.2 sign --format claude --receipts ./receipts --key ./keys/gateway.json"
          }
        ]
      }
    ]
  }
}
```
### Sign the policy decision itself

From 0.13.0, `sign` can evaluate the policy and record the real decision in the
receipt instead of an unconditional allow. Pass the policy directory and the
same input and context the hook would pass to `evaluate`:

```bash
npx protect-mcp@0.32.2 sign --cedar ./cedar --tool Bash \
  --input '{"command":"rm -rf /"}' --context '{"command_pattern":"rm -rf"}' \
  --receipts ./receipts --key ./keys/gateway.json
```

Without `--receipts`, the receipt joins the gateway's own log (`.protect-mcp-receipts.jsonl` in `--dir`), so a deployment has one chain and `record` shows every decision; `--receipts <dir>` keeps a separate `receipts.jsonl`.

The receipt payload then carries `decision` (allow or deny), `reason`
(`cedar_allow` or `cedar_deny`), and `policy_digest` (the acta-policy-digest-v1
digest of the policy set), and cites draft-farley-acta-signed-receipts-03. The
command prints the decision and digest on stdout. A deny is still signed: the
receipt is the record of the decision, not permission to proceed.

Two Cedar action models are supported. The runtime gate evaluates
`Action::"MCP::Tool::call"` with the tool as the resource, which is what the
policies in `cedar/` expect and what `sign --cedar` uses by default. Policies
that name the tool as the action (`action == Action::"Bash"`), such as the
published conformance policy in agent-governance-testvectors, need
`--action-model tool`. `evaluate` accepts the same flag.

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
npx -y protect-mcp@0.32.2 evaluate --format codex  --cedar ./cedar   # OpenAI Codex
npx -y protect-mcp@0.32.2 evaluate --format gemini --cedar ./cedar   # Gemini CLI BeforeTool
npx -y protect-mcp@0.32.2 evaluate --format cursor --cedar ./cedar   # Cursor beforeShellExecution
npx -y protect-mcp@0.32.2 evaluate --format hermes --cedar ./cedar   # Hermes pre_tool_call
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

- `coding-starter`: the starter policy above, seven named forbids over a default allow.
- `filesystem-safe`: destructive file actions and secret-like path reads.
- `git-safe`: force pushes, hard resets, destructive cleanup, repo deletion.
- `email-safe`: allow drafting, block unattended sends.
- `database-safe`: read-oriented DB posture, block write/admin SQL.
- `cloud-spend-safe`: obvious cloud spend creation and infrastructure destruction.
- `secrets-safe`: common file, env, shell, and cloud secret exfiltration.
- `finance-mandate-safe`: restricted-list and concentration breaches in booking flows.

## Credentials the agent never holds

The gateway can hold a secret and inject it at dispatch, so the agent works with a label and never sees the value. Configure the vault in `protect-mcp.json`; the value is read from the named environment variable of the gateway process, not the agent's:

```json
{
  "credentials": {
    "github_token": { "inject": "header", "name": "Authorization", "value_env": "GITHUB_TOKEN" },
    "warehouse":    { "inject": "env",    "name": "PGPASSWORD",    "value_env": "WAREHOUSE_PASSWORD" }
  }
}
```

### The grant travels with the call

A personal-agent platform (Meta Muse, Claude Code, Codex, any MCP client) can present the grant its agent is acting under with each call, in `params._meta["veritasacta.com/connector"]`, as a bare or platform-signed context: platform, agent, grant type (`one_time`, `session`, `task`, `time_bounded`, `perpetual`), an optional purpose and mandate digest. The gateway records it on the decision receipt as `connector`, together with what it could check about the platform's signature and the digest of the call it actually received. List the platform keys you trust in the policy file:

```json
{ "connector_platform_keys": { "sb:platform:meta-muse": "<64 hex Ed25519 public key>" } }
```

Without a key for the signing kid the context is recorded as `unverifiable`, never as `valid`; a verifier with the key can still check the signature itself (`npx @veritasacta/verify receipt.json --platform-key <kid>=<hex>`). The profile is draft-farley-acta-connector-action-00; the vectors are in `vectors/connector-action.v1.json`.

`inject: "env"` puts the value in the wrapped server's environment; `inject: "header"` and `"query"` attach it to the outbound call. A tool whose name matches a label is resolved on every call; if the secret is missing the call is refused with `credential_error` rather than sent without it. Each receipt for such a call carries `credential_ref` with the label, never the value, so a reader can see that the credential the standard names was used through the gateway. What the receipts cannot show is that the agent had no other copy of the secret; that is a property of the deployment.

A ScopeBlind standard states this as `requirements.credentials_held_by_gate`, and the gateway receipt report on scopeblind.com/verify checks the label on every receipt for the tool.
