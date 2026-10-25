# Command reference

[Quickstart](../README.md) · [Local gateway guide](local-gateway.md) · [Hosted coordination](hosted-coordination.md)

For a first Claude Code setup, follow the [recommended hook workflow](local-gateway.md#claude-code-hook-quickstart):
preview the changes, install, check locally, then run the server and verify a
real host call. The commands below cover other workflows as well.

| Command | Description |
|---------|-------------|
| `serve` | Start the HTTP hook server for Claude Code (port 9377). `--enforce` runs the restraint self-test first; `--cedar <dir>` and `--policy <path>` select the policy. |
| `init-hooks` | Install Claude Code HTTP hooks without replacing unrelated settings. `--dry-run` previews without writing files; `--uninstall` removes only unchanged entries tracked by the installer. Policies, keys and records are retained. `--dir <path>` selects the project and `--port <port>` selects the local hook port. |
| `init` | Generate an Ed25519 keypair (`keys/gateway.json`, mode 0600 in a 0700 folder), a config template, and a sample policy. `init --starter` instead writes `./protect.cedar` from the starter policy and creates `./protect-mcp.key`; `--contain` adds the only-inside-this-folder rules. |
| `sample` | Seed a clearly-labeled sample record (8 decisions: one blocked call, two payments; kid `sample-demo`) plus a tampered copy, so `record`, `claim`, `verify-claim`, and `anchor-record` are replayable from scratch before wiring an agent. Refuses to touch an existing record; `--force` overrides. |
| `policy` | See and change the Cedar policy from the terminal: `policy list` (permit / forbid / default-deny per tool, with how often the gate allowed or denied it), `policy show`, `policy allow <tool>`, `policy deny <tool>`, `policy path`. A running `serve` hot-reloads on the change. |
| `wrap` | Print a protected MCP command or patch Claude Desktop MCP servers. Dry-run by default; use `--write` to update Claude Desktop config. |
| `dashboard` | Start a local-only dashboard on `127.0.0.1` showing tool inventory, risk, policy coverage, exact-action approvals, receipt chains, and audit export. It accepts a change only from its own page: the same origin, a JSON body and the page's per-launch token. |
| `recommend` | Draft a reviewable JSON policy from observed local calls. Dry-run by default; use `--write` to create `protect-mcp.recommended.json`. |
| `registry` | Create an org identity, anchor receipt digests, and write a static verifier page. Hosted mode sends digests plus identifiers and public-key/billing metadata. |
| `record` | Open a local, searchable viewer over your receipts (`--live` streams as the agent runs): Ed25519 signatures verified in your browser against your gateway key, capability tags, a provenance tree, and one-click signed export. All local, nothing uploaded. |
| `claim` | Mint a signed, position-blind attestation of a predicate over the record (`--no <cap>` incl. `--no payment`, `--only <c1,c2>`, `--no-verdict <verdict>`, `--count <verdict>`, `--payment-under <cap>`), disclosing only decision categories. Add `--anchor` to record the claim digest in the public transparency log; enrolled keys anchor as a named org. |
| `anchor-record` | Checkpoint the record's Merkle root + count + time range into the public log (heartbeat-friendly: skips when unchanged). A matching later claim covers that committed set; anchoring does not establish all actions were recorded. |
| `verify-claim` | Verify a claim pack offline: signature, recomputed Merkle root, independently recomputed predicate, and the anchor sidecar when present (binds the anchored envelope to this exact claim, then confirms the public log holds it). `--check-anchor` requires the anchor; `--offline` skips the log hop. |
| `killer-demo` | Generate a complete shadow-mode to policy to approval to signed-receipt demo pack. |
| `verify-disclosure` | Verify a `scopeblind.selective_disclosure.v0` package and explain disclosed versus hidden fields. |
| `policy-packs` | List, inspect, and install starter Cedar policy packs. |
| `evaluate` | Evaluate one tool call against a Cedar policy (PreToolUse gate). Exit 2 = deny (fail-closed), exit 0 = allow. On a deny the rule's `@id` and `@reason` go to stderr. `--policy builtin:starter` uses the bundled starter policy. |
| `sign` | Record one decision, optionally evaluating Cedar with `--cedar`. With a key it signs a receipt; without one it records an unsigned line. `--receipts <dir>` writes `<dir>/receipts.jsonl`; otherwise it uses `.protect-mcp-receipts.jsonl` under `--dir`. This command does not execute the proposed tool. |
| `simulate` | Dry-run a policy against a recorded decision log to see what it would have blocked. |
| `demo` | Start a built-in demo server wrapped with the gate, to see receipts instantly. |
| `doctor` | Check local configuration, keys, policies, receipt files and the installed Cedar evaluator. `--dir`, `--policy` and `--cedar` select the setup; `--json` emits structured results. No network or package installation by default. `--hosted` adds an explicit ScopeBlind API health check. It does not establish that the host loaded its hooks. |
| `bundle` | Export an offline-verifiable audit bundle of receipts plus the public key. |
| `report` | Generate a compliance report (Markdown or JSON) from the decision log and receipts. |

The wrapper itself, `protect-mcp [options] -- <command>`: `--enforce` refuses to
start when signing is configured but its key cannot be loaded, and refuses an
allowed call whose receipt cannot be signed. `--http` listens on 127.0.0.1 and
needs `Authorization: Bearer <token>`, with the token from
`PROTECT_MCP_HTTP_TOKEN` (at least 32 characters) or the one it prints; `--host`
exposes it beyond this machine. `--cedar` with `--policy` applies both.

`doctor` exits **0** when its local configured checks pass, **1** for a missing
or broken selected setup or a failed check, and **2** for invalid flags. A
`not_checked` result remains unestablished, even when other checks pass.
Relative paths resolve from `--dir` (the current directory by default).

Run `npx --yes protect-mcp@0.32.3 --help` for the full flag reference.
