# Claude Code plugin

The plugin connects Claude Code's tool hooks to a local protect-mcp gate. It
also exposes MCP tools for explicitly evaluating policies and inspecting
receipts. Those MCP tools do not intercept other tools by themselves.

Use **Claude Code 2.1.295 or later**, Node.js 22 or later, and npm. The hook's
`onFailure: "block"` setting requires that Claude Code version. Older hosts are
not supported for this setup. Keep Claude Code's native permissions enabled.

## Prepare the project

In a terminal, change to the project you want to protect. For a new setup:

```sh
npx --yes protect-mcp@0.32.3 init
npx --yes protect-mcp@0.32.3 policy-packs install coding-starter --dir ./policies
```

The first command creates `protect-mcp.json` and an owner-readable signing key
at `keys/gateway.json`. The second installs `policies/coding-starter.cedar`.
Neither installs host hooks. If you already have a configuration, keep it and
review its signing and policy paths instead of overwriting it.

Read the Cedar file before continuing. The starter permits calls except for its
named forbid rules. Shell rules inspect command text, so they are guardrails,
not process isolation. Adapt the policy to the project.

Start the gate from that same project directory and leave the terminal open:

```sh
npx --yes protect-mcp@0.32.3 serve --enforce --cedar ./policies --policy ./protect-mcp.json
```

Use one project and one gate at a time on the default port, `9377`. The relay
checks that the endpoint reports enforcement, Cedar policies and signing; it
does not authenticate the local process or establish which workspace it serves.
For concurrent projects, give each gate a different `--port` and launch its
Claude Code process with the matching `PROTECT_MCP_HOOK_PORT` environment value.
The relay accepts only a numeric port on `127.0.0.1`, not a remote URL.

## Install in this project

From a second terminal in the project directory:

```sh
claude plugin install protect-mcp --marketplace ScopeBlind/scopeblind-gateway --scope project
```

This uses ScopeBlind's own marketplace. Directory submission and approval are
separate. Restart Claude Code after installing and confirm protect-mcp appears
in its plugin and hooks views.

Do not also run `init-hooks`: the plugin already supplies its hooks. If this
project already has an installer-managed setup, review `init-hooks --uninstall`
before switching. It preserves custom entries, so inspect the remaining hooks
to avoid duplicates. Keep the standalone installation until the replacement is
ready to test.

## Confirm the route is working

1. Ask Claude Code to read a harmless project file. Check that a new decision
   appears in `.protect-mcp-log.jsonl` and a receipt in
   `.protect-mcp-receipts.jsonl` in the gate's project directory.
2. Stop the gate, then ask it to read that file again. The plugin should block
   the call with `connection_failed`. Restart the gate to continue.
3. Test a harmless input covered by a deny rule before relying on the policy.
   Do not test by executing a destructive command.

A healthy endpoint or a passing `doctor` check alone does not establish that
Claude Code loaded its hooks. Keep the host check above as part of setup.

Before a tool call, the relay rejects unavailable, shadow-mode, unsigned or
non-Cedar gates, malformed responses and timeouts. A successful gate response
does not grant a Claude Code permission: native permission checks still apply.
Hook launch failures and host timeouts are blocked by `onFailure: "block"` on
the supported host versions.

After a tool call, failures are reported but cannot undo the action. Version
0.32.3's post-action HTTP response does not itself confirm that the receipt was
saved. Inspect the local receipt log before claiming after-action evidence.

## Data and trust

The relay sends tool names, arguments, session information and, after execution,
tool results to the local gate. These can contain sensitive project data. The
gate writes local records; review retention and access as part of setup. The
relay does not send those payloads to ScopeBlind and does not print them in its
error messages. npm may download the pinned package on first use.

The gate's signer is the local operator. A valid receipt does not establish
that the operator recorded every action, that an allowed action executed, or
that the operator was entitled to approve it. The plugin does not prevent the
host owner from disabling hooks or changing the local server.

See [receipt verification](receipts.md) and the
[security boundary](../SECURITY.md). Obtain the expected signing public key
through a separate trusted channel when checking someone else's record.

This guide targets Claude Code. Claude's platform documentation also describes
local hooks in Cowork, but that host needs its own validation before claiming
support. Claude chat does not run these local enforcement hooks.

## Remove the plugin

```sh
claude plugin uninstall protect-mcp@scopeblind --scope project
```

Stop the gate terminal separately. The project policy, signing key and local
records remain yours; plugin removal does not erase them.

## Maintainer checks

```sh
claude plugin validate --strict .
node --test scripts/claude-plugin-hooks.test.mjs
node scripts/distribution-smoke.mjs
```

Set `PROTECT_MCP_TEST_CLI` to the published package's `dist/cli.js` to include
the real-gate tests. Validate both MCP configurations with an `initialize` and
`tools/list` exchange. A schema check alone does not establish a working server.

Host behavior: [Claude Code hooks](https://code.claude.com/docs/en/hooks).
Distribution: [Publish a plugin](https://code.claude.com/docs/en/plugins/publish).
