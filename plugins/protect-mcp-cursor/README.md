# protect-mcp for Cursor

A project-configured adapter between Cursor Agent tool hooks and a local
[protect-mcp](https://www.npmjs.com/package/protect-mcp) policy gate. The
[gateway repository](https://github.com/ScopeBlind/scopeblind-gateway) is the
canonical runtime and source project. This plugin has its own version.

**Preview:** a live Cursor 3.17.8 project-hook trial confirmed a harmless Shell
allow executes, a policy deny blocks, and a stopped gate blocks. The observed
decision and after-action receipts verified against the test setup's expected
public key. A sanitized host-input fixture is included in
[`tests/fixtures/cursor-3.17.8-shell.json`](tests/fixtures/cursor-3.17.8-shell.json).
A second synthetic project hook's deny also blocked a call the gate allowed.
This does not establish every tool, native permission prompts or native
plugin marketplace loading. Complete the checks below for your installation.
This package is not listed as a Cursor partner integration.

The pre-action hook checks an enforcing, signed Cedar gate. Unknown tools,
missing project configuration, unavailable gates, malformed responses and
timeouts block the action. A permitted call continues through Cursor; this
adapter does not configure Cursor permissions or change tool arguments.

## Prepare one project

Use Node.js 22 or later, npm and a current Cursor desktop application supporting
`preToolUse`, `postToolUse` and `failClosed`. The project-hook trial used Cursor
3.17.8. This release does not establish support for older versions, cloud
agents, the standalone Cursor CLI agent or Tab completions.

In the project you want to protect, prepare the pinned gateway:

```sh
npx --yes protect-mcp@0.32.4 init
npx --yes protect-mcp@0.32.4 policy-packs install coding-starter --dir ./policies
```

Keep any existing configuration and signing key. Review the policy before
starting the gate. The coding starter permits calls except for named forbids;
it is not a deny-by-default sandbox. Shell rules inspect command text and do
not constrain every process or network request a command can start.

```sh
npx --yes protect-mcp@0.32.4 serve --enforce --cedar ./policies --policy ./protect-mcp.json
```

Leave that terminal open. npm is used during setup, never from the hot hook
path. The hooks themselves use Node's standard library and loopback HTTP.

## Install the local project preview

From a reviewed checkout of the gateway repository, preview the changes:

```sh
node plugins/protect-mcp-cursor/install-project.mjs --project /absolute/path/to/project
```

After reviewing that plan, explicitly enable the project hooks:

```sh
node plugins/protect-mcp-cursor/install-project.mjs --project /absolute/path/to/project --install
```

Setup creates `.cursor/protect-mcp.json`, copies the two small relay files into
`.cursor/protect-mcp/`, and adds its two entries to `.cursor/hooks.json`.
Other project hooks are preserved. No user, team or enterprise settings,
permissions, MCP servers, signing keys or policies are changed. Restart Cursor
and open the project as a trusted workspace to load project hooks.

Use only one installation route: project hooks **or** the native plugin.
Installing both produces duplicate checks. The native plugin manifest is
`.cursor-plugin/plugin.json` in this package; its hook paths resolve from the
plugin directory. Native plugin distribution still requires separate host and
directory validation. It uses the same explicit project configuration.

The project configuration is intentionally small:

```json
{
  "version": 1,
  "port": 9377,
  "mcpTools": {
    "MCP:demo_lookup": "demo_lookup"
  }
}
```

`mcpTools` is optional and empty by default. Add an exact Cursor MCP tool name
only after reviewing which server provides it and which Cedar policy name it
should use. The example does not configure or trust a server. Unknown MCP
names are denied until mapped. Nested MCP arguments remain objects and reach
the policy unchanged. The generic Cursor hooks use object inputs; the
separate `beforeMCPExecution` JSON-string format is not this plugin's hook.

Built-in aliases are explicit: `Shell` becomes `Bash`, `Delete` becomes
`delete_file`, and `Read`, `Write`, `Grep`, `Glob` and `Task` keep their names.
Receipts contain these policy tool names. Other native tool names are denied.
Test the policies against the real tool inputs, including each MCP server.

One workspace root is supported. Calls outside it or from a multiroot workspace
are blocked. Cursor 3.17.8 can send an empty working directory for a Shell call;
the adapter uses the checked single workspace root for that field and leaves
the tool arguments unchanged. Missing or non-string working directories and
explicit directories outside the workspace remain blocked.
Each concurrent project needs a different port, matching its gate's
`--port` and `.cursor/protect-mcp.json`. For first setup, `--port 19377` can be
added to the installer. Changing an existing port is an explicit config edit.

## Check it in Cursor

Use a disposable project and harmless inputs. A health response alone does not
establish that Cursor loaded its hooks.

1. Add a temporary Cedar forbid for a harmless command marker. Ask Cursor to
   run an allowed `printf` command and confirm it executed. Inspect the new
   decision and signed receipt in the gate's project.
2. Ask for the marker command. Confirm Cursor blocks it and the gate records
   a deny. Tell the agent not to substitute another tool or command.
3. Stop the gate. Confirm a previously allowed command is blocked, then
   restart the gate.
4. Confirm a separate Cursor permission prompt or a second test hook's deny
   still takes effect. Do not disable native protections to complete the test.
5. Exercise each additional tool and MCP server you intend to use. A shell
   check does not validate every tool or the native marketplace plugin path.

The repository provides a synthetic project generator for maintainers:

```sh
node scripts/cursor-plugin-preview.mjs
```

It creates a temporary project with test keys, harmless allow/deny commands and
project hooks, then prints the gate launch arguments and host test prompts.
It does not launch Cursor, a model or an external service.

Cursor's generic pre-action hook currently does not enforce `ask`. The relay
therefore keeps an approval-required result blocked. Review and satisfy the
gate's approval mechanism, then retry the exact action. A chat message saying
"approved" does not satisfy a gate approval.

## Evidence and limits

Pre-action receipts show the local gate's policy decision. They do not prove
the tool executed. Successful `postToolUse` events use the same conversation
and call IDs and forward the actual JSON result for after-action recording.
Failed tools and denied calls are not mislabeled as successful execution.

Gateway 0.32.4's post-action response does not confirm durable receipt storage.
The relay suppresses its optimistic receipt message. Check the actual local
receipt log. A post-action failure cannot undo the action. The adapter neither
rewrites a tool result nor claims complete execution coverage.

Tool inputs and outputs are sent to `127.0.0.1` only by this relay; npm setup,
Cursor and the tools themselves can use the network. The configured gate's
logging and signing determine what it retains. Email addresses and transcript
paths from Cursor's common hook input are not forwarded. The loopback health
check does not authenticate the process or prove it belongs to the project.
A malicious local process or workspace owner can replace the gate, scripts or
configuration. This is a policy boundary for configured host tools, not OS
isolation or proof that all actions went through it.

Verify saved receipts with a separately trusted signer key:

```sh
npx --yes @veritasacta/verify@0.11.0 receipt.json --key "$PROTECT_MCP_PUBLIC_KEY" --json
```

Set that variable to the expected public key obtained through a trusted route.
An embedded key is not a trust anchor. Never share the private signing key.

## Remove or update

```sh
node plugins/protect-mcp-cursor/install-project.mjs --project /absolute/path/to/project --uninstall
```

Only unchanged installer-owned hook entries and scripts are removed. Modified
scripts or entries are preserved for review. Keys, policies, receipts and
`.cursor/protect-mcp.json` remain. Restart Cursor and inspect its loaded hooks.
Removal still works if that project configuration is malformed; it preserves
the configuration bytes for repair.
For an update, remove the old copy with its old installer first, then review and
install the new copy. Setup refuses to overwrite different managed scripts.

If using a native plugin installation, uninstall it through Cursor's plugin
manager instead. Removing the project configuration while hooks remain active
intentionally causes calls to block.

## Maintainer checks

```sh
node scripts/cursor-plugin-sync.mjs
node --test scripts/cursor-plugin.test.mjs
```

`lib/gate-client.mjs` is a generated exact copy of the canonical
`hooks/relay.mjs` in the gateway repository. After a transport change, regenerate
with `node scripts/cursor-plugin-sync.mjs --write` and run both host suites.
This keeps the package self-contained without maintaining a second transport.

Report security issues privately to **security@scopeblind.com**. See the
[gateway security policy](https://github.com/ScopeBlind/scopeblind-gateway/blob/main/SECURITY.md).
The package is [MIT licensed](LICENSE).

References: [Cursor hooks](https://cursor.com/docs/hooks) and
[Cursor plugin reference](https://cursor.com/docs/reference/plugins).
