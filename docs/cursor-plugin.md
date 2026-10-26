# Cursor integration preview

The [self-contained Cursor package](../plugins/protect-mcp-cursor/README.md)
contains the project setup, host checks, coverage limits and uninstall steps.

It uses Cursor's generic `preToolUse` and `postToolUse` hooks with stable call
IDs, a signed enforcing local Cedar gate, and explicit project configuration.
Missing configuration or a stopped gate blocks pre-action calls. Approval
requirements stay blocked because Cursor does not currently enforce `ask` on
the generic pre-action hook. No arguments, results or native permission
settings are rewritten.

This is distinct from `protect-mcp evaluate --format cursor`, which handles
Cursor's dedicated shell/MCP hook payloads. Do not combine both installation
routes without checking for duplicate evaluations and receipts.

A live Cursor 3.17.8 project-hook trial confirmed a harmless Shell call runs,
a policy-denied call is blocked, and a stopped gate blocks another call.
The observed decision and after-action receipts verified against the expected
test public key. The package contains a sanitized fixture from that host input.
A separate synthetic project hook's deny still blocked a call the gate allowed.
That trial ran on a pre-release build, before 0.32.4 (the validation record lists
the sources it used); 0.32.4 itself has not been re-validated in Cursor.

This does not establish native marketplace loading, every tool or native
permission prompts. Complete and record the package's acceptance checks
for the tools and installation route you intend to use.

## Upgrade a copy installed before 0.32.4

Before 0.32.4 the preview's relay could exit without a check when it was
started through a path that differed only in letter case
(GHSA-xf4c-59j2-hgf2). Setup refuses managed files that differ, and the 0.32.4
installer keeps files that differ from its own when it uninstalls. So remove
the old copy with the installer it came from, then install the new one. Every
copy installed from `main` before 0.32.4 has the files of commit
`7a73d00b8748a5a48955dcd69426ee086241b830`, so that commit's installer removes
it.

Close the project in Cursor first: between the two steps it has no
protect-mcp hooks. From your gateway checkout:

```sh
git fetch --tags origin
git checkout 7a73d00b8748a5a48955dcd69426ee086241b830
node plugins/protect-mcp-cursor/install-project.mjs --project /absolute/path/to/project --uninstall
git checkout v0.32.4
node plugins/protect-mcp-cursor/install-project.mjs --project /absolute/path/to/project
node plugins/protect-mcp-cursor/install-project.mjs --project /absolute/path/to/project --install
```

The uninstall should list nothing under `preserved`. A file listed there was
edited after setup: review it before installing. Other project hooks, keys,
policies, receipts and `.cursor/protect-mcp.json` are kept, and the install
leaves a backup of `.cursor/hooks.json` beside it.

The 0.32.4 starter adds rules for the preview's own files. In the project, if
you installed the coding starter before 0.32.4 and have not edited it, replace
it with the new text:

```sh
npx --yes protect-mcp@0.32.4 policy-packs install coding-starter --dir ./policies --force
```

`--force` overwrites your copy. If you edited it, compare it with
`npx --yes protect-mcp@0.32.4 policy-packs show coding-starter` and add the new
forbids yourself. The starter blocks direct writes and deletes of the
preview's hook files through Write and Delete. It does not cover shell access:
a Shell command can still change or delete those files.

Stop the gate and start it again on 0.32.4:

```sh
npx --yes protect-mcp@0.32.4 serve --enforce --cedar ./policies --policy ./protect-mcp.json
```

Restart Cursor, open the project as a trusted workspace and repeat the checks
in the [package README](../plugins/protect-mcp-cursor/README.md#check-it-in-cursor).
