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

This does not establish native marketplace loading, every tool or native
permission prompts. Complete and record the package's acceptance checks
for the tools and installation route you intend to use.
