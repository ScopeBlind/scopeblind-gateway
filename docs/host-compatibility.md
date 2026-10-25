# Host compatibility and release status

The gateway is the shared runtime. Host packages choose how to connect to it;
guidance plugins explain setup and verification without intercepting tools.
The npm release these guides pin is **protect-mcp 0.32.4**, with
**@veritasacta/verify 0.11.0**. The assistant preview's demo still pins 0.32.3
until it is checked against 0.32.4. Plugin versions are separate.

## Choose the route

| Route | What it does | Status and limits |
|---|---|---|
| [MCP wrapper](local-gateway.md#connect-your-mcp-server) | Wraps one selected stdio or HTTP MCP server. | Released. Covers routed calls, not unrelated host tools or direct network access. |
| [Claude Code enforcement plugin](claude-plugin.md) | Relays pre/post tool events to a local signed Cedar gate. | Automated relay and gateway checks. Requires the documented host version and real-host setup checks. |
| [Claude Code project HTTP hooks](local-gateway.md#claude-code-hook-quickstart) | Installs reversible project hooks. | Released installer. Host HTTP-hook failure behavior differs from the command relay; a stopped server alone does not establish blocking. |
| [Cursor project preview](../plugins/protect-mcp-cursor/README.md) | Uses generic pre/post hooks, explicit project configuration and tool mappings. | Live Cursor 3.17.8 project-hook trial: harmless Shell allow, policy deny, stopped-gate block and a second hook's deny overriding gate allow; observed receipts verified. The trial ran on a pre-release build, before 0.32.4, and 0.32.4 has not been re-validated in Cursor. Other tools, native permission prompts and marketplace loading remain unvalidated. |
| [ChatGPT / Codex assistant preview](../plugins/protect-mcp-assistant/README.md) | Guides setup, runs a harmless local demo and verifies receipts where execution is available. | Local discovery and installation verified with Codex 0.145.0; the test entry was removed afterward. No hooks, automatic enforcement, completed host onboarding or public OpenAI directory listing is claimed. |
| [Existing Claude directory guidance plugin](https://github.com/tomjwxf/protect-mcp-plugin) | Provides manually selected setup and verification workflows. | Separate repository and publication process. Installing guidance does not enable enforcement. |
| Standalone `evaluate --format` / `sign --format` | Reads selected host payloads and writes that host's response shape. | Contract-level support is not a completed native integration. See the source status below. |

The MCP helper server (`protect-mcp mcp`) exposes policy and receipt tools. It
does not intercept the other tools in a host merely because it is installed.
ChatGPT chat, Codex, Gemini CLI and Gemini chat are different execution surfaces;
an integration for one is not evidence that the others are protected.

## Hook format changes in 0.32.4

0.32.4 changes standalone CLI hook parsing and response behavior from 0.32.3
(the [changelog](../CHANGELOG.md) lists each format):

- Malformed or absent formatted input denies rather than falling back to
  allowed `--tool` / `--input` flags.
- Cursor's dedicated MCP hook's JSON-string input is decoded, nested arguments
  reach Cedar, and permission responses use Cursor's current field names.
- Cursor and Gemini post-action signing returns an empty host object instead
  of emitting another action decision.

A command pinned to 0.32.3 does not have these changes. No native Gemini
extension is included. Native Gemini tool names also need explicit policy
mapping; a rule for `Bash` does not automatically cover `run_shell_command`.

The Cursor preview connects to the released HTTP gate rather than relying on
these standalone CLI fixes. It preserves nested generic-hook inputs and uses
its own explicit tool map. Its documented MCP mapping is separate from the
dedicated `beforeMCPExecution` payload adapter.

[Maintainer validation record, 25 October 2026](host-validation-20261025.json) records
the tested host versions, observed cases and remaining limits.

## What the checks establish

From a prepared development checkout:

```sh
npm run build
npm run test:hosts
npm run test:assistant:smoke
```

The shared suite checks CLI contracts for Claude, Codex, Cursor, Gemini and
Hermes; strict local HTTP relays; signed receipts from a real local gate; and
package structure and instructions. The assistant smoke test installs the
published pins in a fresh temporary directory and runs the shipped demo.

These checks establish deterministic adapter behavior for the supplied inputs.
They do not establish that a host loaded the plugin, that every host action
triggers the hook, that native permissions remain effective, or that a
marketplace accepted the package.

Before using an integration with a real project, record the host version and
installation route, then check a harmless allowed call, a harmless denied call,
a stopped gate, an approval hold and preservation of existing permission rules.
Inspect the actual receipt files and verify them against the expected public
key. Test each tool family and server you intend to use. Keep synthetic host
captures free of credentials, personal paths and real tool arguments.

## Updates

Keep commands pinned to the versions tested with the package. Update the pins,
instructions and acceptance evidence together. A plugin directory may review
and publish a source update separately from its repository or npm release.
Changing a README link does not update installed hooks or runtime packages.
