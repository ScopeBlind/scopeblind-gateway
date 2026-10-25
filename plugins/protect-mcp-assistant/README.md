# protect-mcp Assistant

Set up one MCP server, try a policy, and check its signed decisions from ChatGPT or Codex.

[Core source](https://github.com/ScopeBlind/scopeblind-gateway) · [Gateway on npm](https://www.npmjs.com/package/protect-mcp) · [Receipt verifier](https://github.com/VeritasActa/verify) · [Product guide](https://scopeblind.com/protect-mcp)

## Start with a task

| Ask your assistant | What happens |
| --- | --- |
| “Help me protect this MCP server.” | Reviews the server, proposes a policy, and helps configure and test the selected route. |
| “Show me a harmless protect-mcp demo.” | Evaluates synthetic proposals, signs an allowed and denied decision, then detects an edited receipt. |
| “Verify this receipt with the expected public key.” | Runs the verifier where execution is available and explains valid, invalid, and not-checked results. |

Installing the plugin does **not** enable enforcement. It contains skills and a local demo, with no hooks, connected services, or account. The gateway only controls calls actually routed through it. Your host's native permissions stay in place.

## Install for local testing

This package is prepared for ChatGPT/Codex plugin distribution; it is not yet listed in OpenAI's public directory. The repository includes a marketplace at `.agents/plugins/marketplace.json`.

With a checkout containing this package, add its local marketplace and install
the plugin through the Codex CLI:

```sh
codex plugin marketplace add /absolute/path/to/scopeblind-gateway
codex plugin add protect-mcp-assistant@scopeblind-assistants
codex plugin list
```

For the documented ChatGPT desktop route, restart if needed, open the Plugins
Directory, select the **ScopeBlind** source, and install **protect-mcp Assistant**.
Run setup in a new conversation. This UI route has not yet been tested for this
package. Local source availability varies by host; see
[OpenAI's local plugin instructions](https://developers.openai.com/plugins/build/plugins#install-a-local-plugin-manually).

To remove this local test installation and its marketplace:

```sh
codex plugin remove protect-mcp-assistant@scopeblind-assistants
codex plugin marketplace remove scopeblind-assistants
```

**Validation status:** on 25 October 2026, Codex CLI **0.145.0** discovered the
local marketplace, installed and enabled this plugin, and listed it. The cached
root manifest and bundled assets were inspected. The temporary plugin and
marketplace were then removed. This establishes CLI discovery and installation;
ChatGPT directory loading and onboarding in fresh or existing conversations
have not yet been verified. The packaged demo has a separate clean-install
smoke test.

In a session with terminal access, these skills can perform the local checks. In a chat-only session, they prepare commands and interpret the results you supply. They cannot change your desktop settings from an unrelated cloud sandbox or verify a signature by reading its text.

## Try the demo without installing a plugin

From the repository root, with Node.js 22 or later and npm, choose a new absolute directory:

```sh
node plugins/protect-mcp-assistant/skills/protect-mcp-demo/scripts/demo.mjs --workspace /absolute/path/to/new/protect-mcp-demo
```

The helper installs **protect-mcp 0.32.4** and **@veritasacta/verify 0.11.0** from npm with lifecycle scripts disabled. It leaves a small policy, test key, original receipts, an altered copy, and a JSON report in the new directory. Existing directories are refused. No real tools are called and no MCP host settings are changed.

Expected result: **allow → deny → two receipts verified → altered receipt rejected**. Missing and wrong expected keys are rejected too. Open `demo-summary.json` to inspect the results. Keep `protect-mcp.key` private; `demo-public-key.txt` contains only the test public key. This demonstrates the checker, not protection of your current host.

## Versions and data

The assistant package is version **0.1.0**, separate from the gateway release. `runtime-versions.json` records its tested npm pins. Update these only alongside the guides and a passing clean-install smoke test.

The skills use the host's existing execution and permission model. npm downloads software when you run a workflow. Receipt verification uses local files; the plugin adds no upload service or telemetry. Content you paste into a chat is handled by that chat service. A real wrapped MCP server may still contact its own external services.

Trust the signer through a separately obtained public key. A valid receipt signature does not alone establish truth, issuer authority, downstream success, or complete coverage.

The assistant package is [MIT licensed](LICENSE). The separately installed verifier is Apache-2.0. Report sensitive vulnerabilities privately to security@scopeblind.com; use the [gateway issues](https://github.com/ScopeBlind/scopeblind-gateway/issues) for setup problems with secrets removed.
