# Configure a selected stdio MCP server

Use Node.js 22 or later and npm, with `protect-mcp@0.32.3` and `@veritasacta/verify@0.11.0`. The first npm or npx invocation downloads software; it does not connect a ScopeBlind account.

## Initialize

In a new configuration directory chosen for this server:

```sh
npx --yes protect-mcp@0.32.3 init
```

This creates `protect-mcp.json` and `keys/gateway.json`. Preserve an existing configuration and key. Never print, upload, or commit the private signing key.

Replace sample tool names with the selected server's exact names, retaining its generated signing configuration:

```json
{
  "tools": {
    "*": { "block": true },
    "safe_lookup": {},
    "expensive_lookup": { "rate_limit": "10/minute" },
    "sensitive_tool": { "require_approval": true }
  },
  "signing": {
    "key_path": "./keys/gateway.json",
    "issuer": "protect-mcp",
    "enabled": true
  }
}
```

The keys are `block`, `require_approval`, and `rate_limit`. An exact rule takes precedence over `*`. Rate limits are in-memory and local to this process; they are not durable or shared quotas.

## Launch shape

For shadow observation from the configuration directory:

```sh
npx --yes protect-mcp@0.32.3 --policy ./protect-mcp.json -- node /absolute/path/to/server.js
```

For enforcement:

```sh
npx --yes protect-mcp@0.32.3 --policy ./protect-mcp.json --enforce -- node /absolute/path/to/server.js
```

Replace the illustrative child command with the selected server's reviewed executable and arguments. Configure the host to launch this wrapper in place of that server. Use absolute policy, signing-key, and server paths when the host starts in another directory. Keep the host's credentials in its existing secret mechanism; do not copy them into the conversation or policy file.

`wrap` prints a client configuration and exits. The standalone `mcp` command exposes helper tools; it does not wrap another server. Neither is the launch shape above.

## Check what works

First use a disposable MCP server with tools that only return synthetic results and record invocation counts. Through the selected host, make one allowed call and one blocked call. In enforce mode, the blocked call must not reach the server. In shadow mode, it does reach the server and the policy denial must still appear in the log.

Then test a harmless real call with the selected host. Do not use a destructive tool to test denial. Keep the user's native permission prompts enabled.

Inspect `.protect-mcp-log.jsonl` and `.protect-mcp-receipts.jsonl` in the gateway's working directory. They may contain sensitive information. Use `protect-mcp-verify` with the expected public key to check the receipts. A valid signature proves integrity relative to that key; it does not prove every other action route was covered or that an allowed tool succeeded.

An approval rule holds the call; this plugin supplies no approval service. Use the [gateway's supported local approval flow](https://github.com/ScopeBlind/scopeblind-gateway/blob/main/docs/local-gateway.md#local-action-dashboard) when requested, rather than weakening the policy.
