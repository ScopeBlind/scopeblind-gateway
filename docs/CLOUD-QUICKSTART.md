# HTTP gateway deployment notes

[Back to the local quickstart](../README.md)

The gateway can expose a wrapped MCP server through Streamable HTTP. The local
README example is the quickest tested route to a policy decision and receipt.
A remote deployment additionally needs authentication, TLS and isolation.

## Transport boundary

The bundled HTTP server uses plain HTTP. It listens on 127.0.0.1 unless you pass
`--host <addr>` (or set `PROTECT_MCP_HTTP_HOST`), and it sends no CORS headers.
Every request except `GET /health` must carry `Authorization: Bearer <token>`:
set the token in `PROTECT_MCP_HTTP_TOKEN` (at least 32 characters; the gateway
refuses to start with a shorter one), or use the one it generates and prints on
stderr at startup. The token is one shared secret, not a way to
tell clients apart. Do not expose the port directly to the internet or an
untrusted network. Terminate TLS and authenticate authorized clients in a
separate ingress that sends the token, then restrict direct access to the
gateway port.

A remote installation therefore has these parts:

```text
authenticated MCP client -> TLS/authenticated ingress -> private HTTP gateway
                                                          -> MCP tool server
```

Select an ingress compatible with the host's Streamable HTTP and authentication
requirements. Preserve streaming behavior and apply request limits there. Give
the wrapped tool server only the credentials and filesystem access it needs.
Other credentials or network routes available to an agent can bypass this gate.

## Start the private gateway

In a controlled environment, initialize a configuration and signing key with
`protect-mcp init`, review the generated JSON policy, and write your Cedar
policies in `./cedar`. Use exact tool names from the server you intend to wrap.
A permit list is easier to review than a broad allow with guessed deny names.

The launch command has this shape; replace the child command with your reviewed
MCP server and keep the port private:

```sh
npx --yes protect-mcp@0.32.0 --http --port 3000 --enforce \
  --policy ./protect-mcp.json --cedar ./cedar -- node your-mcp-server.js
```

With both flags, a call runs only when a Cedar policy permits it and the JSON
policy's rules for that tool (`block`, `require_approval`, rate limits and
`min_tier`) also allow it. Signing and credentials come from the JSON file, and
with `--enforce` the gateway refuses to start if that signing key is missing or
unreadable.

When the ingress runs on another host or container, add `--host` with the
address it reaches the gateway on, and set `PROTECT_MCP_HTTP_TOKEN` so the
ingress can send the token.

A cloud MCP host connects to your authenticated HTTPS ingress, not directly to
the private HTTP listener. Container deployments must mount the exact data paths
the child server uses and restrict published ports; this guide does not provide
a production-ready container or ingress configuration.

## Check before connecting real tools

Use synthetic data and disposable credentials to check one allowed call and one
prohibited call through the actual ingress and wrapped server. Confirm the
prohibited call never reaches the child, allowed work succeeds, and receipts
carry the expected policy digest. Also check authentication rejection and that
the gateway port cannot be reached around the ingress. A health response is not
proof of those properties.

Shadow mode, the default without `--enforce`, records violations without blocking
them. Enforcing Cedar evaluation denies on policy or engine failure. Protect the
signing key and arrange persistence for the receipt log before restarting a gate.

## Verify the supplied record

After signing is configured, receipts are appended to
`.protect-mcp-receipts.jsonl`. In the gateway's directory:

```sh
npx --yes @veritasacta/verify@0.10.27 --replay-chain .protect-mcp-receipts.jsonl \
  --key "$(node -p 'JSON.parse(require("fs").readFileSync("keys/gateway.json", "utf8")).publicKey')"
```

An auditor should receive the expected public key through a trusted channel,
independently of the record being checked. Never share `keys/gateway.json`, which
also contains the private key. Once installed, verification can run offline.

Verification checks signatures and the supplied chain links. It does not prove
when the operator signed, that stated decisions match actual execution, or that
all actions were included. A withheld suffix needs an independently known
expected checkpoint to detect. Exit 1 means an invalid result; exit 2 means a
result could not be checked. Neither is automatically proof of tampering.

See [SECURITY.md](../SECURITY.md) and [release validation](releases.md) for the
current support policy and the checks run on the package. Deployment-specific
TLS, identity, network isolation and persistence remain the operator's work.
