# ScopeBlind Gateway

> **Source-available under the [Functional Source License (FSL-1.1-MIT)](https://fsl.software).**
> You may use, modify, and self-host this freely for your own projects or internal company use.
> You may not offer ScopeBlind (or a substantially similar service) as a hosted/managed product to third parties.
> After 2 years, each version automatically converts to the MIT license.
> For zero-ops managed hosting with real-time abuse intelligence, use [scopeblind.com](https://scopeblind.com).

**Drop-in gateway protection for public APIs using ScopeBlind pass-token verification.**

ScopeBlind helps public APIs let trusted agents through, challenge unknown traffic privately, and stop repeat abuse without CAPTCHA friction or invasive tracking. This gateway is the **secure-mode** deployment path.

> The browser script starts observation and access decisions. The gateway is the real security boundary for protected APIs.

## When to Use This Gateway

Use this repo when:
- you want stricter protection than client-side observe mode alone
- your API can be called directly (bots can skip the browser)
- you want edge enforcement before requests hit your origin
- you want to verify ScopeBlind pass tokens without adding SDK code to every service

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/tomjwxf/scopeblind-gateway.git
cd scopeblind-gateway
npm install

# 2. Edit wrangler.toml:
#    - ORIGIN_URL = "https://your-api.com"
#    - SCOPEBLIND_AUDIENCE = "YOUR_SLUG"
#    - SCOPEBLIND_JWKS_URL = "https://api.scopeblind.com/.well-known/jwks.json"
#      (get your slug by scanning your endpoint at scopeblind.com)

# 3. Deploy
npx wrangler deploy
```

Your gateway is now live at `scopeblind-gateway.<your-account>.workers.dev`.

Point protected API traffic at the gateway URL instead of your origin. Requests with valid ScopeBlind pass tokens are forwarded. Requests without valid tokens are either logged (observe mode) or blocked (enforce mode).

## What Observe Mode Does

Observe mode is the default. It **never blocks anything** — it measures what would happen if secure enforcement were enabled.

Every protected request (POST, PUT, DELETE, PATCH by default) is checked for a ScopeBlind pass token:
- browser traffic usually sends it via the `sb_pass` cookie
- API-only or agent traffic can send it via the `X-ScopeBlind-Token` header

| Scenario | Observe Mode | Enforce Mode |
|----------|--------------|--------------|
| No token | ✅ Forward + log `would-block` | ❌ 403 Rejected |
| Invalid / expired token | ✅ Forward + log `would-block` | ❌ 403 Rejected |
| Valid token | ✅ Forward + log `verified` | ✅ Forward |
| JWKS verification unavailable | ✅ Forward + log `fallback-allow` | Depends on `FALLBACK_MODE` |

GET requests pass through by default.

## Reading Observe Mode Logs

```bash
npx wrangler tail --format json | jq 'select(.logs[]?.message | contains("_scopeblind"))'
```

Every log entry includes:
- `action`: `missing_token`, `invalid_token`, or `verified`
- `method`: HTTP method
- `path`: request path
- `ts`: ISO timestamp

After a few days, you will know exactly how much direct API traffic would fail secure-mode verification.

## Health Check

```bash
curl https://scopeblind-gateway.<you>.workers.dev/_scopeblind/health
```

Returns:

```json
{
  "ok": true,
  "mode": "observe",
  "origin": "https://your-api.com",
  "audience": "your-slug",
  "jwks": "https://api.scopeblind.com/.well-known/jwks.json"
}
```

## Configuration

All config lives in `wrangler.toml`:

| Variable | Description |
|----------|-------------|
| `ORIGIN_URL` | Your backend API URL |
| `SCOPEBLIND_AUDIENCE` | Your tenant slug (expected JWT `aud`) |
| `SCOPEBLIND_JWKS_URL` | JWKS endpoint for EdDSA pass-token verification |
| `OBSERVE_MODE` | `"true"` = log only, `"false"` = enforce |
| `PROTECTED_METHODS` | Comma-separated methods to protect |
| `FALLBACK_MODE` | `"open"` = allow if verification infra is down, `"closed"` = reject |

Legacy `SHADOW_MODE` is still supported for older deployments, but new installs should use `OBSERVE_MODE`.

## How It Works

```text
Client -> ScopeBlind decision flow -> pass token issued
                                     |
                                     v
Client -> Cloudflare Edge -> [ScopeBlind Gateway] -> Your API
```

1. ScopeBlind decides whether to allow, challenge, pay, or deny
2. Allowed requests receive a signed pass token (`sb_pass` cookie or `X-ScopeBlind-Token` header)
3. This gateway verifies the token against the public JWKS endpoint
4. Valid requests are forwarded to your origin with `X-ScopeBlind-*` metadata headers
5. Missing or invalid tokens are logged in observe mode or rejected in enforce mode

Headers forwarded to your origin:
- `X-ScopeBlind-Mode`: `observe` or `enforce`
- `X-ScopeBlind-Verified`: `true`, `missing`, `invalid`, `error`, or `skipped`
- `X-ScopeBlind-Subject`: tenant-scoped device hash from the JWT
- `X-ScopeBlind-Agent`: `true` if token came from the agent fast-lane
- `X-ScopeBlind-Expires`: JWT expiry timestamp
- `X-ScopeBlind-JTI`: JWT ID (for replay-sensitive origin logic if needed)

The gateway strips `sb_pass` and `X-ScopeBlind-Token` before forwarding so your origin does not need to handle raw ScopeBlind credentials.

## Switching to Enforcement

When your observe-mode data confirms the pattern, switch to strict enforcement:

```toml
OBSERVE_MODE = "false"
```

```bash
npx wrangler deploy
```

Now protected requests without a valid ScopeBlind pass token are blocked at the edge before they hit your backend.

## What This Repo Does Not Do

This gateway does **not** issue tokens or run the challenge flow itself. That still happens in ScopeBlind's browser/agent path. This repo is the enforcement layer for APIs that need a clean edge boundary.

It also does **not** implement the future payment-required branch yet. When ScopeBlind later returns machine-readable payment options for over-quota traffic, that logic belongs on the protected resource path above this gateway.

## License

[FSL-1.1-MIT](https://fsl.software) — source-available now, converts to MIT after 2 years. See `LICENSE`.
