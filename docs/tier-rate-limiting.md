# Receipt-Aware Rate Limiting — Tier Economics

protect-mcp v0.5.3 supports trust-tier-aware rate limiting. This document defines
the economic incentive model that encourages agents to accumulate verifiable receipts.

## Trust Tiers

| Tier | Requirements | Default Rate Multiplier |
|------|-------------|------------------------|
| `unknown` | No manifest, no receipts | 1× (baseline) |
| `signed-known` | Valid Ed25519-signed manifest | 2× |
| `evidenced` | 10+ receipts, 3+ epoch hours, 2+ issuers | 5× |
| `privileged` | Operator-assigned (out-of-band) | 10× |

## Per-Tool Tier-Aware Rate Limits

```json
{
  "tools": {
    "web_search": {
      "rate_limit": "10/hour",
      "rate_limits": {
        "unknown": { "max": 10, "window": "hour" },
        "signed-known": { "max": 25, "window": "hour" },
        "evidenced": { "max": 100, "window": "hour" },
        "privileged": { "max": 500, "window": "hour" }
      }
    },
    "deploy": {
      "min_tier": "signed-known",
      "rate_limit": "3/hour",
      "rate_limits": {
        "signed-known": { "max": 3, "window": "hour" },
        "evidenced": { "max": 10, "window": "hour" },
        "privileged": { "max": 50, "window": "hour" }
      }
    },
    "*": {
      "rate_limit": "100/hour",
      "rate_limits": {
        "unknown": { "max": 100, "window": "hour" },
        "signed-known": { "max": 250, "window": "hour" },
        "evidenced": { "max": 1000, "window": "hour" },
        "privileged": { "max": 5000, "window": "hour" }
      }
    }
  }
}
```

## Flywheel Effect

1. **Agent registers** with a signed manifest → promoted to `signed-known` → 2× rate limit
2. **Agent accumulates receipts** across sessions and issuers → promoted to `evidenced` → 5× rate limit
3. **Receipts feed the evidence store** → verifiable activity record viewable in receipt explorer
4. **Operators grant `privileged`** tier to agents with strong receipt history → 10× rate limit
5. **Each receipt is independently verifiable** → agents carry their trust record across platforms

## Managed Platform Pricing Tiers

On scopeblind.com (managed platform), receipt-aware economics translate to pricing advantages:

| Plan | Rate Limit (no receipts) | Rate Limit (evidenced) | Price/1K requests |
|------|--------------------------|------------------------|--------------------|
| Free | 100/hour | 500/hour | $0.50 |
| Pro | 500/hour | 2,500/hour | $0.30 |
| Enterprise | Unlimited | Unlimited | Custom |

Agents with `evidenced` status get 5× the rate limit at the same price, creating an economic incentive to sign manifests and accumulate verifiable activity.

## Evidence Store Thresholds (Configurable)

```json
{
  "evidence_thresholds": {
    "min_receipts": 10,
    "min_epoch_hours": 3,
    "min_issuers": 2,
    "max_receipts_per_agent": 200
  }
}
```

Override in `protect-mcp.json` to adjust promotion criteria for your use case.
