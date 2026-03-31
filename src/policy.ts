import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { ProtectPolicy, ToolPolicy, RateLimit, CredentialConfig, SigningConfig } from './types.js';

// ============================================================
// Policy loading
// ============================================================

/**
 * Load and validate a policy file. Returns the policy, credentials, signing config, and digest.
 */
export function loadPolicy(path: string): {
  policy: ProtectPolicy;
  digest: string;
  credentials?: Record<string, CredentialConfig>;
  signing?: SigningConfig;
} {
  const raw = readFileSync(path, 'utf-8');
  const parsed = JSON.parse(raw);

  if (!parsed.tools || typeof parsed.tools !== 'object') {
    throw new Error(`Invalid policy file: missing "tools" object in ${path}`);
  }

  const policy: ProtectPolicy = {
    tools: parsed.tools,
    default_tier: parsed.default_tier || 'unknown',
    policy_engine: parsed.policy_engine || 'built-in',
    ...(parsed.external ? { external: parsed.external } : {}),
  };

  const digest = computePolicyDigest(policy);

  return {
    policy,
    digest,
    credentials: parsed.credentials,
    signing: parsed.signing,
  };
}

/**
 * Compute a SHA-256 digest of the canonicalized policy.
 * Uses recursive key sorting so nested tool rules are preserved.
 */
function computePolicyDigest(policy: ProtectPolicy): string {
  const canonical = JSON.stringify(sortKeysDeep(policy));
  return createHash('sha256').update(canonical).digest('hex').slice(0, 16);
}

/**
 * Recursively sort object keys for deterministic serialization.
 */
function sortKeysDeep(obj: unknown): unknown {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sortKeysDeep);
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
    sorted[key] = sortKeysDeep((obj as Record<string, unknown>)[key]);
  }
  return sorted;
}

// ============================================================
// Policy evaluation
// ============================================================

/**
 * Get the policy for a specific tool. Falls back to "*" wildcard, then default-allow.
 *
 * Backwards compatible: old policies with just { block, rate_limit, require }
 * still work. New policies can add { min_tier, rate_limits }.
 */
export function getToolPolicy(toolName: string, policy: ProtectPolicy | null): ToolPolicy {
  if (!policy) {
    return { require: 'any' };
  }

  // Exact match first
  if (policy.tools[toolName]) {
    return policy.tools[toolName];
  }

  // Wildcard fallback
  if (policy.tools['*']) {
    return policy.tools['*'];
  }

  // Default: allow everything
  return { require: 'any' };
}

// ============================================================
// Rate limiting
// ============================================================

/**
 * Parse a rate limit spec like "5/hour", "100/day", "10/minute".
 */
export function parseRateLimit(spec: string): RateLimit {
  const match = spec.match(/^(\d+)\/(second|minute|hour|day)$/);
  if (!match) {
    throw new Error(`Invalid rate limit format: "${spec}". Expected "N/unit" (e.g. "5/hour")`);
  }

  const count = parseInt(match[1], 10);
  const unit = match[2];

  const windowMs: Record<string, number> = {
    second: 1_000,
    minute: 60_000,
    hour: 3_600_000,
    day: 86_400_000,
  };

  return { count, windowMs: windowMs[unit] };
}

/**
 * In-memory sliding window rate limiter.
 * Returns { allowed, remaining } based on recent invocations.
 */
export function checkRateLimit(
  key: string,
  limit: RateLimit,
  store: Map<string, number[]>,
): { allowed: boolean; remaining: number } {
  const now = Date.now();
  const windowStart = now - limit.windowMs;

  // Get existing timestamps, prune expired
  const timestamps = (store.get(key) || []).filter((t) => t > windowStart);

  if (timestamps.length >= limit.count) {
    store.set(key, timestamps);
    return { allowed: false, remaining: 0 };
  }

  // Record this invocation
  timestamps.push(now);
  store.set(key, timestamps);

  return { allowed: true, remaining: limit.count - timestamps.length };
}
