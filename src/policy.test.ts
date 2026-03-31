import { describe, it, expect, beforeEach } from 'vitest';
import { writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadPolicy, getToolPolicy, parseRateLimit, checkRateLimit } from './policy.js';
import type { ProtectPolicy, RateLimit } from './types.js';

// ============================================================
// loadPolicy
// ============================================================

describe('loadPolicy', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'protect-mcp-test-'));
  });

  it('loads a valid policy file and returns policy + digest', () => {
    const policyFile = join(tmpDir, 'policy.json');
    writeFileSync(policyFile, JSON.stringify({
      tools: {
        'file_write': { block: true },
        '*': { rate_limit: '10/minute' },
      },
    }));

    const { policy, digest } = loadPolicy(policyFile);
    expect(policy.tools).toBeDefined();
    expect(policy.tools['file_write']).toEqual({ block: true });
    expect(policy.tools['*']).toEqual({ rate_limit: '10/minute' });
    expect(digest).toHaveLength(16);
    expect(/^[a-f0-9]{16}$/.test(digest)).toBe(true);
  });

  it('produces deterministic digest regardless of key order', () => {
    const policyFile1 = join(tmpDir, 'p1.json');
    const policyFile2 = join(tmpDir, 'p2.json');

    writeFileSync(policyFile1, JSON.stringify({
      tools: { a: { block: true }, b: { rate_limit: '5/hour' } },
    }));
    writeFileSync(policyFile2, JSON.stringify({
      tools: { b: { rate_limit: '5/hour' }, a: { block: true } },
    }));

    const { digest: d1 } = loadPolicy(policyFile1);
    const { digest: d2 } = loadPolicy(policyFile2);
    expect(d1).toBe(d2);
  });

  it('throws on invalid JSON', () => {
    const badFile = join(tmpDir, 'bad.json');
    writeFileSync(badFile, '{ not valid json }');
    expect(() => loadPolicy(badFile)).toThrow();
  });

  it('throws on missing "tools" field', () => {
    const noTools = join(tmpDir, 'no-tools.json');
    writeFileSync(noTools, JSON.stringify({ rules: {} }));
    expect(() => loadPolicy(noTools)).toThrow(/missing "tools"/);
  });

  it('throws on non-object "tools" field', () => {
    const badTools = join(tmpDir, 'bad-tools.json');
    writeFileSync(badTools, JSON.stringify({ tools: 'not-object' }));
    expect(() => loadPolicy(badTools)).toThrow(/missing "tools"/);
  });

  it('throws on non-existent file', () => {
    expect(() => loadPolicy('/nonexistent/policy.json')).toThrow();
  });
});

// ============================================================
// getToolPolicy
// ============================================================

describe('getToolPolicy', () => {
  const policy: ProtectPolicy = {
    tools: {
      'file_write': { block: true },
      'web_search': { rate_limit: '5/minute' },
      '*': { require: 'gateway', rate_limit: '100/hour' },
    },
  };

  it('returns exact match for a named tool', () => {
    expect(getToolPolicy('file_write', policy)).toEqual({ block: true });
  });

  it('returns exact match for another named tool', () => {
    expect(getToolPolicy('web_search', policy)).toEqual({ rate_limit: '5/minute' });
  });

  it('falls back to wildcard for unknown tool', () => {
    expect(getToolPolicy('unknown_tool', policy)).toEqual({ require: 'gateway', rate_limit: '100/hour' });
  });

  it('returns default allow when no policy provided', () => {
    expect(getToolPolicy('any_tool', null)).toEqual({ require: 'any' });
  });

  it('returns default allow when policy has no wildcard and no match', () => {
    const noWildcard: ProtectPolicy = {
      tools: {
        'file_write': { block: true },
      },
    };
    expect(getToolPolicy('other_tool', noWildcard)).toEqual({ require: 'any' });
  });
});

// ============================================================
// parseRateLimit
// ============================================================

describe('parseRateLimit', () => {
  it('parses "5/second"', () => {
    expect(parseRateLimit('5/second')).toEqual({ count: 5, windowMs: 1_000 });
  });

  it('parses "10/minute"', () => {
    expect(parseRateLimit('10/minute')).toEqual({ count: 10, windowMs: 60_000 });
  });

  it('parses "100/hour"', () => {
    expect(parseRateLimit('100/hour')).toEqual({ count: 100, windowMs: 3_600_000 });
  });

  it('parses "1000/day"', () => {
    expect(parseRateLimit('1000/day')).toEqual({ count: 1000, windowMs: 86_400_000 });
  });

  it('throws on invalid format "5 per hour"', () => {
    expect(() => parseRateLimit('5 per hour')).toThrow(/Invalid rate limit format/);
  });

  it('throws on invalid unit "5/week"', () => {
    expect(() => parseRateLimit('5/week')).toThrow(/Invalid rate limit format/);
  });

  it('throws on empty string', () => {
    expect(() => parseRateLimit('')).toThrow(/Invalid rate limit format/);
  });

  it('throws on missing count "minute"', () => {
    expect(() => parseRateLimit('/minute')).toThrow(/Invalid rate limit format/);
  });
});

// ============================================================
// checkRateLimit
// ============================================================

describe('checkRateLimit', () => {
  let store: Map<string, number[]>;
  const limit: RateLimit = { count: 3, windowMs: 60_000 };

  beforeEach(() => {
    store = new Map();
  });

  it('allows first request and reports remaining', () => {
    const result = checkRateLimit('tool:test', limit, store);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(2);
  });

  it('allows up to the limit', () => {
    checkRateLimit('tool:test', limit, store);
    checkRateLimit('tool:test', limit, store);
    const result = checkRateLimit('tool:test', limit, store);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(0);
  });

  it('denies after limit is reached', () => {
    checkRateLimit('tool:test', limit, store);
    checkRateLimit('tool:test', limit, store);
    checkRateLimit('tool:test', limit, store);
    const result = checkRateLimit('tool:test', limit, store);
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
  });

  it('uses independent buckets per key', () => {
    checkRateLimit('tool:a', limit, store);
    checkRateLimit('tool:a', limit, store);
    checkRateLimit('tool:a', limit, store);

    // tool:b should still have full budget
    const result = checkRateLimit('tool:b', limit, store);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(2);
  });

  it('prunes expired timestamps and allows again', () => {
    // Manually insert old timestamps
    const pastTime = Date.now() - 120_000; // 2 minutes ago
    store.set('tool:test', [pastTime, pastTime + 1, pastTime + 2]);

    // All 3 are expired, so we should be allowed
    const result = checkRateLimit('tool:test', limit, store);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(2);
  });

  it('handles empty store gracefully', () => {
    const result = checkRateLimit('nonexistent', limit, store);
    expect(result.allowed).toBe(true);
  });
});
