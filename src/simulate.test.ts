import { describe, it, expect } from 'vitest';
import { simulate, parseLogFile, formatSimulation } from './simulate.js';
import { writeFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ProtectPolicy } from './types.js';

describe('simulate', () => {
  it('evaluates a permissive log against a strict policy', () => {
    const entries = [
      { v: 2, tool: 'read_file', decision: 'allow', reason_code: 'observe_mode', mode: 'shadow', timestamp: Date.now() },
      { v: 2, tool: 'read_file', decision: 'allow', reason_code: 'observe_mode', mode: 'shadow', timestamp: Date.now() },
      { v: 2, tool: 'delete_file', decision: 'allow', reason_code: 'observe_mode', mode: 'shadow', timestamp: Date.now() },
      { v: 2, tool: 'send_email', decision: 'allow', reason_code: 'observe_mode', mode: 'shadow', timestamp: Date.now() },
    ];

    const policy: ProtectPolicy = {
      tools: {
        'delete_file': { block: true },
        'send_email': { require_approval: true } as any,
        '*': { rate_limit: '100/hour' },
      },
      default_tier: 'unknown',
      policy_engine: 'built-in',
    };

    const result = simulate(entries, policy);

    expect(result.total_calls).toBe(4);
    expect(result.results.allow).toBe(2); // 2 read_file
    expect(result.results.block).toBe(1); // delete_file
    expect(result.results.require_approval).toBe(1); // send_email
    expect(result.original.allow).toBe(4);
    expect(result.original.deny).toBe(0);
    expect(result.changes.length).toBeGreaterThan(0);
  });

  it('detects rate limit exhaustion', () => {
    const entries = Array.from({ length: 12 }, (_, i) => ({
      v: 2,
      tool: 'web_search',
      decision: 'allow',
      reason_code: 'observe_mode',
      mode: 'shadow',
      timestamp: Date.now() + i,
    }));

    const policy: ProtectPolicy = {
      tools: { 'web_search': { rate_limit: '10/minute' } },
      default_tier: 'unknown',
      policy_engine: 'built-in',
    };

    const result = simulate(entries, policy);

    expect(result.results.allow).toBe(10);
    expect(result.results.rate_limited).toBe(2);
  });

  it('detects tier-insufficient decisions', () => {
    const entries = [
      { v: 2, tool: 'admin_tool', decision: 'allow', reason_code: 'observe_mode', mode: 'shadow', timestamp: Date.now() },
    ];

    const policy: ProtectPolicy = {
      tools: { 'admin_tool': { min_tier: 'signed-known' } },
      default_tier: 'unknown',
      policy_engine: 'built-in',
    };

    const result = simulate(entries, policy, 'unknown');

    expect(result.results.tier_insufficient).toBe(1);
    expect(result.results.allow).toBe(0);
  });

  it('handles empty log gracefully', () => {
    const result = simulate([], { tools: {}, default_tier: 'unknown', policy_engine: 'built-in' });
    expect(result.total_calls).toBe(0);
    expect(result.tool_breakdown).toHaveLength(0);
  });
});

describe('parseLogFile', () => {
  it('parses JSONL with [PROTECT_MCP] prefix', () => {
    const tmpFile = join(tmpdir(), `test-log-${Date.now()}.jsonl`);
    const lines = [
      `[PROTECT_MCP] {"v":2,"tool":"read_file","decision":"allow","reason_code":"observe_mode","mode":"shadow","timestamp":${Date.now()}}`,
      `[PROTECT_MCP] {"v":2,"tool":"write_file","decision":"deny","reason_code":"policy_block","mode":"enforce","timestamp":${Date.now()}}`,
      '', // empty line
      'not json', // malformed
    ].join('\n');

    writeFileSync(tmpFile, lines);
    const entries = parseLogFile(tmpFile);
    unlinkSync(tmpFile);

    expect(entries).toHaveLength(2);
    expect(entries[0].tool).toBe('read_file');
    expect(entries[1].tool).toBe('write_file');
  });
});

describe('formatSimulation', () => {
  it('produces readable output', () => {
    const summary = {
      policy_file: 'strict.json',
      log_file: '.protect-mcp-log.jsonl',
      total_calls: 10,
      results: { allow: 6, block: 2, rate_limited: 1, require_approval: 1, tier_insufficient: 0 },
      original: { allow: 10, deny: 0 },
      tool_breakdown: [
        { tool: 'read_file', calls: 6, results: { allow: 6, block: 0, rate_limited: 0, require_approval: 0, tier_insufficient: 0 }, original: { allow: 6, deny: 0 } },
        { tool: 'delete_file', calls: 2, results: { allow: 0, block: 2, rate_limited: 0, require_approval: 0, tier_insufficient: 0 }, original: { allow: 2, deny: 0 } },
      ],
      changes: ['delete_file: 2 calls would be blocked (was: all allowed)'],
    };

    const output = formatSimulation(summary);
    expect(output).toContain('strict.json');
    expect(output).toContain('read_file');
    expect(output).toContain('delete_file');
    expect(output).toContain('2 blocked');
    expect(output).toContain('Changes:');
  });
});
