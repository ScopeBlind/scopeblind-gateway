import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  buildCoverageStatement,
  analyzeBuiltInPolicy,
  handleCoverage,
  DEFAULT_NOT_GOVERNED,
  RESIDUAL_BYPASS_ROUTES,
} from './coverage.js';

const BASE_INPUT = {
  mode: 'hook' as const,
  enforce: true,
  engine: 'built-in' as const,
  policyDigest: 'abc123',
  policySource: 'policy.json',
  governedTools: ['send_email', 'read_file'],
  blockedTools: ['send_email'],
  wildcardRule: 'require: any',
  probe: { method: 'static-policy-probe' as const, probe_tool: 'send_email', would_deny: true },
  packageVersion: '0.0.0-test',
  generatedAt: '2026-07-09T00:00:00.000Z',
};

describe('buildCoverageStatement', () => {
  it('always includes the default not_governed items, appending extras after them', () => {
    const bare = buildCoverageStatement(BASE_INPUT);
    expect(bare.not_governed).toEqual([...DEFAULT_NOT_GOVERNED]);

    const withExtras = buildCoverageStatement({
      ...BASE_INPUT,
      extraNotGoverned: ['the trading desk Bloomberg terminal', '  '],
    });
    expect(withExtras.not_governed.slice(0, DEFAULT_NOT_GOVERNED.length)).toEqual([
      ...DEFAULT_NOT_GOVERNED,
    ]);
    expect(withExtras.not_governed).toContain('the trading desk Bloomberg terminal');
    // Blank extras are dropped, defaults are never displaced.
    expect(withExtras.not_governed.length).toBe(DEFAULT_NOT_GOVERNED.length + 1);
  });

  it('is a scope enumeration: no numeric coverage claims anywhere in the statement', () => {
    const s = buildCoverageStatement(BASE_INPUT);
    const text = JSON.stringify(s).toLowerCase();
    expect(text).not.toMatch(/coverage[_ ]?(score|percent|pct|ratio)/);
    expect(text).not.toMatch(/%/);
  });

  it('binds the policy digest, engine, and enforcement mode', () => {
    const s = buildCoverageStatement(BASE_INPUT);
    expect(s.type).toBe('scopeblind.coverage_statement.v1');
    expect(s.policy.digest).toBe('abc123');
    expect(s.policy.engine).toBe('built-in');
    expect(s.deployment.enforcement).toBe('enforce');
    expect(buildCoverageStatement({ ...BASE_INPUT, enforce: false }).deployment.enforcement).toBe('shadow');
  });

  it('carries the residual bypass-route table and the epistemic limit', () => {
    const s = buildCoverageStatement(BASE_INPUT);
    expect(s.residual_bypass_routes).toEqual(RESIDUAL_BYPASS_ROUTES);
    expect(s.residual_bypass_routes.length).toBe(5);
    expect(s.attestation_note).toMatch(/not a proof of the absence/);
    expect(s.basis).toBe('configuration-at-generation-time');
    expect(s.attestation_note).toMatch(/configuration at generation time/);
  });

  it('sorts tool lists for deterministic output', () => {
    const s = buildCoverageStatement({
      ...BASE_INPUT,
      governedTools: ['zeta', 'alpha'],
      blockedTools: ['zeta', 'alpha'],
    });
    expect(s.governed.tools_with_explicit_rules).toEqual(['alpha', 'zeta']);
    expect(s.governed.explicitly_blocked_tools).toEqual(['alpha', 'zeta']);
  });
});

describe('analyzeBuiltInPolicy', () => {
  const policy = {
    tools: {
      send_email: { block: true },
      read_file: { require: 'any' },
      '*': { require: 'any' },
    },
  };

  it('enumerates governed and blocked tools, excluding the wildcard', () => {
    const a = analyzeBuiltInPolicy(policy as any);
    expect(a.governedTools.sort()).toEqual(['read_file', 'send_email']);
    expect(a.blockedTools).toEqual(['send_email']);
    expect(a.wildcardRule).toBe('require: any');
  });

  it('probes the first blocked tool through the real getToolPolicy path', () => {
    const a = analyzeBuiltInPolicy(policy as any);
    expect(a.probe.method).toBe('static-policy-probe');
    expect(a.probe.probe_tool).toBe('send_email');
    expect(a.probe.would_deny).toBe(true);
  });

  it('reports an honest no-probe reason when nothing is blocked', () => {
    const a = analyzeBuiltInPolicy({ tools: { read_file: { require: 'any' } } } as any);
    expect(a.probe.method).toBe('none');
    expect(a.probe.reason).toMatch(/no explicitly blocked tool/);
  });
});

describe('handleCoverage (integration, unsigned path)', () => {
  let dir: string;
  afterEach(() => {
    if (dir && existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  });

  it('writes an unsigned statement file that says plainly it is unsigned', async () => {
    dir = mkdtempSync(join(tmpdir(), 'coverage-test-'));
    const policyPath = join(dir, 'policy.json');
    const outPath = join(dir, 'scopeblind-coverage.json');
    writeFileSync(
      policyPath,
      JSON.stringify({ tools: { dangerous_tool: { block: true }, '*': { require: 'any' } } }),
    );

    await handleCoverage(['--mode', 'hook', '--enforce', '--policy', policyPath, '--out', outPath]);

    const written = JSON.parse(readFileSync(outPath, 'utf-8'));
    expect(written.signature).toBeNull();
    expect(written.unsigned_reason).toMatch(/declaration, not evidence/);
    const stmt = written.artifact;
    expect(stmt.type).toBe('scopeblind.coverage_statement.v1');
    expect(stmt.policy.engine).toBe('built-in');
    expect(stmt.governed.explicitly_blocked_tools).toEqual(['dangerous_tool']);
    expect(stmt.self_test.would_deny).toBe(true);
    expect(stmt.not_governed.length).toBeGreaterThanOrEqual(DEFAULT_NOT_GOVERNED.length);
    expect(stmt.basis).toBe('configuration-at-generation-time');
    // The live evaluator self-test rides along: runtime-proven fail-closed
    // vectors, not only the static configuration probe.
    expect((stmt.evaluator_self_test as { passed?: boolean } | undefined)?.passed).toBe(true);
  });

  it('requires --mode and sets a failing exit code without it', async () => {
    dir = mkdtempSync(join(tmpdir(), 'coverage-test-'));
    const prev = process.exitCode;
    await handleCoverage([]);
    expect(process.exitCode).toBe(1);
    process.exitCode = prev;
  });
});
