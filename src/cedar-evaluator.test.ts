import { describe, it, expect, beforeEach } from 'vitest';
import { writeFileSync, mkdtempSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadCedarPolicies, evaluateCedar, runEvaluatorSelfTest, policySetFromSource } from './cedar-evaluator.js';

// ============================================================
// loadCedarPolicies
// ============================================================

describe('loadCedarPolicies', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'cedar-test-'));
  });

  it('loads .cedar files from a directory', () => {
    writeFileSync(join(tmpDir, 'test.cedar'), `
      @id("test-001")
      forbid (
        principal,
        action == Action::"MCP::Tool::call",
        resource == Tool::"bash"
      );
    `);

    const result = loadCedarPolicies(tmpDir);
    expect(result.fileCount).toBe(1);
    expect(result.files).toEqual(['test.cedar']);
    expect(result.source).toContain('test-001');
    expect(result.digest).toHaveLength(16);
    expect(/^[a-f0-9]{16}$/.test(result.digest)).toBe(true);
  });

  it('loads multiple .cedar files sorted alphabetically', () => {
    writeFileSync(join(tmpDir, 'b-policy.cedar'), '@id("b-001") forbid(principal, action, resource);');
    writeFileSync(join(tmpDir, 'a-policy.cedar'), '@id("a-001") forbid(principal, action, resource);');

    const result = loadCedarPolicies(tmpDir);
    expect(result.fileCount).toBe(2);
    expect(result.files).toEqual(['a-policy.cedar', 'b-policy.cedar']);
    // Source should contain both policies
    expect(result.source).toContain('a-001');
    expect(result.source).toContain('b-001');
  });

  it('produces deterministic digest regardless of file creation order', () => {
    const dir1 = mkdtempSync(join(tmpdir(), 'cedar-det-1-'));
    const dir2 = mkdtempSync(join(tmpdir(), 'cedar-det-2-'));

    // Same files, different creation order
    writeFileSync(join(dir1, 'a.cedar'), 'forbid(principal, action, resource);');
    writeFileSync(join(dir1, 'b.cedar'), 'permit(principal, action, resource);');

    writeFileSync(join(dir2, 'b.cedar'), 'permit(principal, action, resource);');
    writeFileSync(join(dir2, 'a.cedar'), 'forbid(principal, action, resource);');

    const r1 = loadCedarPolicies(dir1);
    const r2 = loadCedarPolicies(dir2);
    expect(r1.digest).toBe(r2.digest);
  });

  it('throws on non-existent directory', () => {
    expect(() => loadCedarPolicies('/nonexistent/cedar/dir')).toThrow(/not found/);
  });

  it('throws on directory with no .cedar files', () => {
    writeFileSync(join(tmpDir, 'not-cedar.json'), '{}');
    expect(() => loadCedarPolicies(tmpDir)).toThrow(/No .cedar files/);
  });

  it('ignores non-.cedar files', () => {
    writeFileSync(join(tmpDir, 'policy.cedar'), '@id("only-this") forbid(principal, action, resource);');
    writeFileSync(join(tmpDir, 'readme.md'), '# Not a Cedar file');
    writeFileSync(join(tmpDir, 'config.json'), '{}');

    const result = loadCedarPolicies(tmpDir);
    expect(result.fileCount).toBe(1);
    expect(result.files).toEqual(['policy.cedar']);
  });
});

// ============================================================
// evaluateCedar: fail-closed semantics (0.7.0 security release)
// ============================================================

const FORBID_RM = policySetFromSource(
  'forbid(principal, action, resource) when { ["rm", "dd", "mkfs"].contains(context.command) };\npermit(principal, action, resource);',
);
// The 0.6.x advisory pattern: `in` on a String type-errors and Cedar silently
// discards the rule, leaving a residual permit. The gate must NOT honor it.
const BROKEN_IN_ON_STRING = policySetFromSource(
  'forbid(principal, action, resource) when { context.command in ["rm", "dd"] };\npermit(principal, action, resource);',
);
const REQ = (command: string) => ({ tool: 'Bash', tier: 'unknown' as const, context: { command } });

describe('evaluateCedar fail-closed semantics', () => {
  it('a real forbid actually denies (Cedar evaluates, not a no-op)', async () => {
    const d = await evaluateCedar(FORBID_RM, REQ('rm'));
    expect(d.allowed).toBe(false);
    expect(d.reason).toContain('cedar_deny');
  });

  it('a permit allows a non-forbidden command', async () => {
    const d = await evaluateCedar(FORBID_RM, REQ('ls'));
    expect(d.allowed).toBe(true);
  });

  it('an in-on-String policy DENIES instead of silently permit-all (regression for #598)', async () => {
    const d = await evaluateCedar(BROKEN_IN_ON_STRING, REQ('rm'));
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/cedar_(policy_errored|eval_error|unparseable|failure)/);
  });

  it('observe mode (failClosed:false) allows on error but flags would_deny', async () => {
    const d = await evaluateCedar(BROKEN_IN_ON_STRING, REQ('rm'), undefined, { failClosed: false });
    expect(d.allowed).toBe(true);
    expect(d.metadata).toMatchObject({ would_deny: true });
    expect(d.reason).toContain('observe mode');
  });

  it('the proof-of-restraint self-test passes on the live engine', async () => {
    const report = await runEvaluatorSelfTest();
    expect(report.passed).toBe(true);
    for (const c of report.cases) expect(c.pass, `${c.name}: expected ${c.expected}, got ${c.actual}`).toBe(true);
  });
});
