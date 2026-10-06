import { describe, it, expect, beforeEach } from 'vitest';
import { writeFileSync, mkdtempSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadCedarPolicies, evaluateCedar, runEvaluatorSelfTest, policySetFromSource, cedarSafeValue, checkCedarPolicyText } from './cedar-evaluator.js';

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
    expect(result.digest).toMatch(/^sha256:[0-9a-f]{64}$/); // acta-policy-digest-v1
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

// ============================================================
// Inputs Cedar can hold (0.31.0)
// ============================================================

describe('cedarSafeValue', () => {
  it('drops nulls, keeps whole numbers Cedar can hold, and writes other numbers as text', () => {
    expect(cedarSafeValue({ a: null, b: undefined, c: 1, d: -7, e: 1.5, f: 0.5, g: 1e20, h: 2 ** 62, i: 'x', j: true }))
      .toEqual({ c: 1, d: -7, e: '1.5', f: '0.5', g: '100000000000000000000', h: 2 ** 62, i: 'x', j: true });
    expect(cedarSafeValue([100.5, 200, null, 'a'])).toEqual(['100.5', 200, 'a']);
    expect(cedarSafeValue(2 ** 63)).toBe('9223372036854776000');
    expect(cedarSafeValue(-(2 ** 63))).toBe('-9223372036854776000');
    expect(cedarSafeValue(Number.NaN)).toBe('NaN');
    expect(cedarSafeValue(null)).toBeUndefined();
  });

  it('keeps a "__proto__" key an ordinary field, as JSON.parse made it', async () => {
    const input = JSON.parse('{"__proto__":{"command":"rm -rf /"},"x":1}') as Record<string, unknown>;
    const safe = cedarSafeValue(input) as Record<string, unknown>;
    expect(Object.keys(safe)).toEqual(['__proto__', 'x']);
    expect(Object.getPrototypeOf(safe)).toBe(Object.prototype);
    expect((safe as { command?: unknown }).command).toBeUndefined();
    const policy = policySetFromSource('forbid(principal, action, resource) when { context has input && context.input has "__proto__" };\npermit(principal, action, resource);');
    expect((await evaluateCedar(policy, { tool: 'mcp__x__y', tier: 'unknown', toolInput: input })).allowed).toBe(false);
    expect((await evaluateCedar(policy, { tool: 'mcp__x__y', tier: 'unknown', toolInput: { x: 1 } })).allowed).toBe(true);
  });

  it('drops the Cedar escape keys at any depth, and only those', () => {
    expect(cedarSafeValue({ ref: { __entity: { type: 'Tool', id: 'Bash' }, keep: 1 }, list: [{ __extn: { fn: 'ip', arg: 'x' } }], __expr: 'true', __other: 2 }))
      .toEqual({ ref: { keep: 1 }, list: [{}], __other: 2 });
  });
});

describe('evaluateCedar with inputs 0.30.0 refused under every policy', () => {
  const PERMIT_ALL = policySetFromSource('permit(principal, action, resource);');
  const inputs: Array<Record<string, unknown>> = [
    { coordinate: [100.5, 200] },
    { zoom: 1.5 },
    { offset: null },
    { big: 1e20 },
    { ref: { __entity: { type: 'Tool', id: 'Bash' } } },
    { host: { __extn: { fn: 'ip', arg: 'not an address' } } },
    { v: { __expr: 'true' } },
  ];

  it('permit-all allows every one of them', async () => {
    for (const toolInput of inputs) {
      const d = await evaluateCedar(PERMIT_ALL, { tool: 'mcp__browser__act', tier: 'unknown', context: { ...toolInput }, toolInput });
      expect(d.allowed, `${JSON.stringify(toolInput)} -> ${d.reason}`).toBe(true);
    }
  });

  it('a policy sees a fraction as its text: == "1.5" matches, a numeric comparison errors and fails closed', async () => {
    const text = policySetFromSource('forbid(principal, action, resource) when { context has input && context.input has zoom && context.input.zoom == "1.5" };\npermit(principal, action, resource);');
    expect((await evaluateCedar(text, { tool: 'zoom', tier: 'unknown', toolInput: { zoom: 1.5 } })).allowed).toBe(false);
    expect((await evaluateCedar(text, { tool: 'zoom', tier: 'unknown', toolInput: { zoom: 2 } })).allowed).toBe(true);
    const numeric = policySetFromSource('forbid(principal, action, resource) when { context has input && context.input has zoom && context.input.zoom > 1 };\npermit(principal, action, resource);');
    const d = await evaluateCedar(numeric, { tool: 'zoom', tier: 'unknown', toolInput: { zoom: 1.5 } });
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/^cedar_policy_errored/);
    expect((await evaluateCedar(numeric, { tool: 'zoom', tier: 'unknown', toolInput: { zoom: 3 } })).allowed).toBe(false);
    expect((await evaluateCedar(numeric, { tool: 'zoom', tier: 'unknown', toolInput: { zoom: 1 } })).allowed).toBe(true);
  });

  it('decimal() reads a fraction with at most four decimal places', async () => {
    const policy = policySetFromSource('forbid(principal, action, resource) when { context has input && context.input has zoom && decimal(context.input.zoom).greaterThan(decimal("1.25")) };\npermit(principal, action, resource);');
    expect((await evaluateCedar(policy, { tool: 'zoom', tier: 'unknown', toolInput: { zoom: 1.5 } })).allowed).toBe(false);
    expect((await evaluateCedar(policy, { tool: 'zoom', tier: 'unknown', toolInput: { zoom: 1.125 } })).allowed).toBe(true);
    // Five places is not a Cedar decimal: the rule errors and the gate fails closed.
    expect((await evaluateCedar(policy, { tool: 'zoom', tier: 'unknown', toolInput: { zoom: 1.12345 } })).allowed).toBe(false);
  });

  it('a whole number stays a number, so numeric rules decide as before', async () => {
    const cap = policySetFromSource('forbid(principal, action, resource) when { context has input && context.input has amount && context.input.amount > 1000 };\npermit(principal, action, resource);');
    expect((await evaluateCedar(cap, { tool: 'pay', tier: 'unknown', toolInput: { amount: 1001 } })).allowed).toBe(false);
    expect((await evaluateCedar(cap, { tool: 'pay', tier: 'unknown', toolInput: { amount: 1000 } })).allowed).toBe(true);
    expect((await evaluateCedar(cap, { tool: 'pay', tier: 'unknown', toolInput: { amount: 2 ** 60 } })).allowed).toBe(false);
  });
});

// ============================================================
// Deny reasons name the rule (0.31.0)
// ============================================================

describe('deny reasons name the rule by @id and @reason', () => {
  const tool = (command: string) => ({ tool: 'Bash', tier: 'unknown' as const, toolInput: { command } });

  it('a matching forbid is named with its reason', async () => {
    const policy = policySetFromSource([
      '@id("allow-all") permit(principal, action, resource);',
      '@id("no-rm") @reason("Deletes files. Ask first.") forbid(principal, action, resource) when { context has input && context.input has command && context.input.command like "rm *" };',
    ].join('\n'));
    const d = await evaluateCedar(policy, tool('rm -rf x'));
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe('cedar_deny: no-rm: Deletes files. Ask first.');
    expect(d.metadata).toMatchObject({ matched_policies: ['no-rm'], denied_by: [{ id: 'no-rm', reason: 'Deletes files. Ask first.' }], default_deny: false });
    const ok = await evaluateCedar(policy, tool('ls'));
    expect(ok.allowed).toBe(true);
    expect(ok.metadata?.matched_policies).toEqual(['allow-all']);
  });

  it('several matching forbids are named in source order', async () => {
    const policy = policySetFromSource([
      'permit(principal, action, resource);',
      '@id("b-second") @reason("Second.") forbid(principal, action, resource) when { context has input && context.input has command && context.input.command like "*x*" };',
      '@id("a-first") forbid(principal, action, resource) when { context has input && context.input has command && context.input.command like "*y*" };',
    ].join('\n'));
    const d = await evaluateCedar(policy, tool('xy'));
    expect(d.reason).toBe('cedar_deny: b-second: Second.; a-first');
  });

  it('no permit matched is a default deny, and says so', async () => {
    const policy = policySetFromSource('@id("only-read") permit(principal, action, resource == Tool::"Read");');
    const d = await evaluateCedar(policy, tool('ls'));
    expect(d.allowed).toBe(false);
    expect(d.reason).toBe('cedar_deny: no permit matched (default deny)');
    expect(d.metadata).toMatchObject({ default_deny: true, denied_by: [] });
  });

  it('a rule without a usable @id keeps the positional id Cedar would give it, past ten rules', async () => {
    const rules = Array.from({ length: 12 }, (_, i) => `forbid(principal, action, resource) when { context has input && context.input has command && context.input.command == "r${i}" };`);
    const policy = policySetFromSource(['permit(principal, action, resource);', ...rules].join('\n'));
    // policy0 is the permit, so rule i is policy(i+1).
    expect((await evaluateCedar(policy, tool('r1'))).reason).toBe('cedar_deny: policy2');
    expect((await evaluateCedar(policy, tool('r9'))).reason).toBe('cedar_deny: policy10');
    expect((await evaluateCedar(policy, tool('r11'))).reason).toBe('cedar_deny: policy12');
  });

  it('a repeated or positional-looking @id falls back to the positional id', async () => {
    const policy = policySetFromSource([
      'permit(principal, action, resource);',
      '@id("same") forbid(principal, action, resource) when { context has input && context.input has command && context.input.command == "a" };',
      '@id("same") forbid(principal, action, resource) when { context has input && context.input has command && context.input.command == "b" };',
      '@id("policy0") forbid(principal, action, resource) when { context has input && context.input has command && context.input.command == "c" };',
    ].join('\n'));
    expect((await evaluateCedar(policy, tool('a'))).reason).toBe('cedar_deny: policy1');
    expect((await evaluateCedar(policy, tool('b'))).reason).toBe('cedar_deny: policy2');
    expect((await evaluateCedar(policy, tool('c'))).reason).toBe('cedar_deny: policy3');
  });

  it('an @id that could not be an object key never lets a forbid go missing', async () => {
    const policy = policySetFromSource([
      'permit(principal, action, resource);',
      '@id("__proto__") @reason("Still a rule.") forbid(principal, action, resource) when { context has input && context.input has command && context.input.command == "a" };',
      '@id("constructor") forbid(principal, action, resource) when { context has input && context.input has command && context.input.command == "b" };',
    ].join('\n'));
    const a = await evaluateCedar(policy, tool('a'));
    expect(a.allowed).toBe(false);
    expect(a.reason).toBe('cedar_deny: policy1: Still a rule.');
    const b = await evaluateCedar(policy, tool('b'));
    expect(b.allowed).toBe(false);
    expect(b.reason).toBe('cedar_deny: constructor');
    expect((await evaluateCedar(policy, tool('c'))).allowed).toBe(true);
  });

  it('a reason is kept to one line', async () => {
    const policy = policySetFromSource('permit(principal, action, resource);\n@id("r") @reason("Line one.\\n   Line two.") forbid(principal, action, resource);');
    expect((await evaluateCedar(policy, tool('x'))).reason).toBe('cedar_deny: r: Line one. Line two.');
  });

  it('naming the rules does not change the policy digest', () => {
    const text = '@id("x") permit(principal, action, resource);';
    expect(policySetFromSource(text).digest).toBe(policySetFromSource(text).digest);
    expect(policySetFromSource(text).source).toBe(text);
  });
});

describe('checkCedarPolicyText', () => {
  it('accepts a policy that parses and names the error in one that does not', async () => {
    expect(await checkCedarPolicyText('permit(principal, action, resource);')).toEqual({ checked: true, ok: true });
    const bad = await checkCedarPolicyText('permit(principal, action, resource) when { context.x like };');
    expect(bad.checked).toBe(true);
    expect(bad.ok).toBe(false);
    expect(bad.error).toBeTruthy();
  });
});
