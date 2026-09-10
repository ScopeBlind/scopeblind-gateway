import { describe, it, expect } from 'vitest';
import { evaluateCedar, policySetFromSource } from './cedar-evaluator';

// agent-governance-testvectors/fixtures/policy/autoresearch-safe.cedar, in the
// valid-Cedar form: set membership on strings is `.contains()`, not `in`.
const CONFORMANCE_POLICY = `
permit (principal, action in [Action::"Read", Action::"Glob", Action::"Grep", Action::"WebSearch"], resource);
permit (principal, action == Action::"Bash", resource) when {
  ["git", "npm", "ls", "cat", "pwd", "echo", "node", "python"].contains(context.command_pattern)
};
forbid (principal, action == Action::"Bash", resource) when {
  ["rm -rf", "dd", "mkfs", "shred"].contains(context.command_pattern)
};
permit (principal, action in [Action::"Write", Action::"Edit"], resource) when {
  context.path_starts_with == "./"
};
`;
// The form the corpus shipped until 2026-09-10. Real Cedar rejects it: `in` is
// the entity-hierarchy operator, and a string on its left is a type error.
const INVALID_IN_FORM = `
permit (principal, action == Action::"Bash", resource) when {
  context.command_pattern in ["git", "npm"]
};
`;
const cases: Array<[string, Record<string, unknown>, Record<string, unknown>, boolean]> = [
  ['Read',  { file_path: './README.md' },              { path_starts_with: './' },    true],
  ['Bash',  { command: 'git status' },                 { command_pattern: 'git' },    true],
  ['Bash',  { command: 'rm -rf /' },                   { command_pattern: 'rm -rf' }, false],
  ['Write', { file_path: './notes.md', content: 'x' }, { path_starts_with: './' },    true],
];
describe("actionModel 'tool' evaluates the conformance policy", () => {
  const policySet = policySetFromSource(CONFORMANCE_POLICY, 'autoresearch-safe');
  for (const [tool, toolInput, context, expected] of cases) {
    it(`${tool} ${JSON.stringify(context)} -> ${expected ? 'allow' : 'deny'}`, async () => {
      const d = await evaluateCedar(policySet, { tool, tier: 'unknown', context, toolInput, actionModel: 'tool' });
      expect(d.allowed).toBe(expected);
    });
  }
  it("the default 'mcp' model denies this policy: nothing permits Action::\"MCP::Tool::call\"", async () => {
    const d = await evaluateCedar(policySet, { tool: 'Read', tier: 'unknown', context: { path_starts_with: './' }, actionModel: 'mcp' });
    expect(d.allowed).toBe(false);
  });
});

describe("a string on the left of `in` is a policy error, and fail-closed denies it", () => {
  it('reports the error instead of guessing', async () => {
    const d = await evaluateCedar(policySetFromSource(INVALID_IN_FORM, 'invalid-in'),
      { tool: 'Bash', tier: 'unknown', context: { command_pattern: 'git' }, actionModel: 'tool' });
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/policy error/);
    const errs = (d.metadata as { policy_errors?: Array<{ message: string }> }).policy_errors ?? [];
    expect(errs.some((e) => /expected \(entity/.test(e.message))).toBe(true);
  });
});
