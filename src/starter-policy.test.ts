/**
 * The starter policy, held to its vectors.
 *
 * vectors/starter-policy.v1.json carries the 59 calls the starter was designed
 * against (28 it must allow, 31 it must block, each block naming its rule) and
 * the inputs Cedar cannot hold as they are: fractions, nulls, numbers beyond 64
 * bits and Cedar escape keys. Here the real Cedar engine decides every one, with
 * the call built the way `evaluate --policy builtin:starter` builds it. The
 * built CLI is exercised on the same file in cli-format.test.ts.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateCedar, policySetFromSource, isCedarAvailable, type CedarPolicySet } from './cedar-evaluator.js';
import {
  STARTER_POLICY,
  STARTER_CONTAIN_TEMPLATE,
  starterRules,
  renderContainRules,
  cedarLikeLiteral,
  resolveBuiltinPolicy,
  builtinPolicyNames,
} from './starter-policy.js';
import { getPolicyPack } from './policy-packs.js';
import { generateSampleCedarPolicy } from './hook-patterns.js';

interface Case { id: string; tool: string; input: Record<string, unknown>; decision: 'allow' | 'deny'; rule?: string; note: string }
interface InputCase { id: string; tool: string; input: Record<string, unknown>; allow_all: 'allow' | 'deny'; starter: 'allow' | 'deny'; rule?: string; note: string }
interface Vectors {
  type: string;
  policy: { spec: string; file: string; version: number; forbid_rules: number; policy_digest: string };
  cases: Case[];
  input_cases: InputCase[];
}

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const vectors = JSON.parse(readFileSync(join(root, 'vectors/starter-policy.v1.json'), 'utf-8')) as Vectors;
const starter = policySetFromSource(STARTER_POLICY, 'builtin:starter');
const allowAll = policySetFromSource('permit(principal, action, resource);', 'allow-all.cedar');
const reasonOf = new Map(starterRules().map((rule) => [rule.id, rule.reason]));

/** The call as `evaluate --policy <p> --tool <t> --input <json>` builds it. */
function evaluateLikeCli(policySet: CedarPolicySet, tool: string, input: Record<string, unknown>) {
  const context: Record<string, unknown> = { ...input };
  if (typeof input.command === 'string') context.command_pattern = input.command;
  return evaluateCedar(policySet, { tool, tier: 'unknown', context, toolInput: input, actionModel: 'mcp' }, undefined, { failClosed: true });
}

describe('one starter text, everywhere it is handed out', () => {
  it('policies/starter.cedar, builtin:starter, the coding-starter pack and init-hooks are the same bytes', () => {
    expect(readFileSync(join(root, vectors.policy.file), 'utf-8')).toBe(STARTER_POLICY);
    expect(resolveBuiltinPolicy('builtin:starter')?.source).toBe(STARTER_POLICY);
    expect(getPolicyPack('coding-starter')?.files.map((f) => f.contents)).toEqual([STARTER_POLICY]);
    expect(generateSampleCedarPolicy()).toBe(STARTER_POLICY);
  });

  it('pins the reviewed text by digest, the one evaluate --policy reports for it', () => {
    expect(vectors.type).toBe('scopeblind.starter-policy-vectors.v1');
    expect(vectors.policy.spec).toBe('builtin:starter');
    expect(starter.digest).toBe(vectors.policy.policy_digest);
  });

  it('names built-ins only by their spec', () => {
    expect(builtinPolicyNames()).toEqual(['builtin:starter']);
    expect(resolveBuiltinPolicy('builtin:nope')).toBeNull();
    expect(resolveBuiltinPolicy('builtin:toString')).toBeNull();
    expect(resolveBuiltinPolicy('./protect.cedar')).toBeNull();
  });
});

describe('every rule has an @id and every forbid an @reason', () => {
  it('reads the annotations through the Cedar engine', async () => {
    expect(await isCedarAvailable()).toBe(true);
    const cedar: any = await import('@cedar-policy/cedar-wasm/nodejs');
    const parts = cedar.policySetTextToParts(STARTER_POLICY);
    expect(parts.type).toBe('success');
    expect(parts.policy_templates).toEqual([]);
    const policies = parts.policies.map((text: string) => cedar.policyToJson(text).json);
    expect(policies).toHaveLength(8);
    const permits = policies.filter((p: any) => p.effect === 'permit');
    const forbids = policies.filter((p: any) => p.effect === 'forbid');
    expect(permits.map((p: any) => p.annotations)).toEqual([{ id: 'starter.allow-by-default' }]);
    expect(forbids).toHaveLength(vectors.policy.forbid_rules);
    for (const f of forbids) {
      expect(f.annotations.id).toMatch(/^starter\.[a-z-]+$/);
      expect(typeof f.annotations.reason).toBe('string');
      expect(f.annotations.reason.length).toBeGreaterThan(20);
    }
    const ids = forbids.map((f: any) => f.annotations.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(starterRules().map((r) => r.id).sort()).toEqual([...ids].sort());
  });
});

describe('the 59 starter cases through the real engine', () => {
  it('carries 28 calls to allow and 31 to block, each block naming a rule', () => {
    expect(vectors.cases).toHaveLength(59);
    expect(vectors.cases.filter((c) => c.decision === 'allow')).toHaveLength(28);
    expect(vectors.cases.filter((c) => c.decision === 'deny')).toHaveLength(31);
    for (const c of vectors.cases) expect(c.decision === 'deny' ? reasonOf.has(c.rule!) : c.rule === undefined, c.id).toBe(true);
    // Every one of the seven rules is exercised by at least one block.
    expect(new Set(vectors.cases.filter((c) => c.rule).map((c) => c.rule)).size).toBe(7);
  });

  for (const c of vectors.cases) {
    it(`${c.id}: ${c.decision} (${c.note})`, async () => {
      const d = await evaluateLikeCli(starter, c.tool, c.input);
      expect(d.allowed, `${c.id} -> ${d.reason}`).toBe(c.decision === 'allow');
      if (c.decision === 'deny') {
        expect((d.metadata?.denied_by as Array<{ id: string }>).map((p) => p.id)).toEqual([c.rule]);
        expect(d.reason).toBe(`cedar_deny: ${c.rule}: ${reasonOf.get(c.rule!)}`);
      } else {
        expect(d.metadata?.matched_policies).toEqual(['starter.allow-by-default']);
      }
    });
  }
});

describe('inputs Cedar cannot hold as they are', () => {
  it('covers null, 0.5, 1e20 and the escape keys', () => {
    const text = readFileSync(join(root, 'vectors/starter-policy.v1.json'), 'utf-8');
    expect(text).toContain('1e20');
    const inputs = JSON.stringify(vectors.input_cases.map((c) => c.input));
    for (const needle of ['null', '0.5', '__entity', '__extn', '__expr']) expect(inputs).toContain(needle);
    expect(vectors.input_cases.some((c) => Object.values(c.input).includes(1e20))).toBe(true);
  });

  for (const c of vectors.input_cases) {
    it(`${c.id}: allow-all ${c.allow_all}, starter ${c.starter} (${c.note})`, async () => {
      const open = await evaluateLikeCli(allowAll, c.tool, c.input);
      expect(open.allowed, `${c.id} allow-all -> ${open.reason}`).toBe(c.allow_all === 'allow');
      const d = await evaluateLikeCli(starter, c.tool, c.input);
      expect(d.allowed, `${c.id} starter -> ${d.reason}`).toBe(c.starter === 'allow');
      if (c.starter === 'deny') expect((d.metadata?.denied_by as Array<{ id: string }>).map((p) => p.id)).toEqual([c.rule]);
    });
  }

  it('one deny case per starter rule, so a fraction never hides a block', () => {
    const rules = vectors.input_cases.filter((c) => c.starter === 'deny').map((c) => c.rule);
    expect(new Set(rules)).toEqual(new Set(starterRules().map((r) => r.id)));
  });
});

describe('the opt-in project rules (init --starter --contain)', () => {
  const home = '/Users/u';
  const project = '/Users/u/work/app';
  const contained = policySetFromSource(`${STARTER_POLICY}\n${renderContainRules(project, home)}`, 'protect.cedar');
  const write = (file_path: string) => evaluateLikeCli(contained, 'Write', { file_path, content: 'x' });
  const bash = (command: string) => evaluateLikeCli(contained, 'Bash', { command });
  const ids = (d: { metadata?: Record<string, unknown> }) => ((d.metadata?.denied_by as Array<{ id: string }>) || []).map((p) => p.id);

  it('fills every placeholder', () => {
    expect(STARTER_CONTAIN_TEMPLATE).toMatch(/__PROJECT__/);
    expect(STARTER_CONTAIN_TEMPLATE).toMatch(/__TILDE__/);
    expect(STARTER_CONTAIN_TEMPLATE).toMatch(/__HOME__/);
    const text = renderContainRules(project, home);
    expect(text).not.toMatch(/__(PROJECT|TILDE|HOME)__/);
    expect(text).toContain('"/Users/u/work/app/*"');
    expect(text).toContain('"*rm -rf ~/work/app/*"');
    expect(text).toContain('"/Users/u/.claude/plans/*"');
  });

  it('allows writes inside the project, in temporary folders and in Claude memory, and blocks the rest', async () => {
    for (const p of [`${project}/src/a.ts`, '/tmp/notes.md', '/private/var/folders/x/y', `${home}/.claude/projects/p/memory/m.md`, `${home}/.claude/plans/plan.md`]) {
      expect((await write(p)).allowed, p).toBe(true);
    }
    const outside = await write(`${home}/work/other/a.ts`);
    expect(outside.allowed).toBe(false);
    expect(ids(outside)).toEqual(['starter.write-outside-project']);
    // The starter's own rules still hold inside the project.
    expect(ids(await write(`${project}/protect.cedar`))).toEqual(['starter.write-sensitive-location']);
    expect(ids(await write(`${home}/.zshrc`))).toEqual(['starter.write-sensitive-location', 'starter.write-outside-project']);
  });

  it('blocks a recursive delete of an absolute path outside the project', async () => {
    for (const c of [`rm -rf ${project}/build`, 'rm -rf ~/work/app/dist', 'rm -rf /tmp/cache', 'rm -rf "$TMPDIR/x"', 'rm -rf node_modules']) {
      expect((await bash(c)).allowed, c).toBe(true);
    }
    for (const c of [`rm -rf ${home}/work/other`, 'rm -rf ~/Documents/x', 'rm -rf "$HOME/x"']) {
      const d = await bash(c);
      expect(d.allowed, c).toBe(false);
      expect(ids(d), c).toContain('starter.delete-outside-project');
    }
  });

  it('escapes a path so a star or a quote in it matches only itself', async () => {
    const odd = '/Users/u/we*rd "app"';
    const text = renderContainRules(odd, home);
    expect(text).toContain(cedarLikeLiteral(odd));
    const policy = policySetFromSource(`${STARTER_POLICY}\n${text}`, 'protect.cedar');
    expect((await evaluateLikeCli(policy, 'Write', { file_path: `${odd}/a.ts`, content: 'x' })).allowed).toBe(true);
    expect((await evaluateLikeCli(policy, 'Write', { file_path: '/Users/u/weXXrd "app"/a.ts', content: 'x' })).allowed).toBe(false);
  });

  it('uses the absolute path for the ~ form when the project is not under home', () => {
    expect(renderContainRules('/srv/app', home)).toContain('"*rm -rf /srv/app/*"');
  });

  it('refuses a folder that is not a project', () => {
    expect(() => renderContainRules('/', home)).toThrow(/project folder/);
    expect(() => renderContainRules(home, home)).toThrow(/project folder/);
    expect(() => renderContainRules(`${home}/`, home)).toThrow(/project folder/);
    expect(() => renderContainRules('relative/app', home)).toThrow(/absolute/);
    expect(() => renderContainRules('/Users/u/a\nb', home)).toThrow(/control characters/);
  });
});
