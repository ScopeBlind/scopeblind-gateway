import { describe, expect, it } from 'vitest';
import { POLICY_PACKS, getPolicyPack, policyPackIds } from './policy-packs.js';
import { evaluateCedar, policySetFromSource } from './cedar-evaluator.js';

describe('policy packs', () => {
  it('ships the expected starter packs', () => {
    expect(policyPackIds()).toEqual([
      'filesystem-safe',
      'git-safe',
      'email-safe',
      'database-safe',
      'cloud-spend-safe',
      'secrets-safe',
      'finance-mandate-safe',
    ]);
    expect(POLICY_PACKS.every((pack) => pack.files.length > 0)).toBe(true);
  });

  it('filesystem-safe blocks secret path reads and permits normal reads', async () => {
    const pack = getPolicyPack('filesystem-safe');
    expect(pack).toBeTruthy();
    const source = pack!.files.map((file) => file.contents).join('\n');
    const policySet = policySetFromSource(source, 'filesystem-safe.cedar');

    const denied = await evaluateCedar(policySet, {
      tool: 'read_file',
      tier: 'unknown',
      toolInput: { path: '/workspace/.env' },
    }, undefined, { failClosed: true });
    expect(denied.allowed).toBe(false);

    const allowed = await evaluateCedar(policySet, {
      tool: 'read_file',
      tier: 'unknown',
      toolInput: { path: '/workspace/README.md' },
    }, undefined, { failClosed: true });
    expect(allowed.allowed).toBe(true);
  });
});
