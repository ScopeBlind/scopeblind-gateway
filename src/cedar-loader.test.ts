import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { evaluateCedar, loadCedarPolicies, getCedarWasmLoadInfo } from './cedar-evaluator.js';

describe('Cedar engine loading', () => {
  it('loads the engine through the /nodejs entry, which works on every supported Node', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'pmcp-loader-'));
    writeFileSync(join(dir, 'allow.cedar'), 'permit(principal, action, resource);\n');
    const verdict = await evaluateCedar(loadCedarPolicies(dir), { tool: 'Read', tier: 'unknown', context: {} });
    const info = getCedarWasmLoadInfo();
    expect(info.loaded).toBe(true);
    expect(info.specifier).toBe('@cedar-policy/cedar-wasm/nodejs');
    expect(info.error).toBeNull();
    expect(verdict.allowed).toBe(true);
  });
});
