/**
 * One standard, two enforcers, one answer: the gate's side of the shared vectors.
 *
 * vectors/standard-decisions.v1.json is generated from the standard compiler on
 * scopeblind.com (packages/scopeblind-pm/web/scripts/gen-standard-vectors.mjs)
 * and holds, per standard, the compiled Cedar policy the signed standard carries
 * and, per case, the decision the standard's own words require. Here the real
 * Cedar engine evaluates the carried policy and the standard gate gives its own
 * decision, and both must match the expected answer for every case. The hosted
 * side (the JS mirror and the rehearsal on scopeblind.com) is held to the same
 * file in that package's release gate.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateCedar, policySetFromSource, isCedarAvailable } from './cedar-evaluator.js';
import { parseStandard, standardDecision } from './standard-gate.js';

interface Vectors {
  type: string;
  standards: Array<{ id: string; title: string; draft: { requirements: Record<string, unknown> }; tool: string; action_model: 'mcp' | 'tool'; policy: string | null; policy_digest: string | null }>;
  cases: Array<{ id: string; standard: string; tool: string; input: Record<string, unknown>; decision: 'allow' | 'deny' | 'hold'; clause: string; note: string }>;
}

const vectors = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '../vectors/standard-decisions.v1.json'), 'utf-8')) as Vectors;

/** The signed-standard shape the gate reads, built from the vector's draft: the requirements and the enforcement block are what decide. */
function gateFor(s: Vectors['standards'][number]) {
  return parseStandard({
    type: 'scopeblind.proof_request.v1', version: 1, request_id: `vector:${s.id}`, digest: 'd'.repeat(64),
    recipient: { name: 'Vectors', organization: 'Vectors', key_id: 'recipient:vectors', verification_key: 'a'.repeat(64) },
    requirements: s.draft.requirements,
    enforcement: s.policy ? { policy_format: 'cedar', tool: s.tool, action_model: s.action_model, policy: s.policy, policy_digest: s.policy_digest } : null,
    signature: { algorithm: 'Ed25519', value: 'f'.repeat(128) },
  });
}

describe('the shared decision vectors', () => {
  it('are the file the compiler wrote, with every case naming a standard', () => {
    expect(vectors.type).toBe('scopeblind.standard-decision-vectors.v1');
    expect(vectors.standards.length).toBeGreaterThanOrEqual(5);
    expect(vectors.cases.length).toBeGreaterThanOrEqual(40);
    for (const c of vectors.cases) expect(vectors.standards.some((s) => s.id === c.standard), c.id).toBe(true);
  });

  for (const s of vectors.standards) {
    const cases = vectors.cases.filter((c) => c.standard === s.id);
    describe(`${s.id}: ${s.title}`, () => {
      const gate = gateFor(s);
      it('the standard gate gives the expected answer for every case', () => {
        for (const c of cases) {
          const got = standardDecision(gate, c.tool, c.input);
          expect(got.decision, `${c.id} (${c.note}) -> ${got.reason}: ${got.detail}`).toBe(c.decision);
        }
      });
      if (s.policy) {
        it('the real Cedar engine admits exactly the calls the gate admits or holds', async () => {
          expect(await isCedarAvailable()).toBe(true);
          const policySet = policySetFromSource(s.policy!, 'standard.cedar');
          for (const c of cases) {
            const d = await evaluateCedar(policySet, { tool: c.tool, tier: 'unknown', toolInput: c.input, actionModel: s.action_model });
            expect(d.allowed, `${c.id} (${c.note}) -> cedar ${d.allowed ? 'allow' : 'deny'} ${d.reason ?? ''}`).toBe(c.decision !== 'deny');
          }
        });
      } else {
        it('carries no gate policy, so the gate admits nothing under it', () => {
          expect(gate.gate_policy).toBe(false);
          for (const c of cases) expect(c.decision).toBe('deny');
        });
      }
    });
  }
});
