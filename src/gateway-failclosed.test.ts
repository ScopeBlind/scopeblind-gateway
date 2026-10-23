/**
 * Regression: the MCP gateway must FAIL CLOSED when the Cedar evaluator throws
 * unexpectedly, as the hook server does. evaluateCedar maps normal evaluation
 * failures to a deny itself, so here an UNEXPECTED throw is forced, the path
 * that used to fall through to the JSON rules and allow. Isolated in its own
 * file so the evaluateCedar mock does not leak into other tests.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ProtectConfig } from './types.js';

vi.mock('./cedar-evaluator.js', async (importActual) => {
  const actual = await importActual<typeof import('./cedar-evaluator.js')>();
  return {
    ...actual,
    evaluateCedar: vi.fn(async () => {
      throw new Error('synthetic cedar crash');
    }),
  };
});

const call = { jsonrpc: '2.0' as const, id: 1, method: 'tools/call', params: { name: 'read_file', arguments: { path: '/tmp/x' } } };
const within = <T>(p: Promise<T>, ms: number): Promise<T | 'timed out'> =>
  Promise.race([p, new Promise<'timed out'>((resolve) => setTimeout(() => resolve('timed out'), ms))]);

describe('gateway fails closed when Cedar evaluation throws', () => {
  const cwd = process.cwd();
  let dir = '';
  beforeAll(() => {
    // The gateway writes its decision log to the working directory.
    dir = mkdtempSync(join(tmpdir(), 'pmcp-gw-failclosed-'));
    process.chdir(dir);
  });
  afterAll(() => process.chdir(cwd));

  it('denies the call in enforce mode instead of running it, and records the deny', async () => {
    const { ProtectGateway } = await import('./gateway.js');
    const { policySetFromSource } = await import('./cedar-evaluator.js');
    // An allow-all policy: if evaluation worked, the call WOULD run.
    const gateway = new ProtectGateway({
      command: process.execPath, args: [], enforce: true, verbose: false, policyDigest: 'test',
      policy: { tools: { '*': { require: 'any' } }, policy_engine: 'cedar' },
    } as ProtectConfig);
    gateway.setCedarPolicies(policySetFromSource('permit(principal, action, resource);'));

    const response = await within(gateway.processRequest(call), 2000);
    expect(response).not.toBe('timed out');
    expect(JSON.parse(response as string).error.message).toMatch(/fails closed/);
    const logged = readFileSync(join(dir, '.protect-mcp-log.jsonl'), 'utf-8').trim().split('\n').map((l) => JSON.parse(l));
    expect(logged.map((l) => [l.decision, l.reason_code])).toEqual([['deny', 'cedar_eval_error']]);
  });
});
