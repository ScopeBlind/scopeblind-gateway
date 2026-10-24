/**
 * Regression: the MCP gateway must FAIL CLOSED when asking the external policy
 * decision point throws unexpectedly, as it does for Cedar. queryExternalPDP
 * turns network failures into its configured fallback (deny by default), so
 * here an UNEXPECTED throw is forced, the path that used to fall through to
 * the JSON rules and allow. Isolated in its own file so the mock does not leak.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ProtectConfig } from './types.js';

vi.mock('./external-pdp.js', async (importActual) => {
  const actual = await importActual<typeof import('./external-pdp.js')>();
  return {
    ...actual,
    queryExternalPDP: vi.fn(async () => {
      throw new Error('synthetic external PDP crash');
    }),
  };
});

const call = { jsonrpc: '2.0' as const, id: 1, method: 'tools/call', params: { name: 'read_file', arguments: { path: '/tmp/x' } } };
const within = <T>(p: Promise<T>, ms: number): Promise<T | 'timed out'> =>
  Promise.race([p, new Promise<'timed out'>((resolve) => setTimeout(() => resolve('timed out'), ms))]);

describe('gateway fails closed when the external PDP evaluation throws', () => {
  const cwd = process.cwd();
  let dir = '';
  beforeAll(() => {
    // The gateway writes its decision log to the working directory.
    dir = mkdtempSync(join(tmpdir(), 'pmcp-gw-pdp-'));
    process.chdir(dir);
  });
  afterAll(() => process.chdir(cwd));

  it('denies the call in enforce mode instead of running it, and records the deny', async () => {
    const { ProtectGateway } = await import('./gateway.js');
    // The JSON rules allow everything: if the throw fell through, the call WOULD run.
    const gateway = new ProtectGateway({
      command: process.execPath, args: [], enforce: true, verbose: false, policyDigest: 'test',
      policy: { tools: { '*': {} }, policy_engine: 'external', external: { endpoint: 'http://127.0.0.1:9/decide' } },
    } as ProtectConfig);

    const response = await within(gateway.processRequest(call), 2000);
    expect(response).not.toBe('timed out');
    expect(JSON.parse(response as string).error.message).toMatch(/external policy engine errored, so the gate fails closed/);
    const logged = readFileSync(join(dir, '.protect-mcp-log.jsonl'), 'utf-8').trim().split('\n').map((l) => JSON.parse(l));
    expect(logged.map((l) => [l.decision, l.reason_code])).toEqual([['deny', 'external_pdp_error']]);
  });
});
