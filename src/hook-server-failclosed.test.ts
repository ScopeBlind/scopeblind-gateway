/**
 * Regression: the hook server must FAIL CLOSED when the Cedar evaluator throws
 * unexpectedly while a policy is configured. evaluateCedar already maps normal
 * eval failures to a deny, so here we force an UNEXPECTED throw (the only path
 * that previously fell through to allow) and assert the call is denied, not
 * allowed. Isolated in its own file so the evaluateCedar mock does not leak into
 * the other hook-server tests.
 */
import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import type { Server } from 'node:http';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// Keep loadCedarPolicies real (so the server starts with a policy set), but make
// evaluateCedar throw to exercise the catch path.
vi.mock('./cedar-evaluator.js', async (importActual) => {
  const actual = await importActual<typeof import('./cedar-evaluator.js')>();
  return {
    ...actual,
    evaluateCedar: vi.fn(async () => {
      throw new Error('synthetic cedar crash');
    }),
  };
});

const HOOK_URL = 'http://127.0.0.1:19379/hook';
// An allow-all policy: if evaluation worked, the call WOULD be allowed. The throw
// must override that and deny, proving the gate fails closed on engine error.
const cedarDir = mkdtempSync(join(tmpdir(), 'pmcp-failclosed-'));
writeFileSync(join(cedarDir, 'policy.cedar'), 'permit(principal, action, resource);\n');

let server: Server | undefined;

beforeAll(async () => {
  const { startHookServer } = await import('./hook-server.js');
  server = await startHookServer({ port: 19379, verbose: false, enforce: true, cedarDir });
  await new Promise(r => setTimeout(r, 200));
}, 10_000);

afterAll(() => {
  if (server) server.close();
});

async function post(body: Record<string, unknown>): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await fetch(HOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

describe('hook server fails closed when Cedar evaluation throws', () => {
  it('denies the tool call instead of silently allowing it', async () => {
    const result = await post({
      hook_event_name: 'PreToolUse',
      session_id: 's1',
      cwd: '/tmp',
      tool_name: 'read_file',
      tool_input: { path: '/tmp/whatever' },
      tool_use_id: 'tu-failclosed-1',
    });
    expect(result.status).toBe(200);
    const output = result.body.hookSpecificOutput as Record<string, unknown> | undefined;
    expect(output?.permissionDecision).toBe('deny');
    expect(String(output?.permissionDecisionReason)).toContain('fails closed');
  });
});
