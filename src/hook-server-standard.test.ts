import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const PORT = 19391;
const STORE_PORT = 19392;
const SID = 'c'.repeat(24);
const standard = {
  type: 'scopeblind.proof_request.v1', version: 1, request_id: 'pr-hook', digest: 'd'.repeat(64),
  recipient: { name: 'Priya Nair', organization: 'Nair Bookkeeping', key_id: 'recipient:1', verification_key: 'a'.repeat(64) },
  requirements: { human_approval: { required_above: { amount: 500, currency: 'USD' }, distinct_approvers: 1 }, action_limits: { amount_max: { amount: 2000, currency: 'USD' }, per_instruction: true }, run: { allowed_tools: ['pay_invoice', 'Bash'] } },
  signature: { algorithm: 'Ed25519', value: 'f'.repeat(128) },
};

let hookServer: Server;
let store: Server;
const held: Record<string, Record<string, unknown>> = {};
const decisions: Record<string, unknown> = {};
const records: Array<{ run_id: string; receipts: string; calls: string }> = [];

const pre = async (tool: string, input: Record<string, unknown>) => {
  const res = await fetch(`http://127.0.0.1:${PORT}/hook`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'session-1', tool_use_id: `tu-${Math.random().toString(36).slice(2, 8)}`, tool_name: tool, tool_input: input }) });
  return (await res.json()) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
};

describe('hook server with a standard in force', () => {
  beforeAll(async () => {
    store = createServer(async (req, res) => {
      const chunks: Buffer[] = []; for await (const c of req) chunks.push(c as Buffer);
      const url = new URL(req.url || '/', 'http://x');
      const hid = url.searchParams.get('held');
      if (req.method === 'GET' && hid) {
        if (!held[hid]) { res.writeHead(404); res.end(JSON.stringify({ ok: false, error: 'held_not_found' })); return; }
        res.end(JSON.stringify({ ok: true, held: { ...held[hid], decision: decisions[hid] ?? null } })); return;
      }
      const body = JSON.parse(Buffer.concat(chunks).toString() || '{}');
      if (req.headers.authorization !== 'Bearer tok') { res.writeHead(403); res.end(JSON.stringify({ ok: false, error: 'bad_token' })); return; }
      const op = url.searchParams.get('op');
      if (op === 'held') { held[body.hid] = body; res.end(JSON.stringify({ ok: true, url: `http://127.0.0.1:${STORE_PORT}/standard?s=${SID}#held-${body.hid}` })); return; }
      if (op === 'record') { records.push(body); res.end(JSON.stringify({ ok: true })); return; }
      res.writeHead(400); res.end('{}');
    }).listen(STORE_PORT);
    const dir = mkdtempSync(join(tmpdir(), 'pm-std-hook-'));
    mkdirSync(join(dir, 'cedar'));
    writeFileSync(join(dir, 'cedar', 'allow.cedar'), 'permit (principal, action, resource);\n');
    writeFileSync(join(dir, 'standard.json'), JSON.stringify(standard));
    const { startHookServer } = await import('./hook-server.js');
    hookServer = await startHookServer({ port: PORT, enforce: true, dataDir: dir, cedarDir: join(dir, 'cedar'), standardPath: join(dir, 'standard.json'), reportUrl: `http://127.0.0.1:${STORE_PORT}/api/standard?s=${SID}`, reportToken: 'tok', runId: 'hook-1' });
  });
  afterAll(async () => {
    await new Promise<void>((r) => hookServer.close(() => r()));
    await new Promise<void>((r) => store.close(() => r()));
  });

  it('refuses a tool the standard does not name', async () => {
    const r = await pre('Write', { file_path: '/tmp/x' });
    expect(r.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(r.hookSpecificOutput?.permissionDecisionReason).toMatch(/not among the tools the standard permits/);
  });

  it('refuses an amount over the limit before it runs', async () => {
    const r = await pre('pay_invoice', { amount_minor: 300000, currency: 'USD' });
    expect(r.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(r.hookSpecificOutput?.permissionDecisionReason).toMatch(/over the standard's limit/);
  });

  it('lets a call with no amount through', async () => {
    const r = await pre('Bash', { command: 'ls' });
    expect(r.hookSpecificOutput?.permissionDecision).not.toBe('deny');
  });

  it('holds an amount above the threshold, then follows the decision made on the page', async () => {
    const input = { amount_minor: 90000, currency: 'USD', beneficiary: 'Acme Ltd' };
    const r1 = await pre('pay_invoice', input);
    expect(r1.hookSpecificOutput?.permissionDecision).toBe('deny');
    const m = /Waiting for the named person at http:\/\/127\.0\.0\.1:19392\/standard\?s=c{24}#held-([0-9a-f]{24})/.exec(r1.hookSpecificOutput?.permissionDecisionReason ?? '');
    expect(m).not.toBeNull();
    const hid = m![1];
    expect(held[hid]).toMatchObject({ tool: 'pay_invoice', run_id: 'hook-1', sid: SID });
    expect((held[hid].readback as { amount: number }).amount).toBe(900);

    const again = await pre('pay_invoice', input);
    expect(again.hookSpecificOutput?.permissionDecisionReason).toContain(`#held-${hid}`);

    decisions[hid] = { decision: 'approve', approver: { key_id: 'recipient:1' }, digest: 'dd', note: 'checked' };
    const approved = await pre('pay_invoice', input);
    expect(approved.hookSpecificOutput?.permissionDecision).not.toBe('deny');

    decisions[hid] = { decision: 'deny', approver: { key_id: 'recipient:1' }, digest: 'ee', note: 'wrong invoice' };
    const denied = await pre('pay_invoice', input);
    expect(denied.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(denied.hookSpecificOutput?.permissionDecisionReason).toMatch(/denied by recipient:1 on the standard's page: wrong invoice/);
  });

  it('reports the calls to the page under the token, in order', async () => {
    await new Promise((r) => setTimeout(r, 1500));
    expect(records.length).toBeGreaterThan(0);
    expect(records[0].run_id).toBe('hook-1');
    const calls = records.flatMap((r) => r.calls.split('\n')).filter(Boolean).map((l) => JSON.parse(l) as { tool: string; decision: string });
    expect(calls.length).toBeGreaterThanOrEqual(7);
    expect(calls[0]).toMatchObject({ tool: 'Write', decision: 'deny' });
    expect(calls.some((c) => c.decision === 'require_approval')).toBe(true);
  });
});
