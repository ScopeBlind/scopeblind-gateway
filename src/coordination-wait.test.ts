import { describe, expect, it, vi } from 'vitest';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { CoordinationClient } from './coordination-client.js';
import { defaultAgreement, generateIdentity, sign, type RoomView } from './coordination-protocol.js';

async function fixture() {
  const authority = await generateIdentity(), owner = await generateIdentity();
  const agreement = await sign(defaultAgreement('wait-room-001', owner.publicKey, authority.publicKey), owner);
  const room: RoomView = { room_id: 'wait-room-001', run_id: 'run-wait-room-001', agreement, owner_name: 'Owner', created_at: new Date().toISOString(), authority_key: authority.publicKey, paused: false,
    budget: { limit_minor: 200000, reserved_minor: 0, spent_minor: 0, remaining_minor: 200000 }, invoices: [], operations: [], grants: [], acceptances: [], events: [], revision: 1 };
  const polls: number[] = [];
  let revoked = false;
  const config = { endpoint: 'https://fixture.test/api/coordination', roomId: room.room_id, authorityKey: authority.publicKey, token: 'private-wait-token' };
  const fetchImpl = (async (_url: unknown, init?: RequestInit) => {
    expect(new Headers(init?.headers).get('authorization')).toBe('Bearer private-wait-token');
    expect(JSON.parse(String(init?.body))).toMatchObject({ action: 'inspect', room_id: room.room_id, body: {} });
    polls.push(performance.now());
    return new Response(JSON.stringify(revoked ? { ok: false, error: 'executor_token_invalid' } : { ok: true, room }), { status: revoked ? 403 : 200, headers: { 'content-type': 'application/json' } });
  }) as typeof fetch;
  return { room, config, polls, fetchImpl, client: new CoordinationClient(config, fetchImpl), revoke: () => { revoked = true; } };
}

describe('bounded agent wait', () => {
  it('exposes a cursor and returns immediately when a change already exists', async () => {
    const f = await fixture(); expect((await f.client.inspect()).cursor).toBe(1);
    const changed = await f.client.wait({ after_cursor: 0 });
    expect(changed).toMatchObject({ status: 'changed', cursor: 1, run_id: f.room.run_id }); expect(f.polls).toHaveLength(2);
  });
  it('awaits an actual decision event at two-second intervals without busy polling', async () => {
    const f = await fixture();
    const timer = setTimeout(() => {
      f.room.revision = 2; f.room.events = [{ id: 2, type: 'decided', at: new Date().toISOString(), message: 'A reviewer requested changes.' }];
      f.room.operations = [{ operation_id: 'wait-operation', run_id: f.room.run_id, tool: 'ledger.pay', input: { invoice_id: 'INV-101', amount_minor: 32000, currency: 'USD', destination: 'sandbox:northstar' }, payload_hash: '00'.repeat(32), status: 'request_changes', reason: 'Please check the amount.', created_at: new Date().toISOString(), updated_at: new Date().toISOString() }];
    }, 40);
    try {
      const result = await f.client.wait({ after_cursor: 1, run_id: f.room.run_id, timeout_ms: 5000 });
      expect(result).toMatchObject({ status: 'changed', cursor: 2, attention: { changes_requested: ['wait-operation'] } });
      expect(result.events).toHaveLength(1); expect(f.polls).toHaveLength(2); expect(f.polls[1] - f.polls[0]).toBeGreaterThanOrEqual(1900);
    } finally { clearTimeout(timer); }
  }, 8000);
  it('returns waiting at its bounded timeout without another model or tight-loop poll', async () => {
    const f = await fixture(), start = performance.now();
    const result = await f.client.wait({ after_cursor: 1, timeout_ms: 1000 });
    expect(result).toMatchObject({ status: 'waiting', cursor: 1, run_id: f.room.run_id });
    expect(f.polls).toHaveLength(1); expect(performance.now() - start).toBeGreaterThanOrEqual(950); expect(performance.now() - start).toBeLessThan(1800);
  });
  it('never polls again when the final fractional interval timer wakes before the monotonic deadline', async () => {
    const f = await fixture(), abort = new AbortController();
    let clock = 100.25;
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const timers = vi.spyOn(globalThis, 'setTimeout');
    vi.spyOn(performance, 'now').mockImplementation(() => clock);
    const client = new CoordinationClient(f.config, (async (...args: Parameters<typeof fetch>) => { const result = await f.fetchImpl(...args); clock += 0.5; return result; }) as typeof fetch);
    let result: Record<string, unknown> | undefined, failure: unknown;
    const pending = client.wait({ after_cursor: 1, timeout_ms: 1000 }, abort.signal).then(value => { result = value; }, error => { failure = error; });
    try {
      for (let i = 0; i < 1000 && timers.mock.calls.length < 3; i++) await new Promise<void>(resolve => setImmediate(resolve));
      expect(timers.mock.calls).toHaveLength(3); // Deadline, fetch timeout, then final sleep.
      const [wake, delay] = timers.mock.calls[2];
      expect(delay).toBe(1000); // 999.5ms must round up, never truncate.
      clock = 1100; // The deadline is 1100.25: deliberately fire a little early.
      (wake as () => void)();
      for (let i = 0; i < 1000 && !result && !failure && f.polls.length === 1; i++) await new Promise<void>(resolve => setImmediate(resolve));
      expect(f.polls).toHaveLength(1); expect(failure).toBeUndefined(); expect(result).toMatchObject({ status: 'waiting', cursor: 1 });
    } finally { abort.abort(); await pending; vi.restoreAllMocks(); vi.useRealTimers(); }
  });
  it.each([true, false])('treats an early local deadline timer as timeout, not caller cancellation (room retrieved: %s)', async retrieved => {
    const f = await fixture(), abort = new AbortController();let clock = 100.25, started = false;
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const timers = vi.spyOn(globalThis, 'setTimeout');vi.spyOn(performance, 'now').mockImplementation(() => clock);
    const fetchImpl = retrieved ? f.fetchImpl : ((_url: unknown, init?: RequestInit) => new Promise<Response>((_resolve, reject) => { started = true; init?.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true }); })) as typeof fetch;
    let result: Record<string, unknown> | undefined, failure: unknown;
    const pending = new CoordinationClient(f.config, fetchImpl).wait({ after_cursor: 1, timeout_ms: 1000 }, abort.signal).then(value => { result = value; }, error => { failure = error; });
    try {
      for (let i = 0; i < 1000 && (retrieved ? timers.mock.calls.length < 3 : !started); i++) await new Promise<void>(resolve => setImmediate(resolve));
      expect(retrieved ? timers.mock.calls.length === 3 : started).toBe(true);
      clock = 1100; // Local timeout fired, although performance.now is still before its deadline.
      (timers.mock.calls[0][0] as () => void)();await pending;
      if (retrieved) { expect(failure).toBeUndefined(); expect(result).toMatchObject({ status: 'waiting', cursor: 1 }); expect(f.polls).toHaveLength(1); }
      else { expect(result).toBeUndefined(); expect(failure).toMatchObject({ code: 'wait_timeout' }); }
    } finally { abort.abort(); await pending; vi.restoreAllMocks(); vi.useRealTimers(); }
  });
  it('stops with a structured error when authority is revoked while waiting', async () => {
    const f = await fixture(), timer = setTimeout(f.revoke, 40);
    try { await expect(f.client.wait({ after_cursor: 1, timeout_ms: 5000 })).rejects.toMatchObject({ code: 'executor_token_invalid' }); expect(f.polls).toHaveLength(2); }
    finally { clearTimeout(timer); }
  }, 8000);
  it('cancels sleep and in-flight inspection and does not poll after cancellation', async () => {
    const f = await fixture(), abort = new AbortController();
    const pending = f.client.wait({ after_cursor: 1 }, abort.signal); setTimeout(() => abort.abort(), 40);
    await expect(pending).rejects.toMatchObject({ code: 'cancelled' }); expect(f.polls).toHaveLength(1);
    const preAborted = new AbortController(); preAborted.abort(); await expect(f.client.wait({ after_cursor: 1 }, preAborted.signal)).rejects.toMatchObject({ code: 'cancelled' }); expect(f.polls).toHaveLength(1);
    let networkAborted = false;
    const slowFetch = ((_url: unknown, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => { networkAborted = true; reject(new Error('network aborted')); }, { once: true });
    })) as typeof fetch;
    const other = new AbortController(), slow = new CoordinationClient(f.config, slowFetch).wait({ after_cursor: 1 }, other.signal);
    setTimeout(() => other.abort(), 40); await expect(slow).rejects.toMatchObject({ code: 'cancelled' }); expect(networkAborted).toBe(true);
  });
  it('rejects invalid cursors/time limits before contacting the service', async () => {
    const f = await fixture();
    for (const input of [{ after_cursor: -1 }, { after_cursor: 0.5 }, { after_cursor: 1, timeout_ms: 0 }, { after_cursor: 1, timeout_ms: 30001 }, { after_cursor: 1, run_id: 'wrong' }]) await expect(f.client.wait(input)).rejects.toMatchObject({ code: 'invalid_wait' });
    expect(f.polls).toHaveLength(0);
  });
  it('the installed MCP server honors cancellation while a wait is active', async () => {
    const f = await fixture();
    let inspected!: () => void;
    const seen = new Promise<void>(resolve => { inspected = resolve; });
    const server = createServer(async (req, res) => {
      let body = ''; for await (const chunk of req) body += chunk;
      const response = await f.fetchImpl('https://fixture.test', { method: 'POST', body, headers: req.headers as Record<string, string> });
      res.writeHead(response.status, { 'content-type': 'application/json' }); res.end(await response.text()); inspected();
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as { port: number }).port;
    const child = spawn(process.execPath, [process.env.PROTECT_MCP_INSTALLED_CLI || join(__dirname, '../dist/cli.js'), 'coordination', '--endpoint', `http://127.0.0.1:${port}/api/coordination`, '--room', f.room.room_id, '--authority-key', f.config.authorityKey], { env: { ...process.env, PROTECT_MCP_COORDINATION_TOKEN: f.config.token, PROTECT_MCP_TELEMETRY: '0' }, stdio: ['pipe', 'pipe', 'pipe'] });
    let output = ''; child.stdout.on('data', chunk => { output += chunk; if (output.includes('\n')) child.stdin.end(); });
    const closed = new Promise<number | null>((resolve, reject) => { child.on('close', resolve); child.on('error', reject); });
    try {
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 15, method: 'tools/call', params: { name: 'coordination.wait', arguments: { after_cursor: 1 } } }) + '\n');
      await seen;
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 15 } }) + '\n');
      expect(await closed).toBe(0); const result = JSON.parse(output.trim()); expect(result.result.isError).toBe(true); expect(JSON.parse(result.result.content[0].text).code).toBe('cancelled'); expect(f.polls).toHaveLength(1);
    } finally { child.kill(); await new Promise<void>(resolve => server.close(() => resolve())); }
  }, 8000);
});
