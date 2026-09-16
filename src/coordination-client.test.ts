import { describe, expect, it } from 'vitest';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { CoordinationClient, type CoordinationPayment } from './coordination-client.js';
import { defaultAgreement, generateIdentity, payloadHash, sign, type Admission, type OperationRequest, type Outcome, type Signed } from './coordination-protocol.js';
import { handleCoordinationRequest } from './coordination-server.js';

const payment: CoordinationPayment = { operation_id: 'pay-INV-101', input: { invoice_id: 'INV-101', amount_minor: 32000, currency: 'USD', destination: 'sandbox:northstar' } };
interface Options {
  decision?: 'held' | 'refused' | 'admitted';
  alterAdmission?: (admission: Admission) => void;
  tamper?: boolean;
  otherSigner?: boolean;
  loseFirstExecuteResponse?: boolean;
  wrongOutcome?: boolean;
  contradictoryReplay?: boolean;
  rejectExecution?: boolean;
}

async function fixture(options: Options = {}) {
  const authority = await generateIdentity(), owner = await generateIdentity(), other = await generateIdentity();
  const agreement = await sign(defaultAgreement('room-001', owner.publicKey, authority.publicKey), owner);
  const stored = new Map<string, { request: OperationRequest; admission: Signed<Admission>; receipt?: Signed<Outcome> }>();
  const counters = { admissions: 0, executions: 0, effects: 0 };
  let lose = options.loseFirstExecuteResponse;
  const json = (data: unknown, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    if (new Headers(init?.headers).get('Authorization') !== 'Bearer private-executor-token') return json({ ok: false }, 401);
    if (!init?.method || init.method === 'GET' || JSON.parse(String(init.body)).action === 'inspect') return json({ ok: true, room: {
      room_id: 'room-001', run_id: 'run-room-001', authority_key: authority.publicKey, agreement,
      paused: false, budget: { limit_minor: 200000, reserved_minor: 0, spent_minor: 0, remaining_minor: 200000 }, invoices: [], operations: [],
    } });
    const body = JSON.parse(String(init.body));
    if (body.room_id !== 'room-001') return json({ ok: false }, 404);
    if (body.action === 'admit') {
      counters.admissions++;
      const request = body.body.operation as OperationRequest;
      const hash = await payloadHash(request.input);
      let record = stored.get(request.operation_id);
      const replay = Boolean(record);
      if (record && record.admission.payload.payload_hash !== hash) return json({ ok: false }, 409);
      if (!record) {
        const a: Admission = {
          type: 'scopeblind.coordination.admission.v1', room_id: 'room-001', run_id: request.run_id,
          operation_id: request.operation_id, agreement_digest: agreement.digest, payload_hash: hash,
          input: request.input, destination: request.input.destination, decision: options.decision || 'admitted',
          reason: 'fixture decision', issued_at: new Date(Date.now() - 1000).toISOString(), expires_at: new Date(Date.now() + 60000).toISOString(),
        };
        options.alterAdmission?.(a);
        const admission = await sign(a, options.otherSigner ? other : authority);
        if (options.tamper) admission.signature = '00'.repeat(64);
        record = { request, admission };
        stored.set(request.operation_id, record);
      }
      const admission = options.contradictoryReplay && record.receipt
        ? await sign({ ...record.admission.payload, decision: 'refused' as const }, authority) : record.admission;
      return json({ ok: true, decision: admission.payload.decision, operation: { receipt: record.receipt }, admission, replay });
    }
    if (body.action === 'execute') {
      counters.executions++;
      if (options.rejectExecution) return json({ ok: false, error: 'room_paused' }, 409);
      const record = stored.get(body.body.operation_id)!;
      const replay = Boolean(record.receipt);
      if (!record.receipt) {
        counters.effects++;
        const input = record.request.input;
        record.receipt = await sign({
          type: 'scopeblind.coordination.outcome.v1', room_id: 'room-001', run_id: 'run-room-001', operation_id: record.request.operation_id,
          payload_hash: await payloadHash(input), status: 'confirmed', amount_minor: options.wrongOutcome ? input.amount_minor + 1 : input.amount_minor,
          destination: input.destination, transaction_id: 'sample-tx-1', observed_by: 'sandbox-ledger', issued_at: new Date().toISOString(),
        } satisfies Outcome, authority);
      }
      if (lose) { lose = false; throw new Error('Connection lost after ledger commit'); }
      return json({ ok: true, outcome: record.receipt, operation: {}, replay });
    }
    return json({ ok: false }, 400);
  }) as typeof fetch;
  const config = { endpoint: 'https://fixture.test/api/coordination', roomId: 'room-001', authorityKey: authority.publicKey, token: 'private-executor-token' };
  return { config, fetchImpl, counters, client: new CoordinationClient(config, fetchImpl) };
}

describe('installed coordination admission adapter', () => {
  it('executes only after a verified admission and returns the original outcome on repeated identity', async () => {
    const f = await fixture();
    expect((await f.client.pay(payment)).status).toBe('confirmed');
    expect((await f.client.pay(payment)).replay).toBe(true);
    expect(f.counters).toEqual({ admissions: 2, executions: 1, effects: 1 });
  });

  it.each(['held', 'refused'] as const)('never forwards a signed %s decision', async decision => {
    const f = await fixture({ decision });
    expect((await f.client.pay(payment)).status).toBe(decision);
    expect(f.counters.executions).toBe(0);
  });

  it.each([
    ['tampered signature', { tamper: true }],
    ['untrusted signer', { otherSigner: true }],
    ['different operation', { alterAdmission: (a: Admission) => { a.operation_id = 'different'; } }],
    ['different room', { alterAdmission: (a: Admission) => { a.room_id = 'different'; } }],
    ['different run', { alterAdmission: (a: Admission) => { a.run_id = 'different'; } }],
    ['different destination', { alterAdmission: (a: Admission) => { a.destination = 'sandbox:other'; } }],
    ['different payload', { alterAdmission: (a: Admission) => { a.input = { ...a.input, amount_minor: a.input.amount_minor + 1 }; } }],
    ['different agreement', { alterAdmission: (a: Admission) => { a.agreement_digest = '00'.repeat(32); } }],
    ['expired admission', { alterAdmission: (a: Admission) => { a.issued_at = new Date(Date.now() - 60000).toISOString(); a.expires_at = new Date(Date.now() - 1000).toISOString(); } }],
  ] satisfies Array<[string, Options]>)('fails closed for %s before execute', async (_label, options) => {
    const f = await fixture(options);
    await expect(f.client.pay(payment)).rejects.toThrow();
    expect(f.counters.executions).toBe(0);
  });

  it('does not treat the same operation ID with changed input as a new payment', async () => {
    const f = await fixture();
    await f.client.pay(payment);
    await expect(f.client.pay({ ...payment, input: { ...payment.input, amount_minor: 32100 } })).rejects.toThrow('HTTP 409');
    expect(f.counters.effects).toBe(1);
  });

  it('requires the explicitly configured run to match the room before requesting authority', async () => {
    const f = await fixture();
    const client = new CoordinationClient({ ...f.config, runId: 'run-another-room' }, f.fetchImpl);
    await expect(client.pay(payment)).rejects.toThrow('configured run');
    expect(f.counters).toEqual({ admissions: 0, executions: 0, effects: 0 });
  });

  it('does not accept a room authority key merely because the service reports it', async () => {
    const f = await fixture();
    const client = new CoordinationClient({ ...f.config, authorityKey: '00'.repeat(32) }, f.fetchImpl);
    await expect(client.pay(payment)).rejects.toThrow('pinned registrar');
    expect(f.counters.admissions).toBe(0);
  });

  it('preserves unknown after response loss and reconciles without duplicating or releasing', async () => {
    const f = await fixture({ loseFirstExecuteResponse: true });
    const first = await f.client.pay(payment);
    expect(first.status).toBe('unknown');
    expect(first.reason).toContain('Retain this operation_id');
    expect((await f.client.pay(payment)).status).toBe('confirmed');
    expect(f.counters).toEqual({ admissions: 2, executions: 1, effects: 1 });
  });

  it('returns unknown rather than claiming success for a signed but mismatched destination outcome', async () => {
    const f = await fixture({ wrongOutcome: true });
    expect((await f.client.pay(payment)).status).toBe('unknown');
    expect(f.counters.effects).toBe(1);
  });

  it('does not claim a governed success from contradictory signed admission and outcome', async () => {
    const f = await fixture({ contradictoryReplay: true });
    expect((await f.client.pay(payment)).status).toBe('confirmed');
    await expect(f.client.pay(payment)).rejects.toThrow('contradicts the signed admission');
    expect(f.counters.executions).toBe(1);
  });

  it('does not locally bypass a fresh server execution rejection using an earlier valid admission', async () => {
    const f = await fixture({ rejectExecution: true });
    const result = await f.client.pay(payment);
    expect(result.status).toBe('unknown');
    expect(f.counters.executions).toBe(1);
    expect(f.counters.effects).toBe(0);
  });

  it('captures payment input before asynchronous work', async () => {
    const f = await fixture();
    const mutable = { ...payment, input: { ...payment.input } };
    const pending = f.client.pay(mutable);
    mutable.input.amount_minor = 999999;
    const result = await pending;
    expect(result.status).toBe('confirmed');
    expect(result.outcome?.payload.amount_minor).toBe(32000);
  });

  it('requires stable operation identity and refuses tool-only or extra argument fields', async () => {
    const f = await fixture();
    const response = await handleCoordinationRequest(f.client, { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'ledger.pay', arguments: { ...payment.input, operation_id: payment.operation_id, override: true } } }) as any;
    expect(response.result.isError).toBe(true);
    for (const operation_id of ['', 'short', 'op:00001', 'op/00001', 'op.00001', 'x'.repeat(101)]) {
      await expect(f.client.pay({ ...payment, operation_id })).rejects.toThrow('stable operation_id');
    }
    expect(f.counters.admissions).toBe(0);
  });

  it('runs through the built CLI and real stdio MCP transport with no token in output', async () => {
    const f = await fixture();
    const server = createServer(async (request, response) => {
      let body = '';
      for await (const chunk of request) body += chunk;
      try {
        const result = await f.fetchImpl(`http://127.0.0.1${request.url}`, { method: request.method, headers: request.headers as Record<string, string>, ...(body ? { body } : {}) });
        response.writeHead(result.status, { 'Content-Type': 'application/json' });
        response.end(await result.text());
      } catch { response.destroy(); }
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address() as { port: number };
    try {
      const result = await new Promise<{ out: string; err: string; code: number | null }>((resolve, reject) => {
        const child = spawn(process.execPath, [join(__dirname, '..', 'dist', 'cli.js'), 'coordination', '--endpoint', `http://127.0.0.1:${address.port}/api/coordination`, '--room', 'room-001', '--authority-key', f.config.authorityKey], {
          env: { ...process.env, PROTECT_MCP_COORDINATION_TOKEN: f.config.token, PROTECT_MCP_TELEMETRY: '0' }, stdio: ['pipe', 'pipe', 'pipe'],
        });
        let out = '', err = '';
        child.stdout.on('data', chunk => { out += chunk; });
        child.stderr.on('data', chunk => { err += chunk; });
        child.on('error', reject);
        child.on('close', code => resolve({ out, err, code }));
        const call = { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'ledger.pay', arguments: { operation_id: payment.operation_id, ...payment.input } } };
        child.stdin.end([
          { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
          { jsonrpc: '2.0', id: 2, method: 'tools/list' }, call, { ...call, id: 4 },
        ].map(value => JSON.stringify(value)).join('\n') + '\n');
      });
      expect(result.code).toBe(0);
      const responses = result.out.trim().split('\n').map(line => JSON.parse(line));
      expect(responses.find(r => r.id === 2).result.tools.map((tool: any) => tool.name)).toEqual(['coordination.deliver', 'ledger.pay', 'coordination.inspect', 'coordination.wait']);
      expect(JSON.parse(responses.find(r => r.id === 3).result.content[0].text).status).toBe('confirmed');
      expect(JSON.parse(responses.find(r => r.id === 4).result.content[0].text).replay).toBe(true);
      expect(result.out + result.err).not.toContain(f.config.token);
      expect(f.counters.effects).toBe(1);
    } finally { await new Promise<void>(resolve => server.close(() => resolve())); }
  }, 20000);
});
