import { describe, it, expect } from 'vitest';
import { parseStandard, readAmount, checkAmount, personRequired, standardDecision, heldIdFor, sidFromReportUrl, RecordReporter } from './standard-gate.js';

const KEY = 'a'.repeat(64);
const standard = (over: Record<string, unknown> = {}) => ({
  type: 'scopeblind.proof_request.v1', version: 1, request_id: 'pr-test', digest: 'd'.repeat(64),
  recipient: { name: 'Priya Nair', organization: 'Nair Bookkeeping', key_id: 'recipient:0000', verification_key: KEY },
  requirements: {
    human_approval: { required_above: { amount: 500, currency: 'USD' }, distinct_approvers: 1 },
    action_limits: { amount_max: { amount: 2000, currency: 'USD' }, per_instruction: true },
    run: { allowed_tools: ['pay_invoice', 'send_email'] },
  },
  enforcement: { policy_digest: 'p'.repeat(64) },
  signature: { algorithm: 'Ed25519', value: 'f'.repeat(128) },
  ...over,
});

describe('parseStandard', () => {
  it('reads the tools, the limit, the threshold, and the signer key', () => {
    const gate = parseStandard(standard());
    expect(gate.tools).toEqual(['pay_invoice', 'send_email']);
    expect(gate.amount_max).toEqual({ minor: 200000, currency: 'USD' });
    expect(gate.required_above).toEqual({ minor: 50000, currency: 'USD' });
    expect(gate.signer_key).toBe(KEY);
    expect(gate.policy_digest).toBe('p'.repeat(64));
    expect(gate.payment_tool).toBeNull(); expect(gate.gate_policy).toBe(true);
    expect(gate.summary).toBe('2 tools, at most USD 2,000.00 per instruction, a person approves above USD 500.00');
  });
  it('a payment standard (a limit, no run block) admits only the tool its enforcement block names', () => {
    const gate = parseStandard(standard({ requirements: { human_approval: { required_above: null, distinct_approvers: 1 }, action_limits: { amount_max: { amount: 2000, currency: 'USD' }, per_instruction: true } }, enforcement: { policy_digest: 'p'.repeat(64), tool: 'submit_payment' } }));
    expect(gate.tools).toEqual(['submit_payment']); expect(gate.payment_tool).toBe('submit_payment'); expect(gate.gate_policy).toBe(true);
    const unnamed = parseStandard(standard({ requirements: { human_approval: { required_above: null, distinct_approvers: 1 }, action_limits: { amount_max: { amount: 2000, currency: 'USD' }, per_instruction: true } }, enforcement: undefined }));
    expect(unnamed.payment_tool).toBe('submit_payment');
  });
  it('accepts a standard with no limits and no run block, and says the gate admits nothing under it', () => {
    const gate = parseStandard(standard({ requirements: { human_approval: { required_above: null, distinct_approvers: 1 } } }));
    expect(gate.tools).toBeNull(); expect(gate.amount_max).toBeNull(); expect(gate.required_above).toBeNull();
    expect(gate.gate_policy).toBe(false); expect(gate.summary).toMatch(/admits nothing/);
    expect(standardDecision(gate, 'pay_invoice', { amount_minor: 1, currency: 'USD' })).toMatchObject({ decision: 'deny', reason: 'standard_no_gate_policy' });
  });
  it('refuses anything that is not a signed standard', () => {
    expect(() => parseStandard({ type: 'other' })).toThrow(/not a signed standard/);
    expect(() => parseStandard(standard({ signature: undefined }))).toThrow(/not signed/);
    expect(() => parseStandard(standard({ recipient: { verification_key: 'short' } }))).toThrow(/signer key/);
  });
});

describe('amounts', () => {
  const gate = parseStandard(standard());
  it('reads minor units, or major units, with a currency', () => {
    expect(readAmount({ amount_minor: 12345, currency: 'usd' })).toEqual({ minor: 12345, currency: 'USD' });
    expect(readAmount({ amount: 123.45, currency: 'USD' })).toEqual({ minor: 12345, currency: 'USD' });
    expect(readAmount({ command: 'ls' })).toBeNull();
  });
  it('refuses over the limit or in another currency, passes at the limit and with no amount', () => {
    expect(checkAmount(gate, 'pay_invoice', { amount_minor: 200000, currency: 'USD' })).toEqual({ ok: true });
    expect(checkAmount(gate, 'pay_invoice', { amount_minor: 200001, currency: 'USD' })).toMatchObject({ ok: false, reason: 'standard_amount_over_limit' });
    expect(checkAmount(gate, 'pay_invoice', { amount_minor: 100, currency: 'AUD' })).toMatchObject({ ok: false, reason: 'standard_currency_not_permitted' });
    expect(checkAmount(gate, 'send_email', { path: '/etc/hosts' })).toEqual({ ok: true });
  });
  it('reads amounts the way the compiled policy does: integer minor units and the exact currency, or the call is refused', () => {
    expect(checkAmount(gate, 'pay_invoice', { amount: 20, currency: 'USD' })).toMatchObject({ ok: false, reason: 'standard_amount_missing' });
    expect(checkAmount(gate, 'pay_invoice', { amount_minor: 20.5, currency: 'USD' })).toMatchObject({ ok: false, reason: 'standard_amount_missing' });
    expect(checkAmount(gate, 'pay_invoice', { amount_minor: 100, currency: 'usd' })).toMatchObject({ ok: false, reason: 'standard_currency_not_permitted' });
    expect(checkAmount(gate, 'pay_invoice', { amount_minor: 100 })).toMatchObject({ ok: false, reason: 'standard_currency_not_permitted' });
  });
  it('a payment standard requires an amount on its tool and ignores the limit for nothing else', () => {
    const pay = parseStandard(standard({ requirements: { human_approval: { required_above: { amount: 500, currency: 'USD' }, distinct_approvers: 1 }, action_limits: { amount_max: { amount: 2000, currency: 'USD' }, per_instruction: true } }, enforcement: { policy_digest: 'p'.repeat(64), tool: 'submit_payment' } }));
    expect(checkAmount(pay, 'submit_payment', { to: 'x' })).toMatchObject({ ok: false, reason: 'standard_amount_missing' });
    expect(standardDecision(pay, 'submit_payment', { amount_minor: 40000, currency: 'USD' })).toMatchObject({ decision: 'allow' });
    expect(standardDecision(pay, 'submit_payment', { amount_minor: 60000, currency: 'USD' })).toMatchObject({ decision: 'hold', reason: 'standard_requires_person' });
    expect(standardDecision(pay, 'submit_payment', { amount_minor: 200001, currency: 'USD' })).toMatchObject({ decision: 'deny', reason: 'standard_amount_over_limit' });
    expect(standardDecision(pay, 'delete_file', { path: '/ledger' })).toMatchObject({ decision: 'deny', reason: 'standard_tool_not_allowed' });
    expect(standardDecision(pay, 'Submit_Payment', { amount_minor: 1, currency: 'USD' })).toMatchObject({ decision: 'deny', reason: 'standard_tool_not_allowed' });
  });
  it('gives one answer per call, in order: tool list, limit, then the person', () => {
    expect(standardDecision(gate, 'rm_rf', {})).toMatchObject({ decision: 'deny', reason: 'standard_tool_not_allowed' });
    expect(standardDecision(gate, 'send_email', { to: 'a@b.c' })).toMatchObject({ decision: 'allow', reason: 'standard_tool_allowed' });
    expect(standardDecision(gate, 'pay_invoice', { amount_minor: 40000, currency: 'USD' })).toMatchObject({ decision: 'allow' });
    expect(standardDecision(gate, 'pay_invoice', { amount_minor: 60000, currency: 'USD' })).toMatchObject({ decision: 'hold' });
    expect(standardDecision(gate, 'pay_invoice', { amount_minor: 300000, currency: 'USD' })).toMatchObject({ decision: 'deny', reason: 'standard_amount_over_limit' });
  });
  it('hands a call above the threshold to a person, and one it cannot compare', () => {
    expect(personRequired(gate, { amount_minor: 50000, currency: 'USD' })).toEqual({ required: false });
    expect(personRequired(gate, { amount_minor: 50001, currency: 'USD' })).toMatchObject({ required: true });
    expect(personRequired(gate, { amount_minor: 1, currency: 'EUR' })).toMatchObject({ required: true });
    expect(personRequired(gate, { to: 'x' })).toEqual({ required: false });
  });
});

describe('held ids and the report url', () => {
  it('is one id per exact action under one standard', () => {
    const a = heldIdFor('0'.repeat(24), 'pay_invoice', 'h1');
    expect(a).toMatch(/^[0-9a-f]{24}$/);
    expect(heldIdFor('0'.repeat(24), 'pay_invoice', 'h1')).toBe(a);
    expect(heldIdFor('0'.repeat(24), 'pay_invoice', 'h2')).not.toBe(a);
    expect(heldIdFor('1'.repeat(24), 'pay_invoice', 'h1')).not.toBe(a);
  });
  it('reads the standard id from the report url only', () => {
    expect(sidFromReportUrl('https://scopeblind.com/api/standard?s=' + 'c'.repeat(24))).toBe('c'.repeat(24));
    expect(sidFromReportUrl('https://scopeblind.com/api/standard')).toBeNull();
    expect(sidFromReportUrl('not a url')).toBeNull();
  });
});

describe('RecordReporter', () => {
  const sid = 'b'.repeat(24);
  const url = `https://scopeblind.com/api/standard?s=${sid}`;
  function fake(responses: Array<{ status: number; body: unknown }>) {
    const calls: Array<{ url: string; init: { method?: string; headers?: Record<string, string>; body?: string } | undefined }> = [];
    const fetchImpl = async (u: string, init?: { method?: string; headers?: Record<string, string>; body?: string }) => {
      calls.push({ url: u, init });
      const next = responses.shift() ?? { status: 200, body: { ok: true } };
      return { ok: next.status < 400, status: next.status, json: async () => next.body };
    };
    return { calls, fetchImpl };
  }
  it('appends queued receipts and calls in one post under the bearer token', async () => {
    const { calls, fetchImpl } = fake([{ status: 200, body: { ok: true } }]);
    const r = new RecordReporter({ url, token: 'tok', runId: 'run-1', fetchImpl, log: () => {} });
    r.record('{"r":1}', '{"c":1}'); r.record('{"r":2}');
    await r.flush();
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe(`${url}&op=record`);
    expect(calls[0].init?.headers?.authorization).toBe('Bearer tok');
    const body = JSON.parse(calls[0].init?.body ?? '{}');
    expect(body).toMatchObject({ sid, run_id: 'run-1', append: true, receipts: '{"r":1}\n{"r":2}', calls: '{"c":1}' });
    expect(r.sent).toBe(2);
  });
  it('swallows a failure and counts it', async () => {
    const { fetchImpl } = fake([{ status: 403, body: { ok: false, error: 'bad_token' } }]);
    const lines: string[] = [];
    const r = new RecordReporter({ url, token: 'wrong', runId: 'run-1', fetchImpl, log: (m) => lines.push(m) });
    r.record('{"r":1}'); await r.flush();
    expect(r.failed).toBe(1); expect(lines[0]).toMatch(/403 bad_token/);
  });
  it('posts a held action and reads its decision', async () => {
    const hid = 'e'.repeat(24);
    const { calls, fetchImpl } = fake([
      { status: 200, body: { ok: true, url: `https://scopeblind.com/standard?s=${sid}#held-${hid}` } },
      { status: 200, body: { ok: true, held: { decision: null } } },
      { status: 200, body: { ok: true, held: { decision: { decision: 'approve', approver: { key_id: 'recipient:1234' }, digest: 'dd', note: 'ok' } } } },
      { status: 404, body: { ok: false, error: 'held_not_found' } },
    ]);
    const r = new RecordReporter({ url, token: 'tok', runId: 'run-1', fetchImpl, log: () => {} });
    const page = await r.hold({ hid, request_id: 'rq', tool: 'pay_invoice', readback: { summary: 'pay 900', payload_hash: 'ph' }, reason: 'above 500' });
    expect(page).toBe(`https://scopeblind.com/standard?s=${sid}#held-${hid}`);
    expect(JSON.parse(calls[0].init?.body ?? '{}')).toMatchObject({ sid, hid, tool: 'pay_invoice', run_id: 'run-1' });
    expect(await r.decision(hid)).toBeNull();
    expect(await r.decision(hid)).toEqual({ decision: 'approve', approver_key_id: 'recipient:1234', digest: 'dd', note: 'ok' });
    expect(await r.decision(hid)).toBeNull();
    expect(calls[1].url).toBe(`${url}&held=${hid}`);
  });
  it('refuses a report url without a standard id', () => {
    expect(() => new RecordReporter({ url: 'https://scopeblind.com/api/standard', token: 't', runId: 'r' })).toThrow(/report URL/);
  });
});
