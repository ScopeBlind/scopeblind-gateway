import { beforeAll, describe, expect, it, vi } from 'vitest';
import { CoordinationClient } from './coordination-client.js';
import { handleCoordinationRequest } from './coordination-server.js';
import { defaultAgreement, defaultFixtures, generateIdentity, sign, type SigningIdentity } from './coordination-protocol.js';
import { defaultRehearsalCases, rehearsalDigest, type RehearsalState, type RehearsalReport } from './coordination-rehearsal.js';

let owner: SigningIdentity, authority: SigningIdentity;
beforeAll(async () => { owner = await generateIdentity(); authority = await generateIdentity(); });
const id = 'rehearsal-room-01';
async function fixture() {
  const agreement = await sign(defaultAgreement(id, owner.publicKey, authority.publicKey), owner);
  const fixtures = defaultFixtures(), cases = defaultRehearsalCases(fixtures);
  const rehearsal: RehearsalState = { agreement_digest: agreement.digest, fixture_digest: await rehearsalDigest(fixtures), cases_digest: await rehearsalDigest(cases), cases, proposals: [], reports: [], grants: [], adoptions: [], can_propose: true, can_adopt: false };
  const response = { ok: true, room_id: id, authority_key: authority.publicKey, agreement, fixtures, rehearsal };
  const fetcher = vi.fn(async () => new Response(JSON.stringify(response), { status: 200 }));
  const client = new CoordinationClient({ endpoint: 'https://test.example/api/coordination', roomId: id, authorityKey: authority.publicKey, token: 'private-test-token', purpose: 'rehearsal' }, fetcher);
  return { client, response, fetcher };
}
const request = (name: string, args: unknown = {}) => ({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
const body = (f: Awaited<ReturnType<typeof fixture>>, index = 0) => JSON.parse((f.fetcher.mock.calls[index] as unknown as [unknown, RequestInit])[1].body as string);

describe('test-only installed coordination tools', () => {
  it('lists only explicitly granted test tools and rejects payments or adoption locally', async () => {
    const f = await fixture();
    const listed: any = await handleCoordinationRequest(f.client, { jsonrpc: '2.0', id: 1, method: 'tools/list' });
    expect(listed.result.tools.map((tool: any) => tool.name)).toEqual(['coordination.inspect_rehearsal','coordination.propose_case','coordination.propose_repair','coordination.run_rehearsal']);
    for (const name of ['ledger.pay','coordination.deliver','coordination.inspect','coordination.adopt']) {
      const response: any = await handleCoordinationRequest(f.client, request(name));
      expect(response.result.isError).toBe(true);
      expect(JSON.parse(response.result.content[0].text).code).toBe('tool_outside_grant');
    }
    expect(f.fetcher).not.toHaveBeenCalled();
  });
  it('verifies the source pin and exact fixture/case snapshots without execution.inspect', async () => {
    const f = await fixture();
    expect((await f.client.inspectRehearsal()).source_signature_verified).toBe(true);
    expect(body(f).action).toBe('rehearsal_get');
    f.response.fixtures.invoices[0].amount_minor++;
    await expect(f.client.inspectRehearsal()).rejects.toMatchObject({ code: 'invalid_rehearsal' });
    const other = await fixture(); other.response.authority_key = owner.publicKey;
    await expect(other.client.inspectRehearsal()).rejects.toMatchObject({ code: 'invalid_rehearsal' });
  });
  it('refuses elevated/unknown fields before transmitting a case or run', async () => {
    const f = await fixture();
    const caseInput = { id: 'expect-review', title: 'Review above 400', kind: 'invoice' as const, invoice_id: 'INV-102', expected: 'ask' as const, requirement: 'A person reviews this amount.' };
    await expect(f.client.proposeCase({ ...caseInput, required: true })).rejects.toMatchObject({ code: 'invalid_input' });
    await expect(f.client.proposeCase({ ...caseInput, approve: true } as any)).rejects.toMatchObject({ code: 'invalid_input' });
    await expect(f.client.runRehearsal({ id: 'compare-1', adopt: true } as any)).rejects.toMatchObject({ code: 'invalid_input' });
    await expect(f.client.runRehearsal({ id: 'bad id' })).rejects.toMatchObject({ code: 'invalid_input' });
    expect(f.fetcher).not.toHaveBeenCalled();
    f.response.rehearsal.cases.push(caseInput); f.response.rehearsal.cases_digest = await rehearsalDigest(f.response.rehearsal.cases);
    await f.client.proposeCase(caseInput);
    expect(body(f)).toEqual({ action: 'rehearsal_case', room_id: id, body: { case: caseInput } });
  });
  it('bounds proposed thresholds by the verified source budget and retains stable IDs', async () => {
    const f = await fixture();
    await expect(f.client.proposeRepair({ id: 'repair-too-large', approval_above_minor: f.response.agreement.payload.budget_minor + 1, rationale: 'test' })).rejects.toMatchObject({ code: 'invalid_input' });
    expect(f.fetcher).toHaveBeenCalledTimes(1);
    const proposal = await sign({ type: 'scopeblind.coordination.repair-proposal.v1' as const, id: 'repair-400', approval_above_minor: 40000, rationale: 'Hold Fieldwork for review while allowing Northstar.', room_id: id, author_key: owner.publicKey, agreement_digest: f.response.agreement.digest, fixture_digest: f.response.rehearsal.fixture_digest, cases_digest: f.response.rehearsal.cases_digest, previous_approval_above_minor: 50000, issued_at: new Date().toISOString() }, authority);
    f.response.rehearsal.proposals.push(proposal); Object.assign(f.response, { proposal });
    await f.client.proposeRepair({ id: 'repair-400', approval_above_minor: 40000, rationale: 'Hold Fieldwork for review while allowing Northstar.' });
    expect(body(f, 2)).toEqual({ action: 'rehearsal_propose', room_id: id, body: { proposal: { id: 'repair-400', approval_above_minor: 40000, rationale: 'Hold Fieldwork for review while allowing Northstar.' } } });
  });
  it('returns unknown with same-ID recovery after a lost run response and never retries automatically', async () => {
    const f = await fixture(); f.fetcher.mockRejectedValueOnce(new Error('sensitive model or network data'));
    await expect(f.client.runRehearsal({ id: 'compare-400', proposal_id: 'repair-400' })).rejects.toMatchObject({ code: 'rehearsal_outcome_unknown', message: expect.stringContaining('SAME test id') });
    expect(f.fetcher).toHaveBeenCalledTimes(1);
    expect(body(f).body).toEqual({ id: 'compare-400', proposal_id: 'repair-400' });
  });
  it('propagates durable revocation as a safe capability error', async () => {
    const f = await fixture(); f.fetcher.mockResolvedValueOnce(new Response(JSON.stringify({ ok: false, error: 'executor_token_invalid', secret: 'do-not-print' }), { status: 403 }));
    const response: any = await handleCoordinationRequest(f.client, request('coordination.inspect_rehearsal'));
    expect(response.result.isError).toBe(true); expect(JSON.parse(response.result.content[0].text).code).toBe('executor_token_invalid');
    expect(JSON.stringify(response)).not.toContain('do-not-print');
  });
  it('rejects an unrelated response artifact or missing requested historical evidence', async () => {
    const f = await fixture();
    Object.assign(f.response, { report: { payload: { id: 'unverified-report' } } });
    await expect(f.client.inspectRehearsal()).rejects.toMatchObject({ code: 'invalid_rehearsal' });
    const other = await fixture();
    await expect(other.client.inspectRehearsal('aa'.repeat(32))).rejects.toMatchObject({ code: 'invalid_rehearsal_evidence' });
  });
  it('snapshots a proposed repair before reading the source budget', async () => {
    const f = await fixture();
    const input = { id: 'repair-snapshot', approval_above_minor: 40000, rationale: 'Review these invoices.' };
    const original = { ...input };
    const proposal = await sign({ ...original, type: 'scopeblind.coordination.repair-proposal.v1' as const, room_id: id, author_key: owner.publicKey, agreement_digest: f.response.agreement.digest, fixture_digest: f.response.rehearsal.fixture_digest, cases_digest: f.response.rehearsal.cases_digest, previous_approval_above_minor: 50000, issued_at: new Date().toISOString() }, authority);
    f.response.rehearsal.proposals.push(proposal); Object.assign(f.response, { proposal });
    f.fetcher.mockImplementationOnce(async () => { input.approval_above_minor = 0; return new Response(JSON.stringify(f.response)); });
    await f.client.proposeRepair(input);
    expect(body(f, 1).body.proposal).toEqual(original);
  });

  it('continues durable chunks with the same ID and returns only a verified complete report', async () => {
    const f = await fixture();
    const report = await sign<RehearsalReport>({ type: 'scopeblind.coordination.rehearsal-report.v1', id: 'chunked-test', room_id: id, agreement_digest: f.response.agreement.digest, fixture_digest: f.response.rehearsal.fixture_digest, cases_digest: f.response.rehearsal.cases_digest, runtime_revision: 'tested-runtime', adapter: 'coordination-d1-sandbox', issued_at: new Date().toISOString(), isolation: 'separate-fixture-ledgers', results: f.response.rehearsal.cases.map(c => ({ case: c, before: { actual: 'refuse', matched: false, reason: 'Synthetic observed failure', steps: [{ action: 'admit', decision: 'refuse', reason: 'Synthetic' }], payments: 0, spent_minor: 0, invariant_passed: false } })), required_passed: false, expectations_met: false, before_approval_above_minor: 50000 }, authority);
    const base = structuredClone(f.response);
    f.response.rehearsal.reports.push(report);
    Object.assign(f.response, { report, evidence: { type: 'scopeblind.coordination.rehearsal-evidence.v1', agreement: f.response.agreement, fixtures: f.response.fixtures, cases: f.response.rehearsal.cases, report } });
    for (const complete of [2,4]) f.fetcher.mockResolvedValueOnce(new Response(JSON.stringify({ ...base, run: { id: 'chunked-test', status: 'running', completed_cases: complete, total_cases: 6 } })));
    const result = await f.client.runRehearsal({ id: 'chunked-test' });
    expect(result.status).toBe('completed'); expect((result.evidence_verification as any).valid).toBe(true);
    expect(f.fetcher).toHaveBeenCalledTimes(3);
    for (let i = 0; i < 3; i++) expect(body(f, i).body).toEqual({ id: 'chunked-test' });
    // Valid evidence of failed expectations is not a passing comparison.
    expect((result.report as any).payload.expectations_met).toBe(false);
  });
  it('preserves a checkpoint when the bounded call deadline is reached', async () => {
    const f = await fixture(); Object.assign(f.response, { run: { id: 'slow-test', status: 'running', completed_cases: 2, total_cases: 10 } });
    let clock = 0; const now = vi.spyOn(performance, 'now').mockImplementation(() => clock);
    f.fetcher.mockImplementation(async () => { clock = 180001; return new Response(JSON.stringify(f.response)); });
    const result = await f.client.runRehearsal({ id: 'slow-test' }); now.mockRestore();
    expect(result.status).toBe('pending'); expect(result.run).toMatchObject({ id: 'slow-test', completed_cases: 2 });
    expect(f.fetcher).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(result.next_steps)).toContain('SAME id');
  });
  it('spaces lease-contention retries and stops when the caller cancels', async () => {
    vi.useFakeTimers();
    try {
      const f = await fixture(), abort = new AbortController();
      f.fetcher.mockImplementation(async () => new Response(JSON.stringify({ ok: false, error: 'rehearsal_in_progress' }), { status: 409 }));
      const promise = f.client.runRehearsal({ id: 'leased-test' }, abort.signal);
      await vi.advanceTimersByTimeAsync(999); expect(f.fetcher).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(1); expect(f.fetcher).toHaveBeenCalledTimes(2);
      abort.abort(); const result = await promise;
      expect(result.status).toBe('pending'); expect(result.cancelled).toBe(true);
      await vi.advanceTimersByTimeAsync(5000); expect(f.fetcher).toHaveBeenCalledTimes(2);
    } finally { vi.useRealTimers(); }
  });
  it('reports uncertain outcome after a bounded request timeout', async () => {
    vi.useFakeTimers();
    try {
      const f = await fixture();
      f.fetcher.mockImplementation((_url: unknown, options: any) => new Promise((_resolve, reject) => { options.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true }); }) as any);
      // Even a longer explicit transport timeout cannot create an automatic retry.
      const client = new CoordinationClient({ endpoint: 'https://test.example/api/coordination', roomId: id, authorityKey: authority.publicKey, token: 'test', purpose: 'rehearsal', timeoutMs: 120000 }, f.fetcher);
      const pending = expect(client.runRehearsal({ id: 'deadline-test' })).rejects.toMatchObject({ code: 'rehearsal_outcome_unknown' });
      await vi.advanceTimersByTimeAsync(120000);
      await pending;
      expect(f.fetcher).toHaveBeenCalledTimes(1);
    } finally { vi.useRealTimers(); }
  });

  it('does not spin on an unchanged leased checkpoint or continue beyond six advancing chunks', async () => {
    const f = await fixture(); let completed = 0;
    f.fetcher.mockImplementation(async () => new Response(JSON.stringify({ ...f.response, run: { id: 'bounded-chunks', status: 'running', completed_cases: ++completed, total_cases: 10 } })));
    const result = await f.client.runRehearsal({ id: 'bounded-chunks' });
    expect(result.status).toBe('pending'); expect(f.fetcher).toHaveBeenCalledTimes(6); expect(result.run).toMatchObject({ completed_cases: 6 });
    vi.useFakeTimers();
    try {
      const leased = await fixture(), abort = new AbortController();
      Object.assign(leased.response, { run: { id: 'unchanged-lease', status: 'running', completed_cases: 0, total_cases: 6 } });
      const pending = leased.client.runRehearsal({ id: 'unchanged-lease' }, abort.signal);
      await vi.advanceTimersByTimeAsync(999); expect(leased.fetcher).toHaveBeenCalledTimes(1);
      abort.abort(); expect((await pending).status).toBe('pending');
    } finally { vi.useRealTimers(); }
  });

});
