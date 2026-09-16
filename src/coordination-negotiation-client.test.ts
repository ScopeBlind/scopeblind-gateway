import { describe, expect, it, vi } from 'vitest';
import { CoordinationClient } from './coordination-client.js';
import { handleCoordinationRequest } from './coordination-server.js';
import { defaultAgreement, defaultFixtures, generateIdentity, makeRequest, sign } from './coordination-protocol.js';
import { NEGOTIATION_AGENT_ACTIONS, mandateCases, negotiationDigest, negotiationPayloadDigest, privateBriefCommitment, type NegotiationMandate, type NegotiationProposal, type NegotiationResponse, type NegotiationState } from './coordination-negotiation.js';

const roomId = 'neg-room-001', sessionId = 'neg-session-001';
async function fixture() {
  const authority = await generateIdentity(), owner = await generateIdentity(), partner = await generateIdentity(), agent = await generateIdentity();
  const agreement = await sign(defaultAgreement(roomId, owner.publicKey, authority.publicKey), owner), fixtures = defaultFixtures();
  const fixtureDigest = await negotiationDigest(fixtures), issued = new Date().toISOString(), expires = new Date(Date.now() + 3600000).toISOString();
  const invitation = await sign({ type: 'scopeblind.coordination.negotiation-invitation.v1' as const, session_id: sessionId, room_id: roomId, agreement_digest: agreement.digest, fixture_digest: fixtureDigest, issuer: owner.publicKey, registrar_key: authority.publicKey, role: 'counterparty' as const, token_hash: 'ab'.repeat(32), max_claims: 1 as const, expires_at: expires }, owner);
  const session = await sign({ type: 'scopeblind.coordination.negotiation-session.v1' as const, id: sessionId, room_id: roomId, agreement_digest: agreement.digest, fixture_digest: fixtureDigest, owner_key: owner.publicKey, registrar_key: authority.publicKey, invitation_digest: invitation.digest, created_at: issued, expires_at: expires, max_proposals: 3 as const }, authority);
  const claim = await sign({ type: 'scopeblind.coordination.negotiation-claim.v1' as const, session_id: sessionId, room_id: roomId, guest_key: partner.publicKey, name: 'Partner', issued_at: issued, nonce: 'claim-nonce-001' }, partner);
  const binding = await sign({ type: 'scopeblind.coordination.negotiation-binding.v1' as const, session_id: sessionId, room_id: roomId, invitation_digest: invitation.digest, guest_key: partner.publicKey, name: 'Partner', issued_at: issued, expires_at: expires, claim }, authority);
  const brief = { text: 'Private owner background. Do not publish it.', preference: 'balanced' as const, salt: 'cd'.repeat(32) };
  const peerBrief = { text: 'OPPOSING_PRIVATE_BACKGROUND', preference: 'more_review' as const, salt: 'ef'.repeat(32) };
  const ownerMandate = await sign<NegotiationMandate>({ type: 'scopeblind.coordination.negotiation-mandate.v1', session_id: sessionId, room_id: roomId, principal_key: owner.publicKey, version: 1, agreement_digest: agreement.digest, fixture_digest: fixtureDigest, min_threshold_minor: 20000, max_threshold_minor: 60000, required_invoices: [], private_brief_commitment: await privateBriefCommitment(brief), agent_mode: 'own', actions: NEGOTIATION_AGENT_ACTIONS, issued_at: issued, expires_at: expires }, owner);
  const partnerMandate = await sign<NegotiationMandate>({ ...ownerMandate.payload, principal_key: partner.publicKey, private_brief_commitment: await privateBriefCommitment(peerBrief) }, partner);
  const state: NegotiationState = { session, invitation, binding, agreement, fixtures, principals: [{ side: 'organizer', key: owner.publicKey, name: 'Owner', mandate: ownerMandate }, { side: 'partner', key: partner.publicKey, name: 'Partner', mandate: partnerMandate }], started: false, status: 'ready', proposals: [], responses: [], reports: [], approvals: [], next_principal_key: owner.publicKey, model_steps: 0, max_model_steps: 6, viewer: { principal_key: owner.publicKey, side: 'organizer', brief, pairs: [], is_agent: true } };
  const authorization = await sign(makeRequest('negotiation_pair_create', roomId, { session_id: sessionId, pair_id: 'pair-neg-001', secret_hash: 'da'.repeat(32), name: 'My agent', expires_at: new Date(Date.now() + 600000).toISOString(), token_expires_at: expires, scope: NEGOTIATION_AGENT_ACTIONS }), owner);
  state.agent_bindings = [await sign({ type: 'scopeblind.coordination.agent-binding.v1', pair_id: 'pair-neg-001', room_id: roomId, session_id: sessionId, principal_key: owner.publicKey, agreement_digest: agreement.digest, owner_key: owner.publicKey, agent_key: agent.publicKey, name: 'My agent', scope: NEGOTIATION_AGENT_ACTIONS, audience: 'scopeblind.coordination.negotiation', issued_at: issued, expires_at: expires, owner_authorization: authorization } as const, authority)];
  const response: Record<string, unknown> = { ok: true, negotiation: state };
  const fetcher = vi.fn(async (_url: unknown, options?: RequestInit) => { expect(new Headers(options?.headers).get('authorization')).toBe('Bearer private-negotiation-token'); return new Response(JSON.stringify(response)); });
  const config = { endpoint: 'https://fixture.test/api/coordination', roomId, authorityKey: authority.publicKey, token: 'private-negotiation-token', purpose: 'negotiation' as const, sessionId, principalKey: owner.publicKey };
  const client = new CoordinationClient(config, fetcher);
  async function proposal(threshold = 40000, author = owner, id = `candidate-${state.proposals.length + 1}`, budget?: number) {
    const next = { ...agreement.payload, id: `next-room-${id}`, approval_above_minor: threshold, ...(budget === undefined ? {} : { budget_minor: budget }), issued_at: issued };
    const grant = { type: 'scopeblind.coordination.grant.v1' as const, grant_id: 'reviewer-grant-001', room_id: next.id, agreement_digest: await negotiationPayloadDigest(next), issuer: owner.publicKey, registrar_key: authority.publicKey, role: 'reviewer' as const, actions: ['decide','accept'] as Array<'decide'|'accept'>, expires_at: expires, token_hash: 'ed'.repeat(32), max_claims: 1 as const };
    const candidate = await sign<NegotiationProposal>({ type: 'scopeblind.coordination.negotiation-proposal.v1', id, approval_above_minor: threshold, ...(budget === undefined ? {} : { budget_minor: budget }), ...(state.proposals.length ? { parent_digest: state.proposals.at(-1)!.digest } : {}), session_id: sessionId, room_id: roomId, round: state.proposals.length + 1, principal_key: author.publicKey, ...(author.publicKey === owner.publicKey ? {agent_key: agent.publicKey, agent_mode: 'own' as const} : {agent_mode: 'manual' as const}), agreement_digest: agreement.digest, fixture_digest: fixtureDigest, mandate_digests: [ownerMandate.digest, partnerMandate.digest], next_agreement: next, next_agreement_digest: await negotiationPayloadDigest(next), reviewer_grant: grant, reviewer_grant_digest: await negotiationPayloadDigest(grant), issued_at: issued }, authority);
    state.proposals.push(candidate); return candidate;
  }
  return { client, config, fetcher, response, state, authority, owner, partner, agent, brief, peerBrief, ownerMandate, partnerMandate, proposal };
}
const rpc = (name: string, args: unknown = {}) => ({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
const requestBody = (f: Awaited<ReturnType<typeof fixture>>, index = 0) => JSON.parse(String(f.fetcher.mock.calls[index][1]?.body));

describe('principal-scoped installed negotiation', () => {
  it('exposes only negotiation tools and rejects payment, hosted execution, and human authority before transport', async () => {
    const f = await fixture();
    const listing: any = await handleCoordinationRequest(f.client, { jsonrpc: '2.0', id: 1, method: 'tools/list' });
    expect(listing.result.tools.map((t: any) => t.name)).toEqual(['coordination.inspect_negotiation','coordination.propose_candidate','coordination.respond_candidate','coordination.compare_candidate','coordination.wait_negotiation']);
    for (const tool of ['ledger.pay','coordination.inspect','coordination.deliver','coordination.inspect_rehearsal','coordination.run_rehearsal','negotiation_step','negotiation_approve','negotiation_adopt','negotiation_pair_create']) {
      const response: any = await handleCoordinationRequest(f.client, rpc(tool));
      expect(JSON.parse(response.result.content[0].text).code).toBe('tool_outside_grant');
    }
    await expect(f.client.inspect()).rejects.toMatchObject({ code: 'tool_outside_grant' });
    const execution = new CoordinationClient({ endpoint: f.config.endpoint, roomId, authorityKey: f.authority.publicKey, token: 'execution' }, f.fetcher);
    const response: any = await handleCoordinationRequest(execution, rpc('coordination.inspect_negotiation'));
    expect(JSON.parse(response.result.content[0].text).code).toBe('tool_outside_grant'); expect(f.fetcher).not.toHaveBeenCalled();
  });
  it('reports the negotiation-capable 0.21.0 release on MCP initialization', async () => {
    const f = await fixture(); vi.stubEnv('PROTECT_MCP_VERSION', '');
    try { const response: any = await handleCoordinationRequest(f.client, { jsonrpc: '2.0', id: 1, method: 'initialize' }); expect(response.result.serverInfo.version).toBe('0.21.0'); } finally { vi.unstubAllEnvs(); }
  });
  it('verifies the own brief commitment without reading a general room or opposing private brief', async () => {
    const f = await fixture(), result = await f.client.inspectNegotiation();
    expect(result.signatures_verified).toBe(true); expect(JSON.stringify(result)).toContain(f.brief.text); expect(JSON.stringify(result)).not.toContain(f.peerBrief.text);
    expect(requestBody(f)).toEqual({ action: 'negotiation_get', room_id: roomId, body: { session_id: sessionId } });
    f.state.viewer.brief = f.peerBrief;
    const failed: any = await handleCoordinationRequest(f.client, rpc('coordination.inspect_negotiation'));
    expect(JSON.parse(failed.result.content[0].text).code).toBe('invalid_negotiation'); expect(JSON.stringify(failed)).not.toContain(f.peerBrief.text);
  });
  it('accepts a room-bound linked-device mandate only with its recorded authorization use', async () => {
    const f=await fixture(),device=await generateIdentity(),issued=f.ownerMandate.payload.issued_at,expires=f.ownerMandate.payload.expires_at;
    const authorization=await sign({type:'scopeblind.coordination.device-authorization.v1' as const,id:'device-grant-001',link_id:'device-link-001',room_id:roomId,agreement_digest:f.state.agreement.digest,principal_key:f.owner.publicKey,device_key:device.publicKey,device_name:'My phone',actions:['negotiation_mandate' as const],issued_at:issued,expires_at:expires,authority_key:f.authority.publicKey},f.owner);
    const mandate=await sign(f.ownerMandate.payload,{...device,deviceAuthorization:authorization});
    mandate.authorization_use=await sign({type:'scopeblind.coordination.device-use.v1',authorization_digest:authorization.digest,principal_key:f.owner.publicKey,device_key:device.publicKey,room_id:roomId,payload_digest:mandate.digest,action:'negotiation_mandate',recorded_at:issued} as const,f.authority);
    f.state.principals[0].mandate=mandate;expect((await f.client.inspectNegotiation()).signatures_verified).toBe(true);
    delete mandate.authorization_use;await expect(f.client.inspectNegotiation()).rejects.toMatchObject({code:'invalid_negotiation'});
    mandate.authorization=await sign({...authorization.payload,room_id:'wrong-room-001'},f.owner);await expect(f.client.inspectNegotiation()).rejects.toMatchObject({code:'invalid_negotiation'});
  });
  it('keeps earlier-runtime history readable but does not acknowledge readiness or invite agent work', async () => {
    const f=await fixture();f.state.runtime_changed=true;f.response.agent_inspection_supported=true;
    const read=await f.client.inspectNegotiation();expect(read.signatures_verified).toBe(true);expect(f.fetcher).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(read.next_steps)).toContain('fresh linked discussion');
    await expect(f.client.proposeCandidate({id:'stale-plan',approval_above_minor:40000})).rejects.toMatchObject({code:'negotiation_runtime_changed'});
    expect((await f.client.waitNegotiation({timeout_ms:1000})).wait_status).toBe('blocked');
    Object.assign(f.state,{runtime_changed:'yes'});await expect(f.client.inspectNegotiation()).rejects.toMatchObject({code:'invalid_negotiation'});
  });
  it('rejects another principal, changed fixtures, injected private fields, and forged mandates', async () => {
    const mutations = [
      (f: Awaited<ReturnType<typeof fixture>>) => { f.state.viewer.principal_key = f.partner.publicKey; },
      (f: Awaited<ReturnType<typeof fixture>>) => { f.state.fixtures.invoices[0].amount_minor++; },
      (f: Awaited<ReturnType<typeof fixture>>) => { Object.assign(f.state.principals[1], { private_brief: f.peerBrief }); },
      (f: Awaited<ReturnType<typeof fixture>>) => { f.ownerMandate.payload.max_threshold_minor++; },
      (f: Awaited<ReturnType<typeof fixture>>) => { f.state.session.payload.id = 'other-session'; },
    ];
    for (const mutate of mutations) { const f = await fixture(); mutate(f); await expect(f.client.inspectNegotiation()).rejects.toMatchObject({ code: 'invalid_negotiation' }); }
  });
  it('refuses extra powers and private proposal text without a request', async () => {
    const f = await fixture();
    for (const input of [{ id: 'candidate', approval_above_minor: 40000, private_brief: f.brief.text }, { id: 'candidate', approval_above_minor: 40000, approve: true }, { id: 'bad id', approval_above_minor: 40000 }]) await expect(f.client.proposeCandidate(input)).rejects.toMatchObject({ code: 'invalid_input' });
    await expect(f.client.respondCandidate({ proposal_digest: 'ab'.repeat(32), decision: 'approve' } as any)).rejects.toMatchObject({ code: 'invalid_input' });
    await expect(f.client.compareCandidate({ proposal_digest: 'ab'.repeat(32), adopt: true } as any)).rejects.toMatchObject({ code: 'invalid_input' });
    const response: any = await handleCoordinationRequest(f.client, rpc('coordination.inspect_negotiation', { principal_key: f.partner.publicKey }));
    expect(JSON.parse(response.result.content[0].text).code).toBe('invalid_input'); expect(f.fetcher).not.toHaveBeenCalled();
  });
  it('enforces own limits and parent identity, and snapshots the candidate across inspection', async () => {
    const f = await fixture();
    await expect(f.client.proposeCandidate({ id: 'too-high', approval_above_minor: 60001 })).rejects.toMatchObject({ code: 'invalid_candidate' }); expect(f.fetcher).toHaveBeenCalledTimes(1);
    const input = { id: 'candidate-1', approval_above_minor: 40000 };
    f.fetcher.mockImplementationOnce(async () => { input.approval_above_minor = 0; return new Response(JSON.stringify(f.response)); });
    f.fetcher.mockImplementationOnce(async () => { await f.proposal(); return new Response(JSON.stringify(f.response)); });
    await f.client.proposeCandidate(input); expect(requestBody(f, 2).body.proposal).toEqual({ id: 'candidate-1', approval_above_minor: 40000 });
    f.state.next_principal_key = f.owner.publicKey;
    await expect(f.client.proposeCandidate({ id: 'candidate-2', approval_above_minor: 40000, parent_digest: 'ab'.repeat(32) })).rejects.toMatchObject({ code: 'invalid_candidate' });
  });
  it('recovers an identical proposal id without another mutation and stops at three candidates', async () => {
    const f = await fixture(), first = await f.proposal();
    expect((await f.client.proposeCandidate({ id: first.payload.id, approval_above_minor: 40000 })).signatures_verified).toBe(true); expect(f.fetcher).toHaveBeenCalledTimes(1);
    await expect(f.client.proposeCandidate({ id: first.payload.id, approval_above_minor: 42000 })).rejects.toMatchObject({ code: 'negotiation_id_conflict' });
    await f.proposal(42000, f.partner); await f.proposal(44000);
    await expect(f.client.proposeCandidate({ id: 'candidate-4', approval_above_minor: 45000, parent_digest: f.state.proposals.at(-1)!.digest })).rejects.toMatchObject({ code: 'negotiation_round_limit' });
    expect(f.fetcher.mock.calls.every((_, i) => requestBody(f, i).action === 'negotiation_get')).toBe(true);
  });
  it('verifies two-parameter mandates, preserves exact submitted budget, and refuses human-only exploration', async () => {
    const f = await fixture();
    Object.assign(f.brief, { budget_preference: 'lower_budget' });
    Object.assign(f.ownerMandate, await sign({ ...f.ownerMandate.payload, min_budget_minor: 80000, max_budget_minor: 180000, private_brief_commitment: await privateBriefCommitment(f.brief) }, f.owner));
    Object.assign(f.partnerMandate, await sign({ ...f.partnerMandate.payload, min_budget_minor: 90000, max_budget_minor: 180000 }, f.partner));
    expect((await f.client.inspectNegotiation()).signatures_verified).toBe(true);
    const before = f.fetcher.mock.calls.length;
    await expect(f.client.proposeCandidate({ id: 'candidate-new', approval_above_minor: 40000, budget_minor: 70000 })).rejects.toMatchObject({code:'invalid_candidate'});
    expect(f.fetcher).toHaveBeenCalledTimes(before + 1);
    const input = {id:'candidate-budget',approval_above_minor:40000,budget_minor:120000};
    f.fetcher.mockImplementationOnce(async () => new Response(JSON.stringify(f.response)));
    f.fetcher.mockImplementationOnce(async () => { await f.proposal(40000,f.owner,input.id,120000); return new Response(JSON.stringify(f.response)); });
    const result = await f.client.proposeCandidate(input);
    expect((result.negotiation as NegotiationState).proposals[0].payload.next_agreement.budget_minor).toBe(120000);
    expect(requestBody(f,f.fetcher.mock.calls.length-1).body.proposal).toEqual(input);
    await expect(f.client.proposeCandidate({...input,budget_minor:130000})).rejects.toMatchObject({code:'negotiation_id_conflict'});
    const count=f.fetcher.mock.calls.length;
    await expect(f.client.proposeCandidate({...input,exploration:true})).rejects.toMatchObject({code:'invalid_input'});
    expect(f.fetcher).toHaveBeenCalledTimes(count);
  });
  it('rejects a half-specified budget mandate and a signed candidate with altered protected terms', async () => {
    const f = await fixture();
    Object.assign(f.ownerMandate,await sign({...f.ownerMandate.payload,min_budget_minor:80000},f.owner));
    await expect(f.client.inspectNegotiation()).rejects.toMatchObject({code:'invalid_negotiation'});
    const g = await fixture(), proposal=await g.proposal();
    proposal.payload.next_agreement.allowed_destinations.push('sandbox:unapproved');
    proposal.payload.next_agreement_digest=await negotiationPayloadDigest(proposal.payload.next_agreement);
    Object.assign(proposal,await sign(proposal.payload,g.authority));
    await expect(g.client.inspectNegotiation()).rejects.toMatchObject({code:'invalid_negotiation'});
  });
  it('binds an agent response to the exact candidate and never labels support as human approval', async () => {
    const f = await fixture(), candidate = await f.proposal();
    f.state.responses.push(await sign<NegotiationResponse>({ type: 'scopeblind.coordination.negotiation-response.v1', session_id: sessionId, principal_key: f.owner.publicKey, proposal_digest: candidate.digest, mandate_digest: f.ownerMandate.digest, decision: 'support', agent_key: f.agent.publicKey, agent_mode: 'own', issued_at: new Date().toISOString() }, f.authority));
    const result = await f.client.respondCandidate({ proposal_digest: candidate.digest, decision: 'support' });
    expect(requestBody(f).body).toEqual({ session_id: sessionId, proposal_digest: candidate.digest, decision: 'support' });
    expect((result.negotiation as NegotiationState).approvals).toEqual([]); expect(result.scope).toContain('not a human approval');
  });
  it('keeps candidate identity and checkpoint at the bounded comparison deadline', async () => {
    const f = await fixture(), candidate = await f.proposal();
    f.state.run = { proposal_digest: candidate.digest, status: 'running', completed_cases: 2, total_cases: mandateCases([f.ownerMandate, f.partnerMandate], f.state.fixtures).length };
    let clock = 0; const now = vi.spyOn(performance, 'now').mockImplementation(() => clock);
    f.fetcher.mockImplementation(async () => { clock = 180001; return new Response(JSON.stringify(f.response)); });
    try { const result = await f.client.compareCandidate({ proposal_digest: candidate.digest }); expect(result.comparison_status).toBe('pending'); expect((result.negotiation as NegotiationState).run?.completed_cases).toBe(2); expect(requestBody(f)).toEqual({ action: 'negotiation_compare', room_id: roomId, body: { session_id: sessionId, proposal_digest: candidate.digest } }); expect(f.fetcher).toHaveBeenCalledTimes(1); }
    finally { now.mockRestore(); }
  });
  it('reports a lost comparison response without automatically creating another run or candidate', async () => {
    const f = await fixture(); f.fetcher.mockRejectedValueOnce(new Error(f.peerBrief.text));
    await expect(f.client.compareCandidate({ proposal_digest: 'ab'.repeat(32) })).rejects.toMatchObject({ code: 'negotiation_outcome_unknown', message: expect.stringContaining('SAME proposal_digest') }); expect(f.fetcher).toHaveBeenCalledTimes(1);
  });
  it('refuses missing requested historical evidence and invalid comparison exports', async () => {
    const f = await fixture();
    await expect(f.client.inspectNegotiation('ab'.repeat(32))).rejects.toMatchObject({ code: 'invalid_negotiation_evidence' });
    f.response.evidence = { type: 'scopeblind.coordination.negotiation-evidence.v1', private_brief: f.peerBrief };
    await expect(f.client.inspectNegotiation()).rejects.toMatchObject({ code: 'invalid_negotiation_evidence' });
  });
  it('waits at two-second intervals on only scoped get and returns when its action is available', async () => {
    const f = await fixture(); f.state.next_principal_key = f.partner.publicKey; f.state.status = 'waiting_agent';
    const polls: number[] = [];
    f.fetcher.mockImplementation(async () => { polls.push(performance.now()); if (polls.length === 2) f.state.next_principal_key = f.owner.publicKey; return new Response(JSON.stringify(f.response)); });
    const result = await f.client.waitNegotiation({ timeout_ms: 5000 });
    expect(result.wait_status).toBe('action_required'); expect(polls).toHaveLength(2); expect(polls[1] - polls[0]).toBeGreaterThanOrEqual(1900); expect(f.fetcher.mock.calls.every((_, i) => requestBody(f, i).action === 'negotiation_get')).toBe(true);
  }, 8000);
  it('returns timeout, blocked, and human-decision states without proposing', async () => {
    const f = await fixture(); f.state.next_principal_key = f.partner.publicKey; f.state.status = 'waiting_agent';
    expect((await f.client.waitNegotiation({ timeout_ms: 1000 })).wait_status).toBe('waiting'); expect(f.fetcher).toHaveBeenCalledTimes(1);
    f.state.status = 'no_overlap'; expect((await f.client.waitNegotiation({})).wait_status).toBe('blocked');
    f.state.status = 'needs_decision'; expect((await f.client.waitNegotiation({})).wait_status).toBe('awaiting_human_decision');
  });
  it('cancels waiting and does not reflect private server error details', async () => {
    const f = await fixture(); f.state.next_principal_key = f.partner.publicKey;
    const abort = new AbortController(), timer = setTimeout(() => abort.abort(), 40);
    try { await expect(f.client.waitNegotiation({}, abort.signal)).rejects.toMatchObject({ code: 'cancelled' }); expect(f.fetcher).toHaveBeenCalledTimes(1); } finally { clearTimeout(timer); }
    f.fetcher.mockResolvedValueOnce(new Response(JSON.stringify({ ok: false, error: 'executor_token_invalid', detail: f.peerBrief.text }), { status: 403 }));
    const response: any = await handleCoordinationRequest(f.client, rpc('coordination.inspect_negotiation'));
    expect(JSON.parse(response.result.content[0].text).code).toBe('executor_token_invalid'); expect(JSON.stringify(response)).not.toContain(f.peerBrief.text);
  });
});
