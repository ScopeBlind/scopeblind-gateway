import { describe, expect, it } from 'vitest';
import evidence from './fixtures/negotiation-adopted.json';
import { generateIdentity, makeRequest, sign, type Signed } from './coordination-protocol.js';
import { NEGOTIATION_AGENT_ACTIONS, negotiationDigest, negotiationPayloadDigest, verifyNegotiationEvidence, type NegotiationExport } from './coordination-negotiation.js';
const fixture = () => structuredClone(evidence) as unknown as NegotiationExport;
const failed = async (e: unknown, pin?: string) => (await verifyNegotiationEvidence(e, pin)).checks.filter(c => !c.passed).map(c => c.name);
const pending = (e: NegotiationExport) => { delete e.adoption; delete e.adopted_agreement; delete e.reviewer_binding; delete e.reviewer_grant; e.approvals = []; return e; };
/** Re-key an actual D1 trace so adversarial changes can be signed, not merely bit-flipped. */
async function keyed(ownAgent = false) {
  const e = fixture(), oldOwner = e.agreement.payload.owner_key;
  const owner = await generateIdentity(), partner = await generateIdentity(), authority = await generateIdentity(), agent = await generateIdentity();
  const who = (old: string) => old === oldOwner ? owner : partner;
  e.agreement = await sign({ ...e.agreement.payload, owner_key: owner.publicKey, registrar_key: authority.publicKey }, owner);
  e.invitation = await sign({ ...e.invitation.payload, agreement_digest: e.agreement.digest, issuer: owner.publicKey, registrar_key: authority.publicKey }, owner);
  e.session = await sign({ ...e.session.payload, agreement_digest: e.agreement.digest, owner_key: owner.publicKey, registrar_key: authority.publicKey, invitation_digest: e.invitation.digest }, authority);
  e.binding = await sign({ ...e.binding.payload, invitation_digest: e.invitation.digest, guest_key: partner.publicKey, claim: await sign({ ...e.binding.payload.claim.payload, guest_key: partner.publicKey }, partner) }, authority);
  e.mandates = await Promise.all(e.mandates.map((m, i) => sign({ ...m.payload, principal_key: i ? partner.publicKey : owner.publicKey, agreement_digest: e.agreement.digest, agent_mode: ownAgent && !i ? 'own' : 'manual' }, i ? partner : owner))) as NegotiationExport['mandates'];
  const digests: [string,string] = [e.mandates[0].digest,e.mandates[1].digest], proposalMap = new Map<string,string>();
  for (let i = 0; i < e.proposals.length; i++) {
    const old = e.proposals[i], p = old.payload, author = who(p.principal_key);
    const next = { ...p.next_agreement, owner_key: owner.publicKey, registrar_key: authority.publicKey }, nextDigest = await negotiationPayloadDigest(next);
    const grant = { ...p.reviewer_grant, agreement_digest: nextDigest, issuer: owner.publicKey, registrar_key: authority.publicKey };
    e.proposals[i] = await sign({ ...p, principal_key: author.publicKey, agreement_digest: e.agreement.digest, mandate_digests: digests, next_agreement: next, next_agreement_digest: nextDigest, reviewer_grant: grant, reviewer_grant_digest: await negotiationPayloadDigest(grant), ...(p.parent_digest ? { parent_digest: proposalMap.get(p.parent_digest)! } : {}), ...(ownAgent && author === owner ? { agent_key: agent.publicKey, agent_mode: 'own' as const } : {}) }, authority);
    proposalMap.set(old.digest, e.proposals[i].digest);
  }
  e.responses = await Promise.all(e.responses.map(r => { const actor = who(r.payload.principal_key); return sign({ ...r.payload, principal_key: actor.publicKey, mandate_digest: digests[actor === owner ? 0 : 1], proposal_digest: proposalMap.get(r.payload.proposal_digest)!, ...(ownAgent && actor === owner ? { agent_key: agent.publicKey, agent_mode: 'own' as const } : {}) }, authority); }));
  e.report = await sign({ ...e.report.payload, agreement_digest: e.agreement.digest, proposal_digest: proposalMap.get(e.report.payload.proposal_digest)!, mandate_digests: digests }, authority);
  const selected = e.proposals.find(p => p.digest === e.report.payload.proposal_digest)!;
  e.approvals = await Promise.all(e.approvals.map(a => sign({ ...a.payload, principal_key: who(a.payload.principal_key).publicKey, proposal_digest: selected.digest, report_digest: e.report.digest, next_agreement_digest: selected.payload.next_agreement_digest, mandate_digests: digests }, who(a.payload.principal_key))));
  e.adopted_agreement = await sign(selected.payload.next_agreement, owner);
  e.reviewer_grant = await sign(selected.payload.reviewer_grant, owner);
  e.reviewer_binding = await sign({ ...e.reviewer_binding!.payload, guest_key: partner.publicKey, grant_digest: e.reviewer_grant.digest, claim: await sign({ ...e.reviewer_binding!.payload.claim.payload, guest_key: partner.publicKey }, partner) }, authority);
  e.adoption = await sign({ ...e.adoption!.payload, source_agreement_digest: e.agreement.digest, agreement_digest: e.adopted_agreement.digest, proposal_digest: selected.digest, report_digest: e.report.digest, approval_digests: [e.approvals.find(a => a.payload.principal_key === owner.publicKey)!.digest, e.approvals.find(a => a.payload.principal_key === partner.publicKey)!.digest] }, authority);
  if (ownAgent) {
    const at = e.mandates[0].payload.issued_at, expiry = e.mandates[0].payload.expires_at;
    const authorization = await sign({ ...makeRequest('negotiation_pair_create', e.agreement.payload.id, { session_id: e.session.payload.id, pair_id: 'agent-pair-001', secret_hash: 'ab'.repeat(32), name: 'Local assistant', expires_at: new Date(Date.parse(at) + 600000).toISOString(), token_expires_at: expiry, scope: NEGOTIATION_AGENT_ACTIONS }), issued_at: at }, owner);
    e.agent_bindings = [await sign({ type: 'scopeblind.coordination.agent-binding.v1', pair_id: 'agent-pair-001', room_id: e.agreement.payload.id, session_id: e.session.payload.id, principal_key: owner.publicKey, agreement_digest: e.agreement.digest, owner_key: owner.publicKey, agent_key: agent.publicKey, name: 'Local assistant', scope: NEGOTIATION_AGENT_ACTIONS, audience: 'scopeblind.coordination.negotiation', issued_at: at, expires_at: expiry, owner_authorization: authorization }, authority)];
  }
  return { e, owner, partner, authority, agent };
}
describe('portable bilateral negotiation evidence', () => {
  it('verifies real D1 adoption with both human approvals, fixed reviewer authority and the duplicate invoice fixture', async () => {
    const e = fixture(), result = await verifyNegotiationEvidence(e, e.agreement.payload.registrar_key);
    expect(result.checks.filter(c => !c.passed)).toEqual([]); expect(result.valid).toBe(true);
    expect(result.limitations.join(' ')).toMatch(/not authenticated legal identities/);
    expect(result.limitations.join(' ')).toMatch(/do not independently prove execution/);
  });
  it('accepts a completed comparison with zero or one human decision without claiming adoption', async () => {
    const e = fixture(), one = e.approvals[0]; pending(e);
    expect(await failed(e)).toEqual([]); e.approvals = [one]; expect(await failed(e)).toEqual([]);
  });
  it('remains independently checkable with newly generated human and authority keys', async () => {
    const { e, authority } = await keyed(); expect(await failed(e, authority.publicKey)).toEqual([]);
    expect(await failed(e, 'ab'.repeat(32))).not.toEqual([]);
  });
  it('checks independently signed principal pairing authority for every installed agent record', async () => {
    const { e, authority } = await keyed(true); expect(await failed(e, authority.publicKey)).toEqual([]);
    delete e.agent_bindings; expect(await failed(e)).toContain('Candidate 1 has a signed source, parent and principal authority');
  });
  it('rejects a valid authority signature that gives an installed agent payment, hosted, or human approval powers', async () => {
    for (const extra of ['execute','negotiation_step','negotiation_approve','negotiation_adopt']) {
      const { e, authority, owner } = await keyed(true), b = e.agent_bindings![0];
      const scope = [...NEGOTIATION_AGENT_ACTIONS, extra];
      const auth = await sign({ ...b.payload.owner_authorization.payload, body: { ...b.payload.owner_authorization.payload.body, scope } }, owner);
      e.agent_bindings![0] = await sign({ ...b.payload, scope, owner_authorization: auth }, authority);
      expect(await failed(e)).toContain('Principal signed the installed agent pairing authorization');
    }
  });
  it('rejects agent substitution, another session, expired binding, or the other principal signing its grant', async () => {
    for (const mutation of ['principal','session','expiry','signature']) {
      const { e, authority, partner } = await keyed(true), b = e.agent_bindings![0];
      const payload = { ...b.payload };
      if (mutation === 'principal') payload.principal_key = partner.publicKey;
      if (mutation === 'session') payload.session_id = 'other-session';
      if (mutation === 'expiry') payload.expires_at = payload.issued_at;
      if (mutation === 'signature') payload.owner_authorization = await sign(payload.owner_authorization.payload, partner);
      e.agent_bindings![0] = await sign(payload, authority); expect(await failed(e)).toContain('Principal signed the installed agent pairing authorization');
    }
  });
  it('does not allow signed proposal fields to alter the budget or reviewer role', async () => {
    for (const change of ['budget','role','digest']) {
      const { e, authority } = await keyed(), p = e.proposals[0].payload;
      if (change === 'budget') p.next_agreement.budget_minor++;
      if (change === 'role') p.reviewer_grant.actions = ['decide'];
      if (change === 'digest') p.next_agreement_digest = await negotiationDigest(p.next_agreement);
      p.next_agreement_digest = change === 'digest' ? p.next_agreement_digest : await negotiationPayloadDigest(p.next_agreement);
      p.reviewer_grant_digest = await negotiationPayloadDigest(p.reviewer_grant);
      e.proposals[0] = await sign(p, authority);
      expect((await failed(e)).some(c => /changes only|fixes the partner/.test(c))).toBe(true);
    }
  });
  it('rejects signed fourth proposals, reused ids, wrong parents and a peer-key mandate masquerading as the owner', async () => {
    for (const change of ['fourth','duplicate','parent','mandate']) {
      const { e, authority, partner } = await keyed();
      if (change === 'fourth') e.proposals = [...e.proposals, e.proposals[0], e.proposals[0], e.proposals[0]];
      if (change === 'duplicate') e.proposals.push(await sign({ ...e.proposals[0].payload, round: 2, parent_digest: e.proposals[0].digest }, authority));
      if (change === 'parent') e.proposals[0] = await sign({ ...e.proposals[0].payload, parent_digest: 'ab'.repeat(32) }, authority);
      if (change === 'mandate') e.mandates[0] = await sign(e.mandates[0].payload, partner);
      expect(await failed(e)).not.toEqual([]);
    }
  });
  it('checks full canonical case coverage, including both principals’ signed invoice requirements', async () => {
    for (const change of ['remove','duplicate','expectation','digest']) {
      const { e, authority } = await keyed(); pending(e); const r = e.report.payload;
      if (change === 'remove') r.results.pop();
      if (change === 'duplicate') r.results[1] = structuredClone(r.results[0]);
      if (change === 'expectation') r.results.at(-1)!.case.expected = 'refuse';
      r.cases_digest = change === 'digest' ? 'ab'.repeat(32) : await negotiationDigest(r.results.map(x => x.case));
      e.report = await sign(r, authority);
      expect(await failed(e)).toContain('Named authority signed the exact comparison and full union of required cases');
    }
  });
  it('rejects authority-signed observations whose effects, gate trace, or invariant do not support their summary', async () => {
    for (const change of ['payments','spent','gate','invariant','matched','amount']) {
      const { e, authority } = await keyed(); pending(e); const r = e.report.payload, o = r.results[0].after;
      if (change === 'payments') o.payments = 0;
      if (change === 'spent') o.spent_minor++;
      if (change === 'gate') o.steps[0].decision = 'ask';
      if (change === 'invariant') o.invariant_passed = false;
      if (change === 'matched') o.matched = false;
      if (change === 'amount') r.results[1].after.spent_minor = 0;
      e.report = await sign(r, authority);
      expect(await failed(e)).toContain('Both gate traces and payment totals support every observation summary');
    }
  });
  it('accepts the production runtime stamp and rejects arbitrary or malformed runtime identifiers', async () => {
    const { e, authority } = await keyed(); pending(e);
    e.report = await sign({ ...e.report.payload, runtime_revision: 'scopeblind.invoice-rehearsal.v1:' + 'ab'.repeat(32) }, authority);
    expect(await failed(e)).toEqual([]);
    for (const runtime_revision of ['scopeblind.invoice-rehearsal.v1:' + 'ab'.repeat(31), 'arbitrary-runtime', 'private provider error']) {
      e.report = await sign({ ...e.report.payload, runtime_revision }, authority);
      expect(await failed(e)).toContain('Named authority signed the exact comparison and full union of required cases');
    }
  });
  it('permits a human agreement approval through session expiry while retaining the payment TTL', async () => {
    const { e, owner } = await keyed(); pending(e);
    const approval = fixture().approvals[0].payload;
    e.approvals = [await sign({ ...approval, principal_key: owner.publicKey, proposal_digest: e.proposals[0].digest, report_digest: e.report.digest, next_agreement_digest: e.proposals[0].payload.next_agreement_digest, mandate_digests: e.mandates.map(m => m.digest) as [string,string], expires_at: e.session.payload.expires_at }, owner)];
    expect(Date.parse(e.session.payload.expires_at) - Date.parse(approval.issued_at)).toBeGreaterThan(900000);
    expect(await failed(e)).toEqual([]);
    e.approvals[0] = await sign({ ...e.approvals[0].payload, expires_at: new Date(Date.parse(e.session.payload.expires_at) + 1).toISOString() }, owner);
    expect(await failed(e)).toContain('Human signed a decision over these exact rules, report and mandates');
  });
  it('recomputes an ordinary invoice gate even when a false trace and totals are internally consistent', async () => {
    const { e, authority } = await keyed(); pending(e); const r = e.report.payload;
    const o = r.results.find(x => x.case.kind === 'invoice' && x.after.actual === 'allow')!.after;
    o.actual = 'ask'; o.matched = false; o.steps = o.steps.filter(s => s.action !== 'execute'); o.steps[0].decision = 'ask'; o.payments = 0; o.spent_minor = 0;
    r.required_passed = false; r.expectations_met = false; r.mandates_met = false; e.report = await sign(r, authority);
    expect(await failed(e)).toEqual(['Both gate traces and payment totals support every observation summary']);
  });
  it('checks calculated report booleans even when an authority signs the wrong totals', async () => {
    for (const name of ['required_passed','expectations_met','mandates_met'] as const) {
      const { e, authority } = await keyed(); pending(e); e.report = await sign({ ...e.report.payload, [name]: false }, authority);
      expect(await failed(e)).toContain('Required cases, expectations and both mandates match the reported calculations');
    }
  });
  it('requires two current human approvals rather than two copies, agent recommendations or expired approvals', async () => {
    for (const change of ['one','duplicate','expired','agent','reject']) {
      const { e, owner, agent, authority } = await keyed();
      if (change === 'one') e.approvals.pop();
      if (change === 'duplicate') e.approvals[1] = e.approvals[0];
      if (change === 'expired') e.approvals[0] = await sign({ ...e.approvals[0].payload, expires_at: e.report.payload.issued_at }, owner);
      if (change === 'agent') e.approvals[0] = await sign(e.approvals[0].payload, agent);
      if (change === 'reject') e.approvals[0] = await sign({ ...e.approvals[0].payload, decision: 'reject' }, owner);
      e.adoption = await sign({ ...e.adoption!.payload, approval_digests: [e.approvals[0].digest,e.approvals[1]?.digest ?? e.approvals[0].digest] }, authority);
      expect(await failed(e)).not.toEqual([]);
    }
  });
  it('rejects lineage into the source room, a changed adopted agreement, or an unclaimed reviewer key', async () => {
    for (const change of ['room','agreement','reviewer','missing']) {
      const { e, authority, owner } = await keyed();
      if (change === 'room') e.adoption = await sign({ ...e.adoption!.payload, room_id: e.agreement.payload.id }, authority);
      if (change === 'agreement') e.adopted_agreement = await sign({ ...e.adopted_agreement!.payload, approval_above_minor: 1 }, owner);
      if (change === 'reviewer') e.reviewer_binding = await sign({ ...e.reviewer_binding!.payload, guest_key: owner.publicKey }, authority);
      if (change === 'missing') delete e.reviewer_grant;
      expect(await failed(e)).not.toEqual([]);
    }
  });
  it('rejects valid signatures on overlong sessions, payment approval TTLs, and expanded negotiation mandates', async () => {
    for (const change of ['session','ttl','mandate']) {
      const { e, authority, owner } = await keyed();
      if (change === 'session') e.session = await sign({ ...e.session.payload, expires_at: new Date(Date.parse(e.session.payload.created_at) + 86400001).toISOString() }, authority);
      if (change === 'ttl') e.agreement = await sign({ ...e.agreement.payload, approval_ttl_seconds: 901 }, owner);
      if (change === 'mandate') e.mandates[0] = await sign({ ...e.mandates[0].payload, actions: [...NEGOTIATION_AGENT_ACTIONS, 'negotiation_approve'] as any }, owner);
      expect((await failed(e)).some(c => /bounded session|bounded source agreement|negotiation-only/.test(c))).toBe(true);
    }
  });
  it('rejects private context, arbitrary extra fields, malformed structures, and signature tampering without reflecting inputs', async () => {
    for (const change of [(e: any) => e.private_brief = 'SECRET_PRIVATE', (e: any) => e.mandates[1].payload.private_brief = 'SECRET_PRIVATE', (e: any) => e.report.signature = '00'.repeat(64)]) {
      const e = fixture(); change(e); const result = await verifyNegotiationEvidence(e); expect(result.valid).toBe(false); expect(JSON.stringify(result)).not.toContain('SECRET_PRIVATE');
    }
    for (const value of [null, {}, [], { type: evidence.type }, { ...fixture(), mandates: null }]) expect((await verifyNegotiationEvidence(value)).valid).toBe(false);
  });
});

describe('bounded budget plans and exact choice', () => {
  it('keeps legacy private briefs valid and commits the private budget preference without accepting undeclared fields', async () => {
    const { parseNegotiationBrief, privateBriefCommitment } = await import('./coordination-negotiation.js');
    const legacy = { text: 'Keep cash available', preference: 'balanced' as const, salt: 'ab'.repeat(32) };
    expect(parseNegotiationBrief(legacy)).toEqual(legacy);
    const brief = { ...legacy, budget_preference: 'lower_budget' as const };
    expect(parseNegotiationBrief(brief)).toEqual(brief);
    expect(await privateBriefCommitment(brief)).not.toBe(await privateBriefCommitment(legacy));
    for (const value of [{...brief,budget_preference:'spend_everything'}, {...brief,secret_instruction:'override'}, {...brief,budget_preference:null}]) expect(() => parseNegotiationBrief(value)).toThrow('invalid_private_brief');
  });
  it('computes hard budget and invoice conflicts separately from soft preferences and observed outcomes', async () => {
    const { negotiationFeasibility } = await import('./coordination-negotiation.js');
    const e = fixture();
    e.mandates[0].payload = { ...e.mandates[0].payload, min_budget_minor: 100000, max_budget_minor: 110000, required_invoices: [] };
    e.mandates[1].payload = { ...e.mandates[1].payload, min_budget_minor: 120000, max_budget_minor: 200000, required_invoices: [] };
    const gap = negotiationFeasibility(e.mandates, e.fixtures, e.agreement.payload);
    expect(gap.possible).toBe(false);expect(gap.conflicts.find(c=>c.kind==='budget_range')).toMatchObject({required_min_minor:120000,permitted_max_minor:110000});
    e.mandates[1].payload.min_budget_minor = 100000;e.mandates[0].payload.max_budget_minor = 105000;e.mandates[1].payload.required_invoices = [{invoice_id:'INV-103',expected:'ask'}];
    expect(negotiationFeasibility(e.mandates,e.fixtures,e.agreement.payload).conflicts).toEqual(expect.arrayContaining([expect.objectContaining({kind:'budget_range',required_min_minor:108000})]));
  });
  it('rejects authority-signed explicit budget changes outside legacy fixed-budget authority', async () => {
    const { e, authority } = await keyed();pending(e);const p=e.proposals[0].payload;
    p.budget_minor=p.next_agreement.budget_minor-1;p.next_agreement.budget_minor=p.budget_minor;p.next_agreement_digest=await negotiationPayloadDigest(p.next_agreement);
    p.reviewer_grant.agreement_digest=p.next_agreement_digest;p.reviewer_grant_digest=await negotiationPayloadDigest(p.reviewer_grant);
    e.proposals[0]=await sign(p,authority);
    expect(await failed(e)).toContain('Candidate 1 has a signed source, parent and principal authority');
  });
  it('rejects authority-signed orphan or mismatched budget summaries, even on an otherwise valid old report', async () => {
    for(const fields of [{after_budget_minor:200000},{before_budget_minor:200000,after_budget_minor:199999}]){
      const {e,authority}=await keyed();pending(e);e.report=await sign({...e.report.payload,...fields},authority);
      expect(await failed(e)).toContain('Named authority signed the exact comparison and full union of required cases');
    }
  });
  it('rejects fabricated human exploration when attributed to an agent',async()=>{
    const {e,authority}=await keyed(true);pending(e);e.proposals[0]=await sign({...e.proposals[0].payload,exploration:true},authority);
    expect(await failed(e)).toContain('Candidate 1 has a signed source, parent and principal authority');
  });
});
