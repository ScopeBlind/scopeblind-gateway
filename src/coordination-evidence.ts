import {verifyHuman,humanPrincipal} from './coordination-devices';
import { verifyNegotiationEvidence } from './coordination-negotiation';
import { verify, payloadHash, canonical, invoiceMatchesPurchaseOrder, type EvidenceBundle, type RoomView, type Signed, type Approval, type Acceptance, type GrantView, type Agreement } from './coordination-protocol';

export async function verifyOwnerAgreement(agreement:Signed<Agreement>,negotiation?:import('./coordination-negotiation').NegotiationExport,depth=0):Promise<boolean>{
  try{if(!agreement.authorization)return await verifyHuman(agreement,agreement.payload.owner_key);
    if(depth>4||!negotiation?.adoption||!negotiation.adopted_agreement||canonical(negotiation.adopted_agreement)!==canonical(agreement)||negotiation.adoption.payload.room_id!==agreement.payload.id)return false;
    return (await verifyNegotiationEvidence(negotiation,agreement.payload.registrar_key,depth)).valid;
  }catch{return false;}
}

export interface EvidenceCheck {
  valid: boolean; checks: Array<{ label: string; ok: boolean }>; errors: string[];
  accepted: boolean; authorityPinned: boolean; limitations: string[];
}
export function evidenceFromRoom(room: RoomView): EvidenceBundle {
  if (!room.manifest) throw new Error('Finalize this run before exporting its evidence.');
  return { type: 'scopeblind.coordination.evidence.v1', agreement: room.agreement, grants: room.grants,
    manifest: room.manifest, acceptances: room.acceptances, acceptance_records: room.acceptance_records ?? [], prior_attempts: room.attempts ?? [], ...(room.negotiation_evidence ? {negotiation:room.negotiation_evidence} : {}) };
}
const integer = (n: unknown): n is number => Number.isSafeInteger(n) && Number(n) >= 0;
const timestamp = (s: string): number => typeof s === 'string' ? Date.parse(s) : NaN;

/** Offline integrity + relationship checks. No network calls or implicit identity trust. */
export async function verifyEvidence(value: unknown, expectedAuthority?: string): Promise<EvidenceCheck> {
  const checks: EvidenceCheck['checks'] = [];
  const check = (label: string, ok: unknown) => { checks.push({ label, ok: ok === true }); };
  let accepted = false;
  try {
    const b = value as EvidenceBundle;
    if (!b || b.type !== 'scopeblind.coordination.evidence.v1' || !Array.isArray(b.grants) || !Array.isArray(b.acceptances)) throw new Error('Unrecognized coordination evidence.');
    const a = b.agreement.payload, m = b.manifest.payload, authority = a.registrar_key;
    check('Agreement signed by its author', a.type === 'scopeblind.coordination.agreement.v1' && await verifyOwnerAgreement(b.agreement,b.negotiation));
    check('Agreement parameters are supported', a.version === 1 && (a.mode===undefined || a.mode==='guided' || a.mode==='live') && a.currency === 'USD' && integer(a.budget_minor) && integer(a.approval_above_minor) && integer(a.approval_ttl_seconds) && a.approval_ttl_seconds > 0 && Array.isArray(a.allowed_destinations) && a.allowed_destinations.every(x => typeof x === 'string') && Number.isFinite(timestamp(a.issued_at)));
    if (expectedAuthority) check('Authority matches the independently supplied key', authority === expectedAuthority);
    if(b.negotiation){
      const negotiated=await verifyNegotiationEvidence(b.negotiation,expectedAuthority);
      check('Two-person agreement history is intact',negotiated.valid && !!b.negotiation.adoption && b.negotiation.adopted_agreement?.digest===b.agreement.digest && b.negotiation.adoption.payload.room_id===a.id);
    }
    check('Finalized manifest signed by the agreed authority', m.type === 'scopeblind.coordination.manifest.v1' && await verify(b.manifest, authority));
    check('Manifest binds this agreement and run', m.room_id === a.id && m.agreement_digest === b.agreement.digest && typeof m.run_id === 'string' && m.run_id.length > 0 && Number.isFinite(timestamp(m.finalized_at)) && timestamp(m.finalized_at) >= timestamp(a.issued_at));
    if (!Array.isArray(m.operations) || m.operations.length > 500 || b.grants.length > 100 || b.acceptances.length > 100) throw new Error('Evidence exceeds supported bounds.');
    check('Result explanation is bounded text',m.summary===undefined || typeof m.summary==='string' && m.summary.length<=600);
    const prior=b.prior_attempts??[];
    if(!Array.isArray(prior) || prior.length>9)throw new Error('Too many prior attempts.');
    const history=m.historical_operations??[];
    check('Revision lineage is complete', prior.length>0 ? m.previous_manifest_digest===prior.at(-1)!.manifest.digest : !m.previous_manifest_digest && history.length===0);
    const priorRuns=new Set<string>();
    for(let index=0;index<prior.length;index++) {
      const attempt=prior[index],link=attempt.revision.payload;
      check(`Prior attempt ${index+1} · no unresolved authority released by revision`,attempt.manifest.payload.budget.reserved_minor===0 && attempt.manifest.payload.operations.every(op=>!['held','request_changes','admitted','unknown'].includes(op.status)));
      // The preceding attempt verifies its own ancestors once, keeping work bounded.
      if(index===prior.length-1) {
        const checked=await verifyEvidence({...b,manifest:attempt.manifest,acceptances:attempt.acceptances,acceptance_records:attempt.acceptance_records,prior_attempts:prior.slice(0,index)},expectedAuthority);
        check(`Prior attempt ${index+1} · signatures and accounting`,checked.valid);
      }
      check(`Prior attempt ${index+1} · authorized continuation`,await verify(attempt.revision,authority) && link.type==='scopeblind.coordination.revision.v1'
        && link.room_id===a.id && link.previous_run_id===attempt.manifest.payload.run_id && link.run_id===(prior[index+1]?.manifest.payload.run_id??m.run_id)
        && link.previous_manifest_digest===attempt.manifest.digest && link.agreement_digest===b.agreement.digest && link.requested_by===a.owner_key
        && !priorRuns.has(link.previous_run_id) && link.previous_run_id!==m.run_id && timestamp(link.issued_at)>=timestamp(attempt.manifest.payload.finalized_at));
      priorRuns.add(link.previous_run_id);
    }
    const expectedHistory=prior.flatMap(attempt=>attempt.manifest.payload.operations.filter(op=>op.status==='confirmed'));
    check('Earlier payments are preserved exactly once',canonical([...history].sort((x,y)=>x.operation_id.localeCompare(y.operation_id)))===canonical(expectedHistory.sort((x,y)=>x.operation_id.localeCompare(y.operation_id))));
    if(prior.length && m.fixtures)check('Invoice records remain unchanged across attempts',prior.every(attempt=>attempt.manifest.payload.fixtures?canonical(attempt.manifest.payload.fixtures)===canonical(m.fixtures):a.mode!=='live'));
    if(a.mode==='live')check('Live agreement requires matching frozen purchase-order records',a.require_po_match===true && !!m.fixtures && integer(m.fixtures.revision) && m.fixtures.revision>0 && Array.isArray(m.fixtures.invoices) && Array.isArray(m.fixtures.purchase_orders));
    const proposal=b.negotiation?.proposals.find(p=>p.digest===b.negotiation?.adoption?.payload.proposal_digest);
    const deviceContext=(principal:string)=>({proposal,approval:b.negotiation?.approvals.find(v=>v.payload.principal_key===principal),requireRecordedUse:true,authorityKey:authority});
    const grants = new Map<string, GrantView>();
    for (const v of b.grants) {
      const g = v.grant.payload;
      let ok = !grants.has(g.grant_id) && g.type === 'scopeblind.coordination.grant.v1' && await verifyHuman(v.grant,a.owner_key,deviceContext(a.owner_key))
        && g.issuer === a.owner_key && g.registrar_key === authority && g.room_id === a.id && g.agreement_digest === b.agreement.digest
        && g.role === 'reviewer' && g.max_claims === 1 && Array.isArray(g.actions) && g.actions.every(x => ['decide', 'accept'].includes(x)) && Number.isFinite(timestamp(g.expires_at));
      if (v.binding) {
        const p = v.binding.payload, c = p.claim.payload;
        ok = ok && p.type === 'scopeblind.coordination.binding.v1' && await verify(v.binding, authority)
          && p.grant_id === g.grant_id && p.grant_digest === v.grant.digest && p.room_id === a.id
          && p.expires_at === g.expires_at && timestamp(p.issued_at) < timestamp(g.expires_at)
          && c.type === 'scopeblind.coordination.claim.v1' && await verifyHuman(p.claim,p.guest_key,deviceContext(p.guest_key))
          && c.guest_key === p.guest_key && c.grant_id === g.grant_id && c.room_id === a.id && c.name === p.name;
      }
      check(`Invitation and guest key binding · ${g.grant_id}`, ok);
      grants.set(g.grant_id, v);
    }
    async function reviewer(s: Signed<Approval | Acceptance>, action: 'decide' | 'accept'): Promise<boolean> {
      const p = s.payload, v = grants.get(p.grant_id), binding = v?.binding?.payload;
      return !!v && !!binding && v.grant.payload.actions.includes(action) && await verifyHuman(s,binding.guest_key,{requireRecordedUse:true,authorityKey:authority})
        && p.room_id === a.id && p.run_id === m.run_id && p.agreement_digest === b.agreement.digest
        && timestamp(p.issued_at) >= timestamp(binding.issued_at) - 300_000 && timestamp(p.issued_at) < timestamp(binding.expires_at);
    }
    const ids = new Set<string>(), paidInvoices = new Set<string>();
    let spent = 0, reserved = 0;
    for(const op of history) {
      const businessKey=op.input.invoice_id;
      check(`Earlier payment ${op.operation_id} · unique invoice`,!paidInvoices.has(businessKey) && !ids.has(op.operation_id));
      paidInvoices.add(businessKey);ids.add(op.operation_id);spent+=op.input.amount_minor;
    }
    for (const op of m.operations) {
      const label = `Operation ${op.operation_id}`;
      const hash = await payloadHash(op.input);
      check(`${label} · exact input and unique identity`, op.tool === 'ledger.pay' && op.run_id === m.run_id && typeof op.operation_id === 'string' && !ids.has(op.operation_id) && hash === op.payload_hash && integer(op.input.amount_minor) && op.input.amount_minor > 0 && op.input.currency === a.currency && typeof op.input.invoice_id === 'string');
      ids.add(op.operation_id);
      if (op.admission) {
        const p = op.admission.payload;
        check(`${label} · signed gate decision`, p.type === 'scopeblind.coordination.admission.v1' && await verify(op.admission, authority)
          && p.room_id === a.id && p.run_id === m.run_id && p.operation_id === op.operation_id && p.agreement_digest === b.agreement.digest && p.payload_hash === hash
          && await payloadHash(p.input) === hash && p.destination === op.input.destination && ['admitted', 'held', 'refused'].includes(p.decision));
      }
      if (op.decision) {
        const p = op.decision.payload;
        check(`${label} · recipient decision binds exact input`, p.type === 'scopeblind.coordination.approval.v1' && await reviewer(op.decision, 'decide') && p.operation_id === op.operation_id && p.payload_hash === hash && ['approve','deny','request_changes'].includes(p.decision) && timestamp(p.expires_at) > timestamp(p.issued_at) && timestamp(p.expires_at) - timestamp(p.issued_at) <= a.approval_ttl_seconds * 1000);
      }
      const invoice=m.fixtures?.invoices.find(i=>i.invoice_id===op.input.invoice_id);
      const needsApproval=op.input.amount_minor>a.approval_above_minor || (a.require_po_match===true && (!invoice || !m.fixtures || !invoiceMatchesPurchaseOrder(invoice,m.fixtures)));
      if (['admitted','confirmed','unknown'].includes(op.status)) {
        if(a.mode==='live')check(`${label} · frozen invoice input`,!!invoice && op.input.fixture_revision===m.fixtures?.revision && op.input.amount_minor===invoice.amount_minor && op.input.destination===invoice.destination);
        const p = op.admission?.payload;
        check(`${label} · authorized destination and admission`, p?.decision === 'admitted' && a.allowed_destinations.includes(op.input.destination));
        if (needsApproval) {
          const d = op.decision?.payload;
          check(`${label} · fresh approval at admission`, !!d && d.decision === 'approve' && !!p && timestamp(d.issued_at) <= timestamp(p.issued_at) + 60_000 && timestamp(d.expires_at) > timestamp(p.issued_at));
        }
        const businessKey = op.input.invoice_id;
        check(`${label} · invoice paid or reserved once`, !paidInvoices.has(businessKey)); paidInvoices.add(businessKey);
      }
      if (op.receipt) {
        const p = op.receipt.payload;
        check(`${label} · signed outcome binds exact input`, p.type === 'scopeblind.coordination.outcome.v1' && await verify(op.receipt, authority)
          && p.room_id === a.id && p.run_id === m.run_id && p.operation_id === op.operation_id && p.payload_hash === hash
          && p.amount_minor === op.input.amount_minor && p.destination === op.input.destination && p.status === op.status);
      }
      if (op.status === 'confirmed') {
        check(`${label} · sandbox destination confirmation`, op.receipt?.payload.status === 'confirmed' && op.receipt.payload.observed_by === 'sandbox-ledger' && !!op.receipt.payload.transaction_id);
        const gate = op.admission?.payload, effectAt = timestamp(op.receipt!.payload.issued_at);
        check(`${label} · effect within admission validity`, !!gate && effectAt >= timestamp(gate.issued_at) && effectAt < timestamp(gate.expires_at));
        if (needsApproval) check(`${label} · approval still fresh at effect`, !!op.decision && effectAt < timestamp(op.decision.payload.expires_at));
        spent += op.input.amount_minor;
      } else if (op.status === 'admitted' || op.status === 'unknown') reserved += op.input.amount_minor;
      else check(`${label} · recognized final state`, ['held','refused','declined','request_changes','superseded','failed'].includes(op.status));
    }
    const budget = m.budget;
    check('Budget reconciles with signed outcomes and reservations', integer(budget.limit_minor) && integer(budget.spent_minor) && integer(budget.reserved_minor) && integer(budget.remaining_minor)
      && budget.limit_minor === a.budget_minor && budget.spent_minor === spent && budget.reserved_minor === reserved && budget.limit_minor === spent + reserved + budget.remaining_minor);
    const records = b.acceptance_records ?? [];
    const acceptanceIds = new Set<string>();
    for (const s of b.acceptances) {
      const p = s.payload;
      const ok = !acceptanceIds.has(s.digest) && p.type === 'scopeblind.coordination.acceptance.v1' && await reviewer(s, 'accept') && p.manifest_digest === b.manifest.digest && ['accept','request_changes'].includes(p.decision) && timestamp(p.issued_at) >= timestamp(m.finalized_at) - 300_000;
      acceptanceIds.add(s.digest);
      check('Recipient decision signs this finalized manifest', ok);
      const record = records.find(r => r.payload.acceptance_digest === s.digest);
      check('Authority recorded recipient authority at acceptance', !!record && record.payload.type === 'scopeblind.coordination.acceptance-record.v1' && await verify(record, authority)
        && record.payload.room_id === a.id && record.payload.run_id === m.run_id && record.payload.manifest_digest === b.manifest.digest && record.payload.reviewer_key === humanPrincipal(s)
        && timestamp(record.payload.recorded_at) >= timestamp(m.finalized_at));
    }
    check('Acceptance records refer only to supplied decisions', records.length === b.acceptances.length && records.every(r => acceptanceIds.has(r.payload.acceptance_digest)));
    const recordedAt = new Map(records.map(r => [r.payload.acceptance_digest, timestamp(r.payload.recorded_at)]));
    accepted = b.acceptances.length > 0 && [...b.acceptances].sort((x,y) => (recordedAt.get(x.digest) ?? 0) - (recordedAt.get(y.digest) ?? 0)).at(-1)?.payload.decision === 'accept';
  } catch (e) { check(e instanceof Error ? e.message : 'Malformed evidence', false); }
  const errors = checks.filter(x => !x.ok).map(x => x.label);
  return { valid: errors.length === 0, checks, errors, accepted: accepted && errors.length === 0, authorityPinned: !!expectedAuthority && errors.length === 0,
    limitations: ['Signatures bind these records to keys; they do not establish a person’s legal identity.',
      'The authority attests to gate state, enrollment, and the sandbox ledger. These records do not prove real payments, agent reasoning, or activity outside this gate.',
      'The manifest binds the included operations. An offline file cannot establish that an operator disclosed every run or that access is still active.',
      ...(!expectedAuthority ? ['No independent authority key was supplied. Integrity was checked against the authority named in the signed agreement.'] : [])] };
}
