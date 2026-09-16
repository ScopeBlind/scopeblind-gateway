import {describe,it,expect} from 'vitest';
import {defaultAgreement,defaultFixtures,generateIdentity,makeRequest,sign} from './coordination-protocol';
import {defaultRehearsalCases,parseRehearsalCase,parseRepairProposal,rehearsalDigest,verifyRehearsalEvidence,type RehearsalAdoption,type RehearsalExport,type RehearsalReport,type RepairProposal} from './coordination-rehearsal';

async function fixture(){
  const owner=await generateIdentity(),authority=await generateIdentity(),fixtures=defaultFixtures();
  const agreement=await sign(defaultAgreement('rehearsal-source',owner.publicKey,authority.publicKey),owner);
  const cases=[...defaultRehearsalCases(fixtures),{id:'expect-review',title:'Review the $480 invoice',kind:'invoice' as const,invoice_id:'INV-102',expected:'ask' as const,requirement:'Ask above $400.'}];
  const fixture_digest=await rehearsalDigest(fixtures),cases_digest=await rehearsalDigest(cases);
  const proposal=await sign<RepairProposal>({type:'scopeblind.coordination.repair-proposal.v1',id:'repair-four-hundred',room_id:agreement.payload.id,author_key:owner.publicKey,agreement_digest:agreement.digest,fixture_digest,cases_digest,previous_approval_above_minor:50000,approval_above_minor:40000,rationale:'Match the collaborator’s approval expectation.',issued_at:new Date().toISOString()},authority);
  const report=await sign<RehearsalReport>({type:'scopeblind.coordination.rehearsal-report.v1',id:'comparison-test',room_id:agreement.payload.id,agreement_digest:agreement.digest,fixture_digest,cases_digest,proposal_digest:proposal.digest,runtime_revision:'test-gate-version',adapter:'coordination-d1-sandbox',isolation:'separate-fixture-ledgers',issued_at:new Date().toISOString(),before_approval_above_minor:50000,after_approval_above_minor:40000,required_passed:true,expectations_met:true,
    results:cases.map(c=>({case:c,before:{actual:'allow',matched:c.expected==='invariant',reason:'Recorded fixture result.',steps:[{action:'admit',decision:'allow',reason:'Recorded gate admission.'}],payments:1,spent_minor:32000,...(c.expected==='invariant'?{invariant_passed:true}:{})},after:{actual:c.expected==='invariant'?'allow':'ask',matched:true,reason:'Recorded fixture result.',steps:[{action:'admit',decision:c.expected==='invariant'?'allow':'ask',reason:'Recorded gate admission.'}],payments:c.expected==='invariant'?1:0,spent_minor:c.expected==='invariant'?32000:0,...(c.expected==='invariant'?{invariant_passed:true}:{})}}))},authority);
  return {authority,owner,bundle:{type:'scopeblind.coordination.rehearsal-evidence.v1',agreement,fixtures,cases,proposal,report} as RehearsalExport};
}
describe('portable rehearsal evidence',()=>{
  it('checks an exact comparison offline without claiming independent execution observation',async()=>{
    const {bundle,authority}=await fixture();const result=await verifyRehearsalEvidence(bundle,authority.publicKey);
    expect(result.errors).toEqual([]);expect(result.valid).toBe(true);expect(result.limitations.join(' ')).toContain('not independent observation');
    expect(bundle.report.payload.results.at(-1)?.before.matched).toBe(false);
  });
  it('rejects changed inputs, missing cases, changed expectations and wrong authority',async()=>{
    const {bundle}=await fixture();
    for(const mutate of [
      (b:RehearsalExport)=>{b.fixtures.invoices[0].amount_minor++;},
      (b:RehearsalExport)=>{b.cases.pop();},
      (b:RehearsalExport)=>{b.cases.at(-1)!.expected='allow';},
      (b:RehearsalExport)=>{b.report.payload.results.at(-1)!.before.actual='ask';},
      (b:RehearsalExport)=>{b.proposal!.payload.approval_above_minor=60000;},
    ]){const altered=structuredClone(bundle);mutate(altered);expect((await verifyRehearsalEvidence(altered)).valid).toBe(false);}
    expect((await verifyRehearsalEvidence(bundle,(await generateIdentity()).publicKey)).valid).toBe(false);
  });
  it('rejects internally inconsistent signed summaries and missing mandatory protections',async()=>{
    const {bundle,authority}=await fixture();
    const inconsistent=structuredClone(bundle);inconsistent.report=await sign({...bundle.report.payload,expectations_met:false},authority);
    expect((await verifyRehearsalEvidence(inconsistent)).valid).toBe(false);
    const missing=structuredClone(bundle);missing.cases.splice(0,1);
    const cases_digest=await rehearsalDigest(missing.cases);
    missing.proposal=await sign({...bundle.proposal!.payload,cases_digest},authority);
    missing.report=await sign({...bundle.report.payload,cases_digest,proposal_digest:missing.proposal.digest,results:bundle.report.payload.results.slice(1)},authority);
    expect((await verifyRehearsalEvidence(missing)).errors).toContain('Required safety cases remain included');
  });
  it('rejects malformed and non-finite artifacts without throwing',async()=>{
    for(const value of [null,{},[],{type:'scopeblind.coordination.rehearsal-evidence.v1',report:{payload:{results:[]}}}])expect((await verifyRehearsalEvidence(value as RehearsalExport)).valid).toBe(false);
  });
  it('requires the owner’s exact signature for adoption, not only an operator assertion',async()=>{
    const {bundle,authority,owner}=await fixture();
    const next=await sign({...bundle.agreement.payload,id:'future-sample-room',issued_at:new Date().toISOString(),approval_above_minor:40000},owner);
    const authorization=await sign(makeRequest('rehearsal_adopt',bundle.agreement.payload.id,{report_digest:bundle.report.digest,proposal_id:bundle.proposal!.payload.id,agreement:next}),owner);
    const adoption=await sign<RehearsalAdoption>({type:'scopeblind.coordination.rehearsal-adoption.v1',source_room_id:bundle.agreement.payload.id,room_id:next.payload.id,source_agreement_digest:bundle.agreement.digest,agreement_digest:next.digest,report_digest:bundle.report.digest,proposal_digest:bundle.proposal!.digest,fixture_digest:bundle.report.payload.fixture_digest,cases_digest:bundle.report.payload.cases_digest,owner_key:owner.publicKey,authorization_digest:authorization.digest,issued_at:new Date().toISOString(),scope:'new-separate-sample-task'},authority);
    const adopted={...bundle,adoption,adoption_authorization:authorization,adopted_agreement:next};
    expect((await verifyRehearsalEvidence(adopted,authority.publicKey)).errors).toEqual([]);
    expect((await verifyRehearsalEvidence({...adopted,adoption_authorization:undefined})).valid).toBe(false);
    const impostor=await sign(authorization.payload,authority);
    const forged=await sign({...adoption.payload,authorization_digest:impostor.digest},authority);
    expect((await verifyRehearsalEvidence({...adopted,adoption:forged,adoption_authorization:impostor})).valid).toBe(false);
    const larger=await sign({...next.payload,budget_minor:300000},owner);
    const broader=await sign(makeRequest('rehearsal_adopt',bundle.agreement.payload.id,{report_digest:bundle.report.digest,proposal_id:bundle.proposal!.payload.id,agreement:larger}),owner);
    const misleading=await sign({...adoption.payload,agreement_digest:larger.digest,authorization_digest:broader.digest},authority);
    expect((await verifyRehearsalEvidence({...adopted,adoption:misleading,adoption_authorization:broader,adopted_agreement:larger})).errors).toContain('Only the tested threshold changed in the new task');
  });
});
describe('bounded shared proposal input',()=>{
  it('does not accept hidden authority changes or imprecise amounts',()=>{
    const c={id:'case-1',title:'Review invoice',kind:'invoice',invoice_id:'INV-102',expected:'ask',requirement:'Ask before paying.'};
    expect(parseRehearsalCase(c)).toEqual(c);
    for(const patch of [{amount_minor:1.5},{amount_minor:NaN},{amount_minor:0},{expected:'invariant'},{approve:true},{title:'x'.repeat(121)}])expect(()=>parseRehearsalCase({...c,...patch})).toThrow();
    for(const kind of ['changed_approval','expired_approval','budget_cap'])expect(()=>parseRehearsalCase({...c,kind,expected:'invariant',amount_minor:48000})).toThrow('rehearsal_amount_not_supported');
    for(const patch of [{budget_minor:999999},{approval_above_minor:200001},{approval_above_minor:-1},{approval_above_minor:1.5},{rationale:''}])expect(()=>parseRepairProposal({id:'change-1',approval_above_minor:40000,rationale:'Review more invoices',...patch},200000)).toThrow();
  });
});
