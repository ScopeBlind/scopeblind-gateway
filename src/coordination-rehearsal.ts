import {verifyOwnerAgreement} from './coordination-evidence';
/** Shared rehearsal contracts. Reports describe observed gate runs, never model predictions. */
import { canonical, sha256, verify, type Agreement, type InvoiceFixtures, type RpcRequest, type Signed } from './coordination-protocol';

export const REHEARSAL_REVISION = 'scopeblind.invoice-rehearsal.v1';
export const REHEARSAL_ACTIONS = ['rehearsal_get','rehearsal_case','rehearsal_run','rehearsal_propose'] as const;
export type RehearsalAction = typeof REHEARSAL_ACTIONS[number];
export type RehearsalKind = 'invoice' | 'approved_invoice' | 'duplicate_invoice' | 'changed_approval' | 'changed_destination' | 'expired_approval' | 'budget_cap';
export type RehearsalOutcome = 'allow' | 'ask' | 'refuse';
export interface RehearsalCase {
  id: string; title: string; kind: RehearsalKind; invoice_id: string;
  /** Invoice AND matching PO override inside the rehearsal; unavailable for controlled approval/budget boundary probes. */
  amount_minor?: number;
  expected: RehearsalOutcome | 'invariant'; requirement: string;
  /** Reserved for shipped safety cases; callers cannot assign or remove it. */
  required?: boolean;
}
export interface RehearsalGrant {
  type: 'scopeblind.coordination.rehearsal-grant.v1'; grant_id: string; room_id: string;
  agreement_digest: string; issuer: string; registrar_key: string; role: 'challenger';
  actions: RehearsalAction[]; expires_at: string; token_hash: string; max_claims: 1;
}
export interface RehearsalClaim {
  type: 'scopeblind.coordination.rehearsal-claim.v1'; grant_id: string; room_id: string;
  guest_key: string; name: string; issued_at: string; nonce: string;
}
export interface RehearsalBinding {
  type: 'scopeblind.coordination.rehearsal-binding.v1'; grant_id: string; grant_digest: string;
  room_id: string; guest_key: string; name: string; issued_at: string; expires_at: string;
  claim: Signed<RehearsalClaim>;
}
export interface RehearsalGrantView { grant: Signed<RehearsalGrant>; binding?: Signed<RehearsalBinding>; revoked: boolean }
export interface RepairProposalInput { id: string; approval_above_minor: number; rationale: string }
export interface RepairProposal extends RepairProposalInput {
  type: 'scopeblind.coordination.repair-proposal.v1'; room_id: string; author_key: string;
  agreement_digest: string; fixture_digest: string; cases_digest: string;
  previous_approval_above_minor: number; issued_at: string;
}
export interface RehearsalStep {
  action: string; decision: RehearsalOutcome | 'confirmed' | 'rejected'; reason: string;
  operation_id?: string; payload_hash?: string;
}
export interface RehearsalObservation {
  actual: RehearsalOutcome | 'error'; matched: boolean; reason: string;
  steps: RehearsalStep[]; payments: number; spent_minor: number;
  /** Used only for an invariant case, based on actual effects and admissions. */
  invariant_passed?: boolean;
}
export interface RehearsalCaseResult { case: RehearsalCase; before: RehearsalObservation; after?: RehearsalObservation }
export interface RehearsalReport {
  type: 'scopeblind.coordination.rehearsal-report.v1'; id: string; room_id: string;
  agreement_digest: string; fixture_digest: string; cases_digest: string; proposal_digest?: string;
  runtime_revision: string; adapter: 'coordination-d1-sandbox'; issued_at: string;
  isolation: 'separate-fixture-ledgers'; results: RehearsalCaseResult[];
  required_passed: boolean; expectations_met: boolean;
  before_approval_above_minor: number; after_approval_above_minor?: number;
}
export interface RehearsalAdoption {
  type: 'scopeblind.coordination.rehearsal-adoption.v1'; source_room_id: string; room_id: string;
  source_agreement_digest: string; agreement_digest: string; report_digest: string; proposal_digest: string;
  fixture_digest: string; cases_digest: string; owner_key: string; issued_at: string;
  authorization_digest: string;
  scope: 'new-separate-sample-task';
}
export interface RehearsalState {
  agreement_digest: string; fixture_digest: string; cases_digest: string;
  cases: RehearsalCase[]; proposals: Signed<RepairProposal>[]; reports: Signed<RehearsalReport>[];
  excluded_cases?: RehearsalCase[];
  runs?: RehearsalRunView[];
  grants: RehearsalGrantView[]; adoptions: Signed<RehearsalAdoption>[];
  can_propose: boolean; can_adopt: boolean;
}
export interface RehearsalRunView {
  id:string;status:'running'|'completed'|'failed';created_at:string;expires_at:string;
  proposal_id?:string;error?:string;completed_cases:number;total_cases:number;
}
export interface RehearsalExport {
  type: 'scopeblind.coordination.rehearsal-evidence.v1'; agreement: Signed<Agreement>;
  source_negotiation?: import('./coordination-negotiation').NegotiationExport;
  fixtures: InvoiceFixtures; cases: RehearsalCase[]; proposal?: Signed<RepairProposal>;
  report: Signed<RehearsalReport>; adoption?: Signed<RehearsalAdoption>;
  adoption_authorization?: Signed<RpcRequest>; adopted_agreement?: Signed<Agreement>;
}
export interface RehearsalDraft {
  original: string; case: RehearsalCase | null; suggested_threshold_minor: number | null;
  assumptions: string[]; unsupported: string[];
}
const kinds = new Set<RehearsalKind>(['invoice','approved_invoice','duplicate_invoice','changed_approval','changed_destination','expired_approval','budget_cap']);
const outcomes = new Set(['allow','ask','refuse','invariant']);
export function parseRehearsalCase(value: unknown): RehearsalCase {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid_rehearsal_case');
  const v = value as Record<string, unknown>;
  if (Object.keys(v).some(k => !['id','title','kind','invoice_id','amount_minor','expected','requirement','required'].includes(k))
    || typeof v.id !== 'string' || !/^[A-Za-z0-9_-]{1,80}$/.test(v.id)
    || typeof v.title !== 'string' || !v.title.trim() || v.title.length > 120
    || typeof v.kind !== 'string' || !kinds.has(v.kind as RehearsalKind)
    || typeof v.invoice_id !== 'string' || !/^[A-Za-z0-9_-]{1,60}$/.test(v.invoice_id)
    || typeof v.expected !== 'string' || !outcomes.has(v.expected)
    || typeof v.requirement !== 'string' || !v.requirement.trim() || v.requirement.length > 400
    || (v.amount_minor !== undefined && (!Number.isSafeInteger(v.amount_minor) || Number(v.amount_minor) < 1 || Number(v.amount_minor) > 10000000))
    || (v.required !== undefined && typeof v.required !== 'boolean')) throw new Error('invalid_rehearsal_case');
  if ((v.kind === 'invoice') === (v.expected === 'invariant')) throw new Error('invalid_rehearsal_expectation');
  if (v.amount_minor !== undefined && ['changed_approval','expired_approval','budget_cap'].includes(v.kind)) throw new Error('rehearsal_amount_not_supported');
  return {id:v.id,title:v.title.trim(),kind:v.kind as RehearsalKind,invoice_id:v.invoice_id,
    ...(v.amount_minor !== undefined ? {amount_minor:Number(v.amount_minor)} : {}),expected:v.expected as RehearsalCase['expected'],
    requirement:v.requirement.trim(),...(v.required !== undefined ? {required:v.required} : {})};
}
export function parseRepairProposal(value: unknown, budget: number): RepairProposalInput {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid_repair_proposal');
  const v = value as Record<string,unknown>;
  if (Object.keys(v).some(k => !['id','approval_above_minor','rationale'].includes(k)) || typeof v.id !== 'string' || !/^[A-Za-z0-9_-]{1,80}$/.test(v.id)
    || !Number.isSafeInteger(v.approval_above_minor) || Number(v.approval_above_minor) < 0 || Number(v.approval_above_minor) > budget
    || typeof v.rationale !== 'string' || !v.rationale.trim() || v.rationale.length > 600) throw new Error('invalid_repair_proposal');
  return {id:v.id,approval_above_minor:Number(v.approval_above_minor),rationale:v.rationale.trim()};
}
/** Fixed safety cases are always included; a new user expectation cannot replace one. */
export function defaultRehearsalCases(fixtures: InvoiceFixtures): RehearsalCase[] {
  const invoice = fixtures.invoices.find(i => !i.duplicate_of)!;
  const make = (id:string,title:string,kind:RehearsalKind,requirement:string):RehearsalCase => ({id:`required-${id}`,title,kind,invoice_id:invoice.invoice_id,expected:'invariant',requirement,required:true});
  return [
    make('valid','A legitimate payment can complete','approved_invoice','An exact, authorized invoice can be paid once. Required review must not prevent approved work from completing.'),
    make('duplicate','Submit the same invoice twice','duplicate_invoice','A second operation for an already-paid invoice must not create another payment.'),
    make('changed','Change the amount after approval','changed_approval','Approval for one exact request must not authorize a changed amount.'),
    make('destination','Change the payment destination','changed_destination','A payment to a destination outside the approved vendor record must be refused.'),
    make('expired','Use an expired approval','expired_approval','An expired exact approval cannot authorize a payment that needs review.'),
    make('budget','Go over the total budget','budget_cap','The aggregate budget cannot be exceeded, even with separate operations and exact approvals.'),
  ];
}
export async function rehearsalDigest(value: unknown): Promise<string> { return sha256(canonical(value)); }

export interface RehearsalVerification { valid:boolean; checks:Array<{label:string;ok:boolean}>; errors:string[]; limitations:string[] }
/** Offline consistency/identity checks. Execution truth still relies on the named gate operator. */
export async function verifyRehearsalEvidence(bundle: RehearsalExport, pin?: string): Promise<RehearsalVerification> {
  const checks:Array<{label:string;ok:boolean}>=[];
  const add=(label:string,ok:unknown)=>checks.push({label,ok:!!ok});
  try {
    add('Recognized rehearsal evidence',bundle.type==='scopeblind.coordination.rehearsal-evidence.v1');
    const a=bundle.agreement.payload,r=bundle.report.payload;
    add('Bounded invoice agreement and case set',a.type==='scopeblind.coordination.agreement.v1'&&a.currency==='USD'&&Number.isSafeInteger(a.budget_minor)&&a.budget_minor>0&&a.budget_minor<=10000000
      &&Number.isSafeInteger(a.approval_above_minor)&&a.approval_above_minor>=0&&a.approval_above_minor<=a.budget_minor
      &&Array.isArray(bundle.cases)&&bundle.cases.length>=6&&bundle.cases.length<=30&&new Set(bundle.cases.map(c=>c.id)).size===bundle.cases.length
      &&bundle.cases.every(c=>canonical(parseRehearsalCase(c))===canonical(c)));
    add('Owner signed the source agreement',await verifyOwnerAgreement(bundle.agreement,bundle.source_negotiation)&&(bundle.agreement.authorization?!!bundle.source_negotiation:bundle.source_negotiation===undefined));
    add('Named authority signed the report',await verify(bundle.report,pin||a.registrar_key));
    add('Report authority matches the agreement',bundle.report.signer===a.registrar_key);
    add('Report binds this agreement and room',r.type==='scopeblind.coordination.rehearsal-report.v1'&&r.agreement_digest===bundle.agreement.digest&&r.room_id===a.id);
    add('Exact source fixtures and included cases are present',r.fixture_digest===await rehearsalDigest(bundle.fixtures)&&r.cases_digest===await rehearsalDigest(bundle.cases));
    add('Report includes each case exactly once',r.results.length===bundle.cases.length&&canonical(r.results.map(x=>x.case))===canonical(bundle.cases));
    add('Declared isolation and adapter are explicit',r.isolation==='separate-fixture-ledgers'&&r.adapter==='coordination-d1-sandbox'&&r.runtime_revision.length>0);
    add('Source threshold matches the tested version',r.before_approval_above_minor===a.approval_above_minor);
    if(bundle.proposal){
      const p=bundle.proposal.payload;
      add('Authority recorded the exact proposed change',await verify(bundle.proposal,a.registrar_key)&&p.type==='scopeblind.coordination.repair-proposal.v1');
      add('Proposal and report share the same source and cases',r.proposal_digest===bundle.proposal.digest&&p.room_id===a.id&&p.agreement_digest===bundle.agreement.digest&&p.fixture_digest===r.fixture_digest&&p.cases_digest===r.cases_digest);
      add('Proposed threshold matches the comparison',p.previous_approval_above_minor===a.approval_above_minor&&p.approval_above_minor===r.after_approval_above_minor&&Number.isSafeInteger(p.approval_above_minor)&&p.approval_above_minor>=0&&p.approval_above_minor<=a.budget_minor);
    }else add('Baseline report claims no proposed version',r.proposal_digest===undefined&&r.after_approval_above_minor===undefined);
    const selected=r.results.map(x=>bundle.proposal?x.after:x.before);
    add('Every compared case has an observation',selected.every(Boolean)&&r.results.every(x=>!!x.before&&(!bundle.proposal?x.after===undefined:true)));
    const sound=(c:RehearsalCase,o:RehearsalObservation)=>o&&typeof o.reason==='string'&&o.reason.length<=2000&&Array.isArray(o.steps)&&o.steps.length>0&&o.steps.length<=50
      &&o.steps.every(s=>typeof s.action==='string'&&s.action.length<=200&&typeof s.reason==='string'&&s.reason.length<=2000&&['allow','ask','refuse','confirmed','rejected'].includes(s.decision))
      &&Number.isSafeInteger(o.payments)&&o.payments>=0&&Number.isSafeInteger(o.spent_minor)&&o.spent_minor>=0&&['allow','ask','refuse','error'].includes(o.actual)
      &&!(o.actual==='error'&&o.matched)&&o.matched===(c.expected==='invariant'?o.invariant_passed===true:o.actual===c.expected);
    add('Observation summaries agree with stated expectations',r.results.every(x=>sound(x.case,x.before)&&(!x.after||sound(x.case,x.after))));
    add('Required safety cases remain included',defaultRehearsalCases(bundle.fixtures).every(c=>bundle.cases.some(x=>canonical(x)===canonical(c))));
    add('Required-case and expectation totals match the observations',r.required_passed===r.results.every((x,i)=>!x.case.required||selected[i]?.matched===true)&&r.expectations_met===selected.every(x=>x?.matched===true));
    if(bundle.adoption){
      const d=bundle.adoption.payload,authorization=bundle.adoption_authorization,next=bundle.adopted_agreement;
      add('Authority recorded adoption of this exact report',await verify(bundle.adoption,a.registrar_key)&&d.type==='scopeblind.coordination.rehearsal-adoption.v1'&&d.source_room_id===a.id&&d.source_agreement_digest===bundle.agreement.digest&&d.report_digest===bundle.report.digest&&d.proposal_digest===bundle.proposal?.digest&&d.fixture_digest===r.fixture_digest&&d.cases_digest===r.cases_digest&&d.owner_key===a.owner_key&&d.scope==='new-separate-sample-task');
      add('Owner signed adoption of the exact report and new agreement',authorization&&next&&await verify(authorization,a.owner_key)&&await verify(next,a.owner_key)
        &&authorization.digest===d.authorization_digest&&authorization.payload.type==='scopeblind.coordination.request.v1'&&authorization.payload.action==='rehearsal_adopt'&&authorization.payload.room_id===a.id
        &&authorization.payload.body.report_digest===bundle.report.digest&&authorization.payload.body.proposal_id===bundle.proposal?.payload.id
        &&canonical(authorization.payload.body.agreement)===canonical(next)&&next.digest===d.agreement_digest&&next.payload.id===d.room_id&&next.payload.id!==a.id);
      add('Only the tested threshold changed in the new task',next&&bundle.proposal&&canonical(next.payload)===canonical({...a,id:next.payload.id,issued_at:next.payload.issued_at,approval_above_minor:bundle.proposal.payload.approval_above_minor})&&r.required_passed&&r.expectations_met);
    }else add('No unbound adoption claims are present',!bundle.adoption_authorization&&!bundle.adopted_agreement);
  }catch{add('Complete, well-formed rehearsal evidence',false);}
  return {valid:checks.every(x=>x.ok),checks,errors:checks.filter(x=>!x.ok).map(x=>x.label),limitations:[
    'These are concrete checks against isolated sample ledgers, not proof for every possible input or another deployment.',
    'The named ScopeBlind authority attests to observed gate behavior. Signatures establish integrity and key control, not independent observation or legal identity.',
    'Proposed changes grant no authority by themselves. A new sample task has its own ledger; earlier work and payments remain unchanged.',
  ]};
}
