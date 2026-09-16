import {verifyHuman} from './coordination-devices';
import {verifyOwnerAgreement} from './coordination-evidence';
/** Bilateral, bounded agreement over the invoice review threshold and total budget.
 * Private background never belongs in an export, RoomView, or public event.
 * Human approval is separate from every agent recommendation.
 */
import { COORDINATION_DOMAIN, canonical, sha256, verify, type Agreement, type InvoiceFixtures, type InvitationGrant, type GuestBinding, type Signed } from './coordination-protocol';
import type { AgentBinding } from './coordination-pairing';
import { defaultRehearsalCases, type RehearsalCase, type RehearsalObservation } from './coordination-rehearsal';

export const NEGOTIATION_REVISION = 'scopeblind.invoice-negotiation.v1';
export const NEGOTIATION_MAX_PROPOSALS = 3;
export const NEGOTIATION_MAX_MODEL_STEPS = 6;
export const NEGOTIATION_AGENT_ACTIONS = ['negotiation_get', 'negotiation_propose', 'negotiation_respond', 'negotiation_compare'] as const;
export const NEGOTIATION_ACTIONS = [
  ...NEGOTIATION_AGENT_ACTIONS, 'negotiation_create', 'negotiation_claim', 'negotiation_mandate',
  'negotiation_approve', 'negotiation_adopt', 'negotiation_pair_create', 'negotiation_pair_claim',
  'negotiation_pair_revoke', 'negotiation_step', 'negotiation_cancel',
] as const;
export type NegotiationAction = typeof NEGOTIATION_ACTIONS[number];
export type NegotiationSide = 'organizer' | 'partner';
export type NegotiationAgentMode = 'hosted' | 'own' | 'manual';
export type NegotiationPreference = 'fewer_reviews' | 'more_review' | 'balanced';
export type NegotiationBudgetPreference = 'preserve_budget' | 'lower_budget' | 'more_capacity';
export interface NegotiationPrivateBrief { text: string; preference: NegotiationPreference; salt: string; budget_preference?: NegotiationBudgetPreference }
export interface NegotiationRequirement { invoice_id: string; expected: 'allow' | 'ask' }
export interface NegotiationMandate {
  type: 'scopeblind.coordination.negotiation-mandate.v1'; session_id: string; room_id: string;
  principal_key: string; version: number; agreement_digest: string; fixture_digest: string;
  min_threshold_minor: number; max_threshold_minor: number;
  /** Omitted together in legacy mandates: the source budget is fixed. */
  min_budget_minor?: number; max_budget_minor?: number; required_invoices: NegotiationRequirement[];
  private_brief_commitment: string; agent_mode: NegotiationAgentMode;
  /** Deliberately excludes payment, approval, invitation and onward-delegation powers. */
  actions: readonly (typeof NEGOTIATION_AGENT_ACTIONS[number])[];
  issued_at: string; expires_at: string;
}
export interface NegotiationInvitation {
  type: 'scopeblind.coordination.negotiation-invitation.v1'; session_id: string; room_id: string;
  agreement_digest: string; fixture_digest: string; issuer: string; registrar_key: string;
  role: 'counterparty'; token_hash: string; max_claims: 1; expires_at: string;
  /** Fresh discussion; no mandate or approval carries over. */
  parent_session_id?: string; source_operation_id?: string;
}
export interface NegotiationClaim {
  type: 'scopeblind.coordination.negotiation-claim.v1'; session_id: string; room_id: string;
  guest_key: string; name: string; issued_at: string; nonce: string;
}
export interface NegotiationBinding {
  type: 'scopeblind.coordination.negotiation-binding.v1'; session_id: string; room_id: string;
  invitation_digest: string; guest_key: string; name: string; issued_at: string; expires_at: string;
  claim: Signed<NegotiationClaim>;
}
export interface NegotiationSession {
  type: 'scopeblind.coordination.negotiation-session.v1'; id: string; room_id: string;
  agreement_digest: string; fixture_digest: string; owner_key: string; registrar_key: string;
  invitation_digest: string; created_at: string; expires_at: string; max_proposals: 3; parent_session_id?: string; source_operation_id?: string; source_invoice_id?: string; source_operation_digest?: string;
}
export interface NegotiationProposalInput { id: string; approval_above_minor: number; budget_minor?: number; exploration?: true; parent_digest?: string }
export interface NegotiationProposal extends NegotiationProposalInput {
  type: 'scopeblind.coordination.negotiation-proposal.v1'; session_id: string; room_id: string;
  round: number; principal_key: string; agent_key?: string; agent_mode: NegotiationAgentMode;
  agreement_digest: string; fixture_digest: string; mandate_digests: [string, string];
  /** This exact future agreement is shown before either human approves it. */
  next_agreement: Agreement; next_agreement_digest: string; reviewer_grant: InvitationGrant; reviewer_grant_digest: string; issued_at: string;
}
export interface NegotiationResponse {
  type: 'scopeblind.coordination.negotiation-response.v1'; session_id: string; principal_key: string;
  proposal_digest: string; mandate_digest: string; decision: 'support' | 'no_agreement';
  agent_key?: string; agent_mode: NegotiationAgentMode; issued_at: string;
}
export interface NegotiationReport {
  type: 'scopeblind.coordination.negotiation-report.v1'; session_id: string; room_id: string;
  proposal_digest: string; agreement_digest: string; fixture_digest: string;
  mandate_digests: [string, string]; cases_digest: string; runtime_revision: string;
  adapter: 'coordination-d1-sandbox'; isolation: 'separate-fixture-ledgers'; issued_at: string;
  before_approval_above_minor: number; after_approval_above_minor: number;
  before_budget_minor?: number; after_budget_minor?: number;
  results: Array<{ case: RehearsalCase; before: RehearsalObservation; after: RehearsalObservation }>;
  required_passed: boolean; expectations_met: boolean; mandates_met: boolean;
}
export interface NegotiationApproval {
  type: 'scopeblind.coordination.negotiation-approval.v1'; session_id: string; principal_key: string;
  proposal_digest: string; report_digest: string; next_agreement_digest: string;
  mandate_digests: [string, string]; decision: 'approve' | 'reject'; selection_basis?: 'human-selected-tested-plan'; issued_at: string; expires_at: string;
}
export interface NegotiationAdoption {
  type: 'scopeblind.coordination.negotiation-adoption.v1'; session_id: string;
  source_room_id: string; room_id: string; source_agreement_digest: string; agreement_digest: string;
  proposal_digest: string; report_digest: string; approval_digests: [string, string];
  issued_at: string; scope: 'new-separate-sample-task';
}
export interface NegotiationPrincipal {
  side: NegotiationSide; key: string; name: string; mandate?: Signed<NegotiationMandate>;
  agent_status?: 'not_set' | 'waiting' | 'working' | 'ready' | 'unavailable' | 'revoked';
}
export interface NegotiationPairView {
  pair_id: string; name: string; principal_key: string; session_id: string;
  status: 'waiting' | 'connected' | 'expired' | 'revoked'; code_expires_at: string; expires_at: string;
  readiness?: import('./coordination-pairing').AgentReadiness;
  agent_key?: string; profile_bound?: true;
}
export interface NegotiationRun {
  proposal_digest: string; status: 'running' | 'completed' | 'failed';
  completed_cases: number; total_cases: number; error?: string;
}
export type NegotiationStatus = 'waiting_partner' | 'setting_limits' | 'ready' | 'working' | 'waiting_agent'
  | 'needs_decision' | 'agreed' | 'no_overlap' | 'round_limit' | 'failed' | 'cancelled' | 'adopted';
export interface NegotiationState {
  source_negotiation?:NegotiationExport;
  session: Signed<NegotiationSession>; invitation: Signed<NegotiationInvitation>; binding?: Signed<NegotiationBinding>;
  agreement: Signed<Agreement>; fixtures: InvoiceFixtures; principals: NegotiationPrincipal[];
  started: boolean; status: NegotiationStatus; proposals: Signed<NegotiationProposal>[]; responses: Signed<NegotiationResponse>[];
  reports: Signed<NegotiationReport>[]; approvals: Signed<NegotiationApproval>[];
  adoption?: Signed<NegotiationAdoption>; adopted_agreement?: Signed<Agreement>; run?: NegotiationRun;
  reviewer_grant?: Signed<InvitationGrant>; reviewer_binding?: Signed<GuestBinding>; agent_bindings?: Signed<AgentBinding>[];
  feasibility?: NegotiationFeasibility;
  selected_proposal_digest?: string; runtime_changed?: boolean;
  next_principal_key?: string; model_steps: number; max_model_steps: 6; error?: string;
  /** Present only for the authenticated principal or its explicitly scoped agent. */
  viewer: { principal_key: string; side: NegotiationSide; brief?: NegotiationPrivateBrief; pairs: NegotiationPairView[]; is_agent: boolean };
}
export interface NegotiationExport {
  source_negotiation?:NegotiationExport;
  type: 'scopeblind.coordination.negotiation-evidence.v1'; session: Signed<NegotiationSession>;
  invitation: Signed<NegotiationInvitation>; binding: Signed<NegotiationBinding>;
  agreement: Signed<Agreement>; fixtures: InvoiceFixtures; mandates: [Signed<NegotiationMandate>, Signed<NegotiationMandate>];
  proposals: Signed<NegotiationProposal>[]; responses: Signed<NegotiationResponse>[];
  report: Signed<NegotiationReport>; approvals: Signed<NegotiationApproval>[];
  adoption?: Signed<NegotiationAdoption>; adopted_agreement?: Signed<Agreement>;
  reviewer_grant?: Signed<InvitationGrant>; reviewer_binding?: Signed<GuestBinding>; agent_bindings?: Signed<AgentBinding>[];
}

export const negotiationDigest = (value: unknown) => sha256(canonical(value));
/** Digest of a future signed payload; fixtures/cases instead use negotiationDigest. */
export const negotiationPayloadDigest = (value: unknown) => sha256(COORDINATION_DOMAIN + canonical(value));
export async function privateBriefCommitment(brief: NegotiationPrivateBrief): Promise<string> {
  return sha256('scopeblind.negotiation.private-brief.v1\n' + canonical(brief));
}
export function parseNegotiationBrief(value: unknown): NegotiationPrivateBrief {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid_private_brief');
  const v = value as Record<string, unknown>;
  if (!['preference,salt,text','budget_preference,preference,salt,text'].includes(Object.keys(v).sort().join(',')) || (v.budget_preference !== undefined && !['preserve_budget','lower_budget','more_capacity'].includes(String(v.budget_preference))) || typeof v.text !== 'string' || v.text.length > 2000
    || !['fewer_reviews', 'more_review', 'balanced'].includes(String(v.preference)) || typeof v.salt !== 'string' || !/^[0-9a-f]{64}$/.test(v.salt)) throw new Error('invalid_private_brief');
  canonical(v);
  return v as unknown as NegotiationPrivateBrief;
}
export function mandateCases(mandates: readonly Signed<NegotiationMandate>[], fixtures: InvoiceFixtures): RehearsalCase[] {
  return [...defaultRehearsalCases(fixtures), ...(mandates.some(m => m.payload.min_budget_minor !== undefined) ? fixtures.invoices.filter(i => !i.duplicate_of).map((i, index) => ({ id: `sample-invoice-${index}`, title: `${i.invoice_id} · sample outcome`, kind: 'invoice' as const, invoice_id: i.invoice_id, expected: 'allow' as const, required: false, requirement: 'Observe this sample invoice in isolation; its outcome is not a hard requirement.' })) : []), ...mandates.flatMap((m, side) => m.payload.required_invoices.map((r, index) => ({
    id: `principal-${side}-${index}`, title: `${r.invoice_id} · ${r.expected === 'allow' ? 'keep moving' : 'needs review'}`,
    kind: 'invoice' as const, invoice_id: r.invoice_id, expected: r.expected,
    requirement: `Required by ${side === 0 ? 'the organizer' : 'the partner'}.`, required: true,
  })))];
}
export interface NegotiationConflict {
  kind: 'threshold_range' | 'budget_range' | 'threshold_exceeds_budget' | 'invoice_requirement';
  principal_keys: string[]; invoice_id?: string;
  required_min_minor?: number; permitted_max_minor?: number;
  reason: string;
}
export interface NegotiationFeasibility {
  possible: boolean; min_threshold_minor: number; max_threshold_minor: number;
  min_budget_minor: number; max_budget_minor: number; conflicts: NegotiationConflict[];
}
export function mandateBudget(m: NegotiationMandate, sourceBudget: number) {
  return { min: m.min_budget_minor ?? sourceBudget, max: m.max_budget_minor ?? sourceBudget };
}
export function negotiationPlanWithinMandate(m: NegotiationMandate, threshold: number, budget: number, sourceBudget: number) {
  const range = mandateBudget(m, sourceBudget);
  return Number.isSafeInteger(threshold) && Number.isSafeInteger(budget) && budget >= range.min && budget <= range.max
    && threshold >= m.min_threshold_minor && threshold <= m.max_threshold_minor && threshold <= budget;
}
/** Feasibility is constraint arithmetic, never a claimed gate comparison. */
export function negotiationFeasibility(mandates: readonly Signed<NegotiationMandate>[], fixtures: InvoiceFixtures, agreement?: Pick<Agreement, 'budget_minor' | 'allowed_destinations' | 'require_po_match'>): NegotiationFeasibility {
  const sourceBudget = agreement?.budget_minor ?? 10000000;
  let min_threshold_minor = Math.max(0, ...mandates.map(m => m.payload.min_threshold_minor));
  let max_threshold_minor = Math.min(10000000, ...mandates.map(m => m.payload.max_threshold_minor));
  let min_budget_minor = Math.max(1, ...mandates.map(m => mandateBudget(m.payload, sourceBudget).min));
  const max_budget_minor = Math.min(10000000, ...mandates.map(m => mandateBudget(m.payload, sourceBudget).max));
  const conflicts: NegotiationConflict[] = [], principal_keys = mandates.map(m => m.payload.principal_key);
  for (const m of mandates) for (const r of m.payload.required_invoices) {
    const invoice = fixtures.invoices.find(i => i.invoice_id === r.invoice_id && !i.duplicate_of);
    if (!invoice) { conflicts.push({ kind: 'invoice_requirement', principal_keys: [m.payload.principal_key], invoice_id: r.invoice_id, reason: 'Required invoice is missing from the signed sample.' }); continue; }
    min_budget_minor = Math.max(min_budget_minor, invoice.amount_minor);
    const order = fixtures.purchase_orders.find(p => p.id === invoice.purchase_order_id);
    const matching = !!order && order.amount_minor === invoice.amount_minor && order.vendor === invoice.vendor && order.destination === invoice.destination && order.currency === 'USD';
    if (agreement && !agreement.allowed_destinations.includes(invoice.destination)) conflicts.push({kind:'invoice_requirement',principal_keys:[m.payload.principal_key],invoice_id:r.invoice_id,reason:'The required invoice destination is outside the fixed allowlist.'});
    if (r.expected === 'allow') {
      min_threshold_minor = Math.max(min_threshold_minor, invoice.amount_minor);
      if (agreement?.require_po_match && !matching) conflicts.push({kind:'invoice_requirement',principal_keys:[m.payload.principal_key],invoice_id:r.invoice_id,reason:'This invoice requires purchase-order review under the fixed rules.'});
    } else if (!agreement?.require_po_match || matching) max_threshold_minor = Math.min(max_threshold_minor, invoice.amount_minor - 1);
  }
  if (min_threshold_minor > max_threshold_minor) conflicts.push({kind:'threshold_range',principal_keys,required_min_minor:min_threshold_minor,permitted_max_minor:max_threshold_minor,reason:'The review threshold needed to satisfy all hard requirements exceeds the permitted maximum.'});
  if (min_budget_minor > max_budget_minor) conflicts.push({kind:'budget_range',principal_keys,required_min_minor:min_budget_minor,permitted_max_minor:max_budget_minor,reason:'The budget needed to satisfy all hard requirements exceeds the permitted maximum.'});
  if (min_threshold_minor > max_budget_minor) conflicts.push({kind:'threshold_exceeds_budget',principal_keys,required_min_minor:min_threshold_minor,permitted_max_minor:max_budget_minor,reason:'The required review threshold exceeds the largest permitted total budget.'});
  max_threshold_minor = Math.min(max_threshold_minor, max_budget_minor);
  min_budget_minor = Math.max(min_budget_minor, min_threshold_minor);
  return { possible: conflicts.length === 0, min_threshold_minor, max_threshold_minor, min_budget_minor, max_budget_minor, conflicts };
}

export interface NegotiationVerification { valid: boolean; checks: Array<{ name: string; passed: boolean }>; limitations: string[] }
const HEX = /^[0-9a-f]{64}$/;
const id = (v: unknown, max = 100) => typeof v === 'string' && /^[A-Za-z0-9_-]+$/.test(v) && v.length >= 8 && v.length <= max;
const integer = (v: unknown, min: number, max: number) => Number.isSafeInteger(v) && Number(v) >= min && Number(v) <= max;
const time = (v: unknown) => typeof v === 'string' ? Date.parse(v) : NaN;
const exact = (v: unknown, required: string[], optional: string[] = []) => !!v && typeof v === 'object' && !Array.isArray(v)
  && required.every(k => Object.hasOwn(v, k)) && Object.keys(v).every(k => required.includes(k) || optional.includes(k));
const same = (a: unknown, b: unknown) => canonical(a) === canonical(b);
const keys = (s: string) => s.split(' ');
const text = (v: unknown, max: number) => typeof v === 'string' && v.length > 0 && v.length <= max;
async function signed<T>(v: Signed<T>, key: string) {
  return exact(v, keys('payload signer digest signature')) && HEX.test(key) && await verify(v, key);
}
function boundedAgreement(a: Agreement) {
  return exact(a, keys('type id version title owner_key registrar_key currency budget_minor approval_above_minor approval_ttl_seconds allowed_destinations issued_at'), keys('mode brief preferences assumptions require_po_match'))
    && a.type === 'scopeblind.coordination.agreement.v1' && id(a.id) && a.version === 1 && text(a.title, 200)
    && HEX.test(a.owner_key) && HEX.test(a.registrar_key) && a.currency === 'USD' && integer(a.budget_minor, 1, 10000000)
    && integer(a.approval_above_minor, 0, a.budget_minor) && integer(a.approval_ttl_seconds, 30, 900)
    && Number.isFinite(time(a.issued_at)) && Array.isArray(a.allowed_destinations) && a.allowed_destinations.length > 0 && a.allowed_destinations.length <= 100
    && new Set(a.allowed_destinations).size === a.allowed_destinations.length && a.allowed_destinations.every(d => text(d, 500))
    && (a.mode === undefined || ['guided','live'].includes(a.mode)) && (a.require_po_match === undefined || typeof a.require_po_match === 'boolean')
    && (a.brief === undefined || typeof a.brief === 'string' && a.brief.length <= 10000)
    && [a.preferences, a.assumptions].every(v => v === undefined || Array.isArray(v) && v.length <= 100 && v.every(t => typeof t === 'string' && t.length <= 2000));
}
function boundedFixtures(f: InvoiceFixtures) {
  return exact(f, keys('revision invoices purchase_orders')) && integer(f.revision, 1, 10000000)
    && Array.isArray(f.invoices) && f.invoices.length > 0 && f.invoices.length <= 100 && f.invoices.some(i => !i.duplicate_of)
    && new Set(f.invoices.filter(i => !i.duplicate_of).map(i => i.invoice_id)).size === f.invoices.filter(i => !i.duplicate_of).length
    && f.invoices.every(i => !i.duplicate_of || f.invoices.some(base => !base.duplicate_of && base.id === i.duplicate_of && base.invoice_id === i.invoice_id && base.amount_minor === i.amount_minor && base.destination === i.destination && base.vendor === i.vendor)) && new Set(f.invoices.map(i => i.id)).size === f.invoices.length
    && f.invoices.every(i => exact(i, keys('id invoice_id vendor description amount_minor destination'), keys('duplicate_of purchase_order_id'))
      && text(i.id, 100) && text(i.invoice_id, 60) && text(i.vendor, 300) && typeof i.description === 'string' && i.description.length <= 2000
      && integer(i.amount_minor, 1, 10000000) && text(i.destination, 500) && (i.duplicate_of === undefined || text(i.duplicate_of, 60)) && (i.purchase_order_id === undefined || text(i.purchase_order_id, 100)))
    && Array.isArray(f.purchase_orders) && f.purchase_orders.length <= 100 && new Set(f.purchase_orders.map(p => p.id)).size === f.purchase_orders.length
    && f.purchase_orders.every(p => exact(p, keys('id vendor destination amount_minor currency')) && text(p.id, 100) && text(p.vendor, 300) && text(p.destination, 500) && integer(p.amount_minor, 1, 10000000) && p.currency === 'USD');
}
/** Check summaries against the included gate trace, never infer an independent execution witness. */
function observationConsistent(c: RehearsalCase, o: RehearsalObservation, a: Agreement, f: InvoiceFixtures) {
  if (!exact(o, keys('actual matched reason steps payments spent_minor'), ['invariant_passed']) || !['allow','ask','refuse','error'].includes(o.actual)
    || typeof o.matched !== 'boolean' || typeof o.reason !== 'string' || o.reason.length > 2000 || !integer(o.payments, 0, 2) || !integer(o.spent_minor, 0, 20000000)
    || !Array.isArray(o.steps) || o.steps.length < 1 || o.steps.length > 50 || !o.steps.every(s => exact(s, keys('action decision reason'), keys('operation_id payload_hash'))
      && ['setup','admit','submit_changed_request','approve_exact','submit_expired_approval','execute'].includes(s.action)
      && ['allow','ask','refuse','confirmed','rejected'].includes(s.decision) && typeof s.reason === 'string' && s.reason.length <= 2000
      && (s.operation_id === undefined || id(s.operation_id)) && (s.payload_hash === undefined || HEX.test(s.payload_hash)))) return false;
  if (c.expected === 'invariant' ? typeof o.invariant_passed !== 'boolean' : o.invariant_passed !== undefined) return false;
  if (o.matched !== (c.expected === 'invariant' ? o.invariant_passed === true : o.actual === c.expected)) return false;
  if (o.actual === 'error') return !o.matched && o.invariant_passed !== true;
  const original = f.invoices.find(i => i.invoice_id === c.invoice_id);
  if (!original) return false;
  let amount = c.amount_minor ?? original.amount_minor;
  if (c.kind !== 'invoice' && c.amount_minor === undefined) amount = Math.min(amount, a.budget_minor);
  if (c.kind === 'budget_cap') amount = Math.floor(a.budget_minor / 2) + 1;
  if (['changed_approval','expired_approval'].includes(c.kind) && a.mode !== 'live' && !a.require_po_match && a.approval_above_minor < a.budget_minor) amount = a.approval_above_minor + 1;
  const admissions = o.steps.filter(s => s.action === 'admit' || s.action === 'submit_changed_request'), first = admissions[0], last = admissions.at(-1);
  const executed = o.steps.filter(s => s.action === 'execute' && s.decision === 'confirmed');
  if (!first || !last || o.payments !== executed.length || o.spent_minor !== amount * o.payments) return false;
  // A reported payment must have a preceding exact admission for the same operation.
  if (executed.some(s => !s.operation_id || !s.payload_hash || !o.steps.slice(0, o.steps.indexOf(s)).some(p => (p.action === 'admit' || p.action === 'submit_changed_request') && p.decision === 'allow' && p.operation_id === s.operation_id && p.payload_hash === s.payload_hash))) return false;
  let invariant = false;
  if (c.kind === 'invoice') {
    // Ordinary probes use one fresh invoice and no approval. Recompute the applicable
    // gate from the source snapshot, including the rehearsal's explicit PO override.
    const order = f.purchase_orders.find(p => p.id === original.purchase_order_id);
    const poMatches = c.amount_minor !== undefined || !!order && order.amount_minor === amount && order.vendor === original.vendor && order.destination === original.destination && order.currency === 'USD';
    const expectedGate = !a.allowed_destinations.includes(original.destination) || amount > a.budget_minor ? 'refuse'
      : amount > a.approval_above_minor || a.require_po_match === true && !poMatches ? 'ask' : 'allow';
    return o.actual === expectedGate && o.actual === first.decision && admissions.length === 1 && o.payments <= 1;
  }
  if (c.kind === 'approved_invoice') {
    invariant = o.payments === 1 && o.spent_minor === amount;
    if (o.actual !== (executed.length ? 'allow' : 'refuse')) return false;
  } else if (c.kind === 'duplicate_invoice' || c.kind === 'budget_cap') {
    if (o.actual !== last.decision || admissions.length < 2) return false;
    invariant = executed.length > 0 && last.decision !== 'allow' && o.payments === 1 && o.spent_minor <= a.budget_minor;
  } else if (c.kind === 'changed_destination') {
    if (o.actual !== last.decision) return false;
    invariant = last.decision === 'refuse' && o.payments === 0;
  } else if (c.kind === 'changed_approval') {
    if (first.decision === 'ask') {
      if (o.actual !== last.decision) return false;
      invariant = o.steps.some(s => s.action === 'approve_exact' && s.decision === 'allow') && last.action === 'submit_changed_request' && last.decision !== 'allow' && o.payments === 0;
    } else if (first.decision === 'allow') {
      invariant = last.decision === 'rejected' && last.reason === 'operation_id_payload_mismatch' && o.payments === 0;
      if (o.actual !== (invariant ? 'refuse' : 'allow')) return false;
    } else if (o.actual !== 'refuse') return false;
  } else if (c.kind === 'expired_approval') {
    if (o.actual !== last.decision) return false;
    const expired = o.steps.find(s => s.action === 'submit_expired_approval');
    invariant = expired?.decision === 'rejected' && expired.reason === 'invalid_approval_expiry' && (!(a.require_po_match === true || amount > a.approval_above_minor) || last.decision !== 'allow') && o.payments === 0;
  }
  return o.invariant_passed === invariant;
}

/** Portable integrity, authority and relationship checks. Expiry is evaluated at the recorded action, so historical evidence remains checkable. */
export async function verifyNegotiationEvidence(value: unknown, authorityKey?: string, depth=0): Promise<NegotiationVerification> {
  const checks: NegotiationVerification['checks'] = [];
  const add = (name: string, passed: unknown) => checks.push({ name, passed: !!passed });
  try {
    if(depth>4)throw new Error('Device agreement lineage exceeds supported depth');
    const e = value as NegotiationExport;
    add('Recognized public negotiation export with no private context', exact(e, keys('type session invitation binding agreement fixtures mandates proposals responses report approvals'), keys('adoption adopted_agreement reviewer_grant reviewer_binding agent_bindings source_negotiation')) && e.type === 'scopeblind.coordination.negotiation-evidence.v1');
    add('Device-signed source has only its required bounded lineage',e.agreement.authorization?!!e.source_negotiation:e.source_negotiation===undefined);
    const a = e.agreement.payload, s = e.session.payload, i = e.invitation.payload, b = e.binding.payload;
    const authority = authorityKey ?? a.registrar_key;
    add('Owner signed the bounded source agreement and exact fixture snapshot', boundedAgreement(a) && boundedFixtures(e.fixtures) && await verifyOwnerAgreement(e.agreement,e.source_negotiation,depth+1) && a.registrar_key === authority);
    add('Named authority signed a bounded session tied to this source', await signed(e.session, authority)
      && exact(s, keys('type id room_id agreement_digest fixture_digest owner_key registrar_key invitation_digest created_at expires_at max_proposals'), ['parent_session_id','source_operation_id','source_invoice_id','source_operation_digest'])
      && s.type === 'scopeblind.coordination.negotiation-session.v1' && id(s.id) && s.room_id === a.id && s.agreement_digest === e.agreement.digest && s.fixture_digest === await negotiationDigest(e.fixtures)
      && (s.parent_session_id === undefined || id(s.parent_session_id) && s.parent_session_id !== s.id) && s.parent_session_id === i.parent_session_id && s.source_operation_id === i.source_operation_id
      && (s.source_operation_id === undefined ? s.source_invoice_id === undefined && s.source_operation_digest === undefined : id(s.source_operation_id) && text(s.source_invoice_id,60) && HEX.test(s.source_operation_digest ?? '') && e.fixtures.invoices.some(v => !v.duplicate_of && v.invoice_id === s.source_invoice_id))
      && s.owner_key === a.owner_key && s.registrar_key === authority && s.invitation_digest === e.invitation.digest && s.max_proposals === 3
      && time(s.created_at) >= time(a.issued_at) - 300000 && time(s.expires_at) > time(s.created_at) && time(s.expires_at) <= time(s.created_at) + 86400000);
    const during = (at: unknown) => time(at) >= time(s.created_at) - 300000 && time(at) < time(s.expires_at);
    add('Owner invited one counterparty for this exact session', await signed(e.invitation, a.owner_key)
      && exact(i, keys('type session_id room_id agreement_digest fixture_digest issuer registrar_key role token_hash max_claims expires_at'), ['parent_session_id','source_operation_id'])
      && i.type === 'scopeblind.coordination.negotiation-invitation.v1' && i.session_id === s.id && i.room_id === a.id && i.agreement_digest === e.agreement.digest && i.fixture_digest === s.fixture_digest
      && i.issuer === a.owner_key && i.registrar_key === authority && i.role === 'counterparty' && i.max_claims === 1 && HEX.test(i.token_hash) && i.expires_at === s.expires_at);
    const claim = b.claim.payload, partner = b.guest_key, principals = [a.owner_key, partner];
    add('Distinct counterparty signed its claim and the authority bound that claim', await signed(e.binding, authority) && await signed(b.claim, partner)
      && exact(b, keys('type session_id room_id invitation_digest guest_key name issued_at expires_at claim')) && b.type === 'scopeblind.coordination.negotiation-binding.v1'
      && b.session_id === s.id && b.room_id === a.id && b.invitation_digest === e.invitation.digest && HEX.test(partner) && partner !== a.owner_key
      && during(b.issued_at) && b.expires_at === s.expires_at && exact(claim, keys('type session_id room_id guest_key name issued_at nonce'))
      && claim.type === 'scopeblind.coordination.negotiation-claim.v1' && claim.session_id === s.id && claim.room_id === a.id && claim.guest_key === partner
      && text(claim.name, 60) && claim.name === b.name && id(claim.nonce) && Math.abs(time(claim.issued_at) - time(b.issued_at)) <= 300000);
    add('Exactly two distinct principal mandates are included in organizer/partner order', Array.isArray(e.mandates) && e.mandates.length === 2 && e.mandates.every((m, n) => m.payload.principal_key === principals[n]) && new Set(e.mandates.map(m => m.digest)).size === 2);
    const mandateDigests = e.mandates.map(m => m.digest);
    for (let n = 0; n < e.mandates.length; n++) {
      const m = e.mandates[n].payload;
      add(`Principal ${n + 1} signed bounded negotiation-only authority`, await verifyHuman(e.mandates[n],principals[n],{requireRecordedUse:true,authorityKey:authority})
        && exact(m, keys('type session_id room_id principal_key version agreement_digest fixture_digest min_threshold_minor max_threshold_minor required_invoices private_brief_commitment agent_mode actions issued_at expires_at'), ['min_budget_minor','max_budget_minor'])
        && m.type === 'scopeblind.coordination.negotiation-mandate.v1' && m.session_id === s.id && m.room_id === a.id && m.principal_key === principals[n]
        && m.agreement_digest === e.agreement.digest && m.fixture_digest === s.fixture_digest && integer(m.version, 1, 1000000)
        && ((m.min_budget_minor === undefined && m.max_budget_minor === undefined) || integer(m.min_budget_minor, 1, 10000000) && integer(m.max_budget_minor, m.min_budget_minor!, 10000000))
        && integer(m.min_threshold_minor, 0, mandateBudget(m, a.budget_minor).max) && integer(m.max_threshold_minor, m.min_threshold_minor, mandateBudget(m, a.budget_minor).max)
        && Array.isArray(m.required_invoices) && m.required_invoices.length <= 2 && new Set(m.required_invoices.map(r => r.invoice_id)).size === m.required_invoices.length
        && m.required_invoices.every(r => exact(r, keys('invoice_id expected')) && ['allow','ask'].includes(r.expected) && e.fixtures.invoices.some(v => v.invoice_id === r.invoice_id && !v.duplicate_of))
        && (s.source_invoice_id === undefined || m.required_invoices.some(r => r.invoice_id === s.source_invoice_id)) && HEX.test(m.private_brief_commitment) && ['hosted','own','manual'].includes(m.agent_mode) && same(m.actions, NEGOTIATION_AGENT_ACTIONS)
        && during(m.issued_at) && time(m.expires_at) > time(m.issued_at) && time(m.expires_at) <= time(s.expires_at));
    }
    const validAt = (principal: string, at: string) => { const m = e.mandates.find(m => m.payload.principal_key === principal)?.payload; return !!m && during(at) && time(at) >= time(m.issued_at) - 300000 && time(at) < time(m.expires_at); };
    const agentBindings = e.agent_bindings ?? [];
    add('Installed agent bindings are bounded and independently scoped per principal', Array.isArray(agentBindings) && agentBindings.length <= 12 && new Set(agentBindings.map(v => v.payload.pair_id)).size === agentBindings.length);
    for (const binding of agentBindings) {
      const g = binding.payload, auth = g.owner_authorization, q = auth.payload, body = q.body, principal = g.principal_key!;
      add('Principal signed the installed agent pairing authorization', await signed(binding, authority) && await signed(auth, principal)
        && exact(g, keys('type pair_id room_id session_id principal_key agreement_digest owner_key agent_key name scope audience issued_at expires_at owner_authorization'))
        && g.type === 'scopeblind.coordination.agent-binding.v1' && g.audience === 'scopeblind.coordination.negotiation' && id(g.pair_id) && g.room_id === a.id && g.session_id === s.id
        && principals.includes(principal) && g.owner_key === principal && HEX.test(g.agent_key) && !principals.includes(g.agent_key) && g.agreement_digest === e.agreement.digest && same(g.scope, NEGOTIATION_AGENT_ACTIONS)
        && validAt(principal, g.issued_at) && time(g.expires_at) > time(g.issued_at) && time(g.expires_at) <= time(e.mandates.find(m => m.payload.principal_key === principal)!.payload.expires_at)
        && exact(q, keys('type action room_id body issued_at nonce')) && q.type === 'scopeblind.coordination.request.v1' && q.action === 'negotiation_pair_create' && q.room_id === a.id && id(q.nonce)
        && exact(body, keys('session_id pair_id secret_hash name expires_at token_expires_at scope'),['expected_agent_key']) && (body.expected_agent_key===undefined || body.expected_agent_key===g.agent_key) && body.session_id === s.id && body.pair_id === g.pair_id && HEX.test(String(body.secret_hash)) && text(body.name, 60) && text(g.name, 60)
        && same(body.scope, NEGOTIATION_AGENT_ACTIONS) && body.token_expires_at === g.expires_at && validAt(principal, q.issued_at)
        && time(body.expires_at) > time(q.issued_at) && time(body.expires_at) <= time(q.issued_at) + 900000 && time(g.issued_at) < time(body.expires_at) && time(g.issued_at) >= time(q.issued_at) - 300000
        && time(body.expires_at) <= time(g.expires_at)
        && !agentBindings.some(other => other.payload.agent_key === g.agent_key && other.payload.principal_key !== principal));
    }
    const actorBound = (p: { principal_key: string; agent_key?: string; agent_mode: NegotiationAgentMode; issued_at: string }) => {
      const mandate = e.mandates.find(m => m.payload.principal_key === p.principal_key)?.payload;
      if (!mandate || !validAt(p.principal_key, p.issued_at)) return false;
      if (p.agent_mode === 'manual') return p.agent_key === undefined;
      if (p.agent_mode === 'hosted') return mandate.agent_mode === 'hosted' && p.agent_key === undefined;
      return p.agent_mode === 'own' && mandate.agent_mode === 'own' && agentBindings.some(v => v.payload.agent_key === p.agent_key && v.payload.principal_key === p.principal_key && time(p.issued_at) >= time(v.payload.issued_at) && time(p.issued_at) < time(v.payload.expires_at));
    };
    add('At most three uniquely identified proposals are included', Array.isArray(e.proposals) && e.proposals.length >= 1 && e.proposals.length <= 3 && new Set(e.proposals.map(p => p.payload.id)).size === e.proposals.length);
    for (let n = 0; n < e.proposals.length; n++) {
      const envelope = e.proposals[n], p = envelope.payload, mine = e.mandates.find(m => m.payload.principal_key === p.principal_key)?.payload, g = p.reviewer_grant;
      add(`Candidate ${n + 1} has a signed source, parent and principal authority`, await signed(envelope, authority)
        && exact(p, keys('type id approval_above_minor session_id room_id round principal_key agent_mode agreement_digest fixture_digest mandate_digests next_agreement next_agreement_digest reviewer_grant reviewer_grant_digest issued_at'), keys('parent_digest agent_key budget_minor exploration'))
        && p.type === 'scopeblind.coordination.negotiation-proposal.v1' && typeof p.id === 'string' && /^[A-Za-z0-9_-]{1,80}$/.test(p.id) && p.session_id === s.id && p.room_id === a.id && p.round === n + 1
        && p.parent_digest === e.proposals[n - 1]?.digest && p.agreement_digest === e.agreement.digest && p.fixture_digest === s.fixture_digest && same(p.mandate_digests, mandateDigests)
        && (p.exploration === undefined || p.exploration === true && p.agent_mode === 'manual' && !p.agent_key) && !!mine && negotiationPlanWithinMandate(mine, p.approval_above_minor, p.budget_minor ?? a.budget_minor, a.budget_minor) && actorBound(p)
        && (n === 0 || time(p.issued_at) >= time(e.proposals[n - 1].payload.issued_at)));
      add(`Candidate ${n + 1} changes only the tested threshold and authorized budget in a separate task`, boundedAgreement(p.next_agreement) && p.next_agreement.id !== a.id
        && same(p.next_agreement, { ...a, id: p.next_agreement.id, issued_at: p.issued_at, approval_above_minor: p.approval_above_minor, budget_minor: p.budget_minor ?? a.budget_minor })
        && p.next_agreement_digest === await negotiationPayloadDigest(p.next_agreement));
      add(`Candidate ${n + 1} fixes the partner's future reviewer role before approval`, exact(g, keys('type grant_id room_id agreement_digest issuer registrar_key role actions expires_at token_hash max_claims'))
        && g.type === 'scopeblind.coordination.grant.v1' && id(g.grant_id) && g.room_id === p.next_agreement.id && g.agreement_digest === p.next_agreement_digest && g.issuer === a.owner_key && g.registrar_key === authority
        && g.role === 'reviewer' && same(g.actions, ['decide','accept']) && HEX.test(g.token_hash) && g.max_claims === 1 && g.expires_at === s.expires_at && p.reviewer_grant_digest === await negotiationPayloadDigest(g));
    }
    add('Recommendations are distinct from human approvals and uniquely bound', Array.isArray(e.responses) && e.responses.length <= 6 && new Set(e.responses.map(r => `${r.payload.proposal_digest}:${r.payload.principal_key}`)).size === e.responses.length);
    for (const response of e.responses) {
      const r = response.payload, p = e.proposals.find(p => p.digest === r.proposal_digest), mine = e.mandates.find(m => m.payload.principal_key === r.principal_key);
      add('Authority recorded an exactly scoped principal recommendation', await signed(response, authority)
        && exact(r, keys('type session_id principal_key proposal_digest mandate_digest decision agent_mode issued_at'), ['agent_key']) && r.type === 'scopeblind.coordination.negotiation-response.v1'
        && r.session_id === s.id && !!p && !!mine && r.mandate_digest === mine.digest && ['support','no_agreement'].includes(r.decision) && actorBound(r)
        && time(r.issued_at) >= time(p!.payload.issued_at) && (r.decision !== 'support' || negotiationPlanWithinMandate(mine!.payload, p!.payload.approval_above_minor, p!.payload.budget_minor ?? a.budget_minor, a.budget_minor)));
    }
    const r = e.report.payload, selected = e.proposals.find(p => p.digest === r.proposal_digest), p = selected!.payload;
    add('Named authority signed the exact comparison and full union of required cases', await signed(e.report, authority)
      && exact(r, keys('type session_id room_id proposal_digest agreement_digest fixture_digest mandate_digests cases_digest runtime_revision adapter isolation issued_at before_approval_above_minor after_approval_above_minor results required_passed expectations_met mandates_met'), ['before_budget_minor','after_budget_minor'])
      && r.type === 'scopeblind.coordination.negotiation-report.v1' && r.session_id === s.id && r.room_id === a.id && !!selected && r.agreement_digest === e.agreement.digest && r.fixture_digest === s.fixture_digest
      && same(r.mandate_digests, mandateDigests) && r.adapter === 'coordination-d1-sandbox' && r.isolation === 'separate-fixture-ledgers' && typeof r.runtime_revision === 'string' && (r.runtime_revision === 'development-unbound' || /^scopeblind\.invoice-rehearsal\.v1:[0-9a-f]{64}$/.test(r.runtime_revision))
      && time(r.issued_at) >= time(p.issued_at) && principals.every(key => validAt(key, r.issued_at))
      && (p.budget_minor === undefined ? r.before_budget_minor === undefined && r.after_budget_minor === undefined : r.before_budget_minor === a.budget_minor && r.after_budget_minor === p.budget_minor)
      && r.before_approval_above_minor === a.approval_above_minor && r.after_approval_above_minor === p.approval_above_minor
      && Array.isArray(r.results) && r.results.length <= 110 && r.results.every(x => exact(x, keys('case before after')))
      && same(r.results.map(x => x.case), mandateCases(e.mandates, e.fixtures)) && r.cases_digest === await negotiationDigest(mandateCases(e.mandates, e.fixtures)));
    add('Both gate traces and payment totals support every observation summary', r.results.every(x => observationConsistent(x.case, x.before, a, e.fixtures) && observationConsistent(x.case, x.after, p.next_agreement, e.fixtures)));
    const rangeMet = e.mandates.every(m => negotiationPlanWithinMandate(m.payload, p.approval_above_minor, p.budget_minor ?? a.budget_minor, a.budget_minor));
    add('Required cases, expectations and both mandates match the reported calculations', r.required_passed === r.results.every(x => !x.case.required || x.after.matched)
      && r.expectations_met === r.results.every(x => x.case.id.startsWith('sample-invoice-') || x.after.matched) && r.mandates_met === (rangeMet && r.results.filter(x => x.case.id.startsWith('principal-')).every(x => x.after.matched)));
    add('Human decisions are at most one per principal', Array.isArray(e.approvals) && e.approvals.length <= 2 && new Set(e.approvals.map(v => v.payload.principal_key)).size === e.approvals.length);
    for (const approval of e.approvals) {
      const v = approval.payload;
      add('Human signed a decision over these exact rules, report and mandates', await verifyHuman(approval,v.principal_key,{proposal:selected,requireRecordedUse:true,authorityKey:authority})
        && exact(v, keys('type session_id principal_key proposal_digest report_digest next_agreement_digest mandate_digests decision issued_at expires_at'), ['selection_basis'])
        && v.type === 'scopeblind.coordination.negotiation-approval.v1' && principals.includes(v.principal_key) && v.session_id === s.id && v.proposal_digest === selected!.digest && v.report_digest === e.report.digest
        && (v.selection_basis === undefined || v.selection_basis === 'human-selected-tested-plan') && v.next_agreement_digest === p.next_agreement_digest && same(v.mandate_digests, mandateDigests) && ['approve','reject'].includes(v.decision)
        && validAt(v.principal_key, v.issued_at) && time(v.issued_at) >= time(r.issued_at) - 300000 && time(v.expires_at) > time(v.issued_at) && time(v.expires_at) <= time(s.expires_at));
    }
    if (e.reviewer_grant) add('Organizer signed the exact proposed reviewer grant', await verifyHuman(e.reviewer_grant,a.owner_key,{proposal:selected,approval:e.approvals.find(v=>v.payload.principal_key===a.owner_key),requireRecordedUse:true,authorityKey:authority}) && same(e.reviewer_grant.payload, p.reviewer_grant) && e.reviewer_grant.digest === p.reviewer_grant_digest);
    if (e.adoption) {
      const d = e.adoption.payload, next = e.adopted_agreement!, g = e.reviewer_grant!, binding = e.reviewer_binding!, rb = binding.payload, claim = rb.claim.payload;
      add('Both unexpired human approvals authorize adoption of this exact tested candidate', e.approvals.length === 2 && e.approvals.every(v => v.payload.decision === 'approve' && time(d.issued_at) >= time(v.payload.issued_at) - 300000 && time(d.issued_at) < time(v.payload.expires_at))
        && selected!.digest === e.proposals.at(-1)!.digest && principals.every(key => validAt(key, d.issued_at)) && r.required_passed && r.expectations_met && r.mandates_met
        && (e.approvals.every(v => v.payload.selection_basis === 'human-selected-tested-plan') || principals.every(key => e.responses.some(v => v.payload.principal_key === key && v.payload.proposal_digest === selected!.digest && v.payload.decision === 'support'))));
      add('Authority recorded exact lineage into a new separately authorized sample task', await signed(e.adoption, authority)
        && exact(d, keys('type session_id source_room_id room_id source_agreement_digest agreement_digest proposal_digest report_digest approval_digests issued_at scope'))
        && d.type === 'scopeblind.coordination.negotiation-adoption.v1' && d.session_id === s.id && d.source_room_id === a.id && d.room_id === p.next_agreement.id && d.room_id !== a.id
        && d.source_agreement_digest === e.agreement.digest && d.agreement_digest === p.next_agreement_digest && d.proposal_digest === selected!.digest && d.report_digest === e.report.digest
        && same(d.approval_digests, principals.map(key => e.approvals.find(v => v.payload.principal_key === key)!.digest)) && d.scope === 'new-separate-sample-task'
        && await verifyHuman(next,a.owner_key,{proposal:selected,approval:e.approvals.find(v=>v.payload.principal_key===a.owner_key),requireRecordedUse:true,authorityKey:authority}) && same(next.payload, p.next_agreement) && next.digest === d.agreement_digest);
      add('Partner independently claimed the fixed reviewer role in the new task', await signed(binding, authority) && await verifyHuman(rb.claim,partner,{proposal:selected,approval:e.approvals.find(v=>v.payload.principal_key===partner),requireRecordedUse:true,authorityKey:authority})
        && exact(rb, keys('type grant_id grant_digest room_id guest_key name issued_at expires_at claim')) && rb.type === 'scopeblind.coordination.binding.v1' && rb.grant_id === g.payload.grant_id && rb.grant_digest === g.digest
        && rb.room_id === d.room_id && rb.guest_key === partner && rb.expires_at === g.payload.expires_at && time(rb.issued_at) >= time(d.issued_at) && time(rb.issued_at) < time(rb.expires_at)
        && exact(claim, keys('type grant_id room_id guest_key name issued_at nonce')) && claim.type === 'scopeblind.coordination.claim.v1' && claim.grant_id === rb.grant_id && claim.room_id === d.room_id
        && claim.guest_key === partner && text(claim.name, 60) && claim.name === rb.name && id(claim.nonce) && time(claim.issued_at) >= time(r.issued_at) - 300000 && time(claim.issued_at) <= time(rb.issued_at) + 300000);
    } else add('No unbound adopted agreement or reviewer binding is present', !e.adopted_agreement && !e.reviewer_binding);
  } catch { add('Complete, well-formed negotiation evidence', false); }
  return { valid: checks.length > 0 && checks.every(c => c.passed), checks, limitations: [
    'Signatures establish record integrity and control of keys. Display names are not authenticated legal identities.',
    'The named service attests to gate traces and sample-ledger effects. These records do not independently prove execution or safety for every input or deployment.',
    'Private briefs are omitted; signed commitments do not reveal or validate their contents. Recommendations are separate from human approval and adoption.',
    'Comparisons test each case in a separate ledger; observing several payable invoices does not establish that all fit one shared run budget.',
    'Expiry is checked at recorded actions. An export does not establish present authorization, revocation status, or permission to make a payment.',
  ] };
}
