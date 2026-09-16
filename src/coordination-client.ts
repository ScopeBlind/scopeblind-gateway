import { verifyOwnerAgreement } from './coordination-evidence.js';
import { verifyHuman } from './coordination-devices.js';
import { validateCoordinationConfig, type CoordinationConfig } from './coordination-config.js';
import { parseRehearsalCase, parseRepairProposal, rehearsalDigest, verifyRehearsalEvidence, type RehearsalAction, type RehearsalCase, type RepairProposalInput, type RehearsalState, type RehearsalExport } from './coordination-rehearsal.js';
import { NEGOTIATION_AGENT_ACTIONS, NEGOTIATION_MAX_PROPOSALS, NEGOTIATION_MAX_MODEL_STEPS, negotiationDigest, negotiationPayloadDigest, privateBriefCommitment, parseNegotiationBrief, mandateCases, mandateBudget, negotiationPlanWithinMandate, verifyNegotiationEvidence, type NegotiationState, type NegotiationProposalInput, type NegotiationExport } from './coordination-negotiation.js';
import { webcrypto } from 'node:crypto';
import {
  canonical, payloadHash, verify,
  type Admission, type Agreement, type OperationRequest, type Outcome,
  type PaymentInput, type InvoiceFixtures, type RoomView, type Signed,
} from './coordination-protocol.js';

// Node 18 supports WebCrypto but does not expose it globally in every entry mode.
if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });

export class CoordinationError extends Error {
  constructor(public readonly code: string, message: string) { super(message); this.name = 'CoordinationError'; }
}

/** The transport never follows redirects or includes a bearer token in a URL/error. */
export class CoordinationTransport {
  #config: CoordinationConfig;
  constructor(config: CoordinationConfig, private readonly fetchImpl: typeof fetch = fetch) {
    this.#config = validateCoordinationConfig(config);
  }

  async get(op: 'room' | 'operation', operationId?: string): Promise<Record<string, unknown>> {
    const url = new URL(this.#config.endpoint);
    url.searchParams.set('op', op);
    url.searchParams.set('room_id', this.#config.roomId);
    if (operationId !== undefined) url.searchParams.set('operation_id', operationId);
    return this.request(url.href, { method: 'GET' });
  }

  async post(action: 'admit' | 'execute' | 'outcome' | 'inspect' | 'deliver' | RehearsalAction | typeof NEGOTIATION_AGENT_ACTIONS[number], body: unknown, signal?: AbortSignal): Promise<Record<string, unknown>> {
    if (this.#config.purpose === 'negotiation' && !(NEGOTIATION_AGENT_ACTIONS as readonly string[]).includes(action)) throw new CoordinationError('tool_outside_grant', 'This negotiation connection cannot access execution or rehearsal actions.');
    return this.request(this.#config.endpoint, {
      method: 'POST',
      body: JSON.stringify({ action, room_id: this.#config.roomId, body }), signal,
    }, action === 'rehearsal_run' || action === 'negotiation_compare' ? 60_000 : undefined);
  }

  private async request(url: string, init: RequestInit, defaultTimeout?: number): Promise<Record<string, unknown>> {
    const abort = new AbortController();
    const cancel = () => abort.abort();
    if (init.signal?.aborted) cancel();
    else init.signal?.addEventListener('abort', cancel, { once: true });
    const timeout = setTimeout(() => abort.abort(), this.#config.timeoutMs ?? defaultTimeout ?? 15_000);
    try {
      const response = await this.fetchImpl(url, {
        ...init, signal: abort.signal, redirect: 'error', cache: 'no-store',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${this.#config.token}` },
      });

      const raw = await response.text();
      if (raw.length > 2_000_000) throw new CoordinationError('invalid_response', 'Coordination response exceeds the supported size.');
      let result: unknown;
      try { result = JSON.parse(raw); } catch { throw new CoordinationError('invalid_response', 'Coordination service returned invalid JSON.'); }
      if (!response.ok) {
        const code = result && typeof result === 'object' && 'error' in result && typeof result.error === 'string' && /^[a-z_]{3,80}$/.test(result.error) ? result.error : 'service_rejected';
        const guidance: Record<string, string> = { rehearsal_in_progress: 'This exact test is still running. Wait before inspecting reports or retrying with the same test id.', rehearsal_run_failed: 'This exact test ended without a completed report. Inspect the source and cases; a new deliberately requested test needs a new id.', proposal_stale: 'Cases or source records changed. Inspect the rehearsal and propose a newly identified repair against the current snapshot.', executor_action_not_permitted: 'This action is outside the owner’s explicit grant. Ask for a separate connection with the required scope.', rehearsal_id_conflict: 'This stable ID already names different content. Inspect the existing record; use a new ID only for a new intended case, proposal, or test.', executor_token_invalid: 'This agent connection expired or was revoked. Ask the owner for a fresh pairing.', room_paused: 'The owner paused this task. Wait for resume; retain all operation IDs.', run_has_unresolved_operations: 'Resolve held or unknown operations before delivering the result.', run_finalized: 'This attempt is already delivered. Wait for an owner-authorized revision.', rate_limited: 'The room request limit was reached. Pause and retry later with unchanged operation IDs.' };
        throw new CoordinationError(code, guidance[code] || `Coordination service rejected the request (${code}; HTTP ${response.status}). Inspect current room state before retrying.`);
      }
      if (!result || typeof result !== 'object' || Array.isArray(result) || (result as Record<string, unknown>).ok !== true) {
        throw new CoordinationError('invalid_response', 'Coordination service did not return a successful protocol response.');
      }
      return result as Record<string, unknown>;
    } catch (error) {
      if (error instanceof CoordinationError) throw error;
      if (init.signal?.aborted) throw new CoordinationError('cancelled', 'The wait was cancelled. No action or approval was performed.');
      throw new CoordinationError('service_unavailable', 'Coordination service could not be reached or the request timed out.');
    } finally {
      clearTimeout(timeout);
      init.signal?.removeEventListener('abort', cancel);
    }
  }
}

export interface CoordinationPayment {
  operation_id: string;
  input: PaymentInput;
}

export interface CoordinationPaymentResult {
  operation_id: string;
  status: 'held' | 'refused' | 'confirmed' | 'failed' | 'unknown';
  reason: string;
  admission?: Signed<Admission>;
  outcome?: Signed<Outcome>;
  replay?: boolean;
}

export interface CoordinationWait {
  after_cursor: number;
  run_id?: string;
  timeout_ms?: number;
}

function waitDelay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const cancelled = () => { clearTimeout(timer); signal.removeEventListener('abort', cancelled); reject(new CoordinationError('cancelled', 'The wait was cancelled. No action or approval was performed.')); };
    const timer = setTimeout(() => { signal.removeEventListener('abort', cancelled); resolve(); }, Math.ceil(ms));
    if (signal.aborted) cancelled();
    else signal.addEventListener('abort', cancelled, { once: true });
  });
}

const operationIdentifier = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_-]{8,100}$/.test(value);

export function validateCoordinationPayment(payment: CoordinationPayment): void {
  if (!payment || !operationIdentifier(payment.operation_id)) throw new CoordinationError('invalid_operation', 'A stable operation_id of 8–100 letters, numbers, underscores, or hyphens is required; retain it when retrying the same intended payment.');
  if (Object.keys(payment).sort().join(',') !== 'input,operation_id') throw new CoordinationError('invalid_operation', 'The executor accepts operation_id and input only; revisions must be made by the room owner.');
  const input = payment.input;
  if (!input || typeof input.invoice_id !== 'string' || !input.invoice_id.length || input.invoice_id.length > 60 || !Number.isSafeInteger(input.amount_minor) || input.amount_minor <= 0 || input.amount_minor > 10_000_000 || input.currency !== 'USD' || typeof input.destination !== 'string' || !input.destination.length || input.destination.length > 100) {
    throw new CoordinationError('invalid_input', 'Payment requires invoice_id, a positive integer amount_minor, currency USD, and a sample destination.');
  }
  if (input.fixture_revision !== undefined && (!Number.isSafeInteger(input.fixture_revision) || input.fixture_revision < 1)) throw new CoordinationError('invalid_input', 'fixture_revision must be a positive integer from coordination.inspect.');
  if (Object.keys(input).filter(key => key !== 'fixture_revision').sort().join(',') !== 'amount_minor,currency,destination,invoice_id') {
    throw new CoordinationError('invalid_input', 'Payment input contains unsupported fields.');
  }
}

/**
 * An installed, fail-closed adapter for the sample ledger destination.
 * An admission is never a generic permission to call an arbitrary downstream tool.
 * The service owns destination idempotency; retries always retain operation_id.
 */
export class CoordinationClient {
  #config: CoordinationConfig;
  #transport: CoordinationTransport;
  #acknowledgedContexts = new Set<string>();
  constructor(config: CoordinationConfig, fetchImpl: typeof fetch = fetch) {
    this.#config = validateCoordinationConfig(config);
    this.#transport = new CoordinationTransport(this.#config, fetchImpl);
  }

  /** Tool visibility is a local convenience; every RPC also checks the persisted grant. */
  get purpose(): 'execution' | 'rehearsal' | 'negotiation' { return this.#config.purpose || 'execution'; }

  /** Acknowledge only a context that this adapter has already verified. Pairing and MCP initialization do not call this. */
  private async acknowledgeInspection(response: Record<string, unknown>, action: 'inspect' | 'rehearsal_get' | 'negotiation_get', contextDigest: string, signal?: AbortSignal): Promise<void> {
    const key = `${action}:${contextDigest}`;
    if (response.agent_inspection_supported !== true || this.#acknowledgedContexts.has(key)) return;
    const acknowledgment = await this.#transport.post(action, { ...(action === 'negotiation_get' ? { session_id: this.#config.sessionId } : {}), observed_context_digest: contextDigest }, signal);
    if (typeof acknowledgment.agent_inspection_acknowledged !== 'boolean') throw new CoordinationError('agent_inspection_unconfirmed', 'The room could not confirm this inspection. Inspect again before continuing.');
    this.#acknowledgedContexts.add(key);
  }

  private negotiationConfig() {
    if (this.purpose !== 'negotiation' || !this.#config.sessionId || !this.#config.principalKey) throw new CoordinationError('tool_outside_grant', 'Use a separate principal-authorized negotiation pairing for these tools.');
    return { sessionId: this.#config.sessionId, principalKey: this.#config.principalKey };
  }

  /** Inspect only the scoped negotiation response. Never read the public room to obtain a mandate. */
  private async checkedNegotiation(response: Record<string, unknown>): Promise<NegotiationState> {
    const { sessionId, principalKey } = this.negotiationConfig();
    const state = response.negotiation as NegotiationState;
    const invalid = () => { throw new CoordinationError('invalid_negotiation', 'The negotiation identity, source records, mandate, or signed candidate could not be verified. No approval or authority was granted.'); };
    const keys = (value: unknown, allowed: string[]) => {
      if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !allowed.includes(key))) invalid();
    };
    const envelope = (value: unknown) => keys(value, ['payload', 'signer', 'digest', 'signature']);
    const humanEnvelope = (value: unknown) => keys(value, ['payload', 'signer', 'digest', 'signature', 'authorization', 'authorization_signature', 'authorization_use']);
    try {
      keys(state, ['session','invitation','binding','agreement','fixtures','principals','status','proposals','responses','reports','approvals','adoption','adopted_agreement','run','feasibility','next_principal_key','model_steps','max_model_steps','error','viewer','started','reviewer_grant','reviewer_binding','agent_bindings','selected_proposal_digest','runtime_changed','source_negotiation']);
      const session = state.session?.payload, agreement = state.agreement?.payload;
      if (!session || !agreement || session.type !== 'scopeblind.coordination.negotiation-session.v1' || session.id !== sessionId || session.room_id !== this.#config.roomId || session.registrar_key !== this.#config.authorityKey || !await verify(state.session, this.#config.authorityKey) ||
        agreement.type !== 'scopeblind.coordination.agreement.v1' || agreement.id !== this.#config.roomId || agreement.owner_key !== session.owner_key || agreement.registrar_key !== this.#config.authorityKey || !await verifyOwnerAgreement(state.agreement, (state as NegotiationState & {source_negotiation?:NegotiationExport}).source_negotiation) || state.agreement.digest !== session.agreement_digest ||
        session.max_proposals !== NEGOTIATION_MAX_PROPOSALS || state.max_model_steps !== NEGOTIATION_MAX_MODEL_STEPS || !Number.isSafeInteger(state.model_steps) || state.model_steps < 0 || state.model_steps > NEGOTIATION_MAX_MODEL_STEPS || !state.fixtures || await negotiationDigest(state.fixtures) !== session.fixture_digest) invalid();
      if (!Number.isFinite(Date.parse(session.created_at)) || !Number.isFinite(Date.parse(session.expires_at)) || Date.parse(session.expires_at) <= Date.parse(session.created_at) || Date.parse(session.expires_at) > Date.parse(session.created_at) + 86400000) invalid();
      envelope(state.session); keys(session, ['type','id','room_id','agreement_digest','fixture_digest','owner_key','registrar_key','invitation_digest','created_at','expires_at','max_proposals','parent_session_id','source_operation_id','source_invoice_id','source_operation_digest']);
      const invitation = state.invitation?.payload;
      if (!invitation || !await verify(state.invitation, session.owner_key) || invitation.type !== 'scopeblind.coordination.negotiation-invitation.v1' || state.invitation.digest !== session.invitation_digest || invitation.session_id !== sessionId || invitation.room_id !== session.room_id || invitation.agreement_digest !== session.agreement_digest || invitation.fixture_digest !== session.fixture_digest || invitation.issuer !== session.owner_key || invitation.registrar_key !== this.#config.authorityKey) invalid();
      if (invitation.role !== 'counterparty' || invitation.max_claims !== 1 || invitation.expires_at !== session.expires_at || !/^[0-9a-f]{64}$/.test(invitation.token_hash)) invalid();
      envelope(state.invitation); keys(invitation, ['type','session_id','room_id','agreement_digest','fixture_digest','issuer','registrar_key','role','token_hash','max_claims','expires_at','parent_session_id','source_operation_id']);
      if (!Array.isArray(state.principals) || state.principals.length < 1 || state.principals.length > 2 || new Set(state.principals.map(p => p.key)).size !== state.principals.length || new Set(state.principals.map(p => p.side)).size !== state.principals.length) invalid();
      if (state.binding) {
        const binding = state.binding.payload;
        envelope(state.binding); keys(binding, ['type','session_id','room_id','invitation_digest','guest_key','name','issued_at','expires_at','claim']);
        if (!await verify(state.binding, this.#config.authorityKey) || binding.type !== 'scopeblind.coordination.negotiation-binding.v1' || binding.session_id !== sessionId || binding.room_id !== session.room_id || binding.invitation_digest !== state.invitation.digest || !await verify(binding.claim, binding.guest_key) || binding.claim.payload.session_id !== sessionId || binding.claim.payload.room_id !== session.room_id || binding.claim.payload.guest_key !== binding.guest_key || binding.guest_key === session.owner_key) invalid();
        envelope(binding.claim); keys(binding.claim.payload, ['type','session_id','room_id','guest_key','name','issued_at','nonce']);
      }
      for (const principal of state.principals) {
        keys(principal, ['side','key','name','mandate','agent_status']);
        if (principal.side === 'organizer' ? principal.key !== session.owner_key : principal.side !== 'partner' || principal.key !== state.binding?.payload.guest_key) invalid();
        if (principal.mandate) {
          humanEnvelope(principal.mandate);
          const mandate = principal.mandate.payload;
          keys(mandate, ['type','session_id','room_id','principal_key','version','agreement_digest','fixture_digest','min_threshold_minor','max_threshold_minor','min_budget_minor','max_budget_minor','required_invoices','private_brief_commitment','agent_mode','actions','issued_at','expires_at']);
          if (!await verifyHuman(principal.mandate, principal.key, {requireRecordedUse:true,authorityKey:this.#config.authorityKey}) || mandate.type !== 'scopeblind.coordination.negotiation-mandate.v1' || mandate.session_id !== sessionId || mandate.room_id !== session.room_id || mandate.principal_key !== principal.key || mandate.agreement_digest !== session.agreement_digest || mandate.fixture_digest !== session.fixture_digest ||
            canonical(mandate.actions) !== canonical(NEGOTIATION_AGENT_ACTIONS) || !Number.isSafeInteger(mandate.version) || mandate.version < 1 || !['hosted','own','manual'].includes(mandate.agent_mode) ||
            !Number.isSafeInteger(mandate.min_threshold_minor) || !Number.isSafeInteger(mandate.max_threshold_minor) || mandate.min_threshold_minor < 0 || mandate.max_threshold_minor < mandate.min_threshold_minor || mandate.max_threshold_minor > mandateBudget(mandate, agreement.budget_minor).max || !Array.isArray(mandate.required_invoices) || !/^[0-9a-f]{64}$/.test(mandate.private_brief_commitment)) invalid();
          if ((mandate.min_budget_minor === undefined) !== (mandate.max_budget_minor === undefined) || (mandate.min_budget_minor !== undefined && (!Number.isSafeInteger(mandate.min_budget_minor) || !Number.isSafeInteger(mandate.max_budget_minor) || mandate.min_budget_minor < 1 || mandate.max_budget_minor! < mandate.min_budget_minor || mandate.max_budget_minor! > 10000000))) invalid();
          if (!Number.isFinite(Date.parse(mandate.issued_at)) || !Number.isFinite(Date.parse(mandate.expires_at)) || Date.parse(mandate.expires_at) <= Date.parse(mandate.issued_at) || Date.parse(mandate.expires_at) > Date.parse(session.expires_at) || mandate.required_invoices.length > 2 || new Set(mandate.required_invoices.map(r => r.invoice_id)).size !== mandate.required_invoices.length) invalid();
          for (const required of mandate.required_invoices) { keys(required, ['invoice_id','expected']); if (!['allow','ask'].includes(required.expected) || !state.fixtures.invoices.some(invoice => invoice.invoice_id === required.invoice_id && !invoice.duplicate_of)) invalid(); }
        }
      }
      const own = state.principals.find(p => p.key === principalKey);
      keys(state.viewer, ['principal_key','side','brief','pairs','is_agent']);
      if (!own?.mandate || own.mandate.payload.agent_mode !== 'own' || state.viewer.principal_key !== principalKey || state.viewer.side !== own.side || state.viewer.is_agent !== true || !state.viewer.brief || await privateBriefCommitment(parseNegotiationBrief(state.viewer.brief)) !== own.mandate.payload.private_brief_commitment || !Array.isArray(state.viewer.pairs)) invalid();
      for (const pair of state.viewer.pairs) {
        keys(pair, ['pair_id','name','principal_key','session_id','status','code_expires_at','expires_at','agent_key','readiness','profile_bound']);
        if (pair.session_id !== sessionId || pair.principal_key !== principalKey || (pair.profile_bound !== undefined && pair.profile_bound !== true)) invalid();
        if (pair.readiness) { keys(pair.readiness, ['observed_at','context_digest']); if (!Number.isFinite(Date.parse(pair.readiness.observed_at)) || !/^[0-9a-f]{64}$/.test(pair.readiness.context_digest)) invalid(); }
      }
      if (typeof state.started !== 'boolean' || (state.runtime_changed !== undefined && typeof state.runtime_changed !== 'boolean')) invalid();
      if (!['waiting_partner','setting_limits','ready','working','waiting_agent','needs_decision','agreed','no_overlap','round_limit','failed','cancelled','adopted'].includes(state.status) || (state.next_principal_key !== undefined && !state.principals.some(p => p.key === state.next_principal_key))) invalid();
      if (!Array.isArray(state.proposals) || state.proposals.length > NEGOTIATION_MAX_PROPOSALS || !Array.isArray(state.responses) || !Array.isArray(state.reports) || !Array.isArray(state.approvals)) invalid();
      const mandates = ['organizer','partner'].map(side => state.principals.find(p => p.side === side)?.mandate);
      const mandateDigests = mandates.filter(Boolean).map(m => m!.digest);
      const agentBindings = state.agent_bindings ?? [];
      if (!Array.isArray(agentBindings) || agentBindings.length > 12) invalid();
      for (const signed of agentBindings) {
        envelope(signed); const b = signed.payload, auth = b.owner_authorization, q = auth?.payload;
        keys(b, ['type','pair_id','room_id','session_id','principal_key','agreement_digest','owner_key','agent_key','name','scope','audience','issued_at','expires_at','owner_authorization']);
        if (!await verify(signed, this.#config.authorityKey) || b.type !== 'scopeblind.coordination.agent-binding.v1' || b.audience !== 'scopeblind.coordination.negotiation' || b.session_id !== sessionId || b.room_id !== session.room_id || b.agreement_digest !== session.agreement_digest || b.owner_key !== b.principal_key || !state.principals.some(p => p.key === b.principal_key) || state.principals.some(p => p.key === b.agent_key) || canonical(b.scope) !== canonical(NEGOTIATION_AGENT_ACTIONS) || !await verify(auth, b.principal_key) || q.type !== 'scopeblind.coordination.request.v1' || q.action !== 'negotiation_pair_create' || q.room_id !== session.room_id || q.body.session_id !== sessionId || q.body.pair_id !== b.pair_id || q.body.token_expires_at !== b.expires_at || canonical(q.body.scope) !== canonical(NEGOTIATION_AGENT_ACTIONS)) invalid();
        envelope(auth); keys(q, ['type','action','room_id','body','issued_at','nonce']); keys(q.body, ['session_id','pair_id','secret_hash','name','expires_at','token_expires_at','scope','expected_agent_key']);
        if (q.body.expected_agent_key !== undefined && q.body.expected_agent_key !== b.agent_key) invalid();
        if (!/^[0-9a-f]{64}$/.test(b.agent_key) || !Number.isFinite(Date.parse(b.issued_at)) || Date.parse(b.expires_at) <= Date.parse(b.issued_at) || Date.parse(b.expires_at) > Date.parse(session.expires_at) || agentBindings.some(other => other.payload.agent_key === b.agent_key && other.payload.principal_key !== b.principal_key)) invalid();
      }
      const actorBound = (record: { principal_key: string; agent_key?: string; agent_mode: string; issued_at: string }) => {
        const mandate = state.principals.find(p => p.key === record.principal_key)?.mandate?.payload;
        if (!mandate || !Number.isFinite(Date.parse(record.issued_at)) || Date.parse(record.issued_at) >= Date.parse(mandate.expires_at)) return false;
        if (record.agent_mode === 'manual') return record.agent_key === undefined;
        if (record.agent_mode === 'hosted') return mandate.agent_mode === 'hosted' && record.agent_key === undefined;
        return record.agent_mode === 'own' && mandate.agent_mode === 'own' && agentBindings.some(b => b.payload.agent_key === record.agent_key && b.payload.principal_key === record.principal_key && Date.parse(record.issued_at) >= Date.parse(b.payload.issued_at) && Date.parse(record.issued_at) < Date.parse(b.payload.expires_at));
      };
      for (let index = 0; index < state.proposals.length; index++) {
        const signed = state.proposals[index], proposal = signed.payload;
        envelope(signed); keys(proposal, ['type','id','approval_above_minor','budget_minor','exploration','parent_digest','session_id','room_id','round','principal_key','agent_key','agent_mode','agreement_digest','fixture_digest','mandate_digests','next_agreement','next_agreement_digest','reviewer_grant','reviewer_grant_digest','issued_at']);
        if (!actorBound(proposal) || !await verify(signed, this.#config.authorityKey) || proposal.type !== 'scopeblind.coordination.negotiation-proposal.v1' || proposal.session_id !== sessionId || proposal.room_id !== session.room_id || proposal.round !== index + 1 || proposal.agreement_digest !== session.agreement_digest || proposal.fixture_digest !== session.fixture_digest || mandateDigests.length !== 2 || canonical(proposal.mandate_digests) !== canonical(mandateDigests) || !state.principals.some(p => p.key === proposal.principal_key) ||
          !Number.isSafeInteger(proposal.approval_above_minor) || proposal.approval_above_minor < 0 || proposal.approval_above_minor > (proposal.budget_minor ?? agreement.budget_minor) || proposal.next_agreement?.approval_above_minor !== proposal.approval_above_minor || await negotiationPayloadDigest(proposal.next_agreement) !== proposal.next_agreement_digest || (index === 0 ? proposal.parent_digest !== undefined : proposal.parent_digest !== state.proposals[index - 1].digest)) invalid();
      }
      if (state.selected_proposal_digest !== undefined && !state.proposals.some(p => p.digest === state.selected_proposal_digest)) invalid();
      for (const { payload: p } of state.proposals) {
        const g = p.reviewer_grant;
        const authorMandate = state.principals.find(principal => principal.key === p.principal_key)!.mandate!.payload;
        if (!negotiationPlanWithinMandate(authorMandate, p.approval_above_minor, p.budget_minor ?? agreement.budget_minor, agreement.budget_minor) || (p.exploration !== undefined && (p.exploration !== true || p.agent_mode !== 'manual'))) invalid();
        keys(g, ['type','grant_id','room_id','agreement_digest','issuer','registrar_key','role','actions','expires_at','token_hash','max_claims']);
        if (canonical(p.next_agreement) !== canonical({ ...agreement, id: p.next_agreement.id, issued_at: p.issued_at, approval_above_minor: p.approval_above_minor, budget_minor: p.budget_minor ?? agreement.budget_minor }) || p.next_agreement.id === agreement.id || g.type !== 'scopeblind.coordination.grant.v1' || g.room_id !== p.next_agreement.id || g.agreement_digest !== p.next_agreement_digest || g.issuer !== agreement.owner_key || g.registrar_key !== this.#config.authorityKey || g.role !== 'reviewer' || canonical(g.actions) !== canonical(['decide','accept']) || g.max_claims !== 1 || g.expires_at !== session.expires_at || await negotiationPayloadDigest(g) !== p.reviewer_grant_digest) invalid();
      }
      for (const signed of state.responses) {
        const response = signed.payload;
        envelope(signed); keys(response, ['type','session_id','principal_key','proposal_digest','mandate_digest','decision','agent_key','agent_mode','issued_at']);
        if (!actorBound(response) || !await verify(signed, this.#config.authorityKey) || response.type !== 'scopeblind.coordination.negotiation-response.v1' || response.session_id !== sessionId || !['support','no_agreement'].includes(response.decision) || !state.proposals.some(p => p.digest === response.proposal_digest) || state.principals.find(p => p.key === response.principal_key)?.mandate?.digest !== response.mandate_digest) invalid();
      }
      for (const signed of state.reports) {
        const report = signed.payload;
        envelope(signed); keys(report, ['type','session_id','room_id','proposal_digest','agreement_digest','fixture_digest','mandate_digests','cases_digest','runtime_revision','adapter','isolation','issued_at','before_approval_above_minor','after_approval_above_minor','before_budget_minor','after_budget_minor','results','required_passed','expectations_met','mandates_met']);
        if (!await verify(signed, this.#config.authorityKey) || report.type !== 'scopeblind.coordination.negotiation-report.v1' || report.session_id !== sessionId || report.room_id !== session.room_id || report.agreement_digest !== session.agreement_digest || report.fixture_digest !== session.fixture_digest || canonical(report.mandate_digests) !== canonical(mandateDigests) || !state.proposals.some(p => p.digest === report.proposal_digest) || report.adapter !== 'coordination-d1-sandbox' || report.isolation !== 'separate-fixture-ledgers') invalid();
      }
      for (const signed of state.approvals) {
        const approval = signed.payload;
        humanEnvelope(signed); keys(approval, ['type','session_id','principal_key','proposal_digest','report_digest','next_agreement_digest','mandate_digests','decision','issued_at','expires_at','selection_basis']);
        if (!state.principals.some(p => p.key === approval.principal_key) || !await verifyHuman(signed, approval.principal_key, {proposal:state.proposals.find(p=>p.digest===approval.proposal_digest),requireRecordedUse:true,authorityKey:this.#config.authorityKey}) || approval.type !== 'scopeblind.coordination.negotiation-approval.v1' || approval.session_id !== sessionId || !['approve','reject'].includes(approval.decision) || canonical(approval.mandate_digests) !== canonical(mandateDigests) || !state.reports.some(r => r.digest === approval.report_digest && r.payload.proposal_digest === approval.proposal_digest) || !state.proposals.some(p => p.digest === approval.proposal_digest && p.payload.next_agreement_digest === approval.next_agreement_digest)) invalid();
      }
      if (state.run) {
        keys(state.run, ['proposal_digest','status','completed_cases','total_cases','error']);
        const total = mandateDigests.length === 2 ? mandateCases(mandates as NonNullable<typeof mandates[number]>[], state.fixtures).length : 0;
        if (!state.proposals.some(p => p.digest === state.run!.proposal_digest) || !['running','completed','failed'].includes(state.run.status) || !Number.isSafeInteger(state.run.completed_cases) || state.run.completed_cases < 0 || state.run.total_cases !== total || state.run.completed_cases > total) invalid();
      }
      // Optional diagnostic fields are codes, never raw backend/model messages.
      if (state.error !== undefined && !/^[a-z_]{3,80}$/.test(state.error)) invalid();
      if (state.run?.error !== undefined && !/^[a-z_]{3,80}$/.test(state.run.error)) invalid();
      return state;
    } catch (error) { if (error instanceof CoordinationError) throw error; return invalid(); }
  }

  private async negotiationResult(response: Record<string, unknown>): Promise<Record<string, unknown>> {
    const negotiation = await this.checkedNegotiation(response);
    let evidenceVerification;
    if (response.evidence !== undefined) {
      const evidence = response.evidence as NegotiationExport;
      evidenceVerification = await verifyNegotiationEvidence(evidence, this.#config.authorityKey);
      if (!evidenceVerification.valid || evidence.session?.digest !== negotiation.session.digest || !negotiation.reports.some(report => report.digest === evidence.report?.digest)) throw new CoordinationError('invalid_negotiation_evidence', 'The exact negotiation comparison evidence could not be verified. Do not treat it as a passing agreement or approval.');
    }
    return { negotiation, state_digest: await negotiationDigest(negotiation), ...(response.evidence !== undefined ? { evidence: response.evidence, evidence_verification: evidenceVerification } : {}), signatures_verified: true,
      scope: 'One principal’s bounded negotiation. Its own private brief is for this agent only. Public proposals and signed mandate constraints are shared. The gate operator records isolated test observations; these are not independent execution observation or payment authority. Support is an agent recommendation, not a human approval.',
      next_steps: negotiation.runtime_changed ? ['These signed records remain historical evidence. Ask the people to start a fresh linked discussion for the current runtime; prior mandates and approvals do not carry over.'] : ['Keep the private brief private. Work within your principal’s signed limits; at most three candidates exist per session. Compare the exact supported candidate, stop on no agreement, and leave approval and adoption to both people.'] };
  }

  async inspectNegotiation(reportDigest?: string, signal?: AbortSignal): Promise<Record<string, unknown>> {
    const { sessionId } = this.negotiationConfig();
    if (reportDigest !== undefined && (typeof reportDigest !== 'string' || !/^[0-9a-f]{64}$/.test(reportDigest))) throw new CoordinationError('invalid_input', 'report_digest must name an exact negotiation report.');
    const response = await this.#transport.post('negotiation_get', { session_id: sessionId, ...(reportDigest ? { report_digest: reportDigest } : {}) }, signal);
    if (reportDigest && (response.evidence as NegotiationExport | undefined)?.report?.digest !== reportDigest) throw new CoordinationError('invalid_negotiation_evidence', 'The requested exact report was not returned.');
    const result = await this.negotiationResult(response);
    const state = result.negotiation as NegotiationState;
    const mandate = state.principals.find(principal => principal.key === this.#config.principalKey)!.mandate!;
    if (!state.runtime_changed) await this.acknowledgeInspection(response, 'negotiation_get', mandate.digest, signal);
    return result;
  }

  async proposeCandidate(value: NegotiationProposalInput): Promise<Record<string, unknown>> {
    const { sessionId, principalKey } = this.negotiationConfig();
    if (!value || Object.keys(value).some(key => !['id','approval_above_minor','budget_minor','parent_digest'].includes(key)) || typeof value.id !== 'string' || !/^[A-Za-z0-9_-]{1,80}$/.test(value.id) || !Number.isSafeInteger(value.approval_above_minor) || value.approval_above_minor < 0 || value.approval_above_minor > 10_000_000 || (value.budget_minor !== undefined && (!Number.isSafeInteger(value.budget_minor) || value.budget_minor < 1 || value.budget_minor > 10_000_000)) || (value.parent_digest !== undefined && !/^[0-9a-f]{64}$/.test(value.parent_digest))) throw new CoordinationError('invalid_input', 'Provide a stable candidate id, a threshold and optional total budget in USD cents, and the current parent_digest for a counterproposal. Private notes and additional powers are not accepted.');
    const proposal = { ...value };
    const result = await this.inspectNegotiation(), before = result.negotiation as NegotiationState;
    if (before.runtime_changed) throw new CoordinationError('negotiation_runtime_changed', 'This discussion belongs to an earlier runtime. Ask the people to start a fresh linked discussion; do not reuse its mandate.');
    const existing = before.proposals.find(p => p.payload.id === proposal.id);
    if (existing) {
      if (existing.payload.principal_key !== principalKey || existing.payload.approval_above_minor !== proposal.approval_above_minor || (existing.payload.budget_minor ?? before.agreement.payload.budget_minor) !== (proposal.budget_minor ?? before.agreement.payload.budget_minor) || existing.payload.exploration !== undefined || existing.payload.parent_digest !== proposal.parent_digest) throw new CoordinationError('negotiation_id_conflict', 'This stable candidate id already names different terms. Inspect it before proposing anything else.');
      return result;
    }
    const own = before.principals.find(p => p.key === principalKey)!.mandate!.payload;
    if (Date.parse(own.expires_at) <= Date.now() || Date.parse(before.session.payload.expires_at) <= Date.now()) throw new CoordinationError('negotiation_expired', 'This session or your signed mandate has expired. Ask your principal to review it.');
    if (before.proposals.length >= NEGOTIATION_MAX_PROPOSALS) throw new CoordinationError('negotiation_round_limit', 'The three-candidate limit has been reached. Stop and explain the remaining disagreement to your principal.');
    if (['needs_decision','agreed','no_overlap','round_limit','failed','cancelled','adopted'].includes(before.status) || before.next_principal_key !== principalKey) throw new CoordinationError('negotiation_not_your_turn', 'This session does not currently invite your agent to propose. Inspect its status; leave human decisions to the people.');
    if (!negotiationPlanWithinMandate(own, proposal.approval_above_minor, proposal.budget_minor ?? before.agreement.payload.budget_minor, before.agreement.payload.budget_minor) || proposal.parent_digest !== before.proposals.at(-1)?.digest) throw new CoordinationError('invalid_candidate', 'The candidate must fit your signed range and name the current parent candidate.');
    for (const requirement of own.required_invoices) {
      const invoice = before.fixtures.invoices.find(invoice => invoice.invoice_id === requirement.invoice_id)!;
      const budget = proposal.budget_minor ?? before.agreement.payload.budget_minor;
      const matching = !before.agreement.payload.require_po_match || before.fixtures.purchase_orders.some(po => po.id === invoice.purchase_order_id && po.vendor === invoice.vendor && po.destination === invoice.destination && po.amount_minor === invoice.amount_minor && po.currency === 'USD');
      const expected = invoice.amount_minor > budget || !before.agreement.payload.allowed_destinations.includes(invoice.destination) ? 'refuse' : !matching || invoice.amount_minor > proposal.approval_above_minor ? 'ask' : 'allow';
      if (expected !== requirement.expected) throw new CoordinationError('invalid_candidate', 'The candidate does not meet your principal’s required invoice decision.');
    }
    const response = await this.#transport.post('negotiation_propose', { session_id: sessionId, proposal });
    const checked = await this.negotiationResult(response), after = checked.negotiation as NegotiationState;
    if (!after.proposals.some(p => p.payload.id === proposal.id && p.payload.principal_key === principalKey && p.payload.approval_above_minor === proposal.approval_above_minor && (p.payload.budget_minor ?? before.agreement.payload.budget_minor) === (proposal.budget_minor ?? before.agreement.payload.budget_minor) && p.payload.exploration === undefined && p.payload.parent_digest === proposal.parent_digest)) throw new CoordinationError('invalid_negotiation', 'The service did not record the exact candidate submitted. Inspect before retrying with the same id.');
    return checked;
  }

  async respondCandidate(value: { proposal_digest: string; decision: 'support' | 'no_agreement' }): Promise<Record<string, unknown>> {
    const { sessionId, principalKey } = this.negotiationConfig();
    if (!value || Object.keys(value).sort().join(',') !== 'decision,proposal_digest' || !/^[0-9a-f]{64}$/.test(value.proposal_digest) || !['support','no_agreement'].includes(value.decision)) throw new CoordinationError('invalid_input', 'Respond only support or no_agreement to an exact proposal_digest. A response does not approve or adopt it.');
    const submitted = { ...value };
    const response = await this.#transport.post('negotiation_respond', { session_id: sessionId, ...submitted });
    const result = await this.negotiationResult(response), state = result.negotiation as NegotiationState;
    if (!state.responses.some(r => r.payload.principal_key === principalKey && r.payload.proposal_digest === submitted.proposal_digest && r.payload.decision === submitted.decision)) throw new CoordinationError('invalid_negotiation', 'The returned record does not contain your exact response. Inspect before retrying.');
    return result;
  }

  async compareCandidate(value: { proposal_digest: string }, signal?: AbortSignal): Promise<Record<string, unknown>> {
    const { sessionId } = this.negotiationConfig();
    if (!value || Object.keys(value).join(',') !== 'proposal_digest' || !/^[0-9a-f]{64}$/.test(value.proposal_digest)) throw new CoordinationError('invalid_input', 'Compare takes only the exact supported proposal_digest. It cannot adopt or approve a proposal.');
    const proposalDigest = value.proposal_digest;
    const abort = new AbortController(), cancel = () => abort.abort();
    if (signal?.aborted) cancel(); else signal?.addEventListener('abort', cancel, { once: true });
    const deadline = performance.now() + 180_000, timer = setTimeout(cancel, 180_000);
    let latest: Record<string, unknown> | undefined, completedCases = 0, advancingChunks = 0, busyWaits = 0;
    const pending = () => ({ ...latest, comparison_status: 'pending', proposal_digest: proposalDigest, ...(signal?.aborted ? { cancelled: true } : {}), next_steps: ['No verified final comparison is available yet. Inspect negotiation status, then resume compare_candidate with the SAME proposal_digest. The server retains its fixed test identity and completed chunks. No approval, payment, or adoption occurred.'] });
    try {
      while (!abort.signal.aborted && performance.now() < deadline && advancingChunks < 8) {
        let response: Record<string, unknown>;
        try { response = await this.#transport.post('negotiation_compare', { session_id: sessionId, proposal_digest: proposalDigest }, abort.signal); }
        catch (error) { if (error instanceof CoordinationError && ['negotiation_in_progress','rehearsal_in_progress'].includes(error.code) && busyWaits++ < 6) { await waitDelay(1000, abort.signal); continue; } throw error; }
        latest = await this.negotiationResult(response);
        const state = latest.negotiation as NegotiationState;
        const report = state.reports.find(report => report.payload.proposal_digest === proposalDigest);
        if (report) {
          if ((response.evidence as NegotiationExport | undefined)?.report?.digest !== report.digest) latest = await this.inspectNegotiation(report.digest, abort.signal);
          return { ...latest, comparison_status: 'completed', proposal_digest: proposalDigest };
        }
        const run = state.run;
        if (!run || run.proposal_digest !== proposalDigest || run.status !== 'running') throw new CoordinationError('invalid_negotiation', 'The comparison did not return a matching checkpoint or verified report. Inspect before resuming the same candidate.');
        if (run.completed_cases <= completedCases) { if (busyWaits++ >= 6) return pending(); await waitDelay(1000, abort.signal); }
        else { completedCases = run.completed_cases; advancingChunks++; }
      }
      return pending();
    } catch (error) {
      if (abort.signal.aborted || error instanceof CoordinationError && ['negotiation_in_progress','rehearsal_in_progress'].includes(error.code)) return pending();
      if (error instanceof CoordinationError && error.code === 'service_unavailable') throw new CoordinationError('negotiation_outcome_unknown', 'The comparison response was lost or timed out. Inspect and resume the SAME proposal_digest; do not create another candidate or assume the test failed. No approval or adoption was requested.');
      throw error;
    } finally { clearTimeout(timer); signal?.removeEventListener('abort', cancel); }
  }

  async waitNegotiation(value: { after_digest?: string; timeout_ms?: number }, signal?: AbortSignal): Promise<Record<string, unknown>> {
    this.negotiationConfig();
    if (!value || Object.keys(value).some(key => !['after_digest','timeout_ms'].includes(key)) || value.after_digest !== undefined && !/^[0-9a-f]{64}$/.test(value.after_digest)) throw new CoordinationError('invalid_wait', 'Use the state_digest from inspect_negotiation as after_digest, with an optional timeout_ms.');
    const timeoutMs = value.timeout_ms ?? 30_000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30_000) throw new CoordinationError('invalid_wait', 'timeout_ms must be an integer from 1000 to 30000.');
    const abort = new AbortController(), cancel = () => abort.abort();
    if (signal?.aborted) cancel(); else signal?.addEventListener('abort', cancel, { once: true });
    const deadline = performance.now() + timeoutMs; let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; abort.abort(); }, timeoutMs);
    let latest: Record<string, unknown> | undefined;
    const result = (waitStatus: string) => ({ ...latest, wait_status: waitStatus });
    try {
      for (;;) {
        if (abort.signal.aborted) throw new CoordinationError('cancelled', 'The negotiation wait was cancelled.');
        latest = await this.inspectNegotiation(undefined, abort.signal);
        const state = latest.negotiation as NegotiationState;
        if (state.runtime_changed) return result('blocked');
        if (['agreed','adopted'].includes(state.status)) return result('completed');
        if (['no_overlap','round_limit','failed','cancelled'].includes(state.status)) return result('blocked');
        if (state.status === 'needs_decision') return result('awaiting_human_decision');
        if (state.next_principal_key === this.#config.principalKey) return result('action_required');
        if (value.after_digest && latest.state_digest !== value.after_digest) return result('changed');
        const remaining = deadline - performance.now();
        if (remaining <= 0) return result('waiting');
        const finalInterval = remaining <= 2000;
        await waitDelay(Math.min(2000, remaining), abort.signal);
        if (finalInterval || timedOut || performance.now() >= deadline) return result('waiting');
      }
    } catch (error) {
      if (!signal?.aborted && timedOut && error instanceof CoordinationError && error.code === 'cancelled') {
        if (latest) return result('waiting');
        throw new CoordinationError('wait_timeout', 'No current negotiation state was retrieved before the timeout. Inspect before retrying.');
      }
      throw error;
    } finally { clearTimeout(timer); signal?.removeEventListener('abort', cancel); }
  }

  private async checkedRehearsal(response: Record<string, unknown>): Promise<{ agreement: Signed<Agreement>; fixtures: InvoiceFixtures; rehearsal: RehearsalState }> {
    const agreement = response.agreement as Signed<Agreement>, fixtures = response.fixtures as InvoiceFixtures, rehearsal = response.rehearsal as RehearsalState;
    if (response.room_id !== this.#config.roomId || response.authority_key !== this.#config.authorityKey ||
      !agreement || agreement.payload?.type !== 'scopeblind.coordination.agreement.v1' || agreement.payload.id !== this.#config.roomId ||
      agreement.payload.registrar_key !== this.#config.authorityKey || !await verifyOwnerAgreement(agreement, response.source_negotiation as NegotiationExport | undefined) ||
      !fixtures || !rehearsal || rehearsal.agreement_digest !== agreement.digest ||
      rehearsal.fixture_digest !== await rehearsalDigest(fixtures) || !Array.isArray(rehearsal.cases) || rehearsal.cases_digest !== await rehearsalDigest(rehearsal.cases)) {
      throw new CoordinationError('invalid_rehearsal', 'The rehearsal source agreement, sample records, or case snapshot could not be verified against the pinned authority.');
    }
    if (!Array.isArray(rehearsal.proposals) || !Array.isArray(rehearsal.reports)) throw new CoordinationError('invalid_rehearsal', 'The rehearsal record is incomplete.');
    for (const proposal of rehearsal.proposals) {
      if (!await verify(proposal, this.#config.authorityKey) || proposal.payload.type !== 'scopeblind.coordination.repair-proposal.v1' || proposal.payload.room_id !== this.#config.roomId || proposal.payload.agreement_digest !== agreement.digest) {
        throw new CoordinationError('invalid_rehearsal', 'A proposed repair does not verify against this source agreement and the pinned authority.');
      }
    }
    for (const report of rehearsal.reports) {
      if (!await verify(report, this.#config.authorityKey) || report.payload.type !== 'scopeblind.coordination.rehearsal-report.v1' || report.payload.room_id !== this.#config.roomId || report.payload.agreement_digest !== agreement.digest) {
        throw new CoordinationError('invalid_rehearsal', 'A rehearsal report does not verify against this source agreement and the pinned authority.');
      }
    }
    return { agreement, fixtures, rehearsal };
  }

  private async rehearsalResult(response: Record<string, unknown>): Promise<Record<string, unknown>> {
    const source = await this.checkedRehearsal(response);
    if (response.proposal && !source.rehearsal.proposals.some(p => canonical(p) === canonical(response.proposal))) throw new CoordinationError('invalid_rehearsal', 'The returned proposal is absent from the verified rehearsal record.');
    if (response.report && !source.rehearsal.reports.some(r => canonical(r) === canonical(response.report))) throw new CoordinationError('invalid_rehearsal', 'The returned report is absent from the verified rehearsal record.');
    let evidenceVerification;
    if (response.evidence !== undefined) {
      const evidence = response.evidence as RehearsalExport;
      evidenceVerification = await verifyRehearsalEvidence(evidence, this.#config.authorityKey);
      if (!evidenceVerification.valid || evidence.agreement.digest !== source.agreement.digest || (response.report && canonical(evidence.report) !== canonical(response.report))) throw new CoordinationError('invalid_rehearsal_evidence', 'The isolated test evidence could not be verified. No authority has been activated.');
    }
    return { room_id: this.#config.roomId, ...source, ...(response.run ? { run: response.run } : {}), ...(response.proposal ? { proposal: response.proposal } : {}), ...(response.report ? { report: response.report } : {}),
      ...(response.evidence ? { evidence: response.evidence, evidence_verification: evidenceVerification } : {}),
      source_signature_verified: true,
      scope: 'Test-only coordination. The named gate operator attests to observed outcomes in separate sample ledgers. Signed records establish integrity, not proof for every input or independent execution observation. Proposals do not change this agreement or authorize payments; adoption belongs to the owner.',
      next_steps: ['Inspect cases and their human expectations. Keep stable IDs for retries. Compare a proposed repair against required safety cases. Explain the observed tradeoffs; leave adoption to the owner.'],
    };
  }

  async inspectRehearsal(reportDigest?: string): Promise<Record<string, unknown>> {
    if (reportDigest !== undefined && (typeof reportDigest !== 'string' || !/^[0-9a-f]{64}$/.test(reportDigest))) throw new CoordinationError('invalid_input', 'report_digest must identify an exact signed rehearsal report.');
    const response = await this.#transport.post('rehearsal_get', reportDigest ? { report_digest: reportDigest } : {});
    if (reportDigest && (response.evidence as RehearsalExport | undefined)?.report?.digest !== reportDigest) throw new CoordinationError('invalid_rehearsal_evidence', 'The returned evidence does not identify the requested report.');
    const result = await this.rehearsalResult(response);
    await this.acknowledgeInspection(response, 'rehearsal_get', (result.agreement as Signed<Agreement>).digest);
    return result;
  }

  async proposeCase(value: RehearsalCase): Promise<Record<string, unknown>> {
    let testCase: RehearsalCase;
    try {
      if (value && ('required' in value || value.id?.startsWith('required-'))) throw new Error();
      testCase = parseRehearsalCase(value);
    } catch { throw new CoordinationError('invalid_input', 'Provide a bounded case with a stable id and explicit expectation. The required safety cases are reserved and cannot be reassigned.'); }
    const response = await this.#transport.post('rehearsal_case', { case: testCase });
    const result = await this.rehearsalResult(response);
    if (![...(response.rehearsal as RehearsalState).cases, ...((response.rehearsal as RehearsalState).excluded_cases || [])].some(c => canonical(c) === canonical(testCase))) throw new CoordinationError('invalid_rehearsal', 'The returned cases do not contain the exact submitted expectation.');
    return result;
  }

  async proposeRepair(value: RepairProposalInput): Promise<Record<string, unknown>> {
    let snapshot: RepairProposalInput;
    try { snapshot = parseRepairProposal(value, 10_000_000); } catch { throw new CoordinationError('invalid_input', 'Provide only a stable id, review threshold in USD cents, and a rationale of at most 600 characters.'); }
    const before = await this.checkedRehearsal(await this.#transport.post('rehearsal_get', {}));
    let proposal: RepairProposalInput;
    try { proposal = parseRepairProposal(snapshot, before.agreement.payload.budget_minor); }
    catch { throw new CoordinationError('invalid_input', 'Propose only a review threshold within the source budget, a stable id, and a rationale of at most 600 characters.'); }
    const response = await this.#transport.post('rehearsal_propose', { proposal });
    const result = await this.rehearsalResult(response);
    const recorded = response.proposal as RehearsalState['proposals'][number] | undefined;
    if (!recorded || recorded.payload.id !== proposal.id || recorded.payload.approval_above_minor !== proposal.approval_above_minor || recorded.payload.rationale !== proposal.rationale) throw new CoordinationError('invalid_rehearsal', 'The signed repair does not match the exact proposed threshold and rationale.');
    return result;
  }

  async runRehearsal(value: { id: string; proposal_id?: string }, signal?: AbortSignal): Promise<Record<string, unknown>> {
    if (!value || Object.keys(value).some(k => !['id','proposal_id'].includes(k)) || typeof value.id !== 'string' || !/^[A-Za-z0-9_-]{1,80}$/.test(value.id) ||
      (value.proposal_id !== undefined && (typeof value.proposal_id !== 'string' || !/^[A-Za-z0-9_-]{1,80}$/.test(value.proposal_id)))) throw new CoordinationError('invalid_input', 'Use a stable test id and optional exact proposal_id. Retain the same id if the response is lost.');
    const snapshot = { ...value }, abort = new AbortController(), cancel = () => abort.abort();
    if (signal?.aborted) cancel(); else signal?.addEventListener('abort', cancel, { once: true });
    const deadline = performance.now() + 180_000, timer = setTimeout(cancel, 180_000);
    let latest: Record<string, unknown> | undefined, chunks = 0, busyWaits = 0, completedCases = 0;
    const pending = () => ({ ...latest, status: 'pending', run: latest?.run || { id: snapshot.id, status: 'unknown' },
      ...(signal?.aborted ? { cancelled: true } : {}),
      next_steps: [`The comparison has no verified final report yet. Inspect rehearsal progress, then resume coordination.run_rehearsal with the SAME id '${snapshot.id}'${snapshot.proposal_id ? ` and proposal_id '${snapshot.proposal_id}'` : ''}. Completed case chunks are retained; do not create a replacement test id. No source payment or rule change was authorized.`] });
    try {
      while (chunks < 6 && performance.now() < deadline && !abort.signal.aborted) {
        let response: Record<string, unknown>;
        try { response = await this.#transport.post('rehearsal_run', snapshot, abort.signal); }
        catch (error) {
          if (error instanceof CoordinationError && error.code === 'rehearsal_in_progress' && busyWaits++ < 6) { await waitDelay(1000, abort.signal); continue; }
          throw error;
        }
        latest = await this.rehearsalResult(response);
        const report = response.report as RehearsalState['reports'][number] | undefined;
        if (report) {
          const proposal = (response.rehearsal as RehearsalState).proposals.find(p => p.payload.id === snapshot.proposal_id);
          if (report.payload.id !== snapshot.id || (snapshot.proposal_id ? !proposal || report.payload.proposal_digest !== proposal.digest : report.payload.proposal_digest !== undefined)) throw new CoordinationError('invalid_rehearsal', 'The report does not match the requested test ID and proposal.');
          if (!response.evidence) {
            const historical = await this.#transport.post('rehearsal_get', { report_digest: report.digest }, abort.signal);
            if ((historical.evidence as RehearsalExport | undefined)?.report?.digest !== report.digest) throw new CoordinationError('invalid_rehearsal_evidence', 'The completed report’s exact evidence snapshot could not be retrieved.');
            latest = { ...await this.rehearsalResult(historical), report };
          }
          return { ...latest, status: 'completed' };
        }
        const run = response.run as Record<string, unknown> | undefined;
        if (!run || run.id !== snapshot.id || run.status !== 'running' || !Number.isSafeInteger(run.completed_cases) || !Number.isSafeInteger(run.total_cases) || Number(run.completed_cases) < 0 || Number(run.completed_cases) > Number(run.total_cases) || Number(run.total_cases) < 1 || Number(run.total_cases) > 10) {
          throw new CoordinationError('invalid_rehearsal', 'The service did not return a usable test checkpoint or final report. Inspect before resuming the same test id.');
        }
        if (Number(run.completed_cases) <= completedCases) {
          if (busyWaits++ >= 6) return pending();
          await waitDelay(1000, abort.signal);
        } else { completedCases = Number(run.completed_cases); chunks++; }
      }
      return pending();
    } catch (error) {
      if (abort.signal.aborted || (error instanceof CoordinationError && error.code === 'rehearsal_in_progress')) return pending();
      if (error instanceof CoordinationError && error.code === 'service_unavailable') throw new CoordinationError('rehearsal_outcome_unknown', 'The test response was lost or timed out. Inspect reports and retry with the SAME test id to recover its result. Do not assume failure or create another test id. No source payment or rule change was authorized.');
      throw error;
    } finally { clearTimeout(timer); signal?.removeEventListener('abort', cancel); }
  }

  private async room(signal?: AbortSignal): Promise<RoomView> {
    const response = await this.#transport.post('inspect', {}, signal);
    const room = response.room as RoomView;
    const agreement = room?.agreement;
    if (!room || room.room_id !== this.#config.roomId || typeof room.run_id !== 'string' || room.authority_key !== this.#config.authorityKey ||
        !agreement || agreement.payload?.type !== 'scopeblind.coordination.agreement.v1' || agreement.payload.id !== this.#config.roomId ||
        agreement.payload.version !== 1 || agreement.payload.currency !== 'USD' || !/^[0-9a-f]{64}$/.test(agreement.payload.owner_key) ||
        agreement.payload.registrar_key !== this.#config.authorityKey || !await verifyOwnerAgreement(agreement, room.negotiation_evidence)) {
      throw new CoordinationError('invalid_agreement', 'The room agreement or its pinned registrar binding could not be verified.');
    }
    if (room.run_id !== `run-${room.room_id}`) {
      const revisions = room.attempts || [];
      let prior = `run-${room.room_id}`;
      for (const attempt of revisions) {
        const r = attempt.revision;
        if (!r || !await verify(r, this.#config.authorityKey) || r.payload.type !== 'scopeblind.coordination.revision.v1' || r.payload.room_id !== room.room_id || r.payload.previous_run_id !== prior || r.payload.previous_manifest_digest !== attempt.manifest.digest || attempt.manifest.payload.room_id !== room.room_id || attempt.manifest.payload.run_id !== prior || r.payload.requested_by !== agreement.payload.owner_key || r.payload.agreement_digest !== agreement.digest || !await verify(attempt.manifest, this.#config.authorityKey)) throw new CoordinationError('invalid_revision', 'The signed chain of authorized result revisions could not be verified.');
        prior = r.payload.run_id;
      }
      if (prior !== room.run_id) throw new CoordinationError('invalid_revision', 'The current run does not follow the signed revision history.');
    }
    if (this.#config.runId && room.run_id !== this.#config.runId) throw new CoordinationError('run_mismatch', 'The configured run does not match this room.');
    await this.acknowledgeInspection(response, 'inspect', agreement.digest, signal);
    return room;
  }

  /** Live room state is informational; only signed artifacts establish signed claims. */
  async inspect(): Promise<Record<string, unknown>> {
    const room = await this.room();
    return {
      room_id: room.room_id, run_id: room.run_id, cursor: room.revision, agreement: room.agreement,
      authority_key: this.#config.authorityKey, paused: room.paused,
      budget: room.budget, invoices: room.invoices, operations: room.operations,
      fixtures: room.fixtures, historical_operations: room.historical_operations, revision_note: room.revision_note,
      result: room.manifest, acceptance: room.acceptances,
      next_steps: room.manifest ? ['Result is delivered. Wait for recipient acceptance or an owner-authorized revision.'] : room.paused ? ['Wait for the owner to resume.'] : ['Inspect invoices and purchase orders. Reuse operation IDs for retries. Await a reviewer for held requests; continue other permitted work. Deliver when all items have a recorded disposition.'],
      agreement_signature_verified: true,
      scope: 'Sample ledger only. No real money moves. Budget and operation lists are service-reported state; ledger.pay verifies each exact admission and outcome independently.',
    };
  }

  /** Poll inside the tool, without model calls, for at most thirty seconds. */
  async wait(input: CoordinationWait, signal?: AbortSignal): Promise<Record<string, unknown>> {
    if (!input || Object.keys(input).some(key => !['after_cursor', 'run_id', 'timeout_ms'].includes(key)) ||
      !Number.isSafeInteger(input.after_cursor) || input.after_cursor < 0 ||
      (input.run_id !== undefined && (typeof input.run_id !== 'string' || !/^run-[A-Za-z0-9_-]{8,100}$/.test(input.run_id)))) {
      throw new CoordinationError('invalid_wait', 'Pass after_cursor and optionally run_id from coordination.inspect.');
    }
    const timeoutMs = input.timeout_ms === undefined ? 30_000 : input.timeout_ms;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30_000) throw new CoordinationError('invalid_wait', 'timeout_ms must be an integer from 1000 to 30000.');
    const abort = new AbortController(), cancel = () => abort.abort();
    if (signal?.aborted) cancel(); else signal?.addEventListener('abort', cancel, { once: true });
    const deadline = performance.now() + timeoutMs;
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; abort.abort(); }, timeoutMs);
    let latest: RoomView | undefined;
    const response = (room: RoomView, status: 'changed' | 'waiting') => {
      const operations = room.operations || [];
      const ready = operations.filter(op => op.status === 'admitted' || (op.status === 'held' && op.decision?.payload.decision === 'approve' && Date.parse(op.decision.payload.expires_at) > Date.now())).map(op => op.operation_id);
      return {
        status, cursor: room.revision, run_id: room.run_id, paused: room.paused, result_ready: !!room.manifest,
        attention: {
          ready_to_retry: ready,
          awaiting_reviewer: operations.filter(op => op.status === 'held' && !ready.includes(op.operation_id)).map(op => op.operation_id),
          changes_requested: operations.filter(op => op.status === 'request_changes').map(op => op.operation_id),
          unknown_outcomes: operations.filter(op => op.status === 'unknown').map(op => op.operation_id),
        },
        events: (room.events || []).filter(event => event.id > input.after_cursor).slice(-30),
        next_steps: status === 'waiting'
          ? ['No change was observed before the timeout. If the client session is still active, call coordination.wait again with this cursor; otherwise resume the session and inspect. This is bounded polling, not a push notification.']
          : ['Inspect the updated room. Retry approved operations with their existing IDs and exact input; unknown outcomes keep their reservations. A new run requires reviewing its revision instructions.'],
        scope: 'Authenticated service-reported state. A decision notification does not itself authorize execution; ledger.pay independently verifies each exact admission and outcome.',
      };
    };
    try {
      for (;;) {
        if (abort.signal.aborted) throw new CoordinationError('cancelled', 'The wait was cancelled. No action or approval was performed.');
        latest = await this.room(abort.signal);
        if (abort.signal.aborted) throw new CoordinationError('cancelled', 'The wait was cancelled. No action or approval was performed.');
        if (!Number.isSafeInteger(latest.revision) || latest.revision < 0) throw new CoordinationError('invalid_cursor', 'The room did not provide a usable event cursor.');
        if (latest.revision !== input.after_cursor || (input.run_id !== undefined && latest.run_id !== input.run_id)) return response(latest, 'changed');
        const remaining = deadline - performance.now();
        if (remaining <= 0) return response(latest, 'waiting');
        const finalInterval = remaining <= 2000;
        await waitDelay(Math.min(2000, remaining), abort.signal);
        // Timer implementations can wake slightly early. The final partial
        // interval ends this wait; it must never authorize another poll.
        if (finalInterval || timedOut || performance.now() >= deadline) return response(latest, 'waiting');
      }
    } catch (error) {
      if (!signal?.aborted && (timedOut || performance.now() >= deadline) && latest && error instanceof CoordinationError && error.code === 'cancelled') return response(latest, latest.revision !== input.after_cursor || (input.run_id !== undefined && latest.run_id !== input.run_id) ? 'changed' : 'waiting');
      if (!signal?.aborted && (timedOut || performance.now() >= deadline) && !latest && error instanceof CoordinationError && error.code === 'cancelled') throw new CoordinationError('wait_timeout', 'No current room state could be retrieved before the wait timed out. Inspect the room before retrying.');
      throw error;
    } finally { clearTimeout(timer); signal?.removeEventListener('abort', cancel); }
  }

  async deliver(runId: string): Promise<Record<string, unknown>> {
    if (typeof runId !== 'string' || !/^run-[A-Za-z0-9_-]{8,100}$/.test(runId)) throw new CoordinationError('invalid_run', 'Pass the exact run_id from coordination.inspect when delivering.');
    const before = await this.room();
    if (before.run_id !== runId) throw new CoordinationError('run_mismatch', 'This attempt has changed. Inspect the revised instructions and work before delivering.');
    const response = await this.#transport.post('deliver', { run_id: before.run_id });
    const room = response.room as RoomView;
    const manifest = room?.manifest;
    if (!manifest || !await verify(manifest, this.#config.authorityKey) || manifest.payload.type !== 'scopeblind.coordination.manifest.v1' || manifest.payload.room_id !== this.#config.roomId || manifest.payload.run_id !== before.run_id || manifest.payload.agreement_digest !== before.agreement.digest) throw new CoordinationError('invalid_manifest', 'The delivered result did not verify against this room and attempt. Inspect the room before retrying.');
    return { manifest, manifest_signature_verified: true, next_step: 'The recipient can accept this exact result or request changes in the shared room. Delivery does not imply their acceptance.' };
  }

  private async checkAdmission(value: unknown, request: OperationRequest, agreement: Signed<Agreement>, hash: string, fresh: boolean): Promise<Signed<Admission>> {
    const envelope = value as Signed<Admission>;
    if (!await verify(envelope, this.#config.authorityKey)) throw new CoordinationError('invalid_admission', 'Admission signature does not match the pinned authority. No execution was requested.');
    const a = envelope.payload;
    if (a.type !== 'scopeblind.coordination.admission.v1' || a.room_id !== this.#config.roomId || a.run_id !== request.run_id ||
        a.operation_id !== request.operation_id || a.agreement_digest !== agreement.digest || a.payload_hash !== hash ||
        canonical(a.input) !== canonical(request.input) || a.destination !== request.input.destination || !['admitted', 'held', 'refused'].includes(a.decision)) {
      throw new CoordinationError('invalid_admission', 'Admission does not authorize these exact operation terms. No execution was requested.');
    }
    const issued = Date.parse(a.issued_at), expiry = Date.parse(a.expires_at);
    if (!Number.isFinite(issued) || !Number.isFinite(expiry) || expiry <= issued || issued > Date.now() + 30_000 || (fresh && expiry <= Date.now())) {
      throw new CoordinationError('expired_admission', 'Admission validity could not be established. No execution was requested.');
    }
    return envelope;
  }

  private async checkOutcome(value: unknown, request: OperationRequest, hash: string): Promise<Signed<Outcome>> {
    const envelope = value as Signed<Outcome>;
    if (!await verify(envelope, this.#config.authorityKey)) throw new CoordinationError('invalid_outcome', 'Destination outcome signature does not match the pinned authority.');
    const o = envelope.payload;
    if (o.type !== 'scopeblind.coordination.outcome.v1' || o.room_id !== this.#config.roomId || o.run_id !== request.run_id ||
        o.operation_id !== request.operation_id || o.payload_hash !== hash || o.amount_minor !== request.input.amount_minor ||
        o.destination !== request.input.destination || !['confirmed', 'failed', 'unknown'].includes(o.status) ||
        (o.observed_by !== 'sandbox-ledger' && !(o.status === 'unknown' && o.observed_by === 'gateway-report')) ||
        !Number.isFinite(Date.parse(o.issued_at)) || Date.parse(o.issued_at) > Date.now() + 30_000 ||
        (o.status === 'confirmed' && !o.transaction_id)) {
      throw new CoordinationError('invalid_outcome', 'Destination outcome does not establish the result of these exact operation terms.');
    }
    return envelope;
  }

  async pay(payment: CoordinationPayment): Promise<CoordinationPaymentResult> {
    validateCoordinationPayment(payment);
    // Snapshot caller input before any await so it cannot be mutated after admission.
    const input = JSON.parse(canonical(payment.input)) as PaymentInput;
    const operationId = payment.operation_id;
    const room = await this.room();
    const request: OperationRequest = { operation_id: operationId, run_id: room.run_id, tool: 'ledger.pay', input };
    const hash = await payloadHash(input);
    const response = await this.#transport.post('admit', { operation: request });
    const receipt = (response.operation as { receipt?: unknown } | undefined)?.receipt;
    const admission = await this.checkAdmission(response.admission, request, room.agreement, hash, !receipt);
    if (response.decision !== admission.payload.decision) throw new CoordinationError('invalid_admission', 'Admission response contradicts its signed decision. No execution was requested.');
    // An already observed outcome is not a fresh instruction to execute again.
    if (receipt) {
      const outcome = await this.checkOutcome(receipt, request, hash);
      if (outcome.payload.status === 'confirmed' && admission.payload.decision !== 'admitted') {
        throw new CoordinationError('invalid_outcome', 'A confirmed outcome contradicts the signed admission decision. No new execution was requested.');
      }
      if (outcome.payload.status === 'unknown' && outcome.payload.observed_by === 'gateway-report') {
        return { operation_id: operationId, status: 'unknown', reason: outcome.payload.note || 'A gateway reported an unknown outcome. Authority remains reserved; no new execution was requested.', admission, outcome, replay: true };
      }
      if (outcome.payload.status !== 'unknown') return { operation_id: operationId, status: outcome.payload.status, reason: outcome.payload.note || 'Previously observed destination outcome.', admission, outcome, replay: true };
      // The sample ledger is explicitly idempotent. Reconciliation uses the SAME
      // operation, never a new attempt ID and never a release of reserved authority.
      await this.checkAdmission(response.admission, request, room.agreement, hash, true);
    }
    if (admission.payload.decision !== 'admitted') {
      return { operation_id: operationId, status: admission.payload.decision, reason: admission.payload.reason, admission };
    }
    try {
      const execution = await this.#transport.post('execute', { operation_id: operationId });
      const outcome = await this.checkOutcome(execution.outcome, request, hash);
      return { operation_id: operationId, status: outcome.payload.status, reason: outcome.payload.note || 'Signed sample-ledger outcome.', admission, outcome, replay: execution.replay === true };
    } catch {
      // Sending execute may have caused an effect even when its response was lost
      // or invalid. Never claim failure, issue a replacement operation, or release.
      return { operation_id: operationId, status: 'unknown', reason: 'Execution was requested, but its outcome could not be verified. Retain this operation_id and inspect or retry the same operation to reconcile; do not create a replacement payment.', admission };
    }
  }
}
