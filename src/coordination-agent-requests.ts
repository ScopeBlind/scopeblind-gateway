import type { Signed, RpcRequest } from './coordination-protocol.js';
import type { AgentBinding } from './coordination-pairing.js';
import type { NegotiationPreference, NegotiationBudgetPreference } from './coordination-negotiation.js';

/** Agent-authored suggestions. This record never grants authority or signs a mandate. */
export interface AgentTaskDraft {
  type: 'scopeblind.coordination.agent-task-draft.v1';
  title: string;
  goal: string;
  counterparty_name: string;
  budget_minor: number;
  approval_above_minor: number;
  approval_ttl_seconds: number;
  require_po_match: true;
  min_budget_minor: number;
  max_budget_minor: number;
  min_threshold_minor: number;
  max_threshold_minor: number;
  private_brief: string;
  preference: NegotiationPreference;
  budget_preference: NegotiationBudgetPreference;
  assumptions: string[];
}

export interface AgentTaskRequestView {
  request_id: string;
  agent_key: string;
  pairing_secret_hash: string;
  status: 'pending' | 'accepted' | 'ready' | 'revoked' | 'expired';
  expires_at: string;
  draft: AgentTaskDraft;
  accepted?: {
    owner_key: string;
    room_id: string;
    session_id: string;
    pair_id: string;
    reviewed_draft: AgentTaskDraft;
    digest: string;
  };
  connection?: {
    purpose: 'negotiation';
    room_id: string;
    session_id: string;
    pair_id: string;
    principal_key: string;
    authority_key: string;
    binding?: Signed<AgentBinding>;
  };
}

export interface AgentHandoffView {
  pair_id: string;
  room_id: string;
  source_room_id: string;
  agent_key: string;
  session_id: string;
  source_pair_id: string;
  name: string;
  expires_at: string;
  token_expires_at: string;
  status: 'waiting' | 'connected' | 'revoked' | 'expired';
  authorization: Signed<RpcRequest>;
  binding?: Signed<AgentBinding>;
}

export const AGENT_REQUEST_ACTIONS = ['agent_request_create','agent_request_get','agent_request_accept','agent_request_revoke','agent_request_reconnect','agent_handoff_get','agent_handoff_create','agent_handoff_claim','agent_handoff_revoke'] as const;

const DRAFT_KEYS = ['type','title','goal','counterparty_name','budget_minor','approval_above_minor','approval_ttl_seconds','require_po_match','min_budget_minor','max_budget_minor','min_threshold_minor','max_threshold_minor','private_brief','preference','budget_preference','assumptions'].sort().join(',');
const text = (value: unknown, min: number, max: number): value is string => typeof value === 'string' && value.length >= min && value.length <= max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value);
const amount = (value: unknown, min = 0): value is number => Number.isSafeInteger(value) && Number(value) >= min && Number(value) <= 10_000_000;

/** Strict shared schema: unsupported fields, coercions and impossible limits are refused. */
export function parseAgentTaskDraft(value: unknown): AgentTaskDraft {
  const invalid = () => { throw new Error('Use a bounded invoice-task draft with explicit suggested limits and assumptions. No authority has been granted.'); };
  if (!value || typeof value !== 'object' || Array.isArray(value)) return invalid();
  const v = value as AgentTaskDraft;
  if (Object.keys(v).sort().join(',') !== DRAFT_KEYS || v.type !== 'scopeblind.coordination.agent-task-draft.v1'
    || !text(v.title,1,100) || !v.title.trim() || !text(v.goal,1,2000) || !v.goal.trim() || !text(v.counterparty_name,0,60)
    || !text(v.private_brief,0,2000) || !amount(v.budget_minor,1) || !amount(v.approval_above_minor)
    || v.approval_above_minor > v.budget_minor || !Number.isSafeInteger(v.approval_ttl_seconds) || v.approval_ttl_seconds < 30 || v.approval_ttl_seconds > 900
    || v.require_po_match !== true || !amount(v.min_budget_minor,1) || !amount(v.max_budget_minor,1) || v.min_budget_minor > v.max_budget_minor
    || !amount(v.min_threshold_minor) || !amount(v.max_threshold_minor) || v.min_threshold_minor > v.max_threshold_minor || v.max_threshold_minor > v.max_budget_minor
    || typeof v.preference !== 'string' || !['fewer_reviews','more_review','balanced'].includes(v.preference)
    || typeof v.budget_preference !== 'string' || !['preserve_budget','lower_budget','more_capacity'].includes(v.budget_preference)
    || !Array.isArray(v.assumptions) || v.assumptions.length > 12 || !v.assumptions.every(item => text(item,1,300))) return invalid();
  return structuredClone(v);
}

/** Defaults are visible suggestions; the browser still requires an explicit reviewed signature. */
export function prepareAgentTaskDraft(value: unknown): AgentTaskDraft {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Provide a task title and goal for human review.');
  const v = value as Partial<AgentTaskDraft>;
  if (Object.keys(v).some(key => !DRAFT_KEYS.split(',').includes(key))) throw new Error('The draft contains a rule this invoice trial cannot enforce. Explain it to the person instead of granting it.');
  if (v.type !== undefined && v.type !== 'scopeblind.coordination.agent-task-draft.v1' || v.assumptions !== undefined && !Array.isArray(v.assumptions)) throw new Error('The draft type or assumptions are invalid.');
  const assumptions = [...(v.assumptions || [])];
  const fallback = <T>(key: keyof AgentTaskDraft, supplied: T | undefined, defaultValue: T, note: string): T => {
    if (supplied !== undefined) return supplied;
    assumptions.push(note);return defaultValue;
  };
  const budget = fallback('budget_minor',v.budget_minor,200000,'Total budget was not supplied: $2,000 is suggested for review.');
  const threshold = fallback('approval_above_minor',v.approval_above_minor,Math.min(50000,budget),'Review threshold was not supplied: up to $500 is suggested for review.');
  const draft: AgentTaskDraft = {
    type:'scopeblind.coordination.agent-task-draft.v1',title:v.title!,goal:v.goal!,counterparty_name:v.counterparty_name ?? '',
    budget_minor:budget,approval_above_minor:threshold,
    approval_ttl_seconds:fallback('approval_ttl_seconds',v.approval_ttl_seconds,900,'Approval expiry was not supplied: 15 minutes is suggested.'),
    require_po_match:v.require_po_match ?? true,
    min_budget_minor:fallback('min_budget_minor',v.min_budget_minor,budget,'Minimum negotiable budget defaults to the suggested total; review before signing.'),
    max_budget_minor:fallback('max_budget_minor',v.max_budget_minor,budget,'Maximum negotiable budget defaults to the suggested total; review before signing.'),
    min_threshold_minor:fallback('min_threshold_minor',v.min_threshold_minor,threshold,'Minimum review threshold defaults to the suggested threshold; review before signing.'),
    max_threshold_minor:fallback('max_threshold_minor',v.max_threshold_minor,threshold,'Maximum review threshold defaults to the suggested threshold; review before signing.'),
    private_brief:v.private_brief ?? '',preference:v.preference ?? 'balanced',budget_preference:v.budget_preference ?? 'preserve_budget',
    assumptions,
  };
  if (!assumptions.includes('This draft uses fictional USD invoices and fixed sample destinations. No real payment service is connected.')) assumptions.push('This draft uses fictional USD invoices and fixed sample destinations. No real payment service is connected.');
  return parseAgentTaskDraft(draft);
}
