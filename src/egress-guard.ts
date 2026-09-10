/**
 * Egress guard for scopeblind.egress_summary.v1.
 *
 * Hosted telemetry is deliberately a different artifact from a local receipt.
 * The local receipt remains authoritative and never leaves the machine. This
 * module emits only fixed-schema, pseudonymous commitments that a separately
 * signed summary envelope can carry to the hosted dashboard.
 */
import { createHash, createHmac } from 'node:crypto';
import { receiptHash } from './acta-envelope.js';

export const EGRESS_SUMMARY_TYPE = 'scopeblind.egress_summary.v1' as const;
export const EGRESS_SUMMARY_VERSION = 1 as const;

/** Exact fields allowed in a summary payload before the signer adds its identity. */
export const EGRESS_SUMMARY_FIELDS: ReadonlySet<string> = new Set([
  'type', 'version', 'source_receipt_commitment', 'request_pseudonym',
  'decision', 'reason_code', 'tool_category', 'policy_commitment', 'mode',
  'action_commitment', 'output_commitment', 'disclosed_field_count', 'deny_iteration',
]);

/** Fields the signed Acta payload may carry after signGenericArtifact() adds common identity fields. */
export const EGRESS_SIGNED_PAYLOAD_FIELDS: ReadonlySet<string> = new Set([
  ...EGRESS_SUMMARY_FIELDS, 'public_key', 'issuer_id', 'issued_at',
]);
export const EGRESS_ALLOWED_PAYLOAD_FIELDS = EGRESS_SIGNED_PAYLOAD_FIELDS;

const KNOWN_RECEIPT_TYPES = new Set(['protectmcp:decision', 'protectmcp:artifact', 'scopeblind.coverage_statement.v1']);
const DECISIONS = new Set(['allow', 'deny', 'approve']);
const MODES = new Set(['enforce', 'shadow', 'audit']);
const REASON_CODES = new Set([
  'cedar_allow', 'cedar_deny', 'policy_allow', 'policy_deny', 'policy_head_mismatch',
  'mandate_expired', 'mandate_missing', 'mandate_denied', 'approval_required',
  'approval_denied', 'signing_error', 'rate_limited', 'other',
]);

export interface EgressSummary {
  type: typeof EGRESS_SUMMARY_TYPE;
  version: typeof EGRESS_SUMMARY_VERSION;
  /** SHA-256 over the full canonical local receipt envelope. */
  source_receipt_commitment: string;
  /** Local-keyed pseudonym of the local request id; never the id itself. */
  request_pseudonym: string;
  decision: 'allow' | 'deny' | 'approve' | 'other';
  reason_code: string;
  tool_category: ToolCategory;
  policy_commitment: string;
  mode: 'enforce' | 'shadow' | 'audit' | 'other';
  action_commitment?: string;
  output_commitment?: string;
  disclosed_field_count?: number;
  deny_iteration?: number;
}

export type ToolCategory = 'communication' | 'source_control' | 'filesystem' | 'database' | 'cloud' | 'browser' | 'finance' | 'other';
export interface EgressViolation { path: string; reason: string; }
export interface EgressCheck { safe: boolean; violations: EgressViolation[]; }
export interface EgressSummaryOptions {
  /**
   * A local-only secret. This is deliberately separate from the receipt key and
   * the tenant bearer token: a hosted-store breach cannot dictionary-check a
   * low-entropy request id or policy reference against this pseudonym.
   */
  pseudonymKey: string | Uint8Array;
  /** Binds a pseudonym to one tenant and hosted destination. */
  tenantScope?: string;
}

function str(v: unknown): string | undefined { return typeof v === 'string' && v.length ? v : undefined; }
function integer(v: unknown): number | undefined { return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? v : undefined; }
function sha256Hex(value: string): string { return createHash('sha256').update(value).digest('hex'); }
function hmacCommitment(domain: string, value: unknown, opts: EgressSummaryOptions): string {
  return `hmac-sha256:${createHmac('sha256', opts.pseudonymKey).update(`${domain}\0${opts.tenantScope || ''}\0${String(value ?? '')}`).digest('hex')}`;
}
function isReceiptCommitment(value: unknown): value is string { return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value); }
function isPseudonym(value: unknown): value is string { return typeof value === 'string' && /^hmac-sha256:[0-9a-f]{64}$/.test(value); }
function isPublicKey(value: unknown): value is string { return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value); }
function isIssuedAt(value: unknown): value is string { return typeof value === 'string' && Number.isFinite(Date.parse(value)); }
function code(value: unknown): string {
  const leading = (str(value) || '').split(/[\s:]/)[0].toLowerCase().slice(0, 64);
  return REASON_CODES.has(leading) ? leading : 'other';
}
function category(tool: unknown): ToolCategory {
  const value = (str(tool) || '').toLowerCase();
  if (/(email|mail|slack|teams|message)/.test(value)) return 'communication';
  if (/(github|git|commit|pull_request)/.test(value)) return 'source_control';
  if (/(file|bash|shell|terminal|directory)/.test(value)) return 'filesystem';
  if (/(sql|database|query)/.test(value)) return 'database';
  if (/(aws|gcp|azure|cloud|deploy)/.test(value)) return 'cloud';
  if (/(browser|web|fetch|http)/.test(value)) return 'browser';
  if (/(trade|order|pms|broker|position)/.test(value)) return 'finance';
  return 'other';
}

/**
 * Create a fixed-schema summary from a complete local receipt. No raw receipt
 * field is copied. Every potentially identifying value is domain-separated and
 * HMAC-pseudonymized with a local-only key before it can cross the boundary.
 */
export function toEgressSummary(envelope: unknown, opts?: EgressSummaryOptions): EgressSummary | null {
  // Do not silently fall back to plain hashing. A caller without a local secret
  // cannot safely forward telemetry, but its local receipt remains unaffected.
  if (!opts?.pseudonymKey || (typeof opts.pseudonymKey === 'string' && !opts.pseudonymKey.length) || (opts.pseudonymKey instanceof Uint8Array && !opts.pseudonymKey.length)) return null;
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) return null;
  const env = envelope as Record<string, unknown>;
  const p = env.payload as Record<string, unknown> | undefined;
  if (!p || typeof p !== 'object' || typeof p.type !== 'string' || !KNOWN_RECEIPT_TYPES.has(p.type)) return null;
  const ar = p.action_readback as Record<string, unknown> | undefined;
  const pd = p.payload_digest as Record<string, unknown> | undefined;
  const disclosed = ar && Array.isArray(ar.disclosed_fields) ? ar.disclosed_fields.length : undefined;
  const rawDecision = str(p.decision);
  const summary: EgressSummary = {
    type: EGRESS_SUMMARY_TYPE,
    version: EGRESS_SUMMARY_VERSION,
    source_receipt_commitment: `sha256:${receiptHash(envelope)}`,
    request_pseudonym: hmacCommitment('scopeblind.egress.request.v1', p.request_id || p.scope || '', opts),
    decision: rawDecision && DECISIONS.has(rawDecision) ? rawDecision as EgressSummary['decision'] : 'other',
    reason_code: code(p.reason),
    tool_category: category(p.tool_name),
    policy_commitment: hmacCommitment('scopeblind.egress.policy.v1', p.policy_digest || '', opts),
    mode: str(p.mode) && MODES.has(str(p.mode)!) ? str(p.mode)! as EgressSummary['mode'] : 'other',
    ...(ar && str(ar.payload_hash) ? { action_commitment: hmacCommitment('scopeblind.egress.action.v1', ar.payload_hash, opts) } : {}),
    ...(pd && str(pd.output_hash) ? { output_commitment: hmacCommitment('scopeblind.egress.output.v1', pd.output_hash, opts) } : {}),
    ...(disclosed !== undefined ? { disclosed_field_count: disclosed } : {}),
    ...(integer(p.deny_iteration) !== undefined ? { deny_iteration: integer(p.deny_iteration) } : {}),
  };
  return summary;
}

/** Validate a pre-signing summary or a signed summary payload. */
export function inspectEgress(obj: unknown, opts: { signed?: boolean } = {}): EgressCheck {
  const violations: EgressViolation[] = [];
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return { safe: false, violations: [{ path: '$', reason: 'not an egress summary object' }] };
  const o = obj as Record<string, unknown>;
  const allowed = opts.signed ? EGRESS_SIGNED_PAYLOAD_FIELDS : EGRESS_SUMMARY_FIELDS;
  for (const [key, value] of Object.entries(o)) {
    if (!allowed.has(key)) { violations.push({ path: `$.${key}`, reason: 'field is not allowed in an egress summary' }); continue; }
    if (value === null || value === undefined) { violations.push({ path: `$.${key}`, reason: 'null and undefined are not permitted' }); continue; }
    if (typeof value === 'object') violations.push({ path: `$.${key}`, reason: 'nested objects and arrays are not permitted' });
  }
  if (o.type !== EGRESS_SUMMARY_TYPE) violations.push({ path: '$.type', reason: 'wrong egress summary type' });
  if (o.version !== EGRESS_SUMMARY_VERSION) violations.push({ path: '$.version', reason: 'unsupported egress summary version' });
  if (!isReceiptCommitment(o.source_receipt_commitment)) violations.push({ path: '$.source_receipt_commitment', reason: 'must be a sha256 receipt commitment' });
  for (const field of ['request_pseudonym', 'policy_commitment'] as const) if (!isPseudonym(o[field])) violations.push({ path: `$.${field}`, reason: 'must be a local hmac-sha256 pseudonym' });
  for (const field of ['action_commitment', 'output_commitment'] as const) if (o[field] !== undefined && !isPseudonym(o[field])) violations.push({ path: `$.${field}`, reason: 'must be a local hmac-sha256 pseudonym' });
  if (!['allow', 'deny', 'approve', 'other'].includes(String(o.decision))) violations.push({ path: '$.decision', reason: 'invalid decision enum' });
  if (!REASON_CODES.has(String(o.reason_code))) violations.push({ path: '$.reason_code', reason: 'invalid reason code enum' });
  if (!['communication', 'source_control', 'filesystem', 'database', 'cloud', 'browser', 'finance', 'other'].includes(String(o.tool_category))) violations.push({ path: '$.tool_category', reason: 'invalid tool category enum' });
  if (!['enforce', 'shadow', 'audit', 'other'].includes(String(o.mode))) violations.push({ path: '$.mode', reason: 'invalid mode enum' });
  for (const field of ['disclosed_field_count', 'deny_iteration'] as const) if (o[field] !== undefined && (!Number.isSafeInteger(o[field]) || Number(o[field]) < 0 || Number(o[field]) > 1_000_000)) violations.push({ path: `$.${field}`, reason: 'must be a bounded non-negative integer' });
  if (opts.signed) {
    if (!isPublicKey(o.public_key)) violations.push({ path: '$.public_key', reason: 'must be a 32-byte Ed25519 public key' });
    if (typeof o.issuer_id !== 'string' || !/^[\x21-\x7e]{1,160}$/.test(o.issuer_id)) violations.push({ path: '$.issuer_id', reason: 'must be a compact issuer id' });
    if (!isIssuedAt(o.issued_at)) violations.push({ path: '$.issued_at', reason: 'must be an ISO timestamp' });
  }
  return { safe: violations.length === 0, violations };
}

export function assertEgressSafe(summary: unknown, opts: { signed?: boolean } = {}): void {
  const check = inspectEgress(summary, opts);
  if (!check.safe) throw new Error(`egress guard blocked a forward: ${check.violations.slice(0, 3).map((v) => `${v.path} (${v.reason})`).join('; ')}`);
}

export interface EgressSelfCheck {
  type: 'scopeblind.egress_self_check.v1';
  generated_at: string;
  summary_fields: string[];
  samples_checked: number;
  all_summaries_safe: boolean;
  raw_content_dropped: boolean;
  private_key_dropped: boolean;
  deny_receipt_forwardable: boolean;
  statement: string;
}

export function runEgressSelfCheck(sampleReceipts: unknown[], now: string): EgressSelfCheck {
  // This fixed key is only for an offline self-check. It is never used by the
  // bridge or sent anywhere.
  const opts: EgressSummaryOptions = { pseudonymKey: 'scopeblind-egress-self-check-v1' };
  const summaries = sampleReceipts.map((r) => toEgressSummary(r, opts)).filter((s): s is EgressSummary => s !== null);
  const allSafe = summaries.every((s) => inspectEgress(s).safe);
  const dirty = {
    payload: {
      type: 'protectmcp:decision', tool_name: 'send_email', decision: 'allow', request_id: 'ceo@victim.com', policy_digest: 'strategy-mean-reversion',
      action_readback: { destination: 'ceo@victim.com', payload_preview: { body: 'we miss earnings by 40%, sell before the print' }, payload_hash: 'deadbeef', disclosed_fields: ['to', 'subject', 'body'] },
      payload_digest: { preview: 'positions AAPL 50000 shares', output_hash: 'cafe' }, privateKey: 'deadbeef'.repeat(8),
    }, signature: { alg: 'EdDSA', kid: 'k', sig: 'y' },
  };
  const dirtySummary = toEgressSummary(dirty, opts)!;
  const blob = JSON.stringify(dirtySummary);
  const deny = { payload: { type: 'protectmcp:decision', tool_name: 'Bash', decision: 'deny', reason: 'cedar_deny: {"reason":["policy0"]}', request_id: 'd1', policy_digest: 'p' }, signature: { alg: 'EdDSA', kid: 'k', sig: 'y' } };
  const denySummary = toEgressSummary(deny, opts);
  return {
    type: 'scopeblind.egress_self_check.v1', generated_at: now, summary_fields: [...EGRESS_SUMMARY_FIELDS].sort(), samples_checked: summaries.length,
    all_summaries_safe: allSafe,
    raw_content_dropped: inspectEgress(dirtySummary).safe && !blob.includes('ceo@victim.com') && !blob.includes('earnings') && !blob.includes('positions') && !blob.includes('40%'),
    private_key_dropped: !blob.includes('deadbeef'.repeat(8)),
    deny_receipt_forwardable: Boolean(denySummary && inspectEgress(denySummary).safe && denySummary.decision === 'deny' && denySummary.reason_code === 'cedar_deny'),
    statement: 'The hosted layer receives a signed, fixed-schema summary of enums, a receipt hash, and local HMAC pseudonyms only. Request ids, policy references, action hashes, and output hashes cannot be dictionary-checked without the local key; raw prompts, payloads, outputs, recipients, positions, amounts, and private keys remain local.',
  };
}
