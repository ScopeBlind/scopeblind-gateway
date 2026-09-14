/**
 * A signed standard in force at the gate, and the page its record lands on.
 *
 * The standard (scopeblind.proof_request.v1, written and signed on
 * scopeblind.com/write) names the tools the agent may use, a per-instruction
 * amount limit, and the amount above which a named person approves. The
 * first two the gate refuses on its own. The third it cannot decide: it holds
 * the action, posts it to the standard's page, and lets the person sign a
 * decision there with the key the standard accepts. A retry of the same
 * action finds that decision and proceeds or is refused.
 *
 * Reporting is opt-in (--report) and best-effort: a receipt is appended to
 * the local chain first and posted after; the page never blocks a call.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export interface Money { minor: number; currency: string }

export interface StandardGate {
  request_id: string;
  digest: string;
  /** The author's Ed25519 verification key (hex). Approvals on the page are signed with it or with a key the standard's trust block accepts. */
  signer_key: string;
  /** Tools the standard permits; null when the standard names none (a standard without a run block). */
  tools: string[] | null;
  /** The per-instruction limit; null when the standard sets none. */
  amount_max: Money | null;
  /** The amount above which a named person approves; null when the standard needs no person. */
  required_above: Money | null;
  /** The gate policy digest the standard was signed with, when it carries one. */
  policy_digest: string | null;
  /** Plain words for the log line at startup. */
  summary: string;
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

function moneyFrom(v: unknown): Money | null {
  if (!isObj(v) || typeof v.amount !== 'number' || !(v.amount >= 0) || typeof v.currency !== 'string' || !/^[A-Z]{3}$/.test(v.currency)) return null;
  return { minor: Math.round(v.amount * 100), currency: v.currency };
}

const fmt = (m: Money) => `${m.currency} ${(m.minor / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

export function parseStandard(value: unknown): StandardGate {
  if (!isObj(value) || value.type !== 'scopeblind.proof_request.v1') throw new Error('not a signed standard (scopeblind.proof_request.v1)');
  if (typeof value.request_id !== 'string' || typeof value.digest !== 'string') throw new Error('the standard has no request_id or digest');
  const recipient = isObj(value.recipient) ? value.recipient : null;
  if (!recipient || typeof recipient.verification_key !== 'string' || !/^[0-9a-f]{64}$/i.test(recipient.verification_key)) throw new Error('the standard names no signer key');
  if (!isObj(value.signature) || typeof value.signature.value !== 'string') throw new Error('the standard is not signed');
  const q = isObj(value.requirements) ? value.requirements : {};
  const run = isObj(q.run) ? q.run : null;
  const tools = run && Array.isArray(run.allowed_tools) ? run.allowed_tools.filter((t): t is string => typeof t === 'string') : null;
  const limits = isObj(q.action_limits) ? q.action_limits : null;
  const amount_max = limits ? moneyFrom(limits.amount_max) : null;
  const approval = isObj(q.human_approval) ? q.human_approval : null;
  const required_above = approval ? moneyFrom(approval.required_above) : null;
  const enforcement = isObj(value.enforcement) ? value.enforcement : null;
  const policy_digest = enforcement && typeof enforcement.policy_digest === 'string' ? enforcement.policy_digest : null;
  const parts = [tools ? `${tools.length} tool${tools.length === 1 ? '' : 's'}` : 'no tool list', amount_max ? `at most ${fmt(amount_max)} per instruction` : 'no amount limit', required_above ? `a person approves above ${fmt(required_above)}` : 'no approval threshold'];
  return { request_id: value.request_id, digest: value.digest, signer_key: recipient.verification_key.toLowerCase(), tools, amount_max, required_above, policy_digest, summary: parts.join(', ') };
}

export function loadStandardFile(path: string): StandardGate {
  return parseStandard(JSON.parse(readFileSync(path, 'utf-8')));
}

/** The amount a call carries, in minor units: amount_minor (integer) or amount (major units), with a currency. Null when the call carries no amount. */
export function readAmount(input: unknown): Money | null {
  if (!isObj(input)) return null;
  const currency = typeof input.currency === 'string' && /^[A-Za-z]{3}$/.test(input.currency) ? input.currency.toUpperCase() : null;
  if (typeof input.amount_minor === 'number' && Number.isFinite(input.amount_minor)) return { minor: Math.round(input.amount_minor), currency: currency ?? '' };
  if (typeof input.amount === 'number' && Number.isFinite(input.amount)) return { minor: Math.round(input.amount * 100), currency: currency ?? '' };
  return null;
}

/** The per-instruction limit, checked before the call runs. A call with no amount is not a payment and passes; a call in another currency is refused. */
export function checkAmount(gate: StandardGate, input: unknown): { ok: true } | { ok: false; reason: string; detail: string } {
  if (!gate.amount_max) return { ok: true };
  const amount = readAmount(input);
  if (!amount) return { ok: true };
  if (amount.currency !== gate.amount_max.currency) return { ok: false, reason: 'standard_currency_not_permitted', detail: `the standard permits ${gate.amount_max.currency} only; this call is in ${amount.currency || 'no named currency'}` };
  if (amount.minor > gate.amount_max.minor) return { ok: false, reason: 'standard_amount_over_limit', detail: `${fmt(amount)} is over the standard's limit of ${fmt(gate.amount_max)} per instruction` };
  return { ok: true };
}

/** Whether the standard hands this call to a named person: it carries an amount above the threshold, or an amount the threshold cannot be compared with. */
export function personRequired(gate: StandardGate, input: unknown): { required: false } | { required: true; detail: string } {
  if (!gate.required_above) return { required: false };
  const amount = readAmount(input);
  if (!amount) return { required: false };
  if (amount.currency !== gate.required_above.currency) return { required: true, detail: `${fmt(amount)} cannot be compared with the standard's threshold of ${fmt(gate.required_above)}` };
  if (amount.minor > gate.required_above.minor) return { required: true, detail: `${fmt(amount)} is above ${fmt(gate.required_above)}, so a named person approves it` };
  return { required: false };
}

/** One id per exact action under one standard, so a retry finds the decision made for it. */
export function heldIdFor(sid: string, tool: string, payloadHash: string): string {
  return createHash('sha256').update(`scopeblind.held_action.v1\0${sid}\0${tool}\0${payloadHash}`).digest('hex').slice(0, 24);
}

export function sidFromReportUrl(url: string): string | null {
  try { const s = new URL(url).searchParams.get('s'); return s && /^[0-9a-f]{24}$/.test(s) ? s : null; } catch { return null; }
}

export interface HeldDecision { decision: 'approve' | 'deny'; approver_key_id: string; digest: string; note: string }

type FetchLike = (input: string, init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/**
 * Posts receipts and held actions to the standard's page and reads decisions
 * from it. Every network failure is logged and swallowed: the local chain is
 * the record; the page is where it lands.
 */
export class RecordReporter {
  readonly url: string;
  readonly sid: string;
  readonly runId: string;
  private readonly token: string;
  private readonly fetchImpl: FetchLike;
  private readonly log: (message: string) => void;
  private queue: Array<{ receipt?: string; call?: string }> = [];
  private timer: ReturnType<typeof setTimeout> | null = null;
  private flushing: Promise<void> = Promise.resolve();
  /** Counts for the startup and shutdown lines. */
  sent = 0;
  failed = 0;

  constructor(opts: { url: string; token: string; runId: string; fetchImpl?: FetchLike; log?: (message: string) => void }) {
    const sid = sidFromReportUrl(opts.url);
    if (!sid) throw new Error('--report must be the standard page\'s report URL (https://scopeblind.com/api/standard?s=<id>)');
    this.url = opts.url; this.sid = sid; this.token = opts.token; this.runId = opts.runId;
    this.fetchImpl = opts.fetchImpl ?? ((input, init) => fetch(input, init));
    this.log = opts.log ?? ((m) => process.stderr.write(`[PROTECT_MCP] ${m}\n`));
  }

  private async post(op: 'record' | 'held', body: Record<string, unknown>): Promise<{ ok: boolean; status: number; body: Record<string, unknown> }> {
    const resp = await this.fetchImpl(`${this.url}&op=${op}`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${this.token}` }, body: JSON.stringify({ sid: this.sid, ...body }), signal: AbortSignal.timeout(8000) });
    const parsed = await resp.json().catch(() => ({})) as Record<string, unknown>;
    return { ok: resp.ok, status: resp.status, body: parsed };
  }

  /** Queues one receipt line (and its call line) for the next flush. Never throws. */
  record(receipt: string | undefined, call?: string): void {
    this.queue.push({ receipt, call });
    if (!this.timer) this.timer = setTimeout(() => { this.timer = null; void this.flush(); }, 800);
    this.timer.unref?.();
  }

  /** Sends everything queued, in order, as one append. */
  flush(): Promise<void> {
    this.flushing = this.flushing.then(async () => {
      if (this.queue.length === 0) return;
      const batch = this.queue; this.queue = [];
      const receipts = batch.map((b) => b.receipt).filter((r): r is string => !!r).join('\n');
      const calls = batch.map((b) => b.call).filter((c): c is string => !!c).join('\n');
      try {
        const r = await this.post('record', { run_id: this.runId, receipts, calls, append: true });
        if (r.ok) this.sent += batch.length; else { this.failed += batch.length; this.log(`Record not accepted by the standard's page (${r.status} ${String(r.body.error ?? '')}); the local chain is intact`); }
      } catch (err) { this.failed += batch.length; this.log(`Record could not reach the standard's page (${err instanceof Error ? err.message : String(err)}); the local chain is intact`); }
    });
    return this.flushing;
  }

  /** Posts a held action. Returns the page URL to send the model to, or null when the page could not be reached. */
  async hold(held: { hid: string; request_id: string; tool: string; readback: { summary: string; payload_hash: string; amount?: number | null; currency?: string | null }; reason: string }): Promise<string | null> {
    try {
      const r = await this.post('held', { ...held, run_id: this.runId });
      if (r.ok && typeof r.body.url === 'string') return r.body.url;
      this.log(`Held action not accepted by the standard's page (${r.status} ${String(r.body.error ?? '')})`);
      return null;
    } catch (err) { this.log(`Held action could not reach the standard's page (${err instanceof Error ? err.message : String(err)})`); return null; }
  }

  /** The decision a person recorded for a held action: approve, deny, none yet (null), or unreachable. */
  async decision(hid: string): Promise<HeldDecision | null | 'unreachable'> {
    try {
      const resp = await this.fetchImpl(`${this.url}&held=${hid}`, { method: 'GET', headers: { accept: 'application/json' }, signal: AbortSignal.timeout(8000) });
      if (resp.status === 404) return null;
      const body = await resp.json().catch(() => ({})) as { ok?: boolean; held?: { decision?: { decision?: string; approver?: { key_id?: string }; digest?: string; note?: string } | null } };
      if (!resp.ok || !body.ok || !body.held) return 'unreachable';
      const d = body.held.decision;
      if (!d || (d.decision !== 'approve' && d.decision !== 'deny')) return null;
      return { decision: d.decision, approver_key_id: d.approver?.key_id ?? 'unknown', digest: d.digest ?? '', note: d.note ?? '' };
    } catch { return 'unreachable'; }
  }
}
