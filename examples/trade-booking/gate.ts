import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import * as cedar from '@cedar-policy/cedar-wasm/nodejs';

export const policySource = readFileSync(new URL('./policy.cedar', import.meta.url), 'utf8');
export const policySha256 = createHash('sha256').update(policySource).digest('hex');
const parts = cedar.policySetTextToParts(policySource);
if (parts.type !== 'success') throw new Error('Trade-booking policy did not parse');
const staticPolicies = Object.fromEntries(parts.policies.map((source) => {
  const parsed = cedar.policyToJson(source);
  if (parsed.type !== 'success') throw new Error('Trade-booking policy did not parse');
  return [parsed.json.annotations?.id ?? '', source];
}));

export interface Evidence {
  recordStatus: 'unknown' | 'booked' | 'cancelled' | 'absent';
  eventCount: number;
  confirmationEvidence: boolean;
  cancelSignatureBroken: boolean;
  ledgerClaimUnbacked: boolean;
}
export interface Context extends Evidence {
  bookingRef: string;
  proposedRef: string;
  nowMs: number;
  deadlineMs: number;
  timedOut: boolean;
  cancellationNeeded: boolean;
  cancelAttempts: number;
  operationsOwned: boolean;
}
export interface Proposal { action: string; bookingRef: string }
export interface Decision { allowed: boolean; rules: string[]; errors: string[] }

/** Internal trusted-context seam. Do not expose this function as a model tool. */
export function evaluatePolicy(action: string, context: Context): Decision {
  try {
    const result = cedar.isAuthorized({
      principal: { type: 'Agent', id: 'synthetic-agent' },
      action: { type: 'Action', id: action },
      resource: { type: 'Booking', id: context.bookingRef },
      context: { ...context }, entities: [], policies: { staticPolicies },
    });
    if (result.type !== 'success') {
      return { allowed: false, rules: [], errors: result.errors.map(e => e.message) };
    }
    const errors = result.response.diagnostics.errors.map(e => String(e.error));
    return {
      allowed: result.response.decision === 'allow' && errors.length === 0,
      rules: result.response.diagnostics.reason,
      errors,
    };
  } catch (error) {
    return { allowed: false, rules: [], errors: [String(error)] };
  }
}

export const unknownEvidence: Evidence = Object.freeze({
  recordStatus: 'unknown', eventCount: 0, confirmationEvidence: false,
  cancelSignatureBroken: false, ledgerClaimUnbacked: false,
});

/** In-memory teaching adapter. No booking API, retries, model or signing calls. */
export class SyntheticGate {
  #bookingRef: string;
  #deadlineMs: number;
  #attempts = 0;
  #operationsOwned = false;
  #evidence: Evidence = { ...unknownEvidence };
  #clock: () => number;
  constructor(bookingRef: string, deadlineMs: number, clock: () => number) {
    if (!bookingRef || !Number.isSafeInteger(deadlineMs) || deadlineMs < 0) throw new Error('Invalid session');
    this.#bookingRef = bookingRef;
    this.#deadlineMs = deadlineMs;
    this.#clock = clock;
  }
  // Trusted adapter input only; a production implementation verifies and binds
  // downstream observations before reaching this seam. No model tool exposes it.
  observe(evidence: Evidence): void {
    if (!['unknown', 'booked', 'cancelled', 'absent'].includes(evidence.recordStatus) ||
        !Number.isSafeInteger(evidence.eventCount) || evidence.eventCount < 0 ||
        ['confirmationEvidence', 'cancelSignatureBroken', 'ledgerClaimUnbacked'].some(
          key => typeof evidence[key as keyof Evidence] !== 'boolean')) throw new Error('Invalid evidence');
    this.#evidence = { ...evidence };
  }
  handToOperations(): void { this.#operationsOwned = true; }
  assess(proposal: Proposal): Decision {
    if (!proposal || Object.keys(proposal).sort().join(',') !== 'action,bookingRef' ||
        typeof proposal.action !== 'string' || typeof proposal.bookingRef !== 'string') {
      return { allowed: false, rules: [], errors: ['Malformed proposal; context is gate-owned'] };
    }
    const nowMs = this.#clock();
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) return { allowed: false, rules: [], errors: ['Invalid clock'] };
    const decision = evaluatePolicy(proposal.action, {
      ...this.#evidence, bookingRef: this.#bookingRef, proposedRef: proposal.bookingRef,
      nowMs, deadlineMs: this.#deadlineMs, timedOut: true, cancellationNeeded: true,
      cancelAttempts: this.#attempts, operationsOwned: this.#operationsOwned,
    });
    // Synchronous reservation makes two callers in THIS instance compete for one
    // attempt. A real adapter needs a durable transaction spanning all workers.
    if (decision.allowed && proposal.action === 'cancel') this.#attempts += 1;
    return decision;
  }
}
