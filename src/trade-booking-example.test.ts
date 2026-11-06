import { describe, expect, it } from 'vitest';
import { evaluatePolicy, SyntheticGate, unknownEvidence } from '../examples/trade-booking/gate';
import type { Context, Evidence, Proposal } from '../examples/trade-booking/gate';

function context(overrides: Partial<Context> = {}): Context {
  return { ...unknownEvidence, bookingRef: 'R1', proposedRef: 'R1', nowMs: 1000, deadlineMs: 1000,
    timedOut: true, cancellationNeeded: true, cancelAttempts: 0, operationsOwned: false, ...overrides };
}
const booked: Evidence = { ...unknownEvidence, recordStatus: 'booked' };
const cancelled: Evidence = { ...unknownEvidence, recordStatus: 'cancelled', eventCount: 1, confirmationEvidence: true };
const proposal = (action: string, bookingRef = 'R1'): Proposal => ({ action, bookingRef });

describe('synthetic trade-booking starter, real Cedar engine', () => {
  it.each([999, 1000, 1001])('keeps the original deadline at t=%i', nowMs => {
    expect(evaluatePolicy('listen', context({ nowMs })).allowed).toBe(nowMs < 1000);
    expect(evaluatePolicy('lookup', context({ nowMs })).allowed).toBe(nowMs >= 1000);
  });
  it('enforces fixed deadline with mutable clock on a single gate instance', () => {
    let now = 999;
    const gate = new SyntheticGate('R1', 1000, () => now);
    expect(gate.assess(proposal('listen')).allowed).toBe(true);
    now = 1000;
    expect(gate.assess(proposal('listen')).allowed).toBe(false);
    expect(gate.assess(proposal('listen')).allowed).toBe(false);
    expect(gate.assess(proposal('lookup')).allowed).toBe(true);
  });
  it('does not turn a successful booking into a timeout recovery', () => {
    expect(evaluatePolicy('lookup', context({ timedOut: false })).allowed).toBe(false);
    expect(evaluatePolicy('cancel', context({ ...booked, cancellationNeeded: false })).allowed).toBe(false);
  });
  it.each(['listen', 'lookup', 'cancel', 'confirm_cancel', 'assert_single_compensation'])('rejects a different reference for %s', action => {
    expect(evaluatePolicy(action, context({ ...cancelled, proposedRef: 'R2' })).allowed).toBe(false);
  });
  it('does not cancel an unknown, absent, or already cancelled booking', () => {
    for (const recordStatus of ['unknown', 'absent', 'cancelled'] as const) {
      expect(evaluatePolicy('cancel', context({ recordStatus })).allowed).toBe(false);
    }
  });
  it('reserves once across racing proposals, including a missing/error reply', async () => {
    const gate = new SyntheticGate('R1', 1000, () => 1000);
    gate.observe(booked);
    const decisions = await Promise.all(Array.from({ length: 10 }, () => Promise.resolve().then(() => gate.assess(proposal('cancel')))));
    expect(decisions.filter(d => d.allowed)).toHaveLength(1);
    // Re-reading booked after a lost/error reply cannot clear the reservation.
    gate.observe(booked);
    expect(gate.assess(proposal('cancel')).allowed).toBe(false);
    expect(gate.assess(proposal('confirm_cancel')).allowed).toBe(false);
  });
  it('leaves automatic actions with operations while still permitting a lookup', () => {
    const gate = new SyntheticGate('R1', 1000, () => 1000);
    gate.observe(booked);
    gate.handToOperations();
    expect(gate.assess(proposal('cancel')).allowed).toBe(false);
    expect(gate.assess(proposal('lookup')).allowed).toBe(true);
  });
  it('does not cancel again after operations supplied a counted event', () => {
    expect(evaluatePolicy('cancel', context({ ...cancelled })).allowed).toBe(false);
    expect(evaluatePolicy('cancel', context({ ...booked, eventCount: 1 })).allowed).toBe(false);
  });
  it('admits a late successful observation before the listening deadline for cancellation', () => {
    expect(evaluatePolicy('cancel', context({ ...booked, nowMs: 999 })).allowed).toBe(true);
  });
  it('requires a counted event, supporting confirmation, and no contradictory cancel evidence', () => {
    expect(evaluatePolicy('confirm_cancel', context(cancelled)).allowed).toBe(true);
    for (const evidence of [unknownEvidence, { ...cancelled, eventCount: 0 },
      { ...cancelled, confirmationEvidence: false }, { ...cancelled, cancelSignatureBroken: true },
      { ...cancelled, ledgerClaimUnbacked: true }]) {
      expect(evaluatePolicy('confirm_cancel', context(evidence)).allowed).toBe(false);
    }
  });
  it('keeps confirmation and single compensation separate for duplicate events', () => {
    expect(evaluatePolicy('confirm_cancel', context({ ...cancelled, eventCount: 2 })).allowed).toBe(true);
    expect(evaluatePolicy('assert_single_compensation', context({ ...cancelled, eventCount: 2 })).allowed).toBe(false);
    expect(evaluatePolicy('assert_single_compensation', context(cancelled)).allowed).toBe(true);
  });
  it('rejects model-supplied context and unknown actions', () => {
    const gate = new SyntheticGate('R1', 1000, () => 1000);
    expect(gate.assess({ ...proposal('cancel'), cancelAttempts: 0 } as Proposal).allowed).toBe(false);
    expect(gate.assess(proposal('book_again')).allowed).toBe(false);
    expect(gate.assess(proposal('cancel')).allowed).toBe(false);
  });
  it('fails closed on missing context and invalid trusted input', () => {
    expect(evaluatePolicy('lookup', {} as Context).allowed).toBe(false);
    const gate = new SyntheticGate('R1', 1000, () => NaN);
    expect(gate.assess(proposal('lookup')).allowed).toBe(false);
    expect(() => gate.observe({ ...cancelled, eventCount: -1 })).toThrow();
  });
});
