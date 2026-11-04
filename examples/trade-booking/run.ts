import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { evaluatePolicy, policySha256, SyntheticGate, unknownEvidence } from './gate.ts';
import type { Evidence, Proposal } from './gate.ts';

function demo() {
  let now = 999;
  const gate = new SyntheticGate('SYNTHETIC-R1', 1000, () => now);
  const steps: Array<{ note: string; proposal: Proposal; allowed: boolean; rules: string[] }> = [];
  const propose = (note: string, action: string, bookingRef = 'SYNTHETIC-R1') => {
    const proposal = { action, bookingRef };
    steps.push({ note, proposal, ...gate.assess(proposal) });
  };
  propose('Before deadline: keep listening', 'listen');
  propose('Before deadline: premature search', 'lookup');
  now = 1000;
  propose('Deadline reached: search original reference', 'lookup');
  propose('Model proposes another reference', 'lookup', 'SYNTHETIC-WRONG');
  gate.observe({ ...unknownEvidence, recordStatus: 'booked' });
  propose('Trusted synthetic lookup found booking: reserve one cancel attempt', 'cancel');
  propose('Lost cancel reply: a second cancel is refused', 'cancel');
  propose('No counted event: confirmation refused', 'confirm_cancel');
  gate.observe({ ...unknownEvidence, recordStatus: 'cancelled', eventCount: 1, confirmationEvidence: true });
  propose('Trusted synthetic booking event: confirmation admitted', 'confirm_cancel');
  return steps;
}

const demoSteps = demo();
if (process.argv.includes('--demo')) {
  console.log(JSON.stringify({ syntheticOnly: true, noExecution: true, demoSteps }, null, 2));
} else {
  const python = process.env.TRADE_BOOKING_PYTHON ?? fileURLToPath(new URL('./.venv/bin/python', import.meta.url));
  const child = spawnSync(python, [fileURLToPath(new URL('./bridge.py', import.meta.url))], {
    encoding: 'utf8', maxBuffer: 1024 * 1024, timeout: 30_000,
  });
  if (child.error || child.status !== 0) {
    throw new Error(`Pinned evidence reader failed. Follow README setup. ${child.error ?? child.stderr}`);
  }
  const corpus = JSON.parse(child.stdout);
  const rows = corpus.rows.map((row: {
    caseId: string; evidence: Evidence; upstreamActual: Record<string, string>;
    upstreamExpected: Record<string, string>; upstreamMatches: boolean;
  }) => {
    // Fixed placeholders are irrelevant to these two evidence-only actions.
    // No runtime admission claim is made for the saved evidence snapshots.
    const context = { ...row.evidence, bookingRef: corpus.bookingRef, proposedRef: corpus.bookingRef,
      nowMs: 0, deadlineMs: 0, timedOut: false, cancellationNeeded: false,
      cancelAttempts: 0, operationsOwned: false };
    const cancel = evaluatePolicy('confirm_cancel', context);
    const single = evaluatePolicy('assert_single_compensation', context);
    const matches = cancel.errors.length === 0 && single.errors.length === 0 &&
      cancel.allowed === (row.upstreamExpected.cancel_confirmed === 'ESTABLISHED') &&
      single.allowed === (row.upstreamExpected.single_compensation === 'ESTABLISHED');
    return { ...row, cedar: { confirmCancel: cancel, singleCompensation: single }, matches };
  });
  const failures = rows.filter((r: { matches: boolean; upstreamMatches: boolean }) => !r.matches || !r.upstreamMatches);
  const report = {
    syntheticOnly: true, noExecution: true, policySha256,
    upstream: { package: 'agent-evidence-vectors', version: corpus.version, digests: corpus.digests },
    coverage: {
      upstreamCases: rows.length, upstreamAxisChecks: rows.length * corpus.axes.length,
      cedarEvidenceChecks: rows.length * 2,
      cedarChecksMeaning: 'Allow iff the corresponding evidence claim is ESTABLISHED; deny merges NOT_ESTABLISHED and CONTRADICTED. Original tri-state outcomes are retained.',
      uncoveredByCedar: ['booking_committed', 'release_backed', 'one_live_booking_per_quote', 'limit_copy_matches', 'resolved'],
      absentFromUpstream: ['listening-window timing', 'pre-action lookup ordering', 'durable cancel-attempt reservation', 'operations handoff state'],
    },
    failures: failures.length, demoSteps, rows,
  };
  const outputIndex = process.argv.indexOf('--output');
  if (outputIndex >= 0) {
    const path = process.argv[outputIndex + 1];
    if (!path || path.startsWith('--')) throw new Error('--output requires a new file path');
    writeFileSync(path, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    console.log(`${rows.length} upstream cases / ${rows.length * corpus.axes.length} axis checks; ${rows.length * 2} Cedar evidence checks; ${failures.length} failures. Report: ${path}`);
  } else console.log(JSON.stringify(report, null, 2));
  if (failures.length) process.exitCode = 1;
}
