/**
 * The running gate must reject a registry that is rolled back to an earlier,
 * still self-consistent, still gate-signed state (finding #6: no monotonic
 * anchor). This is a session-scoped defence: the gate remembers the longest
 * signed history it has enforced and refuses a shorter/forked one.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from '@noble/hashes/utils';
import type { Server } from 'node:http';
import { createReceiptEnvelope } from './acta-envelope.js';
import { initializeMandateRegistry, createPolicyProposal, mandatePaths, type DirectController, type GateSigner } from './mandate-lifecycle.js';

const PORT = 19381;
const ROOT = mkdtempSync(join(tmpdir(), 'pmcp-rollback-'));
const CEDAR = join(ROOT, 'cedar');
const CAND = join(ROOT, 'candidate');
const KEYS = join(ROOT, 'keys');
const BASE = 'forbid(principal, action, resource == Tool::"Bash");\npermit(principal, action, resource);\n';
const WIDE = 'permit(principal, action, resource == Tool::"Bash");\npermit(principal, action, resource);\n';

const gatePriv = bytesToHex(randomBytes(32));
const gate: GateSigner = { privateKey: gatePriv, publicKey: bytesToHex(ed25519.getPublicKey(gatePriv)), kid: 'managed-gate' };
const controllerPriv = bytesToHex(randomBytes(32));
const controller: DirectController = { id: 'cro', label: 'CRO', type: 'ed25519', public_key: bytesToHex(ed25519.getPublicKey(controllerPriv)) };

mkdirSync(CEDAR); mkdirSync(CAND); mkdirSync(KEYS);
writeFileSync(join(CEDAR, 'policy.cedar'), BASE);
writeFileSync(join(CAND, 'policy.cedar'), WIDE);
writeFileSync(join(KEYS, 'gateway.json'), JSON.stringify(gate));

const initial = initializeMandateRegistry({ cedarDir: CEDAR, signer: gate, controllers: [controller] });
// Capture the post-init registry bytes (history length 1) as the rollback target.
const rolledBackBytes = readFileSync(mandatePaths(CEDAR).registry, 'utf-8');
// Grow the signed history to length 2 with a valid proposal (head unchanged).
createPolicyProposal({
  cedarDir: CEDAR, signer: gate, candidateDir: CAND,
  denialReceipt: createReceiptEnvelope({
    type: 'protectmcp:decision', tool_name: 'Bash', decision: 'deny', reason: 'restricted_tool',
    policy_digest: initial.active.policy_digest, request_id: 'r1', mode: 'enforce', public_key: gate.publicKey,
  }, gate.privateKey, gate.kid, new Date().toISOString()).envelope,
  reason: 'grow history for the rollback test', expiresAt: '2030-01-01T00:00:00.000Z',
});

// Build a SAME-LENGTH FORK on a second dir: same gate + same baseline policy give
// the same registry_id and baseline head, but a different proposal makes the
// transition at the high-water index differ. Dropped into the first registry, a
// gate that already saw the real history must reject it as forked.
const FORK = join(ROOT, 'fork');
mkdirSync(FORK); mkdirSync(join(FORK, 'candidate'));
writeFileSync(join(FORK, 'policy.cedar'), BASE);
writeFileSync(join(FORK, 'candidate', 'policy.cedar'), WIDE);
const forkInit = initializeMandateRegistry({ cedarDir: FORK, signer: gate, controllers: [controller] });
createPolicyProposal({
  cedarDir: FORK, signer: gate, candidateDir: join(FORK, 'candidate'),
  denialReceipt: createReceiptEnvelope({
    type: 'protectmcp:decision', tool_name: 'Bash', decision: 'deny', reason: 'restricted_tool',
    policy_digest: forkInit.active.policy_digest, request_id: 'r-fork', mode: 'enforce', public_key: gate.publicKey,
  }, gate.privateKey, gate.kid, new Date().toISOString()).envelope,
  reason: 'a divergent same-length history', expiresAt: '2030-01-01T00:00:00.000Z',
});
const forkedBytes = readFileSync(mandatePaths(FORK).registry, 'utf-8');

let server: Server | undefined;
beforeAll(async () => {
  const original = process.cwd();
  process.chdir(ROOT);
  try {
    const { startHookServer } = await import('./hook-server.js');
    server = await startHookServer({ port: PORT, cedarDir: CEDAR, enforce: true });
  } finally {
    process.chdir(original);
  }
  await new Promise((r) => setTimeout(r, 150));
}, 10_000);
afterAll(() => { server?.close(); });

async function hook(toolName: string): Promise<{ hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } }> {
  const res = await fetch(`http://127.0.0.1:${PORT}/hook`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: toolName, tool_input: {}, tool_use_id: `rb-${Date.now()}` }),
  });
  return res.json() as Promise<{ hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } }>;
}

describe('managed mandate rollback protection', () => {
  it('enforces normally at the current (grown) history, then denies after a rollback to an earlier signed state', async () => {
    // First request establishes the high-water mark at the grown history length.
    const first = await hook('read_file');
    expect(first.hookSpecificOutput?.permissionDecisionReason || '').not.toContain('mandate_rollback_detected');

    // A same-length fork (divergent history of equal length) must be rejected.
    writeFileSync(mandatePaths(CEDAR).registry, forkedBytes);
    const forked = await hook('read_file');
    expect(forked.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(forked.hookSpecificOutput?.permissionDecisionReason || '').toContain('mandate_history_forked');

    // A rollback to a shorter, still valid, post-init state must be rejected.
    writeFileSync(mandatePaths(CEDAR).registry, rolledBackBytes);
    const second = await hook('read_file');
    expect(second.hookSpecificOutput?.permissionDecision).toBe('deny');
    expect(second.hookSpecificOutput?.permissionDecisionReason || '').toContain('mandate_rollback_detected');
  });
});
