import { describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes } from '@noble/hashes/utils';
import { createReceiptEnvelope } from './acta-envelope.js';
import {
  approvePolicyProposalWithDirectSignature,
  approvePolicyProposalWithWebAuthn,
  createDirectControllerApproval,
  createPolicyProposal,
  createWebAuthnPolicyChallenge,
  exportMandateDisciplineRecord,
  initializeMandateRegistry,
  loadMandateRegistry,
  mandatePaths,
  refreshManagedMandate,
  snapshotFromDirectory,
  verifyMandateLifecycleExport,
  verifyMandateRegistry,
  type DirectController,
  type GateSigner,
} from './mandate-lifecycle.js';
import { buildPolicyBundle } from './policy-digest.js';

const BASE_POLICY = 'forbid(principal, action, resource == Tool::"Bash");\npermit(principal, action, resource);\n';
const WIDENED_POLICY = 'permit(principal, action, resource == Tool::"Bash");\npermit(principal, action, resource);\n';

function key(kid: string): GateSigner {
  const privateKey = bytesToHex(randomBytes(32));
  return { privateKey, publicKey: bytesToHex(ed25519.getPublicKey(privateKey)), kid };
}

function setup(): {
  root: string;
  cedar: string;
  candidate: string;
  gate: GateSigner;
  controller: DirectController;
  controllerPrivate: string;
} {
  const root = mkdtempSync(join(tmpdir(), 'pmcp-mandate-'));
  const cedar = join(root, 'cedar');
  const candidate = join(root, 'candidate');
  mkdirSync(cedar); mkdirSync(candidate);
  writeFileSync(join(cedar, 'policy.cedar'), BASE_POLICY);
  writeFileSync(join(candidate, 'policy.cedar'), WIDENED_POLICY);
  const gate = key('gate-1');
  const controllerPrivate = bytesToHex(randomBytes(32));
  const controller: DirectController = {
    id: 'cro-1',
    label: 'Chief Risk Officer',
    type: 'ed25519',
    public_key: bytesToHex(ed25519.getPublicKey(controllerPrivate)),
  };
  return { root, cedar, candidate, gate, controller, controllerPrivate };
}

function denial(gate: GateSigner, policyDigest: string, at: string) {
  return createReceiptEnvelope({
    type: 'protectmcp:decision',
    tool_name: 'Bash',
    decision: 'deny',
    reason: 'restricted_tool',
    policy_digest: policyDigest,
    request_id: 'denial-1',
    mode: 'enforce',
    public_key: gate.publicKey,
  }, gate.privateKey, gate.kid, at).envelope;
}

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');

function signedPasskeyAssertion(challenge: { challenge: string; rpId: string }, privateKey: string, origin: string) {
  const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: challenge.challenge, origin }), 'utf-8');
  const authData = new Uint8Array(37);
  authData.set(sha256(new TextEncoder().encode(challenge.rpId)), 0);
  authData[32] = 0x05; // user present + user verified
  authData[36] = 1; // signCount = 1
  const signature = ed25519.sign(concatBytes(authData, sha256(clientData)), privateKey);
  return {
    credentialId: 'credential-1',
    authenticatorData: b64url(authData),
    clientDataJSON: b64url(clientData),
    signature: b64url(signature),
  };
}

describe('runtime-enforced mandate lifecycle', () => {
  it('requires a signed denial, a distinct controller approval, then atomically installs the exact proposed head', () => {
    const f = setup();
    const clock = new Date('2026-07-10T12:00:00.000Z');
    const initial = initializeMandateRegistry({ cedarDir: f.cedar, signer: f.gate, controllers: [f.controller], now: clock });
    expect(verifyMandateRegistry(initial, clock)).toMatchObject({ valid: true });

    const proposal = createPolicyProposal({
      cedarDir: f.cedar,
      signer: f.gate,
      candidateDir: f.candidate,
      denialReceipt: denial(f.gate, initial.active.policy_digest, clock.toISOString()),
      reason: 'Permit Bash only for the approved operational workflow.',
      expiresAt: '2026-07-10T13:00:00.000Z',
      now: clock,
    });
    expect(proposal.diff.added_statements).toHaveLength(1);
    expect(proposal.diff.removed_statements).toHaveLength(1);
    expect(loadMandateRegistry(f.cedar)?.active.policy_digest).toBe(initial.active.policy_digest);

    const approval = createDirectControllerApproval({ proposal, controller: f.controller, privateKey: f.controllerPrivate, now: new Date('2026-07-10T12:01:00.000Z') });
    const active = approvePolicyProposalWithDirectSignature({
      cedarDir: f.cedar,
      signer: f.gate,
      proposalId: proposal.proposal_id,
      approval,
      now: new Date('2026-07-10T12:01:00.000Z'),
    });
    expect(active.active.policy_digest).toBe(proposal.proposed_policy_digest);
    expect(readFileSync(join(f.cedar, 'policy.cedar'), 'utf-8')).toBe(WIDENED_POLICY);
    expect(active.history.map((entry) => entry.event)).toEqual(['initialized', 'proposal_created', 'proposal_approved', 'policy_activated']);
    expect(verifyMandateRegistry(active, new Date('2026-07-10T12:02:00.000Z'))).toMatchObject({ valid: true });

    const exportBundle = buildPolicyBundle('cedar', [{ name: 'policy.cedar', content: WIDENED_POLICY }]);
    expect(verifyMandateLifecycleExport(active, exportBundle, new Date('2026-07-10T12:02:00.000Z'))).toMatchObject({ valid: true });
    const discipline = exportMandateDisciplineRecord(active, new Date('2026-07-10T12:02:00.000Z')) as { active_policy_digest: string; changes: Array<{ event: string }> };
    expect(discipline.active_policy_digest).toBe(proposal.proposed_policy_digest);
    expect(discipline.changes.map((item) => item.event)).toContain('policy_activated');
  });

  it('fails closed if an operator edits managed Cedar bytes directly', () => {
    const f = setup();
    const initial = initializeMandateRegistry({ cedarDir: f.cedar, signer: f.gate, controllers: [f.controller] });
    writeFileSync(join(f.cedar, 'policy.cedar'), WIDENED_POLICY);
    expect(refreshManagedMandate({ cedarDir: f.cedar, signer: f.gate })).toMatchObject({
      valid: false,
      code: 'policy_head_mismatch',
    });
    expect(initial.active.policy_digest).not.toBe(snapshotFromDirectory(f.cedar).policy_digest);
  });

  it('automatically restores the signed baseline as soon as an approved grant expires', () => {
    const f = setup();
    const start = new Date('2026-07-10T12:00:00.000Z');
    const initial = initializeMandateRegistry({ cedarDir: f.cedar, signer: f.gate, controllers: [f.controller], now: start });
    const proposal = createPolicyProposal({
      cedarDir: f.cedar, signer: f.gate, candidateDir: f.candidate,
      denialReceipt: denial(f.gate, initial.active.policy_digest, start.toISOString()),
      reason: 'Temporary controlled exception for the approved workflow.',
      expiresAt: '2026-07-10T12:05:00.000Z', now: start,
    });
    const approval = createDirectControllerApproval({ proposal, controller: f.controller, privateKey: f.controllerPrivate, now: new Date('2026-07-10T12:01:00.000Z') });
    approvePolicyProposalWithDirectSignature({ cedarDir: f.cedar, signer: f.gate, proposalId: proposal.proposal_id, approval, now: new Date('2026-07-10T12:01:00.000Z') });

    const afterExpiry = refreshManagedMandate({ cedarDir: f.cedar, signer: f.gate, now: new Date('2026-07-10T12:06:00.000Z') });
    expect(afterExpiry).toMatchObject({ valid: true, expired_reverted: true });
    expect(afterExpiry.registry?.active.policy_digest).toBe(initial.active.policy_digest);
    expect(readFileSync(join(f.cedar, 'policy.cedar'), 'utf-8')).toBe(BASE_POLICY);
    expect(afterExpiry.registry?.history.at(-1)?.event).toBe('policy_expired_reverted');
  });

  it('rejects self-approval and detects any registry or transition tampering offline', () => {
    const f = setup();
    const selfController: DirectController = { id: f.gate.kid, label: 'Not a controller', type: 'ed25519', public_key: f.gate.publicKey };
    expect(() => initializeMandateRegistry({ cedarDir: f.cedar, signer: f.gate, controllers: [selfController] })).toThrow(/cannot be registered/);

    const registry = initializeMandateRegistry({ cedarDir: f.cedar, signer: f.gate, controllers: [f.controller] });
    registry.history[0].head_after = 'sha256:' + '0'.repeat(64);
    expect(verifyMandateRegistry(registry)).toMatchObject({ valid: false });
  });

  it('persists a WebAuthn challenge that is cryptographically bound to the exact policy proposal', () => {
    const f = setup();
    const passkeyPrivate = bytesToHex(randomBytes(32));
    const controller = {
      id: 'cro-passkey', label: 'CRO passkey', type: 'webauthn' as const,
      credential_id: 'credential-1', credential_public_key: { alg: -8 as const, publicKeyHex: bytesToHex(ed25519.getPublicKey(passkeyPrivate)) }, sign_count: 0,
    };
    const initial = initializeMandateRegistry({ cedarDir: f.cedar, signer: f.gate, controllers: [controller] });
    const proposal = createPolicyProposal({
      cedarDir: f.cedar, signer: f.gate, candidateDir: f.candidate,
      denialReceipt: denial(f.gate, initial.active.policy_digest, new Date().toISOString()),
      reason: 'Awaiting a passkey controller.', expiresAt: '2030-01-01T00:00:00.000Z',
    });
    const challenge = createWebAuthnPolicyChallenge({ cedarDir: f.cedar, proposalId: proposal.proposal_id, controllerId: controller.id, rpId: 'localhost' });
    expect(challenge.requestId).toBe(proposal.proposal_id);
    expect(challenge.toolName).toBe('scopeblind:policy-change');
    expect(loadMandateRegistry(f.cedar)?.pending_webauthn[proposal.proposal_id]?.challenge.contextHash).toBe(challenge.contextHash);
    expect(readFileSync(mandatePaths(f.cedar).registry, 'utf-8')).toContain(proposal.proposal_id);

    const approved = approvePolicyProposalWithWebAuthn({
      cedarDir: f.cedar, signer: f.gate, proposalId: proposal.proposal_id,
      assertion: signedPasskeyAssertion(challenge, passkeyPrivate, 'http://localhost:9377'),
      expectedOrigin: 'http://localhost:9377',
    });
    expect(approved.active.policy_digest).toBe(proposal.proposed_policy_digest);
    expect(verifyMandateRegistry(approved)).toMatchObject({ valid: true });
  });
});
