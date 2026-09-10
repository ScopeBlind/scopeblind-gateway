/**
 * Regression tests for the mandate-lifecycle hardening pass (2026-07-10).
 * Each test reproduces a CONFIRMED finding from the adversarial review and
 * asserts the attack is now rejected. See build-sprints-2026-07.md.
 */
import { describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
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
  initializeMandateRegistry,
  loadMandateRegistry,
  verifyMandateRegistry,
  type DirectController,
  type GateSigner,
  type WebAuthnController,
} from './mandate-lifecycle.js';

const BASE_POLICY = 'forbid(principal, action, resource == Tool::"Bash");\npermit(principal, action, resource);\n';
const WIDENED_POLICY = 'permit(principal, action, resource == Tool::"Bash");\npermit(principal, action, resource);\n';
const AT = new Date('2026-07-10T12:00:00.000Z');
const FAR = '2030-01-01T00:00:00.000Z';

function key(kid: string): GateSigner {
  const privateKey = bytesToHex(randomBytes(32));
  return { privateKey, publicKey: bytesToHex(ed25519.getPublicKey(privateKey)), kid };
}

function setup() {
  const root = mkdtempSync(join(tmpdir(), 'pmcp-harden-'));
  const cedar = join(root, 'cedar');
  const candidate = join(root, 'candidate');
  mkdirSync(cedar); mkdirSync(candidate);
  writeFileSync(join(cedar, 'policy.cedar'), BASE_POLICY);
  writeFileSync(join(candidate, 'policy.cedar'), WIDENED_POLICY);
  const gate = key('gate-1');
  const controllerPrivate = bytesToHex(randomBytes(32));
  const controller: DirectController = {
    id: 'cro-1', label: 'Chief Risk Officer', type: 'ed25519',
    public_key: bytesToHex(ed25519.getPublicKey(controllerPrivate)),
  };
  return { root, cedar, candidate, gate, controller, controllerPrivate };
}

function denial(gate: GateSigner, policyDigest: string, at: string, requestId = 'denial-1') {
  return createReceiptEnvelope({
    type: 'protectmcp:decision', tool_name: 'Bash', decision: 'deny', reason: 'restricted_tool',
    policy_digest: policyDigest, request_id: requestId, mode: 'enforce', public_key: gate.publicKey,
  }, gate.privateKey, gate.kid, at).envelope;
}

/** Full ed25519 widening cycle: init -> propose -> approve -> activate. */
function widened() {
  const f = setup();
  const initial = initializeMandateRegistry({ cedarDir: f.cedar, signer: f.gate, controllers: [f.controller], now: AT });
  const proposal = createPolicyProposal({
    cedarDir: f.cedar, signer: f.gate, candidateDir: f.candidate,
    denialReceipt: denial(f.gate, initial.active.policy_digest, AT.toISOString()),
    reason: 'Reviewed migration window.', expiresAt: FAR, now: AT,
  });
  const approval = createDirectControllerApproval({ proposal, controller: f.controller, privateKey: f.controllerPrivate, now: AT });
  approvePolicyProposalWithDirectSignature({ cedarDir: f.cedar, signer: f.gate, proposalId: proposal.proposal_id, approval, now: AT });
  return { f, proposalId: proposal.proposal_id };
}

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
function signedPasskeyAssertion(challenge: { challenge: string; rpId: string }, privateKey: string, origin: string) {
  const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: challenge.challenge, origin }), 'utf-8');
  const authData = new Uint8Array(37);
  authData.set(sha256(new TextEncoder().encode(challenge.rpId)), 0);
  authData[32] = 0x05; authData[36] = 1;
  const signature = ed25519.sign(concatBytes(authData, sha256(clientData)), privateKey);
  return { credentialId: 'credential-1', authenticatorData: b64url(authData), clientDataJSON: b64url(clientData), signature: b64url(signature) };
}

/** Full webauthn cycle with an Ed25519 passkey, returns the registry + ids. */
function webauthnWidened() {
  const f = setup();
  const passkeyPrivate = bytesToHex(randomBytes(32));
  const controller: WebAuthnController = {
    id: 'cro-passkey', label: 'CRO passkey', type: 'webauthn', credential_id: 'credential-1',
    credential_public_key: { alg: -8, publicKeyHex: bytesToHex(ed25519.getPublicKey(passkeyPrivate)) }, sign_count: 0,
  };
  // WebAuthn challenge freshness is checked against the real wall clock (the
  // challenge createdAt is real time), so this cycle uses real time throughout.
  const nowStr = new Date().toISOString();
  const initial = initializeMandateRegistry({ cedarDir: f.cedar, signer: f.gate, controllers: [controller] });
  const proposal = createPolicyProposal({
    cedarDir: f.cedar, signer: f.gate, candidateDir: f.candidate,
    denialReceipt: denial(f.gate, initial.active.policy_digest, nowStr),
    reason: 'Passkey approval.', expiresAt: FAR,
  });
  const challenge = createWebAuthnPolicyChallenge({ cedarDir: f.cedar, proposalId: proposal.proposal_id, controllerId: controller.id, rpId: 'localhost' });
  approvePolicyProposalWithWebAuthn({
    cedarDir: f.cedar, signer: f.gate, proposalId: proposal.proposal_id,
    assertion: signedPasskeyAssertion(challenge, passkeyPrivate, 'http://localhost:9377'), expectedOrigin: 'http://localhost:9377',
  });
  return { f, proposalId: proposal.proposal_id, controllerId: controller.id };
}

describe('mandate lifecycle hardening', () => {
  it('positive control: a legitimately widened registry verifies', () => {
    const { f } = widened();
    expect(verifyMandateRegistry(loadMandateRegistry(f.cedar)!)).toMatchObject({ valid: true });
  });

  it('rejects an injected controller (controller set is gate-signed)', () => {
    const { f } = widened();
    const reg = loadMandateRegistry(f.cedar)!;
    const rogue = bytesToHex(randomBytes(32));
    reg.controllers.push({ id: 'rogue', label: 'Rogue', type: 'ed25519', public_key: bytesToHex(ed25519.getPublicKey(rogue)) });
    expect(verifyMandateRegistry(reg)).toMatchObject({ valid: false, code: 'controller_set_unanchored' });
  });

  it('rejects a swapped passkey credential key (credential is inside the signed set)', () => {
    const { f } = webauthnWidened();
    const reg = loadMandateRegistry(f.cedar)!;
    const c = reg.controllers.find((x) => x.type === 'webauthn') as WebAuthnController;
    c.credential_public_key = { alg: -8, publicKeyHex: bytesToHex(ed25519.getPublicKey(bytesToHex(randomBytes(32)))) };
    expect(verifyMandateRegistry(reg)).toMatchObject({ valid: false, code: 'controller_set_unanchored' });
  });

  it('rejects stripping the active expiry (temporary widening cannot be made permanent)', () => {
    const { f } = widened();
    const reg = loadMandateRegistry(f.cedar)!;
    delete reg.active.expires_at;
    expect(verifyMandateRegistry(reg)).toMatchObject({ valid: false, code: 'active_expiry_mismatch' });
  });

  it('rejects extending the active expiry beyond the signed activation', () => {
    const { f } = widened();
    const reg = loadMandateRegistry(f.cedar)!;
    reg.active.expires_at = '2099-01-01T00:00:00.000Z';
    expect(verifyMandateRegistry(reg)).toMatchObject({ valid: false, code: 'active_expiry_mismatch' });
  });

  it('rejects making a widening permanent by ALSO clearing proposal_id (active state is chain-reconstructed)', () => {
    const { f } = widened();
    const reg = loadMandateRegistry(f.cedar)!;
    delete reg.active.expires_at;
    delete reg.active.proposal_id; // the earlier weak check keyed off proposal_id; this must still be caught
    expect(verifyMandateRegistry(reg)).toMatchObject({ valid: false, code: 'active_expiry_mismatch' });
  });

  it('rejects repointing the active baseline at the widened head (would neuter expiry-revert)', () => {
    const { f } = widened();
    const reg = loadMandateRegistry(f.cedar)!;
    reg.active.baseline_policy_digest = reg.active.policy_digest; // revert would become a no-op
    expect(verifyMandateRegistry(reg)).toMatchObject({ valid: false, code: 'active_baseline_mismatch' });
  });

  it('rejects clearing the active proposal_id on a widened head', () => {
    const { f } = widened();
    const reg = loadMandateRegistry(f.cedar)!;
    delete reg.active.proposal_id; // but keep expires_at, so only the proposal_id is wrong
    expect(verifyMandateRegistry(reg)).toMatchObject({ valid: false, code: 'active_proposal_mismatch' });
  });

  it('rejects deleting the display expiry on the activation transition (display must equal the signed payload)', () => {
    const { f } = widened();
    const reg = loadMandateRegistry(f.cedar)!;
    const activation = reg.history.find((t) => t.event === 'policy_activated')!;
    delete activation.expiry;          // signed payload.expiry still says the real expiry
    delete reg.active.expires_at;       // and the active field is cleared too
    expect(verifyMandateRegistry(reg)).toMatchObject({ valid: false, code: 'transition_state_mismatch' });
  });

  it('refuses to reuse one denial receipt for a second proposal', () => {
    const f = setup();
    const initial = initializeMandateRegistry({ cedarDir: f.cedar, signer: f.gate, controllers: [f.controller], now: AT });
    const d = denial(f.gate, initial.active.policy_digest, AT.toISOString());
    createPolicyProposal({ cedarDir: f.cedar, signer: f.gate, candidateDir: f.candidate, denialReceipt: d, reason: 'first', expiresAt: FAR, now: AT });
    expect(() => createPolicyProposal({ cedarDir: f.cedar, signer: f.gate, candidateDir: f.candidate, denialReceipt: d, reason: 'second', expiresAt: FAR, now: AT }))
      .toThrow(/already been used/);
  });

  it('refuses to stack a widening on an already-active temporary grant', () => {
    const { f } = widened(); // active is now widened, with an expiry
    const cand2 = join(f.root, 'cand2'); mkdirSync(cand2);
    writeFileSync(join(cand2, 'policy.cedar'), 'permit(principal, action, resource);\npermit(principal, action, resource == Tool::"Bash");\npermit(principal, action, resource == Tool::"Wire");\n');
    const reg = loadMandateRegistry(f.cedar)!;
    expect(() => createPolicyProposal({
      cedarDir: f.cedar, signer: f.gate, candidateDir: cand2,
      denialReceipt: denial(f.gate, reg.active.policy_digest, new Date().toISOString(), 'denial-2'),
      reason: 'stack attempt', expiresAt: FAR,
    })).toThrow(/already active/);
  });

  it('refuses a webauthn controller whose credential key equals the gate key', () => {
    const f = setup();
    const clash: WebAuthnController = {
      id: 'clash', label: 'Clash', type: 'webauthn', credential_id: 'c',
      credential_public_key: { alg: -8, publicKeyHex: f.gate.publicKey }, sign_count: 0,
    };
    expect(() => initializeMandateRegistry({ cedarDir: f.cedar, signer: f.gate, controllers: [clash], now: AT }))
      .toThrow(/gate signing key cannot also be a mandate controller/);
  });

  it('does not brick when a controller sign_count advances after approval (no fail-closed DoS)', () => {
    const { f } = webauthnWidened();
    const reg = loadMandateRegistry(f.cedar)!;
    const c = reg.controllers.find((x) => x.type === 'webauthn') as WebAuthnController;
    c.sign_count = 99; // a later approval by the same authenticator advances the stored counter
    expect(verifyMandateRegistry(reg)).toMatchObject({ valid: true });
  });

  it('rejects a webauthn approval whose challenge is not the proposal binding', () => {
    const { f } = webauthnWidened();
    const reg = loadMandateRegistry(f.cedar)!;
    const approval = reg.approvals[Object.keys(reg.approvals)[0]] as { challenge: { challenge: string } };
    approval.challenge.challenge = b64url(randomBytes(32));
    expect(verifyMandateRegistry(reg)).toMatchObject({ valid: false, code: 'approval_not_bound_to_proposal' });
  });
});
