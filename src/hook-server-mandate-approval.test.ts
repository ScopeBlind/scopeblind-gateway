/** Local controller page must reveal the exact diff before asking for a passkey. */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from '@noble/hashes/utils';
import { createReceiptEnvelope } from './acta-envelope.js';
import { createPolicyProposal, initializeMandateRegistry, type GateSigner, type WebAuthnController } from './mandate-lifecycle.js';
import type { Server } from 'node:http';

const PORT = 19384;
const ROOT = mkdtempSync(join(tmpdir(), 'pmcp-mandate-approval-'));
const CEDAR = join(ROOT, 'cedar');
const CANDIDATE = join(ROOT, 'candidate');

function key(kid: string): GateSigner {
  const privateKey = bytesToHex(randomBytes(32));
  return { privateKey, publicKey: bytesToHex(ed25519.getPublicKey(privateKey)), kid };
}

mkdirSync(CEDAR); mkdirSync(CANDIDATE); mkdirSync(join(ROOT, 'keys'));
writeFileSync(join(CEDAR, 'policy.cedar'), 'forbid(principal, action, resource == Tool::"Bash");\npermit(principal, action, resource);\n');
writeFileSync(join(CANDIDATE, 'policy.cedar'), 'permit(principal, action, resource == Tool::"Bash");\npermit(principal, action, resource);\n');
const gate = key('approval-gate');
writeFileSync(join(ROOT, 'keys', 'gateway.json'), JSON.stringify(gate));
const passkeyPrivate = bytesToHex(randomBytes(32));
const controller: WebAuthnController = {
  id: 'cro-passkey', label: 'Chief Risk Officer', type: 'webauthn', credential_id: 'cred-approval',
  credential_public_key: { alg: -8, publicKeyHex: bytesToHex(ed25519.getPublicKey(passkeyPrivate)) }, sign_count: 0,
};
const initial = initializeMandateRegistry({ cedarDir: CEDAR, signer: gate, controllers: [controller] });
const denial = createReceiptEnvelope({
  type: 'protectmcp:decision', tool_name: 'Bash', decision: 'deny', reason: 'restricted_tool',
  policy_digest: initial.active.policy_digest, request_id: 'approval-denial', mode: 'enforce', public_key: gate.publicKey,
}, gate.privateKey, gate.kid).envelope;
const proposal = createPolicyProposal({
  cedarDir: CEDAR, signer: gate, candidateDir: CANDIDATE, denialReceipt: denial,
  reason: 'Temporary operational exception for an approved migration.', expiresAt: '2030-01-01T00:00:00.000Z',
});

let server: Server | undefined;
beforeAll(async () => {
  const cwd = process.cwd(); process.chdir(ROOT);
  try {
    const { startHookServer } = await import('./hook-server.js');
    server = await startHookServer({
      port: PORT, cedarDir: CEDAR, enforce: true,
      mandateRelyingPartyId: 'localhost', mandateApprovalOrigin: `http://localhost:${PORT}`,
    });
  } finally { process.chdir(cwd); }
  await new Promise((resolve) => setTimeout(resolve, 150));
}, 10_000);
afterAll(() => { server?.close(); });

describe('managed mandate WebAuthn approval page', () => {
  it('shows the exact reason, current policy, added and removed executable statements before passkey approval', async () => {
    const page = await fetch(`http://127.0.0.1:${PORT}/mandate/proposals/${proposal.proposal_id}/approve?controller_id=${controller.id}`);
    const html = await page.text();
    expect(page.status).toBe(200);
    expect(html).toContain('You are approving exactly this policy change.');
    expect(html).toContain('Temporary operational exception');
    expect(html).toContain('permit(principal, action, resource == Tool::&quot;Bash&quot;);');
    expect(html).toContain('forbid(principal, action, resource == Tool::&quot;Bash&quot;);');
    expect(html).toContain('2030-01-01T00:00:00.000Z');
  });

  it('creates a WebAuthn challenge bound to the selected proposal and controller only', async () => {
    const response = await fetch(`http://127.0.0.1:${PORT}/mandate/proposals/${proposal.proposal_id}/webauthn/challenge?controller_id=${controller.id}`);
    const body = await response.json() as { proposal_id: string; controller: { id: string }; publicKey: { rpId: string; allowCredentials: Array<{ id: string }> } };
    expect(response.status).toBe(200);
    expect(body.proposal_id).toBe(proposal.proposal_id);
    expect(body.controller.id).toBe(controller.id);
    expect(body.publicKey.rpId).toBe('localhost');
    expect(body.publicKey.allowCredentials[0].id).toBe(controller.credential_id);
  });
});
