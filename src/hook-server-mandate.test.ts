/** End-to-end gate proof: unmanaged edits cannot become live policy. */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from '@noble/hashes/utils';
import type { Server } from 'node:http';
import { initializeMandateRegistry, mandatePaths, type DirectController, type GateSigner } from './mandate-lifecycle.js';

const PORT = 19380;
const ROOT = mkdtempSync(join(tmpdir(), 'pmcp-hook-mandate-'));
const CEDAR = join(ROOT, 'cedar');
const KEYS = join(ROOT, 'keys');
const BASE = 'forbid(principal, action, resource == Tool::"Bash");\npermit(principal, action, resource);\n';
const EDITED = 'permit(principal, action, resource);\n';

function key(kid: string): GateSigner {
  const privateKey = bytesToHex(randomBytes(32));
  return { privateKey, publicKey: bytesToHex(ed25519.getPublicKey(privateKey)), kid };
}

const gate = key('managed-gate');
const controllerPrivate = bytesToHex(randomBytes(32));
const controller: DirectController = {
  id: 'cro-controller', label: 'CRO', type: 'ed25519', public_key: bytesToHex(ed25519.getPublicKey(controllerPrivate)),
};

mkdirSync(CEDAR); mkdirSync(KEYS);
writeFileSync(join(CEDAR, 'policy.cedar'), BASE);
writeFileSync(join(KEYS, 'gateway.json'), JSON.stringify(gate));
const initial = initializeMandateRegistry({ cedarDir: CEDAR, signer: gate, controllers: [controller] });

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
  await new Promise((resolve) => setTimeout(resolve, 150));
}, 10_000);

afterAll(() => { server?.close(); });

async function hook(toolName: string): Promise<Record<string, unknown>> {
  const response = await fetch(`http://127.0.0.1:${PORT}/hook`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      hook_event_name: 'PreToolUse', tool_name: toolName, tool_input: {}, tool_use_id: `managed-${Date.now()}`,
    }),
  });
  return response.json() as Promise<Record<string, unknown>>;
}

describe('managed mandate hook enforcement', () => {
  it('reports its signed active policy head through the local health/status surface', async () => {
    const response = await fetch(`http://127.0.0.1:${PORT}/mandate`);
    const body = await response.json() as { valid: boolean; mandate: { active: { policy_digest: string } } };
    expect(response.status).toBe(200);
    expect(body.valid).toBe(true);
    expect(body.mandate.active.policy_digest).toBe(initial.active.policy_digest);
  });

  it('fails closed rather than hot-reloading an unauthorised Cedar edit, and signs the last known registry head into the denial receipt', async () => {
    writeFileSync(join(CEDAR, 'policy.cedar'), EDITED);
    const result = await hook('Bash');
    const output = result.hookSpecificOutput as { permissionDecision?: string; permissionDecisionReason?: string };
    expect(output.permissionDecision).toBe('deny');
    expect(output.permissionDecisionReason).toContain('policy_head_mismatch');

    const receiptLines = readFileSync(join(ROOT, '.protect-mcp-receipts.jsonl'), 'utf-8').trim().split('\n');
    const receipt = JSON.parse(receiptLines.at(-1)!) as { payload: { mandate_registry?: { active_policy_digest?: string }; decision?: string } };
    expect(receipt.payload.decision).toBe('deny');
    expect(receipt.payload.mandate_registry?.active_policy_digest).toBe(initial.active.policy_digest);
  });

  // Regression guard for a fail-OPEN (the June-2026 incident class): a registry
  // that cannot even be PARSED made ensureManagedMandate throw, which escaped the
  // explicit-deny path and returned an HTTP 400 with no permissionDecision — which
  // a PreToolUse hook reads as "no deny" and lets the tool run. Corrupting the
  // registry to invalid JSON is the easiest attack for anyone who can already
  // tamper the policy dir, so it MUST deny.
  it('fails closed with an explicit deny (not a 400 the host reads as allow) when the registry is corrupt JSON', async () => {
    const regPath = mandatePaths(CEDAR).registry;
    const good = readFileSync(regPath, 'utf-8');
    writeFileSync(regPath, 'this is not valid json {{{');
    try {
      const result = await hook('read_file');
      const output = result.hookSpecificOutput as { permissionDecision?: string; permissionDecisionReason?: string };
      expect(output.permissionDecision).toBe('deny');
      expect(output.permissionDecisionReason).toContain('mandate_registry_unreadable');
    } finally {
      writeFileSync(regPath, good);
    }
  });
});
