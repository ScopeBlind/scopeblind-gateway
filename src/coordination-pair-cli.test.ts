import { describe, expect, it, vi } from 'vitest';
import { mkdtempSync, writeFileSync, chmodSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readPrivateConfig, coordinationConfigFromFile, shellQuote, claimPairing, runCoordinationSetup, runCoordinationPair } from './coordination-pair-cli.js';
import { agentConfigFilename, agentRegistration, agentPrompt, agentServerName } from './coordination-agent-setup.js';
import { encodePairingCode, decodePairingCode, REHEARSAL_PAIRING_SCOPE, REHEARSAL_PAIRING_AUDIENCE, NEGOTIATION_PAIRING_SCOPE, NEGOTIATION_PAIRING_AUDIENCE, type AgentBinding } from './coordination-pairing.js';

import { bytesToHex, generateIdentity, makeRequest, sign, sha256 } from './coordination-protocol.js';
const config = { type: 'scopeblind.coordination.config.v1', endpoint: 'https://scopeblind.com/api/coordination', roomId: 'room-001', authorityKey: 'aa'.repeat(32), agentKey: 'bb'.repeat(32), token: 'private-token', name: 'Test' };
describe('private agent pairing setup', () => {
  it('refuses public-readable files, symlinks, malformed JSON and unfinished pairing without leaking credentials', () => {
    const dir = mkdtempSync(join(tmpdir(), 'scopeblind-config-'));
    try {
      const path = join(dir, 'room.json'); writeFileSync(path, JSON.stringify(config), { mode: 0o600 });
      expect(readPrivateConfig(path).token).toBe('private-token');
      expect(() => coordinationConfigFromFile(path)).toThrow('Pairing has not completed');
      chmodSync(path, 0o644); expect(() => readPrivateConfig(path)).toThrow('permissions 600'); chmodSync(path, 0o600);
      symlinkSync(path, join(dir, 'linked.json')); expect(() => readPrivateConfig(join(dir, 'linked.json'))).toThrow('could not be opened');
      writeFileSync(path, '{"token":"do-not-print-secret');
      try { readPrivateConfig(path); throw new Error('Expected rejection'); } catch (error) { expect(String(error)).toContain('not valid JSON'); expect(String(error)).not.toContain('do-not-print'); }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
  it('parses only bounded pairing codes without extra scopes', () => {
    const code = { version: 1 as const, endpoint: config.endpoint, room_id: config.roomId, pair_id: 'pair-001', authority_key: config.authorityKey, secret: 'cc'.repeat(32) };
    expect(decodePairingCode(encodePairingCode(code))).toEqual(code);
    expect(() => decodePairingCode(encodePairingCode({ ...code, scope: 'approve' } as typeof code))).toThrow('invalid');
    expect(() => decodePairingCode('secret')).toThrow('incomplete');
    expect(shellQuote("/tmp/a' $(echo bad).json")).toBe("'/tmp/a'\\'' $(echo bad).json'");
  });
  it('keeps legacy codes unchanged and accepts only explicit test-only v2 scope/audience', () => {
    const code = { version: 2 as const, endpoint: config.endpoint, room_id: config.roomId, pair_id: 'pair-001', authority_key: config.authorityKey, secret: 'cc'.repeat(32), scope: REHEARSAL_PAIRING_SCOPE, audience: REHEARSAL_PAIRING_AUDIENCE };
    const encoded = encodePairingCode(code);
    expect(encoded.startsWith('sbp2.')).toBe(true);
    expect(decodePairingCode(encoded)).toEqual(code);
    for (const changed of [{ ...code, scope: [...code.scope, 'execute'] }, { ...code, scope: ['rehearsal_get'] }, { ...code, audience: 'scopeblind.coordination.sample-ledger' }, { ...code, owner_key: config.agentKey }]) {
      expect(() => decodePairingCode(encodePairingCode(changed as any))).toThrow('invalid');
    }
    expect(() => decodePairingCode(encoded.replace('sbp2.', 'sbp1.'))).toThrow('invalid');
  });
  it('verifies that the signed owner grant explicitly names exactly the test scope', async () => {
    const owner = await generateIdentity(), authority = await generateIdentity();
    const keypair = await crypto.subtle.generateKey('Ed25519', true, ['sign','verify']) as CryptoKeyPair;
    const agent = { privateKey: keypair.privateKey, publicKey: bytesToHex(new Uint8Array(await crypto.subtle.exportKey('raw', keypair.publicKey))) };
    const secret = 'cc'.repeat(32), expires = new Date(Date.now() + 3600000).toISOString();
    const code = { version: 2 as const, endpoint: config.endpoint, room_id: config.roomId, pair_id: 'pair-001', authority_key: authority.publicKey, secret, scope: REHEARSAL_PAIRING_SCOPE, audience: REHEARSAL_PAIRING_AUDIENCE };
    const pending = { ...config, type: 'scopeblind.coordination.config.v1' as const, agentKey: agent.publicKey, authorityKey: authority.publicKey, pending: { code, privateKey: bytesToHex(new Uint8Array(await crypto.subtle.exportKey('pkcs8', agent.privateKey))) } };
    const grantBody = { pair_id: code.pair_id, secret_hash: await sha256(secret), token_expires_at: expires, scope: REHEARSAL_PAIRING_SCOPE };
    let binding = await sign<AgentBinding>({ type: 'scopeblind.coordination.agent-binding.v1', pair_id: code.pair_id, room_id: code.room_id, agreement_digest: 'dd'.repeat(32), owner_key: owner.publicKey, agent_key: agent.publicKey, name: config.name, scope: REHEARSAL_PAIRING_SCOPE, audience: REHEARSAL_PAIRING_AUDIENCE, issued_at: new Date().toISOString(), expires_at: expires, owner_authorization: await sign(makeRequest('pair_create', code.room_id, grantBody), owner) }, authority);
    const fetcher = async () => new Response(JSON.stringify({ ok: true, binding, executor_token: config.token }));
    const ready = await claimPairing(pending, fetcher);
    expect(ready.purpose).toBe('rehearsal'); expect(ready.pending).toBeUndefined();
    const { scope: _scope, ...legacy } = grantBody;
    binding = await sign({ ...binding.payload, owner_authorization: await sign(makeRequest('pair_create', code.room_id, legacy), owner) }, authority);
    await expect(claimPairing(pending, fetcher)).rejects.toThrow('could not be verified');
    binding = await sign({ ...binding.payload, scope: [...REHEARSAL_PAIRING_SCOPE, 'execute'] }, authority);
    await expect(claimPairing(pending, fetcher)).rejects.toThrow('exact scope');
  });

});

describe('separate principal negotiation pairing', () => {
  const code = { version: 3 as const, endpoint: config.endpoint, room_id: config.roomId, pair_id: 'neg-pair-001', authority_key: config.authorityKey, secret: 'cc'.repeat(32), scope: NEGOTIATION_PAIRING_SCOPE, audience: NEGOTIATION_PAIRING_AUDIENCE, session_id: 'neg-session-001', principal_key: 'ee'.repeat(32) };
  it('decodes sbp3 only with exact principal, session, scope and audience while preserving older code formats', () => {
    expect(encodePairingCode(code).startsWith('sbp3.')).toBe(true); expect(decodePairingCode(encodePairingCode(code))).toEqual(code);
    for (const mutation of [{ ...code, version: 2 }, { ...code, principal_key: '' }, { ...code, session_id: 'short' }, { ...code, scope: [...code.scope,'execute'] }, { ...code, scope: [...code.scope,'negotiation_step'] }, { ...code, scope: [...code.scope].reverse() }, { ...code, audience: REHEARSAL_PAIRING_AUDIENCE }, { ...code, brief: 'PRIVATE' }]) {
      expect(() => decodePairingCode(encodePairingCode(mutation as any))).toThrow('invalid');
    }
    expect(() => decodePairingCode(encodePairingCode(code).replace('sbp3.','sbp1.'))).toThrow('invalid');
  });
  it('claims with a separate agent key and verifies the principal-signed session-specific authority', async () => {
    const principal = await generateIdentity(), other = await generateIdentity(), authority = await generateIdentity();
    const pair = await crypto.subtle.generateKey('Ed25519', true, ['sign','verify']) as CryptoKeyPair;
    const agentKey = bytesToHex(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)));
    const c = { ...code, principal_key: principal.publicKey, authority_key: authority.publicKey }, expires = new Date(Date.now() + 3600000).toISOString();
    const pending = { ...config, type: 'scopeblind.coordination.config.v1' as const, authorityKey: authority.publicKey, agentKey, purpose: 'negotiation' as const, sessionId: c.session_id, principalKey: c.principal_key, pending: { code: c, privateKey: bytesToHex(new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))) } };
    const grantBody = { session_id: c.session_id, pair_id: c.pair_id, name: config.name, secret_hash: await sha256(c.secret), expires_at: new Date(Date.now() + 600000).toISOString(), token_expires_at: expires, scope: NEGOTIATION_PAIRING_SCOPE };
    const grant = await sign(makeRequest('negotiation_pair_create', c.room_id, grantBody), principal);
    const base: AgentBinding = { type: 'scopeblind.coordination.agent-binding.v1', pair_id: c.pair_id, room_id: c.room_id, session_id: c.session_id, principal_key: principal.publicKey, agreement_digest: 'dd'.repeat(32), owner_key: principal.publicKey, agent_key: agentKey, name: config.name, scope: NEGOTIATION_PAIRING_SCOPE, audience: NEGOTIATION_PAIRING_AUDIENCE, issued_at: new Date().toISOString(), expires_at: expires, owner_authorization: grant };
    let binding = await sign(base, authority), requests = 0;
    const fetcher: typeof fetch = async (_url, options) => {
      requests++; const request = JSON.parse(String(options?.body)).request;
      expect(request.signer).toBe(agentKey); expect(request.payload.action).toBe('negotiation_pair_claim');
      expect(request.payload.body.session_id).toBe(c.session_id); expect(request.payload.body.executor_token).toBe(config.token); expect(options?.redirect).toBe('error');
      return new Response(JSON.stringify({ ok: true, binding, executor_token: config.token }));
    };
    const ready = await claimPairing(pending, fetcher);
    expect(ready.purpose).toBe('negotiation'); expect(ready.sessionId).toBe(c.session_id); expect(ready.principalKey).toBe(principal.publicKey); expect(ready.pending).toBeUndefined();
    const dir = mkdtempSync(join(tmpdir(), 'scopeblind-neg-config-'));
    try { const path = join(dir, 'principal.json'); writeFileSync(path, JSON.stringify(ready), { mode: 0o600 }); expect(coordinationConfigFromFile(path)).toMatchObject({ purpose: 'negotiation', sessionId: c.session_id, principalKey: principal.publicKey });
      const output = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
      try { runCoordinationSetup(['--config', path]); runCoordinationSetup(['--config', path, '--client', 'json']); const printed = output.mock.calls.map(c => c[0]).join(''); expect(printed).toContain('protect-mcp@0.21.0'); expect(printed).not.toContain('0.16.0'); expect(printed).toContain('scopeblind-negotiate-' + principal.publicKey.slice(0, 8)); expect(printed).not.toContain(config.token); } finally { output.mockRestore(); } } finally { rmSync(dir, { recursive: true, force: true }); }
    for (const override of [{ session_id: 'other-session' }, { principal_key: other.publicKey }, { owner_key: other.publicKey }, { scope: [...NEGOTIATION_PAIRING_SCOPE,'negotiation_approve'] }, { audience: REHEARSAL_PAIRING_AUDIENCE }, { expires_at: new Date(Date.now()-1000).toISOString() }]) {
      binding = await sign({ ...base, ...override } as AgentBinding, authority); await expect(claimPairing(pending, fetcher)).rejects.toThrow();
    }
    for (const override of [{ session_id: 'other-session' }, { scope: [...NEGOTIATION_PAIRING_SCOPE,'negotiation_step'] }, { token_expires_at: new Date(Date.now()+7200000).toISOString() }, { secret_hash: '00'.repeat(32) }]) {
      binding = await sign({ ...base, owner_authorization: await sign(makeRequest('negotiation_pair_create', c.room_id, { ...grantBody, ...override }), principal) }, authority);
      await expect(claimPairing(pending, fetcher)).rejects.toThrow('could not be verified');
    }
    binding = await sign({ ...base, owner_authorization: await sign(grant.payload, other) }, authority);
    await expect(claimPairing(pending, fetcher)).rejects.toThrow('could not be verified');
    const before = requests;
    await expect(claimPairing({ ...pending, sessionId: 'other-session' }, fetcher)).rejects.toThrow('session and principal'); expect(requests).toBe(before);
  });
});


describe('client-specific setup and recovery instructions', () => {
  it('produces accurate shell-safe Claude, Codex, and generic MCP setup without private values', () => {
    const path="/tmp/a' $(echo should-not-execute).json", name='scopeblind-work-pair-001';
    const claude=agentRegistration('claude-code',name,path), codex=agentRegistration('codex',name,path), generic=JSON.parse(agentRegistration('json',name,path));
    expect(claude).toContain('claude mcp add --transport stdio --scope local '+name+' -- npx --yes ');
    expect(codex).toContain('codex mcp add '+name+' -- npx --yes ');
    expect(claude).toContain(shellQuote(path)); expect(codex).toContain(shellQuote(path));
    expect(generic.mcpServers[name].args.at(-1)).toBe(path);
    expect(generic.mcpServers[name].env).toBeUndefined();
    for(const command of [claude,codex,JSON.stringify(generic)])expect(command).not.toContain(config.token);
  });
  it('isolates new connections and resumes the exact purpose and session', () => {
    const execution=agentConfigFilename('execution','room-001','pair-001'), test=agentConfigFilename('rehearsal','room-001','pair-001'), fresh=agentConfigFilename('execution','room-001','pair-002');
    expect(new Set([execution,test,fresh]).size).toBe(3);
    expect(()=>agentConfigFilename('execution','../../bad','pair-001')).toThrow();
    expect(agentServerName('execution','room-001','pair-001')).not.toBe(agentServerName('execution','room-001','pair-002'));
    expect(agentPrompt('negotiation','room-001','session-001')).toContain('session-001');
    expect(agentPrompt('negotiation','room-001','session-001')).toContain('coordination.inspect_negotiation');
    expect(agentPrompt('rehearsal','room-001')).toContain('coordination.inspect_rehearsal');
    expect(agentPrompt('execution','room-001')).toContain('Reuse existing operation IDs');
  });
  it('preserves legacy server names, isolates new ones, and refuses expired reconnect setup without changing credentials', () => {
    const dir=mkdtempSync(join(tmpdir(),'scopeblind-resume-')), path=join(dir,'existing.json');
    const binding={payload:{audience:'scopeblind.coordination.sample-ledger',pair_id:'pair-001',expires_at:new Date(Date.now()+3600000).toISOString()}};
    const output=vi.spyOn(process.stdout,'write').mockImplementation(()=>true);
    try {
      writeFileSync(path,JSON.stringify({...config,binding}),{mode:0o600});
      runCoordinationSetup(['--config',path,'--client','codex']);
      expect(String(output.mock.calls.at(-1)![0])).toContain('codex mcp add scopeblind --');
      writeFileSync(path,JSON.stringify({...config,binding,setupVersion:2}));
      runCoordinationSetup(['--config',path,'--client','codex']);
      expect(String(output.mock.calls.at(-1)![0])).toContain('codex mcp add scopeblind-work-pair-001 --');
      expect(readPrivateConfig(path).token).toBe(config.token);
      binding.payload.expires_at=new Date(Date.now()-1000).toISOString();
      writeFileSync(path,JSON.stringify({...config,binding,setupVersion:2}));
      expect(()=>runCoordinationSetup(['--config',path,'--client','codex'])).toThrow('expired');
      expect(output.mock.calls.flat().join('')).not.toContain(config.token);
    } finally {output.mockRestore();rmSync(dir,{recursive:true,force:true});}
  });
  it('rejects raw code flags and unknown clients before reading input or writing a connection', async () => {
    await expect(runCoordinationPair(['--code','private-secret'])).rejects.toThrow('Unsupported');
    await expect(runCoordinationPair(['--client','unknown'])).rejects.toThrow('Supported setup clients');
  });
});
