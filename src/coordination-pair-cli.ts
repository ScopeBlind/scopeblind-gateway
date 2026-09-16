import { createInterface } from 'node:readline';
import { Writable } from 'node:stream';
import { constants, openSync, readFileSync, closeSync, fstatSync, writeFileSync, mkdirSync, renameSync, unlinkSync, chmodSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { homedir } from 'node:os';
import { randomBytes, webcrypto } from 'node:crypto';
import { bytesToHex, canonical, importIdentity, makeRequest, sha256, sign, verify } from './coordination-protocol.js';
import { decodePairingCode, PAIRING_SCOPE, pairingScope, pairingAudience, REHEARSAL_PAIRING_AUDIENCE, NEGOTIATION_PAIRING_AUDIENCE, isRehearsalPairingScope, isNegotiationPairingScope, type AgentBinding, type PairingCode } from './coordination-pairing.js';
import { validateCoordinationConfig, type CoordinationConfig } from './coordination-config.js';
import type { Signed } from './coordination-protocol.js';
import { agentClient, agentRegistration, agentServerName, agentPrompt } from './coordination-agent-setup.js';
export { shellQuote } from './coordination-agent-setup.js';

if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
export const DEFAULT_COORDINATION_CONFIG = resolve(homedir(), '.scopeblind', 'coordination.json');
interface StoredConfig extends CoordinationConfig {
  type: 'scopeblind.coordination.config.v1'; agentKey: string; name: string; setupVersion?: 2;
  binding?: Signed<AgentBinding>; pending?: { code: PairingCode; privateKey: string };
}

export function readPrivateConfig(path: string): StoredConfig {
  let fd: number;
  try { fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW); }
  catch { throw new Error('The agent connection file could not be opened. Pair from the room first.'); }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > 64_000 || (process.platform !== 'win32' && ((stat.mode & 0o077) !== 0 || (process.getuid && stat.uid !== process.getuid())))) throw new Error('The connection file must be owned by you, with permissions 600.');
    let data: StoredConfig;
    try { data = JSON.parse(readFileSync(fd, 'utf8')) as StoredConfig; } catch { throw new Error('The agent connection file is not valid JSON.'); }
    if (data.type !== 'scopeblind.coordination.config.v1' || (data.setupVersion !== undefined && data.setupVersion !== 2) || !/^[0-9a-f]{64}$/.test(data.agentKey)) throw new Error('The agent connection file is invalid.');
    validateCoordinationConfig(data);
    return data;
  } finally { closeSync(fd); }
}
export function coordinationConfigFromFile(path: string): CoordinationConfig {
  const data = readPrivateConfig(resolve(path));
  if (!data.binding || data.pending) throw new Error('Pairing has not completed. Run the pair command again with the same --config file.');
  const binding = data.binding.payload;
  const purpose = binding.audience === NEGOTIATION_PAIRING_AUDIENCE ? 'negotiation' : binding.audience === REHEARSAL_PAIRING_AUDIENCE ? 'rehearsal' : 'execution';
  return validateCoordinationConfig({ ...data, purpose, ...(purpose === 'negotiation' ? { sessionId: binding.session_id, principalKey: binding.principal_key } : {}) });
}
function savePrivateConfig(path: string, data: StoredConfig, create: boolean): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  if (create) {
    const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { writeFileSync(fd, JSON.stringify(data) + '\n'); } finally { closeSync(fd); }
    return;
  }
  // Existing-file checks prevent following a link or weakening permissions.
  readPrivateConfig(path);
  const temporary = `${path}.${randomBytes(8).toString('hex')}.tmp`;
  try {
    writeFileSync(temporary, JSON.stringify(data) + '\n', { flag: 'wx', mode: 0o600 });
    renameSync(temporary, path);
    chmodSync(path, 0o600);
  } finally { try { unlinkSync(temporary); } catch { /* no temporary file remains */ } }
}
async function codeFromInput(variable: string): Promise<string> {
  if (process.env[variable]) return process.env[variable]!.trim();
  process.stderr.write('Paste the private pairing code from your room, then press Enter:\n');
  const silent = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
  const lines = createInterface({ input: process.stdin, output: silent, terminal: !!process.stdin.isTTY });
  try {
    for await (const line of lines) {
      if (line.trim()) {
        if (line.length > 4096) throw new Error('The pairing code is too long.');
        return line.trim();
      }
    }
  } finally { lines.close(); }
  throw new Error('No pairing code was provided. Copy a new code from your room.');
}
const safeMessage: Record<string, string> = {
  pairing_not_found: 'This pairing code could not be matched. Create a new code in the room.',
  pairing_expired_or_revoked: 'This pairing has expired or was revoked. Create a new code in the room.',
  pairing_already_claimed: 'This pairing code has already enrolled another agent. Create a new code in the room.',
  run_finalized: 'This result is already delivered. Start an authorized revision before connecting another agent.',
};

export async function claimPairing(config: StoredConfig, fetchImpl: typeof fetch = fetch): Promise<StoredConfig> {
  if (!config.pending) return config;
  const { code, privateKey } = config.pending;
  // Validate destination before transmitting either secret. Redirects are refused.
  validateCoordinationConfig(config);
  if (code.endpoint !== config.endpoint || code.room_id !== config.roomId || code.authority_key !== config.authorityKey) throw new Error('The saved pairing destination does not match its authority pin.');
  if (code.version === 3 && (config.purpose !== 'negotiation' || config.sessionId !== code.session_id || config.principalKey !== code.principal_key)) throw new Error('The saved pairing does not match its negotiation session and principal.');
  const identity = await importIdentity(privateKey, config.agentKey);
  const request = await sign(makeRequest(code.version === 3 ? 'negotiation_pair_claim' : 'pair_claim', code.room_id, { ...(code.version === 3 ? { session_id: code.session_id } : {}), pair_id: code.pair_id, secret: code.secret, executor_token: config.token, name: config.name }), identity);
  const abort = new AbortController(), timer = setTimeout(() => abort.abort(), 20_000);
  try {
    const response = await fetchImpl(config.endpoint, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ request }), redirect: 'error', signal: abort.signal });
    const raw = await response.text();
    if (raw.length > 64000) throw new Error('Pairing returned an oversized response.');
    const result = JSON.parse(raw) as { ok?: boolean; error?: string; binding?: Signed<AgentBinding>; executor_token?: string };
    if (!response.ok || !result.ok) throw new Error(safeMessage[result.error || ''] || 'The room refused this pairing. Check its state before retrying.');
    const binding = result.binding, b = binding?.payload;
    if (!binding || !b || !await verify(binding, config.authorityKey) || b.type !== 'scopeblind.coordination.agent-binding.v1' || b.room_id !== code.room_id || b.pair_id !== code.pair_id ||
      b.agent_key !== config.agentKey || b.name !== config.name || b.audience !== pairingAudience(code) || canonical(b.scope) !== canonical(pairingScope(code)) ||
      result.executor_token !== config.token || !Number.isFinite(Date.parse(b.expires_at)) || Date.parse(b.expires_at) <= Date.now() || !/^[0-9a-f]{64}$/.test(b.agreement_digest)) throw new Error('The pairing acknowledgment did not match the pinned authority and exact scope.');
    if (code.version === 3 && (b.session_id !== code.session_id || b.principal_key !== code.principal_key || b.owner_key !== code.principal_key)) throw new Error('The pairing acknowledgment names another negotiation session or principal.');
    const owner = b.owner_authorization, grant = owner?.payload;
    if (!await verify(owner, b.owner_key) || grant?.action !== (code.version === 3 ? 'negotiation_pair_create' : 'pair_create') || grant.room_id !== code.room_id || grant.body.pair_id !== code.pair_id ||
      grant.body.secret_hash !== await sha256(code.secret) || grant.body.token_expires_at !== b.expires_at || (code.version === 3 ? !isNegotiationPairingScope(grant.body.scope) || grant.body.session_id !== code.session_id : code.version === 2 ? !isRehearsalPairingScope(grant.body.scope) : grant.body.scope !== undefined)) throw new Error('The owner authorization for this connection could not be verified.');
    if (grant.body.expected_agent_key !== undefined && (code.version !== 3 || grant.body.expected_agent_key !== config.agentKey)) throw new Error('The owner authorization is bound to another agent key.');
    const { pending: _pending, ...ready } = config;
    return { ...ready, purpose: code.version === 3 ? 'negotiation' : code.version === 2 ? 'rehearsal' : 'execution', binding };
  } catch (error) {
    if (error instanceof Error && error.name !== 'AbortError' && !/fetch|connect|JSON|Unexpected|network/i.test(error.message)) throw error;
    throw new Error('The pairing response could not be verified. Rerun the same command and config to recover safely.');
  } finally { clearTimeout(timer); }
}

function configArgs(args: string[], pairing: boolean): Map<string, string> {
  const options = new Map<string, string>(), allowed = new Set(pairing ? ['--config', '--name', '--code-env', '--client'] : ['--config', '--client']);
  for (let i = 0; i < args.length; i += 2) {
    if (!allowed.has(args[i]) || options.has(args[i]) || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error('Unsupported, repeated, or incomplete connection option.');
    options.set(args[i], args[i + 1]);
  }
  return options;
}
export async function runCoordinationPair(args: string[]): Promise<void> {
  const options = configArgs(args, true), path = resolve(options.get('--config') || DEFAULT_COORDINATION_CONFIG);
  const client = agentClient(options.get('--client') || 'claude-code');
  let config: StoredConfig | undefined;
  try { config = readPrivateConfig(path); } catch (error) {
    try { const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW); closeSync(fd); throw error; }
    catch (check) { if ((check as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  }
  if (config?.binding && !config.pending) {
    if (Date.parse(config.binding.payload.expires_at) <= Date.now()) throw new Error('This saved connection has expired. Create a fresh pairing in the room and use its new config filename.');
    process.stdout.write('This config is already paired. Its existing identity and scope are unchanged. Reuse the setup below to reconnect; the room will confirm readiness only after a successful tool inspection. A revoked connection needs a fresh code and config filename.\n');
    runCoordinationSetup(['--config', path, '--client', client]);
    const existing = coordinationConfigFromFile(path);
    process.stdout.write('\nAsk your agent:\n' + agentPrompt(existing.purpose || 'execution', existing.roomId, existing.sessionId) + '\n');
    return;
  }
  if (!config) {
    const variable = options.get('--code-env') || 'PROTECT_MCP_PAIRING_CODE';
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(variable)) throw new Error('--code-env must name an environment variable.');
    const code = decodePairingCode(await codeFromInput(variable));
    const name = options.get('--name') || 'My agent';
    if (!name.trim() || name !== name.trim() || name.length > 60 || /[\u0000-\u001f]/.test(name)) throw new Error('Agent name must contain 1–60 printable characters.');
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as CryptoKeyPair;
    const token = randomBytes(32).toString('hex');
    config = { type: 'scopeblind.coordination.config.v1', setupVersion: 2, ...validateCoordinationConfig({ endpoint: code.endpoint, roomId: code.room_id, authorityKey: code.authority_key, token, ...(code.version === 3 ? { purpose: 'negotiation', sessionId: code.session_id, principalKey: code.principal_key } : {}) }),
      agentKey: bytesToHex(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))), name,
      pending: { code: { ...code, endpoint: new URL(code.endpoint).href }, privateKey: bytesToHex(new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))) } };
    savePrivateConfig(path, config, true);
  }
  const ready = await claimPairing(config);
  savePrivateConfig(path, ready, false);
  if (ready.purpose === 'negotiation') process.stdout.write(`Connected ${ready.name} for one principal’s bounded negotiation until ${ready.binding!.payload.expires_at}. This agent can read its principal’s mandate and shared proposals, propose or support a candidate, compare it in isolation, and wait. It cannot inspect the other private brief, pay, approve, adopt, or run a hosted agent.\nConnection saved privately. Each principal needs a separate pairing and config.\n`);
  else if (ready.purpose === 'rehearsal') process.stdout.write(`Connected ${ready.name} to test these rules until ${ready.binding!.payload.expires_at}. This agent can inspect rules, add cases, propose repairs, and run isolated tests. It cannot pay, approve, or activate changes.\nConnection saved privately. Return to the room to see or revoke this agent.\n`);
  else process.stdout.write(`Connected ${ready.name}. This independently keyed agent can inspect records, request permitted sandbox payments, and deliver results until ${ready.binding!.payload.expires_at}. It cannot approve exceptions or change the rules.\nConnection saved privately. Return to the room to see or revoke this agent.\n`);
  process.stdout.write(client === 'json' ? 'Merge this entry into your MCP client’s local configuration; preserve existing servers:\n' : client === 'codex' ? 'Run this command to add the connection to your Codex configuration:\n' : 'Run this command in the project where you use Claude Code:\n');
  runCoordinationSetup(['--config', path, '--client', client]);
  process.stdout.write('\nOpen or restart the selected client, then ask:\n' + agentPrompt(ready.purpose || 'execution', ready.roomId, ready.sessionId) + '\n');
  process.stdout.write('The room will show “Read current instructions” only after your agent successfully inspects and verifies its signed context. Pairing alone does not start an agent. Resume requires an active agent session.\n');
}
export function runCoordinationSetup(args: string[]): void {
  const options = configArgs(args, false), path = resolve(options.get('--config') || DEFAULT_COORDINATION_CONFIG);
  const stored = readPrivateConfig(path), config = coordinationConfigFromFile(path);
  if (Date.parse(stored.binding!.payload.expires_at) <= Date.now()) throw new Error('This saved connection has expired. Create a fresh pairing in the room and use its new config filename.');
  const serverName = stored.setupVersion === 2 ? agentServerName(config.purpose || 'execution', config.roomId, stored.binding?.payload.pair_id, config.principalKey) : config.purpose === 'negotiation' ? `scopeblind-negotiate-${config.principalKey!.slice(0,8)}` : config.purpose === 'rehearsal' ? 'scopeblind-test' : 'scopeblind';
  process.stdout.write(agentRegistration(agentClient(options.get('--client') || 'claude-code'), serverName, path) + '\n');
}
