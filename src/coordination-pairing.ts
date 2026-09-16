import { NEGOTIATION_AGENT_ACTIONS } from './coordination-negotiation.js';
import { REHEARSAL_ACTIONS } from './coordination-rehearsal.js';
import { type RpcRequest, type Signed } from './coordination-protocol.js';

export const PAIRING_SCOPE = ['inspect', 'admit', 'execute', 'outcome', 'deliver'] as const;
export const REHEARSAL_PAIRING_SCOPE = REHEARSAL_ACTIONS;
export const REHEARSAL_PAIRING_AUDIENCE = 'scopeblind.coordination.rehearsal' as const;
export const NEGOTIATION_PAIRING_SCOPE = NEGOTIATION_AGENT_ACTIONS;
export const NEGOTIATION_PAIRING_AUDIENCE = 'scopeblind.coordination.negotiation' as const;
interface PairingDestination { endpoint: string; room_id: string; pair_id: string; authority_key: string; secret: string }
export type PairingCode = PairingDestination & ({ version: 1 } | { version: 2; scope: typeof REHEARSAL_PAIRING_SCOPE; audience: typeof REHEARSAL_PAIRING_AUDIENCE } | { version: 3; scope: typeof NEGOTIATION_PAIRING_SCOPE; audience: typeof NEGOTIATION_PAIRING_AUDIENCE; principal_key: string; session_id: string });
export function isRehearsalPairingScope(scope: unknown): scope is typeof REHEARSAL_PAIRING_SCOPE {
  return Array.isArray(scope) && JSON.stringify(scope) === JSON.stringify(REHEARSAL_PAIRING_SCOPE);
}
export function isNegotiationPairingScope(scope: unknown): scope is typeof NEGOTIATION_PAIRING_SCOPE {
  return Array.isArray(scope) && JSON.stringify(scope) === JSON.stringify(NEGOTIATION_PAIRING_SCOPE);
}
export function pairingScope(code: PairingCode): readonly string[] { return code.version === 3 ? NEGOTIATION_PAIRING_SCOPE : code.version === 2 ? REHEARSAL_PAIRING_SCOPE : PAIRING_SCOPE; }
export function pairingAudience(code: PairingCode): AgentBinding['audience'] { return code.version === 3 ? NEGOTIATION_PAIRING_AUDIENCE : code.version === 2 ? REHEARSAL_PAIRING_AUDIENCE : 'scopeblind.coordination.sample-ledger'; }
export interface AgentBinding {
  type: 'scopeblind.coordination.agent-binding.v1'; pair_id: string; room_id: string;
  agreement_digest: string; owner_key: string; agent_key: string; name: string;
  scope: readonly string[]; audience: 'scopeblind.coordination.sample-ledger' | typeof REHEARSAL_PAIRING_AUDIENCE | typeof NEGOTIATION_PAIRING_AUDIENCE;
  principal_key?: string; session_id?: string;
  issued_at: string; expires_at: string; owner_authorization: Signed<RpcRequest>;
}
export interface AgentPairingView {
  pair_id: string; name: string; status: 'waiting' | 'connected' | 'expired' | 'revoked';
  code_expires_at: string; expires_at: string; agent_key?: string; scope: readonly string[];
  binding?: Signed<AgentBinding>;
  readiness?: AgentReadiness;
  profile_bound?: true;
}
/** An authenticated adapter acknowledged the exact signed context it inspected.
 * This is an observation, not proof of understanding, live presence, or authority. */
export interface AgentReadiness { observed_at: string; context_digest: string }

export function encodePairingCode(code: PairingCode): string {
  const bytes = new TextEncoder().encode(JSON.stringify(code));
  return `sbp${code.version}.` + btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function decodePairingCode(value: string): PairingCode {
  if (!/^sbp[123]\.[A-Za-z0-9_-]{100,4000}$/.test(value)) throw new Error('The pairing code is incomplete. Copy a fresh code from the room.');
  try {
    const raw = value.slice(5).replace(/-/g, '+').replace(/_/g, '/');
    const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(Uint8Array.from(atob(raw), c => c.charCodeAt(0))));
    const keys = parsed?.version === 3 ? 'audience,authority_key,endpoint,pair_id,principal_key,room_id,scope,secret,session_id,version' : parsed?.version === 2 ? 'audience,authority_key,endpoint,pair_id,room_id,scope,secret,version' : 'authority_key,endpoint,pair_id,room_id,secret,version';
    if (!parsed || Object.keys(parsed).sort().join(',') !== keys || ![1,2,3].includes(parsed.version) || value.slice(0,5) !== `sbp${parsed.version}.` ||
      (parsed.version === 3 && (!isNegotiationPairingScope(parsed.scope) || parsed.audience !== NEGOTIATION_PAIRING_AUDIENCE || !/^[0-9a-f]{64}$/.test(parsed.principal_key) || !/^[A-Za-z0-9_-]{8,100}$/.test(parsed.session_id))) ||
      (parsed.version === 2 && (!isRehearsalPairingScope(parsed.scope) || parsed.audience !== REHEARSAL_PAIRING_AUDIENCE)) ||
      !/^[A-Za-z0-9_-]{8,100}$/.test(parsed.room_id) || !/^[A-Za-z0-9_-]{8,100}$/.test(parsed.pair_id) ||
      !/^[0-9a-f]{64}$/.test(parsed.authority_key) || !/^[0-9a-f]{64}$/.test(parsed.secret) || typeof parsed.endpoint !== 'string') throw new Error();
    return parsed as PairingCode;
  } catch { throw new Error('The pairing code is invalid. Copy a fresh code from the room.'); }
}
