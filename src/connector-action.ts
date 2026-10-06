/**
 * Connector-action profile (draft-farley-acta-connector-action-00).
 *
 * An agent platform (Meta Muse, Claude Code, Codex, any MCP client) presents,
 * with a tool call, the grant under which its agent is acting. The gate that
 * receives the call records three separate things: what was presented, what
 * it could check about it, and the digest of the call it actually received.
 * A service that acts on the call may add what it read back afterwards. The
 * record rides on the decision receipt as its `connector` member and is
 * verifiable offline with the same rules as the receipt itself.
 *
 * Presented context and recorded check are kept apart on purpose: a platform
 * can claim any grant; only a signature under a key the recorder trusts turns
 * the claim into something a third party can rely on, and the receipt says
 * which of the two it holds.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { canonicalize } from './acta-envelope.js';

/** The `_meta` key an MCP client uses to present the context with `tools/call`. */
export const CONNECTOR_META_KEY = 'veritasacta.com/connector';
export const CONNECTOR_CONTEXT_TYPE = 'acta:connector-context';
export const CONNECTOR_RECORD_VERSION = 1;
export const GRANT_TYPES = ['one_time', 'session', 'task', 'time_bounded', 'perpetual'] as const;
export const CONTEXT_CHECKS = ['valid', 'invalid', 'unsigned', 'unverifiable'] as const;
export const EFFECT_STATUSES = ['confirmed', 'refused', 'not_observed'] as const;
export type GrantType = (typeof GRANT_TYPES)[number];
export type ContextCheck = (typeof CONTEXT_CHECKS)[number];
export type EffectStatus = (typeof EFFECT_STATUSES)[number];

export interface ConnectorGrant {
  /** How long the person's grant lasts, in the platform's own terms. */
  type: GrantType;
  /** The platform's identifier for the grant, if it has one. */
  id?: string;
  /** What the person granted the agent for, in their words or the platform's. */
  purpose?: string;
  issued_at?: string;
  expires_at?: string;
}

/** What the platform presents. Signed by the platform when it can be. */
export interface ConnectorContext {
  type: typeof CONNECTOR_CONTEXT_TYPE;
  /** The platform, as a stable lowercase name such as "meta.muse" or "anthropic.claude-code". */
  platform: string;
  /** The platform's identifier or public key for the acting agent. */
  agent: string;
  grant: ConnectorGrant;
  /** The digest of the signed standard or mandate the grant sits under, as "sha256:<hex>". */
  mandate_digest?: string;
  issued_at?: string;
  /** Present when signed: the platform key identifier, equal to the signature's kid. */
  issuer_id?: string;
}

export interface ConnectorSignature { alg: 'EdDSA'; kid: string; sig: string }

/** The presented object: an Acta envelope, signature optional. */
export interface PresentedConnectorContext { payload: ConnectorContext; signature?: ConnectorSignature }

export interface ConnectorEffect {
  status: EffectStatus;
  /** Required when confirmed: sha256 hex of the service's readback, canonicalized by the service. */
  readback_digest?: string;
  observed_at?: string;
}

/** What the recorder writes into the receipt. */
export interface ConnectorRecord {
  v: typeof CONNECTOR_RECORD_VERSION;
  context: ConnectorContext;
  context_signature?: ConnectorSignature;
  /** What the recorder established about the signature, never what the platform claimed. */
  context_check: ContextCheck;
  /** The trusted key identifier the recorder verified under, present only when context_check is valid. */
  platform_kid?: string;
  /** sha256 hex of JCS({tool, input}) as the recorder received the call. */
  request_digest: string;
  effect?: ConnectorEffect;
}

export type PlatformKeys = Record<string, string>;

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const SHA256_PREFIXED = /^sha256:[0-9a-f]{64}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const SHORT = 200;
const PURPOSE = 500;

const obj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const text = (v: unknown, max: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= max && !CONTROL.test(v);
const at = (v: unknown): v is string => typeof v === 'string' && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
const only = (v: Record<string, unknown>, keys: string[]): boolean => Object.keys(v).every((k) => keys.includes(k));

export function validConnectorGrant(v: unknown): v is ConnectorGrant {
  return obj(v) && only(v, ['type', 'id', 'purpose', 'issued_at', 'expires_at'])
    && (GRANT_TYPES as readonly string[]).includes(v.type as string)
    && (v.id === undefined || text(v.id, SHORT))
    && (v.purpose === undefined || text(v.purpose, PURPOSE))
    && (v.issued_at === undefined || at(v.issued_at))
    && (v.expires_at === undefined || at(v.expires_at))
    && (v.issued_at === undefined || v.expires_at === undefined || Date.parse(v.expires_at as string) > Date.parse(v.issued_at as string));
}

export function validConnectorContext(v: unknown): v is ConnectorContext {
  return obj(v) && only(v, ['type', 'platform', 'agent', 'grant', 'mandate_digest', 'issued_at', 'issuer_id'])
    && v.type === CONNECTOR_CONTEXT_TYPE
    && text(v.platform, SHORT) && /^[a-z0-9][a-z0-9.-]*$/.test(v.platform as string)
    && text(v.agent, SHORT)
    && validConnectorGrant(v.grant)
    && (v.mandate_digest === undefined || SHA256_PREFIXED.test(v.mandate_digest as string))
    && (v.issued_at === undefined || at(v.issued_at))
    && (v.issuer_id === undefined || text(v.issuer_id, SHORT));
}

export function validConnectorSignature(v: unknown): v is ConnectorSignature {
  return obj(v) && only(v, ['alg', 'kid', 'sig']) && v.alg === 'EdDSA' && text(v.kid, SHORT) && HEX128.test(v.sig as string);
}

export function validPresentedConnectorContext(v: unknown): v is PresentedConnectorContext {
  return obj(v) && only(v, ['payload', 'signature']) && validConnectorContext(v.payload)
    && (v.signature === undefined || validConnectorSignature(v.signature))
    // A signed context names its signer inside the signed bytes, so the kid cannot be swapped.
    && (v.signature === undefined || (v.payload as ConnectorContext).issuer_id === (v.signature as ConnectorSignature).kid);
}

export function validConnectorEffect(v: unknown): v is ConnectorEffect {
  return obj(v) && only(v, ['status', 'readback_digest', 'observed_at'])
    && (EFFECT_STATUSES as readonly string[]).includes(v.status as string)
    && (v.readback_digest === undefined || HEX64.test(v.readback_digest as string))
    && (v.status !== 'confirmed' || HEX64.test(v.readback_digest as string))
    && (v.observed_at === undefined || at(v.observed_at));
}

/** Schema errors of a recorded connector member; an empty list means well-formed. */
export function connectorRecordErrors(v: unknown): string[] {
  const errors: string[] = [];
  if (!obj(v)) return ['connector is not an object'];
  if (!only(v, ['v', 'context', 'context_signature', 'context_check', 'platform_kid', 'request_digest', 'effect'])) errors.push('connector carries an unknown member');
  if (v.v !== CONNECTOR_RECORD_VERSION) errors.push('connector.v is not 1');
  if (!validConnectorContext(v.context)) errors.push('connector.context is malformed');
  if (v.context_signature !== undefined && !validConnectorSignature(v.context_signature)) errors.push('connector.context_signature is malformed');
  if (!(CONTEXT_CHECKS as readonly string[]).includes(v.context_check as string)) errors.push('connector.context_check is not one of valid, invalid, unsigned, unverifiable');
  if (v.context_check === 'unsigned' && v.context_signature !== undefined) errors.push('connector.context_check says unsigned but a signature is present');
  if (v.context_check !== 'unsigned' && v.context_signature === undefined) errors.push(`connector.context_check says ${String(v.context_check)} without a signature`);
  if (v.context_check === 'valid' && !text(v.platform_kid, SHORT)) errors.push('connector.context_check is valid without platform_kid');
  if (v.context_check !== 'valid' && v.platform_kid !== undefined) errors.push('connector.platform_kid is present although the check is not valid');
  if (v.context_check === 'valid' && obj(v.context_signature) && v.platform_kid !== v.context_signature.kid) errors.push('connector.platform_kid differs from the signature kid');
  if (obj(v.context_signature) && obj(v.context) && v.context.issuer_id !== v.context_signature.kid) errors.push('connector.context.issuer_id differs from the signature kid');
  if (!HEX64.test(v.request_digest as string)) errors.push('connector.request_digest is not a sha256 hex digest');
  if (v.effect !== undefined && !validConnectorEffect(v.effect)) errors.push('connector.effect is malformed');
  return errors;
}

export function validConnectorRecord(v: unknown): v is ConnectorRecord { return connectorRecordErrors(v).length === 0; }

/** The digest of the call as received: sha256 over JCS({tool, input}). */
export function requestDigest(tool: string, input: unknown): string {
  return bytesToHex(sha256(utf8ToBytes(canonicalize({ tool, input: input ?? {} }))));
}

/** The digest of what a service read back, computed the same way over any JSON value. */
export function readbackDigest(readback: unknown): string {
  return bytesToHex(sha256(utf8ToBytes(canonicalize(readback))));
}

/** Verify a presented signature under a key the recorder trusts; the platform's own claims never count. */
export function checkContextSignature(context: ConnectorContext, signature: ConnectorSignature | undefined, keys: PlatformKeys | undefined): { check: ContextCheck; kid?: string } {
  if (!signature) return { check: 'unsigned' };
  const key = keys?.[signature.kid];
  if (!key || !HEX64.test(key)) return { check: 'unverifiable' };
  try {
    const ok = ed25519.verify(hexToBytes(signature.sig), utf8ToBytes(canonicalize(context)), hexToBytes(key));
    return ok ? { check: 'valid', kid: signature.kid } : { check: 'invalid' };
  } catch {
    return { check: 'invalid' };
  }
}

/** Sign a context as a platform would; used by tests, vectors and platform SDKs. */
export function signConnectorContext(context: Omit<ConnectorContext, 'type' | 'issuer_id'>, privateKeyHex: string, kid: string): PresentedConnectorContext {
  const payload: ConnectorContext = { type: CONNECTOR_CONTEXT_TYPE, ...context, issuer_id: kid };
  const sig = bytesToHex(ed25519.sign(utf8ToBytes(canonicalize(payload)), hexToBytes(privateKeyHex)));
  return { payload, signature: { alg: 'EdDSA', kid, sig } };
}

/** Build the record a gate writes for one received call. */
export function recordConnectorAction(presented: PresentedConnectorContext, tool: string, input: unknown, keys: PlatformKeys | undefined): ConnectorRecord {
  const { check, kid } = checkContextSignature(presented.payload, presented.signature, keys);
  const record: ConnectorRecord = { v: CONNECTOR_RECORD_VERSION, context: presented.payload, context_check: check, request_digest: requestDigest(tool, input) };
  if (presented.signature) record.context_signature = presented.signature;
  if (kid) record.platform_kid = kid;
  return record;
}

/** Add what the service read back, once it has. */
export function withEffect(record: ConnectorRecord, effect: ConnectorEffect): ConnectorRecord {
  if (!validConnectorEffect(effect)) throw new Error('connector_effect_invalid');
  return { ...record, effect };
}

/**
 * Read a presented context from the `_meta` of a tools/call request. A missing
 * key means no context; a malformed one is reported and never recorded, so a
 * receipt never carries a context the profile would reject.
 */
export function readConnectorContext(params: unknown, tool: string, input: unknown, keys: PlatformKeys | undefined): { record: ConnectorRecord | null; problem: string | null } {
  const meta = obj(params) && obj(params._meta) ? params._meta : null;
  if (!meta || !(CONNECTOR_META_KEY in meta)) return { record: null, problem: null };
  const presented = meta[CONNECTOR_META_KEY];
  if (!validPresentedConnectorContext(presented)) return { record: null, problem: 'connector_context_malformed' };
  return { record: recordConnectorAction(presented, tool, input, keys), problem: null };
}
