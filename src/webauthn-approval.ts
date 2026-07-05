/**
 * WebAuthn/Passkey Approval for protect-mcp Human-in-the-Loop Gates
 *
 * Enables biometric (FaceID, TouchID, Windows Hello, YubiKey) approval
 * of agent tool calls. When an agent requests a tool that requires
 * human approval, the system generates a WebAuthn challenge. The human
 * authenticates with their biometric device, producing a cryptographic
 * proof that a specific human authorized a specific action.
 *
 * The WebAuthn assertion is embedded in the approval receipt as the
 * `authenticator_data` field, creating an unforgeable binding between
 * biological intent and machine execution.
 *
 * Flow:
 *   1. Agent requests `db_write` → policy says `require_approval`
 *   2. protect-mcp generates a WebAuthn challenge containing the tool
 *      name, request ID, and a timestamp
 *   3. Human receives notification (SMS/Slack/browser) with the challenge
 *   4. Human authenticates with FaceID/TouchID/YubiKey
 *   5. The WebAuthn assertion is verified server-side
 *   6. A signed approval receipt is emitted with the authenticator data
 *   7. The agent's tool call is unblocked
 *
 * Usage:
 *   import { createApprovalChallenge, verifyApprovalAssertion } from './webauthn-approval.js';
 *
 *   // Server-side: create challenge
 *   const challenge = createApprovalChallenge(requestId, toolName, agentId);
 *
 *   // Client-side: browser calls navigator.credentials.get() with challenge
 *   // ... user authenticates with biometric ...
 *
 *   // Server-side: verify the assertion
 *   const result = verifyApprovalAssertion(challenge, assertion, credentialId);
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { p256 } from '@noble/curves/p256';
import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { hexToBytes } from '@noble/hashes/utils';

export interface ApprovalChallenge {
  /** Random challenge bytes (base64url) */
  challenge: string;
  /** Request ID of the tool call being approved */
  requestId: string;
  /** Tool name being approved */
  toolName: string;
  /** Agent requesting the approval */
  agentId?: string;
  /** Timestamp when challenge was created */
  createdAt: string;
  /** Challenge expiry (seconds) */
  timeoutSeconds: number;
  /** Relying party ID (domain) */
  rpId: string;
  /** SHA-256 hash of the challenge context (for receipt embedding) */
  contextHash: string;
}

export interface ApprovalAssertion {
  /** Credential ID used (base64url) */
  credentialId: string;
  /** Authenticator data (base64url) */
  authenticatorData: string;
  /** Client data JSON (base64url) */
  clientDataJSON: string;
  /** Signature (base64url) */
  signature: string;
  /** User handle (base64url, optional) */
  userHandle?: string;
}

export interface ApprovalResult {
  /** Whether the assertion is valid */
  valid: boolean;
  /** The credential ID used */
  credentialId: string;
  /** Authenticator type detected */
  authenticatorType: 'platform' | 'cross-platform' | 'unknown';
  /** Whether user verification was performed (biometric) */
  userVerified: boolean;
  /** Signature counter (for cloning detection) */
  signCount: number;
  /** Context hash that was signed */
  contextHash: string;
  /** Timestamp of approval */
  approvedAt: string;
  /** On failure, a machine-readable reason (e.g. 'invalid_signature'). */
  reason?: string;
}

/**
 * The registered credential public key, extracted from the COSE_Key at
 * registration. ES256 keys are an uncompressed P-256 point; EdDSA keys are a
 * 32-byte Ed25519 public key.
 */
export interface CredentialPublicKey {
  /** COSE algorithm: -7 = ES256 (P-256 / ECDSA), -8 = EdDSA (Ed25519). */
  alg: -7 | -8;
  /** Public key, hex. ES256: 65-byte uncompressed point (0x04 || x || y). EdDSA: 32-byte key. */
  publicKeyHex: string;
}

export interface VerifyAssertionOptions {
  /** Allowed origin(s) the assertion must come from, e.g. 'https://app.scopeblind.com'. Defaults to https://<rpId>. */
  expectedOrigin?: string | string[];
  /** Require the UV (user-verified / biometric or PIN) flag. Default true. */
  requireUserVerification?: boolean;
  /** The signCount stored from the previous assertion; a non-increasing counter signals a cloned authenticator. */
  prevSignCount?: number;
  /** Override 'now' (ms) for testing. */
  now?: number;
}

/**
 * Create a WebAuthn challenge for approving a tool call.
 *
 * The challenge contains the tool name and request ID so the
 * approval is cryptographically bound to a specific action.
 *
 * @param requestId - The request ID of the pending tool call
 * @param toolName - The tool being approved
 * @param agentId - The agent requesting approval (optional)
 * @param rpId - Relying party ID (default: scopeblind.com)
 * @param timeoutSeconds - Challenge timeout (default: 300 = 5 minutes)
 */
export function createApprovalChallenge(
  requestId: string,
  toolName: string,
  agentId?: string,
  rpId = 'scopeblind.com',
  timeoutSeconds = 300,
): ApprovalChallenge {
  // Generate random challenge bytes
  const challengeBytes = randomBytes(32);

  // Create context hash binding challenge to the specific action
  const contextHash = createHash('sha256')
    .update(JSON.stringify({ requestId, toolName, agentId, timestamp: Date.now() }))
    .digest('hex');

  return {
    challenge: base64urlEncode(challengeBytes),
    requestId,
    toolName,
    agentId,
    createdAt: new Date().toISOString(),
    timeoutSeconds,
    rpId,
    contextHash,
  };
}

/**
 * Generate the WebAuthn PublicKeyCredentialRequestOptions
 * that the browser needs to call navigator.credentials.get().
 *
 * This is sent to the client for the biometric prompt.
 */
export function toCredentialRequestOptions(
  challenge: ApprovalChallenge,
  allowCredentials?: Array<{ id: string; type: 'public-key' }>,
): {
  publicKey: {
    challenge: ArrayBuffer;
    rpId: string;
    timeout: number;
    userVerification: 'required';
    allowCredentials?: Array<{ id: ArrayBuffer; type: 'public-key' }>;
  };
} {
  return {
    publicKey: {
      challenge: base64urlDecode(challenge.challenge).buffer as ArrayBuffer,
      rpId: challenge.rpId,
      timeout: challenge.timeoutSeconds * 1000,
      userVerification: 'required', // Always require biometric
      ...(allowCredentials
        ? {
            allowCredentials: allowCredentials.map((c) => ({
              id: base64urlDecode(c.id).buffer as ArrayBuffer,
              type: 'public-key' as const,
            })),
          }
        : {}),
    },
  };
}

/**
 * Verify a WebAuthn assertion: full, fail-closed verification of a passkey or
 * security-key co-sign. This proves a SPECIFIC human authorized a SPECIFIC
 * action with a hardware-held key the host operator cannot exfiltrate. It
 * checks, in order: challenge freshness; clientDataJSON type, challenge, and
 * origin; the rpIdHash; the UP (and, by default, UV) flags; the authenticator
 * signature over authenticatorData || SHA-256(clientDataJSON) using the
 * registered credential public key (ES256 or EdDSA); and signCount monotonicity
 * (clone detection) when a previous count is supplied. Any failure returns
 * valid:false with a reason; nothing is trusted on a partial check.
 *
 * @param challenge - the original challenge
 * @param assertion - the assertion from navigator.credentials.get()
 * @param credentialPublicKey - the registered public key for assertion.credentialId
 * @param opts - origin / UV / signCount / clock options
 */
export function verifyApprovalAssertion(
  challenge: ApprovalChallenge,
  assertion: ApprovalAssertion,
  credentialPublicKey?: CredentialPublicKey,
  opts: VerifyAssertionOptions = {},
): ApprovalResult {
  const now = opts.now ?? Date.now();
  const fail = (reason: string, partial: Partial<ApprovalResult> = {}): ApprovalResult => ({
    valid: false,
    reason,
    credentialId: assertion.credentialId,
    authenticatorType: 'unknown',
    userVerified: false,
    signCount: 0,
    contextHash: challenge.contextHash,
    approvedAt: new Date(now).toISOString(),
    ...partial,
  });

  // 1. Freshness.
  const createdAt = new Date(challenge.createdAt).getTime();
  if (now - createdAt > challenge.timeoutSeconds * 1000) return fail('challenge_expired');

  // 2. A signature cannot be verified without the registered key: fail closed.
  if (!credentialPublicKey?.publicKeyHex) return fail('missing_credential_public_key');

  // 3. clientDataJSON: type, challenge, origin.
  const clientDataBytes = base64urlDecode(assertion.clientDataJSON);
  let clientData: { type?: string; challenge?: string; origin?: string };
  try {
    clientData = JSON.parse(Buffer.from(clientDataBytes).toString('utf8'));
  } catch {
    return fail('client_data_parse_error');
  }
  if (clientData.type !== 'webauthn.get') return fail('wrong_client_data_type');
  if (!constantTimeStrEqual(clientData.challenge ?? '', challenge.challenge)) return fail('challenge_mismatch');
  const allowedOrigins = opts.expectedOrigin
    ? (Array.isArray(opts.expectedOrigin) ? opts.expectedOrigin : [opts.expectedOrigin])
    : [`https://${challenge.rpId}`];
  if (!clientData.origin || !allowedOrigins.includes(clientData.origin)) return fail('origin_mismatch');

  // 4. authenticatorData: rpIdHash, flags, signCount.
  const authData = base64urlDecode(assertion.authenticatorData);
  if (authData.length < 37) return fail('authenticator_data_too_short');
  const rpIdHash = authData.slice(0, 32);
  const expectedRpIdHash = sha256(new TextEncoder().encode(challenge.rpId));
  if (!bytesEqual(rpIdHash, expectedRpIdHash)) return fail('rp_id_hash_mismatch');
  const flags = authData[32];
  const userPresent = !!(flags & 0x01);
  const userVerified = !!(flags & 0x04);
  if (!userPresent) return fail('user_not_present');
  if ((opts.requireUserVerification ?? true) && !userVerified) return fail('user_verification_required', { userVerified });
  const signCount = (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36];
  if (typeof opts.prevSignCount === 'number' && signCount !== 0 && signCount <= opts.prevSignCount) {
    return fail('sign_count_regression', { userVerified, signCount });
  }

  // 5. The cryptographic signature over authenticatorData || SHA-256(clientDataJSON).
  const signedData = concatBytes(authData, sha256(clientDataBytes));
  const sigBytes = base64urlDecode(assertion.signature);
  let sigOk = false;
  try {
    if (credentialPublicKey.alg === -7) {
      // ES256: ECDSA-P256 over SHA-256(signedData); WebAuthn encodes the signature as ASN.1 DER.
      sigOk = p256.verify(sigBytes, sha256(signedData), hexToBytes(credentialPublicKey.publicKeyHex), { format: 'der' });
    } else if (credentialPublicKey.alg === -8) {
      // EdDSA: Ed25519 over signedData directly.
      sigOk = ed25519.verify(sigBytes, signedData, hexToBytes(credentialPublicKey.publicKeyHex));
    } else {
      return fail('unsupported_algorithm', { userVerified, signCount });
    }
  } catch {
    sigOk = false;
  }
  if (!sigOk) return fail('invalid_signature', { userVerified, signCount });

  return {
    valid: true,
    credentialId: assertion.credentialId,
    // Heuristic: platform authenticators (TouchID/FaceID/Hello) report UV; roaming
    // keys without a PIN are UP-only. Attachment is authoritative only at registration.
    authenticatorType: userVerified ? 'platform' : 'cross-platform',
    userVerified,
    signCount,
    contextHash: challenge.contextHash,
    approvedAt: new Date(now).toISOString(),
  };
}

/**
 * Create the approval receipt payload for embedding in an Acta receipt.
 *
 * This is the data that gets signed into the DAG as an acta:approval node,
 * proving a human biometrically authorized a specific machine action.
 */
export function createApprovalReceiptPayload(
  challenge: ApprovalChallenge,
  result: ApprovalResult,
): {
  type: 'acta:approval';
  approval_method: 'webauthn';
  tool_name: string;
  request_id: string;
  agent_id?: string;
  authenticator_type: string;
  user_verified: boolean;
  context_hash: string;
  approved_at: string;
  credential_id_hash: string; // Hash of credential ID for privacy
} {
  return {
    type: 'acta:approval',
    approval_method: 'webauthn',
    tool_name: challenge.toolName,
    request_id: challenge.requestId,
    agent_id: challenge.agentId,
    authenticator_type: result.authenticatorType,
    user_verified: result.userVerified,
    context_hash: result.contextHash,
    approved_at: result.approvedAt,
    // Hash the credential ID for privacy — don't store the raw ID
    credential_id_hash: createHash('sha256')
      .update(result.credentialId)
      .digest('hex')
      .slice(0, 16),
  };
}

// ── Helpers ──

function base64urlEncode(buffer: Buffer | Uint8Array): string {
  return Buffer.from(buffer)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** Constant-time byte comparison (length-checked). */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/** Constant-time UTF-8 string comparison. */
function constantTimeStrEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
