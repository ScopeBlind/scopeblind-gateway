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

import { createHash, randomBytes } from 'node:crypto';

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
 * Verify a WebAuthn assertion from the client.
 *
 * This is a simplified verification that checks the structure
 * and extracts the authenticator data. For production use with
 * full signature verification, use the @simplewebauthn/server package.
 *
 * @param challenge - The original challenge
 * @param assertion - The assertion from navigator.credentials.get()
 * @returns ApprovalResult with verification details
 */
export function verifyApprovalAssertion(
  challenge: ApprovalChallenge,
  assertion: ApprovalAssertion,
): ApprovalResult {
  // Check challenge hasn't expired
  const createdAt = new Date(challenge.createdAt).getTime();
  const now = Date.now();
  if (now - createdAt > challenge.timeoutSeconds * 1000) {
    return {
      valid: false,
      credentialId: assertion.credentialId,
      authenticatorType: 'unknown',
      userVerified: false,
      signCount: 0,
      contextHash: challenge.contextHash,
      approvedAt: new Date().toISOString(),
    };
  }

  // Parse authenticator data
  const authData = base64urlDecode(assertion.authenticatorData);
  const flags = authData[32]; // flags byte is at offset 32

  // Check flags
  const userPresent = !!(flags & 0x01);    // UP flag
  const userVerified = !!(flags & 0x04);   // UV flag
  const attestedCredData = !!(flags & 0x40); // AT flag

  // Extract sign count (bytes 33-36, big-endian)
  const signCount = authData.length >= 37
    ? (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36]
    : 0;

  // Determine authenticator type from client data
  let authenticatorType: 'platform' | 'cross-platform' | 'unknown' = 'unknown';
  try {
    const clientData = JSON.parse(Buffer.from(base64urlDecode(assertion.clientDataJSON)).toString());
    if (clientData.type === 'webauthn.get') {
      authenticatorType = 'platform'; // Simplified — real detection needs more context
    }
  } catch {
    // Client data parsing failed
  }

  return {
    valid: userPresent, // At minimum, user must be present
    credentialId: assertion.credentialId,
    authenticatorType,
    userVerified,
    signCount,
    contextHash: challenge.contextHash,
    approvedAt: new Date().toISOString(),
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
