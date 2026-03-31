/**
 * W3C DID/VC Mapping for ScopeBlind Passport Manifests
 *
 * Maps passport manifests to W3C Verifiable Credential format
 * and generates did:key identifiers from Ed25519 public keys.
 *
 * @standard W3C DID/VC interoperability — standard mapping, not patent-protected.
 * Implements W3C Decentralized Identifiers (DID) v1.0 and Verifiable Credentials
 * Data Model v1.1.
 */

/**
 * Generate a did:key identifier from an Ed25519 public key (hex).
 *
 * @standard W3C DID/VC interoperability — standard mapping, not patent-protected.
 */
export function ed25519ToDIDKey(publicKeyHex: string): string {
  // did:key uses multicodec prefix 0xed01 for Ed25519
  const multicodecPrefix = Buffer.from([0xed, 0x01]);
  const publicKeyBytes = Buffer.from(publicKeyHex, 'hex');
  const multicodecKey = Buffer.concat([multicodecPrefix, publicKeyBytes]);
  // Base58btc encode with 'z' prefix
  const base58 = base58btcEncode(multicodecKey);
  return `did:key:z${base58}`;
}

/**
 * Convert a passport manifest to a W3C Verifiable Credential.
 *
 * @standard W3C DID/VC interoperability — standard mapping, not patent-protected.
 */
export function manifestToVC(manifest: {
  agent_id: string;
  display_name?: string;
  public_key: string;
  capabilities?: string[];
  policy_digest?: string;
  created_at?: string;
  signature?: string;
}): {
  '@context': string[];
  type: string[];
  issuer: string;
  issuanceDate: string;
  credentialSubject: Record<string, unknown>;
  proof?: Record<string, unknown>;
} {
  const did = ed25519ToDIDKey(manifest.public_key);

  return {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      'https://veritasacta.com/contexts/agent-manifest/v1',
    ],
    type: ['VerifiableCredential', 'AgentManifestCredential'],
    issuer: did,
    issuanceDate: manifest.created_at || new Date().toISOString(),
    credentialSubject: {
      id: did,
      agentId: manifest.agent_id,
      displayName: manifest.display_name,
      capabilities: manifest.capabilities || [],
      policyDigest: manifest.policy_digest,
      publicKey: manifest.public_key,
    },
    ...(manifest.signature ? {
      proof: {
        type: 'Ed25519Signature2020',
        created: manifest.created_at || new Date().toISOString(),
        verificationMethod: `${did}#key-1`,
        proofPurpose: 'assertionMethod',
        proofValue: manifest.signature,
      },
    } : {}),
  };
}

/**
 * Convert a decision receipt to a W3C Verifiable Presentation.
 *
 * @standard W3C DID/VC interoperability — standard mapping, not patent-protected.
 */
export function receiptToVP(receipt: Record<string, unknown>, issuerPublicKey: string): {
  '@context': string[];
  type: string[];
  holder: string;
  verifiableCredential: Record<string, unknown>[];
} {
  const did = ed25519ToDIDKey(issuerPublicKey);
  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiablePresentation'],
    holder: did,
    verifiableCredential: [{
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://veritasacta.com/contexts/decision-receipt/v1',
      ],
      type: ['VerifiableCredential', 'DecisionReceiptCredential'],
      issuer: did,
      issuanceDate: (receipt.event_time as string) || new Date().toISOString(),
      credentialSubject: {
        receiptId: receipt.receipt_id,
        receiptType: receipt.receipt_type,
        toolName: (receipt.payload as Record<string, unknown>)?.tool_name,
        decision: (receipt.payload as Record<string, unknown>)?.decision,
      },
    }],
  };
}

// Simple base58btc encoding (Bitcoin alphabet)
function base58btcEncode(buffer: Buffer): string {
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let num = BigInt('0x' + buffer.toString('hex'));
  let result = '';
  while (num > 0n) {
    result = ALPHABET[Number(num % 58n)] + result;
    num = num / 58n;
  }
  // Handle leading zeros
  for (const byte of buffer) {
    if (byte === 0) result = '1' + result;
    else break;
  }
  return result;
}
