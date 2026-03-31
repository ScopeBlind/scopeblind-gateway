/**
 * C2PA Content Credential Integration
 *
 * Embeds Veritas Acta provenance into C2PA (Coalition for Content
 * Provenance and Authenticity) manifest assertions. This enables
 * the "right-click to verify" UX — any content generated during
 * a governed agent session carries its Acta receipt chain as a
 * Content Credential.
 *
 * C2PA is backed by Adobe, Microsoft, BBC, and others. By embedding
 * Acta receipts as C2PA assertions, AI-generated content becomes
 * traceable through the existing content provenance ecosystem.
 *
 * Usage:
 *   import { createC2PAManifest, embedInImage, embedInDocument } from './c2pa-credentials.js';
 *
 *   // Create a C2PA manifest from an Acta receipt chain
 *   const manifest = createC2PAManifest(receipts, {
 *     title: 'AI-generated report',
 *     generator: 'protect-mcp v0.3.3',
 *   });
 *
 *   // The manifest can be embedded in images, PDFs, or documents
 *   // using c2patool or the C2PA Rust/JS SDK
 */

import { createHash } from 'node:crypto';

/**
 * C2PA Manifest structure compatible with the C2PA specification.
 * This is the JSON representation that c2patool can consume.
 */
export interface C2PAManifest {
  /** C2PA claim generator identifier */
  claim_generator: string;
  /** C2PA claim generator version */
  claim_generator_info: Array<{
    name: string;
    version: string;
    icon?: { format: string; identifier: string };
  }>;
  /** Title of the content */
  title: string;
  /** Assertions about the content */
  assertions: C2PAAssertion[];
  /** Ingredients (source materials) */
  ingredients?: C2PAIngredient[];
}

export interface C2PAAssertion {
  /** Assertion label (URI) */
  label: string;
  /** Assertion data */
  data: Record<string, unknown>;
  /** Whether this assertion is hashed (for privacy) */
  is_hash?: boolean;
}

export interface C2PAIngredient {
  /** Title of the ingredient */
  title: string;
  /** Relationship to the output */
  relationship: 'parentOf' | 'componentOf' | 'inputTo';
  /** Hash of the ingredient */
  hash?: string;
}

export interface C2PAOptions {
  /** Title of the generated content */
  title: string;
  /** Generator name (default: 'protect-mcp') */
  generator?: string;
  /** Generator version */
  version?: string;
  /** Whether to include full receipt data or only hashes */
  includeFullReceipts?: boolean;
  /** Additional assertions to include */
  additionalAssertions?: C2PAAssertion[];
}

/**
 * Create a C2PA manifest from an Acta receipt chain.
 *
 * The manifest contains:
 * - An `acta.decision-provenance` assertion with the receipt chain summary
 * - An `acta.policy-compliance` assertion showing policy adherence
 * - Standard C2PA actions (c2pa.actions) documenting what the agent did
 *
 * @param receipts - Array of Acta receipts from the agent session
 * @param options - Configuration for the manifest
 * @returns C2PA manifest JSON (compatible with c2patool)
 */
export function createC2PAManifest(
  receipts: Array<Record<string, unknown>>,
  options: C2PAOptions,
): C2PAManifest {
  const generator = options.generator || 'protect-mcp';
  const version = options.version || '0.3.3';

  // Compute receipt chain summary
  const decisions = receipts.filter(r =>
    (r.receipt_type as string)?.includes('decision') ||
    (r.type as string)?.includes('decision')
  );
  const allows = decisions.filter(r =>
    (r.payload as Record<string, unknown>)?.decision === 'allow'
  );
  const denies = decisions.filter(r =>
    (r.payload as Record<string, unknown>)?.decision === 'deny'
  );

  // Compute Merkle root of receipt chain
  const receiptHashes = receipts.map(r =>
    createHash('sha256').update(JSON.stringify(r)).digest('hex')
  );
  const merkleRoot = computeMerkleRoot(receiptHashes);

  // Build assertions
  const assertions: C2PAAssertion[] = [
    // Acta decision provenance — the core assertion
    {
      label: 'acta.decision-provenance',
      data: {
        protocol: 'veritas-acta',
        protocol_version: '0.1',
        ietf_draft: 'draft-farley-acta-signed-receipts-00',
        receipt_count: receipts.length,
        decision_count: decisions.length,
        allows: allows.length,
        denies: denies.length,
        merkle_root: merkleRoot,
        signing_algorithm: 'Ed25519',
        canonicalization: 'JCS (RFC 8785)',
        verifier: 'npx @veritasacta/verify',
        verify_url: 'https://scopeblind.com/verify',
        trace_url: 'https://scopeblind.com/trace',
      },
    },
    // Policy compliance assertion
    {
      label: 'acta.policy-compliance',
      data: {
        policy_violations: denies.length,
        total_decisions: decisions.length,
        compliance_rate: decisions.length > 0
          ? ((allows.length / decisions.length) * 100).toFixed(1) + '%'
          : 'N/A',
        policy_engine: 'Cedar + JSON',
        human_approvals: receipts.filter(r =>
          (r.receipt_type as string)?.includes('approval') ||
          (r.type as string)?.includes('approval')
        ).length,
      },
    },
    // Standard C2PA actions
    {
      label: 'c2pa.actions',
      data: {
        actions: [
          {
            action: 'c2pa.created',
            when: new Date().toISOString(),
            softwareAgent: `${generator}/${version}`,
            parameters: {
              description: 'Content generated by AI agent with ScopeBlind governance',
            },
          },
        ],
      },
    },
  ];

  // Add receipt data (hashed or full)
  if (options.includeFullReceipts) {
    assertions.push({
      label: 'acta.receipt-chain',
      data: {
        receipts: receipts.map(r => ({
          id: r.receipt_id || r.id,
          type: r.receipt_type || r.type,
          tool: (r.payload as Record<string, unknown>)?.tool_name,
          decision: (r.payload as Record<string, unknown>)?.decision,
          timestamp: r.timestamp || r.event_time,
        })),
      },
    });
  } else {
    assertions.push({
      label: 'acta.receipt-chain',
      data: {
        receipt_hashes: receiptHashes,
        merkle_root: merkleRoot,
        note: 'Full receipts available via verify URL. Hashes provided for integrity verification.',
      },
      is_hash: true,
    });
  }

  // Add any additional assertions
  if (options.additionalAssertions) {
    assertions.push(...options.additionalAssertions);
  }

  return {
    claim_generator: `${generator}/${version}`,
    claim_generator_info: [
      {
        name: generator,
        version,
      },
    ],
    title: options.title,
    assertions,
  };
}

/**
 * Export the C2PA manifest as JSON for use with c2patool.
 *
 * Usage:
 *   const json = exportC2PAManifestJSON(manifest);
 *   fs.writeFileSync('manifest.json', json);
 *   // Then: c2patool output.jpg -m manifest.json -o signed-output.jpg
 */
export function exportC2PAManifestJSON(manifest: C2PAManifest): string {
  return JSON.stringify(manifest, null, 2);
}

/**
 * Generate a c2patool command for embedding the manifest into a file.
 *
 * @param manifestPath - Path to the manifest JSON file
 * @param inputPath - Path to the input file (image, PDF, etc.)
 * @param outputPath - Path for the signed output file
 * @returns The c2patool command to run
 */
export function generateC2PACommand(
  manifestPath: string,
  inputPath: string,
  outputPath: string,
): string {
  return `c2patool ${inputPath} -m ${manifestPath} -o ${outputPath}`;
}

/**
 * Verify that a file contains valid Acta C2PA assertions.
 *
 * @param c2paManifestJson - The C2PA manifest JSON extracted from a file
 * @returns Verification result
 */
export function verifyActaC2PAAssertions(
  c2paManifestJson: string,
): {
  hasActaProvenance: boolean;
  receiptCount: number;
  merkleRoot: string | null;
  complianceRate: string | null;
  verifyUrl: string | null;
} {
  try {
    const manifest = JSON.parse(c2paManifestJson);
    const assertions = manifest.assertions || [];

    const provenanceAssertion = assertions.find(
      (a: C2PAAssertion) => a.label === 'acta.decision-provenance'
    );
    const complianceAssertion = assertions.find(
      (a: C2PAAssertion) => a.label === 'acta.policy-compliance'
    );

    if (!provenanceAssertion) {
      return {
        hasActaProvenance: false,
        receiptCount: 0,
        merkleRoot: null,
        complianceRate: null,
        verifyUrl: null,
      };
    }

    return {
      hasActaProvenance: true,
      receiptCount: (provenanceAssertion.data as Record<string, number>).receipt_count || 0,
      merkleRoot: (provenanceAssertion.data as Record<string, string>).merkle_root || null,
      complianceRate: complianceAssertion
        ? (complianceAssertion.data as Record<string, string>).compliance_rate
        : null,
      verifyUrl: (provenanceAssertion.data as Record<string, string>).verify_url || null,
    };
  } catch {
    return {
      hasActaProvenance: false,
      receiptCount: 0,
      merkleRoot: null,
      complianceRate: null,
      verifyUrl: null,
    };
  }
}

// ── Internal helpers ──

function computeMerkleRoot(hashes: string[]): string {
  if (hashes.length === 0) return '';
  if (hashes.length === 1) return hashes[0];

  const nextLevel: string[] = [];
  for (let i = 0; i < hashes.length; i += 2) {
    const left = hashes[i];
    const right = i + 1 < hashes.length ? hashes[i + 1] : left;
    nextLevel.push(
      createHash('sha256').update(left + right).digest('hex')
    );
  }
  return computeMerkleRoot(nextLevel);
}
