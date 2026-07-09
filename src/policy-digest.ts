/**
 * @scopeblind/protect-mcp — Normative policy digest construction
 *
 * The policy_digest a receipt carries must be a recomputable commitment, not
 * the evaluator's name for something. This module defines ONE construction,
 * "acta-policy-digest-v1", used by every policy engine:
 *
 *   M = {
 *     "construction": "acta-policy-digest-v1",
 *     "engine": <engine id, e.g. "cedar" | "builtin">,
 *     "files": [ { "name": <string>, "sha256": <64 lowercase hex over the
 *                  file's exact UTF-8 bytes> }, ... ]   // sorted by name
 *   }
 *   policy_digest = "sha256:" + lowercase_hex(SHA-256(UTF-8(JCS(M))))
 *
 * Design properties, in response to the public review of opaque policy ids:
 *  - Per-file hashing (no concatenation) makes file boundaries unambiguous;
 *    a digest over concatenated sources cannot distinguish ["ab","c"] from
 *    ["a","bc"], and a join delimiter only moves the ambiguity.
 *  - Sorting by name makes the digest independent of directory read order.
 *  - Including names makes renames observable.
 *  - The manifest M is exactly what a policy bundle publishes, so a verifier
 *    who has never talked to the evaluator recomputes the digest from public
 *    bytes alone: hash each published file, build M, JCS, SHA-256.
 *
 * Anything protect-mcp emitted before 0.10.0 used engine-specific preimages
 * truncated to 16 hex chars with no prefix; treat those as opaque labels,
 * not recomputable commitments.
 */

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, extname } from 'node:path';
import { canonicalize } from './acta-envelope.js';

export const POLICY_DIGEST_CONSTRUCTION = 'acta-policy-digest-v1';
export const POLICY_BUNDLE_SCHEMA = 'acta.policy-bundle.v1';

export interface PolicyFileEntry {
  name: string;
  /** SHA-256 (lowercase hex) over the file's exact UTF-8 bytes */
  sha256: string;
}

export interface PolicyDigestResult {
  /** "sha256:<64 lowercase hex>" */
  policy_digest: string;
  construction: typeof POLICY_DIGEST_CONSTRUCTION;
  engine: string;
  files: PolicyFileEntry[];
}

export interface PolicyBundle {
  schema: typeof POLICY_BUNDLE_SCHEMA;
  construction: typeof POLICY_DIGEST_CONSTRUCTION;
  engine: string;
  policy_digest: string;
  files: Array<PolicyFileEntry & { content: string }>;
  generated_at: string;
}

const sha256hex = (data: string | Buffer): string =>
  createHash('sha256').update(data).digest('hex');

/** Core construction: named contents -> manifest -> JCS -> SHA-256. */
export function digestPolicyFiles(
  engine: string,
  files: Array<{ name: string; content: string }>,
): PolicyDigestResult {
  if (files.length === 0) throw new Error('policy digest requires at least one file');
  const names = new Set<string>();
  for (const f of files) {
    if (!f.name) throw new Error('policy file entries require a name');
    if (names.has(f.name)) throw new Error(`duplicate policy file name: ${f.name}`);
    names.add(f.name);
  }
  const entries: PolicyFileEntry[] = files
    .map((f) => ({ name: f.name, sha256: sha256hex(Buffer.from(f.content, 'utf-8')) }))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const manifest = { construction: POLICY_DIGEST_CONSTRUCTION, engine, files: entries };
  return {
    policy_digest: `sha256:${sha256hex(Buffer.from(canonicalize(manifest), 'utf-8'))}`,
    construction: POLICY_DIGEST_CONSTRUCTION,
    engine,
    files: entries,
  };
}

/** Cedar policy directory: every .cedar file, exact bytes, sorted by name. */
export function digestCedarDir(dirPath: string): PolicyDigestResult & { dir: string } {
  if (!existsSync(dirPath)) throw new Error(`Cedar policy directory not found: ${dirPath}`);
  const names = readdirSync(dirPath).filter((f) => extname(f) === '.cedar').sort();
  if (names.length === 0) throw new Error(`No .cedar files found in: ${dirPath}`);
  const files = names.map((name) => ({ name, content: readFileSync(join(dirPath, name), 'utf-8') }));
  return { ...digestPolicyFiles('cedar', files), dir: dirPath };
}

/** A single in-memory Cedar source (self-test, mcp-server): fixed name. */
export function digestCedarSource(source: string): PolicyDigestResult {
  return digestPolicyFiles('cedar', [{ name: 'policy.cedar', content: source }]);
}

/**
 * Built-in JSON policy: the policy subset object (not the config file, which
 * also carries credentials/signing). Bytes are the UTF-8 of JCS(policy) so
 * the digest is independent of key order and whitespace in the config file.
 */
export function digestBuiltinPolicy(policy: unknown): PolicyDigestResult {
  return digestPolicyFiles('builtin', [{ name: 'policy.json', content: canonicalize(policy) }]);
}

/** Short display label for logs: engine prefix + first 16 hex of the digest. */
export function shortPolicyLabel(result: { engine: string; policy_digest: string }): string {
  return `${result.engine}:${result.policy_digest.replace(/^sha256:/, '').slice(0, 16)}`;
}

/** Build the publishable bundle (.well-known/acta-policies/<hex>.json). */
export function buildPolicyBundle(
  engine: string,
  files: Array<{ name: string; content: string }>,
  generatedAt?: string,
): PolicyBundle {
  const d = digestPolicyFiles(engine, files);
  const byName = new Map(files.map((f) => [f.name, f.content]));
  return {
    schema: POLICY_BUNDLE_SCHEMA,
    construction: POLICY_DIGEST_CONSTRUCTION,
    engine,
    policy_digest: d.policy_digest,
    files: d.files.map((e) => ({ ...e, content: byName.get(e.name) as string })),
    generated_at: generatedAt || new Date().toISOString(),
  };
}

/**
 * Recompute a bundle's digest from its published bytes alone.
 * Returns valid only if every per-file hash matches its content AND the
 * manifest digest matches the claimed policy_digest.
 */
export function verifyPolicyBundle(bundle: unknown): { valid: boolean; recomputed?: string; error?: string } {
  try {
    const b = bundle as PolicyBundle;
    if (!b || b.schema !== POLICY_BUNDLE_SCHEMA) return { valid: false, error: 'unknown_schema' };
    if (b.construction !== POLICY_DIGEST_CONSTRUCTION) return { valid: false, error: 'unknown_construction' };
    if (!Array.isArray(b.files) || b.files.length === 0) return { valid: false, error: 'missing_files' };
    for (const f of b.files) {
      if (sha256hex(Buffer.from(f.content, 'utf-8')) !== f.sha256) {
        return { valid: false, error: `file_hash_mismatch:${f.name}` };
      }
    }
    const recomputed = digestPolicyFiles(b.engine, b.files.map((f) => ({ name: f.name, content: f.content }))).policy_digest;
    return recomputed === b.policy_digest
      ? { valid: true, recomputed }
      : { valid: false, recomputed, error: 'digest_mismatch' };
  } catch (err) {
    return { valid: false, error: `verify_error:${err instanceof Error ? err.message : 'unknown'}` };
  }
}
