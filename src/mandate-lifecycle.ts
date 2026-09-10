/**
 * Runtime-enforced mandate lifecycle for protect-mcp.
 *
 * A Cedar directory becomes managed only after `initializeMandateRegistry`.
 * From that point, the gateway accepts a policy head only when it can prove:
 *
 *  1. the exact compiled bytes were signed by the configured gate;
 *  2. any widening was proposed from a signed denial under the prior head;
 *  3. a distinct registered controller approved the exact proposal; and
 *  4. an expiry has not rolled the head back to its baseline.
 *
 * Registry state and policy snapshots stay local. The registry deliberately
 * contains policy bytes so an exported copy is independently verifiable
 * offline; no ScopeBlind service is required to operate the control.
 */

import { createHash, randomUUID } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { createReceiptEnvelope, verifyReceipt, canonicalize, receiptHash, type ActaEnvelope } from './acta-envelope.js';
import { digestPolicyFiles, type PolicyBundle } from './policy-digest.js';
import {
  createApprovalChallenge,
  verifyApprovalAssertion,
  type ApprovalAssertion,
  type ApprovalChallenge,
  type ApprovalResult,
  type CredentialPublicKey,
} from './webauthn-approval.js';

export const MANDATE_REGISTRY_SCHEMA = 'scopeblind.mandate-registry.v1' as const;
export const MANDATE_PROPOSAL_SCHEMA = 'scopeblind.mandate-proposal.v1' as const;
export const MANDATE_APPROVAL_SCHEMA = 'scopeblind.mandate-approval.v1' as const;

export interface GateSigner {
  privateKey: string;
  publicKey: string;
  kid: string;
  issuer?: string;
}

export interface DirectController {
  id: string;
  label: string;
  type: 'ed25519';
  public_key: string;
}

export interface WebAuthnController {
  id: string;
  label: string;
  type: 'webauthn';
  credential_id: string;
  credential_public_key: CredentialPublicKey;
  sign_count: number;
}

export type MandateController = DirectController | WebAuthnController;

export interface PolicySnapshot {
  engine: 'cedar';
  policy_digest: string;
  files: Array<{ name: string; content: string; sha256: string }>;
  compiled_at: string;
}

export interface DenialOrigin {
  /** A signed protect-mcp decision receipt, not an operator-supplied log line. */
  receipt: ActaEnvelope;
  receipt_hash: string;
  request_id: string;
  tool: string;
  reason_code: string;
}

export interface PolicyDiff {
  added_statements: string[];
  removed_statements: string[];
  changed_files: Array<{ name: string; before_sha256: string | null; after_sha256: string | null }>;
  plain_english: string[];
}

export interface MandateProposal {
  schema: typeof MANDATE_PROPOSAL_SCHEMA;
  proposal_id: string;
  proposal_digest: string;
  created_at: string;
  expires_at: string;
  proposed_by: { gate_kid: string; gate_public_key: string };
  base_policy_digest: string;
  proposed_policy_digest: string;
  denial_origin: DenialOrigin;
  reason: string;
  diff: PolicyDiff;
  candidate: PolicySnapshot;
  proposal_receipt: ActaEnvelope;
}

export interface DirectApprovalProof {
  method: 'ed25519';
  controller_id: string;
  controller_label: string;
  approval_receipt: ActaEnvelope;
  approved_at: string;
}

export interface WebAuthnApprovalProof {
  method: 'webauthn';
  controller_id: string;
  controller_label: string;
  challenge: ApprovalChallenge;
  assertion: ApprovalAssertion;
  result: ApprovalResult;
  expected_origin: string;
  approved_at: string;
}

export type MandateApproval = DirectApprovalProof | WebAuthnApprovalProof;

export interface MandateTransition {
  sequence: number;
  event: 'initialized' | 'proposal_created' | 'proposal_approved' | 'policy_activated' | 'policy_expired_reverted';
  occurred_at: string;
  head_before: string | null;
  head_after: string;
  proposal_id?: string;
  approval_digest?: string;
  policy_digest?: string;
  expiry?: string;
  /** Gate-signed digest of the controller SET, carried on the `initialized` transition so injecting or swapping a controller in the plain registry is detected. */
  controllers_digest?: string;
  transition_receipt: ActaEnvelope;
}

export interface ActiveMandateHead {
  policy_digest: string;
  baseline_policy_digest: string;
  activated_at: string;
  expires_at?: string;
  proposal_id?: string;
  compilation_receipt: ActaEnvelope;
}

export interface PendingWebAuthnChallenge {
  proposal_id: string;
  controller_id: string;
  challenge: ApprovalChallenge;
}

export interface MandateRegistry {
  schema: typeof MANDATE_REGISTRY_SCHEMA;
  registry_id: string;
  created_at: string;
  updated_at: string;
  gate: { kid: string; public_key: string; issuer?: string };
  controllers: MandateController[];
  active: ActiveMandateHead;
  policies: Record<string, PolicySnapshot>;
  proposals: Record<string, MandateProposal>;
  approvals: Record<string, MandateApproval>;
  pending_webauthn: Record<string, PendingWebAuthnChallenge>;
  history: MandateTransition[];
}

export interface RegistryCheck {
  valid: boolean;
  code?: string;
  message?: string;
  registry?: MandateRegistry;
  expired_reverted?: boolean;
}

export interface MandatePaths {
  registry: string;
  snapshots: string;
  auditLog: string;
}

const SHA256 = (value: string | Buffer): string => createHash('sha256').update(value).digest('hex');

function nowIso(now?: Date): string {
  return (now || new Date()).toISOString();
}

function mustIso(value: string, label: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(`${label} must be an ISO-8601 timestamp`);
  return parsed;
}

function safePolicyFileName(name: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]*\.cedar$/.test(name) && !name.includes('..');
}

function stableDigest(value: unknown): string {
  return `sha256:${SHA256(Buffer.from(canonicalize(value), 'utf-8'))}`;
}

/**
 * The immutable identity of a controller, EXCLUDING the mutable webauthn
 * sign_count. The controller-set digest is taken over these so an authorised
 * counter advance does not break verification, but injecting a controller or
 * swapping a registered public/credential key does.
 */
function controllerIdentity(c: MandateController): Record<string, unknown> {
  return c.type === 'ed25519'
    ? { id: c.id, label: c.label, type: c.type, public_key: c.public_key.toLowerCase() }
    : { id: c.id, label: c.label, type: c.type, credential_id: c.credential_id, credential_public_key: c.credential_public_key };
}

/**
 * A gate-signable digest of the whole controller set. Bound into the signed
 * `initialized` transition and re-derived by the verifier, so a party who can
 * write the registry file but not forge the gate signature cannot add a
 * controller or swap a passkey key undetected. (A holder of the gate key can
 * re-sign the entire chain; that residual case needs an external anchor and is
 * documented, not silently claimed away.)
 */
function controllersDigest(controllers: MandateController[]): string {
  // Deterministic codepoint order (NOT localeCompare, which is locale-dependent
  // and not a stable total order), so the digest is reproducible everywhere.
  const identities = controllers.map(controllerIdentity)
    .sort((a, b) => (String(a.id) < String(b.id) ? -1 : String(a.id) > String(b.id) ? 1 : 0));
  return stableDigest(identities);
}

/** The raw public/credential key material a controller authenticates with, for gate-vs-controller separation across both controller types. */
function controllerKeyMaterial(c: MandateController): string {
  return (c.type === 'ed25519' ? c.public_key : c.credential_public_key?.publicKeyHex || '').toLowerCase();
}

/**
 * Deterministic WebAuthn challenge (base64url) bound to the EXACT proposal. The
 * passkey signs the challenge, so binding it to the proposal digest makes the
 * biometric consent a cryptographic statement about WHICH policy change was
 * approved, not a signature over a bare random nonce.
 */
function policyApprovalChallenge(proposal: MandateProposal, controllerId: string): string {
  return createHash('sha256').update(Buffer.from(canonicalize({
    purpose: 'scopeblind:policy-change',
    proposed_by: proposal.proposed_by,
    proposal_id: proposal.proposal_id,
    proposal_digest: proposal.proposal_digest,
    base_policy_digest: proposal.base_policy_digest,
    proposed_policy_digest: proposal.proposed_policy_digest,
    expires_at: proposal.expires_at,
    controller_id: controllerId,
  }), 'utf-8')).digest('base64url');
}

/** Registry metadata lives beside, not inside, the replaceable Cedar directory. */
export function mandatePaths(cedarDir: string): MandatePaths {
  const absolute = resolve(cedarDir);
  const parent = dirname(absolute);
  const base = basename(absolute);
  return {
    registry: join(parent, `.${base}.scopeblind-mandate-registry.json`),
    snapshots: join(parent, `.${base}.scopeblind-mandate-snapshots`),
    auditLog: join(parent, `.${base}.scopeblind-mandate-history.jsonl`),
  };
}

export function loadGateSigner(keyPath: string): GateSigner {
  const raw = JSON.parse(readFileSync(keyPath, 'utf-8')) as Record<string, unknown>;
  if (typeof raw.privateKey !== 'string' || !/^[0-9a-f]{64}$/i.test(raw.privateKey)) {
    throw new Error('gate key must contain a 32-byte hexadecimal privateKey');
  }
  if (typeof raw.publicKey !== 'string' || !/^[0-9a-f]{64}$/i.test(raw.publicKey)) {
    throw new Error('gate key must contain a 32-byte hexadecimal publicKey');
  }
  if (typeof raw.kid !== 'string' || raw.kid.length === 0) {
    throw new Error('gate key must contain a non-empty kid');
  }
  return {
    privateKey: raw.privateKey.toLowerCase(),
    publicKey: raw.publicKey.toLowerCase(),
    kid: raw.kid,
    ...(typeof raw.issuer === 'string' ? { issuer: raw.issuer } : {}),
  };
}

export function snapshotFromDirectory(cedarDir: string, compiledAt?: string): PolicySnapshot {
  const entries = readdirSync(cedarDir, { encoding: 'utf-8' })
    .filter((name) => name.endsWith('.cedar'))
    .sort();
  if (entries.length === 0) throw new Error(`no Cedar policy files found in ${cedarDir}`);
  const files = entries.map((name) => {
    if (!safePolicyFileName(name)) throw new Error(`unsafe Cedar policy filename: ${name}`);
    const content = readFileSync(join(cedarDir, name), 'utf-8');
    return { name, content, sha256: SHA256(Buffer.from(content, 'utf-8')) };
  });
  const digest = digestPolicyFiles('cedar', files).policy_digest;
  return { engine: 'cedar', policy_digest: digest, files, compiled_at: compiledAt || nowIso() };
}

function assertSnapshot(snapshot: PolicySnapshot): void {
  if (!snapshot || snapshot.engine !== 'cedar' || !Array.isArray(snapshot.files) || snapshot.files.length === 0) {
    throw new Error('invalid Cedar policy snapshot');
  }
  for (const file of snapshot.files) {
    if (!safePolicyFileName(file.name)) throw new Error(`unsafe policy filename: ${file.name}`);
    if (SHA256(Buffer.from(file.content, 'utf-8')) !== file.sha256) {
      throw new Error(`policy snapshot content hash mismatch: ${file.name}`);
    }
  }
  const actual = digestPolicyFiles('cedar', snapshot.files).policy_digest;
  if (actual !== snapshot.policy_digest) throw new Error('policy snapshot digest mismatch');
}

function signLifecycleEvent(
  signer: GateSigner,
  fields: Record<string, unknown>,
  issuedAt: string,
): ActaEnvelope {
  return createReceiptEnvelope({
    type: 'scopeblind.mandate-transition.v1',
    ...fields,
    gate_public_key: signer.publicKey,
    ...(signer.issuer ? { gate_issuer: signer.issuer } : {}),
  }, signer.privateKey, signer.kid, issuedAt).envelope;
}

function verifyGateEnvelope(envelope: unknown, gate: MandateRegistry['gate']): boolean {
  const check = verifyReceipt(envelope, gate.public_key);
  if (!check.valid) return false;
  const payload = (envelope as ActaEnvelope).payload;
  return payload.issuer_id === gate.kid && payload.gate_public_key === gate.public_key;
}

function writeAtomic(path: string, contents: string): void {
  const parent = dirname(path);
  mkdirSync(parent, { recursive: true });
  const temp = join(parent, `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  try {
    writeFileSync(temp, contents, { encoding: 'utf-8', mode: 0o600 });
    renameSync(temp, path);
  } finally {
    if (existsSync(temp)) rmSync(temp, { force: true });
  }
}

function persistRegistry(cedarDir: string, registry: MandateRegistry): void {
  registry.updated_at = nowIso();
  const paths = mandatePaths(cedarDir);
  writeAtomic(paths.registry, JSON.stringify(registry, null, 2) + '\n');
  const last = registry.history[registry.history.length - 1];
  if (last) {
    writeFileSync(paths.auditLog, JSON.stringify(last) + '\n', { encoding: 'utf-8', flag: 'a', mode: 0o600 });
  }
}

function persistSnapshot(cedarDir: string, snapshot: PolicySnapshot): void {
  const paths = mandatePaths(cedarDir);
  mkdirSync(paths.snapshots, { recursive: true, mode: 0o700 });
  const name = `${snapshot.policy_digest.replace(/^sha256:/, '')}.json`;
  const output = join(paths.snapshots, name);
  if (!existsSync(output)) writeAtomic(output, JSON.stringify(snapshot, null, 2) + '\n');
}

function sourceStatements(snapshot: PolicySnapshot): Map<string, Set<string>> {
  const byFile = new Map<string, Set<string>>();
  for (const file of snapshot.files) {
    // This is presentation only: policy compilation and the policy digest remain
    // the authoritative security boundaries. Keep exact statement text visible.
    const statements = file.content
      .split(/;\s*(?:\r?\n|$)/g)
      .map((s) => s.replace(/\/\/[^\n]*/g, '').trim())
      .filter((s) => /^(permit|forbid)\s*\(/.test(s))
      .map((s) => `${s};`);
    byFile.set(file.name, new Set(statements));
  }
  return byFile;
}

export function describePolicyDiff(before: PolicySnapshot, after: PolicySnapshot): PolicyDiff {
  assertSnapshot(before);
  assertSnapshot(after);
  const beforeStatements = sourceStatements(before);
  const afterStatements = sourceStatements(after);
  const names = [...new Set([...beforeStatements.keys(), ...afterStatements.keys()])].sort();
  const added: string[] = [];
  const removed: string[] = [];
  for (const name of names) {
    const oldSet = beforeStatements.get(name) || new Set<string>();
    const newSet = afterStatements.get(name) || new Set<string>();
    for (const statement of newSet) if (!oldSet.has(statement)) added.push(`${name}: ${statement}`);
    for (const statement of oldSet) if (!newSet.has(statement)) removed.push(`${name}: ${statement}`);
  }
  const beforeFiles = new Map(before.files.map((file) => [file.name, file.sha256]));
  const afterFiles = new Map(after.files.map((file) => [file.name, file.sha256]));
  const changedFiles = names
    .filter((name) => beforeFiles.get(name) !== afterFiles.get(name))
    .map((name) => ({ name, before_sha256: beforeFiles.get(name) || null, after_sha256: afterFiles.get(name) || null }));
  const plainEnglish: string[] = [];
  if (added.length) plainEnglish.push(`Adds ${added.length} executable policy statement${added.length === 1 ? '' : 's'}: the lines are shown below exactly as compiled.`);
  if (removed.length) plainEnglish.push(`Removes ${removed.length} executable policy statement${removed.length === 1 ? '' : 's'}: removed protections are shown below exactly as compiled.`);
  if (!added.length && !removed.length && changedFiles.length) plainEnglish.push('Changes policy file bytes without changing a recognisable permit or forbid statement; review the exact file digest change before approval.');
  if (!changedFiles.length) plainEnglish.push('No executable policy change was detected. The proposal cannot be used to widen a mandate.');
  return { added_statements: added, removed_statements: removed, changed_files: changedFiles, plain_english: plainEnglish };
}

function assertController(controller: MandateController): void {
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(controller.id)) throw new Error('controller id is invalid');
  if (!controller.label.trim()) throw new Error('controller label is required');
  if (controller.type === 'ed25519' && !/^[0-9a-f]{64}$/i.test(controller.public_key)) {
    throw new Error(`controller ${controller.id} requires a 32-byte Ed25519 public key`);
  }
  if (controller.type === 'webauthn' && (!controller.credential_id || !controller.credential_public_key?.publicKeyHex)) {
    throw new Error(`controller ${controller.id} requires a registered WebAuthn credential`);
  }
}

function proposalUnsigned(input: Omit<MandateProposal, 'proposal_receipt' | 'proposal_digest'>): Record<string, unknown> {
  return {
    schema: input.schema,
    proposal_id: input.proposal_id,
    created_at: input.created_at,
    expires_at: input.expires_at,
    proposed_by: input.proposed_by,
    base_policy_digest: input.base_policy_digest,
    proposed_policy_digest: input.proposed_policy_digest,
    denial_origin: input.denial_origin,
    reason: input.reason,
    diff: input.diff,
    candidate: input.candidate,
  };
}

function approvalDigest(approval: MandateApproval): string {
  return stableDigest(approval);
}

function transition(
  registry: MandateRegistry,
  signer: GateSigner,
  event: MandateTransition['event'],
  headBefore: string | null,
  headAfter: string,
  fields: Omit<MandateTransition, 'sequence' | 'event' | 'occurred_at' | 'head_before' | 'head_after' | 'transition_receipt'> = {},
  at = nowIso(),
): MandateTransition {
  const sequence = registry.history.length + 1;
  const body = {
    event,
    registry_id: registry.registry_id,
    sequence,
    head_before: headBefore,
    head_after: headAfter,
    ...fields,
  };
  return {
    sequence,
    event,
    occurred_at: at,
    head_before: headBefore,
    head_after: headAfter,
    ...fields,
    transition_receipt: signLifecycleEvent(signer, body, at),
  };
}

export function initializeMandateRegistry(input: {
  cedarDir: string;
  signer: GateSigner;
  controllers: MandateController[];
  now?: Date;
}): MandateRegistry {
  const { cedarDir, signer, controllers } = input;
  const paths = mandatePaths(cedarDir);
  if (existsSync(paths.registry)) throw new Error(`managed mandate registry already exists: ${paths.registry}`);
  if (!controllers.length) throw new Error('at least one distinct controller is required before managing a mandate');
  const ids = new Set<string>();
  for (const controller of controllers) {
    assertController(controller);
    if (ids.has(controller.id)) throw new Error(`duplicate controller id: ${controller.id}`);
    if (controller.id === signer.kid) throw new Error('the gate signer cannot be registered as a mandate controller');
    // Separation across BOTH controller types: a webauthn credential key that
    // equals the gate key would also collapse dual control.
    if (controllerKeyMaterial(controller) === signer.publicKey.toLowerCase()) {
      throw new Error('the gate signing key cannot also be a mandate controller key');
    }
    ids.add(controller.id);
  }
  const created = nowIso(input.now);
  const baseline = snapshotFromDirectory(cedarDir, created);
  const registryId = `sb:mandate:${SHA256(`${signer.kid}|${baseline.policy_digest}`).slice(0, 24)}`;
  const compilation = signLifecycleEvent(signer, {
    event: 'compiled',
    registry_id: registryId,
    policy_digest: baseline.policy_digest,
    snapshot_digest: stableDigest(baseline),
  }, created);
  const registry: MandateRegistry = {
    schema: MANDATE_REGISTRY_SCHEMA,
    registry_id: registryId,
    created_at: created,
    updated_at: created,
    gate: { kid: signer.kid, public_key: signer.publicKey, ...(signer.issuer ? { issuer: signer.issuer } : {}) },
    controllers,
    active: {
      policy_digest: baseline.policy_digest,
      baseline_policy_digest: baseline.policy_digest,
      activated_at: created,
      compilation_receipt: compilation,
    },
    policies: { [baseline.policy_digest]: baseline },
    proposals: {},
    approvals: {},
    pending_webauthn: {},
    history: [],
  };
  registry.history.push(transition(registry, signer, 'initialized', null, baseline.policy_digest, {
    policy_digest: baseline.policy_digest,
    controllers_digest: controllersDigest(controllers),
  }, created));
  persistSnapshot(cedarDir, baseline);
  persistRegistry(cedarDir, registry);
  return registry;
}

export function loadMandateRegistry(cedarDir: string): MandateRegistry | null {
  const path = mandatePaths(cedarDir).registry;
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf-8')) as MandateRegistry;
  } catch (error) {
    throw new Error(`could not parse mandate registry: ${error instanceof Error ? error.message : 'unknown error'}`);
  }
}

function verifyDirectApproval(registry: MandateRegistry, proposal: MandateProposal, approval: DirectApprovalProof): string | null {
  const controller = registry.controllers.find((candidate) => candidate.id === approval.controller_id);
  if (!controller || controller.type !== 'ed25519') return 'controller_not_registered';
  const check = verifyReceipt(approval.approval_receipt, controller.public_key);
  if (!check.valid) return `approval_${check.error || 'signature_invalid'}`;
  const payload = approval.approval_receipt.payload;
  if (payload.type !== MANDATE_APPROVAL_SCHEMA) return 'approval_schema_invalid';
  if (payload.proposal_id !== proposal.proposal_id || payload.proposal_digest !== proposal.proposal_digest) return 'approval_not_bound_to_proposal';
  if (payload.controller_id !== controller.id || payload.decision !== 'approve') return 'approval_controller_or_decision_invalid';
  if (approval.approval_receipt.signature.kid !== controller.id) return 'approval_signer_kid_invalid';
  return null;
}

function verifyWebAuthnApproval(registry: MandateRegistry, proposal: MandateProposal, approval: WebAuthnApprovalProof): string | null {
  const controller = registry.controllers.find((candidate) => candidate.id === approval.controller_id);
  if (!controller || controller.type !== 'webauthn') return 'controller_not_registered';
  // The signed challenge must be the deterministic binding to THIS proposal, so
  // the passkey signature (which is over the challenge) commits to the exact
  // policy change, not a bare nonce that a registry writer could substitute.
  if (approval.challenge.requestId !== proposal.proposal_id ||
    approval.challenge.toolName !== 'scopeblind:policy-change' ||
    approval.challenge.challenge !== policyApprovalChallenge(proposal, controller.id)) {
    return 'approval_not_bound_to_proposal';
  }
  if (approval.assertion.credentialId !== controller.credential_id) return 'approval_credential_not_registered';
  // Re-verification checks the assertion SIGNATURE over the bound challenge. It
  // does NOT re-apply signCount monotonicity: that is a live clone-detection
  // check consumed once at apply time (approvePolicyProposalWithWebAuthn).
  // Re-applying it against the now-advanced stored counter would fail every
  // historical approval and brick the gate (fail-closed DoS).
  const verified = verifyApprovalAssertion(approval.challenge, approval.assertion, controller.credential_public_key, {
    expectedOrigin: approval.expected_origin,
    requireUserVerification: true,
    now: Date.parse(approval.approved_at),
  });
  if (!verified.valid || !verified.userVerified) return `approval_${verified.reason || 'webauthn_invalid'}`;
  if (!approval.result.valid || approval.result.contextHash !== verified.contextHash) return 'approval_result_invalid';
  return null;
}

function verifyProposal(registry: MandateRegistry, proposal: MandateProposal): string | null {
  if (proposal.schema !== MANDATE_PROPOSAL_SCHEMA) return 'proposal_schema_invalid';
  const unsigned = proposalUnsigned(proposal);
  if (stableDigest(unsigned) !== proposal.proposal_digest) return 'proposal_digest_invalid';
  if (!verifyGateEnvelope(proposal.proposal_receipt, registry.gate)) return 'proposal_signature_invalid';
  const payload = proposal.proposal_receipt.payload;
  if (payload.type !== MANDATE_PROPOSAL_SCHEMA || payload.proposal_id !== proposal.proposal_id || payload.proposal_digest !== proposal.proposal_digest) {
    return 'proposal_receipt_binding_invalid';
  }
  // Bind the proposal to THIS registry, so a gate-signed proposal cannot be
  // replayed into a different registry the same gate also manages.
  if (payload.registry_id !== registry.registry_id) return 'proposal_registry_mismatch';
  if (proposal.proposed_by.gate_kid !== registry.gate.kid || proposal.proposed_by.gate_public_key !== registry.gate.public_key) {
    return 'proposal_gate_identity_invalid';
  }
  const denialCheck = verifyReceipt(proposal.denial_origin.receipt, registry.gate.public_key);
  if (!denialCheck.valid || proposal.denial_origin.receipt_hash !== (denialCheck.hash || receiptHash(proposal.denial_origin.receipt))) {
    return 'proposal_denial_receipt_invalid';
  }
  const denialPayload = proposal.denial_origin.receipt.payload;
  if (denialPayload.type !== 'protectmcp:decision' || denialPayload.decision !== 'deny' ||
    denialPayload.policy_digest !== proposal.base_policy_digest || denialPayload.request_id !== proposal.denial_origin.request_id ||
    denialPayload.tool_name !== proposal.denial_origin.tool) {
    return 'proposal_denial_binding_invalid';
  }
  try { assertSnapshot(proposal.candidate); } catch { return 'proposal_snapshot_invalid'; }
  if (proposal.candidate.policy_digest !== proposal.proposed_policy_digest) return 'proposal_snapshot_digest_invalid';
  return null;
}

export function verifyMandateRegistry(registry: MandateRegistry, now = new Date()): RegistryCheck {
  try {
    if (!registry || registry.schema !== MANDATE_REGISTRY_SCHEMA) return { valid: false, code: 'unknown_registry_schema', message: 'Registry schema is not recognised.' };
    if (!registry.gate?.kid || !/^[0-9a-f]{64}$/i.test(registry.gate.public_key)) return { valid: false, code: 'gate_identity_invalid', message: 'Registry gate identity is malformed.' };
    const controllerIds = new Set<string>();
    for (const controller of registry.controllers || []) {
      assertController(controller);
      if (controllerIds.has(controller.id)) return { valid: false, code: 'duplicate_controller', message: `Controller ${controller.id} appears more than once.` };
      if (controller.id === registry.gate.kid || controllerKeyMaterial(controller) === registry.gate.public_key.toLowerCase()) {
        return { valid: false, code: 'gate_is_controller', message: 'The gate signer cannot be a mandate controller.' };
      }
      controllerIds.add(controller.id);
    }
    if (!registry.controllers.length) return { valid: false, code: 'missing_controller', message: 'Managed policy has no controller.' };
    for (const [digest, snapshot] of Object.entries(registry.policies || {})) {
      assertSnapshot(snapshot);
      if (digest !== snapshot.policy_digest) return { valid: false, code: 'snapshot_map_mismatch', message: 'A stored policy snapshot is addressed by the wrong digest.' };
    }
    const activeSnapshot = registry.policies?.[registry.active?.policy_digest];
    if (!activeSnapshot) return { valid: false, code: 'active_snapshot_missing', message: 'The active policy head has no compiled snapshot.' };
    if (!verifyGateEnvelope(registry.active.compilation_receipt, registry.gate)) return { valid: false, code: 'active_compilation_signature_invalid', message: 'The active compiled policy is not signed by the configured gate.' };
    const compilationPayload = registry.active.compilation_receipt.payload;
    if (compilationPayload.policy_digest !== registry.active.policy_digest) return { valid: false, code: 'active_compilation_binding_invalid', message: 'The signed compiled policy does not bind the active head.' };
    let priorHash: string | null = null;
    let currentHead: string | null = null;
    // The authoritative active state is RECONSTRUCTED from the signed chain, not
    // trusted from the mutable registry.active fields. This anchors expiry,
    // baseline, and proposal_id, so clearing/repointing any of them (e.g. to make
    // a temporary widening permanent, or to turn expiry-revert into a no-op) is
    // detected below.
    let currentExpiry: string | null = null;
    let currentBaseline: string | null = null;
    let currentProposalId: string | null = null;
    for (let index = 0; index < registry.history.length; index += 1) {
      const item = registry.history[index];
      if (item.sequence !== index + 1 || !verifyGateEnvelope(item.transition_receipt, registry.gate)) {
        return { valid: false, code: 'transition_signature_invalid', message: 'A policy transition is missing or has an invalid gate signature.' };
      }
      const payload = item.transition_receipt.payload;
      if (payload.registry_id !== registry.registry_id || payload.sequence !== item.sequence || payload.event !== item.event) {
        return { valid: false, code: 'transition_binding_invalid', message: 'A signed transition does not bind this registry state.' };
      }
      // BIDIRECTIONAL display-vs-signed check: the display fields must EQUAL the
      // signed payload, not merely "match when present". Otherwise deleting a
      // display field (e.g. a transition's expiry) while the signed payload still
      // carries it slips past a one-directional check.
      if ((payload.head_before ?? null) !== (item.head_before ?? null) ||
        (payload.head_after ?? null) !== (item.head_after ?? null) ||
        (payload.proposal_id ?? null) !== (item.proposal_id ?? null) ||
        (payload.approval_digest ?? null) !== (item.approval_digest ?? null) ||
        (payload.policy_digest ?? null) !== (item.policy_digest ?? null) ||
        (payload.controllers_digest ?? null) !== (item.controllers_digest ?? null) ||
        (payload.expiry ?? null) !== (item.expiry ?? null)) {
        return { valid: false, code: 'transition_state_mismatch', message: 'Displayed policy transition state does not match the signed transition.' };
      }
      // The controller SET is anchored to the signed `initialized` transition.
      // Injecting a controller or swapping a passkey key in the plain registry
      // changes the re-derived digest and is rejected here (short of gate-key
      // compromise, which can re-sign the chain and needs an external anchor).
      if (item.event === 'initialized') {
        const derived = controllersDigest(registry.controllers);
        if (!payload.controllers_digest || payload.controllers_digest !== derived) {
          return { valid: false, code: 'controller_set_unanchored', message: 'The controller set does not match the gate-signed controller-set digest. A controller may have been injected or a key swapped.' };
        }
      }
      if (item.head_before !== currentHead) {
        return { valid: false, code: 'transition_head_chain_invalid', message: 'Policy transition heads are discontinuous.' };
      }
      const hash = stableDigest(item.transition_receipt);
      if (priorHash && payload.previous_transition_hash !== priorHash) {
        return { valid: false, code: 'transition_chain_invalid', message: 'Policy transition chain is discontinuous.' };
      }
      priorHash = hash;
      currentHead = item.head_after;
      // Reconstruct the active state that THIS transition establishes, reading
      // from the gate-SIGNED payload (immutable), not the display fields.
      const pExpiry = (payload.expiry as string | undefined) || null;
      const pProposalId = (payload.proposal_id as string | undefined) || null;
      const pHeadBefore = (payload.head_before as string | null | undefined) ?? null;
      const pHeadAfter = (payload.head_after as string | undefined) || '';
      if (item.event === 'initialized') {
        currentBaseline = pHeadAfter; currentExpiry = null; currentProposalId = null;
      } else if (item.event === 'policy_activated') {
        currentBaseline = pHeadBefore; currentExpiry = pExpiry; currentProposalId = pProposalId;
      } else if (item.event === 'policy_expired_reverted') {
        currentBaseline = pHeadAfter; currentExpiry = null; currentProposalId = null;
      }
      // proposal_created / proposal_approved leave head, expiry, and baseline unchanged.
    }
    if (currentHead !== registry.active.policy_digest) return { valid: false, code: 'active_head_transition_mismatch', message: 'Active policy head does not match the signed transition chain.' };
    // active.{expires_at, baseline_policy_digest, proposal_id} must equal what the
    // gate-signed chain establishes. Stripping the expiry (temporary widening ->
    // permanent), extending it, or repointing the baseline (revert -> no-op) are
    // all rejected, because none of those fields is trusted on its own.
    if ((registry.active.expires_at || null) !== currentExpiry) {
      return { valid: false, code: 'active_expiry_mismatch', message: 'The active grant expiry does not match the gate-signed transition chain (stripped or extended).' };
    }
    if (registry.active.baseline_policy_digest !== currentBaseline) {
      return { valid: false, code: 'active_baseline_mismatch', message: 'The active baseline policy digest does not match the gate-signed transition chain.' };
    }
    if ((registry.active.proposal_id || null) !== currentProposalId) {
      return { valid: false, code: 'active_proposal_mismatch', message: 'The active proposal id does not match the gate-signed transition chain.' };
    }
    const usedDenials = new Set<string>();
    for (const proposal of Object.values(registry.proposals || {})) {
      const error = verifyProposal(registry, proposal);
      if (error) return { valid: false, code: error, message: 'A policy proposal cannot be verified.' };
      if (usedDenials.has(proposal.denial_origin.receipt_hash)) {
        return { valid: false, code: 'denial_receipt_reused', message: 'A denial receipt was used for more than one policy proposal.' };
      }
      usedDenials.add(proposal.denial_origin.receipt_hash);
    }
    for (const [proposalId, approval] of Object.entries(registry.approvals || {})) {
      const proposal = registry.proposals[proposalId];
      if (!proposal) return { valid: false, code: 'approval_without_proposal', message: 'A controller approval refers to no proposal.' };
      const error = approval.method === 'ed25519'
        ? verifyDirectApproval(registry, proposal, approval)
        : verifyWebAuthnApproval(registry, proposal, approval);
      if (error) return { valid: false, code: error, message: 'A controller approval cannot be verified.' };
    }
    for (const item of registry.history) {
      if (item.event !== 'proposal_approved' && item.event !== 'policy_activated') continue;
      if (!item.proposal_id || !item.approval_digest) return { valid: false, code: 'activation_approval_missing', message: 'A policy activation lacks its proposal or controller approval reference.' };
      const approval = registry.approvals[item.proposal_id];
      const proposal = registry.proposals[item.proposal_id];
      if (!approval || !proposal || approvalDigest(approval) !== item.approval_digest) {
        return { valid: false, code: 'activation_approval_mismatch', message: 'A policy activation does not bind the exact verified controller approval.' };
      }
      if (item.event === 'policy_activated' && (item.head_before !== proposal.base_policy_digest || item.head_after !== proposal.proposed_policy_digest)) {
        return { valid: false, code: 'activation_policy_mismatch', message: 'A policy activation does not bind the proposed policy transition.' };
      }
    }
    if (registry.active.expires_at && Date.parse(registry.active.expires_at) <= now.getTime()) {
      return { valid: false, code: 'active_grant_expired', message: 'The active widened policy has expired and must be reverted before enforcement.' };
    }
    return { valid: true, registry };
  } catch (error) {
    return { valid: false, code: 'registry_verification_error', message: error instanceof Error ? error.message : 'Registry verification failed.' };
  }
}

function installSnapshotAtomically(cedarDir: string, snapshot: PolicySnapshot): void {
  assertSnapshot(snapshot);
  const target = resolve(cedarDir);
  const parent = dirname(target);
  const base = basename(target);
  if (!existsSync(target) || !statSync(target).isDirectory()) throw new Error(`managed Cedar directory is missing: ${target}`);
  const stage = join(parent, `.${base}.scopeblind-stage-${process.pid}-${randomUUID()}`);
  const backup = join(parent, `.${base}.scopeblind-backup-${process.pid}-${randomUUID()}`);
  mkdirSync(stage, { recursive: true, mode: 0o700 });
  try {
    for (const file of snapshot.files) writeFileSync(join(stage, file.name), file.content, { encoding: 'utf-8', mode: 0o600 });
    // A directory swap prevents the running Node process from observing a
    // partially-written policy set. On a crash between the two renames, the
    // recovery path restores the old directory before returning an error.
    renameSync(target, backup);
    try {
      renameSync(stage, target);
    } catch (error) {
      renameSync(backup, target);
      throw error;
    }
    rmSync(backup, { recursive: true, force: true });
  } finally {
    if (existsSync(stage)) rmSync(stage, { recursive: true, force: true });
    if (existsSync(backup) && !existsSync(target)) renameSync(backup, target);
  }
}

function addTransition(registry: MandateRegistry, signer: GateSigner, item: Omit<MandateTransition, 'transition_receipt' | 'sequence'>, at?: string): MandateTransition {
  const previous = registry.history[registry.history.length - 1];
  const previousTransitionHash = previous ? stableDigest(previous.transition_receipt) : undefined;
  const trans = transition(registry, signer, item.event, item.head_before, item.head_after, {
    ...(item.proposal_id ? { proposal_id: item.proposal_id } : {}),
    ...(item.approval_digest ? { approval_digest: item.approval_digest } : {}),
    ...(item.policy_digest ? { policy_digest: item.policy_digest } : {}),
    ...(item.expiry ? { expiry: item.expiry } : {}),
    ...(previousTransitionHash ? { previous_transition_hash: previousTransitionHash } : {}),
  }, at || item.occurred_at);
  registry.history.push(trans);
  return trans;
}

export function createPolicyProposal(input: {
  cedarDir: string;
  signer: GateSigner;
  candidateDir: string;
  denialReceipt: ActaEnvelope;
  reason: string;
  expiresAt: string;
  now?: Date;
}): MandateProposal {
  const registry = loadMandateRegistry(input.cedarDir);
  if (!registry) throw new Error('managed mandate registry not initialized');
  const integrity = verifyMandateRegistry(registry, input.now);
  if (!integrity.valid) throw new Error(`cannot propose against invalid registry: ${integrity.code}`);
  if (input.signer.kid !== registry.gate.kid || input.signer.publicKey !== registry.gate.public_key) throw new Error('proposal signer does not match the registered gate');
  const receiptCheck = verifyReceipt(input.denialReceipt, registry.gate.public_key);
  if (!receiptCheck.valid) throw new Error('proposal origin must be a valid gate-signed denial receipt');
  const receipt = input.denialReceipt.payload;
  if (receipt.type !== 'protectmcp:decision' || receipt.decision !== 'deny') throw new Error('proposal origin must be a denied protect-mcp decision');
  if (receipt.policy_digest !== registry.active.policy_digest) throw new Error('proposal origin was denied under a different policy head');
  const expiresAtMs = mustIso(input.expiresAt, 'proposal expiry');
  const createdAt = nowIso(input.now);
  if (expiresAtMs <= Date.parse(createdAt)) throw new Error('proposal expiry must be in the future');
  const candidate = snapshotFromDirectory(input.candidateDir, createdAt);
  if (candidate.policy_digest === registry.active.policy_digest) throw new Error('candidate policy is identical to the active policy');
  // No stacking: propose a widening only from a stable head, not on top of an
  // already-active temporary grant. Stacking would let the outer grant's expiry
  // be lost when the inner one reverts (revert targets the immediate prior head).
  // Let the active grant expire or revert to baseline, then widen from there.
  if (registry.active.expires_at) throw new Error('a temporary widening is already active; let it expire or revert to baseline before proposing another');
  const origin: DenialOrigin = {
    receipt: input.denialReceipt,
    receipt_hash: receiptCheck.hash || stableDigest(input.denialReceipt),
    request_id: String(receipt.request_id || ''),
    tool: String(receipt.tool_name || ''),
    reason_code: String(receipt.reason || ''),
  };
  if (!origin.request_id || !origin.tool) throw new Error('denial receipt lacks an actionable request id or tool name');
  // Single-use: one signed denial justifies at most one widening proposal, so a
  // denial receipt is not a reusable token for repeated widenings.
  if (Object.values(registry.proposals).some((p) => p.denial_origin.receipt_hash === origin.receipt_hash)) {
    throw new Error('this denial receipt has already been used for a policy proposal');
  }
  const draftBase = {
    schema: MANDATE_PROPOSAL_SCHEMA,
    proposal_id: `proposal-${randomUUID()}`,
    created_at: createdAt,
    expires_at: input.expiresAt,
    proposed_by: { gate_kid: input.signer.kid, gate_public_key: input.signer.publicKey },
    base_policy_digest: registry.active.policy_digest,
    proposed_policy_digest: candidate.policy_digest,
    denial_origin: origin,
    reason: input.reason.trim(),
    diff: describePolicyDiff(registry.policies[registry.active.policy_digest], candidate),
    candidate,
  } satisfies Omit<MandateProposal, 'proposal_digest' | 'proposal_receipt'>;
  if (!draftBase.reason) throw new Error('a controller-facing reason is required');
  const proposalDigest = stableDigest(proposalUnsigned(draftBase));
  const proposalReceipt = signLifecycleEvent(input.signer, {
    type: MANDATE_PROPOSAL_SCHEMA,
    registry_id: registry.registry_id,
    proposal_id: draftBase.proposal_id,
    proposal_digest: proposalDigest,
    base_policy_digest: draftBase.base_policy_digest,
    proposed_policy_digest: draftBase.proposed_policy_digest,
    denial_receipt_hash: origin.receipt_hash,
  }, createdAt);
  const proposal: MandateProposal = { ...draftBase, proposal_digest: proposalDigest, proposal_receipt: proposalReceipt };
  registry.proposals[proposal.proposal_id] = proposal;
  persistSnapshot(input.cedarDir, candidate);
  addTransition(registry, input.signer, {
    event: 'proposal_created',
    occurred_at: createdAt,
    head_before: registry.active.policy_digest,
    head_after: registry.active.policy_digest,
    proposal_id: proposal.proposal_id,
    policy_digest: proposal.proposed_policy_digest,
    expiry: proposal.expires_at,
  }, createdAt);
  persistRegistry(input.cedarDir, registry);
  return proposal;
}

export function createDirectControllerApproval(input: {
  proposal: MandateProposal;
  controller: DirectController;
  privateKey: string;
  now?: Date;
}): DirectApprovalProof {
  const approvedAt = nowIso(input.now);
  const approval = createReceiptEnvelope({
    type: MANDATE_APPROVAL_SCHEMA,
    proposal_id: input.proposal.proposal_id,
    proposal_digest: input.proposal.proposal_digest,
    controller_id: input.controller.id,
    decision: 'approve',
    approval_method: 'ed25519',
    controller_public_key: input.controller.public_key,
  }, input.privateKey, input.controller.id, approvedAt).envelope;
  return {
    method: 'ed25519',
    controller_id: input.controller.id,
    controller_label: input.controller.label,
    approval_receipt: approval,
    approved_at: approvedAt,
  };
}

export function createWebAuthnPolicyChallenge(input: {
  cedarDir: string;
  proposalId: string;
  controllerId: string;
  rpId: string;
  timeoutSeconds?: number;
}): ApprovalChallenge {
  const registry = loadMandateRegistry(input.cedarDir);
  if (!registry) throw new Error('managed mandate registry not initialized');
  const proposal = registry.proposals[input.proposalId];
  if (!proposal) throw new Error('unknown policy proposal');
  const controller = registry.controllers.find((item) => item.id === input.controllerId);
  if (!controller || controller.type !== 'webauthn') throw new Error('selected controller has no registered WebAuthn credential');
  const challenge = createApprovalChallenge(proposal.proposal_id, 'scopeblind:policy-change', controller.id, input.rpId, input.timeoutSeconds || 300, policyApprovalChallenge(proposal, controller.id));
  registry.pending_webauthn[proposal.proposal_id] = { proposal_id: proposal.proposal_id, controller_id: controller.id, challenge };
  persistRegistry(input.cedarDir, registry);
  return challenge;
}

function activateApprovedProposal(cedarDir: string, registry: MandateRegistry, signer: GateSigner, proposal: MandateProposal, approval: MandateApproval, at: string): MandateRegistry {
  // Never activate on top of a registry that does not itself verify: this makes
  // an injected controller or a swapped credential (caught by verifyMandateRegistry)
  // block the activation, not just later decisions.
  const integrity = verifyMandateRegistry(registry, new Date(Date.parse(at)));
  if (!integrity.valid && integrity.code !== 'active_grant_expired') throw new Error(`cannot activate against invalid registry: ${integrity.code}`);
  if (registry.active.policy_digest !== proposal.base_policy_digest) throw new Error('active policy changed after proposal; create a new proposal against the current head');
  if (Date.parse(proposal.expires_at) <= Date.parse(at)) throw new Error('proposal expired before approval; it cannot be activated');
  const controller = registry.controllers.find((item) => item.id === approval.controller_id);
  if (!controller) throw new Error('approval controller is not registered');
  const error = approval.method === 'ed25519'
    ? verifyDirectApproval(registry, proposal, approval)
    : verifyWebAuthnApproval(registry, proposal, approval);
  if (error) throw new Error(`controller approval rejected: ${error}`);
  // Gate and controller are distinct authorities by construction. A controller
  // id that reuses the gate kid would make the gate widen its own leash.
  if (controller.id === registry.gate.kid) throw new Error('the gate cannot approve its own policy proposal');
  const before = registry.active.policy_digest;
  const candidate = registry.policies[proposal.proposed_policy_digest] || proposal.candidate;
  assertSnapshot(candidate);
  installSnapshotAtomically(cedarDir, candidate);
  const compilationReceipt = signLifecycleEvent(signer, {
    event: 'compiled',
    registry_id: registry.registry_id,
    policy_digest: candidate.policy_digest,
    snapshot_digest: stableDigest(candidate),
    proposal_id: proposal.proposal_id,
    approval_digest: approvalDigest(approval),
  }, at);
  registry.policies[candidate.policy_digest] = candidate;
  registry.approvals[proposal.proposal_id] = approval;
  registry.active = {
    policy_digest: candidate.policy_digest,
    baseline_policy_digest: before,
    activated_at: at,
    expires_at: proposal.expires_at,
    proposal_id: proposal.proposal_id,
    compilation_receipt: compilationReceipt,
  };
  addTransition(registry, signer, {
    event: 'proposal_approved',
    occurred_at: at,
    head_before: before,
    head_after: before,
    proposal_id: proposal.proposal_id,
    approval_digest: approvalDigest(approval),
  }, at);
  addTransition(registry, signer, {
    event: 'policy_activated',
    occurred_at: at,
    head_before: before,
    head_after: candidate.policy_digest,
    proposal_id: proposal.proposal_id,
    approval_digest: approvalDigest(approval),
    policy_digest: candidate.policy_digest,
    expiry: proposal.expires_at,
  }, at);
  delete registry.pending_webauthn[proposal.proposal_id];
  persistRegistry(cedarDir, registry);
  return registry;
}

export function approvePolicyProposalWithDirectSignature(input: {
  cedarDir: string;
  signer: GateSigner;
  proposalId: string;
  approval: DirectApprovalProof;
  now?: Date;
}): MandateRegistry {
  const registry = loadMandateRegistry(input.cedarDir);
  if (!registry) throw new Error('managed mandate registry not initialized');
  const proposal = registry.proposals[input.proposalId];
  if (!proposal) throw new Error('unknown policy proposal');
  return activateApprovedProposal(input.cedarDir, registry, input.signer, proposal, input.approval, nowIso(input.now));
}

export function approvePolicyProposalWithWebAuthn(input: {
  cedarDir: string;
  signer: GateSigner;
  proposalId: string;
  assertion: ApprovalAssertion;
  expectedOrigin: string;
  now?: Date;
}): MandateRegistry {
  const registry = loadMandateRegistry(input.cedarDir);
  if (!registry) throw new Error('managed mandate registry not initialized');
  const proposal = registry.proposals[input.proposalId];
  const pending = registry.pending_webauthn[input.proposalId];
  if (!proposal || !pending) throw new Error('no pending WebAuthn approval exists for this proposal');
  const controller = registry.controllers.find((item) => item.id === pending.controller_id);
  if (!controller || controller.type !== 'webauthn') throw new Error('pending approval controller is not registered for WebAuthn');
  // The stored challenge must be the deterministic binding to this proposal;
  // recompute it so a registry writer cannot substitute a nonce of their own.
  if (pending.challenge.challenge !== policyApprovalChallenge(proposal, controller.id)) {
    throw new Error('pending WebAuthn challenge is not bound to this proposal');
  }
  const at = nowIso(input.now);
  const result = verifyApprovalAssertion(pending.challenge, input.assertion, controller.credential_public_key, {
    expectedOrigin: input.expectedOrigin,
    requireUserVerification: true,
    prevSignCount: controller.sign_count,
    now: Date.parse(at),
  });
  if (!result.valid || !result.userVerified) throw new Error(`WebAuthn approval rejected: ${result.reason || 'user verification required'}`);
  controller.sign_count = result.signCount;
  const approval: WebAuthnApprovalProof = {
    method: 'webauthn',
    controller_id: controller.id,
    controller_label: controller.label,
    challenge: pending.challenge,
    assertion: input.assertion,
    result,
    expected_origin: input.expectedOrigin,
    approved_at: at,
  };
  return activateApprovedProposal(input.cedarDir, registry, input.signer, proposal, approval, at);
}

export function refreshManagedMandate(input: { cedarDir: string; signer: GateSigner; now?: Date }): RegistryCheck {
  const registry = loadMandateRegistry(input.cedarDir);
  if (!registry) return { valid: true };
  if (registry.gate.kid !== input.signer.kid || registry.gate.public_key !== input.signer.publicKey) {
    return { valid: false, code: 'gate_signer_mismatch', message: 'The local gate signer does not match the signer pinned in the mandate registry.' };
  }
  const now = input.now || new Date();
  // Verify durable state before touching an expired head. Expiry is a normal
  // transition, but a tampered expired registry must never be allowed to pick
  // a baseline and have the gate countersign a fresh rollback event.
  const structural = verifyMandateRegistry(registry, now);
  if (!structural.valid && structural.code !== 'active_grant_expired') return structural;
  const savedExpiry = registry.active.expires_at;
  if (savedExpiry && Date.parse(savedExpiry) <= now.getTime()) {
    const baseline = registry.policies[registry.active.baseline_policy_digest];
    if (!baseline) return { valid: false, code: 'expiry_baseline_missing', message: 'Expired policy has no baseline snapshot to restore.' };
    try {
      installSnapshotAtomically(input.cedarDir, baseline);
      const at = nowIso(now);
      const before = registry.active.policy_digest;
      const compilationReceipt = signLifecycleEvent(input.signer, {
        event: 'compiled', registry_id: registry.registry_id, policy_digest: baseline.policy_digest,
        snapshot_digest: stableDigest(baseline), reverted_from: before,
      }, at);
      registry.active = {
        policy_digest: baseline.policy_digest,
        baseline_policy_digest: baseline.policy_digest,
        activated_at: at,
        compilation_receipt: compilationReceipt,
      };
      addTransition(registry, input.signer, {
        event: 'policy_expired_reverted', occurred_at: at, head_before: before,
        head_after: baseline.policy_digest, policy_digest: baseline.policy_digest, expiry: savedExpiry,
      }, at);
      persistRegistry(input.cedarDir, registry);
      return { valid: true, registry, expired_reverted: true };
    } catch (error) {
      return { valid: false, code: 'expiry_revert_failed', message: error instanceof Error ? error.message : 'Failed to restore the expired policy baseline.' };
    }
  }
  const check = verifyMandateRegistry(registry, now);
  if (!check.valid) return check;
  try {
    const current = snapshotFromDirectory(input.cedarDir);
    if (current.policy_digest !== registry.active.policy_digest) {
      return { valid: false, code: 'policy_head_mismatch', message: 'Policy files differ from the signed active registry head. The gate refuses to enforce an unauthorised edit.' };
    }
  } catch (error) {
    return { valid: false, code: 'policy_read_failed', message: error instanceof Error ? error.message : 'Could not read active policy files.' };
  }
  return check;
}

export function publicMandateStatus(registry: MandateRegistry): Record<string, unknown> {
  return {
    schema: registry.schema,
    registry_id: registry.registry_id,
    gate: { kid: registry.gate.kid, public_key: registry.gate.public_key, ...(registry.gate.issuer ? { issuer: registry.gate.issuer } : {}) },
    active: {
      policy_digest: registry.active.policy_digest,
      baseline_policy_digest: registry.active.baseline_policy_digest,
      activated_at: registry.active.activated_at,
      ...(registry.active.expires_at ? { expires_at: registry.active.expires_at } : {}),
      ...(registry.active.proposal_id ? { proposal_id: registry.active.proposal_id } : {}),
    },
    controllers: registry.controllers.map((controller) => ({ id: controller.id, label: controller.label, type: controller.type })),
    proposals: Object.values(registry.proposals).map((proposal) => ({
      proposal_id: proposal.proposal_id,
      proposal_digest: proposal.proposal_digest,
      base_policy_digest: proposal.base_policy_digest,
      proposed_policy_digest: proposal.proposed_policy_digest,
      expires_at: proposal.expires_at,
      reason: proposal.reason,
      diff: proposal.diff,
      approved: Boolean(registry.approvals[proposal.proposal_id]),
    })),
    transitions: registry.history.map((entry) => ({
      sequence: entry.sequence, event: entry.event, occurred_at: entry.occurred_at,
      head_before: entry.head_before, head_after: entry.head_after,
      ...(entry.proposal_id ? { proposal_id: entry.proposal_id } : {}),
      ...(entry.expiry ? { expiry: entry.expiry } : {}),
      transition_receipt_hash: stableDigest(entry.transition_receipt),
    })),
  };
}

/**
 * Position-blind Discipline Record attachment. The full registry is retained
 * alongside this summary for an offline verifier, while the summary exposes
 * only the policy-head timeline, controller method, expiry, and signed receipt
 * hashes. It never carries a prompt, portfolio, or tool payload.
 */
export function exportMandateDisciplineRecord(registry: MandateRegistry, now?: Date): Record<string, unknown> {
  const check = verifyMandateRegistry(registry, now);
  if (!check.valid) throw new Error(`cannot export invalid mandate lifecycle: ${check.code}`);
  return {
    type: 'scopeblind.discipline-policy-changes.v1',
    generated_at: nowIso(),
    registry_id: registry.registry_id,
    registry_digest: stableDigest(registry),
    active_policy_digest: registry.active.policy_digest,
    active_baseline_policy_digest: registry.active.baseline_policy_digest,
    active_grant_expires_at: registry.active.expires_at || null,
    invariant: 'A policy head becomes active only after a gate-signed proposal bound to a signed denial, a distinct registered controller approval, and an atomic install. Expired widened grants restore their signed baseline before another action is evaluated.',
    changes: registry.history.map((transition) => ({
      sequence: transition.sequence,
      event: transition.event,
      occurred_at: transition.occurred_at,
      head_before: transition.head_before,
      head_after: transition.head_after,
      proposal_id: transition.proposal_id || null,
      expires_at: transition.expiry || null,
      transition_receipt_hash: stableDigest(transition.transition_receipt),
    })),
    proposals: Object.values(registry.proposals).map((proposal) => ({
      proposal_id: proposal.proposal_id,
      proposal_digest: proposal.proposal_digest,
      base_policy_digest: proposal.base_policy_digest,
      proposed_policy_digest: proposal.proposed_policy_digest,
      denial_receipt_hash: proposal.denial_origin.receipt_hash,
      expires_at: proposal.expires_at,
      approval_method: registry.approvals[proposal.proposal_id]?.method || null,
      active: registry.active.proposal_id === proposal.proposal_id,
    })),
    disclosure: {
      included: ['policy digests', 'transition hashes', 'denial receipt hashes', 'controller approval method', 'expiry'],
      excluded: ['tool payloads', 'prompts', 'portfolio data', 'strategy inputs'],
      full_registry_attachment_required_for_offline_transition_verification: true,
    },
  };
}

/** Offline verifier for a copied registry and its policy bytes. */
export function verifyMandateLifecycleExport(
  registry: MandateRegistry,
  expectedPolicy?: PolicyBundle,
  now?: Date,
): RegistryCheck {
  // An offline verifier must be able to assess a historical export at its
  // stated as-of time; otherwise verification becomes nondeterministic as the
  // wall clock passes an approved grant's expiry.
  const status = verifyMandateRegistry(registry, now);
  if (!status.valid || !expectedPolicy) return status;
  const snapshot = registry.policies[registry.active.policy_digest];
  if (!snapshot) return { valid: false, code: 'active_snapshot_missing', message: 'The active snapshot is absent.' };
  const bundled = digestPolicyFiles('cedar', expectedPolicy.files.map((file) => ({ name: file.name, content: file.content }))).policy_digest;
  if (bundled !== snapshot.policy_digest) return { valid: false, code: 'export_policy_mismatch', message: 'The exported policy bundle does not match the active lifecycle head.' };
  return status;
}
