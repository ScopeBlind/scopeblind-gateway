// ── Core Gateway ────────────────────────────────────────────────
export { ProtectGateway } from './gateway.js';

// ── Policy ──────────────────────────────────────────────────────
export { loadPolicy, getToolPolicy, parseRateLimit, checkRateLimit } from './policy.js';

// ── Trust Tier Admission ────────────────────────────────────────
export { evaluateTier, meetsMinTier } from './admission.js';
export type { ManifestPresentation, AdmissionResult, TierOverrides } from './admission.js';

// ── Credential Vault ────────────────────────────────────────────
export { resolveCredential, listCredentialLabels, validateCredentials } from './credentials.js';

// ── Signing ─────────────────────────────────────────────────────
export { initSigning, signDecision, getSignerInfo, isSigningEnabled } from './signing.js';

// ── External PDP (BYOPE) ───────────────────────────────────────
export { queryExternalPDP, buildDecisionContext } from './external-pdp.js';

// ── Audit Bundle Export ────────────────────────────────────────
export { createAuditBundle, collectSignedReceipts } from './bundle.js';
export type { AuditBundle, AuditBundleOptions } from './bundle.js';

// ── Simulate ──────────────────────────────────────────────────
export { simulate, parseLogFile, formatSimulation } from './simulate.js';
export type { SimulationResult, SimulationSummary } from './simulate.js';

// ── Compliance Report ─────────────────────────────────────────
export { generateReport, formatReportMarkdown } from './report.js';
export type { ComplianceReport } from './report.js';

// ── Manifest Validation ────────────────────────────────────────
export {
  isAgentId,
  isEvidenceType,
  isManifestStatus,
  isDisclosureMode,
  validateManifest,
  validateEvidenceReceipt,
} from './manifest.js';

// ── Hook Server (Claude Code Integration) ──────────────────────
export { startHookServer } from './hook-server.js';
export type { HookServerOptions } from './hook-server.js';

// ── Hook Patterns ──────────────────────────────────────────────
export { BUILTIN_PATTERNS, generateHookSettings, generateSampleCedarPolicy, generateVerifyReceiptSkill } from './hook-patterns.js';

// ── Cedar Schema Generation ──────────────────────────────────
export { generateCedarSchema, generateSchemaStub } from './cedar-schema.js';
export type { McpToolDescription, CedarSchemaResult, SchemaGeneratorConfig } from './cedar-schema.js';

// ── Cedar Evaluator ──────────────────────────────────────────
export { evaluateCedar, loadCedarPolicies, isCedarAvailable } from './cedar-evaluator.js';
export type { CedarPolicySet, CedarEvalRequest, CedarSchema } from './cedar-evaluator.js';
export type { HookPattern } from './hook-patterns.js';

// ── Types ───────────────────────────────────────────────────────
export type {
  ProtectPolicy,
  ToolPolicy,
  RateLimit,
  DecisionLog,
  ProtectConfig,
  JsonRpcRequest,
  JsonRpcResponse,
  TrustTier,
  PolicyEngineMode,
  ExternalPDPConfig,
  DecisionContext,
  ExternalDecision,
  CredentialConfig,
  SigningConfig,
  // Enterprise hardening types (v0.5.0+)
  HookEventName,
  HookInput,
  HookResponse,
  SwarmContext,
  TimingMetrics,
  PayloadDigest,
  PlanReceipt,
  CCRConnectorConfig,
  CCRSessionContext,
  PassportTokenClaims,
} from './types.js';

export type {
  AgentId,
  BuilderId,
  Ed25519PublicKey,
  SHA256Hash,
  ManifestStatus,
  DisclosureMode,
  EvidenceType,
  AgentManifest,
  ManifestIdentity,
  ManifestBuilder,
  ManifestCapabilities,
  ManifestConfig,
  EvidenceSummary,
  EvidenceSummaryEntry,
  LeaseCompatibility,
  ManifestSignature,
  IssuerType,
  EvidenceIssuer,
  EvidenceReceiptBase,
  ArenaPayload,
  BenchmarkPayload,
  WorkPayload,
  RestraintPayload,
  AttestationPayload,
  ArenaReceipt,
  BenchmarkReceipt,
  WorkReceipt,
  RestraintReceipt,
  AttestationReceipt,
  EvidenceReceipt,
} from './manifest.js';

// ── Rekor Transparency Log Anchoring ────────────────────────────
export { anchorToRekor, verifyRekorAnchor, hashReceipt, createLogAnchorField } from './rekor-anchor.js';
export type { RekorAnchor, RekorVerification } from './rekor-anchor.js';

// ── Selective Disclosure ────────────────────────────────────────
export { redactFields, revealField, verifyCommitment, verifyAllCommitments, createDisclosurePackage } from './selective-disclosure.js';
export type { RedactionSalt, RedactedResult } from './selective-disclosure.js';

// ── Notifications ───────────────────────────────────────────────
export { sendApprovalNotification, parseNotificationConfigFromEnv } from './notifications.js';
export type { NotificationConfig, ApprovalNotification } from './notifications.js';

// ── HuggingFace Export ──────────────────────────────────────────
export { receiptsToHFRows, generateHFMetadata, exportJSONL, generateDatasetCard } from './huggingface-export.js';
export type { HFReceiptRow, HFDatasetMetadata } from './huggingface-export.js';

// ── WebAuthn/Passkey Approval ───────────────────────────────────
export {
  createApprovalChallenge,
  toCredentialRequestOptions,
  verifyApprovalAssertion,
  createApprovalReceiptPayload,
} from './webauthn-approval.js';
export type { ApprovalChallenge, ApprovalAssertion, ApprovalResult } from './webauthn-approval.js';

// ── W3C DID/VC Interoperability ────────────────────────────────
export { ed25519ToDIDKey, manifestToVC, receiptToVP } from './did-vc.js';

// ── E2B Sandbox Evaluation ─────────────────────────────────────
export { createSandbox, runInSandbox, generateSafetyTranscript, destroySandbox } from './sandbox.js';
export type { SandboxConfig, Sandbox, SandboxToolCall, SandboxResult, SandboxReceipt, SafetyTranscript } from './sandbox.js';

// ── Evidence Authenticity (TLSNotary / zkTLS) ──────────────────
export { createEvidenceAttestation, verifyEvidenceAttestation, hashResponseBody, createAttestationField } from './evidence-authenticity.js';
export type { EvidenceAttestation, EvidenceAttestationInput } from './evidence-authenticity.js';

// ── C2PA Content Credentials ───────────────────────────────────
export { createC2PAManifest, exportC2PAManifestJSON, generateC2PACommand, verifyActaC2PAAssertions } from './c2pa-credentials.js';
export type { C2PAManifest, C2PAAssertion, C2PAIngredient, C2PAOptions } from './c2pa-credentials.js';

// ── Prediction Lifecycle Bridge ─────────────────────────────────
export { computeCalibration, toMetaculusFormat, toManifoldFormat } from './prediction-bridge.js';
export type { PredictionReceipt, PredictionResolution, CalibrationScore } from './prediction-bridge.js';

// ── Agent-to-Agent Receipt Exchange (Beta) ──────────────────────
export { ReceiptPropagator, createReceiptChannel } from './agent-exchange.js';
export type { DelegationReceipt, ActionReceipt, PropagatorConfig } from './agent-exchange.js';

// ── Confidential Computing (Beta / Enterprise) ──────────────────
export { ConfidentialGate, confidentialInference } from './confidential.js';
export type { AttestationDocument, AttestationResult, ConfidentialGateConfig, ConfidentialInferenceConfig, AttestationProvider } from './confidential.js';

// ── Smithery Sandbox Server ────────────────────────────────────
// Required by Smithery registry to scan server capabilities
export { createSandboxServer } from './demo-server.js';
