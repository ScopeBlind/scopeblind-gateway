/** Browser/Worker/Node shared contract. No storage, secrets, or Node imports. */
export const COORDINATION_DOMAIN = 'scopeblind.coordination.v1\n';
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export interface Signed<T> { payload: T; signer: string; digest: string; signature: string; authorization?: Signed<import('./coordination-devices').DeviceAuthorization>; authorization_signature?: string; authorization_use?: Signed<import('./coordination-devices').DeviceUse> }
export interface SigningIdentity { publicKey: string; privateKey: CryptoKey; deviceAuthorization?: Signed<import('./coordination-devices').DeviceAuthorization> }
export interface Agreement {
  type: 'scopeblind.coordination.agreement.v1'; id: string; version: 1; title: string;
  owner_key: string; registrar_key: string; currency: 'USD'; budget_minor: number;
  approval_above_minor: number; approval_ttl_seconds: number; allowed_destinations: string[]; issued_at: string;
  mode?: 'guided' | 'live'; brief?: string; preferences?: string[]; assumptions?: string[]; require_po_match?: boolean;
}
export interface InvitationGrant {
  type: 'scopeblind.coordination.grant.v1'; grant_id: string; room_id: string;
  agreement_digest: string; issuer: string; registrar_key: string; role: 'reviewer';
  actions: Array<'decide' | 'accept'>; expires_at: string; token_hash: string; max_claims: 1;
}
export interface ClaimProof {
  type: 'scopeblind.coordination.claim.v1'; grant_id: string; room_id: string;
  guest_key: string; name: string; issued_at: string; nonce: string;
}
export interface GuestBinding {
  type: 'scopeblind.coordination.binding.v1'; grant_id: string; grant_digest: string;
  room_id: string; guest_key: string; name: string; issued_at: string; expires_at: string;
  claim: Signed<ClaimProof>;
}
export interface PaymentInput { invoice_id: string; amount_minor: number; currency: 'USD'; destination: string; fixture_revision?: number }
export interface OperationRequest { operation_id: string; run_id: string; tool: 'ledger.pay'; input: PaymentInput; supersedes?: string }
export interface Invoice { id: string; invoice_id: string; vendor: string; description: string; amount_minor: number; destination: string; duplicate_of?: string; purchase_order_id?: string }
export interface PurchaseOrder { id: string; vendor: string; destination: string; amount_minor: number; currency: 'USD' }
export interface InvoiceFixtures { revision: number; invoices: Invoice[]; purchase_orders: PurchaseOrder[] }
export type OperationStatus = 'held' | 'admitted' | 'confirmed' | 'refused' | 'declined' | 'request_changes' | 'superseded' | 'unknown' | 'failed';
export interface Approval {
  type: 'scopeblind.coordination.approval.v1'; room_id: string; run_id: string; operation_id: string;
  agreement_digest: string; payload_hash: string; grant_id: string;
  decision: 'approve' | 'deny' | 'request_changes'; issued_at: string; expires_at: string; note: string;
}
export interface Admission {
  type: 'scopeblind.coordination.admission.v1'; room_id: string; run_id: string; operation_id: string;
  agreement_digest: string; payload_hash: string; input: PaymentInput; destination: string;
  decision: 'admitted' | 'held' | 'refused'; reason: string; issued_at: string; expires_at: string;
}
export interface Outcome {
  type: 'scopeblind.coordination.outcome.v1'; room_id: string; run_id: string; operation_id: string;
  payload_hash: string; status: 'confirmed' | 'failed' | 'unknown'; amount_minor: number;
  destination: string; transaction_id?: string; observed_by: 'sandbox-ledger' | 'gateway-report'; issued_at: string; note?: string;
}
export interface Operation {
  operation_id: string; run_id: string; tool: 'ledger.pay'; input: PaymentInput; payload_hash: string;
  status: OperationStatus; reason: string; created_at: string; updated_at: string;
  decision?: Signed<Approval>; admission?: Signed<Admission>; receipt?: Signed<Outcome>;
  supersedes?: string; previous_input?: PaymentInput;
}
export interface Manifest {
  type: 'scopeblind.coordination.manifest.v1'; room_id: string; run_id: string; agreement_digest: string;
  operations: Operation[]; budget: Budget; finalized_at: string;
  summary?: string; previous_manifest_digest?: string; historical_operations?: Operation[]; fixtures?: InvoiceFixtures;
}
export interface Acceptance {
  type: 'scopeblind.coordination.acceptance.v1'; room_id: string; run_id: string;
  agreement_digest: string; manifest_digest: string; grant_id: string;
  decision: 'accept' | 'request_changes'; issued_at: string; note: string;
}
export interface AcceptanceRecord {
  type: 'scopeblind.coordination.acceptance-record.v1'; room_id: string; run_id: string;
  manifest_digest: string; acceptance_digest: string; reviewer_key: string; recorded_at: string;
}
export interface AttemptRevision {
  type: 'scopeblind.coordination.revision.v1'; room_id: string; previous_run_id: string; run_id: string;
  previous_manifest_digest: string; agreement_digest: string; requested_by: string; note: string; issued_at: string;
}
export interface AttemptView {
  manifest: Signed<Manifest>; acceptances: Signed<Acceptance>[]; acceptance_records: Signed<AcceptanceRecord>[]; revision: Signed<AttemptRevision>;
}
export interface Budget { limit_minor: number; reserved_minor: number; spent_minor: number; remaining_minor: number }
export interface RoomEvent { id: number; type: string; at: string; message: string; operation_id?: string }
export interface GrantView { grant: Signed<InvitationGrant>; binding?: Signed<GuestBinding>; revoked: boolean }
export interface LiveState {
  status:'ready'|'running'|'waiting'|'completed'|'error'|'exhausted';
  message:string; steps_used:number; step_limit:number; model:string; last_error?:string; updated_at:string;
}
export interface RoomView {
  room_id: string; run_id: string; agreement: Signed<Agreement>; owner_name: string; created_at: string;
  paused: boolean; authority_key: string; budget: Budget; invoices: Invoice[]; operations: Operation[];
  grants: GrantView[]; manifest?: Signed<Manifest>; acceptances: Signed<Acceptance>[]; events: RoomEvent[]; revision: number;
  acceptance_records?: Signed<AcceptanceRecord>[];
  rehearsal_parent?: Signed<import('./coordination-rehearsal').RehearsalAdoption>;
  negotiation_parent?: Signed<import('./coordination-negotiation').NegotiationAdoption>;
  negotiation_evidence?: import('./coordination-negotiation').NegotiationExport;
  fixtures?: InvoiceFixtures; inputs_locked?: boolean; attempt?: number; attempts?: AttemptView[]; historical_operations?: Operation[]; revision_note?: string; live?: LiveState; agent_pairings?: import('./coordination-pairing').AgentPairingView[];
}
export type RpcAction = 'create' | 'invite' | 'claim' | 'revoke' | 'admit' | 'execute' | 'outcome' | 'decide' | 'revise' | 'finalize' | 'accept' | 'pause' | 'actor_token' | 'inspect' | 'deliver' | 'fixtures_update' | 'restart' | 'live_start' | 'live_tick' | 'live_retry' | 'pair_create' | 'pair_revoke' | 'pair_claim' | 'brief_draft'
  | import('./coordination-rehearsal').RehearsalAction | 'rehearsal_invite' | 'rehearsal_claim' | 'rehearsal_revoke' | 'rehearsal_adopt' | 'rehearsal_draft' | 'rehearsal_case_review'
  | import('./coordination-negotiation').NegotiationAction | 'negotiation_share' | 'negotiation_invitation_rotate' | 'result_share'
  | import('./coordination-devices').DeviceAction
  | import('./coordination-repository').RepositoryAction
  | import('./coordination-repository-collaboration').RepositoryCollaborationAction
  | import('./coordination-repository-workspace').RepositoryWorkspaceAction
  | import('./coordination-repository-review').RepositoryReviewAction
  | typeof import('./coordination-agent-requests').AGENT_REQUEST_ACTIONS[number]
  | typeof import('./coordination-inbox').DECISION_ACTIONS[number];
export interface RpcRequest {
  type: 'scopeblind.coordination.request.v1'; action: RpcAction; room_id: string;
  issued_at: string; nonce: string; body: Record<string, unknown>;
}
export interface AuthorityInfo { live_available?: boolean; ok: true; authority_key: string; label: string; protocol: 'scopeblind.coordination.v1' }
export interface AdmissionResult { ok: true; decision: 'admitted' | 'held' | 'refused'; operation: Operation; admission: Signed<Admission>; replay: boolean }
export interface OutcomeResult { ok: true; operation: Operation; outcome: Signed<Outcome>; replay: boolean }
export interface EvidenceBundle {
  type: 'scopeblind.coordination.evidence.v1'; agreement: Signed<Agreement>; grants: GrantView[];
  manifest: Signed<Manifest>; acceptances: Signed<Acceptance>[];
  acceptance_records?: Signed<AcceptanceRecord>[]; prior_attempts?: AttemptView[]; negotiation?: import('./coordination-negotiation').NegotiationExport;
}
export const DEMO_INVOICES: Invoice[] = [
  { id: 'northstar', invoice_id: 'INV-101', vendor: 'Northstar Supplies', description: 'Office supplies · purchase order matched', amount_minor: 32000, destination: 'sandbox:northstar' },
  { id: 'fieldwork', invoice_id: 'INV-102', vendor: 'Fieldwork Studio', description: 'Design support · purchase order matched', amount_minor: 48000, destination: 'sandbox:fieldwork' },
  { id: 'atlas', invoice_id: 'INV-103', vendor: 'Atlas Services', description: 'Monthly services · needs your reviewer', amount_minor: 108000, destination: 'sandbox:atlas' },
  { id: 'northstar-copy', invoice_id: 'INV-101', vendor: 'Northstar Supplies', description: 'A second copy of INV-101', amount_minor: 32000, destination: 'sandbox:northstar', duplicate_of: 'northstar' },
];
export const DEMO_PURCHASE_ORDERS: PurchaseOrder[] = [
  { id: 'PO-101', vendor: 'Northstar Supplies', destination: 'sandbox:northstar', amount_minor: 32000, currency: 'USD' },
  { id: 'PO-102', vendor: 'Fieldwork Studio', destination: 'sandbox:fieldwork', amount_minor: 48000, currency: 'USD' },
  { id: 'PO-103', vendor: 'Atlas Services', destination: 'sandbox:atlas', amount_minor: 98000, currency: 'USD' },
];
export function defaultFixtures(): InvoiceFixtures {
  return { revision: 1, invoices: DEMO_INVOICES.map(i => ({ ...i, purchase_order_id: `PO-${i.invoice_id.slice(4)}` })), purchase_orders: DEMO_PURCHASE_ORDERS.map(p => ({ ...p })) };
}
export function invoiceMatchesPurchaseOrder(invoice: Invoice, fixtures: InvoiceFixtures): boolean {
  const order = fixtures.purchase_orders.find(p => p.id === invoice.purchase_order_id);
  return !!order && order.amount_minor === invoice.amount_minor && order.destination === invoice.destination && order.vendor === invoice.vendor && order.currency === 'USD';
}
export function bytesToHex(bytes: Uint8Array): string { return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(''); }
export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  if (!/^(?:[0-9a-f]{2})+$/i.test(hex)) throw new Error('Invalid hexadecimal data');
  return Uint8Array.from(hex.match(/../g)!.map(x => parseInt(x, 16)));
}
function validUnicode(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) { const n = value.charCodeAt(++i); if (!(n >= 0xdc00 && n <= 0xdfff)) return false; }
    else if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
}
/** JCS key ordering is emitted directly, including integer-looking object keys. */
export function canonical(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string') { if (!validUnicode(value)) throw new Error('Invalid Unicode'); return JSON.stringify(value); }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') { if (!Number.isFinite(value)) throw new Error('Non-finite number'); return JSON.stringify(value); }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) if (!Object.hasOwn(value, i)) throw new Error('Sparse arrays are not JSON');
    return '[' + value.map(canonical).join(',') + ']';
  }
  if (typeof value === 'object') {
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) throw new Error('Expected a plain JSON object');
    const object = value as Record<string, unknown>;
    return '{' + Object.keys(object).sort().map(k => canonical(k) + ':' + canonical(object[k])).join(',') + '}';
  }
  throw new Error('Not a JSON value');
}
export async function sha256(value: string): Promise<string> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))));
}
export async function payloadHash(input: PaymentInput): Promise<string> { return sha256(canonical(input)); }
export async function generateIdentity(): Promise<SigningIdentity> {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair;
  return { publicKey: bytesToHex(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey) as ArrayBuffer)), privateKey: pair.privateKey };
}
/** The public key accompanies a PKCS8 service secret in config as a non-secret pin. */
export async function importIdentity(pkcs8Hex: string, publicKey: string): Promise<SigningIdentity> {
  if (!/^[0-9a-f]{64}$/.test(publicKey)) throw new Error('Invalid public key');
  const privateKey = await crypto.subtle.importKey('pkcs8', hexToBytes(pkcs8Hex), { name: 'Ed25519' }, false, ['sign']);
  const identity = { publicKey, privateKey };
  const check = await sign({ type: 'scopeblind.coordination.key-check.v1' }, identity);
  if (!await verify(check, publicKey)) throw new Error('Signing key does not match authority key');
  return identity;
}
export async function sign<T>(payload: T, identity: SigningIdentity): Promise<Signed<T>> {
  const preimage = COORDINATION_DOMAIN + canonical(payload);
  const signature = await crypto.subtle.sign('Ed25519', identity.privateKey, new TextEncoder().encode(preimage));
  const envelope:Signed<T>={ payload, signer: identity.publicKey, digest: await sha256(preimage), signature: bytesToHex(new Uint8Array(signature)) };
  if(identity.deviceAuthorization){
    envelope.authorization=identity.deviceAuthorization;
    const binding='scopeblind.coordination.device-authorization.v1\n'+envelope.digest+'\n'+identity.deviceAuthorization.digest;
    envelope.authorization_signature=bytesToHex(new Uint8Array(await crypto.subtle.sign('Ed25519',identity.privateKey,new TextEncoder().encode(binding))));
  }
  return envelope;
}
export async function verify<T>(envelope: Signed<T>, expectedSigner?: string): Promise<boolean> {
  try {
    if (!envelope || !/^[0-9a-f]{64}$/.test(envelope.signer) || !/^[0-9a-f]{64}$/.test(envelope.digest) || !/^[0-9a-f]{128}$/.test(envelope.signature)) return false;
    if (expectedSigner && expectedSigner !== envelope.signer) return false;
    const preimage = COORDINATION_DOMAIN + canonical(envelope.payload);
    if (await sha256(preimage) !== envelope.digest) return false;
    const key = await crypto.subtle.importKey('raw', hexToBytes(envelope.signer), { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify('Ed25519', key, hexToBytes(envelope.signature), new TextEncoder().encode(preimage));
  } catch { return false; }
}
export function makeRequest(action: RpcAction, room_id: string, body: Record<string, unknown>): RpcRequest {
  return { type: 'scopeblind.coordination.request.v1', action, room_id, body, issued_at: new Date().toISOString(), nonce: crypto.randomUUID() };
}
export function defaultAgreement(id: string, owner_key: string, registrar_key: string): Agreement {
  return { type: 'scopeblind.coordination.agreement.v1', id, version: 1, title: "This week's invoices", owner_key, registrar_key,
    currency: 'USD', budget_minor: 200000, approval_above_minor: 50000, approval_ttl_seconds: 900,
    allowed_destinations: ['sandbox:northstar', 'sandbox:fieldwork', 'sandbox:atlas'], issued_at: new Date().toISOString() };
}
