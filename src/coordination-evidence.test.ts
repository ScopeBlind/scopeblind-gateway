import { test } from 'vitest';
import assert from 'node:assert/strict';
import { canonical, generateIdentity, sign, verify, payloadHash, sha256, defaultAgreement, type EvidenceBundle, type Operation, type Acceptance, type ClaimProof, type GuestBinding, type InvitationGrant, type Manifest, type Approval, type Admission, type Outcome, type AcceptanceRecord } from './coordination-protocol';
import { verifyEvidence } from './coordination-evidence';

test('canonicalization commits nested input and lexically orders numeric keys', async () => {
  assert.equal(canonical({'2': 2, '10': 10, a: {'100': 1, '20': 2}}), '{"10":10,"2":2,"a":{"100":1,"20":2}}');
  assert.equal(canonical({z:-0,a:[true,null,'é']}), '{"a":[true,null,"é"],"z":0}');
  assert.notEqual(await sha256(canonical({input:{amount:10}})), await sha256(canonical({input:{amount:11}})));
  for (const x of [NaN,Infinity,undefined,new Date(),{a:undefined},'\ud800',Array(2)]) assert.throws(() => canonical(x));
});
test('signature verifies only the exact complete payload and expected signer', async () => {
  const owner = await generateIdentity(), other = await generateIdentity();
  const s = await sign({tool:'pay',input:{amount:12,destination:'a'}},owner);
  assert.equal(await verify(s,owner.publicKey),true);
  assert.equal(await verify(s,other.publicKey),false);
  s.payload.input.amount=13;
  assert.equal(await verify(s),false);
});
async function fixture() {
  const owner=await generateIdentity(), authority=await generateIdentity(), guest=await generateIdentity();
  const ago = (s:number) => new Date(Date.now()-s*1000).toISOString();
  const agreement = await sign({...defaultAgreement('room',owner.publicKey,authority.publicKey),issued_at:ago(100)},owner);
  const grant = await sign<InvitationGrant>({type:'scopeblind.coordination.grant.v1',grant_id:'invite',room_id:'room',agreement_digest:agreement.digest,issuer:owner.publicKey,registrar_key:authority.publicKey,role:'reviewer',actions:['decide','accept'],expires_at:ago(-3600),token_hash:'f'.repeat(64),max_claims:1},owner);
  const claim=await sign<ClaimProof>({type:'scopeblind.coordination.claim.v1',grant_id:'invite',room_id:'room',guest_key:guest.publicKey,name:'Guest',issued_at:ago(90),nonce:'unique'},guest);
  const binding=await sign<GuestBinding>({type:'scopeblind.coordination.binding.v1',grant_id:'invite',grant_digest:grant.digest,room_id:'room',guest_key:guest.publicKey,name:'Guest',issued_at:ago(89),expires_at:grant.payload.expires_at,claim},authority);
  const input={invoice_id:'INV-103',amount_minor:108000,currency:'USD' as const,destination:'sandbox:atlas'}, hash=await payloadHash(input);
  const decision=await sign<Approval>({type:'scopeblind.coordination.approval.v1',room_id:'room',run_id:'run',operation_id:'op',agreement_digest:agreement.digest,payload_hash:hash,grant_id:'invite',decision:'approve',issued_at:ago(80),expires_at:ago(-800),note:''},guest);
  const admission=await sign<Admission>({type:'scopeblind.coordination.admission.v1',room_id:'room',run_id:'run',operation_id:'op',agreement_digest:agreement.digest,payload_hash:hash,input,destination:input.destination,decision:'admitted',reason:'within agreement',issued_at:ago(70),expires_at:ago(-200)},authority);
  const receipt=await sign<Outcome>({type:'scopeblind.coordination.outcome.v1',room_id:'room',run_id:'run',operation_id:'op',payload_hash:hash,status:'confirmed',amount_minor:108000,destination:input.destination,transaction_id:'txn',observed_by:'sandbox-ledger',issued_at:ago(60)},authority);
  const operation:Operation={operation_id:'op',run_id:'run',tool:'ledger.pay',input,payload_hash:hash,status:'confirmed',reason:'paid',created_at:ago(85),updated_at:ago(60),decision,admission,receipt};
  const manifest=await sign<Manifest>({type:'scopeblind.coordination.manifest.v1',room_id:'room',run_id:'run',agreement_digest:agreement.digest,operations:[operation],budget:{limit_minor:200000,spent_minor:108000,reserved_minor:0,remaining_minor:92000},finalized_at:ago(50)},authority);
  const acceptance=await sign<Acceptance>({type:'scopeblind.coordination.acceptance.v1',room_id:'room',run_id:'run',agreement_digest:agreement.digest,manifest_digest:manifest.digest,grant_id:'invite',decision:'accept',issued_at:ago(40),note:'Reviewed'},guest);
  const record=await sign<AcceptanceRecord>({type:'scopeblind.coordination.acceptance-record.v1',room_id:'room',run_id:'run',manifest_digest:manifest.digest,acceptance_digest:acceptance.digest,reviewer_key:guest.publicKey,recorded_at:ago(39)},authority);
  const bundle:EvidenceBundle={type:'scopeblind.coordination.evidence.v1',agreement,grants:[{grant,binding,revoked:false}],manifest,acceptances:[acceptance],acceptance_records:[record]};
  return {bundle,authority,guest};
}
test('portable evidence checks full author → invitation → guest → exact approval → effect → acceptance chain', async () => {
  const {bundle,authority}=await fixture();
  assert.deepEqual((await verifyEvidence(bundle,authority.publicKey)).errors,[]);
  assert.equal((await verifyEvidence(bundle)).authorityPinned,false);
  assert.equal((await verifyEvidence(bundle,authority.publicKey)).accepted,true);
  assert.equal((await verifyEvidence(bundle,'0'.repeat(64))).valid,false);
});
test('a valid manifest signature cannot conceal missing approvals, corrupted nested inputs, or unrecorded acceptance', async () => {
  const {bundle,authority}=await fixture();
  const original=structuredClone(bundle);
  delete bundle.manifest.payload.operations[0].decision;
  bundle.manifest=await sign(bundle.manifest.payload,authority);
  bundle.acceptances=[];bundle.acceptance_records=[];
  assert.equal((await verifyEvidence(bundle)).valid,false);
  original.manifest.payload.operations[0].input.amount_minor=108001;
  assert.equal((await verifyEvidence(original)).valid,false);
  const fresh=(await fixture()).bundle;
  fresh.acceptance_records=[];
  assert.equal((await verifyEvidence(fresh)).valid,false);
});
test('a valid guest signature is not by itself recipient authority', async () => {
  const {bundle,guest}=await fixture();
  bundle.acceptances[0]=await sign({...bundle.acceptances[0].payload,grant_id:'ungranted'},guest);
  assert.equal((await verifyEvidence(bundle)).valid,false);
  assert.equal((await verifyEvidence({type:'scopeblind.coordination.evidence.v1'})).valid,false);
});

test('revised evidence preserves earlier payments, recipient decisions and complete attempt lineage',async()=>{
  const {bundle,authority}=await fixture();
  const revision=await sign({type:'scopeblind.coordination.revision.v1' as const,room_id:'room',previous_run_id:'run',run_id:'run-next',previous_manifest_digest:bundle.manifest.digest,agreement_digest:bundle.agreement.digest,requested_by:bundle.agreement.payload.owner_key,note:'Clarify the result.',issued_at:new Date().toISOString()},authority);
  const prior={manifest:bundle.manifest,acceptances:bundle.acceptances,acceptance_records:bundle.acceptance_records!,revision};
  const manifest=await sign<Manifest>({...bundle.manifest.payload,run_id:'run-next',operations:[],historical_operations:bundle.manifest.payload.operations,previous_manifest_digest:bundle.manifest.digest,finalized_at:new Date().toISOString()},authority);
  const revised:EvidenceBundle={...bundle,manifest,acceptances:[],acceptance_records:[],prior_attempts:[prior]};
  assert.deepEqual((await verifyEvidence(revised,authority.publicKey)).errors,[]);
  const missing=structuredClone(revised);missing.prior_attempts=[];assert.equal((await verifyEvidence(missing,authority.publicKey)).valid,false);
  const erased=structuredClone(revised);erased.manifest=await sign({...erased.manifest.payload,historical_operations:[],budget:{limit_minor:200000,spent_minor:0,reserved_minor:0,remaining_minor:200000}},authority);
  assert.equal((await verifyEvidence(erased,authority.publicKey)).valid,false,'a fresh authority signature cannot erase a preceding signed payment');
  const corrupt=structuredClone(revised);corrupt.prior_attempts![0].acceptances[0].payload.note='Different review';assert.equal((await verifyEvidence(corrupt,authority.publicKey)).valid,false);
  const mislinked=structuredClone(revised);mislinked.prior_attempts![0].revision=await sign({...revision.payload,run_id:'another-run'},authority);assert.equal((await verifyEvidence(mislinked,authority.publicKey)).valid,false);
});

test('offline live verifier independently requires purchase-order approval and exact frozen input',async()=>{
  const owner=await generateIdentity(),authority=await generateIdentity();
  const time=new Date(Date.now()-10000).toISOString();
  const agreement=await sign({...defaultAgreement('live-room',owner.publicKey,authority.publicKey),mode:'live' as const,require_po_match:true,issued_at:time},owner);
  const input={invoice_id:'INV-LIVE',amount_minor:30000,currency:'USD' as const,destination:'sandbox:northstar',fixture_revision:1},hash=await payloadHash(input);
  const admission=await sign<Admission>({type:'scopeblind.coordination.admission.v1',room_id:'live-room',run_id:'run-live',operation_id:'operation-live',agreement_digest:agreement.digest,payload_hash:hash,input,destination:input.destination,decision:'admitted',reason:'Within scope',issued_at:time,expires_at:new Date(Date.now()+60000).toISOString()},authority);
  const receipt=await sign<Outcome>({type:'scopeblind.coordination.outcome.v1',room_id:'live-room',run_id:'run-live',operation_id:'operation-live',payload_hash:hash,status:'confirmed',amount_minor:30000,destination:input.destination,transaction_id:'demo-live',observed_by:'sandbox-ledger',issued_at:new Date(Date.now()-5000).toISOString()},authority);
  const operation:Operation={operation_id:'operation-live',run_id:'run-live',tool:'ledger.pay',input,payload_hash:hash,status:'confirmed',reason:'Paid',created_at:time,updated_at:receipt.payload.issued_at,admission,receipt};
  const manifest=await sign<Manifest>({type:'scopeblind.coordination.manifest.v1',room_id:'live-room',run_id:'run-live',agreement_digest:agreement.digest,operations:[operation],budget:{limit_minor:200000,spent_minor:30000,reserved_minor:0,remaining_minor:170000},finalized_at:new Date().toISOString(),fixtures:{revision:1,invoices:[{id:'record',invoice_id:'INV-LIVE',vendor:'Vendor',description:'Matching record',amount_minor:30000,destination:input.destination,purchase_order_id:'PO-LIVE'}],purchase_orders:[{id:'PO-LIVE',vendor:'Vendor',amount_minor:30000,destination:input.destination,currency:'USD'}]}},authority);
  const bundle:EvidenceBundle={type:'scopeblind.coordination.evidence.v1',agreement,grants:[],manifest,acceptances:[]};
  assert.deepEqual((await verifyEvidence(bundle,authority.publicKey)).errors,[]);
  const mismatch=structuredClone(bundle);mismatch.manifest.payload.fixtures!.purchase_orders[0].amount_minor=29000;mismatch.manifest=await sign(mismatch.manifest.payload,authority);
  assert.equal((await verifyEvidence(mismatch,authority.publicKey)).valid,false,'below-threshold PO exception still needs approval');
  const altered=structuredClone(bundle);altered.manifest.payload.fixtures!.invoices[0].amount_minor=30001;altered.manifest.payload.fixtures!.purchase_orders[0].amount_minor=30001;altered.manifest=await sign(altered.manifest.payload,authority);
  assert.equal((await verifyEvidence(altered,authority.publicKey)).valid,false,'matching documents do not authorize a different payment amount');
});
