import {expect,it} from 'vitest';
import {canonical,defaultAgreement,generateIdentity,makeRequest,sha256,sign,type EvidenceBundle,type Manifest} from './coordination-protocol';
import {SNAPSHOT_RETENTION_MS,verifyPublicSnapshot,type PublicSnapshot,type SnapshotReceipt} from './coordination-sharing';

async function fixture(){
 const owner=await generateIdentity(),authority=await generateIdentity(),outsider=await generateIdentity(),created_at=new Date().toISOString(),expires_at=new Date(Date.parse(created_at)+SNAPSHOT_RETENTION_MS).toISOString();
 const agreement=await sign({...defaultAgreement('snapshot-test-room',owner.publicKey,authority.publicKey),issued_at:new Date(Date.now()-60000).toISOString()},owner);
 const manifest=await sign<Manifest>({type:'scopeblind.coordination.manifest.v1',room_id:agreement.payload.id,run_id:'snapshot-test-run',agreement_digest:agreement.digest,operations:[],budget:{limit_minor:agreement.payload.budget_minor,spent_minor:0,reserved_minor:0,remaining_minor:agreement.payload.budget_minor},finalized_at:created_at},authority);
 const evidence:EvidenceBundle={type:'scopeblind.coordination.evidence.v1',agreement,manifest,grants:[],acceptances:[]};
 const authorization=await sign({...makeRequest('result_share',agreement.payload.id,{manifest_digest:manifest.digest}),issued_at:created_at},owner),id='ab'.repeat(32);
 const receipt=await sign<SnapshotReceipt>({type:'scopeblind.coordination.public-snapshot.v1',id,kind:'result',room_id:agreement.payload.id,target_digest:manifest.digest,evidence_sha256:await sha256(canonical(evidence)),authorization_digest:authorization.digest,shared_by:owner.publicKey,created_at,expires_at,purpose:'public_read_only_snapshot',historical:true},authority);
 const snapshot:PublicSnapshot={kind:'result',id,created_at,expires_at,evidence,receipt,authorization};return {snapshot,owner,authority,outsider};
}
it('verifies exact historical snapshot bytes against an independently supplied authority',async()=>{
 const {snapshot,authority,outsider}=await fixture(),verified=await verifyPublicSnapshot(snapshot,authority.publicKey);
 expect(verified.checks.filter(c=>!c.passed)).toEqual([]);expect(verified.valid).toBe(true);
 expect((await verifyPublicSnapshot(JSON.parse(canonical(snapshot)),authority.publicKey)).valid).toBe(true);
 expect((await verifyPublicSnapshot(snapshot,outsider.publicKey)).valid).toBe(false);
 const changed=structuredClone(snapshot);changed.evidence.manifest.payload.budget.spent_minor++;
 expect((await verifyPublicSnapshot(changed,authority.publicKey)).valid).toBe(false);
});
it('rejects a valid authority receipt when the sharing signature belongs to an unrelated person or target',async()=>{
 for(const change of['person','target']){
  const {snapshot,authority,owner,outsider}=await fixture();
  snapshot.authorization=await sign({...snapshot.authorization.payload,...(change==='target'?{body:{manifest_digest:'ff'.repeat(32)}}:{})},change==='person'?outsider:owner);
  snapshot.receipt=await sign({...snapshot.receipt.payload,authorization_digest:snapshot.authorization.digest,shared_by:change==='person'?outsider.publicKey:owner.publicKey},authority);
  expect((await verifyPublicSnapshot(snapshot,authority.publicKey)).valid).toBe(false);
 }
});
it('rejects re-signed scope, retention, and arbitrary authorization payload changes',async()=>{
 for(const change of['scope','retention','extra']){
  const {snapshot,authority,owner}=await fixture();
  if(change==='extra')snapshot.authorization=await sign({...snapshot.authorization.payload,private_context:'must not be carried in a public snapshot'},owner);
  if(change==='retention')snapshot.expires_at=new Date(Date.parse(snapshot.created_at)+SNAPSHOT_RETENTION_MS+1).toISOString();
  const receipt=await sign({...snapshot.receipt.payload,authorization_digest:snapshot.authorization.digest,expires_at:snapshot.expires_at,...(change==='scope'?{historical:false}:{})},authority);
  expect((await verifyPublicSnapshot({...snapshot,receipt},authority.publicKey)).valid).toBe(false);
 }
});
