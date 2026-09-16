import {canonical,sha256,verify,type EvidenceBundle,type RpcRequest,type Signed} from './coordination-protocol';
import {verifyNegotiationEvidence,type NegotiationExport} from './coordination-negotiation';
import {verifyEvidence} from './coordination-evidence';

export const SNAPSHOT_RETENTION_MS=30*24*60*60*1000;
export const SNAPSHOT_MAX_BYTES=512*1024;
export interface SnapshotReceipt {
 type:'scopeblind.coordination.public-snapshot.v1'; id:string; kind:'negotiation'|'result';
 room_id:string; session_id?:string; proposal_digest?:string; target_digest:string;
 evidence_sha256:string; authorization_digest:string; shared_by:string;
 created_at:string; expires_at:string; purpose:'public_read_only_snapshot'; historical:true;
}
interface SnapshotBase {
 id:string; created_at:string; expires_at:string; receipt:Signed<SnapshotReceipt>; authorization:Signed<RpcRequest>;
}
export type PublicSnapshot=(SnapshotBase&{kind:'negotiation';evidence:NegotiationExport})|(SnapshotBase&{kind:'result';evidence:EvidenceBundle});
export interface SnapshotVerification {valid:boolean;checks:Array<{name:string;passed:boolean}>;limitations:string[]}
const exact=(v:unknown,names:string[])=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...names].sort().join(',');
/** Verifies the saved historical bytes and explicit sharing signature. A link confers no authority. */
export async function verifyPublicSnapshot(value:unknown,authorityKey:string):Promise<SnapshotVerification>{
 const checks:SnapshotVerification['checks']=[],add=(name:string,passed:unknown)=>checks.push({name,passed:passed===true});
 try{
  const s=value as PublicSnapshot,r=s.receipt.payload,a=s.authorization.payload,created=Date.parse(r.created_at),expires=Date.parse(r.expires_at);
  add('Recognized immutable snapshot',exact(s,['kind','id','created_at','expires_at','evidence','receipt','authorization'])&&['negotiation','result'].includes(s.kind)&&/^[0-9a-f]{64}$/.test(s.id));
  add('Pinned authority signed the historical sharing receipt',/^[0-9a-f]{64}$/.test(authorityKey)&&await verify(s.receipt,authorityKey)&&r.type==='scopeblind.coordination.public-snapshot.v1'&&r.purpose==='public_read_only_snapshot'&&r.historical===true);
  add('Receipt names these exact bytes and retention dates',exact(r,['type','id','kind','room_id','target_digest','evidence_sha256','authorization_digest','shared_by','created_at','expires_at','purpose','historical',...(s.kind==='negotiation'?['session_id','proposal_digest']:[])])&&r.id===s.id&&r.kind===s.kind&&r.created_at===s.created_at&&r.expires_at===s.expires_at&&Number.isFinite(created)&&expires-created===SNAPSHOT_RETENTION_MS&&r.evidence_sha256===await sha256(canonical(s.evidence))&&new TextEncoder().encode(canonical(s.evidence)).byteLength<=SNAPSHOT_MAX_BYTES);
  add('A person explicitly signed public sharing of this target',exact(s.authorization,['payload','signer','digest','signature'])&&exact(a,['type','action','room_id','issued_at','nonce','body'])&&await verify(s.authorization,r.shared_by)&&r.authorization_digest===s.authorization.digest&&a.type==='scopeblind.coordination.request.v1'&&a.room_id===r.room_id&&Math.abs(created-Date.parse(a.issued_at))<=300000&&typeof a.nonce==='string'&&/^[A-Za-z0-9_-]{8,100}$/.test(a.nonce));
  if(s.kind==='negotiation'){
   const e=s.evidence,checked=await verifyNegotiationEvidence(e,authorityKey);
   add('Exact verified negotiation report',checked.valid&&a.action==='negotiation_share'&&exact(a.body,['session_id','proposal_digest','report_digest'])&&a.body.session_id===r.session_id&&a.body.proposal_digest===r.proposal_digest&&a.body.report_digest===r.target_digest&&r.room_id===e.session.payload.room_id&&r.session_id===e.session.payload.id&&r.proposal_digest===e.report.payload.proposal_digest&&r.proposal_digest===e.proposals.at(-1)?.digest&&r.target_digest===e.report.digest);
   add('Sharing person is one of the two principals',r.shared_by===e.session.payload.owner_key||r.shared_by===e.binding.payload.guest_key);
  }else{
   const e=s.evidence,checked=await verifyEvidence(e,authorityKey);
   add('Exact verified completed result',checked.valid&&a.action==='result_share'&&exact(a.body,['manifest_digest'])&&a.body.manifest_digest===r.target_digest&&r.room_id===e.agreement.payload.id&&r.target_digest===e.manifest.digest);
   add('Sharing person was organizer or a current reviewer',r.shared_by===e.agreement.payload.owner_key||e.grants.some(g=>!g.revoked&&g.binding?.payload.guest_key===r.shared_by&&Date.parse(g.grant.payload.expires_at)>created&&g.grant.payload.actions.some(x=>x==='decide'||x==='accept')));
  }
 }catch{add('Snapshot structure is complete',false);}
 return {valid:checks.length>0&&checks.every(c=>c.passed),checks,limitations:['This is a historical snapshot of the exact shared export. It does not establish current task status, current approval, or payment authority.','The public link permits reading only. Its hosted copy is available for 30 days; downloaded evidence can be retained separately.']};
}
