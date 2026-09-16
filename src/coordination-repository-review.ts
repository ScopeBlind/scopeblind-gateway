/** Additive review records. Existing repository v1 approvals and receipts retain their exact meaning. */
import {verify, type Signed} from './coordination-protocol.js';
import {REPOSITORY_HEX, REPOSITORY_ID, REPOSITORY_SHA, validRepositoryEnvelope, type RepositoryTask, type RepositoryProposal, type RepositoryApproval, type RepositoryState} from './coordination-repository.js';
export const REPOSITORY_REVIEW_ACTIONS=['repository_review_get','repository_review_packet','repository_review_feedback','repository_review_recommendation','repository_review_export'] as const;
export type RepositoryReviewAction=typeof REPOSITORY_REVIEW_ACTIONS[number];
export interface RepositoryReviewContent {
 brief:string;
 success_criteria:Array<{id:string;text:string}>;
 preview_policy?:{environment:string;check:{name:string;app_id:number};allowed_origins:string[];required:boolean};
}
export interface RepositoryReviewBrief extends RepositoryReviewContent {
 type:'scopeblind.repository.review-brief.v1';task_id:string;task_digest:string;owner_key:string;issued_at:string;expires_at:string;
}
/** The receiver attests to API metadata, not to the bytes served by this mutable URL. */
export interface RepositoryDeploymentObservation {
 deployment_id:number;status_id:number;sha:string;environment:string;state:'success';environment_url:string;
 deployment_creator_id:number;status_creator_id:number;created_at:string;updated_at:string;
 check:{id:number;name:string;app_id:number;head_sha:string;conclusion:'success'};
}
/** Separate GitHub Actions artifact metadata. No assertion binds this artifact's bytes to a preview URL. */
export interface RepositoryArtifactObservation {id:number;name:string;sha256:string;workflow_run_id:number;head_sha:string;expires_at:string}
export type RepositoryReviewPreview={status:'not_requested'|'missing'|'pending'|'failed'|'unavailable'|'ambiguous';reason:string}|{status:'available';deployment:RepositoryDeploymentObservation;artifact?:RepositoryArtifactObservation};
export interface RepositoryReviewPacket {
 type:'scopeblind.repository.review-packet.v1';task_id:string;task_digest:string;brief_digest:string;proposal_digest:string;
 base_sha:string;head_sha:string;merge_sha:string;preview:RepositoryReviewPreview;observed_at:string;expires_at:string;
}
/** Signed together with the ordinary v1 approval; neither signature may be substituted for the other. */
export interface RepositoryReviewDecision {
 type:'scopeblind.repository.review-decision.v1';task_id:string;task_digest:string;brief_digest:string;packet_digest:string;proposal_digest:string;
 approval_digest:string;principal_key:string;role:'owner'|'reviewer';issued_at:string;expires_at:string;
}
export interface RepositoryReviewFeedback {
 type:'scopeblind.repository.review-feedback.v1';id:string;task_id:string;task_digest:string;basis_digest:string;packet_digest:string;
 requester_key:string;mandate_digest?:string;criterion_ids:string[];message:string;requested_changes:string;issued_at:string;
}
export type RepositoryCriterionEvidence={kind:'check';id:number}|{kind:'file';path:string}|{kind:'deployment';id:number}|{kind:'artifact';sha256:string};
export interface RepositoryReviewRecommendation {
 type:'scopeblind.repository.review-recommendation.v1';id:string;task_id:string;task_digest:string;packet_digest:string;proposal_digest:string;brief_digest:string;
 agent_key:string;mandate_digest:string;recommendation:'ready_for_human_review'|'changes_recommended'|'insufficient_evidence';
 criteria:Array<{criterion_id:string;verdict:'met'|'not_met'|'unknown';evidence_refs:RepositoryCriterionEvidence[];explanation:string}>;
 source:{kind:'agent';model?:string};observed_at:string;
}
export interface RepositoryReviewAgentUse {
 type:'scopeblind.repository.review-agent-use.v1';task_id:string;task_digest:string;record_digest:string;
 permission:'report_criteria'|'request_revision';
 mandate:Signed<import('./coordination-repository-workspace.js').WorkspacePreparationMandate>;
 adoption:Signed<import('./coordination-repository-workspace.js').WorkspacePreparationMandate>;
 assignment:Signed<import('./coordination-repository-workspace.js').WorkspaceTaskAssignment>;checked_at:string;
}
export interface RepositoryReviewState {
 type:'scopeblind.repository.review-state.v1';task_id:string;task_digest:string;origin_digest?:string;coding_origin_digest?:string;brief:Signed<RepositoryReviewBrief>;
 packet:Signed<RepositoryReviewPacket>|null;decisions:Array<Signed<RepositoryReviewDecision>>;
 feedback:Array<Signed<RepositoryReviewFeedback>>;recommendations:Array<Signed<RepositoryReviewRecommendation>>;
 history:Array<{state:Signed<RepositoryState>;packet:Signed<RepositoryReviewPacket>;decisions:Array<Signed<RepositoryReviewDecision>>}>;agent_uses:Array<Signed<RepositoryReviewAgentUse>>;observed_at:string;
}
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const shape=(v:unknown,required:string[],optional:string[]=[]):v is Record<string,unknown>=>object(v)&&required.every(k=>Object.prototype.hasOwnProperty.call(v,k))&&Object.keys(v).every(k=>required.includes(k)||optional.includes(k));
const text=(v:unknown,max:number,empty=false)=>typeof v==='string'&&(empty||v.trim().length>0)&&v.length<=max&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v);
const line=(v:unknown,max:number)=>text(v,max)&&!/[\r\n\t]/.test(String(v));
const hex=(v:unknown):v is string=>typeof v==='string'&&REPOSITORY_HEX.test(v);
const id=(v:unknown):v is string=>typeof v==='string'&&REPOSITORY_ID.test(v);
const sha=(v:unknown):v is string=>typeof v==='string'&&REPOSITORY_SHA.test(v);
const num=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>0;
const at=(v:unknown):v is string=>typeof v==='string'&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString()===v;
const span=(a:unknown,b:unknown,max:number)=>at(a)&&at(b)&&Date.parse(b)>Date.parse(a)&&Date.parse(b)-Date.parse(a)<=max;
export function safeRepositoryPreviewUrl(value:unknown):value is string {
 if(typeof value!=='string'||value.length>2000||/[\s\u0000-\u001f\u007f]/.test(value))return false;
 try{const u=new URL(value);return u.protocol==='https:'&&!u.username&&!u.password&&u.href===value&&!u.hash&&!u.search&&u.hostname!=='localhost'&&!u.hostname.endsWith('.localhost')&&u.hostname.includes('.')&&!/^\d+(?:\.\d+){3}$/.test(u.hostname)&&!u.hostname.includes(':');}catch{return false;}
}
function content(v:Record<string,unknown>){
 if(!text(v.brief,4000)||!Array.isArray(v.success_criteria)||v.success_criteria.length<1||v.success_criteria.length>20||!v.success_criteria.every(c=>shape(c,['id','text'])&&id(c.id)&&text(c.text,600))||new Set(v.success_criteria.map(c=>c.id)).size!==v.success_criteria.length)return false;
 const p=v.preview_policy;
 return p===undefined||shape(p,['environment','check','allowed_origins','required'])&&line(p.environment,100)&&shape(p.check,['name','app_id'])&&line(p.check.name,100)&&num(p.check.app_id)&&typeof p.required==='boolean'&&Array.isArray(p.allowed_origins)&&p.allowed_origins.length>0&&p.allowed_origins.length<=8&&new Set(p.allowed_origins).size===p.allowed_origins.length&&p.allowed_origins.every(origin=>typeof origin==='string'&&safeRepositoryPreviewUrl(origin+'/')&&new URL(origin).origin===origin);
}
export function validRepositoryReviewContent(v:unknown):v is RepositoryReviewContent{return shape(v,['brief','success_criteria'],['preview_policy'])&&content(v);}
export function validRepositoryReviewBrief(v:unknown,task:RepositoryTask,taskDigest:string):v is RepositoryReviewBrief {
 return shape(v,['type','task_id','task_digest','owner_key','brief','success_criteria','issued_at','expires_at'],['preview_policy'])&&v.type==='scopeblind.repository.review-brief.v1'&&v.task_id===task.id&&v.task_digest===taskDigest&&v.owner_key===task.owner_key&&content(v)&&span(v.issued_at,v.expires_at,7*86400000)&&Date.parse(String(v.issued_at))>=Date.parse(task.issued_at)&&Date.parse(String(v.expires_at))<=Date.parse(task.expires_at);
}
export function validRepositoryReviewPacket(v:unknown,brief:Signed<RepositoryReviewBrief>,proposal:Signed<RepositoryProposal>):v is RepositoryReviewPacket {
 if(!shape(v,['type','task_id','task_digest','brief_digest','proposal_digest','base_sha','head_sha','merge_sha','preview','observed_at','expires_at'])||v.type!=='scopeblind.repository.review-packet.v1'||v.task_id!==brief.payload.task_id||v.task_digest!==brief.payload.task_digest||v.brief_digest!==brief.digest||v.proposal_digest!==proposal.digest||v.base_sha!==proposal.payload.base_sha||v.head_sha!==proposal.payload.head_sha||v.merge_sha!==proposal.payload.merge_sha||!span(v.observed_at,v.expires_at,900000)||Date.parse(String(v.observed_at))<Math.max(Date.parse(brief.payload.issued_at),Date.parse(proposal.payload.observed_at))||Date.parse(String(v.expires_at))>Date.parse(brief.payload.expires_at))return false;
 const p=v.preview,policy=brief.payload.preview_policy;
 if(!object(p))return false;
 if(p.status!=='available')return shape(p,['status','reason'])&&['not_requested','missing','pending','failed','unavailable','ambiguous'].includes(String(p.status))&&text(p.reason,600)&&((p.status==='not_requested')===!policy);
 if(!policy||!shape(p,['status','deployment'],['artifact']))return false;
 const d=p.deployment;
 if(!shape(d,['deployment_id','status_id','sha','environment','state','environment_url','deployment_creator_id','status_creator_id','created_at','updated_at','check'])||![d.deployment_id,d.status_id,d.deployment_creator_id,d.status_creator_id].every(num)||d.sha!==v.head_sha||d.environment!==policy.environment||d.state!=='success'||!safeRepositoryPreviewUrl(d.environment_url)||!policy.allowed_origins.includes(new URL(d.environment_url).origin)||!at(d.created_at)||!at(d.updated_at)||Date.parse(d.updated_at)<Date.parse(d.created_at)||Date.parse(d.updated_at)>Date.parse(String(v.observed_at))||!shape(d.check,['id','name','app_id','head_sha','conclusion'])||!num(d.check.id)||d.check.name!==policy.check.name||d.check.app_id!==policy.check.app_id||d.check.head_sha!==v.head_sha||d.check.conclusion!=='success')return false;
 const a=p.artifact;
 return a===undefined||shape(a,['id','name','sha256','workflow_run_id','head_sha','expires_at'])&&num(a.id)&&line(a.name,200)&&hex(a.sha256)&&num(a.workflow_run_id)&&a.head_sha===v.head_sha&&at(a.expires_at)&&Date.parse(a.expires_at)>Date.parse(String(v.observed_at));
}
export function validRepositoryReviewDecision(v:unknown,brief:Signed<RepositoryReviewBrief>,packet:Signed<RepositoryReviewPacket>,approval:Signed<RepositoryApproval>):v is RepositoryReviewDecision {
 return shape(v,['type','task_id','task_digest','brief_digest','packet_digest','proposal_digest','approval_digest','principal_key','role','issued_at','expires_at'])&&v.type==='scopeblind.repository.review-decision.v1'&&v.task_id===brief.payload.task_id&&v.task_digest===brief.payload.task_digest&&v.brief_digest===brief.digest&&v.packet_digest===packet.digest&&v.proposal_digest===packet.payload.proposal_digest&&v.approval_digest===approval.digest&&v.principal_key===approval.payload.principal_key&&v.role===approval.payload.role&&v.issued_at===approval.payload.issued_at&&v.expires_at===approval.payload.expires_at&&at(v.issued_at)&&at(v.expires_at)&&Date.parse(v.issued_at)>=Date.parse(packet.payload.observed_at)&&Date.parse(v.expires_at)<=Date.parse(packet.payload.expires_at)&&(!brief.payload.preview_policy?.required||packet.payload.preview.status==='available'||approval.payload.decision==='reject');
}
export function validRepositoryReviewFeedback(v:unknown,brief:Signed<RepositoryReviewBrief>,packet:Signed<RepositoryReviewPacket>):v is RepositoryReviewFeedback {
 return shape(v,['type','id','task_id','task_digest','basis_digest','packet_digest','requester_key','criterion_ids','message','requested_changes','issued_at'],['mandate_digest'])&&v.type==='scopeblind.repository.review-feedback.v1'&&id(v.id)&&v.task_id===brief.payload.task_id&&v.task_digest===brief.payload.task_digest&&hex(v.basis_digest)&&v.packet_digest===packet.digest&&hex(v.requester_key)&&(v.mandate_digest===undefined||hex(v.mandate_digest))&&Array.isArray(v.criterion_ids)&&v.criterion_ids.length<=20&&new Set(v.criterion_ids).size===v.criterion_ids.length&&v.criterion_ids.every(cid=>brief.payload.success_criteria.some(c=>c.id===cid))&&text(v.message,2000)&&text(v.requested_changes,4000,true)&&at(v.issued_at)&&Date.parse(v.issued_at)>=Date.parse(packet.payload.observed_at);
}
export function validRepositoryReviewRecommendation(v:unknown,brief:Signed<RepositoryReviewBrief>,packet:Signed<RepositoryReviewPacket>,proposal:Signed<RepositoryProposal>):v is RepositoryReviewRecommendation {
 if(!shape(v,['type','id','task_id','task_digest','packet_digest','proposal_digest','brief_digest','agent_key','mandate_digest','recommendation','criteria','source','observed_at'])||v.type!=='scopeblind.repository.review-recommendation.v1'||!id(v.id)||v.task_id!==brief.payload.task_id||v.task_digest!==brief.payload.task_digest||v.packet_digest!==packet.digest||v.proposal_digest!==proposal.digest||v.brief_digest!==brief.digest||!hex(v.agent_key)||!hex(v.mandate_digest)||!['ready_for_human_review','changes_recommended','insufficient_evidence'].includes(String(v.recommendation))||!shape(v.source,['kind'],['model'])||v.source.kind!=='agent'||v.source.model!==undefined&&!line(v.source.model,120)||!at(v.observed_at)||Date.parse(v.observed_at)<Date.parse(packet.payload.observed_at)||!Array.isArray(v.criteria)||v.criteria.length!==brief.payload.success_criteria.length)return false;
 if(new Set(v.criteria.map(c=>object(c)?c.criterion_id:null)).size!==v.criteria.length)return false;
 return v.criteria.every(c=>shape(c,['criterion_id','verdict','evidence_refs','explanation'])&&brief.payload.success_criteria.some(b=>b.id===c.criterion_id)&&['met','not_met','unknown'].includes(String(c.verdict))&&text(c.explanation,1000)&&Array.isArray(c.evidence_refs)&&c.evidence_refs.length<=12&&c.evidence_refs.every(r=>{
  if(!object(r))return false;
  if(r.kind==='check')return shape(r,['kind','id'])&&proposal.payload.checks.some(check=>check.id===r.id);
  if(r.kind==='file')return shape(r,['kind','path'])&&proposal.payload.files.some(file=>file.path===r.path);
  if(r.kind==='deployment')return shape(r,['kind','id'])&&packet.payload.preview.status==='available'&&packet.payload.preview.deployment.deployment_id===r.id;
  return r.kind==='artifact'&&shape(r,['kind','sha256'])&&packet.payload.preview.status==='available'&&packet.payload.preview.artifact?.sha256===r.sha256;
 }));
}

/** Owner-local import: observed choices only; importing does not authorize a preview or a task. */
export interface RepositoryPreviewDiscovery {
 type:'scopeblind.repository.preview-discovery.v1';repository:string;pull_number:number;head_sha:string;
 owner_key:string;receiver_key:string;authority_key:string;
 candidates:Array<{environment:string;origin:string;environment_url:string;deployment_id:number;status_id:number}>;
 checks:Array<{name:string;app_id:number;id:number}>;
 status:'observed'|'unavailable';observed_at:string;expires_at:string;
}
export async function verifyRepositoryPreviewDiscovery(value:unknown,pins:{owner_key:string;receiver_key:string;authority_key:string;repository:string;pull_number?:number},now=Date.now()):Promise<boolean>{
 try{const e=value as Signed<RepositoryPreviewDiscovery>,v=e.payload;return validRepositoryEnvelope(e)&&shape(v,['type','repository','pull_number','head_sha','owner_key','receiver_key','authority_key','candidates','checks','status','observed_at','expires_at'])&&v.type==='scopeblind.repository.preview-discovery.v1'&&v.repository===pins.repository&&num(v.pull_number)&&(pins.pull_number===undefined||v.pull_number===pins.pull_number)&&sha(v.head_sha)&&v.owner_key===pins.owner_key&&v.receiver_key===pins.receiver_key&&v.authority_key===pins.authority_key&&span(v.observed_at,v.expires_at,86400000)&&Date.parse(v.observed_at)<=now+1000&&Date.parse(v.expires_at)>now&&['observed','unavailable'].includes(v.status)&&Array.isArray(v.candidates)&&v.candidates.length<=20&&v.candidates.every(c=>shape(c,['environment','origin','environment_url','deployment_id','status_id'])&&line(c.environment,100)&&safeRepositoryPreviewUrl(c.environment_url)&&new URL(c.environment_url).origin===c.origin&&num(c.deployment_id)&&num(c.status_id))&&new Set(v.candidates.map(c=>c.deployment_id)).size===v.candidates.length&&Array.isArray(v.checks)&&v.checks.length<=100&&v.checks.every(c=>shape(c,['name','app_id','id'])&&line(c.name,100)&&num(c.app_id)&&num(c.id))&&new Set(v.checks.map(c=>c.name+':'+c.app_id)).size===v.checks.length&&(v.status!=='unavailable'||v.candidates.length===0)&&await verify(e,pins.receiver_key);}catch{return false;}
}
