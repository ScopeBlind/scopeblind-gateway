/** Guided installation is a connection, never a task approval or a standing effect grant. */
import {canonical,COORDINATION_DOMAIN,sha256,verify,type Signed} from './coordination-protocol.js';
import {REPOSITORY_HEX,REPOSITORY_ID,REPOSITORY_SHA,repositoryBranch,validRepositoryEnvelope} from './coordination-repository.js';
import {validRepositoryConnection,validRepositoryReadiness,type RepositoryConnection,type RepositoryReadiness} from './coordination-repository-collaboration.js';
import {verifyRepositoryPreviewDiscovery,type RepositoryPreviewDiscovery} from './coordination-repository-review.js';
import {codingCommand,codingSafePath} from './coordination-repository-coding.js';
import type {WorkspaceTaskAssignment} from './coordination-repository-workspace.js';

export const REPOSITORY_SETUP_ACTIONS=['repository_setup_info','repository_setup_create','repository_setup_get','repository_setup_oauth','repository_setup_enroll','repository_setup_confirm','repository_setup_ready','repository_setup_coding_ready','repository_setup_refresh','repository_setup_renew','repository_setup_revoke','repository_setup_dispatch','repository_setup_job_get','repository_setup_job_complete'] as const;
export type RepositorySetupAction=typeof REPOSITORY_SETUP_ACTIONS[number];
export const REPOSITORY_GUIDED_WORKFLOW='.github/workflows/scopeblind-connection.yml';
export const REPOSITORY_SETUP_TTL=30*60_000;
export const REPOSITORY_CODING_IMAGE='node@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752';
export interface RepositorySetupRequest {
 type:'scopeblind.repository.setup-request.v1';id:string;owner_key:string;authority_key:string;
 repository:string;pull_number:number;mode:'github_app'|'owner_local';
 secret_hash:string;state_hash:string;pkce_challenge:string;issued_at:string;expires_at:string;
}
export interface RepositorySetupInfo {
 type:'scopeblind.repository.setup-info.v1';authority_key:string;endpoint:string;observed_at:string;
 app:{available:boolean;slug:string|null;client_id:string|null;callback_url:string;install_url:string|null};
 receiver:{version:string;url:string;sha256:string|null};coding_image:string;
}
/** This is a service observation of authenticated GitHub API responses, not a GitHub signature. */
export interface RepositorySetupGitHub {
 type:'scopeblind.repository.setup-github.v1';setup_digest:string;app_id:number;installation_id:number;
 user_id:number;login:string;repository_id:number;repository:string;default_branch:string;
 permissions:{admin:boolean;push:boolean};repository_selection:'selected';observed_at:string;
}
/** Read-only preparation before a guest joins; no merge readiness or preview bytes are claimed. */
export interface RepositorySetupInspection {
 type:'scopeblind.repository.setup-inspection.v1';setup_digest:string;owner_key:string;receiver_key:string;
 repository:string;repository_id:number;pull_number:number;title:string;url:string;
 base_branch:string;head_branch:string;base_sha:string;head_sha:string;draft:boolean;mergeable:boolean|null;
 files:Array<{path:string;previous_path?:string;status:'added'|'modified'|'removed'|'renamed';additions:number;deletions:number;patch?:string;patch_truncated?:true}>;
 checks:Array<{id:number;name:string;app_id:number;head_sha:string;status:'queued'|'in_progress'|'completed';conclusion:string|null}>;
 preview:Signed<RepositoryPreviewDiscovery>|null;observed_at:string;expires_at:string;
}
export interface RepositorySetupInstallation {
 workflow_path:typeof REPOSITORY_GUIDED_WORKFLOW;workflow:string;workflow_sha256:string;
 receiver_url:string;receiver_sha256:string;
 secret_name:'SCOPEBLIND_GUIDED_RECEIVER_KEY';variable_name:'SCOPEBLIND_GUIDED_CONNECTION';
}
export interface RepositorySetupEnrollment {
 type:'scopeblind.repository.setup-enrollment.v1';setup_id:string;setup_digest:string;receiver_key:string;
 connection:RepositoryConnection;readiness:Signed<RepositoryReadiness>;inspection:Signed<RepositorySetupInspection>;
 installation:RepositorySetupInstallation;coding?:RepositorySetupCoding;replaces?:RepositoryGuidedReceiverConfig;issued_at:string;
}
export interface RepositoryCodingConnectionConfig {
 type:'scopeblind.repository.coding-config.v1';endpoint:string;authority_key:string;worker_key:string;repository:string;base_branch:string;
 runtime:'node22-static-v1';test_command:string[];build_command:string[];preview_directory:string;docker_image:string;
}
export interface RepositorySetupCoding {
 config:RepositoryCodingConnectionConfig;workflow:string;workflow_sha256:string;artifact_url:string;artifact_sha256:string;
}
export interface RepositorySetupCodingReady {
 type:'scopeblind.repository.setup-coding-ready.v1';setup_id:string;setup_digest:string;connection_digest:string;
 coding_digest:string;worker_key:string;challenge_id:string;run_id:number;run_attempt:number;workflow_ref:string;workflow_sha:string;observed_at:string;expires_at:string;
}
/** An explicit owner signature authorizes only these reviewed installation bytes and public pins. */
export interface RepositorySetupAuthorization {
 type:'scopeblind.repository.setup-authorization.v1';setup_id:string;setup_digest:string;enrollment_digest:string;
 connection_digest:string;owner_key:string;repository_id:number;workflow_path:typeof REPOSITORY_GUIDED_WORKFLOW;
 workflow_sha256:string;receiver_url:string;receiver_sha256:string;issued_at:string;expires_at:string;
}
export interface RepositorySetupRenewal {
 type:'scopeblind.repository.setup-renewal.v1';id:string;setup_id:string;authorization_digest:string;owner_key:string;issued_at:string;expires_at:string;
}
export interface RepositorySetupChallenge {id:string;audience:string;issued_at:string;expires_at:string}
export interface RepositorySetupReady {
 type:'scopeblind.repository.setup-ready.v1';setup_id:string;setup_digest:string;connection_digest:string;
 authorization_digest:string;challenge_id:string;receiver_key:string;readiness:Signed<RepositoryReadiness>;
 inspection:Signed<RepositorySetupInspection>|null;run_id:number;run_attempt:number;workflow_ref:string;workflow_sha:string;
 observed_at:string;
}
export interface RepositorySetupWorkflowProof {
 repository_id:number;run_id:number;run_attempt:number;workflow_ref:string;workflow_sha:string;
 token_digest:string;verified_at:string;
}
export type RepositorySetupStatus='awaiting_github'|'awaiting_receiver'|'awaiting_confirmation'|'awaiting_workflow'|'ready'|'expired'|'revoked'|'superseded'|'replacement_pending'|'installation_expired';
export interface RepositorySetupState {
 type:'scopeblind.repository.setup-state.v1';request:Signed<RepositorySetupRequest>;github:Signed<RepositorySetupGitHub>|null;
 enrollment:Signed<RepositorySetupEnrollment>|null;connection:Signed<RepositoryConnection>|null;
 authorization:Signed<RepositorySetupAuthorization>|null;installation_renewal?:Signed<RepositorySetupRenewal>|null;challenge:RepositorySetupChallenge|null;
 ready:Signed<RepositorySetupReady>|null;workflow_proof:RepositorySetupWorkflowProof|null;
 initial_ready?:{ready:Signed<RepositorySetupReady>;workflow_proof:RepositorySetupWorkflowProof}|null;
 coding_ready?:{ready:Signed<RepositorySetupCodingReady>;workflow_proof:RepositorySetupWorkflowProof}|null;
 superseded_by?:string|null;blocking_jobs?:boolean;status:RepositorySetupStatus;dispatch:'none'|'requested'|'unconfigured'|'unavailable';observed_at:string;
}
export interface RepositorySetupJob {
 type:'scopeblind.repository.setup-job.v1';id:string;setup_id:string;connection_digest:string;owner_key:string;
 receiver_key:string;requested_by:string;operation:'ready'|'inspect'|'execute'|'reconcile';task_id:string|null;
 challenge:RepositorySetupChallenge|null;issued_at:string;expires_at:string;
}
export interface RepositorySetupJobState {
 type:'scopeblind.repository.setup-job-state.v1';job:Signed<RepositorySetupJob>;
 status:'queued'|'running'|'completed'|'failed';run_id:number|null;error:string|null;observed_at:string;
}
export interface RepositorySetupTaskBinding {
 type:'scopeblind.repository.setup-task-binding.v1';task_id:string;task_digest:string;
 assignment:Signed<WorkspaceTaskAssignment>;active:boolean;observed_at:string;
}
export interface RepositoryGuidedReceiverConfig {
 type:'scopeblind.repository.guided-receiver-config.v1';endpoint:string;authority_key:string;
 connection:Signed<RepositoryConnection>;authorization:Signed<RepositorySetupAuthorization>;
}

const obj=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const shape=(v:unknown,keys:string[],optional:string[]=[]):v is Record<string,unknown>=>obj(v)&&keys.every(k=>k in v)&&Object.keys(v).every(k=>keys.includes(k)||optional.includes(k));
const hex=(v:unknown):v is string=>typeof v==='string'&&REPOSITORY_HEX.test(v);
const id=(v:unknown):v is string=>typeof v==='string'&&REPOSITORY_ID.test(v);
const sha=(v:unknown):v is string=>typeof v==='string'&&REPOSITORY_SHA.test(v);
const num=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>0;
const at=(v:unknown):v is string=>typeof v==='string'&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString()===v;
const text=(v:unknown,max:number):v is string=>typeof v==='string'&&v.trim().length>0&&v.length<=max&&!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v);
const line=(v:unknown,max:number):v is string=>text(v,max)&&!/[\r\n\t]/.test(v);
const repo=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(v)&&!v.split('/').some(x=>x==='.'||x==='..');
const span=(a:unknown,b:unknown,max:number)=>at(a)&&at(b)&&Date.parse(b)>Date.parse(a)&&Date.parse(b)-Date.parse(a)<=max;
export function repositorySetupArtifactUrl(v:unknown):v is string{return typeof v==='string'&&/^https:\/\/scopeblind\.com\/releases\/repository-receiver-[0-9]+\.[0-9]+\.[0-9]+\.cjs$/.test(v);}
export function validRepositorySetupRequest(v:unknown):v is RepositorySetupRequest {
 return shape(v,['type','id','owner_key','authority_key','repository','pull_number','mode','secret_hash','state_hash','pkce_challenge','issued_at','expires_at'])&&v.type==='scopeblind.repository.setup-request.v1'&&id(v.id)&&hex(v.owner_key)&&hex(v.authority_key)&&v.owner_key!==v.authority_key&&repo(v.repository)&&num(v.pull_number)&&['github_app','owner_local'].includes(String(v.mode))&&hex(v.secret_hash)&&hex(v.state_hash)&&typeof v.pkce_challenge==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v.pkce_challenge)&&span(v.issued_at,v.expires_at,REPOSITORY_SETUP_TTL);
}
export function validRepositorySetupInspection(v:unknown,request:Signed<RepositorySetupRequest>,receiverKey:string):v is RepositorySetupInspection {
 if(!shape(v,['type','setup_digest','owner_key','receiver_key','repository','repository_id','pull_number','title','url','base_branch','head_branch','base_sha','head_sha','draft','mergeable','files','checks','preview','observed_at','expires_at'])||v.type!=='scopeblind.repository.setup-inspection.v1'||v.setup_digest!==request.digest||v.owner_key!==request.payload.owner_key||v.receiver_key!==receiverKey||v.repository!==request.payload.repository||!num(v.repository_id)||v.pull_number!==request.payload.pull_number||!line(v.title,300)||v.url!==`https://github.com/${v.repository}/pull/${v.pull_number}`||!repositoryBranch(String(v.base_branch))||!repositoryBranch(String(v.head_branch))||!sha(v.base_sha)||!sha(v.head_sha)||typeof v.draft!=='boolean'||v.mergeable!==null&&typeof v.mergeable!=='boolean'||!span(v.observed_at,v.expires_at,86400000))return false;
 if(!Array.isArray(v.files)||v.files.length>50||!v.files.every(f=>shape(f,['path','status','additions','deletions'],['previous_path','patch','patch_truncated'])&&line(f.path,500)&&['added','modified','removed','renamed'].includes(String(f.status))&&Number.isSafeInteger(f.additions)&&Number(f.additions)>=0&&Number.isSafeInteger(f.deletions)&&Number(f.deletions)>=0&&(f.previous_path===undefined||line(f.previous_path,500))&&((f.status==='renamed')===(f.previous_path!==undefined))&&(f.patch===undefined||typeof f.patch==='string'&&f.patch.length<=4000)&& (f.patch_truncated===undefined||f.patch_truncated===true&&typeof f.patch==='string'))||new Set(v.files.map(f=>f.path)).size!==v.files.length)return false;
 return Array.isArray(v.checks)&&v.checks.length<=100&&v.checks.every(c=>shape(c,['id','name','app_id','head_sha','status','conclusion'])&&num(c.id)&&line(c.name,100)&&num(c.app_id)&&c.head_sha===v.head_sha&&['queued','in_progress','completed'].includes(String(c.status))&&(c.conclusion===null||line(c.conclusion,100)))&&new Set(v.checks.map(c=>c.id)).size===v.checks.length&&(v.preview===null||validRepositoryEnvelope(v.preview));
}
export function validRepositorySetupAuthorization(v:unknown):v is RepositorySetupAuthorization {
 return shape(v,['type','setup_id','setup_digest','enrollment_digest','connection_digest','owner_key','repository_id','workflow_path','workflow_sha256','receiver_url','receiver_sha256','issued_at','expires_at'])&&v.type==='scopeblind.repository.setup-authorization.v1'&&id(v.setup_id)&&[v.setup_digest,v.enrollment_digest,v.connection_digest,v.owner_key,v.workflow_sha256,v.receiver_sha256].every(hex)&&num(v.repository_id)&&v.workflow_path===REPOSITORY_GUIDED_WORKFLOW&&repositorySetupArtifactUrl(v.receiver_url)&&span(v.issued_at,v.expires_at,REPOSITORY_SETUP_TTL);
}
export function validRepositorySetupRenewal(v:unknown):v is RepositorySetupRenewal {
 return shape(v,['type','id','setup_id','authorization_digest','owner_key','issued_at','expires_at'])&&v.type==='scopeblind.repository.setup-renewal.v1'&&id(v.id)&&id(v.setup_id)&&hex(v.authorization_digest)&&hex(v.owner_key)&&span(v.issued_at,v.expires_at,REPOSITORY_SETUP_TTL);
}
export function validRepositoryCodingConnectionConfig(v:unknown):v is RepositoryCodingConnectionConfig {
 if(!obj(v)||typeof v.endpoint!=='string')return false;let endpoint:URL;try{endpoint=new URL(v.endpoint);}catch{return false;}if(endpoint.protocol!=='https:'||endpoint.pathname!=='/api/coordination'||endpoint.search||endpoint.hash||endpoint.username||endpoint.password||endpoint.href!==v.endpoint)return false;
 return shape(v,['type','endpoint','authority_key','worker_key','repository','base_branch','runtime','test_command','build_command','preview_directory','docker_image'])&&v.type==='scopeblind.repository.coding-config.v1'&&typeof v.endpoint==='string'&&/^https:\/\/[^/?#]+\/api\/coordination$/.test(v.endpoint)&&hex(v.authority_key)&&hex(v.worker_key)&&repo(v.repository)&&repositoryBranch(String(v.base_branch))&&v.runtime==='node22-static-v1'&&codingCommand(v.test_command)&&codingCommand(v.build_command)&&codingSafePath(v.preview_directory)&&typeof v.docker_image==='string'&&/^node@sha256:[a-f0-9]{64}$/.test(v.docker_image);
}
export async function verifyRepositorySetupEnrollment(value:unknown,request:Signed<RepositorySetupRequest>,expectedEndpoint='https://scopeblind.com/api/coordination'):Promise<boolean>{
 try{if(!validRepositoryEnvelope(value))return false;const e=value as Signed<RepositorySetupEnrollment>,v=e.payload,c=v.connection;
  if(!shape(v,['type','setup_id','setup_digest','receiver_key','connection','readiness','inspection','installation','issued_at'],['coding','replaces'])||v.type!=='scopeblind.repository.setup-enrollment.v1'||v.setup_id!==request.payload.id||v.setup_digest!==request.digest||!hex(v.receiver_key)||[request.payload.owner_key,request.payload.authority_key].includes(v.receiver_key)||!at(v.issued_at)||!validRepositoryConnection(c)||c.id!==request.payload.id||c.owner_key!==request.payload.owner_key||c.authority_key!==request.payload.authority_key||c.receiver_key!==v.receiver_key||c.repository!==request.payload.repository||c.endpoint!==expectedEndpoint)return false;
  const i=v.installation;if(!shape(i,['workflow_path','workflow','workflow_sha256','receiver_url','receiver_sha256','secret_name','variable_name'])||i.workflow_path!==REPOSITORY_GUIDED_WORKFLOW||!text(i.workflow,30000)||!hex(i.workflow_sha256)||await sha256(i.workflow)!==i.workflow_sha256||!repositorySetupArtifactUrl(i.receiver_url)||!hex(i.receiver_sha256)||i.secret_name!=='SCOPEBLIND_GUIDED_RECEIVER_KEY'||i.variable_name!=='SCOPEBLIND_GUIDED_CONNECTION')return false;
  if(!validRepositoryEnvelope(v.readiness)||!validRepositoryReadiness(v.readiness.payload)||v.readiness.payload.runtime!=='local'||v.readiness.payload.connection_digest!==await sha256(COORDINATION_DOMAIN+canonical(c))||!validRepositoryEnvelope(v.inspection)||!validRepositorySetupInspection(v.inspection.payload,request,v.receiver_key))return false;
  const r=v.readiness.payload,s=v.inspection.payload;if(Date.parse(v.issued_at)<Date.parse(request.payload.issued_at)-1000||Date.parse(v.issued_at)>Date.parse(request.payload.expires_at)||Date.parse(c.issued_at)<Date.parse(request.payload.issued_at)-1000||[r.observed_at,s.observed_at].some(t=>Date.parse(t)>Date.parse(v.issued_at)+1000||Date.parse(v.issued_at)-Date.parse(t)>300000)||Date.parse(r.expires_at)>Date.parse(c.expires_at)||['repository','base_branch','owner_key','receiver_key','authority_key'].some(k=>r[k as keyof RepositoryReadiness]!==c[k as keyof RepositoryConnection])||s.base_branch!==c.base_branch||r.base_sha!==s.base_sha||r.check_head_sha!==s.head_sha)return false;
  if(s.preview&&(s.preview.payload.head_sha!==s.head_sha||!await verifyRepositoryPreviewDiscovery(s.preview,{owner_key:c.owner_key,receiver_key:c.receiver_key,authority_key:c.authority_key,repository:c.repository,pull_number:request.payload.pull_number},Date.parse(s.observed_at))))return false;
  if(v.coding){const k=v.coding;if(!shape(k,['config','workflow','workflow_sha256','artifact_url','artifact_sha256'])||!validRepositoryCodingConnectionConfig(k.config)||k.config.endpoint!==c.endpoint||k.config.repository!==c.repository||k.config.base_branch!==c.base_branch||k.config.authority_key!==c.authority_key||[c.owner_key,c.receiver_key,c.authority_key].includes(k.config.worker_key)||!text(k.workflow,30000)||!hex(k.workflow_sha256)||await sha256(k.workflow)!==k.workflow_sha256||!/^https:\/\/scopeblind\.com\/releases\/repository-coding-[0-9]+\.[0-9]+\.[0-9]+\.cjs$/.test(k.artifact_url)||!hex(k.artifact_sha256))return false;}
  if(v.replaces&&!await verifyRepositorySetupReplacement(v.replaces,c))return false;
  return await verify(e,v.receiver_key)&&await verify(v.readiness,v.receiver_key)&&await verify(v.inspection,v.receiver_key);
 }catch{return false;}
}
export async function verifyRepositorySetupReplacement(value:unknown,next:RepositoryConnection):Promise<boolean>{
 try{if(!shape(value,['type','endpoint','authority_key','connection','authorization'])||value.type!=='scopeblind.repository.guided-receiver-config.v1'||!validRepositoryEnvelope(value.connection)||!validRepositoryEnvelope(value.authorization))return false;const c=value.connection as Signed<RepositoryConnection>,a=value.authorization as Signed<RepositorySetupAuthorization>;
 return validRepositoryConnection(c.payload)&&validRepositorySetupAuthorization(a.payload)&&value.endpoint===next.endpoint&&value.authority_key===next.authority_key&&c.payload.id!==next.id&&['endpoint','repository','base_branch','owner_key','receiver_key','authority_key'].every(k=>c.payload[k as keyof RepositoryConnection]===next[k as keyof RepositoryConnection])&&a.payload.connection_digest===c.digest&&a.payload.setup_id===c.payload.id&&a.payload.owner_key===next.owner_key&&await verify(c,next.owner_key)&&await verify(a,next.owner_key);
 }catch{return false;}
}
function validWorkflowProof(proof:unknown,ready:{run_id:number;run_attempt:number;workflow_ref:string;workflow_sha:string;observed_at:string},repositoryId:number,workflowRef:string,observedAt:string):proof is RepositorySetupWorkflowProof {
 return shape(proof,['repository_id','run_id','run_attempt','workflow_ref','workflow_sha','token_digest','verified_at'])&&proof.repository_id===repositoryId&&num(proof.run_id)&&num(proof.run_attempt)&&proof.run_id===ready.run_id&&proof.run_attempt===ready.run_attempt&&proof.workflow_ref===workflowRef&&ready.workflow_ref===workflowRef&&sha(proof.workflow_sha)&&proof.workflow_sha===ready.workflow_sha&&hex(proof.token_digest)&&at(proof.verified_at)&&at(ready.observed_at)&&Date.parse(proof.verified_at)>=Date.parse(ready.observed_at)-1000&&Date.parse(proof.verified_at)-Date.parse(ready.observed_at)<=300000&&Date.parse(proof.verified_at)<=Date.parse(observedAt)+1000;
}
export async function verifyRepositorySetupState(value:unknown,authorityKey:string,ownerKey?:string,expectedEndpoint='https://scopeblind.com/api/coordination'):Promise<boolean>{
 try{
  if(!validRepositoryEnvelope(value))return false;
  const signed=value as Signed<RepositorySetupState>;if(!await verify(signed,authorityKey))return false;
  const s=signed.payload,r=s.request;
  if(!shape(s,['type','request','github','enrollment','connection','authorization','challenge','ready','workflow_proof','status','dispatch','observed_at'],['coding_ready','superseded_by','blocking_jobs','initial_ready','installation_renewal'])||s.type!=='scopeblind.repository.setup-state.v1'||!validRepositoryEnvelope(r)||!validRepositorySetupRequest(r.payload)||r.payload.authority_key!==authorityKey||ownerKey&&r.payload.owner_key!==ownerKey||!await verify(r,r.payload.owner_key)||!at(s.observed_at)||Date.parse(s.observed_at)<Date.parse(r.payload.issued_at)-1000||!['awaiting_github','awaiting_receiver','awaiting_confirmation','awaiting_workflow','ready','expired','revoked','superseded','replacement_pending','installation_expired'].includes(s.status)||!['none','requested','unconfigured','unavailable'].includes(s.dispatch))return false;
  if(s.blocking_jobs!==undefined&&typeof s.blocking_jobs!=='boolean'||s.superseded_by!==undefined&&s.superseded_by!==null&&(!id(s.superseded_by)||s.superseded_by===r.payload.id))return false;
  const observed=Date.parse(s.observed_at);
  if(s.github){
   const g=s.github.payload;
   if(!validRepositoryEnvelope(s.github)||!await verify(s.github,authorityKey)||!shape(g,['type','setup_digest','app_id','installation_id','user_id','login','repository_id','repository','default_branch','permissions','repository_selection','observed_at'])||g.type!=='scopeblind.repository.setup-github.v1'||g.setup_digest!==r.digest||g.repository!==r.payload.repository||g.repository_selection!=='selected'||![g.app_id,g.installation_id,g.user_id,g.repository_id].every(num)||!line(g.login,100)||!repositoryBranch(g.default_branch)||!shape(g.permissions,['admin','push'])||typeof g.permissions.admin!=='boolean'||g.permissions.push!==true||!at(g.observed_at)||Date.parse(g.observed_at)>observed+1000||Date.parse(g.observed_at)<Date.parse(r.payload.issued_at)-1000)return false;
  }
  if(s.enrollment){
   if(!await verifyRepositorySetupEnrollment(s.enrollment,r,expectedEndpoint)||Date.parse(s.enrollment.payload.issued_at)>observed+1000)return false;
   if(r.payload.mode==='github_app'&&(!s.github||s.github.payload.repository_id!==s.enrollment.payload.inspection.payload.repository_id||s.github.payload.default_branch!==s.enrollment.payload.connection.base_branch))return false;
  }
  if(!!s.connection!==!!s.authorization)return false;
  if(s.connection&&(!s.enrollment||!validRepositoryEnvelope(s.connection)||!await verify(s.connection,r.payload.owner_key)||canonical(s.connection.payload)!==canonical(s.enrollment.payload.connection)))return false;
  if(s.authorization){
   const a=s.authorization;
   if(!s.connection||!s.enrollment||!validRepositoryEnvelope(a)||!validRepositorySetupAuthorization(a.payload)||!await verify(a,r.payload.owner_key)||a.payload.setup_id!==r.payload.id||a.payload.setup_digest!==r.digest||a.payload.enrollment_digest!==s.enrollment.digest||a.payload.connection_digest!==s.connection.digest||a.payload.owner_key!==r.payload.owner_key||a.payload.repository_id!==s.enrollment.payload.inspection.payload.repository_id||a.payload.workflow_sha256!==s.enrollment.payload.installation.workflow_sha256||a.payload.receiver_url!==s.enrollment.payload.installation.receiver_url||a.payload.receiver_sha256!==s.enrollment.payload.installation.receiver_sha256||Date.parse(a.payload.issued_at)<Date.parse(s.enrollment.payload.issued_at)-1000||Date.parse(a.payload.issued_at)>observed+1000||Date.parse(a.payload.expires_at)>Date.parse(r.payload.expires_at))return false;
  }
  if(s.installation_renewal){const renewal=s.installation_renewal;if(!s.authorization||!s.connection||!validRepositoryEnvelope(renewal)||!validRepositorySetupRenewal(renewal.payload)||renewal.payload.setup_id!==r.payload.id||renewal.payload.authorization_digest!==s.authorization.digest||renewal.payload.owner_key!==r.payload.owner_key||!await verify(renewal,r.payload.owner_key)||Date.parse(renewal.payload.issued_at)<Date.parse(s.authorization.payload.issued_at)||Date.parse(renewal.payload.issued_at)>observed+1000||Date.parse(renewal.payload.expires_at)>Date.parse(s.connection.payload.expires_at))return false;}
  if(s.challenge&&(!s.authorization||!shape(s.challenge,['id','audience','issued_at','expires_at'])||!id(s.challenge.id)||!span(s.challenge.issued_at,s.challenge.expires_at,600000)||Date.parse(s.challenge.issued_at)>observed+1000||!s.challenge.audience.startsWith(`https://scopeblind.com/repository-setup/${r.payload.id}/`)||!id(s.challenge.audience.slice(s.challenge.audience.lastIndexOf('/')+1))))return false;
  if(!!s.ready!==!!s.workflow_proof)return false;
  if(s.initial_ready&&(!shape(s.initial_ready,['ready','workflow_proof'])||!validRepositoryEnvelope(s.initial_ready.ready)||!s.initial_ready.ready.payload.inspection))return false;
  const readinessRecords=[...(s.initial_ready?[s.initial_ready]:[]),...(s.ready?[{ready:s.ready,workflow_proof:s.workflow_proof}]:[])];
  for(const record of readinessRecords){
   const q=record.ready,p=q.payload,c=s.connection?.payload;
   if(!s.authorization||!s.connection||!s.enrollment||!c||!validRepositoryEnvelope(q)||!shape(p,['type','setup_id','setup_digest','connection_digest','authorization_digest','challenge_id','receiver_key','readiness','inspection','run_id','run_attempt','workflow_ref','workflow_sha','observed_at'])||p.type!=='scopeblind.repository.setup-ready.v1'||!await verify(q,c.receiver_key)||p.setup_id!==r.payload.id||p.setup_digest!==r.digest||p.connection_digest!==s.connection.digest||p.authorization_digest!==s.authorization.digest||p.receiver_key!==c.receiver_key||!id(p.challenge_id)||!validWorkflowProof(record.workflow_proof,p,s.enrollment.payload.inspection.payload.repository_id,`${c.repository}/${REPOSITORY_GUIDED_WORKFLOW}@refs/heads/${c.base_branch}`,s.observed_at)||!validRepositoryEnvelope(p.readiness)||!validRepositoryReadiness(p.readiness.payload)||p.readiness.payload.runtime!=='github_actions'||p.readiness.payload.workflow!=='matching'||p.readiness.payload.connection_digest!==s.connection.digest||!await verify(p.readiness,c.receiver_key))return false;
   const ready=p.readiness.payload;if(p.inspection===null&&(!s.initial_ready||Date.parse(p.observed_at)<Date.parse(s.initial_ready.ready.payload.observed_at)))return false;if(p.inspection!==null&&(!validRepositoryEnvelope(p.inspection)||!validRepositorySetupInspection(p.inspection.payload,r,c.receiver_key)||!await verify(p.inspection,c.receiver_key)))return false;const i=p.inspection?.payload;
   if(['repository','base_branch','owner_key','receiver_key','authority_key'].some(k=>ready[k as keyof RepositoryReadiness]!==c[k as keyof RepositoryConnection])||i&&(i.repository_id!==s.enrollment.payload.inspection.payload.repository_id||i.base_branch!==c.base_branch||ready.base_sha!==i.base_sha||ready.check_head_sha!==i.head_sha)||Date.parse(ready.expires_at)>Date.parse(c.expires_at)||Date.parse(p.observed_at)<Date.parse(s.authorization.payload.issued_at)-1000||[ready.observed_at,...(i?[i.observed_at]:[])].some(t=>Date.parse(t)>Date.parse(p.observed_at)+1000||Date.parse(p.observed_at)-Date.parse(t)>300000))return false;
   if(i?.preview&&(i.preview.payload.head_sha!==i.head_sha||!await verifyRepositoryPreviewDiscovery(i.preview,{owner_key:c.owner_key,receiver_key:c.receiver_key,authority_key:c.authority_key,repository:c.repository,pull_number:r.payload.pull_number},Date.parse(i.observed_at))))return false;
  }
  if(s.coding_ready){
   const bundle=s.coding_ready,q=bundle.ready,p=q?.payload,c=s.connection?.payload,k=s.enrollment?.payload.coding;
   if(!shape(bundle,['ready','workflow_proof'])||!c||!k||!s.authorization||!validRepositoryEnvelope(q)||!shape(p,['type','setup_id','setup_digest','connection_digest','coding_digest','worker_key','challenge_id','run_id','run_attempt','workflow_ref','workflow_sha','observed_at','expires_at'])||p.type!=='scopeblind.repository.setup-coding-ready.v1'||p.setup_id!==r.payload.id||p.setup_digest!==r.digest||p.connection_digest!==s.connection!.digest||p.coding_digest!==await sha256(canonical(k.config))||p.worker_key!==k.config.worker_key||!id(p.challenge_id)||!span(p.observed_at,p.expires_at,86400000)||Date.parse(p.expires_at)>Date.parse(c.expires_at)||Date.parse(p.observed_at)<Date.parse(s.authorization.payload.issued_at)-1000||!await verify(q,k.config.worker_key)||!validWorkflowProof(bundle.workflow_proof,p,s.enrollment!.payload.inspection.payload.repository_id,`${c.repository}/.github/workflows/scopeblind-coding.yml@refs/heads/${c.base_branch}`,s.observed_at))return false;
  }
  if(s.status==='revoked')return true;
  if(s.status==='superseded'||s.status==='replacement_pending')return !!s.superseded_by;
  if(s.superseded_by)return false;
  const expired=Date.parse(s.connection?.payload.expires_at??r.payload.expires_at)<=observed;
  const expected:RepositorySetupStatus=expired?'expired':s.ready&&Date.parse(s.ready.payload.readiness.payload.expires_at)>observed?'ready':r.payload.mode==='github_app'&&!s.github?'awaiting_github':!s.enrollment?'awaiting_receiver':!s.authorization?'awaiting_confirmation':!s.initial_ready&&!s.ready&&Date.parse(s.installation_renewal?.payload.expires_at??s.authorization.payload.expires_at)<=observed?'installation_expired':'awaiting_workflow';
  return s.status===expected;
 }catch{return false;}
}
