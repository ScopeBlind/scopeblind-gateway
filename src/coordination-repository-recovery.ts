/** Dated service observations for recovery. These never authorize work or replace receiver evidence. */
import {verify,type Signed} from './coordination-protocol.js';
import {REPOSITORY_HEX,REPOSITORY_ID,REPOSITORY_SHA,validRepositoryEnvelope} from './coordination-repository.js';

export const REPOSITORY_RECOVERY_CODES = [
 'github_connection_required','local_dispatch','connection_expired','connection_revoked','connection_replaced',
 'installation_pending','installation_expired','receiver_readiness_expired','coding_readiness_pending','coding_readiness_expired',
 'workflow_response_pending','workflow_approval_required','workflow_waiting','workflow_running','workflow_failed',
 'workflow_completed_without_response','provider_unavailable','provider_observation_incomplete',
 'pull_draft','pull_closed','pull_conflict','pull_mergeability_pending','pull_metadata_stale','base_changed','head_changed',
 'required_check_missing','required_check_pending','required_check_failed','inspection_needed','job_expired',
] as const;
export type RepositoryRecoveryCode=typeof REPOSITORY_RECOVERY_CODES[number];
export interface RepositoryRecoveryIssue {
 code:RepositoryRecoveryCode;actor:'owner'|'github_reviewer'|'worker';check_name?:string;app_id?:number;
}
export interface RepositoryRecoveryObservation {
 type:'scopeblind.repository.recovery-observation.v1';setup_id:string;setup_digest:string;owner_key:string;
 task_id:string|null;task_digest:string|null;job_id:string|null;repository:string;pull_number:number;
 observed_at:string;expires_at:string;issues:RepositoryRecoveryIssue[];
 pull:{state:'open'|'closed';draft:boolean;base_sha:string;head_sha:string;mergeable:boolean|null}|null;
 expected:{base_sha:string|null;head_sha:string|null};
 workflow:{run_id:number;status:string;conclusion:string|null;url:string}|null;
 checks:Array<{name:string;app_id:number|null;state:'missing'|'pending'|'failed'|'passed';run_id:number|null}>;
}
const obj=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const shape=(v:unknown,keys:string[],optional:string[]=[])=>obj(v)&&keys.every(k=>k in v)&&Object.keys(v).every(k=>keys.includes(k)||optional.includes(k));
const id=(v:unknown)=>typeof v==='string'&&REPOSITORY_ID.test(v);
const hex=(v:unknown)=>typeof v==='string'&&REPOSITORY_HEX.test(v);
const sha=(v:unknown)=>typeof v==='string'&&REPOSITORY_SHA.test(v);
const integer=(v:unknown)=>Number.isSafeInteger(v)&&Number(v)>0;
const text=(v:unknown,max=100)=>typeof v==='string'&&v.length>0&&v.length<=max&&!/[\u0000-\u001f\u007f]/.test(v);
const time=(v:unknown)=>typeof v==='string'&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString()===v;
export function validRepositoryRecoveryObservation(v:unknown):v is RepositoryRecoveryObservation {
 if(!shape(v,['type','setup_id','setup_digest','owner_key','task_id','task_digest','job_id','repository','pull_number','observed_at','expires_at','issues','pull','expected','workflow','checks']))return false;
 const p=v as unknown as RepositoryRecoveryObservation;
 if(p.type!=='scopeblind.repository.recovery-observation.v1'||!id(p.setup_id)||!hex(p.setup_digest)||!hex(p.owner_key)||p.task_id!==null&&!id(p.task_id)||p.task_digest!==null&&!hex(p.task_digest)||(p.task_id===null)!==(p.task_digest===null)||p.job_id!==null&&!id(p.job_id)||typeof p.repository!=='string'||!(/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/).test(p.repository)||p.repository.split('/').some(x=>x==='.'||x==='..')||!integer(p.pull_number)||!time(p.observed_at)||!time(p.expires_at)||Date.parse(p.expires_at)-Date.parse(p.observed_at)!==120000)return false;
 if(!shape(p.expected,['base_sha','head_sha'])||[p.expected.base_sha,p.expected.head_sha].some(s=>s!==null&&!sha(s)))return false;
 if(p.pull&&(!shape(p.pull,['state','draft','base_sha','head_sha','mergeable'])||!['open','closed'].includes(p.pull.state)||typeof p.pull.draft!=='boolean'||!sha(p.pull.base_sha)||!sha(p.pull.head_sha)||p.pull.mergeable!==null&&typeof p.pull.mergeable!=='boolean'))return false;
 if(p.workflow&&(!shape(p.workflow,['run_id','status','conclusion','url'])||!integer(p.workflow.run_id)||!text(p.workflow.status,40)||p.workflow.conclusion!==null&&!text(p.workflow.conclusion,40)||p.workflow.url!==`https://github.com/${p.repository}/actions/runs/${p.workflow.run_id}`))return false;
 if(!Array.isArray(p.issues)||p.issues.length>70||!p.issues.every(i=>shape(i,['code','actor'],['check_name','app_id'])&&REPOSITORY_RECOVERY_CODES.includes(i.code)&&['owner','github_reviewer','worker'].includes(i.actor)&&(i.check_name===undefined||text(i.check_name))&&(i.app_id===undefined||integer(i.app_id))))return false;
 return Array.isArray(p.checks)&&p.checks.length<=50&&p.checks.every(c=>shape(c,['name','app_id','state','run_id'])&&text(c.name)&&(c.app_id===null||integer(c.app_id))&&['missing','pending','failed','passed'].includes(c.state)&&(c.run_id===null||integer(c.run_id)));
}
export async function verifyRepositoryRecoveryObservation(value:unknown,authorityKey:string,scope:{setupId:string;ownerKey:string;taskId?:string|null;jobId?:string|null},now=Date.now()):Promise<boolean>{
 try{if(!validRepositoryEnvelope(value))return false;const s=value as Signed<RepositoryRecoveryObservation>;if(!validRepositoryRecoveryObservation(s.payload))return false;const p=s.payload;
 return p.setup_id===scope.setupId&&p.owner_key===scope.ownerKey&&p.task_id===(scope.taskId??null)&&(scope.jobId===undefined||p.job_id===scope.jobId)&&Date.parse(p.observed_at)<=now+1000&&Date.parse(p.expires_at)>now&&await verify(s,authorityKey);
 }catch{return false;}
}
