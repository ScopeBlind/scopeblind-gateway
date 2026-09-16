import type {Signed} from './coordination-protocol.js';
import type {RepositoryProposal} from './coordination-repository.js';
import {safeRepositoryPreviewUrl,type RepositoryReviewBrief,type RepositoryReviewPreview} from './coordination-repository-review.js';
type GitHubGet=(path:string)=>Promise<{body:unknown}>;
const positive=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>0;
const timestamp=(v:unknown):v is string=>typeof v==='string'&&Number.isFinite(Date.parse(v));
const unavailable=():RepositoryReviewPreview=>({status:'unavailable',reason:'GitHub did not provide a complete, verifiable preview observation. No preview URL was inferred.'});
/** GET-only discovery. No preview URL is fetched; no PR code is checked out or executed. */
export async function observeRepositoryReviewPreview(get:GitHubGet,repository:string,brief:Signed<RepositoryReviewBrief>,proposal:Signed<RepositoryProposal>,now=Date.now()):Promise<RepositoryReviewPreview>{
 const policy=brief.payload.preview_policy;if(!policy)return {status:'not_requested',reason:'This brief does not require or identify a deployment preview.'};
 const repo=`/repos/${repository.split('/').map(encodeURIComponent).join('/')}`,head=proposal.payload.head_sha;
 try{
  const deployments=(await get(`${repo}/deployments?sha=${head}&environment=${encodeURIComponent(policy.environment)}&per_page=100`)).body as any;
  if(!Array.isArray(deployments)||deployments.length>=100)return unavailable();
  if(!deployments.length)return {status:'missing',reason:'GitHub has no deployment for the exact proposed head and selected environment.'};
  if(!deployments.every(d=>positive(d.id)&&d.sha===head&&d.environment===policy.environment&&timestamp(d.created_at)&&positive(d.creator?.id)&&Date.parse(d.created_at)<=now))return unavailable();
  const sorted=[...deployments].sort((a,b)=>Date.parse(b.created_at)-Date.parse(a.created_at)||b.id-a.id),deployment=sorted[0];
  if(new Set(sorted.map(d=>d.id)).size!==sorted.length)return unavailable();
  const statuses=(await get(`${repo}/deployments/${deployment.id}/statuses?per_page=100`)).body as any;
  if(!Array.isArray(statuses)||statuses.length>=100)return unavailable();
  if(!statuses.length)return {status:'pending',reason:'The newest matching deployment has not reported a status.'};
  if(!statuses.every(s=>positive(s.id)&&timestamp(s.created_at)&&timestamp(s.updated_at)&&Date.parse(s.updated_at)>=Date.parse(s.created_at)&&Date.parse(s.updated_at)<=now&&positive(s.creator?.id)))return unavailable();
  const status=[...statuses].sort((a,b)=>Date.parse(b.created_at)-Date.parse(a.created_at)||b.id-a.id)[0];
  if(['pending','queued','in_progress'].includes(status.state))return {status:'pending',reason:'The newest matching deployment is still in progress.'};
  if(['failure','error','inactive'].includes(status.state))return {status:'failed',reason:'The newest matching deployment is not a successful active preview.'};
  if(status.state!=='success'||status.environment!==policy.environment||!safeRepositoryPreviewUrl(status.environment_url)||!policy.allowed_origins.includes(new URL(status.environment_url).origin))return unavailable();
  const body=(await get(`${repo}/commits/${head}/check-runs?per_page=100&filter=latest`)).body as any;
  if(!body||!Number.isSafeInteger(body.total_count)||body.total_count<0||body.total_count>100||!Array.isArray(body.check_runs)||body.check_runs.length!==body.total_count)return unavailable();
  const matching=body.check_runs.filter((c:any)=>c.name===policy.check.name&&c.app?.id===policy.check.app_id);
  if(!matching.length)return {status:'unavailable',reason:'The named check from the pinned GitHub App was not observed at this head.'};
  if(!matching.every((c:any)=>positive(c.id)&&c.head_sha===head))return unavailable();
  const check=matching.sort((a:any,b:any)=>b.id-a.id)[0];
  if(check.status!=='completed')return {status:'pending',reason:'The pinned preview check has not completed at the proposed head.'};
  if(check.conclusion!=='success')return {status:'failed',reason:'The pinned preview check did not succeed at the proposed head.'};
  return {status:'available',deployment:{deployment_id:deployment.id,status_id:status.id,sha:head,environment:policy.environment,state:'success',environment_url:status.environment_url,deployment_creator_id:deployment.creator.id,status_creator_id:status.creator.id,created_at:new Date(deployment.created_at).toISOString(),updated_at:new Date(status.updated_at).toISOString(),check:{id:check.id,name:policy.check.name,app_id:policy.check.app_id,head_sha:head,conclusion:'success'}}};
 }catch{return unavailable();}
}

/** Bounded owner-local menu of observations. No relationship between a check provider and URL publisher is inferred. */
export async function discoverRepositoryPreviewChoices(get:GitHubGet,repository:string,head:string,now=Date.now()):Promise<Pick<import('./coordination-repository-review.js').RepositoryPreviewDiscovery,'candidates'|'checks'|'status'>>{
 const repo=`/repos/${repository.split('/').map(encodeURIComponent).join('/')}`;
 try{
  const [deployments,runs]=await Promise.all([get(`${repo}/deployments?sha=${head}&per_page=100`).then(r=>r.body as any),get(`${repo}/commits/${head}/check-runs?per_page=100&filter=latest`).then(r=>r.body as any)]);
  if(!Array.isArray(deployments)||deployments.length>=100||!runs||!Number.isSafeInteger(runs.total_count)||runs.total_count>100||!Array.isArray(runs.check_runs)||runs.check_runs.length!==runs.total_count)throw Error();
  const selected=new Map<string,any>();for(const d of deployments){if(!positive(d.id)||d.sha!==head||typeof d.environment!=='string'||!d.environment.trim()||d.environment.length>100||/[\u0000-\u001f\u007f]/.test(d.environment)||!timestamp(d.created_at)||Date.parse(d.created_at)>now)throw Error();const prior=selected.get(d.environment);if(!prior||Date.parse(d.created_at)>Date.parse(prior.created_at)||d.created_at===prior.created_at&&d.id>prior.id)selected.set(d.environment,d);}
  if(selected.size>20)throw Error();
  const candidates:import('./coordination-repository-review.js').RepositoryPreviewDiscovery['candidates']=[];
  for(const d of selected.values()){const rows=(await get(`${repo}/deployments/${d.id}/statuses?per_page=100`)).body as any;if(!Array.isArray(rows)||rows.length>=100)throw Error();if(!rows.length)continue;const sorted=[...rows].sort((a,b)=>Date.parse(b.created_at)-Date.parse(a.created_at)||b.id-a.id),s=sorted[0];if(!positive(s.id)||!timestamp(s.created_at)||!timestamp(s.updated_at)||Date.parse(s.updated_at)>now)throw Error();if(s.state==='success'&&s.environment===d.environment&&safeRepositoryPreviewUrl(s.environment_url))candidates.push({environment:d.environment,origin:new URL(s.environment_url).origin,environment_url:s.environment_url,deployment_id:d.id,status_id:s.id});}
  const checks:import('./coordination-repository-review.js').RepositoryPreviewDiscovery['checks']=[];
  for(const c of runs.check_runs){if(c.status!=='completed'||c.conclusion!=='success')continue;if(c.head_sha!==head||!positive(c.id)||!positive(c.app?.id)||typeof c.name!=='string'||!c.name.trim()||c.name.length>100||/[\u0000-\u001f\u007f]/.test(c.name))throw Error();const i=checks.findIndex(x=>x.name===c.name&&x.app_id===c.app.id);const item={id:c.id,name:c.name,app_id:c.app.id};if(i<0)checks.push(item);else if(c.id>checks[i].id)checks[i]=item;}
  return {status:'observed',candidates,checks};
 }catch{return {status:'unavailable',candidates:[],checks:[]};}
}
