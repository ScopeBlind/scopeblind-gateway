import {afterEach,describe,it,expect,vi} from 'vitest';
import {createHash} from 'node:crypto';
import {RepositoryDemoRunner} from './repository-demo-runner.js';
import {RepositoryReceiver} from './repository-receiver.js';
import {canonical,generateIdentity,sign,verify,type Signed} from './coordination-protocol.js';
import {verifyRepositoryEvidence,type RepositoryTask,type RepositoryState,type RepositoryClaim,type RepositoryProposal,type RepositoryApproval,type RepositoryExecution} from './coordination-repository.js';
import {DEMO_REPOSITORY,DEMO_CHECK,DEFAULT_CONTACT_PAGE,contactPageBytes,type RepositoryDemoRequest,type RepositoryDemoJob,type RepositoryDemoCompletion,type RepositoryDemoProvision,type RepositoryParticipants} from './coordination-repository-collaboration.js';
afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();});
const taskId='demo-request-001',template='1'.repeat(40),change='2'.repeat(40),tree='3'.repeat(40),merge='4'.repeat(40),proposed={...DEFAULT_CONTACT_PAGE,target:'contact' as const,accent:'emerald' as const};
async function fixture(){
 const [authority,owner,reviewer,receiver,attacker]=await Promise.all(Array.from({length:5},()=>generateIdentity())),now=Date.now(),at=(delta:number)=>new Date(now+delta).toISOString();
 let request=await sign<RepositoryDemoRequest>({type:'scopeblind.repository.demo-request.v1',id:taskId,owner_key:owner.publicKey,receiver_key:receiver.publicKey,authority_key:authority.publicKey,title:'Fix the contact button',goal:'Make the contact action work.',proposed,reviewer_secret_hash:'f'.repeat(64),issued_at:at(-60000),expires_at:at(3600000)},owner);
 const refs=new Map<string,string>(),pulls:any[]=[],githubCalls:Array<{path:string;method:string;body:any}>=[],completions:Signed<RepositoryDemoCompletion>[]=[];
 let kind:RepositoryDemoJob['kind']='provision',state:Signed<RepositoryState>|null=null,participants:Signed<RepositoryParticipants>|null=null,provision:Signed<RepositoryDemoProvision>|null=null;
 let outerSigner=authority,jobChange:(j:RepositoryDemoJob)=>RepositoryDemoJob=j=>j,losePullReply=false,conflict=false;
 function content(sha:string){const model=sha===template?DEFAULT_CONTACT_PAGE:proposed,text=contactPageBytes(model),bytes=Buffer.from(text),blob=createHash('sha1').update(Buffer.from(`blob ${bytes.length}\0`)).update(bytes).digest('hex');return {type:'file',path:'demo/contact.json',encoding:'base64',content:bytes.toString('base64'),size:bytes.length,sha:blob};}
 const fetchImpl:typeof fetch=async(input,init={})=>{
  const url=new URL(String(input));
  if(url.hostname==='scopeblind.com'){
   const envelope=JSON.parse(String(init.body)).request,q=envelope.payload;expect(await verify(envelope,receiver.publicKey)).toBe(true);expect((init.headers as any).Authorization).toBeUndefined();
   if(q.action==='repository_demo_poll'){
    const job:RepositoryDemoJob={type:'scopeblind.repository.demo-job.v1',id:'demo-job-0001',request_id:taskId,kind,request,provision,task:state?.payload.task??null,participants,task_state:state,parent_state:null,revision_request:null,lease_id:q.body.lease_id,lease_expires_at:at(60000),issued_at:new Date().toISOString()};return Response.json({ok:true,job:await sign(jobChange(job),outerSigner)});
   }
   if(q.action==='repository_demo_complete'){expect(await verify(q.body.completion,receiver.publicKey)).toBe(true);completions.push(q.body.completion);return Response.json({ok:true});}
   if(q.action==='repository_get')return Response.json({ok:true,repository_task:state});
   throw new Error('Unexpected service action '+q.action);
  }
  expect(url.origin).toBe('https://api.github.com');expect(init.redirect).toBe('error');const method=init.method??'GET',body=init.body?JSON.parse(String(init.body)):null,path=url.pathname;githubCalls.push({path,method,body});
  const prefix=`/repos/${DEMO_REPOSITORY}`;
  if(path.startsWith(prefix+'/contents/'))return Response.json(content(url.searchParams.get('ref')!));
  if(path.startsWith(prefix+'/git/ref/heads/')){const name=path.slice((prefix+'/git/ref/heads/').length),sha=refs.get(name);return sha?Response.json({ref:'refs/heads/'+name,object:{type:'commit',sha:conflict?'e'.repeat(40):sha}}):Response.json({message:'not found'},{status:404});}
  if(path===prefix+'/git/refs'&&method==='POST'){expect(body.ref.startsWith('refs/heads/scopeblind/demo/'+taskId+'/')).toBe(true);expect(refs.has(body.ref.slice(11))).toBe(false);refs.set(body.ref.slice(11),body.sha);return Response.json({ref:body.ref,object:{type:'commit',sha:body.sha}});}
  if(path===prefix+'/git/commits/'+template)return Response.json({sha:template,tree:{sha:'0'.repeat(40)},parents:[]});
  if(path===prefix+'/git/commits/'+change)return Response.json({sha:change,tree:{sha:tree},parents:[{sha:template}]});
  if(path===prefix+'/git/trees'&&method==='POST'){expect(body).toEqual({base_tree:'0'.repeat(40),tree:[{path:'demo/contact.json',mode:'100644',type:'blob',content:contactPageBytes(proposed)}]});return Response.json({sha:tree});}
  if(path===prefix+'/git/commits'&&method==='POST'){expect(body.parents).toEqual([template]);expect(body.tree).toBe(tree);return Response.json({sha:change});}
  if(path===prefix+'/check-runs'&&method==='POST'){expect(body.head_sha).toBe(change);expect(body.name).toBe(DEMO_CHECK.name);return Response.json({id:7});}
  if(path===prefix+'/pulls'&&method==='GET')return Response.json(pulls);
  if(path===prefix+'/pulls'&&method==='POST'){const pull={number:7,state:'open',head:{ref:body.head,sha:change},base:{ref:body.base,sha:template}};pulls.push(pull);if(losePullReply){losePullReply=false;throw new Error('lost reply after PR creation');}return Response.json(pull);}
  throw new Error('Unexpected GitHub request '+method+' '+path);
 };
 const runner=new RepositoryDemoRunner({endpoint:'https://scopeblind.com/api/coordination',authority_key:authority.publicKey,receiver_key:receiver.publicKey,template_sha:template},receiver,'PRIVATE_LOCAL_GITHUB_TOKEN',fetchImpl);
 async function executeContext(selectedTaskId=taskId){
  kind='execute';const base=`scopeblind/demo/${selectedTaskId}/base`,head=`scopeblind/demo/${selectedTaskId}/change`;
  const task=await sign<RepositoryTask>({type:'scopeblind.repository.task.v1',id:selectedTaskId,title:request.payload.title,repository:DEMO_REPOSITORY,pull_number:7,base_branch:base,owner_key:owner.publicKey,receiver_key:receiver.publicKey,authority_key:authority.publicKey,allowed_paths:['demo/contact.json'],required_checks:[DEMO_CHECK],reviewer_secret_hash:request.payload.reviewer_secret_hash,issued_at:at(-55000),expires_at:at(3600000)},owner);
  const claim=await sign<RepositoryClaim>({type:'scopeblind.repository.claim.v1',task_id:selectedTaskId,task_digest:task.digest,reviewer_key:reviewer.publicKey,name:'Reviewer',issued_at:at(-50000)},reviewer);
  const proposal=await sign<RepositoryProposal>({type:'scopeblind.repository.proposal.v1',id:'demo-proposal-001',task_id:selectedTaskId,task_digest:task.digest,repository_id:'R_demo',base_ref:'refs/heads/'+base,head_ref:'refs/heads/'+head,base_sha:template,head_sha:change,merge_sha:merge,tree_sha:tree,files:[{path:'demo/contact.json',status:'modified',mode:'100644',additions:1,deletions:1}],checks:[{id:7,...DEMO_CHECK,head_sha:change,conclusion:'success'}],observed_at:at(-40000)},receiver);
  const approvals=await Promise.all([owner,reviewer].map((principal,i)=>sign<RepositoryApproval>({type:'scopeblind.repository.approval.v1',task_id:selectedTaskId,task_digest:task.digest,proposal_digest:proposal.digest,role:i?'reviewer':'owner',principal_key:principal.publicKey,decision:'approve',issued_at:at(-20000),expires_at:at(600000),note:''},principal)));
  state=await sign<RepositoryState>({type:'scopeblind.repository.state.v1',task,reviewer:claim,proposal,approvals,execution:null,outcome:null,acceptance:null,status:'approved',revision:4,observed_at:new Date().toISOString()},authority);expect((await verifyRepositoryEvidence({type:'scopeblind.repository.evidence.v1',state},authority.publicKey)).valid).toBe(true);
  participants=await sign<RepositoryParticipants>({type:'scopeblind.repository.participants.v1',task_id:selectedTaskId,task_digest:task.digest,owner_key:owner.publicKey,receiver_key:receiver.publicKey,reviewer_key:reviewer.publicKey,reviewer_claim_digest:claim.digest,issued_at:at(-30000),expires_at:at(3600000)},owner);
  provision=await sign<RepositoryDemoProvision>({type:'scopeblind.repository.demo-provision.v1',request_id:selectedTaskId,request_digest:request.digest,repository:DEMO_REPOSITORY,base_branch:base,head_branch:head,pull_number:7,initial_base_sha:template,initial_head_sha:change,receiver_key:receiver.publicKey,required_checks:[DEMO_CHECK],observed_at:at(-58000)},receiver);
  return state;
 }
 async function recordExecution(){
  const s=state!.payload;const execution=await sign<RepositoryExecution>({type:'scopeblind.repository.execution.v1',operation_id:'demo-operation-001',receiver_attempt_id:'demo-attempt-001',task_id:s.task.payload.id,task_digest:s.task.digest,proposal_digest:s.proposal!.digest,owner_approval_digest:s.approvals[0].digest,reviewer_approval_digest:s.approvals[1].digest,receiver_key:receiver.publicKey,action:'github.updateRefs',issued_at:at(-10000),expires_at:at(50000)},authority);
  state=await sign({...s,execution,status:'executing' as const},authority);
 }
 async function refreshState(){state=await sign({...state!.payload,status:state!.payload.execution?'executing' as const:'review' as const,observed_at:new Date().toISOString()},authority);return state;}
 return {runner,refs,pulls,githubCalls,completions,authority,owner,receiver,attacker,at,executeContext,recordExecution,refreshState,
  get request(){return request;},set request(v:Signed<RepositoryDemoRequest>){request=v;},get participants(){return participants;},set participants(v:Signed<RepositoryParticipants>|null){participants=v;},set outerSigner(v:typeof authority){outerSigner=v;},set jobChange(v:(j:RepositoryDemoJob)=>RepositoryDemoJob){jobChange=v;},set losePullReply(v:boolean){losePullReply=v;},set conflict(v:boolean){conflict=v;}};
}
describe('trusted disposable repository runner',()=>{
 it('provisions only isolated branches and fixed JSON, then reuses the same PR after a lost reply',async()=>{
  const f=await fixture();f.losePullReply=true;expect(await f.runner.runOne()).toBe(true);expect(f.completions[0].payload.status).toBe('failed');expect(f.pulls).toHaveLength(1);
  expect(await f.runner.runOne()).toBe(true);const completion=f.completions[1];expect(completion.payload.status).toBe('complete');expect(await verify(completion.payload.provision!,f.receiver.publicKey)).toBe(true);expect(f.pulls).toHaveLength(1);expect(f.refs.size).toBe(2);
  expect(f.githubCalls.filter(c=>c.path.endsWith('/git/refs')&&c.method==='POST')).toHaveLength(2);expect(f.githubCalls.filter(c=>c.path.endsWith('/git/commits')&&c.method==='POST')).toHaveLength(1);expect(f.githubCalls.some(c=>c.path==='/graphql')).toBe(false);
  expect(JSON.stringify(f.completions)).not.toContain('PRIVATE_LOCAL_GITHUB_TOKEN');
 });
 it('never overwrites a conflicting existing disposable branch',async()=>{
  const f=await fixture();await f.runner.runOne();const count=f.githubCalls.filter(c=>c.method==='POST').length;f.conflict=true;await f.runner.runOne();expect(f.completions.at(-1)!.payload).toMatchObject({status:'failed',error:'demo_base_changed'});expect(f.githubCalls.filter(c=>c.method==='POST')).toHaveLength(count);
 });
 it('rejects counterfeit authority, wrong lease and forged owner jobs before any GitHub request',async()=>{
  const forged=await fixture();forged.outerSigner=forged.attacker;await expect(forged.runner.runOne()).rejects.toThrow('demo_job_signature_invalid');expect(forged.githubCalls).toEqual([]);
  const lease=await fixture();lease.jobChange=j=>({...j,lease_id:'another-lease-001'});await expect(lease.runner.runOne()).rejects.toThrow('demo_job_invalid');expect(lease.githubCalls).toEqual([]);
  const owner=await fixture();owner.request=await sign(owner.request.payload,owner.attacker);await expect(owner.runner.runOne()).rejects.toThrow('demo_owner_request_invalid');expect(owner.githubCalls).toEqual([]);
 });
 it('delegates execution only after the original owner binds the exact enrolled reviewer',async()=>{
  const f=await fixture(),state=await f.executeContext(),execute=vi.spyOn(RepositoryReceiver.prototype,'execute').mockResolvedValue(state);
  const original=f.participants!;f.participants=null;await f.runner.runOne();expect(execute).not.toHaveBeenCalled();expect(f.completions.at(-1)!.payload.status).toBe('failed');
  f.participants=await sign({...original.payload,reviewer_key:f.attacker.publicKey},f.owner);await f.runner.runOne();expect(execute).not.toHaveBeenCalled();
  f.participants=original;await f.runner.runOne();expect(execute).toHaveBeenCalledTimes(1);expect(execute).toHaveBeenCalledWith(taskId);expect(f.completions.at(-1)!.payload.status).toBe('complete');expect(f.githubCalls).toEqual([]);
 });
 it('refuses signed but wrong-type participant records and queue records crossing request/task identities',async()=>{
  const malformed=await fixture(),state=await malformed.executeContext(),execute=vi.spyOn(RepositoryReceiver.prototype,'execute').mockResolvedValue(state);
  malformed.participants=await sign({...malformed.participants!.payload,type:'scopeblind.unrelated.v1'},malformed.owner) as unknown as Signed<RepositoryParticipants>;
  await malformed.runner.runOne();expect(execute).not.toHaveBeenCalled();expect(malformed.completions.at(-1)!.payload.status).toBe('failed');
  const crossed=await fixture();await crossed.executeContext('demo-another-task-001');await crossed.runner.runOne();expect(execute).not.toHaveBeenCalled();expect(crossed.completions.at(-1)!.payload.status).toBe('failed');expect(crossed.githubCalls).toEqual([]);
 });
 it('allows only read-only reconciliation of an existing signed execution after the demo request expires',async()=>{
  const f=await fixture(),missing=await fixture();await f.executeContext();await f.recordExecution();await missing.executeContext();
  vi.useFakeTimers({toFake:['Date']});vi.setSystemTime(Date.now()+2*3600000);
  const state=await f.refreshState();await missing.refreshState();expect((await verifyRepositoryEvidence({type:'scopeblind.repository.evidence.v1',state},f.authority.publicKey)).valid).toBe(true);
  const fresh=(j:RepositoryDemoJob,kind:RepositoryDemoJob['kind'])=>({...j,kind,issued_at:new Date().toISOString(),lease_expires_at:new Date(Date.now()+60000).toISOString()});
  f.jobChange=j=>fresh(j,'reconcile');missing.jobChange=j=>fresh(j,'reconcile');
  const reconcile=vi.spyOn(RepositoryReceiver.prototype,'reconcile').mockResolvedValue(state),execute=vi.spyOn(RepositoryReceiver.prototype,'execute').mockResolvedValue(state);
  await expect(f.runner.runOne()).resolves.toBe(true);expect(reconcile).toHaveBeenCalledTimes(1);expect(f.completions.at(-1)!.payload.status).toBe('complete');expect(f.githubCalls).toEqual([]);
  await expect(missing.runner.runOne()).resolves.toBe(true);expect(missing.completions.at(-1)!.payload).toMatchObject({status:'failed',error:'demo_existing_execution_required'});expect(reconcile).toHaveBeenCalledTimes(1);
  f.jobChange=j=>fresh(j,'execute');await expect(f.runner.runOne()).rejects.toThrow();expect(execute).not.toHaveBeenCalled();
 });
});
