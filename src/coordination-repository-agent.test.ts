import {afterEach,describe,it,expect} from 'vitest';
import {mkdtempSync,rmSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {CoordinationAgentClient} from './coordination-agent-client.js';
import {handleAgentProfileRequest} from './coordination-agent-server.js';
import {ensureAgentProfile,readAgentProfile} from './coordination-agent-profile.js';
import {canonical,generateIdentity,sign,verify,type Signed} from './coordination-protocol.js';
import type {RepositoryState,RepositoryTask,RepositoryClaim,RepositoryProposal} from './coordination-repository.js';
import type {RepositoryAgentGrant,RepositoryCollaboration,RepositoryRevisionRequest,ContactPage} from './coordination-repository-collaboration.js';
import type {RepositoryCollaborationEvidence} from './coordination-repository-collaboration-evidence.js';

const dirs:string[]=[];afterEach(()=>{for(const path of dirs.splice(0))rmSync(path,{recursive:true,force:true});});
const taskId='repository-task-001',grantId='repository-grant-001',requestId='repository-revision-001';
const proposed:ContactPage={type:'scopeblind.contact-page.v1',button_label:'Contact us',target:'contact',accent:'emerald'};
const call=(name:string,arguments_:unknown)=>({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:arguments_}});
async function fixture(){
 const dir=mkdtempSync(join(tmpdir(),'repository-agent-'));dirs.push(dir);const path=join(dir,'profile.json');
 const [authority,owner,reviewer,receiver,stranger]=await Promise.all(Array.from({length:5},()=>generateIdentity()));
 const profile=await ensureAgentProfile(path,'https://scopeblind.com/api/coordination',authority.publicKey),now=Date.now(),at=(delta:number)=>new Date(now+delta).toISOString();
 const task=await sign<RepositoryTask>({type:'scopeblind.repository.task.v1',id:taskId,title:'Fix the contact action',repository:'example/reviewed',pull_number:7,base_branch:'main',owner_key:owner.publicKey,receiver_key:receiver.publicKey,authority_key:authority.publicKey,allowed_paths:['demo/contact.json'],required_checks:[{name:'CI',app_id:123}],reviewer_secret_hash:'1'.repeat(64),issued_at:at(-60000),expires_at:at(3600000)},owner);
 const claim=await sign<RepositoryClaim>({type:'scopeblind.repository.claim.v1',task_id:taskId,task_digest:task.digest,reviewer_key:reviewer.publicKey,name:'Reviewer',issued_at:at(-50000)},reviewer);
 let proposal=await sign<RepositoryProposal>({type:'scopeblind.repository.proposal.v1',id:'proposal-example-001',task_id:taskId,task_digest:task.digest,repository_id:'R_example',base_ref:'refs/heads/main',head_ref:'refs/heads/change',base_sha:'a'.repeat(40),head_sha:'b'.repeat(40),merge_sha:'c'.repeat(40),tree_sha:'d'.repeat(40),files:[{path:'demo/contact.json',status:'modified',mode:'100644',additions:1,deletions:1}],checks:[{id:77,name:'CI',app_id:123,head_sha:'b'.repeat(40),conclusion:'success'}],observed_at:at(-40000)},receiver);
 let grant=await sign<RepositoryAgentGrant>({type:'scopeblind.repository.agent-grant.v1',id:grantId,task_id:taskId,task_digest:task.digest,issuer_key:owner.publicKey,agent_key:profile.agentKey,permissions:['read_task','request_revision'],issued_at:at(-30000),expires_at:at(1800000)},owner);
 let revoked=false,stale=false,wrongStatePin=false,wrongAlias=false,corruptRead=false,omitRequest=false,loseBefore=false,loseAfter=false;
 const requests:Signed<RepositoryRevisionRequest>[]=[],calls:Array<{action:string;body:any}>=[];
 async function evidence():Promise<RepositoryCollaborationEvidence>{
  const observed=stale?at(-300000):new Date().toISOString();
  const state=await sign<RepositoryState>({type:'scopeblind.repository.state.v1',task,reviewer:claim,proposal,approvals:[],execution:null,outcome:null,acceptance:null,status:'review',revision:1,observed_at:observed},wrongStatePin?stranger:authority);
  const collaboration=await sign<RepositoryCollaboration>({type:'scopeblind.repository.collaboration.v1',task_id:taskId,task_digest:task.digest,participants:null,preview:null,agent_grants:[{grant,revoked}],requests:omitRequest?[]:requests,revisions:[],observed_at:observed},authority);
  return {type:'scopeblind.repository.collaboration-evidence.v1',repository:{type:'scopeblind.repository.evidence.v1',state},collaboration};
 }
 const fetchImpl:typeof fetch=async(_url,init)=>{
  const signed=JSON.parse(String(init?.body)).request,q=signed.payload;expect(await verify(signed,profile.agentKey)).toBe(true);expect(init?.redirect).toBe('error');expect(q.room_id).toBe(taskId);calls.push({action:q.action,body:q.body});
  if(q.action==='repository_agent_get')expect(q.body).toEqual({grant_id:grantId});
  else if(q.action==='repository_revision_request'){
   expect(readAgentProfile(path).repositoryRevisions?.[q.body.request.payload.id]?.request).toEqual(q.body.request);expect(await verify(q.body.request,profile.agentKey)).toBe(true);
   if(loseBefore){loseBefore=false;throw new Error('reply lost before commit');}
   if(!requests.some(r=>r.digest===q.body.request.digest))requests.push(q.body.request);
   if(loseAfter){loseAfter=false;throw new Error('reply lost after commit');}
  }else throw new Error('Unexpected authority-bearing action '+q.action);
  const e=await evidence();if(corruptRead)e.collaboration.payload.agent_grants[0].grant.payload.agent_key=stranger.publicKey;
  return Response.json({ok:true,repository_task:wrongAlias?{bad:true}:e.repository.state,collaboration:e.collaboration,evidence:e});
 };
 const client=new CoordinationAgentClient(path,fetchImpl);
 const input=()=>({connection_id:grantId,request_id:requestId,basis_digest:proposal.digest,message:'Use a working contact action.',proposed});
 return {path,profile,client,calls,requests,authority,owner,reviewer,receiver,stranger,task,claim,at,input,evidence,
  get grant(){return grant;},set grant(v:Signed<RepositoryAgentGrant>){grant=v;},get proposal(){return proposal;},set proposal(v:Signed<RepositoryProposal>){proposal=v;},
  set revoked(v:boolean){revoked=v;},set stale(v:boolean){stale=v;},set wrongStatePin(v:boolean){wrongStatePin=v;},set wrongAlias(v:boolean){wrongAlias=v;},set corruptRead(v:boolean){corruptRead=v;},set omitRequest(v:boolean){omitRequest=v;},set loseBefore(v:boolean){loseBefore=v;},set loseAfter(v:boolean){loseAfter=v;}};
}
describe('repository agent profile boundaries and exact retry recovery',()=>{
 it('verifies an explicit human grant and saves only a separate repository connection, without exposing profile credentials',async()=>{
  const f=await fixture(),result=await f.client.inspectRepository(taskId,grantId),profile=readAgentProfile(f.path);
  expect(result).toMatchObject({connection_id:grantId,purpose:'repository',current_basis_digest:f.proposal.digest,scope:['read_task','request_revision']});
  expect(profile.connections).toEqual({});expect(profile.repositoryConnections?.[grantId].grant).toEqual(f.grant);expect(profile.requests).toEqual({});
  const listed=f.client.connections();expect(listed.agent_key).toBe(f.profile.agentKey);expect(listed.connections[0].purpose).toBe('repository');expect(JSON.stringify(result)+JSON.stringify(listed)).not.toContain(f.profile.privateKey);
  expect(()=>f.client.clientFor(grantId)).toThrow('does not hold');expect(f.calls.map(c=>c.action)).toEqual(['repository_agent_get']);
 });
 it('refuses wrong authority, corrupt envelopes, inconsistent aliases, and grants for another agent before saving access',async()=>{
  for(const change of ['wrongStatePin','corruptRead','wrongAlias'] as const){const f=await fixture();f[change]=true;await expect(f.client.inspectRepository(taskId,grantId)).rejects.toMatchObject({code:'repository_evidence_invalid'});expect(readAgentProfile(f.path).repositoryConnections).toBeUndefined();}
  const f=await fixture();f.grant=await sign({...f.grant.payload,agent_key:f.stranger.publicKey},f.owner);await expect(f.client.inspectRepository(taskId,grantId)).rejects.toMatchObject({code:'repository_agent_grant_inactive'});expect(readAgentProfile(f.path).repositoryConnections).toBeUndefined();
 });
 it('keeps stale, expired, revoked and read-only grants from authorizing a suggestion',async()=>{
  const f=await fixture();await f.client.inspectRepository(taskId,grantId);f.revoked=true;await expect(f.client.requestRepositoryRevision(f.input())).rejects.toMatchObject({code:'repository_agent_grant_inactive'});expect(f.calls.some(c=>c.action==='repository_revision_request')).toBe(false);
  const expired=await fixture();expired.grant=await sign({...expired.grant.payload,issued_at:expired.at(-30000),expires_at:expired.at(-1000)},expired.owner);await expect(expired.client.inspectRepository(taskId,grantId)).rejects.toMatchObject({code:'repository_agent_grant_inactive'});
  const read=await fixture();read.grant=await sign({...read.grant.payload,permissions:['read_task']},read.owner);await read.client.inspectRepository(taskId,grantId);await expect(read.client.requestRepositoryRevision(read.input())).rejects.toMatchObject({code:'repository_revision_outside_grant'});expect(read.requests).toEqual([]);
  const stale=await fixture();stale.stale=true;await expect(stale.client.inspectRepository(taskId,grantId)).rejects.toThrow();expect(readAgentProfile(stale.path).repositoryConnections).toBeUndefined();
 });
 it('persists the exact signed suggestion before transport and resends identical bytes after an uncommitted lost reply',async()=>{
  const f=await fixture();await f.client.inspectRepository(taskId,grantId);f.loseBefore=true;await expect(f.client.requestRepositoryRevision(f.input())).rejects.toMatchObject({code:'agent_connection_interrupted'});
  const saved=readAgentProfile(f.path).repositoryRevisions![requestId].request;expect(saved.payload.grant_digest).toBe(f.grant.digest);expect(saved.payload.basis_digest).toBe(f.proposal.digest);
  const result=await f.client.requestRepositoryRevision(f.input());expect(result.status).toBe('recorded');expect(result.request_digest).toBe(saved.digest);
  expect(f.calls.filter(c=>c.action==='repository_revision_request').map(c=>canonical(c.body.request))).toEqual([canonical(saved),canonical(saved)]);expect(f.requests).toHaveLength(1);
  const count=f.calls.length;await expect(f.client.requestRepositoryRevision({...f.input(),message:'Different intent'})).rejects.toMatchObject({code:'repository_revision_id_conflict'});expect(f.calls).toHaveLength(count);
 });
 it('recovers a committed lost reply by verifying the recorded suggestion, without sending another mutation',async()=>{
  const f=await fixture();await f.client.inspectRepository(taskId,grantId);f.loseAfter=true;await expect(f.client.requestRepositoryRevision(f.input())).rejects.toThrow();
  const result=await f.client.requestRepositoryRevision(f.input());expect(result.status).toBe('recorded');expect(f.calls.filter(c=>c.action==='repository_revision_request')).toHaveLength(1);expect(f.requests).toHaveLength(1);
 });
 it('persists opaque request IDs as data without inheriting or changing object prototype authority',async()=>{
  const f=await fixture();await f.client.inspectRepository(taskId,grantId);const input={...f.input(),request_id:'__proto__'};
  expect((await f.client.requestRepositoryRevision(input)).status).toBe('recorded');const profile=readAgentProfile(f.path);
  expect(Object.hasOwn(profile.repositoryRevisions!,'__proto__')).toBe(true);expect(profile.repositoryRevisions!['__proto__'].request.payload.id).toBe('__proto__');
  expect((await f.client.requestRepositoryRevision(input)).status).toBe('recorded');expect(f.requests).toHaveLength(1);
 });
 it('never rebases a saved suggestion onto a different proposal or treats an unverified receipt as success',async()=>{
  const f=await fixture();await f.client.inspectRepository(taskId,grantId);const original=f.input();f.loseBefore=true;await expect(f.client.requestRepositoryRevision(original)).rejects.toThrow();const before=readFileSync(f.path,'utf8');
  f.proposal=await sign({...f.proposal.payload,id:'proposal-example-002',head_sha:'e'.repeat(40),merge_sha:'f'.repeat(40),checks:[{...f.proposal.payload.checks[0],head_sha:'e'.repeat(40)}]},f.receiver);
  await expect(f.client.requestRepositoryRevision(original)).rejects.toMatchObject({code:'repository_revision_basis_stale'});expect(readFileSync(f.path,'utf8')).toBe(before);expect(f.calls.filter(c=>c.action==='repository_revision_request')).toHaveLength(1);
  const hidden=await fixture();await hidden.client.inspectRepository(taskId,grantId);hidden.omitRequest=true;await expect(hidden.client.requestRepositoryRevision(hidden.input())).rejects.toMatchObject({code:'repository_revision_unverified'});expect(readAgentProfile(hidden.path).repositoryRevisions![requestId]).toBeTruthy();
 });
 it('exposes only bounded repository read/suggest tools and rejects human, execution or arbitrary code fields before transport',async()=>{
  const f=await fixture();await f.client.inspectRepository(taskId,grantId);const count=f.calls.length;
  const listed:any=await handleAgentProfileRequest(f.client,{jsonrpc:'2.0',id:1,method:'tools/list'}),names=listed.result.tools.map((t:any)=>t.name);expect(names).toContain('coordination.inspect_repository');expect(names).toContain('coordination.request_repository_revision');expect(names.filter((n:string)=>n.includes('repository'))).toHaveLength(2);
  for(const [name,args,code] of [['coordination.repository_approve',{connection_id:grantId},'unknown_tool'],['coordination.inspect',{connection_id:grantId},'unknown_agent_connection'],['coordination.request_repository_revision',{...f.input(),approve:true},'invalid_input'],['coordination.request_repository_revision',{...f.input(),proposed:{...proposed,javascript:'run()'}},'invalid_repository_revision']] as const){const result:any=await handleAgentProfileRequest(f.client,call(name,args));expect(JSON.parse(result.result.content[0].text).code).toBe(code);}
  expect(f.calls).toHaveLength(count);expect(f.requests).toEqual([]);
 });
});
