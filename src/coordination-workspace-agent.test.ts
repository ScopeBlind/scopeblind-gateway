import {afterEach,describe,it,expect} from 'vitest';
import {mkdtempSync,rmSync,readFileSync,statSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {CoordinationAgentClient} from './coordination-agent-client.js';
import {handleAgentProfileRequest} from './coordination-agent-server.js';
import {ensureAgentProfile,readAgentProfile} from './coordination-agent-profile.js';
import {canonical,generateIdentity,sign,verify,type Signed} from './coordination-protocol.js';
import type {RepositoryWorkspace,WorkspaceInvitation,WorkspaceMemberClaim,WorkspaceMember,WorkspacePreparationMandate,WorkspaceReviewDraft,RepositoryWorkspaceAgentState,WorkspaceMandateView} from './coordination-repository-workspace.js';
import type {WorkspaceTaskAssignment} from './coordination-repository-workspace.js';
import type {RepositoryTask,RepositoryClaim,RepositoryProposal,RepositoryState} from './coordination-repository.js';
import type {RepositoryReviewBrief,RepositoryReviewPacket,RepositoryReviewState,RepositoryReviewFeedback,RepositoryReviewRecommendation,RepositoryReviewAgentUse} from './coordination-repository-review.js';

const dirs:string[]=[];afterEach(()=>{for(const dir of dirs.splice(0))rmSync(dir,{recursive:true,force:true});});
const workspaceId='workspace-client-001',mandateId='mandate-review-001',requestId='draft-review-001';
async function fixture(){
 const dir=mkdtempSync(join(tmpdir(),'workspace-agent-'));dirs.push(dir);const path=join(dir,'agent.json');
 const [authority,owner,reviewer,receiver,stranger]=await Promise.all(Array.from({length:5},()=>generateIdentity()));
 const profile=await ensureAgentProfile(path,'https://scopeblind.com/api/coordination',authority.publicKey),now=Date.now(),at=(offset:number)=>new Date(now+offset).toISOString();
 const workspace=await sign<RepositoryWorkspace>({type:'scopeblind.repository.workspace.v1',id:workspaceId,title:'Client website',client_name:'Example client',repository:'example/site',base_branch:'main',receiver_key:receiver.publicKey,authority_key:authority.publicKey,owner_member_id:'owner-member-001',owner_key:owner.publicKey,issued_at:at(-100000),expires_at:at(86400000)},owner);
 const invitation=await sign<WorkspaceInvitation>({type:'scopeblind.repository.workspace-invitation.v1',id:'invitation-client-001',workspace_id:workspaceId,workspace_digest:workspace.digest,member_id:'reviewer-member-001',role:'reviewer',display_name:'Client reviewer',issuer_key:owner.publicKey,secret_hash:'1'.repeat(64),issued_at:at(-90000),expires_at:at(3600000)},owner);
 const claim=await sign<WorkspaceMemberClaim>({type:'scopeblind.repository.workspace-member-claim.v1',workspace_id:workspaceId,invitation_digest:invitation.digest,member_id:'reviewer-member-001',member_key:reviewer.publicKey,issued_at:at(-80000)},reviewer);
 const members:WorkspaceMember[]=[{member_id:'owner-member-001',display_name:'Owner',role:'owner',status:'active',current_key:owner.publicKey,revision:1,invitation:null,claim:null,recovery:null,rotations:[],updates:[]},{member_id:'reviewer-member-001',display_name:'Client reviewer',role:'reviewer',status:'active',current_key:reviewer.publicKey,revision:1,invitation,claim,recovery:null,rotations:[],updates:[]}];
 let mandate=await sign<WorkspacePreparationMandate>({type:'scopeblind.repository.preparation-mandate.v1',id:mandateId,workspace_id:workspaceId,workspace_digest:workspace.digest,mode:'prepare_review',owner_member_id:'owner-member-001',owner_key:owner.publicKey,owner_member_revision:1,reviewer_member_id:'reviewer-member-001',reviewer_key:reviewer.publicKey,reviewer_member_revision:1,agent_key:profile.agentKey,repository:'example/site',base_branch:'main',allowed_paths:['src/**'],required_checks:[{name:'CI',app_id:123}],permissions:['prepare_review','read_task','report_criteria','request_revision'],max_requests:3,max_open_requests:2,issued_at:at(-60000),expires_at:at(3600000)},owner);
 let adoption:Signed<WorkspacePreparationMandate>|null=await sign(mandate.payload,reviewer),status:WorkspaceMandateView['status']='active',used=0,open=0,stale=false,wrongAuthority=false,tamper=false,omit=false,loseBefore=false,loseAfter=false;
 const drafts:Array<{draft:Signed<WorkspaceReviewDraft>;decision:null}>=[],calls:Array<{action:string;body:any}>=[];
 async function state(){const payload:RepositoryWorkspaceAgentState={type:'scopeblind.repository.workspace-agent-state.v1',workspace,members,mandate:{mandate,adoption,revocation:null,status,used_requests:used,open_requests:open},drafts:omit?[]:drafts,observed_at:stale?at(-300000):new Date().toISOString()};const result=await sign(payload,wrongAuthority?stranger:authority);if(tamper)result.payload.mandate.mandate.payload.repository='other/repo';return result;}
 const fetchImpl:typeof fetch=async(_url,init)=>{
  const signed=JSON.parse(String(init?.body)).request,q=signed.payload;expect(await verify(signed,profile.agentKey)).toBe(true);expect(q.room_id).toBe(workspaceId);expect(init?.redirect).toBe('error');calls.push({action:q.action,body:q.body});
  if(q.action==='repository_workspace_agent_get')expect(q.body).toEqual({mandate_id:mandateId});
  else if(q.action==='repository_workspace_draft'){
   expect(await verify(q.body.draft,profile.agentKey)).toBe(true);expect(readAgentProfile(path).workspaceDrafts?.[q.body.draft.payload.id]?.draft).toEqual(q.body.draft);
   if(loseBefore){loseBefore=false;throw new Error('reply lost before commit');}
   if(!drafts.some(d=>d.draft.digest===q.body.draft.digest)){drafts.push({draft:q.body.draft,decision:null});used++;open++;}
   if(loseAfter){loseAfter=false;throw new Error('reply lost after commit');}
  }else throw new Error('Unexpected action '+q.action);
  return Response.json({ok:true,agent:await state()});
 };
 const client=new CoordinationAgentClient(path,fetchImpl);
 const input=()=>({connection_id:mandateId,request_id:requestId,draft:{pull_number:42,title:'Update the contact form',content:{brief:'Make the contact form easier to use.',success_criteria:[{id:'criterion-submit-001',text:'A successful submission displays confirmation.'}]}}});
 return {path,profile,authority,owner,reviewer,receiver,stranger,workspace,client,drafts,calls,input,at,state,members,fetchImpl,
  get mandate(){return mandate;},set mandate(v:Signed<WorkspacePreparationMandate>){mandate=v;},get adoption(){return adoption;},set adoption(v:Signed<WorkspacePreparationMandate>|null){adoption=v;},
  set status(v:WorkspaceMandateView['status']){status=v;},set used(v:number){used=v;},set open(v:number){open=v;},set stale(v:boolean){stale=v;},set wrongAuthority(v:boolean){wrongAuthority=v;},set tamper(v:boolean){tamper=v;},set omit(v:boolean){omit=v;},set loseBefore(v:boolean){loseBefore=v;},set loseAfter(v:boolean){loseAfter=v;}};
}
describe('reusable workspace agent authority and exact preparation recovery',()=>{
 it('saves the independently signed joint mandate in a separate private connection and never exposes credentials',async()=>{
  const f=await fixture(),result=await f.client.inspectWorkspace(workspaceId,mandateId),saved=readAgentProfile(f.path),listed=f.client.connections();
  expect(result).toMatchObject({connection_id:mandateId,status:'active',remaining_requests:3});expect(saved.connections).toEqual({});expect(saved.workspaceConnections?.[mandateId].mandate).toEqual(f.mandate);expect(listed.connections[0]).toMatchObject({purpose:'repository_preparation',workspace_id:workspaceId,same_profile_key:true});expect(JSON.stringify(result)+JSON.stringify(listed)).not.toContain(f.profile.privateKey);expect(statSync(f.path).mode&0o777).toBe(0o600);expect(()=>f.client.clientFor(mandateId)).toThrow();
 });
 it('rejects wrong pins, corrupted records, missing adoption and stale observations without creating usable authority',async()=>{
  for(const mode of ['wrongAuthority','tamper','stale'] as const){const f=await fixture();f[mode]=true;await expect(f.client.inspectWorkspace(workspaceId,mandateId)).rejects.toThrow();expect(readAgentProfile(f.path).workspaceConnections).toBeUndefined();}
  const f=await fixture();f.adoption=null;f.status='awaiting_reviewer';const result=await f.client.inspectWorkspace(workspaceId,mandateId);expect(result.connection_id).toBeNull();await expect(f.client.prepareRepositoryReview(f.input())).rejects.toMatchObject({code:'unknown_workspace_connection'});
 });
 it('inherits the exact signed scope, records a draft once and leaves human approval authority untouched',async()=>{
  const f=await fixture();await f.client.inspectWorkspace(workspaceId,mandateId);const result=await f.client.prepareRepositoryReview(f.input());expect(result).toMatchObject({status:'recorded',used_requests:1,open_requests:1});expect(f.drafts[0].draft.payload).toMatchObject({repository:'example/site',mandate_digest:f.mandate.digest,allowed_paths:['src/**'],required_checks:[{name:'CI',app_id:123}]});expect(f.calls.map(c=>c.action)).toEqual(['repository_workspace_agent_get','repository_workspace_agent_get','repository_workspace_draft']);expect(readAgentProfile(f.path).connections).toEqual({});
 });
 it('replays identical saved intent after a lost uncommitted reply and refuses changed intent before transport',async()=>{
  const f=await fixture();await f.client.inspectWorkspace(workspaceId,mandateId);f.loseBefore=true;await expect(f.client.prepareRepositoryReview(f.input())).rejects.toMatchObject({code:'agent_connection_interrupted'});const saved=readAgentProfile(f.path).workspaceDrafts![requestId].draft;
  expect((await f.client.prepareRepositoryReview(f.input())).draft_digest).toBe(saved.digest);expect(f.calls.filter(c=>c.action==='repository_workspace_draft').map(c=>canonical(c.body.draft))).toEqual([canonical(saved),canonical(saved)]);expect(f.drafts).toHaveLength(1);
  const count=f.calls.length;await expect(f.client.prepareRepositoryReview({...f.input(),draft:{...f.input().draft,title:'Different change'}})).rejects.toMatchObject({code:'workspace_draft_id_conflict'});expect(f.calls).toHaveLength(count);
 });
 it('recognizes a committed lost reply even when the allowance has since been exhausted, without a second mutation',async()=>{
  const f=await fixture();f.mandate=await sign({...f.mandate.payload,max_requests:1,max_open_requests:1},f.owner);f.adoption=await sign(f.mandate.payload,f.reviewer);await f.client.inspectWorkspace(workspaceId,mandateId);f.loseAfter=true;await expect(f.client.prepareRepositoryReview(f.input())).rejects.toThrow();f.status='exhausted';
  expect((await f.client.prepareRepositoryReview(f.input())).status).toBe('recorded');expect(f.calls.filter(c=>c.action==='repository_workspace_draft')).toHaveLength(1);expect(f.drafts).toHaveLength(1);
 });
 it('preserves the exact feedback source through interrupted preparation and refuses to silently change its lineage',async()=>{
  const f=await fixture();await f.client.inspectWorkspace(workspaceId,mandateId);
  const source={task_id:'previous-review-001',task_digest:'a'.repeat(64),basis_digest:'b'.repeat(64),packet_digest:'c'.repeat(64),feedback_digest:'d'.repeat(64)},input={...f.input(),draft:{...f.input().draft,source}};
  f.loseBefore=true;await expect(f.client.prepareRepositoryReview(input)).rejects.toThrow();const saved=readAgentProfile(f.path).workspaceDrafts![requestId].draft;
  expect(saved.payload.source).toEqual(source);expect((await f.client.prepareRepositoryReview(input)).draft_digest).toBe(saved.digest);
  const calls=f.calls.length;
  await expect(f.client.prepareRepositoryReview({...input,draft:{...input.draft,source:{...source,feedback_digest:'e'.repeat(64)}}})).rejects.toMatchObject({code:'workspace_draft_id_conflict'});
  await expect(f.client.prepareRepositoryReview(f.input())).rejects.toMatchObject({code:'workspace_draft_id_conflict'});
  await expect(f.client.prepareRepositoryReview({...input,request_id:'draft-invalid-source',draft:{...input.draft,source:{...source,feedback_digest:'invalid'}}})).rejects.toMatchObject({code:'invalid_workspace_draft'});
  expect(f.calls).toHaveLength(calls);expect(f.drafts).toHaveLength(1);expect(f.drafts[0].draft).toEqual(saved);
 });
 it('rejects broadened paths, check removal/provider substitution, unexpected fields and quotas before writing a new draft',async()=>{
  const f=await fixture();await f.client.inspectWorkspace(workspaceId,mandateId);
  for(const draft of [{...f.input().draft,allowed_paths:['other/**']},{...f.input().draft,required_checks:[{name:'CI',app_id:999}]},{...f.input().draft,required_checks:[{name:'other',app_id:123}]},{...f.input().draft,approve:true}])await expect(f.client.prepareRepositoryReview({...f.input(),draft})).rejects.toThrow();
  expect(f.calls.some(c=>c.action==='repository_workspace_draft')).toBe(false);expect(readAgentProfile(f.path).workspaceDrafts).toBeUndefined();
  await f.client.prepareRepositoryReview({...f.input(),request_id:'draft-existing-001'});await f.client.prepareRepositoryReview({...f.input(),request_id:'draft-existing-002'});const writes=f.calls.filter(c=>c.action==='repository_workspace_draft').length;await expect(f.client.prepareRepositoryReview(f.input())).rejects.toMatchObject({code:'workspace_preparation_limit'});expect(f.calls.filter(c=>c.action==='repository_workspace_draft')).toHaveLength(writes);
 });
 it('supports narrower paths and extra checks, but an unverified recording never becomes success',async()=>{
  const f=await fixture();await f.client.inspectWorkspace(workspaceId,mandateId);const input={...f.input(),draft:{...f.input().draft,allowed_paths:['src/components/**'],required_checks:[...f.mandate.payload.required_checks,{name:'Accessibility',app_id:124}]}};expect((await f.client.prepareRepositoryReview(input)).status).toBe('recorded');
  const hidden=await fixture();await hidden.client.inspectWorkspace(workspaceId,mandateId);hidden.omit=true;await expect(hidden.client.prepareRepositoryReview(hidden.input())).rejects.toMatchObject({code:'workspace_evidence_invalid'});expect(readAgentProfile(hidden.path).workspaceDrafts![requestId]).toBeTruthy();
 });
 it('stores prototype-looking IDs as ordinary data and preserves signed local intent on revocation',async()=>{
  const f=await fixture();await f.client.inspectWorkspace(workspaceId,mandateId);const input={...f.input(),request_id:'__proto__'};expect((await f.client.prepareRepositoryReview(input)).status).toBe('recorded');expect(Object.hasOwn(readAgentProfile(f.path).workspaceDrafts!,'__proto__')).toBe(true);
  const g=await fixture();await g.client.inspectWorkspace(workspaceId,mandateId);g.loseBefore=true;await expect(g.client.prepareRepositoryReview(g.input())).rejects.toThrow();const saved=readFileSync(g.path,'utf8');g.status='membership_changed';await expect(g.client.prepareRepositoryReview(g.input())).rejects.toThrow();expect(readFileSync(g.path,'utf8')).toBe(saved);
 });
 it('offers the five bounded tools and refuses human authority tools and extra execution fields',async()=>{
  const f=await fixture();const listed:any=await handleAgentProfileRequest(f.client,{jsonrpc:'2.0',id:1,method:'tools/list'}),names=listed.result.tools.map((t:any)=>t.name);
  for(const name of ['inspect_workspace','prepare_repository_review','inspect_repository_review','report_repository_criteria','request_repository_changes'])expect(names).toContain('coordination.'+name);
  for(const name of ['coordination.workspace_adopt','coordination.repository_approve','coordination.repository_begin','coordination.repository_accept']){const response:any=await handleAgentProfileRequest(f.client,{jsonrpc:'2.0',id:2,method:'tools/call',params:{name,arguments:{}}});expect(JSON.parse(response.result.content[0].text).code).toBe('unknown_tool');}
  const response:any=await handleAgentProfileRequest(f.client,{jsonrpc:'2.0',id:3,method:'tools/call',params:{name:'coordination.prepare_repository_review',arguments:{...f.input(),approve:true}}});expect(JSON.parse(response.result.content[0].text).code).toBe('invalid_input');expect(f.calls).toHaveLength(0);
 });
});

async function reviewFixture(){
 const f=await fixture();await f.client.inspectWorkspace(workspaceId,mandateId);const taskId='assigned-review-001';
 const task=await sign<RepositoryTask>({type:'scopeblind.repository.task.v1',id:taskId,title:'Improve the contact form',repository:'example/site',pull_number:42,base_branch:'main',owner_key:f.owner.publicKey,receiver_key:f.receiver.publicKey,authority_key:f.authority.publicKey,allowed_paths:['src/**'],required_checks:[{name:'CI',app_id:123}],reviewer_secret_hash:'2'.repeat(64),issued_at:f.at(-50000),expires_at:f.at(3600000)},f.owner);
 const brief=await sign<RepositoryReviewBrief>({type:'scopeblind.repository.review-brief.v1',task_id:taskId,task_digest:task.digest,owner_key:f.owner.publicKey,...f.input().draft.content,issued_at:f.at(-49000),expires_at:task.payload.expires_at},f.owner);
 const assignment=await sign<WorkspaceTaskAssignment>({type:'scopeblind.repository.workspace-task-assignment.v1',workspace_id:workspaceId,workspace_digest:f.workspace.digest,task_id:taskId,task_digest:task.digest,owner_member_id:'owner-member-001',owner_key:f.owner.publicKey,owner_member_revision:1,reviewer_member_id:'reviewer-member-001',reviewer_key:f.reviewer.publicKey,reviewer_member_revision:1,review_brief_digest:brief.digest,issued_at:f.at(-48000),expires_at:task.payload.expires_at},f.owner);
 const claim=await sign<RepositoryClaim>({type:'scopeblind.repository.claim.v1',task_id:taskId,task_digest:task.digest,reviewer_key:f.reviewer.publicKey,name:'Client reviewer',issued_at:f.at(-47000)},f.reviewer);
 let proposal=await sign<RepositoryProposal>({type:'scopeblind.repository.proposal.v1',id:'proposal-review-001',task_id:taskId,task_digest:task.digest,repository_id:'R_example',base_ref:'refs/heads/main',head_ref:'refs/heads/improve',base_sha:'a'.repeat(40),head_sha:'b'.repeat(40),merge_sha:'c'.repeat(40),tree_sha:'d'.repeat(40),files:[{path:'src/contact.tsx',status:'modified',mode:'100644',additions:4,deletions:1}],checks:[{id:77,name:'CI',app_id:123,head_sha:'b'.repeat(40),conclusion:'success'}],observed_at:f.at(-40000)},f.receiver);
 let packet=await sign<RepositoryReviewPacket>({type:'scopeblind.repository.review-packet.v1',task_id:taskId,task_digest:task.digest,brief_digest:brief.digest,proposal_digest:proposal.digest,base_sha:proposal.payload.base_sha,head_sha:proposal.payload.head_sha,merge_sha:proposal.payload.merge_sha,preview:{status:'not_requested',reason:'This review does not require a deployment preview.'},observed_at:f.at(-39000),expires_at:f.at(840000)},f.receiver);
 const feedback:Signed<RepositoryReviewFeedback>[]=[],recommendations:Signed<RepositoryReviewRecommendation>[]=[],uses:Signed<RepositoryReviewAgentUse>[]=[],history:RepositoryReviewState['history']=[],frozen=new Map<string,{state:Signed<RepositoryState>;packet:Signed<RepositoryReviewPacket>}>(),reviewCalls:Array<{action:string;body:any}>=[];
 let loseBefore=false,loseAfter=false,omitUse=false,wrongAlias=false,denyCurrent=false;
 async function state(){return sign<RepositoryState>({type:'scopeblind.repository.state.v1',task,reviewer:claim,proposal,approvals:[],execution:null,outcome:null,acceptance:null,status:'review',revision:1,observed_at:new Date().toISOString()},f.authority);}
 async function response(recoverDigest?:string){
  const old=recoverDigest?frozen.get(recoverDigest):undefined,core=old?.state??await state(),selectedFeedback=recoverDigest?feedback.filter(r=>r.digest===recoverDigest):feedback,selectedRecommendations=recoverDigest?recommendations.filter(r=>r.digest===recoverDigest):recommendations;
  const review=await sign<RepositoryReviewState>({type:'scopeblind.repository.review-state.v1',task_id:taskId,task_digest:task.digest,brief,packet:old?.packet??packet,decisions:[],feedback:selectedFeedback,recommendations:selectedRecommendations,history:recoverDigest?[]:history,agent_uses:omitUse?[]:recoverDigest?uses.filter(u=>u.payload.record_digest===recoverDigest):uses,observed_at:new Date().toISOString()},f.authority);
  const evidence={type:'scopeblind.repository.review-evidence.v1',repository:{type:'scopeblind.repository.evidence.v1',state:core},review};return {ok:true,repository_task:wrongAlias?{incorrect:true}:core,review,evidence,...(recoverDigest?{historical_only:true}:{})};
 }
 const fetchImpl:typeof fetch=async(url,init)=>{
  const signed=JSON.parse(String(init?.body)).request,q=signed.payload;
  if(q.action.startsWith('repository_workspace_'))return f.fetchImpl(url,init);
  expect(await verify(signed,f.profile.agentKey)).toBe(true);expect(q.room_id).toBe(taskId);reviewCalls.push({action:q.action,body:q.body});
  if(q.action==='repository_review_get'){
   if(q.body.record_digest){if(!frozen.has(q.body.record_digest))return Response.json({ok:false,error:'repository_review_record_missing'},{status:404});return Response.json(await response(q.body.record_digest));}
   if(denyCurrent)return Response.json({ok:false,error:'workspace_mandate_inactive'},{status:403});return Response.json(await response());
  }
  const record=(q.body.feedback??q.body.recommendation) as Signed<RepositoryReviewFeedback|RepositoryReviewRecommendation>;expect(q.body.mandate_id).toBe(mandateId);expect(await verify(record,f.profile.agentKey)).toBe(true);expect(readAgentProfile(f.path).workspaceReviewRecords?.[record.payload.id]?.record).toEqual(record);
  if(loseBefore){loseBefore=false;throw new Error('lost before commit');}
  if(!frozen.has(record.digest)){
   frozen.set(record.digest,{state:await state(),packet});if(record.payload.type==='scopeblind.repository.review-feedback.v1')feedback.push(record as Signed<RepositoryReviewFeedback>);else recommendations.push(record as Signed<RepositoryReviewRecommendation>);
   uses.push(await sign<RepositoryReviewAgentUse>({type:'scopeblind.repository.review-agent-use.v1',task_id:taskId,task_digest:task.digest,record_digest:record.digest,permission:record.payload.type==='scopeblind.repository.review-feedback.v1'?'request_revision':'report_criteria',mandate:f.mandate,adoption:f.adoption!,assignment,checked_at:new Date().toISOString()},f.authority));
  }
  if(loseAfter){loseAfter=false;throw new Error('lost after commit');}return Response.json(await response());
 };
 const client=new CoordinationAgentClient(f.path,fetchImpl);
 const report=()=>({connection_id:mandateId,task_id:taskId,request_id:'assessment-review-001',packet_digest:packet.digest,assessment:{recommendation:'insufficient_evidence' as const,criteria:[{criterion_id:'criterion-submit-001',verdict:'unknown' as const,evidence_refs:[{kind:'check' as const,id:77},{kind:'file' as const,path:'src/contact.tsx'}],explanation:'CI passed, but the packet contains no interactive submission result.'}],source:{kind:'agent' as const,model:'test-agent'}}});
 const changes=()=>({connection_id:mandateId,task_id:taskId,request_id:'feedback-review-001',packet_digest:packet.digest,basis_digest:proposal.digest,feedback:{criterion_ids:['criterion-submit-001'],message:'Please demonstrate a successful submission.',requested_changes:'Add a test covering the displayed confirmation.'}});
 return {f,taskId,client,reviewCalls,feedback,recommendations,uses,report,changes,response,
  set loseBefore(v:boolean){loseBefore=v;},set loseAfter(v:boolean){loseAfter=v;},set omitUse(v:boolean){omitUse=v;},set wrongAlias(v:boolean){wrongAlias=v;},set denyCurrent(v:boolean){denyCurrent=v;},
  async refresh(){history.push({state:await state(),packet});proposal=await sign({...proposal.payload,id:'proposal-review-002',head_sha:'e'.repeat(40),merge_sha:'f'.repeat(40),checks:[{...proposal.payload.checks[0],head_sha:'e'.repeat(40)}],observed_at:new Date().toISOString()},f.receiver);packet=await sign({...packet.payload,proposal_digest:proposal.digest,head_sha:proposal.payload.head_sha,merge_sha:proposal.payload.merge_sha,observed_at:new Date().toISOString()},f.receiver);if(!feedback.length&&!recommendations.length)history.splice(0);},
 };
}
describe('agent criterion findings and general PR feedback',()=>{
 it('verifies the exact review and attributes unknown findings and requested changes without approving work',async()=>{
  const x=await reviewFixture();const inspected=await x.client.inspectRepositoryReview(mandateId,x.taskId);expect(inspected.packet_digest).toBe(x.report().packet_digest);expect((await x.client.reportRepositoryCriteria(x.report())).status).toBe('recorded');expect((await x.client.requestRepositoryChanges(x.changes())).status).toBe('recorded');expect(x.recommendations).toHaveLength(1);expect(x.feedback).toHaveLength(1);expect(x.uses.map(u=>u.payload.permission)).toEqual(['report_criteria','request_revision']);expect(x.reviewCalls.some(c=>/approve|begin|accept/.test(c.action))).toBe(false);
 });
 it('rejects missing criterion coverage, invented evidence refs and mismatched response aliases',async()=>{
  const x=await reviewFixture(),r=x.report();await expect(x.client.reportRepositoryCriteria({...r,assessment:{...r.assessment,criteria:[]}})).rejects.toMatchObject({code:'invalid_repository_assessment'});await expect(x.client.reportRepositoryCriteria({...r,assessment:{...r.assessment,criteria:[{...r.assessment.criteria[0],evidence_refs:[{kind:'check',id:999}]}]}})).rejects.toMatchObject({code:'invalid_repository_assessment'});expect(x.recommendations).toHaveLength(0);x.wrongAlias=true;await expect(x.client.inspectRepositoryReview(mandateId,x.taskId)).rejects.toMatchObject({code:'repository_review_evidence_invalid'});
 });
 it('never accepts an agent signature without the recorded dual mandate and assignment proof',async()=>{
  const x=await reviewFixture();x.omitUse=true;await expect(x.client.reportRepositoryCriteria(x.report())).rejects.toMatchObject({code:'repository_review_evidence_invalid'});expect(readAgentProfile(x.f.path).workspaceReviewRecords?.['assessment-review-001']).toBeTruthy();
 });
 it('recovers an exact committed finding after revocation without reading new task data or writing again',async()=>{
  const x=await reviewFixture(),input=x.report();x.loseAfter=true;await expect(x.client.reportRepositoryCriteria(input)).rejects.toThrow();x.denyCurrent=true;x.f.status='revoked';const workspaceReads=x.f.calls.length;expect((await x.client.reportRepositoryCriteria(input)).status).toBe('recorded');expect(x.f.calls).toHaveLength(workspaceReads);expect(x.reviewCalls.filter(c=>c.action==='repository_review_recommendation')).toHaveLength(1);expect(x.reviewCalls.at(-1)?.body.record_digest).toBe(x.recommendations[0].digest);
 });
 it('retries an uncommitted record with its identical signature and refuses changing or rebasing saved findings',async()=>{
  const x=await reviewFixture(),input=x.changes();x.loseBefore=true;await expect(x.client.requestRepositoryChanges(input)).rejects.toThrow();expect((await x.client.requestRepositoryChanges(input)).status).toBe('recorded');const writes=x.reviewCalls.filter(c=>c.action==='repository_review_feedback');expect(writes).toHaveLength(2);expect(canonical(writes[0].body.feedback)).toBe(canonical(writes[1].body.feedback));await expect(x.client.requestRepositoryChanges({...input,feedback:{...input.feedback,message:'Different intent'}})).rejects.toMatchObject({code:'repository_review_id_conflict'});
  const y=await reviewFixture(),pending=y.report();y.loseBefore=true;await expect(y.client.reportRepositoryCriteria(pending)).rejects.toThrow();const before=readFileSync(y.f.path,'utf8');await y.refresh();await expect(y.client.reportRepositoryCriteria(pending)).rejects.toMatchObject({code:'repository_review_basis_stale'});expect(readFileSync(y.f.path,'utf8')).toBe(before);expect(y.reviewCalls.filter(c=>c.action==='repository_review_recommendation')).toHaveLength(1);
 });
});
