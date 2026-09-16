import {describe,it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {canonical,generateIdentity,sign,sha256,type Signed} from './coordination-protocol.js';
import {contactPageBytes,DEFAULT_CONTACT_PAGE,DEMO_CHECK,DEMO_REPOSITORY,type RepositoryCollaboration,type RepositoryPreview,type RepositoryAgentGrant,type RepositoryRevisionRequest,type RepositoryRevisionLink,type RepositoryDemoRequest,type RepositoryDemoProvision,type RepositoryDemoState} from './coordination-repository-collaboration.js';
import {verifyRepositoryCollaborationEvidence,type RepositoryCollaborationEvidence} from './coordination-repository-collaboration-evidence.js';
import {verifyRepositoryEvidence,type RepositoryTask,type RepositoryClaim,type RepositoryProposal,type RepositoryState,type RepositoryApproval,type RepositoryExecution,type RepositoryOutcome,type RepositoryAcceptance} from './coordination-repository.js';
const time=(n:number)=>new Date(1800000000000+n*1000).toISOString();
async function fixture(){
 const [owner,reviewer,receiver,service,agent]=await Promise.all(Array.from({length:5},()=>generateIdentity()));const id='repository-demo-test';
 const task=await sign<RepositoryTask>({type:'scopeblind.repository.task.v1',id,title:'Fix the contact button',repository:DEMO_REPOSITORY,pull_number:1,base_branch:`scopeblind/demo/${id}/base`,owner_key:owner.publicKey,receiver_key:receiver.publicKey,authority_key:service.publicKey,allowed_paths:['demo/contact.json'],required_checks:[DEMO_CHECK],reviewer_secret_hash:'a'.repeat(64),issued_at:time(0),expires_at:time(7200)},owner);
 const claim=await sign<RepositoryClaim>({type:'scopeblind.repository.claim.v1',task_id:id,task_digest:task.digest,reviewer_key:reviewer.publicKey,name:'Jamie',issued_at:time(1)},reviewer);
 const proposal=await sign<RepositoryProposal>({type:'scopeblind.repository.proposal.v1',id:'proposal-test',task_id:id,task_digest:task.digest,repository_id:'R_demo',base_ref:`refs/heads/${task.payload.base_branch}`,head_ref:`refs/heads/scopeblind/demo/${id}/change`,base_sha:'1'.repeat(40),head_sha:'2'.repeat(40),merge_sha:'3'.repeat(40),tree_sha:'4'.repeat(40),files:[{path:'demo/contact.json',status:'modified',mode:'100644',additions:1,deletions:1}],checks:[{id:12,...DEMO_CHECK,head_sha:'2'.repeat(40),conclusion:'success'}],observed_at:time(2)},receiver);
 const state=await sign<RepositoryState>({type:'scopeblind.repository.state.v1',task,reviewer:claim,proposal,approvals:[],execution:null,outcome:null,acceptance:null,status:'review',revision:3,observed_at:time(10)},service);
 const side=async(model:typeof DEFAULT_CONTACT_PAGE)=>{const bytes=contactPageBytes(model);return {model,content_sha256:await sha256(bytes),blob_sha:createHash('sha1').update(`blob ${Buffer.byteLength(bytes)}\0`).update(bytes).digest('hex')};};
 const preview=await sign<RepositoryPreview>({type:'scopeblind.repository.preview.v1',task_id:id,task_digest:task.digest,proposal_digest:proposal.digest,base_sha:proposal.payload.base_sha,head_sha:proposal.payload.head_sha,merge_sha:proposal.payload.merge_sha,tree_sha:proposal.payload.tree_sha,path:'demo/contact.json',renderer:'scopeblind.contact-page.v1',before:await side(DEFAULT_CONTACT_PAGE),after:await side({...DEFAULT_CONTACT_PAGE,target:'contact'}),observed_at:time(3)},receiver);
 const collaboration=await sign<RepositoryCollaboration>({type:'scopeblind.repository.collaboration.v1',task_id:id,task_digest:task.digest,participants:null,preview,requests:[],revisions:[],agent_grants:[],observed_at:time(10)},service);
 const bundle:RepositoryCollaborationEvidence={type:'scopeblind.repository.collaboration-evidence.v1',repository:{type:'scopeblind.repository.evidence.v1',state},collaboration};return{bundle,owner,reviewer,receiver,service,agent,task,proposal};
}
async function incomingFixture(agent=false){
 const f=await fixture(),parent=f.bundle.repository.state.payload,id=f.task.payload.id,childId='repository-child-test';
 const approvals=await Promise.all([f.owner,f.reviewer].map((key,i)=>sign<RepositoryApproval>({type:'scopeblind.repository.approval.v1',task_id:id,task_digest:f.task.digest,proposal_digest:f.proposal.digest,role:i?'reviewer':'owner',principal_key:key.publicKey,decision:'approve',issued_at:time(3),expires_at:time(303),note:''},key)));
 const execution=await sign<RepositoryExecution>({type:'scopeblind.repository.execution.v1',operation_id:'repository-operation-test',receiver_attempt_id:'repository-attempt-test',task_id:id,task_digest:f.task.digest,proposal_digest:f.proposal.digest,owner_approval_digest:approvals[0].digest,reviewer_approval_digest:approvals[1].digest,receiver_key:f.receiver.publicKey,action:'github.updateRefs',issued_at:time(4),expires_at:time(124)},f.service);
 const outcome=await sign<RepositoryOutcome>({type:'scopeblind.repository.outcome.v1',operation_id:execution.payload.operation_id,task_id:id,task_digest:f.task.digest,proposal_digest:f.proposal.digest,execution_digest:execution.digest,status:'confirmed',observed_base_sha:f.proposal.payload.merge_sha,readback:'exact_ref',observed_at:time(5),note:'Confirmed original exact change'},f.receiver);
 const parentState=await sign<RepositoryState>({...parent,approvals,execution,outcome,status:'confirmed',revision:6,observed_at:time(20)},f.service);
 const proposed={...DEFAULT_CONTACT_PAGE,target:'contact' as const,accent:'emerald' as const};
 const grant=agent?await sign<RepositoryAgentGrant>({type:'scopeblind.repository.agent-grant.v1',id:'parent-agent-grant-test',task_id:id,task_digest:f.task.digest,issuer_key:f.owner.publicKey,agent_key:f.agent.publicKey,permissions:['read_task','request_revision'],issued_at:time(10),expires_at:time(300)},f.owner):undefined;
 const request=await sign<RepositoryRevisionRequest>({type:'scopeblind.repository.revision-request.v1',id:'parent-feedback-test',task_id:id,task_digest:f.task.digest,basis_digest:outcome.digest,requester_key:agent?f.agent.publicKey:f.reviewer.publicKey,...(grant?{grant_digest:grant.digest}:{}),message:'Please make the working contact button green.',proposed,issued_at:time(12)},agent?f.agent:f.reviewer);
 const demoRequest=await sign<RepositoryDemoRequest>({type:'scopeblind.repository.demo-request.v1',id:childId,owner_key:f.owner.publicKey,receiver_key:f.receiver.publicKey,authority_key:f.service.publicKey,title:'Refine the contact button',goal:'Apply the reviewed feedback.',proposed,reviewer_secret_hash:'b'.repeat(64),issued_at:time(15),expires_at:time(7200),parent_task_id:id,parent_task_digest:f.task.digest,parent_basis_digest:outcome.digest,revision_request_digest:request.digest},f.owner);
 const provision=await sign<RepositoryDemoProvision>({type:'scopeblind.repository.demo-provision.v1',request_id:childId,request_digest:demoRequest.digest,repository:DEMO_REPOSITORY,base_branch:`scopeblind/demo/${childId}/base`,head_branch:`scopeblind/demo/${childId}/change`,pull_number:2,initial_base_sha:f.proposal.payload.merge_sha,initial_head_sha:'5'.repeat(40),receiver_key:f.receiver.publicKey,required_checks:[DEMO_CHECK],observed_at:time(18)},f.receiver);
 const childTask=await sign<RepositoryTask>({...f.task.payload,id:childId,title:demoRequest.payload.title,pull_number:2,base_branch:provision.payload.base_branch,reviewer_secret_hash:demoRequest.payload.reviewer_secret_hash,issued_at:time(20)},f.owner);
 const state=await sign<RepositoryState>({type:'scopeblind.repository.state.v1',task:childTask,reviewer:null,proposal:null,approvals:[],execution:null,outcome:null,acceptance:null,status:'awaiting_reviewer',revision:1,observed_at:time(30)},f.service);
 const link=await sign<RepositoryRevisionLink>({type:'scopeblind.repository.revision-link.v1',id:'parent-child-link-test',parent_task_id:id,parent_task_digest:f.task.digest,parent_basis_digest:outcome.digest,request_digest:request.digest,child_task_id:childId,child_task_digest:childTask.digest,owner_key:f.owner.publicKey,issued_at:time(20)},f.owner);
 const collaboration=await sign<RepositoryCollaboration>({type:'scopeblind.repository.collaboration.v1',task_id:childId,task_digest:childTask.digest,participants:null,preview:null,requests:[],revisions:[link],agent_grants:[],observed_at:time(30)},f.service);
 const demo=await sign<RepositoryDemoState>({type:'scopeblind.repository.demo-state.v1',request:demoRequest,provision,task:childTask,status:'active',dispatch:'requested',error:null,observed_at:time(30)},f.service);
 const bundle:RepositoryCollaborationEvidence={type:'scopeblind.repository.collaboration-evidence.v1',repository:{type:'scopeblind.repository.evidence.v1',state},collaboration,demo,parent:{type:'scopeblind.repository.evidence.v1',state:parentState},parent_request:request,...(grant?{parent_agent_grant:grant}:{})};
 /** Re-sign every outer dependency, so negative tests reach semantic checks rather than stale digests. */
 async function replaceRequest(request:Signed<RepositoryRevisionRequest>,selectedGrant=grant){
  const revisedLink=await sign({...link.payload,request_digest:request.digest},f.owner),revisedRequest=await sign({...demoRequest.payload,revision_request_digest:request.digest},f.owner),revisedProvision=await sign({...provision.payload,request_digest:revisedRequest.digest},f.receiver);
  const result={...bundle,parent_request:request,collaboration:await sign({...collaboration.payload,revisions:[revisedLink]},f.service),demo:await sign({...demo.payload,request:revisedRequest,provision:revisedProvision},f.service)};if(selectedGrant)result.parent_agent_grant=selectedGrant;else delete result.parent_agent_grant;return result;
 }
 return {...f,bundle,parentState,request,grant,replaceRequest,outcome};
}
describe('portable repository collaboration evidence',()=>{
 it('verifies the exact visual model without treating a preview as a deployed website or acceptance',async()=>{
  const f=await fixture(),r=await verifyRepositoryCollaborationEvidence(f.bundle,f.service.publicKey);expect(r.valid,r.errors.join(';')).toBe(true);expect(r.previewVerified).toBe(true);expect(r.accepted).toBe(false);expect(r.authorityPinned).toBe(true);expect(r.limitations.join(' ')).toContain('does not execute repository code');expect((await verifyRepositoryCollaborationEvidence(f.bundle,f.owner.publicKey)).valid).toBe(false);
 });
 it('rejects re-signed misleading preview bytes, Git blob ids and proposal links',async()=>{
  const f=await fixture(),c=f.bundle.collaboration.payload,p=c.preview!.payload;
  for(const changed of [{...p,proposal_digest:'f'.repeat(64)},{...p,after:{...p.after,model:{...p.after.model,button_label:'Different'}}},{...p,after:{...p.after,blob_sha:'f'.repeat(40)}}]){
   const bundle={...f.bundle,collaboration:await sign({...c,preview:await sign(changed,f.receiver)},f.service)};const result=await verifyRepositoryCollaborationEvidence(bundle);expect(result.valid).toBe(false);expect(result.previewVerified).toBe(false);
  }
 });
 it('checks the agent’s exact grant, expiry and separation from human/receiver roles',async()=>{
  const f=await fixture(),c=f.bundle.collaboration.payload;
  const grant=await sign<RepositoryAgentGrant>({type:'scopeblind.repository.agent-grant.v1',id:'agent-grant-test',task_id:f.task.payload.id,task_digest:f.task.digest,issuer_key:f.owner.publicKey,agent_key:f.agent.publicKey,permissions:['read_task','request_revision'],issued_at:time(4),expires_at:time(300)},f.owner);
  const request=await sign<RepositoryRevisionRequest>({type:'scopeblind.repository.revision-request.v1',id:'agent-revision-test',task_id:f.task.payload.id,task_digest:f.task.digest,basis_digest:f.proposal.digest,requester_key:f.agent.publicKey,grant_digest:grant.digest,message:'Please make the button green.',proposed:{...DEFAULT_CONTACT_PAGE,target:'contact',accent:'emerald'},issued_at:time(5)},f.agent);
  const make=async(g=grant,r=request)=>({...f.bundle,collaboration:await sign({...c,requests:[r],agent_grants:[{grant:g,revoked:false}]},f.service)});
  const valid=await verifyRepositoryCollaborationEvidence(await make());expect(valid.valid,valid.errors.join(';')).toBe(true);
  const expired=await sign({...request.payload,issued_at:time(301)},f.agent);expect((await verifyRepositoryCollaborationEvidence(await make(grant,expired))).valid).toBe(false);
  const readOnly=await sign({...grant.payload,permissions:['read_task'] as Array<'read_task'>},f.owner),wrongScope=await sign({...request.payload,grant_digest:readOnly.digest},f.agent);expect((await verifyRepositoryCollaborationEvidence(await make(readOnly,wrongScope))).valid).toBe(false);
  const borrowed=await sign({...grant.payload,agent_key:f.receiver.publicKey},f.owner);expect((await verifyRepositoryCollaborationEvidence(await make(borrowed))).valid).toBe(false);
  const future=await sign({...grant.payload,issued_at:time(11)},f.owner),unobserved={...f.bundle,collaboration:await sign({...c,agent_grants:[{grant:future,revoked:false}]},f.service)};expect((await verifyRepositoryCollaborationEvidence(unobserved)).valid).toBe(false);
 });
 it('fails closed for malformed envelopes and unknown companion fields',async()=>{
  const f=await fixture();for(const value of [null,{}, {...f.bundle,previewVerified:true},{...f.bundle,collaboration:{...f.bundle.collaboration,payload:{...f.bundle.collaboration.payload,preview:null}}}])expect((await verifyRepositoryCollaborationEvidence(value)).valid).toBe(false);
 });
 it('verifies an incoming child only with the exact original human or scoped-agent feedback',async()=>{
  for(const agent of [false,true]){const f=await incomingFixture(agent),result=await verifyRepositoryCollaborationEvidence(f.bundle,f.service.publicKey);expect(result.valid,result.errors.join(';')).toBe(true);expect(result.revisionLinked).toBe(true);expect(result.accepted).toBe(false);
   const missing={...f.bundle};delete missing.parent_request;const rejected=await verifyRepositoryCollaborationEvidence(missing,f.service.publicKey);expect(rejected.valid).toBe(false);expect(rejected.revisionLinked).toBe(false);
   if(agent){const missingGrant={...f.bundle};delete missingGrant.parent_agent_grant;expect((await verifyRepositoryCollaborationEvidence(missingGrant,f.service.publicKey)).valid).toBe(false);}
  }
 });
 it('rejects freshly re-signed feedback from a wrong task, basis, author or later than its owner link',async()=>{
  const f=await incomingFixture(),stranger=await generateIdentity();
  const variants=[await sign({...f.request.payload,task_id:'different-parent-task'},f.reviewer),await sign({...f.request.payload,task_digest:'f'.repeat(64)},f.reviewer),await sign({...f.request.payload,basis_digest:'e'.repeat(64)},f.reviewer),await sign({...f.request.payload,requester_key:stranger.publicKey},stranger),await sign({...f.request.payload,issued_at:time(21)},f.reviewer)];
  for(const request of variants){const result=await verifyRepositoryCollaborationEvidence(await f.replaceRequest(request),f.service.publicKey);expect(result.valid).toBe(false);expect(result.revisionLinked).toBe(false);}
  const borrowed=await incomingFixture(true);const human=await sign({...borrowed.request.payload,requester_key:borrowed.reviewer.publicKey},borrowed.reviewer);expect((await verifyRepositoryCollaborationEvidence(await borrowed.replaceRequest(human),borrowed.service.publicKey)).valid).toBe(false);
 });
 it('rejects missing, wrong-source, out-of-time and read-only authorizations for the original suggesting agent',async()=>{
  const f=await incomingFixture(true),stranger=await generateIdentity(),g=f.grant!.payload;
  const grants=[await sign({...g,task_id:'different-parent-task'},f.owner),await sign({...g,issuer_key:stranger.publicKey},stranger),await sign({...g,agent_key:f.receiver.publicKey},f.owner),await sign({...g,permissions:['read_task'] as Array<'read_task'>},f.owner),await sign({...g,expires_at:time(11)},f.owner),await sign({...g,issued_at:time(13)},f.owner)];
  for(const grant of grants){const request=await sign({...f.request.payload,grant_digest:grant.digest},f.agent),result=await verifyRepositoryCollaborationEvidence(await f.replaceRequest(request,grant),f.service.publicKey);expect(result.valid).toBe(false);expect(result.revisionLinked).toBe(false);}
 });
 it('rejects a child provisioning request that silently changes the original requested model',async()=>{
  const f=await incomingFixture(),demo=f.bundle.demo!,request=await sign({...demo.payload.request.payload,proposed:{...demo.payload.request.payload.proposed,button_label:'Unrequested button'}},f.owner),provision=await sign({...demo.payload.provision!.payload,request_digest:request.digest},f.receiver),bundle={...f.bundle,demo:await sign({...demo.payload,request,provision},f.service)};
  const result=await verifyRepositoryCollaborationEvidence(bundle,f.service.publicKey);expect(result.valid).toBe(false);expect(result.revisionLinked).toBe(false);
 });
 it('preserves the frozen parent basis after a later acceptance without replacing its historical snapshot',async()=>{
  const f=await incomingFixture(true),frozen=canonical(f.bundle.parent),before=await verifyRepositoryCollaborationEvidence(f.bundle,f.service.publicKey);expect(before.valid,before.errors.join(';')).toBe(true);
  const acceptance=await sign<RepositoryAcceptance>({type:'scopeblind.repository.acceptance.v1',task_id:f.task.payload.id,task_digest:f.task.digest,outcome_digest:f.outcome.digest,reviewer_key:f.reviewer.publicKey,decision:'accept',issued_at:time(100),note:'Accepted later'},f.reviewer);
  const laterParent={type:'scopeblind.repository.evidence.v1' as const,state:await sign<RepositoryState>({...f.parentState.payload,acceptance,status:'accepted',revision:7,observed_at:time(101)},f.service)};expect((await verifyRepositoryEvidence(laterParent,f.service.publicKey)).valid).toBe(true);
  expect(canonical(f.bundle.parent)).toBe(frozen);expect((await verifyRepositoryCollaborationEvidence(f.bundle,f.service.publicKey)).valid).toBe(true);expect((await verifyRepositoryCollaborationEvidence({...f.bundle,parent:laterParent},f.service.publicKey)).valid).toBe(false);
 });
 it('does not label an unrelated unvalidated predecessor record as valid companion evidence',async()=>{
  const f=await fixture();for(const extra of [{parent_request:{forged:true}},{parent_agent_grant:{forged:true}},{parent:f.bundle.repository}])expect((await verifyRepositoryCollaborationEvidence({...f.bundle,...extra},f.service.publicKey)).valid).toBe(false);
 });
 it('requires one incoming link and rejects an unused agent grant attached to human feedback',async()=>{
  const f=await incomingFixture(),c=f.bundle.collaboration.payload,second=await sign({...c.revisions[0].payload,id:'second-parent-link'},f.owner);
  const ambiguous={...f.bundle,collaboration:await sign({...c,revisions:[...c.revisions,second]},f.service)};expect((await verifyRepositoryCollaborationEvidence(ambiguous,f.service.publicKey)).valid).toBe(false);
  const agent=await incomingFixture(true);expect((await verifyRepositoryCollaborationEvidence({...f.bundle,parent_agent_grant:agent.grant},f.service.publicKey)).valid).toBe(false);
 });
});
