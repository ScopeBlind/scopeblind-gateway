/** Repository suggestions through a reusable agent identity; never human or receiver authority. */
import {canonical,importIdentity,sign,verify,type RpcAction,type Signed} from './coordination-protocol.js';
import {CoordinationError} from './coordination-client.js';
import {readAgentProfile,updateAgentProfile,profileId,profileEntry,type ProfileRepositoryConnection} from './coordination-agent-profile.js';
import {repositoryRevisionBasis,validContactPage,validRepositoryRevisionRequest,type ContactPage,type RepositoryRevisionRequest} from './coordination-repository-collaboration.js';
import {verifyRepositoryCollaborationEvidence,type RepositoryCollaborationEvidence} from './coordination-repository-collaboration-evidence.js';

type Transport=(action:RpcAction,taskId:string,body:Record<string,unknown>)=>Promise<Record<string,unknown>>;
const exact=(v:unknown,keys:string[]):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
function fail(code:string,message:string):never{throw new CoordinationError(code,message);}
const hex=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
export function repositoryConnectionSummary(id:string,c:ProfileRepositoryConnection,agentKey:string){
 return {connection_id:id,purpose:'repository' as const,room_id:c.taskId,task_id:c.taskId,task_digest:c.taskDigest,principal_key:c.grant.payload.issuer_key,agent_key:agentKey,expires_at:c.grant.payload.expires_at,locally_expired:Date.parse(c.grant.payload.expires_at)<=Date.now(),same_profile_key:true,scope:c.grant.payload.permissions};
}
export class RepositoryAgentClient {
 constructor(private profilePath:string,private transport:Transport){}
 private profile(){return readAgentProfile(this.profilePath);}
 private async checked(response:Record<string,unknown>,taskId:string,grantId:string){
  const profile=this.profile(),e=response.evidence as RepositoryCollaborationEvidence;
  const checked=await verifyRepositoryCollaborationEvidence(e,profile.authorityKey);
  if(!checked.valid||!checked.authorityPinned||!response.repository_task||!response.collaboration||canonical(response.repository_task)!==canonical(e.repository.state)||canonical(response.collaboration)!==canonical(e.collaboration))fail('repository_evidence_invalid','The repository evidence did not verify against this profile’s pinned authority. No grant was saved or revision reported as recorded.');
  const s=e.repository.state.payload,c=e.collaboration.payload,task=s.task.payload,now=Date.now();
  if(task.id!==taskId||Math.abs(now-Date.parse(s.observed_at))>120000||Math.abs(now-Date.parse(c.observed_at))>120000)fail('repository_state_stale','Inspect this exact repository task again; the signed observation is stale or belongs to another task.');
  const entries=c.agent_grants.filter(entry=>entry.grant.payload.id===grantId);
  if(entries.length!==1)fail('repository_agent_grant_missing','The signed task does not contain this exact agent grant. Ask your person to authorize this profile’s public key.');
  const entry=entries[0],grant=entry.grant,g=grant.payload;
  if(entry.revoked||g.agent_key!==profile.agentKey||!g.permissions.includes('read_task')||Date.parse(g.issued_at)>now+60000||Date.parse(g.expires_at)<=now||Date.parse(task.expires_at)<=now)fail('repository_agent_grant_inactive','The exact repository grant is inactive, revoked, expired or belongs to another agent. No authority is inherited from another connection.');
  const saved=profileEntry(profile.repositoryConnections,grantId);if(saved&&(saved.taskId!==taskId||saved.taskDigest!==s.task.digest||saved.grant.digest!==grant.digest))fail('repository_agent_grant_conflict','This connection ID already names a different signed repository grant.');
  return {evidence:e,grant,connection:{taskId,taskDigest:s.task.digest,grant} satisfies ProfileRepositoryConnection};
 }
 private async read(taskId:string,grantId:string){
  if(!profileId(taskId)||!profileId(grantId))fail('invalid_repository_connection','Use the task_id and grant_id supplied by the person after they authorize this profile key.');
  const response=await this.transport('repository_agent_get',taskId,{grant_id:grantId});return this.checked(response,taskId,grantId);
 }
 private summary(e:RepositoryCollaborationEvidence){const s=e.repository.state.payload,c=e.collaboration.payload;return {task:s.task.payload,status:s.status,reviewer_key:s.reviewer?.payload.reviewer_key??null,proposal:s.proposal?.payload??null,preview:c.preview?.payload??null,current_basis_digest:repositoryRevisionBasis(s),approvals:s.approvals.map(a=>({principal_key:a.payload.principal_key,decision:a.payload.decision,expires_at:a.payload.expires_at})),outcome:s.outcome?.payload??null,acceptance:s.acceptance?.payload??null,revision_requests:c.requests.map(r=>({...r.payload,digest:r.digest})),revisions:c.revisions.map(r=>r.payload),observed_at:s.observed_at};}
 async inspect(taskId:string,grantId:string){
  const checked=await this.read(taskId,grantId);
  await updateAgentProfile(this.profilePath,p=>{const prior=profileEntry(p.repositoryConnections,grantId);if(prior&&prior.grant.digest!==checked.grant.digest)fail('repository_agent_grant_conflict','A different repository grant was saved concurrently.');p.repositoryConnections??=Object.create(null);Object.defineProperty(p.repositoryConnections,grantId,{value:checked.connection,enumerable:true,writable:true,configurable:true});});
  return {...repositoryConnectionSummary(grantId,checked.connection,this.profile().agentKey),...this.summary(checked.evidence),evidence:checked.evidence,next_step:'Read the verified task and exact current_basis_digest. If this grant permits request_revision, you may suggest only the supported contact-page model. Humans must review the suggestion, create any revision task, and approve its fresh exact snapshot. You cannot claim a human role, approve, accept, install a receiver, or execute a branch update.'};
 }
 async requestRevision(input:{connection_id:string;request_id:string;basis_digest:string;message:string;proposed:ContactPage}){
  if(!exact(input,['connection_id','request_id','basis_digest','message','proposed'])||!profileId(input.connection_id)||!profileId(input.request_id)||!hex(input.basis_digest)||typeof input.message!=='string'||!input.message.trim()||input.message.length>600||/[\u0000-\u001f\u007f]/.test(input.message)||!validContactPage(input.proposed))fail('invalid_repository_revision','Use a stable request_id, the exact inspected basis_digest, a brief message, and only the supported contact-page model.');
  const p=this.profile(),saved=profileEntry(p.repositoryConnections,input.connection_id);if(!saved)fail('unknown_repository_connection','Call coordination.inspect_repository with the person’s exact task and grant IDs first.');
  const pending=profileEntry(p.repositoryRevisions,input.request_id);
  if(pending&&(pending.connectionId!==input.connection_id||pending.request.payload.basis_digest!==input.basis_digest||pending.request.payload.message!==input.message||canonical(pending.request.payload.proposed)!==canonical(input.proposed)))fail('repository_revision_id_conflict','This request ID already names another exact suggestion. Preserve it for retries; use a new ID for a different intended revision.');
  const checked=await this.read(saved.taskId,input.connection_id),c=checked.evidence.collaboration.payload;
  if(!checked.grant.payload.permissions.includes('request_revision'))fail('repository_revision_outside_grant','This connection permits reading only. Ask the person to review any additional revision permission.');
  if(pending){
   if(!await verify(pending.request,p.agentKey))fail('repository_revision_invalid','The locally saved revision signature is invalid; it cannot be replayed.');
   if(c.requests.some(r=>r.digest===pending.request.digest))return this.recorded(input.connection_id,pending.request);
  }
  if(repositoryRevisionBasis(checked.evidence.repository.state.payload)!==input.basis_digest)fail('repository_revision_basis_stale','The task now has a different inspected change or result. Inspect it and ask whether a new suggestion is still appropriate; the saved suggestion was not rewritten.');
  if(!pending){
   const payload:RepositoryRevisionRequest={type:'scopeblind.repository.revision-request.v1',id:input.request_id,task_id:saved.taskId,task_digest:saved.taskDigest,basis_digest:input.basis_digest,requester_key:p.agentKey,grant_digest:checked.grant.digest,message:input.message,proposed:input.proposed,issued_at:new Date().toISOString()};
   if(!validRepositoryRevisionRequest(payload))fail('invalid_repository_revision','The proposed revision cannot be represented by this bounded protocol.');
   const request=await sign(payload,await importIdentity(p.privateKey,p.agentKey));
   await updateAgentProfile(this.profilePath,current=>{
    const prior=profileEntry(current.repositoryRevisions,input.request_id);if(prior&&(prior.connectionId!==input.connection_id||prior.request.payload.basis_digest!==input.basis_digest||prior.request.payload.message!==input.message||canonical(prior.request.payload.proposed)!==canonical(input.proposed)))fail('repository_revision_id_conflict','Another writer used this request ID for a different exact suggestion.');
    current.repositoryRevisions??=Object.create(null);if(!prior)Object.defineProperty(current.repositoryRevisions,input.request_id,{value:{connectionId:input.connection_id,request},enumerable:true,writable:true,configurable:true});
   });
  }
  const request=profileEntry(this.profile().repositoryRevisions,input.request_id)!.request;
  const response=await this.transport('repository_revision_request',saved.taskId,{request});
  const recorded=await this.checked(response,saved.taskId,input.connection_id);
  if(!recorded.evidence.collaboration.payload.requests.some(r=>r.digest===request.digest&&canonical(r)===canonical(request)))fail('repository_revision_unverified','The reply did not include this exact signed revision request. Retry the same request_id; its original signature is saved locally.');
  return this.recorded(input.connection_id,request);
 }
 private recorded(connectionId:string,request:Signed<RepositoryRevisionRequest>){return {connection_id:connectionId,request_id:request.payload.id,request_digest:request.digest,basis_digest:request.payload.basis_digest,status:'recorded',next_step:'The signed suggestion is recorded for human review. It did not create or approve a task, execute a change, or accept a result. Keep this request_id for retries.'};}
}
