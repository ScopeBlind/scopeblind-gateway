/** Durable client/project context. Membership and preparation authority never replace exact PR approvals. */
import { canonical, verify, type Signed } from './coordination-protocol.js';
import { REPOSITORY_HEX, REPOSITORY_ID, pathAllowed, repositoryBranch, repositoryPath } from './coordination-repository.js';
import { validRepositoryReviewContent, type RepositoryReviewContent } from './coordination-repository-review.js';

export const REPOSITORY_WORKSPACE_ACTIONS = [
 'repository_workspace_create','repository_workspace_get','repository_workspace_list','repository_workspace_inbox',
 'repository_workspace_invite','repository_workspace_join','repository_workspace_member_update',
 'repository_workspace_recovery_enroll','repository_workspace_recover',
 'repository_workspace_assign','repository_workspace_claim','repository_workspace_task_get',
 'repository_workspace_mandate','repository_workspace_adopt','repository_workspace_mandate_revoke',
 'repository_workspace_agent_get','repository_workspace_draft','repository_workspace_draft_decide',
] as const;
export type RepositoryWorkspaceAction = typeof REPOSITORY_WORKSPACE_ACTIONS[number];
export type WorkspaceRole = 'owner'|'reviewer'|'observer';
export interface RepositoryWorkspace {
 type:'scopeblind.repository.workspace.v1'; id:string; title:string; client_name:string;
 repository:string; base_branch:string; receiver_key:string; authority_key:string;
 owner_member_id:string; owner_key:string; issued_at:string; expires_at:string;
}
export interface WorkspaceInvitation {
 type:'scopeblind.repository.workspace-invitation.v1'; id:string; workspace_id:string; workspace_digest:string;
 member_id:string; role:'reviewer'|'observer'; display_name:string; issuer_key:string; secret_hash:string; issued_at:string; expires_at:string;
}
export interface WorkspaceMemberClaim {
 type:'scopeblind.repository.workspace-member-claim.v1'; workspace_id:string; invitation_digest:string; member_id:string; member_key:string; issued_at:string;
}
export interface WorkspaceMemberUpdate {
 type:'scopeblind.repository.workspace-member-update.v1'; id:string; workspace_id:string; member_id:string; expected_revision:number;
 role:'reviewer'|'observer'; status:'active'|'revoked'; issuer_key:string; issued_at:string;
}
export interface WorkspaceRecovery {
 type:'scopeblind.repository.workspace-recovery.v1'; id:string; workspace_id:string; member_id:string; member_key:string;
 recovery_key:string; expected_revision:number; issued_at:string; expires_at:string;
 previous_recovery_digest?:string;
}
export interface WorkspaceRotation {
 type:'scopeblind.repository.workspace-key-rotation.v1'; id:string; workspace_id:string; member_id:string;
 previous_key:string; new_key:string; recovery_digest:string; expected_revision:number; issued_at:string;
}
export interface WorkspaceRotationProof { recovery:Signed<WorkspaceRecovery>; rotation:Signed<WorkspaceRotation>; confirmation:Signed<WorkspaceRotation> }
export interface WorkspaceMember {
 member_id:string; display_name:string; role:WorkspaceRole; status:'active'|'revoked'; current_key:string; revision:number;
 invitation:Signed<WorkspaceInvitation>|null; claim:Signed<WorkspaceMemberClaim>|null;
 recovery:Signed<WorkspaceRecovery>|null; rotations:WorkspaceRotationProof[]; updates:Signed<WorkspaceMemberUpdate>[];
}
export interface WorkspaceTaskAssignment {
 type:'scopeblind.repository.workspace-task-assignment.v1'; workspace_id:string; workspace_digest:string; task_id:string; task_digest:string;
 owner_member_id:string; owner_key:string; owner_member_revision:number; reviewer_member_id:string; reviewer_key:string; reviewer_member_revision:number; review_brief_digest:string;
 source_draft_digest?:string; issued_at:string; expires_at:string;
}
export type WorkspaceAgentPermission = 'prepare_review'|'read_task'|'report_criteria'|'request_revision';
export interface WorkspacePreparationMandate {
 type:'scopeblind.repository.preparation-mandate.v1'; id:string; workspace_id:string; workspace_digest:string;
 mode:'prepare_review'; owner_member_id:string; owner_key:string; owner_member_revision:number; reviewer_member_id:string; reviewer_key:string; reviewer_member_revision:number; agent_key:string;
 repository:string; base_branch:string; allowed_paths:string[]; required_checks:Array<{name:string;app_id:number}>;
 permissions:WorkspaceAgentPermission[]; max_requests:number; max_open_requests:number; issued_at:string; expires_at:string;
}
export interface WorkspaceMandateRevocation { type:'scopeblind.repository.preparation-revocation.v1'; mandate_id:string; mandate_digest:string; workspace_id:string; principal_key:string; issued_at:string }
export interface WorkspaceMandateView {
 mandate:Signed<WorkspacePreparationMandate>; adoption:Signed<WorkspacePreparationMandate>|null;
 revocation:Signed<WorkspaceMandateRevocation>|null; status:'awaiting_reviewer'|'active'|'expired'|'revoked'|'membership_changed'|'exhausted';
 used_requests:number; open_requests:number;
}
export interface WorkspaceReviewDraft {
 type:'scopeblind.repository.workspace-review-draft.v1'; id:string; workspace_id:string; mandate_digest:string; agent_key:string;
 repository:string; pull_number:number; title:string; content:RepositoryReviewContent; allowed_paths:string[]; required_checks:Array<{name:string;app_id:number}>;
 suggested_preview_url?:string; observed_head_sha?:string; source?:{task_id:string;task_digest:string;basis_digest:string;packet_digest:string;feedback_digest:string}; issued_at:string;
}
export interface WorkspaceDraftDecision {
 type:'scopeblind.repository.workspace-draft-decision.v1'; workspace_id:string; draft_digest:string; owner_key:string;
 decision:'adopt'|'reject'; task_id?:string; task_digest?:string; note:string; issued_at:string;
}
export interface WorkspaceDraftView { draft:Signed<WorkspaceReviewDraft>; decision:Signed<WorkspaceDraftDecision>|null }
export interface RepositoryWorkspaceState {
 type:'scopeblind.repository.workspace-state.v1'; workspace:Signed<RepositoryWorkspace>; members:WorkspaceMember[];
 invitations:Signed<WorkspaceInvitation>[];
 assignments:Signed<WorkspaceTaskAssignment>[]; mandates:WorkspaceMandateView[]; drafts:WorkspaceDraftView[];
 viewer:{key:string;member_id:string|null;role:WorkspaceRole|null;capabilities:string[]}; observed_at:string;
}
export interface WorkspaceInvitationState {type:'scopeblind.repository.workspace-invitation-state.v1';workspace:Signed<RepositoryWorkspace>;invitation:Signed<WorkspaceInvitation>;status:'available'|'claimed'|'expired';observed_at:string}
export interface WorkspaceAttentionItem {
 id:string; workspace_id:string; task_id:string|null; title:string; state:string; who_waits:string;
 action:'review_draft'|'join_review'|'inspect'|'review_change'|'accept_result'|'read_feedback'|'reconcile'|'replace_review'|'adopt_mandate';
 target_digest:string; task_digest?:string; proposal_digest?:string; can_act:boolean; disabled_reason:string|null; href:string; updated_at:string;
}
export interface RepositoryWorkspaceInbox {
 type:'scopeblind.repository.workspace-inbox.v1'; viewer_key:string; items:WorkspaceAttentionItem[]; has_more:boolean; observed_at:string;
}
export interface RepositoryWorkspaceAgentState {
 type:'scopeblind.repository.workspace-agent-state.v1'; workspace:Signed<RepositoryWorkspace>; mandate:WorkspaceMandateView;
 members:WorkspaceMember[]; drafts:WorkspaceDraftView[]; observed_at:string;
}

const obj=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const exact=(v:Record<string,unknown>,req:string[],opt:string[]=[])=>req.every(k=>Object.hasOwn(v,k))&&Object.keys(v).every(k=>req.includes(k)||opt.includes(k));
const text=(v:unknown,max:number)=>typeof v==='string'&&v.trim().length>0&&v.length<=max&&!/[\u0000-\u001f\u007f]/.test(v);
const key=(v:unknown)=>typeof v==='string'&&REPOSITORY_HEX.test(v);
const id=(v:unknown)=>typeof v==='string'&&REPOSITORY_ID.test(v);
const at=(v:unknown)=>typeof v==='string'&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString()===v;
const period=(v:Record<string,unknown>,max:number)=>at(v.issued_at)&&at(v.expires_at)&&Date.parse(String(v.expires_at))>Date.parse(String(v.issued_at))&&Date.parse(String(v.expires_at))-Date.parse(String(v.issued_at))<=max;
const repo=(v:unknown)=>typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(v);
const paths=(v:unknown):v is string[]=>Array.isArray(v)&&v.length>0&&v.length<=12&&new Set(v).size===v.length&&v.every(p=>typeof p==='string'&&repositoryPath(p.endsWith('/**')?p.slice(0,-3):p)&&pathAllowed(p.endsWith('/**')?p.slice(0,-2)+'placeholder':p,[p]));
const checks=(v:unknown)=>Array.isArray(v)&&v.length>0&&v.length<=12&&v.every(c=>obj(c)&&exact(c,['name','app_id'])&&text(c.name,100)&&Number.isSafeInteger(c.app_id)&&Number(c.app_id)>0)&&new Set(v.map(c=>c.name)).size===v.length;
const revision=(v:unknown)=>Number.isSafeInteger(v)&&Number(v)>0;
/** A subtree grant can narrow to a subtree or file. An exact file never widens to a subtree. */
export function workspacePathsWithin(proposed:string[],allowed:string[]){return proposed.every(path=>path.endsWith('/**')?allowed.some(rule=>rule.endsWith('/**')&&(path===rule||path.slice(0,-3).startsWith(rule.slice(0,-2)))):pathAllowed(path,allowed));}
export function validRepositoryWorkspace(v:unknown):v is RepositoryWorkspace {return obj(v)&&exact(v,['type','id','title','client_name','repository','base_branch','receiver_key','authority_key','owner_member_id','owner_key','issued_at','expires_at'])&&v.type==='scopeblind.repository.workspace.v1'&&id(v.id)&&id(v.owner_member_id)&&text(v.title,100)&&text(v.client_name,100)&&repo(v.repository)&&repositoryBranch(v.base_branch)&&[v.owner_key,v.receiver_key,v.authority_key].every(key)&&new Set([v.owner_key,v.receiver_key,v.authority_key]).size===3&&period(v,365*86400000);}
export function validWorkspaceInvitation(v:unknown):v is WorkspaceInvitation {return obj(v)&&exact(v,['type','id','workspace_id','workspace_digest','member_id','role','display_name','issuer_key','secret_hash','issued_at','expires_at'])&&v.type==='scopeblind.repository.workspace-invitation.v1'&&[v.id,v.workspace_id,v.member_id].every(id)&&[v.workspace_digest,v.issuer_key,v.secret_hash].every(key)&&['reviewer','observer'].includes(String(v.role))&&text(v.display_name,60)&&period(v,7*86400000);}
export function validWorkspaceMemberClaim(v:unknown):v is WorkspaceMemberClaim {return obj(v)&&exact(v,['type','workspace_id','invitation_digest','member_id','member_key','issued_at'])&&v.type==='scopeblind.repository.workspace-member-claim.v1'&&[v.workspace_id,v.member_id].every(id)&&[v.invitation_digest,v.member_key].every(key)&&at(v.issued_at);}
export function validWorkspaceMemberUpdate(v:unknown):v is WorkspaceMemberUpdate {return obj(v)&&exact(v,['type','id','workspace_id','member_id','expected_revision','role','status','issuer_key','issued_at'])&&v.type==='scopeblind.repository.workspace-member-update.v1'&&[v.id,v.workspace_id,v.member_id].every(id)&&key(v.issuer_key)&&revision(v.expected_revision)&&['reviewer','observer'].includes(String(v.role))&&['active','revoked'].includes(String(v.status))&&at(v.issued_at);}
export function validWorkspaceRecovery(v:unknown):v is WorkspaceRecovery {return obj(v)&&exact(v,['type','id','workspace_id','member_id','member_key','recovery_key','expected_revision','issued_at','expires_at'],['previous_recovery_digest'])&&v.type==='scopeblind.repository.workspace-recovery.v1'&&[v.id,v.workspace_id,v.member_id].every(id)&&[v.member_key,v.recovery_key].every(key)&&v.member_key!==v.recovery_key&&revision(v.expected_revision)&&(v.previous_recovery_digest===undefined||key(v.previous_recovery_digest))&&period(v,365*86400000);}
export function validWorkspaceRotation(v:unknown):v is WorkspaceRotation {return obj(v)&&exact(v,['type','id','workspace_id','member_id','previous_key','new_key','recovery_digest','expected_revision','issued_at'])&&v.type==='scopeblind.repository.workspace-key-rotation.v1'&&[v.id,v.workspace_id,v.member_id].every(id)&&[v.previous_key,v.new_key,v.recovery_digest].every(key)&&v.previous_key!==v.new_key&&revision(v.expected_revision)&&at(v.issued_at);}
export function validWorkspaceTaskAssignment(v:unknown):v is WorkspaceTaskAssignment {return obj(v)&&exact(v,['type','workspace_id','workspace_digest','task_id','task_digest','owner_member_id','owner_key','owner_member_revision','reviewer_member_id','reviewer_key','reviewer_member_revision','review_brief_digest','issued_at','expires_at'],['source_draft_digest'])&&v.type==='scopeblind.repository.workspace-task-assignment.v1'&&[v.workspace_id,v.task_id,v.owner_member_id,v.reviewer_member_id].every(id)&&[v.workspace_digest,v.task_digest,v.owner_key,v.reviewer_key,v.review_brief_digest].every(key)&&v.owner_key!==v.reviewer_key&&v.owner_member_id!==v.reviewer_member_id&&revision(v.owner_member_revision)&&revision(v.reviewer_member_revision)&&(v.source_draft_digest===undefined||key(v.source_draft_digest))&&period(v,7*86400000);}
export function validWorkspacePreparationMandate(v:unknown):v is WorkspacePreparationMandate {return obj(v)&&exact(v,['type','id','workspace_id','workspace_digest','mode','owner_member_id','owner_key','owner_member_revision','reviewer_member_id','reviewer_key','reviewer_member_revision','agent_key','repository','base_branch','allowed_paths','required_checks','permissions','max_requests','max_open_requests','issued_at','expires_at'])&&v.type==='scopeblind.repository.preparation-mandate.v1'&&v.mode==='prepare_review'&&[v.id,v.workspace_id,v.owner_member_id,v.reviewer_member_id].every(id)&&[v.workspace_digest,v.owner_key,v.reviewer_key,v.agent_key].every(key)&&new Set([v.owner_key,v.reviewer_key,v.agent_key]).size===3&&revision(v.owner_member_revision)&&revision(v.reviewer_member_revision)&&repo(v.repository)&&repositoryBranch(v.base_branch)&&paths(v.allowed_paths)&&checks(v.required_checks)&&Array.isArray(v.permissions)&&v.permissions.includes('prepare_review')&&v.permissions.length<=4&&new Set(v.permissions).size===v.permissions.length&&v.permissions.every(p=>['prepare_review','read_task','report_criteria','request_revision'].includes(String(p)))&&Number.isSafeInteger(v.max_requests)&&Number(v.max_requests)>0&&Number(v.max_requests)<=20&&Number.isSafeInteger(v.max_open_requests)&&Number(v.max_open_requests)>0&&Number(v.max_open_requests)<=3&&Number(v.max_open_requests)<=Number(v.max_requests)&&period(v,7*86400000);}
export function validWorkspaceMandateRevocation(v:unknown):v is WorkspaceMandateRevocation {return obj(v)&&exact(v,['type','mandate_id','mandate_digest','workspace_id','principal_key','issued_at'])&&v.type==='scopeblind.repository.preparation-revocation.v1'&&[v.mandate_id,v.workspace_id].every(id)&&[v.mandate_digest,v.principal_key].every(key)&&at(v.issued_at);}
export function validWorkspaceReviewDraft(v:unknown):v is WorkspaceReviewDraft {return obj(v)&&exact(v,['type','id','workspace_id','mandate_digest','agent_key','repository','pull_number','title','content','allowed_paths','required_checks','issued_at'],['suggested_preview_url','observed_head_sha','source'])&&v.type==='scopeblind.repository.workspace-review-draft.v1'&&[v.id,v.workspace_id].every(id)&&[v.mandate_digest,v.agent_key].every(key)&&repo(v.repository)&&Number.isSafeInteger(v.pull_number)&&Number(v.pull_number)>0&&text(v.title,140)&&validRepositoryReviewContent(v.content)&&paths(v.allowed_paths)&&checks(v.required_checks)&&at(v.issued_at)&&(v.source===undefined||obj(v.source)&&exact(v.source,['task_id','task_digest','basis_digest','packet_digest','feedback_digest'])&&id(v.source.task_id)&&[v.source.task_digest,v.source.basis_digest,v.source.packet_digest,v.source.feedback_digest].every(key))&&(v.observed_head_sha===undefined||typeof v.observed_head_sha==='string'&&/^[a-f0-9]{40}$/.test(v.observed_head_sha))&&(v.suggested_preview_url===undefined||typeof v.suggested_preview_url==='string'&&v.suggested_preview_url.length<=2000&&safeWorkspacePreview(v.suggested_preview_url));}
export function safeWorkspacePreview(value:string){try{const u=new URL(value);return u.protocol==='https:'&&!u.username&&!u.password&&!u.hash;}catch{return false;}}
export function validWorkspaceDraftDecision(v:unknown):v is WorkspaceDraftDecision {return obj(v)&&exact(v,['type','workspace_id','draft_digest','owner_key','decision','note','issued_at'],['task_id','task_digest'])&&v.type==='scopeblind.repository.workspace-draft-decision.v1'&&id(v.workspace_id)&&[v.draft_digest,v.owner_key].every(key)&&['adopt','reject'].includes(String(v.decision))&&typeof v.note==='string'&&v.note.length<=600&&at(v.issued_at)&&(v.decision==='adopt'?id(v.task_id)&&key(v.task_digest):v.task_id===undefined&&v.task_digest===undefined);}

const cleanEnvelope=(v:unknown):v is Signed<unknown>=>obj(v)&&exact(v,['payload','signer','digest','signature']);
const before=(time:string,observation:string)=>Date.parse(time)<=Date.parse(observation);
function memberAt(member:WorkspaceMember,time:string,workspace:RepositoryWorkspace){
 let current=member.claim?.payload.member_key??workspace.owner_key,role:WorkspaceRole=member.invitation?.payload.role??'owner',status:'active'|'revoked'='active',revision=1;
 const events=[...member.rotations.map(p=>({at:p.rotation.payload.issued_at,revision:p.rotation.payload.expected_revision,rotation:p.rotation.payload,update:null})),...member.updates.map(u=>({at:u.payload.issued_at,revision:u.payload.expected_revision,rotation:null,update:u.payload}))].sort((a,b)=>a.revision-b.revision);
 for(const e of events)if(before(e.at,time)){if(e.rotation)current=e.rotation.new_key;if(e.update){role=e.update.role;status=e.update.status;}revision=e.revision+1;}
 return {key:current,role,status,revision};
}
function memberRevisionAt(member:WorkspaceMember,wanted:number,time:string,workspace:RepositoryWorkspace){
 if(!Number.isSafeInteger(wanted)||wanted<1||wanted>member.revision)return null;
 let current=member.claim?.payload.member_key??workspace.owner_key,role:WorkspaceRole=member.invitation?.payload.role??'owner',status:'active'|'revoked'='active',start=member.claim?.payload.issued_at??workspace.issued_at;
 const events=[...member.rotations.map(p=>({at:p.rotation.payload.issued_at,revision:p.rotation.payload.expected_revision,rotation:p.rotation.payload,update:null})),...member.updates.map(u=>({at:u.payload.issued_at,revision:u.payload.expected_revision,rotation:null,update:u.payload}))].sort((a,b)=>a.revision-b.revision);
 for(const e of events){if(e.revision>=wanted){if(Date.parse(time)>Date.parse(e.at))return null;break;}if(e.rotation)current=e.rotation.new_key;if(e.update){role=e.update.role;status=e.update.status;}start=e.at;}
 return Date.parse(time)>=Date.parse(start)?{key:current,role,status,revision:wanted}:null;
}
function historicalMemberKeys(member:WorkspaceMember,workspace:RepositoryWorkspace){return [...new Set([member.claim?.payload.member_key??workspace.owner_key,member.current_key,...member.rotations.flatMap(p=>[p.rotation.payload.previous_key,p.rotation.payload.new_key])])];}
function memberRecoveryKeys(member:WorkspaceMember){return [...new Set([...(member.recovery?[member.recovery.payload.recovery_key]:[]),...member.rotations.map(p=>p.recovery.payload.recovery_key)])];}
function ownerKeyAt(owner:WorkspaceMember,key:string,time:string,workspace:RepositoryWorkspace){for(let r=1;r<=owner.revision;r++){const state=memberRevisionAt(owner,r,time,workspace);if(state?.key===key&&state.role==='owner'&&state.status==='active')return true;}return false;}
async function checkedMembers(workspace:Signed<RepositoryWorkspace>,members:WorkspaceMember[],observation:string){
 const w=workspace.payload;if(!cleanEnvelope(workspace)||!validRepositoryWorkspace(w)||!await verify(workspace,w.owner_key)||!at(observation)||!before(w.issued_at,observation)||!Array.isArray(members)||!members.length||members.length>20||new Set(members.map(m=>m.member_id)).size!==members.length||new Set(members.map(m=>m.current_key)).size!==members.length)return false;
 const humans=members.flatMap(m=>historicalMemberKeys(m,w)),recoveries=members.flatMap(memberRecoveryKeys);if(new Set(humans).size!==humans.length||humans.some(k=>[w.authority_key,w.receiver_key].includes(k))||recoveries.some(k=>[w.authority_key,w.receiver_key,...humans].includes(k)))return false;
 const owner=members.find(m=>m.member_id===w.owner_member_id);if(!owner||owner.invitation||owner.claim||owner.role!=='owner'||owner.updates.length)return false;
 for(const m of [owner,...members.filter(m=>m!==owner)]){
  if(!exact(m as unknown as Record<string,unknown>,['member_id','display_name','role','status','current_key','revision','invitation','claim','recovery','rotations','updates'])||!id(m.member_id)||!text(m.display_name,60)||!key(m.current_key)||!revision(m.revision)||!['owner','reviewer','observer'].includes(m.role)||!['active','revoked'].includes(m.status)||!Array.isArray(m.rotations)||m.rotations.length>12||!Array.isArray(m.updates)||m.updates.length>40)return false;
  let current=w.owner_key,previousAt=w.issued_at;
  if(m!==owner){const invitation=m.invitation,claim=m.claim;if(!invitation||!claim||!cleanEnvelope(invitation)||!cleanEnvelope(claim)||!validWorkspaceInvitation(invitation.payload)||!validWorkspaceMemberClaim(claim.payload))return false;const i=invitation.payload,c=claim.payload;if(i.workspace_id!==w.id||i.workspace_digest!==workspace.digest||i.member_id!==m.member_id||!ownerKeyAt(owner,i.issuer_key,i.issued_at,w)||c.workspace_id!==w.id||c.member_id!==m.member_id||c.invitation_digest!==invitation.digest||Date.parse(c.issued_at)<Date.parse(i.issued_at)||Date.parse(c.issued_at)>=Date.parse(i.expires_at)||!before(c.issued_at,observation)||!await verify(invitation,i.issuer_key)||!await verify(claim,c.member_key))return false;current=c.member_key;previousAt=c.issued_at;}
  const events=[...m.rotations.map(p=>({revision:p.rotation.payload.expected_revision,rotation:p,update:null})),...m.updates.map(u=>({revision:u.payload.expected_revision,rotation:null,update:u}))].sort((a,b)=>a.revision-b.revision);
  if(events.length!==m.revision-1)return false;
  for(let index=0;index<events.length;index++){const event=events[index];if(event.revision!==index+1)return false;
   if(event.rotation){const p=event.rotation,r=p.rotation.payload,g=p.recovery.payload;if(!exact(p as unknown as Record<string,unknown>,['recovery','rotation','confirmation'])||![p.recovery,p.rotation,p.confirmation].every(cleanEnvelope)||!validWorkspaceRecovery(g)||!validWorkspaceRotation(r)||g.workspace_id!==w.id||g.member_id!==m.member_id||g.member_key!==current||g.expected_revision>r.expected_revision||memberRevisionAt(m,g.expected_revision,g.issued_at,w)?.key!==g.member_key||memberRevisionAt(m,g.expected_revision,g.issued_at,w)?.status!=='active'||r.workspace_id!==w.id||r.member_id!==m.member_id||r.previous_key!==current||r.recovery_digest!==p.recovery.digest||p.confirmation.digest!==p.rotation.digest||Date.parse(r.issued_at)<Date.parse(g.issued_at)||Date.parse(r.issued_at)<Date.parse(previousAt)||Date.parse(r.issued_at)>=Date.parse(g.expires_at)||!before(r.issued_at,observation)||!await verify(p.recovery,current)||!await verify(p.rotation,g.recovery_key)||!await verify(p.confirmation,r.new_key))return false;current=r.new_key;previousAt=r.issued_at;}
   else{const u=event.update!,p=u.payload;if(!cleanEnvelope(u)||!validWorkspaceMemberUpdate(p)||p.workspace_id!==w.id||p.member_id!==m.member_id||!ownerKeyAt(owner,p.issuer_key,p.issued_at,w)||Date.parse(p.issued_at)<Date.parse(previousAt)||!before(p.issued_at,observation)||!await verify(u,p.issuer_key))return false;previousAt=p.issued_at;}
  }
  const observed=memberAt(m,observation,w);if(current!==m.current_key||observed.role!==m.role||observed.status!==m.status||observed.revision!==m.revision)return false;
  if(m.recovery){const g=m.recovery.payload;if(!cleanEnvelope(m.recovery)||!validWorkspaceRecovery(g)||g.workspace_id!==w.id||g.member_id!==m.member_id||g.member_key!==m.current_key||g.expected_revision>m.revision||memberRevisionAt(m,g.expected_revision,g.issued_at,w)?.key!==g.member_key||memberRevisionAt(m,g.expected_revision,g.issued_at,w)?.status!=='active'||!before(g.issued_at,observation)||!await verify(m.recovery,m.current_key))return false;}
 }
 return true;
}
async function checkedMandate(view:WorkspaceMandateView,workspace:Signed<RepositoryWorkspace>,members:WorkspaceMember[],observation:string){
 if(!obj(view)||!exact(view as unknown as Record<string,unknown>,['mandate','adoption','revocation','status','used_requests','open_requests'])||!cleanEnvelope(view.mandate)||!validWorkspacePreparationMandate(view.mandate.payload))return false;
 const p=view.mandate.payload,w=workspace.payload,o=members.find(m=>m.member_id===p.owner_member_id),r=members.find(m=>m.member_id===p.reviewer_member_id);if(!o||!r)return false;
 const owner=memberRevisionAt(o,p.owner_member_revision,p.issued_at,w),reviewer=memberRevisionAt(r,p.reviewer_member_revision,p.issued_at,w);if(!owner||!reviewer||p.workspace_id!==w.id||p.workspace_digest!==workspace.digest||p.repository!==w.repository||p.base_branch!==w.base_branch||p.owner_key!==owner.key||p.reviewer_key!==reviewer.key||owner.role!=='owner'||reviewer.role!=='reviewer'||owner.status!=='active'||reviewer.status!=='active'||[w.receiver_key,w.authority_key,...members.flatMap(m=>historicalMemberKeys(m,w)),...members.flatMap(memberRecoveryKeys)].includes(p.agent_key)||!before(p.issued_at,observation)||Date.parse(p.expires_at)>Date.parse(w.expires_at)||!await verify(view.mandate,p.owner_key)||!Number.isSafeInteger(view.used_requests)||view.used_requests<0||view.used_requests>p.max_requests||!Number.isSafeInteger(view.open_requests)||view.open_requests<0||view.open_requests>p.max_open_requests||view.open_requests>view.used_requests)return false;
 if(view.adoption&&(!cleanEnvelope(view.adoption)||view.adoption.digest!==view.mandate.digest||canonical(view.adoption.payload)!==canonical(p)||!await verify(view.adoption,p.reviewer_key)))return false;
 if(view.revocation){const rev=view.revocation.payload;if(!cleanEnvelope(view.revocation)||!validWorkspaceMandateRevocation(rev)||rev.workspace_id!==w.id||rev.mandate_id!==p.id||rev.mandate_digest!==view.mandate.digest||![p.owner_key,p.reviewer_key].includes(rev.principal_key)||!before(rev.issued_at,observation)||!await verify(view.revocation,rev.principal_key))return false;}
 const nowO=memberAt(o,observation,w),nowR=memberAt(r,observation,w),expected=view.revocation?'revoked':nowO.key!==p.owner_key||nowR.key!==p.reviewer_key||nowO.revision!==p.owner_member_revision||nowR.revision!==p.reviewer_member_revision||nowO.role!=='owner'||nowR.role!=='reviewer'||nowO.status!=='active'||nowR.status!=='active'?'membership_changed':Date.parse(p.expires_at)<=Date.parse(observation)?'expired':!view.adoption?'awaiting_reviewer':view.used_requests>=p.max_requests?'exhausted':'active';return view.status===expected;
}
async function checkedDraft(view:WorkspaceDraftView,workspace:Signed<RepositoryWorkspace>,members:WorkspaceMember[],mandates:WorkspaceMandateView[],observation:string){
 if(!obj(view)||!exact(view as unknown as Record<string,unknown>,['draft','decision'])||!cleanEnvelope(view.draft)||!validWorkspaceReviewDraft(view.draft.payload))return false;const p=view.draft.payload,m=mandates.find(m=>m.mandate.digest===p.mandate_digest),g=m?.mandate.payload;if(!g||!m?.adoption||p.workspace_id!==workspace.payload.id||p.agent_key!==g.agent_key||p.repository!==g.repository||Date.parse(p.issued_at)<Date.parse(g.issued_at)||Date.parse(p.issued_at)>=Date.parse(g.expires_at)||!before(p.issued_at,observation)||!await verify(view.draft,g.agent_key)||!workspacePathsWithin(p.allowed_paths,g.allowed_paths)||!g.required_checks.every(c=>p.required_checks.some(r=>canonical(r)===canonical(c)))||p.required_checks.some(c=>g.required_checks.some(r=>r.name===c.name&&r.app_id!==c.app_id)))return false;
 if(view.decision){const d=view.decision.payload,owner=members.find(m=>m.member_id===workspace.payload.owner_member_id);if(!owner||!cleanEnvelope(view.decision)||!validWorkspaceDraftDecision(d)||d.workspace_id!==workspace.payload.id||d.draft_digest!==view.draft.digest||!ownerKeyAt(owner,d.owner_key,d.issued_at,workspace.payload)||!before(d.issued_at,observation)||!await verify(view.decision,d.owner_key))return false;}return true;
}
/** Verifies signatures and membership history. Live state remains a service observation, never an effect grant. */
export async function verifyRepositoryWorkspaceState(value:unknown,authorityKey:string,viewerKey?:string):Promise<boolean>{try{const e=value as Signed<RepositoryWorkspaceState>,s=e.payload;if(!cleanEnvelope(e)||!s||!exact(s as unknown as Record<string,unknown>,['type','workspace','members','invitations','assignments','mandates','drafts','viewer','observed_at'])||s.type!=='scopeblind.repository.workspace-state.v1'||!await verify(e,authorityKey)||s.workspace.payload.authority_key!==authorityKey||viewerKey&&s.viewer.key!==viewerKey||!await checkedMembers(s.workspace,s.members,s.observed_at)||!Array.isArray(s.invitations)||s.invitations.length>40||!Array.isArray(s.assignments)||s.assignments.length>100||!Array.isArray(s.mandates)||s.mandates.length>40||!Array.isArray(s.drafts)||s.drafts.length>100)return false;
 const viewer=s.members.find(m=>m.current_key===s.viewer.key);if(!obj(s.viewer)||!exact(s.viewer as unknown as Record<string,unknown>,['key','member_id','role','capabilities'])||!viewer||viewer.status!=='active'||s.viewer.member_id!==viewer.member_id||s.viewer.role!==viewer.role||canonical(s.viewer.capabilities)!==canonical(viewer.role==='owner'?['read','invite','assign','prepare_mandate','review_draft','recover']:viewer.role==='reviewer'?['read','review','adopt_mandate','recover']:['read','recover']))return false;
 const owner=s.members.find(m=>m.member_id===s.workspace.payload.owner_member_id)!;for(const i of s.invitations)if(!cleanEnvelope(i)||!validWorkspaceInvitation(i.payload)||i.payload.workspace_id!==s.workspace.payload.id||i.payload.workspace_digest!==s.workspace.digest||!ownerKeyAt(owner,i.payload.issuer_key,i.payload.issued_at,s.workspace.payload)||!before(i.payload.issued_at,s.observed_at)||!await verify(i,i.payload.issuer_key))return false;
 for(const a of s.assignments){const p=a.payload,o=s.members.find(m=>m.member_id===p.owner_member_id),r=s.members.find(m=>m.member_id===p.reviewer_member_id);if(!cleanEnvelope(a)||!validWorkspaceTaskAssignment(p)||!o||!r||p.workspace_id!==s.workspace.payload.id||p.workspace_digest!==s.workspace.digest||p.owner_key!==memberRevisionAt(o,p.owner_member_revision,p.issued_at,s.workspace.payload)?.key||p.reviewer_key!==memberRevisionAt(r,p.reviewer_member_revision,p.issued_at,s.workspace.payload)?.key||memberRevisionAt(o,p.owner_member_revision,p.issued_at,s.workspace.payload)?.role!=='owner'||memberRevisionAt(o,p.owner_member_revision,p.issued_at,s.workspace.payload)?.status!=='active'||memberRevisionAt(r,p.reviewer_member_revision,p.issued_at,s.workspace.payload)?.role!=='reviewer'||memberRevisionAt(r,p.reviewer_member_revision,p.issued_at,s.workspace.payload)?.status!=='active'||!before(p.issued_at,s.observed_at)||!await verify(a,p.owner_key))return false;}
 for(const m of s.mandates)if(!await checkedMandate(m,s.workspace,s.members,s.observed_at))return false;for(const d of s.drafts)if(!await checkedDraft(d,s.workspace,s.members,s.mandates,s.observed_at))return false;return true;
 }catch{return false;}}
export async function verifyRepositoryWorkspaceAgentState(value:unknown,authorityKey:string,agentKey?:string):Promise<boolean>{try{const e=value as Signed<RepositoryWorkspaceAgentState>,s=e.payload;if(!cleanEnvelope(e)||!s||!exact(s as unknown as Record<string,unknown>,['type','workspace','members','mandate','drafts','observed_at'])||s.type!=='scopeblind.repository.workspace-agent-state.v1'||!await verify(e,authorityKey)||s.workspace.payload.authority_key!==authorityKey||agentKey&&s.mandate.mandate.payload.agent_key!==agentKey||!await checkedMembers(s.workspace,s.members,s.observed_at)||!await checkedMandate(s.mandate,s.workspace,s.members,s.observed_at)||!Array.isArray(s.drafts)||s.drafts.length>20||s.drafts.length!==s.mandate.used_requests||s.drafts.filter(d=>!d.decision).length!==s.mandate.open_requests)return false;for(const d of s.drafts)if(!await checkedDraft(d,s.workspace,s.members,[s.mandate],s.observed_at))return false;return true;}catch{return false;}}
