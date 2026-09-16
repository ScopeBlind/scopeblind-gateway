/** Project-scoped human devices. Device signatures never become principal signatures. */
import {canonical,hexToBytes,verify,type Signed} from './coordination-protocol.js';
import type {RepositoryTask} from './coordination-repository.js';

export const REPOSITORY_DEVICE_DOMAIN='scopeblind.repository.device-authorization.v1\n';
export const REPOSITORY_DEVICE_ACTIONS=['repository_device_link_request','repository_device_link_status','repository_device_authorize','repository_device_confirm','repository_device_list','repository_device_revoke'] as const;
export type RepositoryDeviceAction=typeof REPOSITORY_DEVICE_ACTIONS[number];
export const REPOSITORY_DEVICE_PERMISSIONS=['read','claim','review','feedback','accept'] as const;
export type RepositoryDevicePermission=typeof REPOSITORY_DEVICE_PERMISSIONS[number];
export const REPOSITORY_DEVICE_LINK_MS=10*60*1000;
export const REPOSITORY_DEVICE_MAX_MS=7*86400000;

export interface RepositoryDeviceLink {
 type:'scopeblind.repository.device-link.v1';id:string;workspace_id:string;device_key:string;name:string;secret_hash:string;issued_at:string;expires_at:string;
}
export interface RepositoryDeviceAuthorization {
 type:'scopeblind.repository.device-authorization.v1';id:string;link_id:string;workspace_id:string;workspace_digest:string;
 member_id:string;member_revision:number;principal_key:string;device_key:string;device_name:string;
 actions:RepositoryDevicePermission[];authority_key:string;issued_at:string;expires_at:string;
}
export interface RepositoryDeviceConfirmation {
 type:'scopeblind.repository.device-confirmation.v1';authorization_digest:string;workspace_id:string;device_key:string;issued_at:string;
}
export interface RepositoryDeviceUse {
 type:'scopeblind.repository.device-use.v1';authorization_digest:string;workspace_id:string;workspace_digest:string;
 member_id:string;member_revision:number;principal_key:string;device_key:string;task_id:string;task_digest:string;
 payload_digest:string;action:RepositoryDevicePermission;recorded_at:string;
}
export type RepositoryDeviceStatus='pending'|'active'|'expired'|'revoked'|'membership_changed';
export interface RepositoryDeviceView {authorization:Signed<RepositoryDeviceAuthorization>;status:RepositoryDeviceStatus;confirmation:Signed<RepositoryDeviceConfirmation>|null;revoked_at?:string}
export interface RepositoryDeviceLinkState {type:'scopeblind.repository.device-link-state.v1';link:Signed<RepositoryDeviceLink>;status:'pending'|'authorized'|'expired';device:RepositoryDeviceView|null;observed_at:string}
export interface RepositoryDeviceListState {type:'scopeblind.repository.device-list.v1';workspace_id:string;viewer_key:string;devices:RepositoryDeviceView[];has_more:boolean;observed_at:string}
export interface RepositoryHumanContext {authorityKey:string;task?:Signed<RepositoryTask>;requireRecordedUse?:boolean}

const obj=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const exact=(v:Record<string,unknown>,required:string[],optional:string[]=[])=>required.every(k=>Object.hasOwn(v,k))&&Object.keys(v).every(k=>required.includes(k)||optional.includes(k));
const key=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const id=(v:unknown):v is string=>typeof v==='string'&&/^[A-Za-z0-9_-]{8,100}$/.test(v);
const name=(v:unknown)=>typeof v==='string'&&v===v.trim()&&v.length>0&&v.length<=60&&!/[\u0000-\u001f\u007f]/.test(v);
const time=(v:unknown):v is string=>typeof v==='string'&&Number.isFinite(Date.parse(v));
const period=(v:Record<string,unknown>,max:number)=>time(v.issued_at)&&time(v.expires_at)&&Date.parse(v.expires_at)>Date.parse(v.issued_at)&&Date.parse(v.expires_at)-Date.parse(v.issued_at)<=max;
const clean=(v:unknown):v is Signed<unknown>=>obj(v)&&exact(v,['payload','signer','digest','signature']);
export function validRepositoryDeviceLink(v:unknown):v is RepositoryDeviceLink{return obj(v)&&exact(v,['type','id','workspace_id','device_key','name','secret_hash','issued_at','expires_at'])&&v.type==='scopeblind.repository.device-link.v1'&&id(v.id)&&id(v.workspace_id)&&key(v.device_key)&&key(v.secret_hash)&&name(v.name)&&period(v,REPOSITORY_DEVICE_LINK_MS);}
export function validRepositoryDeviceAuthorization(v:unknown):v is RepositoryDeviceAuthorization{return obj(v)&&exact(v,['type','id','link_id','workspace_id','workspace_digest','member_id','member_revision','principal_key','device_key','device_name','actions','authority_key','issued_at','expires_at'])&&v.type==='scopeblind.repository.device-authorization.v1'&&[v.id,v.link_id,v.workspace_id,v.member_id].every(id)&&[v.workspace_digest,v.principal_key,v.device_key,v.authority_key].every(key)&&new Set([v.principal_key,v.device_key,v.authority_key]).size===3&&Number.isSafeInteger(v.member_revision)&&Number(v.member_revision)>0&&name(v.device_name)&&Array.isArray(v.actions)&&v.actions.includes('read')&&v.actions.length<=REPOSITORY_DEVICE_PERMISSIONS.length&&new Set(v.actions).size===v.actions.length&&v.actions.every(a=>REPOSITORY_DEVICE_PERMISSIONS.includes(a))&&period(v,REPOSITORY_DEVICE_MAX_MS);}
export function validRepositoryDeviceConfirmation(v:unknown):v is RepositoryDeviceConfirmation{return obj(v)&&exact(v,['type','authorization_digest','workspace_id','device_key','issued_at'])&&v.type==='scopeblind.repository.device-confirmation.v1'&&key(v.authorization_digest)&&key(v.device_key)&&id(v.workspace_id)&&time(v.issued_at);}
export async function verifyRepositoryDeviceAuthorization(value:unknown):Promise<boolean>{return clean(value)&&validRepositoryDeviceAuthorization(value.payload)&&await verify(value,value.payload.principal_key);}
export function repositoryDevicePreimage(payloadDigest:string,authorizationDigest:string){return REPOSITORY_DEVICE_DOMAIN+payloadDigest+'\n'+authorizationDigest;}
export function repositoryHumanPrincipal(value:Signed<unknown>){return value.repository_authorization?.payload.principal_key??value.signer;}
export function sameRepositoryHumanIntent(left:Signed<unknown>,right:Signed<unknown>):boolean {
 if(!validRepositoryHumanEnvelope(left)||!validRepositoryHumanEnvelope(right))return false;
 const {repository_authorization_use:ignoredLeft,...a}=left,{repository_authorization_use:ignoredRight,...b}=right;
 return canonical(a)===canonical(b);
}
export function repositoryDevicePermission(action:string):RepositoryDevicePermission|null {
 if(['repository_workspace_list','repository_workspace_get','repository_workspace_inbox','repository_workspace_task_get','repository_get','repository_export','repository_review_get','repository_review_export','repository_collaboration_get','repository_collaboration_export'].includes(action))return 'read';
 if(action==='repository_workspace_claim')return 'claim';
 if(action==='repository_approve')return 'review';
 if(action==='repository_review_feedback')return 'feedback';
 if(action==='repository_accept')return 'accept';
 return null;
}
/** Only these human statements may carry project-device authority. */
export function repositoryHumanPermission(value:Signed<unknown>):{action:RepositoryDevicePermission;at:string}|null {
 const p=value.payload,g=value.repository_authorization?.payload;if(!obj(p)||!g||!time(p.issued_at))return null;
 if(p.type==='scopeblind.coordination.request.v1'){
  const action=typeof p.action==='string'?repositoryDevicePermission(p.action):null;
  return action?{action,at:p.issued_at}:null;
 }
 const action=p.type==='scopeblind.repository.claim.v1'&&p.reviewer_key===g.principal_key?'claim':
  ['scopeblind.repository.approval.v1','scopeblind.repository.review-decision.v1'].includes(String(p.type))&&p.principal_key===g.principal_key?'review':
  p.type==='scopeblind.repository.acceptance.v1'&&p.reviewer_key===g.principal_key?'accept':
  p.type==='scopeblind.repository.review-feedback.v1'&&p.requester_key===g.principal_key&&!p.mandate_digest?'feedback':null;
 return action&&id(p.task_id)&&key(p.task_digest)?{action,at:p.issued_at}:null;
}
export function validRepositoryHumanEnvelope(value:unknown):value is Signed<unknown>{
 if(!obj(value))return false;
 if(!Object.hasOwn(value,'repository_authorization'))return clean(value);
 return exact(value,['payload','signer','digest','signature','repository_authorization','repository_authorization_signature'],['repository_authorization_use']);
}
/** Offline historical authority check. Live acceptance must also atomically check revocation/membership. */
export async function verifyRepositoryHuman<T>(value:Signed<T>,principal:string,context:RepositoryHumanContext):Promise<boolean>{
 try{
  if(!validRepositoryHumanEnvelope(value)||!key(principal))return false;
  if(!value.repository_authorization)return await verify(value,principal);
  const authorization=value.repository_authorization,g=authorization.payload;
  if(!await verifyRepositoryDeviceAuthorization(authorization)||g.authority_key!==context.authorityKey||g.principal_key!==principal||g.device_key!==value.signer||!await verify(value)||typeof value.repository_authorization_signature!=='string'||!/^[a-f0-9]{128}$/.test(value.repository_authorization_signature))return false;
  const publicKey=await crypto.subtle.importKey('raw',hexToBytes(value.signer),{name:'Ed25519'},false,['verify']);
  if(!await crypto.subtle.verify('Ed25519',publicKey,hexToBytes(value.repository_authorization_signature),new TextEncoder().encode(repositoryDevicePreimage(value.digest,authorization.digest))))return false;
  const permission=repositoryHumanPermission(value),p=value.payload as Record<string,unknown>;
  if(!permission||!g.actions.includes(permission.action)||Date.parse(permission.at)<Date.parse(g.issued_at)||Date.parse(permission.at)>=Date.parse(g.expires_at))return false;
  if(p.expires_at!==undefined&&(!time(p.expires_at)||Date.parse(p.expires_at)>Date.parse(g.expires_at)))return false;
  if(context.task&&(p.task_id!==context.task.payload.id||p.task_digest!==context.task.digest||context.task.payload.authority_key!==g.authority_key))return false;
  const use=value.repository_authorization_use;if(!use)return !context.requireRecordedUse;
  const u=use.payload;
  return clean(use)&&obj(u)&&exact(u,['type','authorization_digest','workspace_id','workspace_digest','member_id','member_revision','principal_key','device_key','task_id','task_digest','payload_digest','action','recorded_at'])&&u.type==='scopeblind.repository.device-use.v1'&&await verify(use,g.authority_key)&&u.authorization_digest===authorization.digest&&u.workspace_id===g.workspace_id&&u.workspace_digest===g.workspace_digest&&u.member_id===g.member_id&&u.member_revision===g.member_revision&&u.principal_key===g.principal_key&&u.device_key===g.device_key&&u.task_id===p.task_id&&u.task_digest===p.task_digest&&u.payload_digest===value.digest&&u.action===permission.action&&time(u.recorded_at)&&Date.parse(u.recorded_at)>=Date.parse(permission.at)&&Date.parse(u.recorded_at)<Date.parse(g.expires_at);
 }catch{return false;}
}
