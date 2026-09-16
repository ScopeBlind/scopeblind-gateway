/** Explicit, room-bound human device delegation. Raw signature verification stays separate. */
import {canonical,hexToBytes,verify,type Signed} from './coordination-protocol';
import type {NegotiationApproval,NegotiationProposal} from './coordination-negotiation';
export const DEVICE_AUTHORIZATION_DOMAIN='scopeblind.coordination.device-authorization.v1\n';
export const DEVICE_ACTIONS=['inspect','decision_inbox','negotiation_get','decide','accept','negotiation_mandate','negotiation_approve'] as const;
export type DevicePermission=typeof DEVICE_ACTIONS[number];
export type DeviceAction='device_link_request'|'device_link_status'|'device_authorize'|'device_list'|'device_revoke';
export const DEVICE_LINK_TTL_MS=10*60*1000;
export const DEVICE_MAX_TTL_MS=7*24*60*60*1000;
export interface DeviceLinkRequest {type:'scopeblind.coordination.device-link.v1';id:string;device_key:string;name:string;secret_hash:string;issued_at:string;expires_at:string}
export interface DeviceAuthorization {type:'scopeblind.coordination.device-authorization.v1';id:string;link_id:string;room_id:string;agreement_digest:string;principal_key:string;device_key:string;device_name:string;actions:DevicePermission[];issued_at:string;expires_at:string;authority_key:string}
export interface DeviceUse {type:'scopeblind.coordination.device-use.v1';authorization_digest:string;principal_key:string;device_key:string;room_id:string;payload_digest:string;action:DevicePermission;recorded_at:string}
export interface DeviceAuthorizationView {authorization:Signed<DeviceAuthorization>;status:'active'|'expired'|'revoked';revoked_at?:string}
export interface DeviceListState {ok:true;authorizations:DeviceAuthorizationView[];has_more:boolean;capability?:{room_id:string;can_authorize:boolean}}
export interface DeviceLinkState {ok:true;link:Signed<DeviceLinkRequest>;status:'pending'|'authorized'|'expired';authorization?:Signed<DeviceAuthorization>}
export interface HumanContext {authorityKey?:string;proposal?:Signed<NegotiationProposal>;approval?:Signed<NegotiationApproval>;requireRecordedUse?:boolean}
const hex=(value:unknown):value is string=>typeof value==='string'&&/^[0-9a-f]{64}$/.test(value);
const id=(value:unknown):value is string=>typeof value==='string'&&/^[A-Za-z0-9_-]{8,100}$/.test(value);
const object=(value:unknown):value is Record<string,unknown>=>!!value&&typeof value==='object'&&!Array.isArray(value);
const time=(value:unknown)=>typeof value==='string'?Date.parse(value):NaN;
const exact=(value:object,fields:string)=>Object.keys(value).sort().join(' ')===fields.split(' ').sort().join(' ');
export function deviceAuthorizationPreimage(payloadDigest:string,authorizationDigest:string){return DEVICE_AUTHORIZATION_DOMAIN+payloadDigest+'\n'+authorizationDigest;}
/** Claimed principal only. Call verifyHuman before trusting this identity. */
export function humanPrincipal(value:Signed<unknown>):string {return value.authorization?.payload.principal_key??value.signer;}
export async function verifyDeviceAuthorization(value:Signed<DeviceAuthorization>):Promise<boolean>{
 try{const g=value.payload;return exact(value,'payload signer digest signature')&&await verify(value,g.principal_key)&&exact(g,'type id link_id room_id agreement_digest principal_key device_key device_name actions issued_at expires_at authority_key')&&g.type==='scopeblind.coordination.device-authorization.v1'&&id(g.id)&&id(g.link_id)&&id(g.room_id)&&hex(g.agreement_digest)&&hex(g.principal_key)&&hex(g.device_key)&&g.device_key!==g.principal_key&&hex(g.authority_key)&&typeof g.device_name==='string'&&g.device_name.trim()===g.device_name&&g.device_name.length>0&&g.device_name.length<=60&&Array.isArray(g.actions)&&g.actions.length>0&&g.actions.length<=DEVICE_ACTIONS.length&&new Set(g.actions).size===g.actions.length&&g.actions.every(action=>DEVICE_ACTIONS.includes(action))&&Number.isFinite(time(g.issued_at))&&time(g.expires_at)>time(g.issued_at)&&time(g.expires_at)-time(g.issued_at)<=DEVICE_MAX_TTL_MS;}catch{return false;}
}
async function contextProposal(context:HumanContext,g:DeviceAuthorization){
 const proposal=context.proposal,p=proposal?.payload;
 return proposal&&p&&await verify(proposal,g.authority_key)&&p.type==='scopeblind.coordination.negotiation-proposal.v1'&&p.room_id===g.room_id&&p.agreement_digest===g.agreement_digest?proposal:null;
}
/** Derives permission from the signed payload, never a caller's requested privilege. */
export async function humanPermission(value:Signed<unknown>,context:HumanContext={}):Promise<{action:DevicePermission;at:string}|null>{
 const p=value.payload,g=value.authorization?.payload;if(!g||!object(p))return null;
 const direct=(action:DevicePermission)=>typeof p.issued_at==='string'&&p.room_id===g.room_id&&(p.agreement_digest===undefined||p.agreement_digest===g.agreement_digest)?{action,at:p.issued_at}:null;
 switch(p.type){
  case 'scopeblind.coordination.request.v1':return typeof p.action==='string'&&DEVICE_ACTIONS.includes(p.action as DevicePermission)?direct(p.action as DevicePermission):null;
  case 'scopeblind.coordination.approval.v1':return direct('decide');
  case 'scopeblind.coordination.acceptance.v1':return direct('accept');
  case 'scopeblind.coordination.negotiation-mandate.v1':return p.principal_key===g.principal_key?direct('negotiation_mandate'):null;
  case 'scopeblind.coordination.negotiation-approval.v1':{
   const proposal=await contextProposal(context,g),q=proposal?.payload;
   return q&&p.principal_key===g.principal_key&&p.session_id===q.session_id&&p.proposal_digest===proposal.digest&&p.next_agreement_digest===q.next_agreement_digest&&canonical(p.mandate_digests)===canonical(q.mandate_digests)&&typeof p.issued_at==='string'?{action:'negotiation_approve',at:p.issued_at}:null;
  }
  case 'scopeblind.coordination.agreement.v1':
  case 'scopeblind.coordination.grant.v1':
  case 'scopeblind.coordination.claim.v1':{
   const proposal=await contextProposal(context,g),q=proposal?.payload,approval=context.approval;
   if(!q||!approval||approval.payload.decision!=='approve'||approval.authorization?.digest!==value.authorization?.digest||!await verifyHuman(approval,g.principal_key,{proposal,requireRecordedUse:context.requireRecordedUse,authorityKey:context.authorityKey}))return null;
   const exactPayload=p.type==='scopeblind.coordination.agreement.v1'?q.next_agreement.owner_key===g.principal_key&&canonical(p)===canonical(q.next_agreement):p.type==='scopeblind.coordination.grant.v1'?q.reviewer_grant.issuer===g.principal_key&&canonical(p)===canonical(q.reviewer_grant):p.guest_key===g.principal_key&&p.room_id===q.next_agreement.id&&p.grant_id===q.reviewer_grant.grant_id&&typeof p.issued_at==='string'&&time(p.issued_at)>=time(approval.payload.issued_at)-300000&&time(p.issued_at)<=time(approval.payload.expires_at);
   return exactPayload?{action:'negotiation_approve',at:approval.payload.issued_at}:null;
  }
  default:return null;
 }
}
/** Offline authorization-at-signing check. Live mutation acceptance must also check storage revocation atomically. */
export async function verifyHuman<T>(value:Signed<T>,expectedPrincipal:string,context:HumanContext={}):Promise<boolean>{
 try{
  if(!value||!object(value)||Object.keys(value).some(key=>!['payload','signer','digest','signature','authorization','authorization_signature','authorization_use'].includes(key)))return false;
  if(!value.authorization)return !value.authorization_signature&&!value.authorization_use&&await verify(value,expectedPrincipal);
  const authorization=value.authorization,g=authorization.payload;
  if(context.authorityKey!==undefined&&g.authority_key!==context.authorityKey)return false;
  if(!await verify(value)||!await verifyDeviceAuthorization(authorization)||g.principal_key!==expectedPrincipal||g.device_key!==value.signer||typeof value.authorization_signature!=='string'||!/^[0-9a-f]{128}$/.test(value.authorization_signature))return false;
  const key=await crypto.subtle.importKey('raw',hexToBytes(value.signer),{name:'Ed25519'},false,['verify']);
  if(!await crypto.subtle.verify('Ed25519',key,hexToBytes(value.authorization_signature),new TextEncoder().encode(deviceAuthorizationPreimage(value.digest,authorization.digest))))return false;
  const permission=await humanPermission(value,context);if(!permission||!g.actions.includes(permission.action)||time(permission.at)<time(g.issued_at)-300000||time(permission.at)>=time(g.expires_at))return false;
  const p=value.payload as Record<string,unknown>;
  if(p.expires_at!==undefined&&!['scopeblind.coordination.grant.v1','scopeblind.coordination.agreement.v1'].includes(String(p.type))&&(!Number.isFinite(time(p.expires_at))||time(p.expires_at)>time(g.expires_at)))return false;
  const use=value.authorization_use;
  if(!use)return !context.requireRecordedUse;
  const u=use.payload;
  return exact(use,'payload signer digest signature')&&await verify(use,g.authority_key)&&exact(u,'type authorization_digest principal_key device_key room_id payload_digest action recorded_at')&&u.type==='scopeblind.coordination.device-use.v1'&&u.authorization_digest===authorization.digest&&u.principal_key===g.principal_key&&u.device_key===g.device_key&&u.room_id===g.room_id&&u.payload_digest===value.digest&&u.action===permission.action&&time(u.recorded_at)>=time(g.issued_at)&&time(u.recorded_at)<time(g.expires_at)&&time(u.recorded_at)>=time(permission.at)-300000;
 }catch{return false;}
}
