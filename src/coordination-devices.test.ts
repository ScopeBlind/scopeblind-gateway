import {describe,it,expect} from 'vitest';
import {generateIdentity,sign,makeRequest,type Approval,type Acceptance,type Signed} from './coordination-protocol';
import {DEVICE_ACTIONS,verifyDeviceAuthorization,verifyHuman,humanPrincipal,type DeviceAuthorization,type DeviceUse} from './coordination-devices';
const iso=(n:number)=>new Date(n).toISOString();
async function fixture(){
 const principal=await generateIdentity(),phone=await generateIdentity(),authority=await generateIdentity(),at=Date.now();
 const authorization=await sign<DeviceAuthorization>({type:'scopeblind.coordination.device-authorization.v1',id:'device-authorization-1',link_id:'device-request-1',room_id:'room-original-1',agreement_digest:'ab'.repeat(32),principal_key:principal.publicKey,device_key:phone.publicKey,device_name:'Phone',actions:[...DEVICE_ACTIONS],issued_at:iso(at),expires_at:iso(at+3600000),authority_key:authority.publicKey},principal);
 const identity={...phone,deviceAuthorization:authorization};
 const payload:Approval={type:'scopeblind.coordination.approval.v1',room_id:authorization.payload.room_id,run_id:'current-run-1',operation_id:'payment-operation-1',agreement_digest:authorization.payload.agreement_digest,payload_hash:'bc'.repeat(32),grant_id:'reviewer-grant-1',decision:'approve',issued_at:iso(at+10),expires_at:iso(at+300000),note:'Exact payment'};
 const approval=await sign(payload,identity);
 const use=await sign<DeviceUse>({type:'scopeblind.coordination.device-use.v1',authorization_digest:authorization.digest,principal_key:principal.publicKey,device_key:phone.publicKey,room_id:authorization.payload.room_id,payload_digest:approval.digest,action:'decide',recorded_at:iso(at+20)},authority);
 return {principal,phone,authority,identity,authorization,approval,use,recorded:{...approval,authorization_use:use},at};
}
describe('explicit room-bound human device signatures',()=>{
 it('retains actual signer and checks the separately signed authorization and recorded use',async()=>{
  const f=await fixture();expect(await verifyDeviceAuthorization(f.authorization)).toBe(true);expect(f.recorded.signer).toBe(f.phone.publicKey);expect(humanPrincipal(f.recorded)).toBe(f.principal.publicKey);
  expect(await verifyHuman(f.approval,f.principal.publicKey)).toBe(true);expect(await verifyHuman(f.approval,f.principal.publicKey,{requireRecordedUse:true})).toBe(false);
  expect(await verifyHuman(f.recorded,f.principal.publicKey,{requireRecordedUse:true,authorityKey:f.authority.publicKey})).toBe(true);
 });
 it('rejects certificate replacement even when the replacement is signed by the same human',async()=>{
  const f=await fixture(),replacement=await sign({...f.authorization.payload,id:'other-authorization'},f.principal);
  expect(await verifyHuman({...f.approval,authorization:replacement},f.principal.publicKey)).toBe(false);
  expect(await verifyHuman(f.recorded,f.phone.publicKey)).toBe(false);
 });
 it('rejects expanded actions, cross-room payloads, wrong principals and onward delegation',async()=>{
  const f=await fixture();for(const action of ['create','invite','device_authorize','negotiation_step','negotiation_adopt','negotiation_pair_create','execute'] as const){const value=await sign(makeRequest(action,f.authorization.payload.room_id,{}),f.identity);expect(await verifyHuman(value,f.principal.publicKey),action).toBe(false);}
  expect(await verifyHuman(await sign({...f.approval.payload,room_id:'room-other-1'},f.identity),f.principal.publicKey)).toBe(false);
  const onward=await sign({...f.authorization.payload,id:'another-device-1'},f.identity);expect(await verifyDeviceAuthorization(onward)).toBe(false);
 });
 it('does not accept an alternative authority, altered use scope or unrecorded acceptance',async()=>{
  const f=await fixture(),other=await generateIdentity();
  expect(await verifyHuman(f.recorded,f.principal.publicKey,{authorityKey:other.publicKey})).toBe(false);
  for(const changed of [{payload_digest:'de'.repeat(32)},{action:'accept' as const},{device_key:other.publicKey},{recorded_at:iso(f.at+3600000)}]){const use=await sign({...f.use.payload,...changed},f.authority);expect(await verifyHuman({...f.recorded,authorization_use:use},f.principal.publicKey,{requireRecordedUse:true})).toBe(false);}
  const {operation_id,payload_hash,expires_at,...base}=f.approval.payload;const acceptance=await sign<Acceptance>({...base,type:'scopeblind.coordination.acceptance.v1',decision:'accept',manifest_digest:'ef'.repeat(32)},f.identity);expect(await verifyHuman(acceptance,f.principal.publicKey,{requireRecordedUse:true})).toBe(false);
 });
 it('bounds signature times and approval validity to the device grant',async()=>{
  const f=await fixture();for(const changed of [{issued_at:iso(f.at+3600000)},{issued_at:iso(f.at-300001)},{expires_at:iso(f.at+3600001)}])expect(await verifyHuman(await sign({...f.approval.payload,...changed},f.identity),f.principal.publicKey)).toBe(false);
  const tooLong=await sign({...f.authorization.payload,expires_at:iso(f.at+604800001)},f.principal);expect(await verifyDeviceAuthorization(tooLong)).toBe(false);
 });
 it('rejects orphan or arbitrary envelope metadata instead of silently dropping authority fields',async()=>{
  const f=await fixture(),raw=await sign(f.approval.payload,f.principal);
  expect(await verifyHuman({...raw,authorization_signature:'ab'.repeat(64)},f.principal.publicKey)).toBe(false);
  expect(await verifyHuman({...raw,authorization_use:f.use},f.principal.publicKey)).toBe(false);
  expect(await verifyHuman({...f.recorded,unrecognized:true} as Signed<Approval>,f.principal.publicKey)).toBe(false);
  expect(await verifyHuman({...f.recorded,authorization_use:{...f.use,authorization_signature:'ab'.repeat(64)}},f.principal.publicKey)).toBe(false);
 });
});
