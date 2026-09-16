import {constants,openSync,readFileSync,closeSync,fstatSync,writeFileSync,mkdirSync,renameSync,unlinkSync,rmdirSync} from 'node:fs';
import {dirname,resolve} from 'node:path';
import {homedir} from 'node:os';
import {randomBytes} from 'node:crypto';
import {bytesToHex,importIdentity,verify,type Signed} from './coordination-protocol.js';
import {validateCoordinationConfig,type CoordinationConfig} from './coordination-config.js';
import {readPrivateConfig,coordinationConfigFromFile} from './coordination-pair-cli.js';
import type {AgentBinding} from './coordination-pairing.js';
import type {AgentTaskDraft,AgentHandoffView} from './coordination-agent-requests.js';

export const DEFAULT_AGENT_PROFILE=resolve(homedir(),'.scopeblind','agent.json');
export interface ProfileConnection extends CoordinationConfig {
  type:'scopeblind.coordination.config.v1';setupVersion?:2;agentKey:string;name:string;binding:Signed<AgentBinding>;
}
export interface ProfileTaskRequest {
  draft:AgentTaskDraft;reviewSecret:string;pairingSecret:string;expiresAt:string;
  pendingToken?:string;pendingPairId?:string;
}
export interface AgentProfile {
  type:'scopeblind.coordination.agent-profile.v1';endpoint:string;authorityKey:string;agentKey:string;privateKey:string;
  requests:Record<string,ProfileTaskRequest>;
  connections:Record<string,ProfileConnection>;
  pendingHandoffs:Record<string,{handoff:AgentHandoffView;token:string}>;
}
export const profileId=(value:unknown):value is string=>typeof value==='string'&&/^[A-Za-z0-9_-]{8,100}$/.test(value);
export function validateProfileDestination(endpoint:string,authorityKey:string){
  const checked=validateCoordinationConfig({endpoint,authorityKey,roomId:'profile-placeholder',token:'profile-placeholder'});
  return {endpoint:checked.endpoint,authorityKey:checked.authorityKey};
}

export function readAgentProfile(path:string):AgentProfile {
  let fd:number;
  try{fd=openSync(resolve(path),constants.O_RDONLY|constants.O_NOFOLLOW);}catch{throw new Error('The private agent profile could not be opened. Run coordination agent setup first.');}
  try{
    const file=fstatSync(fd);
    if(!file.isFile()||file.size>2_000_000||(process.platform!=='win32'&&((file.mode&0o077)!==0||process.getuid&&file.uid!==process.getuid())))throw new Error('The agent profile must be owned by you with permissions 600.');
    let value:AgentProfile;try{value=JSON.parse(readFileSync(fd,'utf8'));}catch{throw new Error('The private agent profile is not valid JSON.');}
    if(value?.type!=='scopeblind.coordination.agent-profile.v1'||!/^[a-f0-9]{64}$/.test(value.agentKey)||!/^[a-f0-9]{96,256}$/.test(value.privateKey)||[value.requests,value.connections,value.pendingHandoffs].some(v=>!v||typeof v!=='object'||Array.isArray(v)))throw new Error('The private agent profile has an unsupported format.');
    validateProfileDestination(value.endpoint,value.authorityKey);
    if(Object.keys(value.requests).length>50||Object.keys(value.connections).length>50||Object.keys(value.pendingHandoffs).length>50)throw new Error('This private profile reached its connection limit. Use a separate profile for new work.');
    for(const [id,connection] of Object.entries(value.connections)){
      validateCoordinationConfig(connection);
      if(!profileId(id)||connection.endpoint!==value.endpoint||connection.authorityKey!==value.authorityKey||!connection.binding||connection.binding.payload.pair_id!==id||connection.binding.payload.agent_key!==connection.agentKey)throw new Error('A saved connection does not match this private profile.');
    }
    return value;
  }finally{closeSync(fd);}
}

/** Serialize local writers. Network operations happen outside this short file lock. */
export async function updateAgentProfile<T>(path:string,change:(profile:AgentProfile)=>T):Promise<T>{
  path=resolve(path);const lock=path+'.lock';let locked=false;
  for(let attempt=0;attempt<30;attempt++){
    try{mkdirSync(lock,{mode:0o700});locked=true;break;}catch(error){if((error as NodeJS.ErrnoException).code!=='EEXIST')throw new Error('The private profile could not be locked.');}
    await new Promise(resolve=>setTimeout(resolve,50));
  }
  if(!locked)throw new Error('Another process is updating this profile. Retry after it finishes; no credentials were changed.');
  const temporary=path+'.'+randomBytes(8).toString('hex')+'.tmp';
  try{
    const profile=readAgentProfile(path),result=change(profile);
    if([profile.requests,profile.connections,profile.pendingHandoffs].some(entries=>Object.keys(entries).length>50))throw new Error('This private profile reached its connection limit. Use a separate profile for new work.');
    writeFileSync(temporary,JSON.stringify(profile)+'\n',{flag:'wx',mode:0o600});renameSync(temporary,path);return result;
  }finally{try{unlinkSync(temporary);}catch{}try{rmdirSync(lock);}catch{}}
}

export async function ensureAgentProfile(path:string,endpoint?:string,authorityKey?:string):Promise<AgentProfile>{
  path=resolve(path);
  try{
    const value=readAgentProfile(path);
    if(endpoint!==undefined&&validateProfileDestination(endpoint,authorityKey||value.authorityKey).endpoint!==value.endpoint||authorityKey!==undefined&&authorityKey.toLowerCase()!==value.authorityKey)throw new Error('This profile is pinned to another authority or endpoint. Use its original settings or a separate profile.');
    await importIdentity(value.privateKey,value.agentKey);return value;
  }catch(error){
    try{const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW);closeSync(fd);throw error;}catch(check){if((check as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
  }
  if(!endpoint||!authorityKey)throw new Error('A new profile needs --endpoint and an independently pinned --authority-key.');
  const destination=validateProfileDestination(endpoint,authorityKey),pair=await crypto.subtle.generateKey('Ed25519',true,['sign','verify']) as CryptoKeyPair;
  const profile:AgentProfile={type:'scopeblind.coordination.agent-profile.v1',...destination,agentKey:bytesToHex(new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey))),privateKey:bytesToHex(new Uint8Array(await crypto.subtle.exportKey('pkcs8',pair.privateKey))),requests:{},connections:{},pendingHandoffs:{}};
  mkdirSync(dirname(path),{recursive:true,mode:0o700});const fd=openSync(path,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{writeFileSync(fd,JSON.stringify(profile)+'\n');}finally{closeSync(fd);}return profile;
}

export async function importProfileConnection(profilePath:string,configPath:string):Promise<string>{
  const stored=readPrivateConfig(configPath),config=coordinationConfigFromFile(configPath),binding=stored.binding!;
  if(!await verify(binding,config.authorityKey)||!await verify(binding.payload.owner_authorization,binding.payload.owner_key))throw new Error('The saved connection signatures could not be verified.');
  await updateAgentProfile(profilePath,profile=>{
    if(config.endpoint!==profile.endpoint||config.authorityKey!==profile.authorityKey)throw new Error('Import requires the same pinned endpoint and authority.');
    const id=binding.payload.pair_id,existing=profile.connections[id];
    if(existing&&existing.binding.digest!==binding.digest)throw new Error('This connection ID already names another signed grant.');
    profile.connections[id]={...config,type:stored.type,setupVersion:stored.setupVersion,agentKey:stored.agentKey,name:stored.name,binding};
  });return binding.payload.pair_id;
}
