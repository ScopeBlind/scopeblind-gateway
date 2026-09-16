import {randomBytes} from 'node:crypto';
import {canonical,importIdentity,makeRequest,sha256,sign,verify,type RpcAction,type Signed,type Agreement} from './coordination-protocol.js';
import {PAIRING_SCOPE,NEGOTIATION_PAIRING_SCOPE,NEGOTIATION_PAIRING_AUDIENCE,type AgentBinding} from './coordination-pairing.js';
import {claimPairing} from './coordination-pair-cli.js';
import {CoordinationClient,CoordinationError} from './coordination-client.js';
import {parseAgentTaskDraft,prepareAgentTaskDraft,type AgentTaskRequestView,type AgentHandoffView} from './coordination-agent-requests.js';
import {readAgentProfile,updateAgentProfile,profileId,type ProfileConnection,type AgentProfile} from './coordination-agent-profile.js';

const hex=(value:unknown):value is string=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const exact=(value:unknown,required:string[],optional:string[]=[]):value is Record<string,unknown>=>!!value&&typeof value==='object'&&!Array.isArray(value)&&required.every(k=>Object.hasOwn(value,k))&&Object.keys(value).every(k=>required.includes(k)||optional.includes(k));
function fail(code:string,message:string):never{throw new CoordinationError(code,message);}
const envelope=(value:unknown)=>exact(value,['payload','signer','digest','signature']);

/** The profile key is an agent identity, never a browser principal or an implicit owner grant. */
export class CoordinationAgentClient {
  constructor(readonly profilePath:string,private readonly fetchImpl:typeof fetch=fetch){}
  private profile(){return readAgentProfile(this.profilePath);}
  private async request(action:RpcAction,roomId:string,body:Record<string,unknown>):Promise<Record<string,unknown>>{
    const profile=this.profile(),identity=await importIdentity(profile.privateKey,profile.agentKey);
    const request=await sign(makeRequest(action,roomId,body),identity);
    const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),25000);
    try{
      const response=await this.fetchImpl(profile.endpoint,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({request}),redirect:'error',cache:'no-store',signal:abort.signal});
      const raw=await response.text();if(raw.length>2_000_000)fail('invalid_agent_response','The service response was too large.');
      let result:Record<string,unknown>;try{result=JSON.parse(raw);}catch{fail('invalid_agent_response','The service did not return a readable response.');}
      if(!response.ok||result!.ok!==true){const code=typeof result!.error==='string'&&/^[a-z_]{3,80}$/.test(result!.error)?result!.error:'agent_request_refused';fail(code,'The service refused this agent request. Inspect the current task or ask the person to review its permissions; no authority was added.');}
      return result!;
    }catch(error){if(error instanceof CoordinationError)throw error;fail('agent_connection_interrupted','The reply was interrupted. Retry the same request or grant ID; its private recovery state is saved locally.');}
    finally{clearTimeout(timer);}
  }
  private async checkedRequest(value:unknown,id:string):Promise<AgentTaskRequestView>{
    const profile=this.profile(),pending=profile.requests[id];
    if(!pending||!exact(value,['request_id','agent_key','pairing_secret_hash','status','expires_at','draft'],['accepted','connection']))fail('invalid_agent_request','The returned draft does not match this profile.');
    const v=value as unknown as AgentTaskRequestView;
    if(v.request_id!==id||v.agent_key!==profile.agentKey||v.pairing_secret_hash!==await sha256(pending.pairingSecret)||v.expires_at!==pending.expiresAt||!['pending','accepted','ready','revoked','expired'].includes(v.status)||canonical(parseAgentTaskDraft(v.draft))!==canonical(pending.draft))fail('invalid_agent_request','The returned draft does not match the exact request prepared here.');
    if(v.accepted){
      const a=v.accepted;
      if(!exact(a,['owner_key','room_id','session_id','pair_id','reviewed_draft','digest'])||!hex(a.owner_key)||a.owner_key===profile.agentKey||![a.room_id,a.session_id,a.pair_id].every(profileId)||!hex(a.digest))fail('invalid_agent_request','The reviewed draft does not name a valid independent principal.');
      if(a.digest!==await sha256(canonical(parseAgentTaskDraft(a.reviewed_draft))))fail('invalid_agent_request','The reviewed draft digest does not match its exact content.');
    }
    if(v.connection){
      const c=v.connection,a=v.accepted;
      if(!a||!exact(c,['purpose','room_id','session_id','pair_id','principal_key','authority_key'],['binding'])||c.purpose!=='negotiation'||c.room_id!==a.room_id||c.session_id!==a.session_id||c.pair_id!==a.pair_id||c.principal_key!==a.owner_key||c.authority_key!==profile.authorityKey)fail('invalid_agent_request','The offered connection does not match the person’s reviewed task.');
    }
    if(v.status==='ready'&&!v.connection)fail('invalid_agent_request','A ready connection must name its exact signed task.');
    return v;
  }
  private reviewLink(id:string,secret:string){const url=new URL('/standard',this.profile().endpoint);url.searchParams.set('trial','new');url.hash='agent_request='+id+'.'+secret;return url.href;}
  async prepareTask(input:{request_id:string;draft:unknown}){
    if(!exact(input,['request_id','draft'])||!profileId(input.request_id))fail('invalid_agent_draft','Use one stable request_id and an explicit draft.');
    const draft=prepareAgentTaskDraft(input.draft),id=input.request_id;
    await updateAgentProfile(this.profilePath,profile=>{
      if(profile.requests[id]){if(canonical(profile.requests[id].draft)!==canonical(draft))fail('agent_request_id_conflict','This request ID already names a different draft. Keep it for retries; use a new ID only for a different intended task.');return;}
      if(Object.keys(profile.requests).length>=50)fail('agent_profile_limit','This profile has 50 saved requests. Use a separate profile for new work.');
      profile.requests[id]={draft,reviewSecret:randomBytes(32).toString('hex'),pairingSecret:randomBytes(32).toString('hex'),expiresAt:new Date(Date.now()+30*60*1000).toISOString()};
    });
    const saved=this.profile().requests[id];
    const response=await this.request('agent_request_create' as RpcAction,id,{request_id:id,secret_hash:await sha256(saved.reviewSecret),pairing_secret_hash:await sha256(saved.pairingSecret),draft:saved.draft,expires_at:saved.expiresAt});
    const request=await this.checkedRequest(response.agent_request,id);
    return {request_id:id,status:request.status,private_review_link:this.reviewLink(id,saved.reviewSecret),draft:{...draft,private_brief:undefined},assumptions:draft.assumptions,scope:'Unsigned suggestions only. Show this private review link to your own person; it includes access to their private draft instructions. They must review the draft, create the shared task, and sign a mandate. This does not create owner authority, invite the colleague, or start a model or payment.'};
  }
  async inspectTaskRequest(id:string){
    if(!profileId(id)||!this.profile().requests[id])fail('unknown_agent_request','This profile has no saved request with that ID.');
    const response=await this.request('agent_request_get' as RpcAction,id,{request_id:id}),request=await this.checkedRequest(response.agent_request,id);
    return {request_id:id,status:request.status,expires_at:request.expires_at,title:request.draft.title,...(request.accepted?{reviewed_draft:request.accepted.reviewed_draft,owner_key:request.accepted.owner_key,room_id:request.accepted.room_id,session_id:request.accepted.session_id}:{}),...(request.connection?{connection_id:request.connection.pair_id}:{}),next_step:request.status==='ready'?'Call coordination.claim_task_connection with this request_id. Then inspect the exact mandate through the returned connection_id.':request.status==='pending'?'Your person must open and review the private link. No authority is granted.':request.status==='accepted'?'The person reviewed the draft. Wait for their signed mandate and explicit agent connection; acceptance of a draft is not an agent grant.':'This request is inactive. Keep its history; ask the person before preparing a new task.'};
  }
  async claimTaskConnection(id:string){
    if(!profileId(id)||!this.profile().requests[id])fail('unknown_agent_request','This profile has no saved request with that ID.');
    const response=await this.request('agent_request_get' as RpcAction,id,{request_id:id}),view=await this.checkedRequest(response.agent_request,id);
    if(view.status!=='ready'||!view.connection)fail('agent_grant_not_ready','The person has not yet signed an active negotiation grant. A reviewed draft alone is not permission.');
    const c=view.connection;
    const existing=this.profile().connections[c.pair_id];if(existing)return this.connectionSummary(c.pair_id,existing);
    await updateAgentProfile(this.profilePath,profile=>{const saved=profile.requests[id];if(saved.pendingPairId!==c.pair_id||!saved.pendingToken){saved.pendingPairId=c.pair_id;saved.pendingToken=randomBytes(32).toString('hex');}});
    const profile=this.profile(),saved=profile.requests[id];
    const ready=await claimPairing({type:'scopeblind.coordination.config.v1',setupVersion:2,endpoint:profile.endpoint,authorityKey:profile.authorityKey,agentKey:profile.agentKey,token:saved.pendingToken!,roomId:c.room_id,purpose:'negotiation',sessionId:c.session_id,principalKey:c.principal_key,name:'My agent',pending:{privateKey:profile.privateKey,code:{version:3,endpoint:profile.endpoint,authority_key:profile.authorityKey,room_id:c.room_id,session_id:c.session_id,principal_key:c.principal_key,pair_id:c.pair_id,secret:saved.pairingSecret,scope:NEGOTIATION_PAIRING_SCOPE,audience:NEGOTIATION_PAIRING_AUDIENCE}}} as Parameters<typeof claimPairing>[0],this.fetchImpl);
    if(ready.binding?.payload.owner_authorization.payload.body.expected_agent_key!==profile.agentKey)fail('agent_grant_wrong_key','This grant must explicitly name the profile’s agent key.');
    await updateAgentProfile(this.profilePath,current=>{
      const prior=current.connections[c.pair_id];if(prior&&prior.binding.digest!==ready.binding!.digest)fail('agent_grant_conflict','The connection ID already belongs to another signed grant.');
      current.connections[c.pair_id]=ready as ProfileConnection;delete current.requests[id].pendingToken;delete current.requests[id].pendingPairId;
    });
    return {...this.connectionSummary(c.pair_id,ready as ProfileConnection),next_step:'Call coordination.inspect_negotiation with this connection_id before taking any next action. Claiming does not establish readiness or start background work.'};
  }
  connectionSummary(id:string,connection:ProfileConnection){return {connection_id:id,purpose:connection.purpose||'execution',room_id:connection.roomId,...(connection.sessionId?{session_id:connection.sessionId,principal_key:connection.principalKey}:{}),agent_key:connection.agentKey,expires_at:connection.binding.payload.expires_at,locally_expired:Date.parse(connection.binding.payload.expires_at)<=Date.now(),same_profile_key:connection.agentKey===this.profile().agentKey,scope:connection.binding.payload.scope};}
  connections(){const profile=this.profile();return {agent_key:profile.agentKey,connections:Object.entries(profile.connections).map(([id,c])=>this.connectionSummary(id,c)),scope:'Saved grants only; connection listings do not prove that authority remains active. Inspect the intended connection before acting. Every action is still checked by the service.'};}
  clientFor(id:string){
    if(!profileId(id))fail('unknown_agent_connection','Use an exact connection_id from coordination.connections.');
    const c=this.profile().connections[id];if(!c)fail('unknown_agent_connection','This profile does not hold that connection.');
    return new CoordinationClient(c,this.fetchImpl);
  }
  private sourceConnection(id:string){
    const profile=this.profile(),source=profile.connections[id];
    if(!source||source.purpose!=='negotiation'||!source.sessionId||!source.principalKey||source.agentKey!==profile.agentKey)fail('handoff_profile_key_required','Seamless execution handoff needs a negotiation connection enrolled with this profile’s own key. Imported legacy connections retain their original scope; their discarded private key cannot be recreated.');
    return source;
  }
  private async checkedHandoff(value:unknown,source:ProfileConnection):Promise<AgentHandoffView>{
    const p=this.profile();
    if(!exact(value,['pair_id','room_id','source_room_id','session_id','source_pair_id','agent_key','name','status','expires_at','token_expires_at','authorization'],['binding']))fail('invalid_handoff','The offered execution connection has an unsupported shape.');
    const h=value as unknown as AgentHandoffView,q=h.authorization?.payload,b=q?.body;
    if(![h.pair_id,h.room_id].every(profileId)||h.source_room_id!==source.roomId||h.session_id!==source.sessionId||h.source_pair_id!==source.binding.payload.pair_id||h.agent_key!==p.agentKey||typeof h.name!=='string'||!h.name.length||h.name.length>60||!['waiting','connected','revoked','expired'].includes(h.status)||![h.expires_at,h.token_expires_at].every(t=>Number.isFinite(Date.parse(t)))||Date.parse(h.token_expires_at)<Date.parse(h.expires_at)||!envelope(h.authorization)||!await verify(h.authorization,source.principalKey))fail('invalid_handoff','The execution handoff is not signed by the expected human principal for this exact source connection.');
    if(!exact(q,['type','action','room_id','body','issued_at','nonce'])||q.type!=='scopeblind.coordination.request.v1'||q.action!=='agent_handoff_create'||q.room_id!==h.room_id||!profileId(q.nonce)||!exact(b,['session_id','source_pair_id','pair_id','agent_key','agreement_digest','scope','name','expires_at','token_expires_at'])||b.session_id!==h.session_id||b.source_pair_id!==h.source_pair_id||b.pair_id!==h.pair_id||b.agent_key!==h.agent_key||!hex(b.agreement_digest)||canonical(b.scope)!==canonical(PAIRING_SCOPE)||b.name!==h.name||b.expires_at!==h.expires_at||b.token_expires_at!==h.token_expires_at)fail('invalid_handoff','The human authorization does not match the exact execution scope and target agreement.');
    return h;
  }
  async checkHandoffs(id:string){
    const source=this.sourceConnection(id),response=await this.request('agent_handoff_get' as RpcAction,source.roomId,{session_id:source.sessionId,source_pair_id:source.binding.payload.pair_id});
    if(!Array.isArray(response.handoffs)||response.handoffs.length>50)fail('invalid_handoff','The handoff response is invalid.');
    const handoffs=await Promise.all(response.handoffs.map(v=>this.checkedHandoff(v,source)));
    return {source_connection_id:id,handoffs:handoffs.map(h=>({handoff_id:h.pair_id,room_id:h.room_id,name:h.name,status:h.status,expires_at:h.expires_at,token_expires_at:h.token_expires_at,agreement_digest:h.authorization.payload.body.agreement_digest})),next_step:'Only an active, separately human-authorized handoff can be claimed. Claiming never spends money or transfers human approval powers.'};
  }
  async claimExecutionConnection(id:string,handoffId:string){
    if(!profileId(handoffId))fail('invalid_handoff','Use the exact handoff_id returned by coordination.check_handoffs.');
    const source=this.sourceConnection(id),response=await this.request('agent_handoff_get' as RpcAction,source.roomId,{session_id:source.sessionId,source_pair_id:source.binding.payload.pair_id});
    if(!Array.isArray(response.handoffs))fail('invalid_handoff','The handoff response is invalid.');
    const offered=response.handoffs.find((v:any)=>v?.pair_id===handoffId);if(!offered)fail('handoff_not_found','No execution grant with that ID belongs to this source connection.');
    const handoff=await this.checkedHandoff(offered,source);
    if(['revoked','expired'].includes(handoff.status)||Date.parse(handoff.token_expires_at)<=Date.now())fail('handoff_inactive','This execution grant is expired or revoked. The person must decide whether to grant new access.');
    const prior=this.profile().connections[handoffId];if(prior)return this.connectionSummary(handoffId,prior);
    if(handoff.status==='waiting'&&Date.parse(handoff.expires_at)<=Date.now())fail('handoff_inactive','This unclaimed execution grant expired.');
    await updateAgentProfile(this.profilePath,profile=>{
      const pending=profile.pendingHandoffs[handoffId];if(pending&&pending.handoff.authorization.digest!==handoff.authorization.digest)fail('handoff_conflict','The saved handoff ID names a different authorization.');
      profile.pendingHandoffs[handoffId]??={handoff,token:randomBytes(32).toString('hex')};
    });
    const profile=this.profile(),token=profile.pendingHandoffs[handoffId].token,claimed=await this.request('agent_handoff_claim' as RpcAction,handoff.room_id,{pair_id:handoffId,executor_token:token,name:handoff.name});
    const binding=claimed.binding as Signed<AgentBinding>,b=binding?.payload;
    if(claimed.executor_token!==token||!envelope(binding)||!b||!await verify(binding,profile.authorityKey)||!exact(b,['type','pair_id','room_id','agreement_digest','owner_key','agent_key','name','scope','audience','issued_at','expires_at','owner_authorization'])||b.type!=='scopeblind.coordination.agent-binding.v1'||b.pair_id!==handoffId||b.room_id!==handoff.room_id||b.agreement_digest!==handoff.authorization.payload.body.agreement_digest||b.owner_key!==source.principalKey||b.agent_key!==profile.agentKey||b.name!==handoff.name||b.audience!=='scopeblind.coordination.sample-ledger'||canonical(b.scope)!==canonical(PAIRING_SCOPE)||b.expires_at!==handoff.token_expires_at||!Number.isFinite(Date.parse(b.issued_at))||Date.parse(b.issued_at)>=Date.parse(b.expires_at)||Date.parse(b.issued_at)>Date.now()+300000||canonical(b.owner_authorization)!==canonical(handoff.authorization))fail('invalid_handoff_binding','The claimed execution grant did not verify against the pinned authority and exact human authorization. Retry the same ID; no connection is presented as verified.');
    const config:ProfileConnection={type:'scopeblind.coordination.config.v1',setupVersion:2,endpoint:profile.endpoint,authorityKey:profile.authorityKey,roomId:handoff.room_id,agentKey:profile.agentKey,token,name:handoff.name,purpose:'execution',binding};
    await updateAgentProfile(this.profilePath,current=>{current.connections[handoffId]=config;delete current.pendingHandoffs[handoffId];});
    return {...this.connectionSummary(handoffId,config),next_step:'Call coordination.inspect with this NEW connection_id to verify the adopted agreement and current work before acting. The negotiation connection remains separately scoped; no action was executed.'};
  }
}
