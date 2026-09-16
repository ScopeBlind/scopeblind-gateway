import {afterEach,describe,expect,it,vi} from 'vitest';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {CoordinationAgentClient} from './coordination-agent-client.js';
import {ensureAgentProfile,readAgentProfile,updateAgentProfile,importProfileConnection} from './coordination-agent-profile.js';
import {handleAgentProfileRequest} from './coordination-agent-server.js';
import {canonical,generateIdentity,makeRequest,sha256,sign,verify,type Signed} from './coordination-protocol.js';
import {NEGOTIATION_PAIRING_SCOPE,NEGOTIATION_PAIRING_AUDIENCE,PAIRING_SCOPE,type AgentBinding} from './coordination-pairing.js';
import type {AgentTaskRequestView,AgentHandoffView} from './coordination-agent-requests.js';
const dirs:string[]=[];afterEach(()=>{for(const d of dirs.splice(0))rmSync(d,{recursive:true,force:true});});
const requestId='request-task-001',roomId='agent-room-001',sessionId='agent-session-001',pairId='agent-pair-001';
const input={request_id:requestId,draft:{title:'Shared review',goal:'Agree how fictional invoices should be reviewed',private_brief:'PRIVATE_GOAL_NEVER_IN_LINK'}};
async function fixture(){
 const dir=mkdtempSync(join(tmpdir(),'scopeblind-agent-client-'));dirs.push(dir);const path=join(dir,'profile.json');
 const authority=await generateIdentity(),owner=await generateIdentity();const profile=await ensureAgentProfile(path,'https://scopeblind.com/api/coordination',authority.publicKey);
 const expires=new Date(Date.now()+3600000).toISOString(),grantExpires=new Date(Date.now()+600000).toISOString();
 let view:AgentTaskRequestView|undefined,binding:Signed<AgentBinding>|undefined,handoff:AgentHandoffView|undefined,executionBinding:Signed<AgentBinding>|undefined;
 const failures=new Set<string>(),bodies:Array<{action:string;body:any}>=[];
 const fetcher=vi.fn(async(_url:unknown,options?:RequestInit)=>{
  const request=JSON.parse(String(options?.body)).request,q=request.payload,body=q.body;
  expect(options?.redirect).toBe('error');expect(await verify(request,profile.agentKey)).toBe(true);bodies.push({action:q.action,body});
  let response:unknown;
  if(q.action==='agent_request_create'){
   const saved=readAgentProfile(path).requests[requestId];expect(saved).toBeTruthy();expect(body.secret_hash).toBe(await sha256(saved.reviewSecret));expect(body.pairing_secret_hash).toBe(await sha256(saved.pairingSecret));expect(JSON.stringify(body)).not.toContain(saved.reviewSecret);expect(JSON.stringify(body)).not.toContain(saved.pairingSecret);
   view??={request_id:requestId,agent_key:profile.agentKey,pairing_secret_hash:body.pairing_secret_hash,status:'pending',expires_at:body.expires_at,draft:body.draft};response={ok:true,agent_request:view};
  }else if(q.action==='agent_request_get'){expect(body.review_secret).toBeUndefined();response={ok:true,agent_request:view};}
  else if(q.action==='negotiation_pair_claim'){
   const saved=readAgentProfile(path).requests[requestId];expect(body.executor_token).toBe(saved.pendingToken);expect(body.secret).toBe(saved.pairingSecret);
   const selectedPair=view!.connection!.pair_id;const authorization=await sign(makeRequest('negotiation_pair_create',roomId,{session_id:sessionId,pair_id:selectedPair,name:'My agent',secret_hash:await sha256(saved.pairingSecret),expires_at:grantExpires,token_expires_at:expires,scope:NEGOTIATION_PAIRING_SCOPE,expected_agent_key:profile.agentKey}),owner);
   if(binding?.payload.pair_id!==selectedPair)binding=await sign<AgentBinding>({type:'scopeblind.coordination.agent-binding.v1',pair_id:selectedPair,room_id:roomId,session_id:sessionId,principal_key:owner.publicKey,agreement_digest:'ad'.repeat(32),owner_key:owner.publicKey,agent_key:profile.agentKey,name:'My agent',scope:NEGOTIATION_PAIRING_SCOPE,audience:NEGOTIATION_PAIRING_AUDIENCE,issued_at:new Date().toISOString(),expires_at:expires,owner_authorization:authorization},authority);response={ok:true,binding,executor_token:body.executor_token};
  }else if(q.action==='agent_handoff_get'){expect(q.room_id).toBe(roomId);expect(body).toEqual({session_id:sessionId,source_pair_id:pairId});response={ok:true,handoffs:handoff?[handoff]:[]};}
  else if(q.action==='agent_handoff_claim'){
   expect(handoff).toBeTruthy();expect(q.room_id).toBe(handoff!.room_id);expect(body.executor_token).toBe(readAgentProfile(path).pendingHandoffs[handoff!.pair_id].token);
   executionBinding??=await sign<AgentBinding>({type:'scopeblind.coordination.agent-binding.v1',pair_id:handoff!.pair_id,room_id:handoff!.room_id,agreement_digest:handoff!.authorization.payload.body.agreement_digest as string,owner_key:owner.publicKey,agent_key:profile.agentKey,name:handoff!.name,scope:PAIRING_SCOPE,audience:'scopeblind.coordination.sample-ledger',issued_at:new Date().toISOString(),expires_at:expires,owner_authorization:handoff!.authorization},authority);response={ok:true,binding:executionBinding,executor_token:body.executor_token};
  }else throw new Error('Unexpected action '+q.action);
  if(failures.delete(q.action))throw new Error('network interrupted');
  return new Response(JSON.stringify(response));
 });
 const client=new CoordinationAgentClient(path,fetcher as typeof fetch);
 async function ready(){await client.prepareTask(input);view!.accepted={owner_key:owner.publicKey,room_id:roomId,session_id:sessionId,pair_id:pairId,reviewed_draft:view!.draft,digest:await sha256(canonical(view!.draft))};view!.status='ready';view!.connection={purpose:'negotiation',room_id:roomId,session_id:sessionId,pair_id:pairId,principal_key:owner.publicKey,authority_key:authority.publicKey};}
 async function offer(){
  const h={pair_id:'execution-pair-001',room_id:'adopted-room-001',source_room_id:roomId,session_id:sessionId,source_pair_id:pairId,agent_key:profile.agentKey,name:'My agent',expires_at:grantExpires,token_expires_at:expires,status:'waiting' as const};
  handoff={...h,authorization:await sign(makeRequest('agent_handoff_create',h.room_id,{session_id:sessionId,source_pair_id:pairId,pair_id:h.pair_id,agent_key:profile.agentKey,agreement_digest:'ef'.repeat(32),scope:PAIRING_SCOPE,name:h.name,expires_at:h.expires_at,token_expires_at:expires}),owner)};return handoff;
 }
 return{client,path,dir,profile,authority,owner,fetcher,failures,bodies,ready,offer,get view(){return view!;},get binding(){return binding!;},set binding(v:Signed<AgentBinding>){binding=v;},get handoff(){return handoff!;},set handoff(v:AgentHandoffView){handoff=v;},get executionBinding(){return executionBinding!;},set executionBinding(v:Signed<AgentBinding>){executionBinding=v;}};
}
const rpc=(name:string,args:unknown={})=>({jsonrpc:'2.0',id:1,method:'tools/call',params:{name,arguments:args}});
describe('agent-first review and separately scoped connections',()=>{
 it('persists draft recovery before transport, retries the same hashes after lost reply, and confines private review access to the fragment',async()=>{
  const f=await fixture();f.failures.add('agent_request_create');await expect(f.client.prepareTask(input)).rejects.toMatchObject({code:'agent_connection_interrupted'});
  const saved=readAgentProfile(f.path).requests[requestId],result=await f.client.prepareTask(input);
  expect(f.bodies[0]).toEqual(f.bodies[1]);expect(result.private_review_link).toBe('https://scopeblind.com/standard?trial=new#agent_request='+requestId+'.'+saved.reviewSecret);
  expect(JSON.stringify(result)).not.toContain(saved.pairingSecret);expect(JSON.stringify(result)).not.toContain(f.profile.privateKey);expect(JSON.stringify(result)).not.toContain(input.draft.private_brief);
  expect(readAgentProfile(f.path).connections).toEqual({});expect(result.scope).toContain('does not create owner authority');
  const calls=f.fetcher.mock.calls.length;await expect(f.client.prepareTask({...input,draft:{...input.draft,title:'Different'}})).rejects.toMatchObject({code:'agent_request_id_conflict'});expect(f.fetcher).toHaveBeenCalledTimes(calls);
 });
 it('keeps accepted drafts powerless and refuses relabeled grants or principals',async()=>{
  const f=await fixture();await f.ready();f.view.status='accepted';delete f.view.connection;
  await expect(f.client.claimTaskConnection(requestId)).rejects.toMatchObject({code:'agent_grant_not_ready'});expect(readAgentProfile(f.path).connections).toEqual({});
  expect((await f.client.inspectTaskRequest(requestId)).next_step).toContain('not an agent grant');
  f.view.accepted!.owner_key=f.profile.agentKey;await expect(f.client.inspectTaskRequest(requestId)).rejects.toMatchObject({code:'invalid_agent_request'});
 });
 it('recovers a lost negotiation claim with exactly the persisted token, without claiming readiness or starting work',async()=>{
  const f=await fixture();await f.ready();f.failures.add('negotiation_pair_claim');await expect(f.client.claimTaskConnection(requestId)).rejects.toThrow('recover safely');
  const token=readAgentProfile(f.path).requests[requestId].pendingToken;expect(token).toMatch(/^[a-f0-9]{64}$/);
  const result=await f.client.claimTaskConnection(requestId),connection=readAgentProfile(f.path).connections[pairId];expect(connection.token).toBe(token);expect(readAgentProfile(f.path).requests[requestId].pendingToken).toBeUndefined();
  expect(f.bodies.filter(b=>b.action==='negotiation_pair_claim').map(b=>b.body.executor_token)).toEqual([token,token]);
  expect(result).toMatchObject({connection_id:pairId,purpose:'negotiation',same_profile_key:true});expect(JSON.stringify(result)).not.toContain(token!);expect(JSON.stringify(result)).toContain('does not establish readiness');
  expect(new Set(f.bodies.map(b=>b.action))).toEqual(new Set(['agent_request_create','agent_request_get','negotiation_pair_claim']));
 });
 it('uses a fresh token for an explicitly replaced pairing after an interrupted old claim',async()=>{
  const f=await fixture();await f.ready();f.failures.add('negotiation_pair_claim');await expect(f.client.claimTaskConnection(requestId)).rejects.toThrow();
  const first=readAgentProfile(f.path).requests[requestId].pendingToken;f.view.accepted!.pair_id='replacement-pair-001';f.view.connection!.pair_id='replacement-pair-001';
  const result=await f.client.claimTaskConnection(requestId),saved=readAgentProfile(f.path);expect(result.connection_id).toBe('replacement-pair-001');expect(saved.connections['replacement-pair-001'].token).not.toBe(first);expect(saved.requests[requestId].pendingPairId).toBeUndefined();
 });
 it('requires explicit connection selection and preserves every purpose boundary before transport',async()=>{
  const f=await fixture();await f.ready();await f.client.claimTaskConnection(requestId);f.fetcher.mockClear();
  const init:any=await handleAgentProfileRequest(f.client,{jsonrpc:'2.0',id:1,method:'initialize'}),listing:any=await handleAgentProfileRequest(f.client,{jsonrpc:'2.0',id:2,method:'tools/list'});
  expect(init.result.capabilities.tools).toEqual({});expect(listing.result.tools.find((t:any)=>t.name==='coordination.inspect').inputSchema.required).toContain('connection_id');
  for(const [name,args,code] of [['coordination.inspect',{},'unknown_agent_connection'],['coordination.inspect',{connection_id:pairId},'tool_outside_grant'],['coordination.prepare_task',{...input,approve:true},'invalid_input'],['negotiation_approve',{connection_id:pairId},'unknown_tool']] as const){const result:any=await handleAgentProfileRequest(f.client,rpc(name,args));expect(JSON.parse(result.result.content[0].text).code).toBe(code);}
  const list:any=await handleAgentProfileRequest(f.client,rpc('coordination.connections'));expect(JSON.stringify(list)).not.toContain(readAgentProfile(f.path).connections[pairId].token);expect(f.fetcher).not.toHaveBeenCalled();
 });
 it('rejects an authority-signed enrollment whose owner grant targets another key',async()=>{
  const f=await fixture();await f.ready();f.failures.add('negotiation_pair_claim');await expect(f.client.claimTaskConnection(requestId)).rejects.toThrow();
  const auth=f.binding.payload.owner_authorization;f.binding=await sign({...f.binding.payload,owner_authorization:await sign({...auth.payload,body:{...auth.payload.body,expected_agent_key:'ab'.repeat(32)}},f.owner)},f.authority);
  await expect(f.client.claimTaskConnection(requestId)).rejects.toThrow('another agent key');expect(readAgentProfile(f.path).connections).toEqual({});
 });
 it('claims an exact separately signed execution grant with a fresh token and recovers a lost reply without widening negotiation',async()=>{
  const f=await fixture();await f.ready();await f.client.claimTaskConnection(requestId);const before=canonical(readAgentProfile(f.path).connections[pairId]);await f.offer();
  const offered=await f.client.checkHandoffs(pairId);expect(offered.handoffs[0].agreement_digest).toBe('ef'.repeat(32));
  f.failures.add('agent_handoff_claim');await expect(f.client.claimExecutionConnection(pairId,f.handoff.pair_id)).rejects.toMatchObject({code:'agent_connection_interrupted'});
  const pending=readAgentProfile(f.path).pendingHandoffs[f.handoff.pair_id];expect(pending.token).not.toBe(readAgentProfile(f.path).connections[pairId].token);
  const result=await f.client.claimExecutionConnection(pairId,f.handoff.pair_id),profile=readAgentProfile(f.path);
  expect(result).toMatchObject({connection_id:f.handoff.pair_id,purpose:'execution'});expect(profile.connections[f.handoff.pair_id].token).toBe(pending.token);expect(profile.pendingHandoffs).toEqual({});expect(canonical(profile.connections[pairId])).toBe(before);
  expect(f.bodies.filter(b=>b.action==='agent_handoff_claim').map(b=>b.body.executor_token)).toEqual([pending.token,pending.token]);expect(JSON.stringify(result)).not.toContain(pending.token);expect(JSON.stringify(result)).toContain('no action was executed');
 });
 it('rejects wrong-source, wider-scope, forged-owner, revoked and corrupt execution grants',async()=>{
  const f=await fixture();await f.ready();await f.client.claimTaskConnection(requestId);const original=await f.offer();
  for(const changed of [{...original,source_pair_id:'another-pair-001'},{...original,authorization:await sign({...original.authorization.payload,body:{...original.authorization.payload.body,scope:[...PAIRING_SCOPE,'decide']}},f.owner)},{...original,authorization:await sign(original.authorization.payload,f.authority)},{...original,status:'revoked' as const}]){f.handoff=changed;await expect(f.client.claimExecutionConnection(pairId,changed.pair_id)).rejects.toThrow();}
  f.handoff=original;f.failures.add('agent_handoff_claim');await expect(f.client.claimExecutionConnection(pairId,original.pair_id)).rejects.toThrow();
  f.executionBinding=await sign({...f.executionBinding.payload,agreement_digest:'ee'.repeat(32)},f.authority);await expect(f.client.claimExecutionConnection(pairId,original.pair_id)).rejects.toMatchObject({code:'invalid_handoff_binding'});
  expect(Object.keys(readAgentProfile(f.path).connections)).toEqual([pairId]);
 });
 it('imports an old grant without pretending its discarded private agent key can authorize a handoff',async()=>{
  const f=await fixture();await f.ready();await f.client.claimTaskConnection(requestId);const old=readAgentProfile(f.path).connections[pairId];
  const otherPath=join(f.dir,'new-profile.json');await ensureAgentProfile(otherPath,f.profile.endpoint,f.profile.authorityKey);const configPath=join(f.dir,'legacy.json');writeFileSync(configPath,JSON.stringify(old),{mode:0o600});
  expect(await importProfileConnection(otherPath,configPath)).toBe(pairId);const other=new CoordinationAgentClient(otherPath,f.fetcher as typeof fetch),before=f.fetcher.mock.calls.length;
  expect(other.connections().connections[0].same_profile_key).toBe(false);await expect(other.checkHandoffs(pairId)).rejects.toMatchObject({code:'handoff_profile_key_required'});expect(f.fetcher).toHaveBeenCalledTimes(before);
 });
});
