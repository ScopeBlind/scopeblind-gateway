import {createInterface} from 'node:readline';
import {resolve} from 'node:path';
import {CoordinationAgentClient} from './coordination-agent-client.js';
import {CoordinationError} from './coordination-client.js';
import {COORDINATION_TOOLS,REHEARSAL_TOOLS,NEGOTIATION_TOOLS,handleCoordinationRequest} from './coordination-server.js';
import {DEFAULT_AGENT_PROFILE,ensureAgentProfile,importProfileConnection} from './coordination-agent-profile.js';
import {agentClient,agentProfileRegistration} from './coordination-agent-setup.js';

const id={type:'string',pattern:'^[A-Za-z0-9_-]{8,100}$'};
const amount={type:'integer',minimum:0,maximum:10_000_000};
const draftSchema={type:'object',additionalProperties:false,properties:{
  title:{type:'string',minLength:1,maxLength:100},goal:{type:'string',minLength:1,maxLength:2000},counterparty_name:{type:'string',maxLength:60},
  budget_minor:{...amount,minimum:1},approval_above_minor:amount,approval_ttl_seconds:{type:'integer',minimum:30,maximum:900},require_po_match:{type:'boolean',const:true},
  min_budget_minor:{...amount,minimum:1},max_budget_minor:{...amount,minimum:1},min_threshold_minor:amount,max_threshold_minor:amount,
  private_brief:{type:'string',maxLength:2000},preference:{type:'string',enum:['fewer_reviews','more_review','balanced']},budget_preference:{type:'string',enum:['preserve_budget','lower_budget','more_capacity']},assumptions:{type:'array',maxItems:12,items:{type:'string',minLength:1,maxLength:300}},
},required:['title','goal']};
export const AGENT_PROFILE_TOOLS=[
  {name:'coordination.prepare_task',description:'Prepare an unsigned shared invoice-task draft for your own person to review. Use a stable request_id for retries. Proposed limits, preferences, and assumptions grant no authority. Returns a private review link intended only for the requesting person; they review and sign in the browser, invite the other person, and explicitly authorize a scoped agent. Do not put unsupported hard rules into a preference. No room, human signature, payment, or hosted model is created by this tool.',inputSchema:{type:'object',additionalProperties:false,properties:{request_id:id,draft:draftSchema},required:['request_id','draft']},annotations:{title:'Prepare a shared task for human review',readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}},
  {name:'coordination.inspect_task_request',description:'Check a draft prepared by this profile. An accepted draft is still not an agent grant. Ready means the person separately signed the named negotiation grant; use claim_task_connection and inspect the mandate before acting. Does not poll in the background or reveal the draft to another principal.',inputSchema:{type:'object',additionalProperties:false,properties:{request_id:id},required:['request_id']},annotations:{title:'Check the person’s review and agent grant',readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false}},
  {name:'coordination.claim_task_connection',description:'Claim the exact negotiation connection explicitly authorized for this profile’s key after human review. Saves its separate token locally and returns a connection_id. Does not sign a mandate, establish readiness, execute, approve, or grant ownership. Inspect the returned connection before taking its next permitted action.',inputSchema:{type:'object',additionalProperties:false,properties:{request_id:id},required:['request_id']},annotations:{title:'Connect to the human-authorized task',readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}},
  {name:'coordination.connections',description:'List saved purpose-scoped connections without credentials. A saved grant may have expired or been revoked: inspect before acting. Every scoped tool requires its explicit connection_id so another task or purpose cannot be selected implicitly.',inputSchema:{type:'object',additionalProperties:false,properties:{}},annotations:{title:'List this agent’s separate connections',readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false}},
  {name:'coordination.check_handoffs',description:'Check whether the organizer separately authorized this same agent to execute the exact jointly adopted task. Requires the original negotiation connection_id. Uses the profile key, never broadens the old negotiation token, and performs no payment. Legacy imported connections without the original private agent key cannot claim this continuity.',inputSchema:{type:'object',additionalProperties:false,properties:{connection_id:id},required:['connection_id']},annotations:{title:'Check for a separately authorized execution handoff',readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false}},
  {name:'coordination.claim_execution_connection',description:'Claim one exact owner-signed execution handoff discovered by check_handoffs. Returns a NEW execution connection_id while preserving the negotiation grant separately. The local token is persisted before claiming so a lost reply can be retried with the same handoff_id. Does not execute or approve anything; inspect the new room before acting.',inputSchema:{type:'object',additionalProperties:false,properties:{connection_id:id,handoff_id:id},required:['connection_id','handoff_id']},annotations:{title:'Claim the approved execution handoff',readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false}},
];
const scopedTools=[...COORDINATION_TOOLS,...REHEARSAL_TOOLS,...NEGOTIATION_TOOLS].map(tool=>({...tool,description:tool.description+' Select the exact saved connection_id for this purpose; permissions are never combined across connections.',inputSchema:{...tool.inputSchema,properties:{...tool.inputSchema.properties,connection_id:id},required:[...('required' in tool.inputSchema?tool.inputSchema.required??[]:[]),'connection_id']}}));
interface Request{jsonrpc?:unknown;id?:string|number|null;method?:unknown;params?:{name?:unknown;arguments?:unknown;requestId?:unknown}}
const result=(request:Request,value:unknown,error=false)=>({jsonrpc:'2.0',id:request.id,result:{content:[{type:'text',text:JSON.stringify(value)}],...(error?{isError:true}:{})}});
export async function handleAgentProfileRequest(client:CoordinationAgentClient,request:Request,signal?:AbortSignal):Promise<unknown>{
  if(!request||request.jsonrpc!=='2.0'||typeof request.method!=='string')return {jsonrpc:'2.0',id:request?.id??null,error:{code:-32600,message:'Invalid JSON-RPC request.'}};
  if(request.id===undefined)return undefined;
  if(request.method==='initialize')return {jsonrpc:'2.0',id:request.id,result:{protocolVersion:'2024-11-05',serverInfo:{name:'protect-mcp-agent',version:process.env.PROTECT_MCP_VERSION||'0.21.0'},capabilities:{tools:{}}}};
  if(request.method==='ping')return {jsonrpc:'2.0',id:request.id,result:{}};
  if(request.method==='tools/list')return {jsonrpc:'2.0',id:request.id,result:{tools:[...AGENT_PROFILE_TOOLS,...scopedTools]}};
  if(request.method!=='tools/call')return {jsonrpc:'2.0',id:request.id,error:{code:-32601,message:'Method not found.'}};
  try{
    const args=request.params?.arguments??{};
    if(!args||typeof args!=='object'||Array.isArray(args))throw new CoordinationError('invalid_input','Tool arguments must be an object.');
    const fields=args as Record<string,unknown>,name=request.params?.name;
    const only=(...keys:string[])=>{if(Object.keys(fields).sort().join(',')!==keys.sort().join(','))throw new CoordinationError('invalid_input','Use only the exact fields required by this tool.');};
    if(name==='coordination.prepare_task'){only('request_id','draft');return result(request,await client.prepareTask(fields as unknown as {request_id:string;draft:unknown}));}
    if(name==='coordination.inspect_task_request'){only('request_id');return result(request,await client.inspectTaskRequest(fields.request_id as string));}
    if(name==='coordination.claim_task_connection'){only('request_id');return result(request,await client.claimTaskConnection(fields.request_id as string));}
    if(name==='coordination.connections'){only();return result(request,client.connections());}
    if(name==='coordination.check_handoffs'){only('connection_id');return result(request,await client.checkHandoffs(fields.connection_id as string));}
    if(name==='coordination.claim_execution_connection'){only('connection_id','handoff_id');return result(request,await client.claimExecutionConnection(fields.connection_id as string,fields.handoff_id as string));}
    if(!scopedTools.some(tool=>tool.name===name))throw new CoordinationError('unknown_tool','This profile does not expose that tool.');
    const {connection_id,...scoped}=fields;
    return await handleCoordinationRequest(client.clientFor(connection_id as string),{...request,params:{name,arguments:scoped}},signal);
  }catch(error){return result(request,{code:error instanceof CoordinationError?error.code:'agent_request_error',error:error instanceof Error?error.message:'The agent request could not be completed.'},true);}
}

function options(args:string[],mode:'server'|'setup'|'import'){
  const allowed=new Set(['--profile','--endpoint','--authority-key',...(mode==='setup'?['--client']:[]),...(mode==='import'?['--config']:[])]),values=new Map<string,string>();
  for(let index=0;index<args.length;index+=2){const flag=args[index],value=args[index+1];if(!allowed.has(flag)||values.has(flag)||!value||value.startsWith('--'))throw new Error('Use --profile, optional --endpoint/--authority-key for first setup, and the documented setup/import options.');values.set(flag,value);}
  return values;
}
export async function runCoordinationAgent(args:string[]):Promise<void>{
  const mode=args[0]==='setup'?'setup':args[0]==='import'?'import':'server';
  const values=options(mode==='server'?args:args.slice(1),mode),path=resolve(values.get('--profile')||DEFAULT_AGENT_PROFILE);
  const selected=mode==='setup'?agentClient(values.get('--client')||'claude-code'):undefined;
  const profile=await ensureAgentProfile(path,values.get('--endpoint'),values.get('--authority-key'));
  if(mode==='setup'){
    process.stdout.write(agentProfileRegistration(selected!,`scopeblind-agent-${profile.agentKey.slice(0,12)}`,path)+'\n');
    process.stdout.write('Register this server once, then ask your agent to prepare a shared task with coordination.prepare_task. The profile is an agent identity only; each person reviews and signs their own authority. Existing connections stay separately scoped.\n');return;
  }
  if(mode==='import'){
    if(!values.get('--config'))throw new Error('Import needs the existing --config file.');
    const id=await importProfileConnection(path,values.get('--config')!);
    process.stdout.write(`Saved existing scoped connection ${id}. Its authority is unchanged. Imported legacy keys cannot be recreated for automatic execution handoff.\n`);return;
  }
  const client=new CoordinationAgentClient(path),lines=createInterface({input:process.stdin,crlfDelay:Infinity});let chain=Promise.resolve();
  const waits=new Map<Request['id'],AbortController>(),cancel=()=>{for(const controller of waits.values())controller.abort();};lines.on('close',cancel);process.stdout.on('error',cancel);
  lines.on('line',line=>{
    if(!line.trim())return;let request:Request;
    try{if(line.length>1_000_000)throw new Error();request=JSON.parse(line);}catch{process.stdout.write(JSON.stringify({jsonrpc:'2.0',id:null,error:{code:-32700,message:'Invalid or oversized JSON-RPC message.'}})+'\n');return;}
    if(request?.jsonrpc==='2.0'&&request.method==='notifications/cancelled'){const id=request.params?.requestId;if(typeof id==='string'||typeof id==='number')waits.get(id)?.abort();return;}
    const controller=request?.method==='tools/call'&&['coordination.wait','coordination.run_rehearsal','coordination.wait_negotiation','coordination.compare_candidate'].includes(String(request.params?.name))?new AbortController():undefined;if(controller)waits.set(request.id,controller);
    chain=chain.then(async()=>{try{const response=await handleAgentProfileRequest(client,request,controller?.signal);if(response!==undefined)process.stdout.write(JSON.stringify(response)+'\n');}finally{if(controller&&waits.get(request.id)===controller)waits.delete(request.id);}});
  });
  process.stderr.write('[PROTECT_MCP] Agent profile ready. Drafts confer no authority. Every scoped tool needs a separately authorized connection_id. No background model work is started.\n');
  await new Promise<void>(resolve=>lines.on('close',resolve));await chain;process.stdout.removeListener('error',cancel);
}
