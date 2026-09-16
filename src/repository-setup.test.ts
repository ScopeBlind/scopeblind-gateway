import {describe,it,expect} from 'vitest';
import {mkdtemp,readFile,readdir,rm,stat,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {canonical,COORDINATION_DOMAIN,generateIdentity,importIdentity,sha256,sign,verify} from './coordination-protocol.js';
import {createRepositoryReadiness,discoverRepository,parseRepositoryConnectionConfig,renderRepositoryWorkflow,runRepositoryCommand} from './repository-setup.js';
import type {RepositoryConnection,RepositoryConnectionImport} from './coordination-repository-collaboration.js';

const repo='example/reviewed',head='a'.repeat(40),base='b'.repeat(40),authority='1'.repeat(64),owner='2'.repeat(64),artifact='3'.repeat(64),token='PRIVATE_GITHUB_TEST_TOKEN';
function fixture(options:{noProtection?:boolean;workflow?:string;count?:number;checks?:any[];required?:any[];pin?:string}={}){
 const calls:Array<{url:string;init:RequestInit}>=[];
 const fetchImpl:typeof fetch=async (input,init={})=>{
  const url=String(input);calls.push({url,init});
  if(url==='https://scopeblind.com/api/coordination?op=info')return Response.json({ok:true,protocol:'scopeblind.coordination.v1',authority_key:options.pin??authority});
  if(url.endsWith('.cjs.sha256'))return new Response(`${artifact}  receiver.cjs\n`);
  const path=new URL(url).pathname;
  if(path===`/repos/${repo}`)return Response.json({full_name:repo,default_branch:'trunk',permissions:{admin:true,push:true}});
  if(path===`/repos/${repo}/branches/trunk`)return Response.json({name:'trunk',commit:{sha:base}});
  if(path===`/repos/${repo}/pulls/7`)return Response.json({number:7,state:'open',merged:false,base:{ref:'trunk',repo:{full_name:repo}},head:{sha:head,repo:{full_name:repo}}});
  if(path.endsWith('/check-runs')){const sha=path.includes(head)?head:base;const runs=options.checks??[{id:1,name:'Build and test',head_sha:sha,app:{id:15368,name:'GitHub Actions'}},{id:2,name:'Build and test',head_sha:sha,app:{id:987,name:'External CI'}}];return Response.json({total_count:options.count??runs.length,check_runs:runs});}
  if(path.endsWith('/protection'))return options.noProtection?Response.json({message:'unavailable'},{status:403}):Response.json({required_status_checks:{contexts:['Build and test','legacy-status'],checks:options.required??[{context:'Build and test',app_id:15368}]}});
  if(path.includes('/rules/branches/'))return Response.json([{type:'required_status_checks',parameters:{required_status_checks:[{context:'Build and test',integration_id:15368}]}}]);
  if(path.includes('/contents/'))return options.workflow===undefined?Response.json({message:'missing'},{status:404}):Response.json({type:'file',path:'.github/workflows/scopeblind-receiver.yml',sha:'c'.repeat(40),encoding:'base64',content:Buffer.from(options.workflow).toString('base64')});
  throw new Error('Unexpected fixture request');
 };
 return {fetchImpl,calls};
}
const setupArgs=(out:string)=>['setup','--repository',repo,'--owner-key',owner,'--authority-key',authority,'--output',out,'--pull','7'];
describe('owner-controlled repository setup',()=>{
 it('discovers actual branch, head, distinct provider identities and unresolved branch requirements using GET only',async()=>{
  const f=fixture(),d=await discoverRepository({repository:repo,pull_number:7},token,f.fetchImpl);
  expect(d.base_branch).toBe('trunk');expect(d.observed_head_sha).toBe(head);expect(d.checks).toEqual([{name:'Build and test',app_id:987,app_name:'External CI'},{name:'Build and test',app_id:15368,app_name:'GitHub Actions'}]);
  expect(d.required_checks).toEqual([{name:'Build and test',app_id:15368},{name:'legacy-status',app_id:null}]);expect(d.warnings.join(' ')).toContain('more than one app');expect(d.warnings.join(' ')).toContain('do not pin an app');
  expect(f.calls.every(c=>c.init.method==='GET'&&c.url.startsWith('https://api.github.com/'))).toBe(true);expect(JSON.stringify(d)).not.toContain(token);
 });
 it('never converts unavailable protection or missing check providers into an affirmative readiness claim',async()=>{
  const f=fixture({noProtection:true}),d=await discoverRepository({repository:repo},token,f.fetchImpl);expect(d.protection_read).toBe('unavailable');expect(d.warnings.join(' ')).toContain('does not mean the branch is unprotected');
  for(const bad of [fixture({count:101}),fixture({count:3}),fixture({checks:[{name:'CI',head_sha:base,app:{id:null}}]}),fixture({checks:[{name:'CI',head_sha:head,app:{id:1}}]})])await expect(discoverRepository({repository:repo},token,bad.fetchImpl)).rejects.toThrow();
  await expect(discoverRepository({repository:repo,base_branch:'attacker-branch'},token,f.fetchImpl)).rejects.toThrow('setup_use_trusted_default_branch');
 });
 it('writes a public exact-connection observation, reproducible workflow and owner-only private key without installing anything',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'repository-setup-')),out=join(dir,'prepared'),f=fixture();let output='';
  try{
   await runRepositoryCommand(setupArgs(out),{fetchImpl:f.fetchImpl,env:{GITHUB_TOKEN:token},stdout:s=>{output+=s;}});
   const key=JSON.parse(await readFile(join(out,'receiver-key.json'),'utf8')),bundle=JSON.parse(await readFile(join(out,'connection.json'),'utf8')) as RepositoryConnectionImport,config=parseRepositoryConnectionConfig(JSON.parse(await readFile(join(out,'connection-config.json'),'utf8')));
   expect((await stat(out)).mode&0o777).toBe(0o700);expect((await stat(join(out,'receiver-key.json'))).mode&0o777).toBe(0o600);expect((await importIdentity(key.private_key,key.public_key)).publicKey).toBe(config.connection.receiver_key);
   expect(await verify(bundle.readiness,key.public_key)).toBe(true);expect(bundle.readiness.payload.connection_digest).toBe(await sha256(COORDINATION_DOMAIN+canonical(bundle.connection)));expect(bundle.readiness.payload.runtime).toBe('local');expect(bundle.readiness.payload.workflow).toBe('missing');
   const workflow=await readFile(join(out,'scopeblind-receiver.yml'),'utf8');expect(workflow).toBe(renderRepositoryWorkflow({url:config.receiver_url,sha256:config.receiver_sha256}));expect(await sha256(workflow)).toBe(config.workflow_sha256);expect(workflow).not.toContain('checkout@');expect(workflow).not.toContain('npm install');expect(workflow).not.toContain('pull_request_target');expect(workflow).toContain('options: [ready, inspect, execute, reconcile]');
   const publicFiles=(await readdir(out)).filter(n=>n!=='receiver-key.json');for(const file of publicFiles){const text=await readFile(join(out,file),'utf8');expect(text).not.toContain(key.private_key);expect(text).not.toContain(token);}expect(output).not.toContain(key.private_key);expect(output).not.toContain(token);
   expect(f.calls.every(c=>c.init.method==='GET')).toBe(true);expect(f.calls.filter(c=>c.url.startsWith('https://scopeblind.com')).every(c=>!(c.init.headers as Record<string,string>)?.Authorization)).toBe(true);
   const before=await readFile(join(out,'receiver-key.json'),'utf8');await expect(runRepositoryCommand(setupArgs(out),{fetchImpl:f.fetchImpl,env:{GITHUB_TOKEN:token},stdout:()=>{}})).rejects.toThrow('setup_output_exists');expect(await readFile(join(out,'receiver-key.json'),'utf8')).toBe(before);
  }finally{await rm(dir,{recursive:true,force:true});}
 });
 it('stops on a wrong service pin before sending a GitHub credential or writing private files',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'repository-setup-')),out=join(dir,'prepared'),f=fixture({pin:'f'.repeat(64)});
  try{await expect(runRepositoryCommand(setupArgs(out),{fetchImpl:f.fetchImpl,env:{GITHUB_TOKEN:token},stdout:()=>{}})).rejects.toThrow('setup_service_pin_mismatch');expect(f.calls).toHaveLength(1);expect(await readdir(dir)).toEqual([]);}finally{await rm(dir,{recursive:true,force:true});}
 });
 it('records an installed workflow response only for its exact reviewed bytes and trusted dispatch context',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'repository-ready-')),out=join(dir,'prepared'),f=fixture();
  try{
   await runRepositoryCommand(setupArgs(out),{fetchImpl:f.fetchImpl,env:{GITHUB_TOKEN:token},stdout:()=>{}});const config=JSON.parse(await readFile(join(out,'connection-config.json'),'utf8'));const workflow=await readFile(join(out,'scopeblind-receiver.yml'),'utf8');const key=JSON.parse(await readFile(join(out,'receiver-key.json'),'utf8'));
   const args=['ready','--connection',join(out,'connection-config.json'),'--output',join(dir,'ready.json')];const env={GITHUB_TOKEN:token,SCOPEBLIND_RECEIVER_PRIVATE_KEY:key.private_key,GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:repo,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REF:'refs/heads/trunk',GITHUB_WORKFLOW_REF:`${repo}/.github/workflows/scopeblind-receiver.yml@refs/heads/trunk`};
   await expect(runRepositoryCommand(args,{fetchImpl:fixture({workflow:workflow+'# changed\n'}).fetchImpl,env,stdout:()=>{}})).rejects.toThrow('receiver_trusted_workflow_required');
   await expect(runRepositoryCommand(args,{fetchImpl:fixture({workflow}).fetchImpl,env:{...env,GITHUB_EVENT_NAME:'pull_request_target'},stdout:()=>{}})).rejects.toThrow('receiver_trusted_workflow_required');
   await runRepositoryCommand(args,{fetchImpl:fixture({workflow}).fetchImpl,env,stdout:()=>{}});const bundle=JSON.parse(await readFile(join(dir,'ready.json'),'utf8')) as RepositoryConnectionImport;expect(bundle.readiness.payload.runtime).toBe('github_actions');expect(bundle.readiness.payload.workflow).toBe('matching');expect(bundle.connection).toEqual(config.connection);expect(await verify(bundle.readiness,key.public_key)).toBe(true);
   await expect(runRepositoryCommand(args,{fetchImpl:fixture({workflow}).fetchImpl,env,stdout:()=>{}})).rejects.toThrow();
  }finally{await rm(dir,{recursive:true,force:true});}
 });
 it('does not permit changed connection fields, same principal keys or malformed pins to borrow signed readiness',async()=>{
  const identity=await generateIdentity(),d=await discoverRepository({repository:repo},token,fixture().fetchImpl),now=Date.now();const connection:RepositoryConnection={type:'scopeblind.repository.connection.v1',id:'connection-test',endpoint:'https://scopeblind.com/api/coordination',repository:repo,base_branch:'trunk',owner_key:owner,authority_key:authority,receiver_key:identity.publicKey,issued_at:new Date(now).toISOString(),expires_at:new Date(now+86400000).toISOString()};
  const bundle=await createRepositoryReadiness(connection,identity,d,{now});const human=await generateIdentity();expect((await sign(connection,human)).digest).toBe(bundle.readiness.payload.connection_digest);expect(await sha256(COORDINATION_DOMAIN+canonical({...connection,repository:'attacker/elsewhere'}))).not.toBe(bundle.readiness.payload.connection_digest);
  await expect(createRepositoryReadiness({...connection,receiver_key:owner},identity,d,{now})).rejects.toThrow();await expect(createRepositoryReadiness({...connection,expires_at:new Date(now-1).toISOString()},identity,d,{now})).rejects.toThrow();
  const c={type:'scopeblind.repository.connection-config.v1',connection,receiver_url:'https://scopeblind.com/releases/repository-receiver-0.22.0.cjs',receiver_sha256:artifact,workflow_path:'.github/workflows/scopeblind-receiver.yml',workflow_sha256:artifact};expect(parseRepositoryConnectionConfig(c)).toEqual(c);
  for(const bad of [{...c,connection:{...connection,owner_key:identity.publicKey}},{...c,receiver_url:'https://attacker.example/receiver.cjs'},{...c,connection:{...connection,endpoint:'https://secret@scopeblind.com/api/coordination'}},{...c,extra:'authority'}])expect(()=>parseRepositoryConnectionConfig(bad)).toThrow();
 });
});
