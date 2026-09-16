import {describe,it,expect} from 'vitest';
import {mkdtemp,readFile,writeFile,copyFile,stat,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import {importIdentity} from './coordination-protocol.js';
import {parseRepositoryReceiverConfig} from './repository-receiver.js';
const config={type:'scopeblind.repository.receiver-config.v1' as const,endpoint:'https://scopeblind.com/api/coordination',repository:'scopeblind/demo',base_branch:'main',authority_key:'1'.repeat(64),owner_key:'2'.repeat(64),reviewer_key:'3'.repeat(64),receiver_key:'4'.repeat(64)};
describe('trusted standalone receiver distribution',()=>{
 it('runs without node_modules, creates a valid owner-only key, and refuses to overwrite it',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'scopeblind-receiver-'));try{const cli=join(dir,'receiver.cjs'),key=join(dir,'key.json');await copyFile(resolve('dist/repository-receiver-cli.js'),cli);const run=()=>spawnSync(process.execPath,[cli,'keygen','--output',key],{cwd:dir,encoding:'utf8',env:{PATH:process.env.PATH}});const first=run();expect(first.status,first.stderr).toBe(0);const raw=await readFile(key,'utf8'),stored=JSON.parse(raw);expect((await stat(key)).mode&0o777).toBe(0o600);expect(first.stdout).not.toContain(stored.private_key);expect((await importIdentity(stored.private_key,stored.public_key)).publicKey).toBe(stored.public_key);expect(run().status).toBe(1);expect(await readFile(key,'utf8')).toBe(raw);
  }finally{await rm(dir,{recursive:true,force:true});}
 });
 it('refuses privileged Actions use from another event, branch or repository before any network call',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'scopeblind-receiver-'));try{const cli=resolve('dist/repository-receiver-cli.js'),key=join(dir,'key.json'),file=join(dir,'config.json');const made=spawnSync(process.execPath,[cli,'keygen','--output',key],{encoding:'utf8'});expect(made.status).toBe(0);const stored=JSON.parse(await readFile(key,'utf8'));await writeFile(file,JSON.stringify({...config,receiver_key:stored.public_key}));for(const override of [{GITHUB_EVENT_NAME:'pull_request_target'},{GITHUB_REF:'refs/heads/feature'},{GITHUB_REPOSITORY:'attacker/demo'}]){const result=spawnSync(process.execPath,[cli,'execute','--config',file,'--task','task-test-123'],{encoding:'utf8',env:{PATH:process.env.PATH,SCOPEBLIND_RECEIVER_PRIVATE_KEY:stored.private_key,GITHUB_TOKEN:'never-sent',GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:config.repository,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REF:'refs/heads/main',...override}});expect(result.status).toBe(1);expect(result.stderr).toContain('receiver_trusted_workflow_required');expect(result.stdout+result.stderr).not.toContain(stored.private_key);}
  }finally{await rm(dir,{recursive:true,force:true});}
 });
 it('rejects credential-bearing, redirect-shaped or malformed configured endpoints and unseparated keys',()=>{
  expect(parseRepositoryReceiverConfig(config)).toEqual(config);for(const endpoint of ['http://scopeblind.com/api/coordination','https://secret@scopeblind.com/api/coordination','https://scopeblind.com/api/coordination?token=secret','https://scopeblind.com/api/coordination#secret','https://scopeblind.com/elsewhere'])expect(()=>parseRepositoryReceiverConfig({...config,endpoint})).toThrow();expect(()=>parseRepositoryReceiverConfig({...config,owner_key:config.receiver_key})).toThrow();expect(()=>parseRepositoryReceiverConfig({...config,unexpected:true})).toThrow();
 });
});
