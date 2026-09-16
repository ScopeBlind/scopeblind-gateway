import {afterEach,describe,expect,it,vi} from 'vitest';
import {mkdtempSync,rmSync,chmodSync,symlinkSync,writeFileSync,statSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {ensureAgentProfile,readAgentProfile,updateAgentProfile} from './coordination-agent-profile.js';
import {parseAgentTaskDraft,prepareAgentTaskDraft} from './coordination-agent-requests.js';
import {runCoordinationAgent} from './coordination-agent-server.js';
import {generateIdentity} from './coordination-protocol.js';
const dirs:string[]=[];function temp(){const dir=mkdtempSync(join(tmpdir(),'scopeblind-agent-profile-'));dirs.push(dir);return join(dir,'private.json');}
afterEach(()=>{for(const dir of dirs.splice(0))rmSync(dir,{recursive:true,force:true});vi.restoreAllMocks();});
describe('unsigned shared task draft',()=>{
 it('marks every inferred limit and preserves the distinction between shared goal and private instructions',()=>{
  const draft=prepareAgentTaskDraft({title:'Review invoices',goal:'Keep normal invoices moving',private_brief:'PRIVATE_NEGOTIATION_CONTEXT'});
  expect(draft.assumptions).toHaveLength(8);expect(draft.assumptions.some(a=>a.includes('15 minutes'))).toBe(true);
  expect(draft.assumptions.some(a=>a.includes('fictional USD'))).toBe(true);expect(draft.private_brief).toBe('PRIVATE_NEGOTIATION_CONTEXT');
  expect(draft).toMatchObject({budget_minor:200000,approval_above_minor:50000,min_budget_minor:200000,max_budget_minor:200000});
  expect(parseAgentTaskDraft(draft)).toEqual(draft);
 });
 it('refuses unsupported authority, ambiguous coercions, impossible limits and oversized assumptions',()=>{
  const draft=prepareAgentTaskDraft({title:'Review',goal:'Agree a policy'});
  for(const changes of [{approve:true},{budget_minor:'200000'},{approval_ttl_seconds:29},{approval_ttl_seconds:901},{require_po_match:false},{min_budget_minor:300000,max_budget_minor:200000},{max_threshold_minor:200001},{assumptions:Array(13).fill('assumed')},{assumptions:['x'.repeat(301)]}])expect(()=>parseAgentTaskDraft({...draft,...changes})).toThrow();
  for(const changes of [{real_bank_account:'unauthorized'},{type:'fake'},{assumptions:'text'}])expect(()=>prepareAgentTaskDraft({title:'Review',goal:'Agree a policy',...changes})).toThrow();
 });
});
describe('persistent private agent identity',()=>{
 it('reuses its agent key and refuses changed pins, unsafe files, symlinks and corrupt credentials',async()=>{
  const path=temp(),authority=await generateIdentity(),profile=await ensureAgentProfile(path,'https://scopeblind.com/api/coordination',authority.publicKey);
  expect(statSync(path).mode&0o777).toBe(0o600);expect((await ensureAgentProfile(path)).agentKey).toBe(profile.agentKey);
  await expect(ensureAgentProfile(path,undefined,'ab'.repeat(32))).rejects.toThrow('pinned');
  chmodSync(path,0o644);expect(()=>readAgentProfile(path)).toThrow('permissions 600');chmodSync(path,0o600);
  const link=path+'.link';symlinkSync(path,link);await expect(ensureAgentProfile(link)).rejects.toThrow('could not be opened');
  writeFileSync(path,'{"privateKey":"DO_NOT_PRINT');expect(()=>readAgentProfile(path)).toThrow('not valid JSON');
  try{readAgentProfile(path);}catch(error){expect(String(error)).not.toContain('DO_NOT_PRINT');}
 });
 it('serializes concurrent local updates and keeps capacity failures atomic',async()=>{
  const path=temp(),authority=await generateIdentity();await ensureAgentProfile(path,'https://scopeblind.com/api/coordination',authority.publicKey);
  await Promise.all(Array.from({length:5},(_,index)=>updateAgentProfile(path,p=>{p.requests['request-'+index]={draft:prepareAgentTaskDraft({title:'Review',goal:'Agree a policy'}),reviewSecret:'aa'.repeat(32),pairingSecret:'bb'.repeat(32),expiresAt:new Date(Date.now()+3600000).toISOString()};})));
  expect(Object.keys(readAgentProfile(path).requests)).toHaveLength(5);const before=readFileSync(path,'utf8');
  await expect(updateAgentProfile(path,p=>{for(let i=0;i<51;i++)p.requests['request-'+i]=p.requests['request-0'];})).rejects.toThrow('connection limit');expect(readFileSync(path,'utf8')).toBe(before);
 });
 it('prints a stable client registration with no private keys, tokens or authority in environment variables',async()=>{
  const path=temp(),authority=await generateIdentity(),write=vi.spyOn(process.stdout,'write').mockImplementation(()=>true);
  await runCoordinationAgent(['setup','--profile',path,'--endpoint','https://scopeblind.com/api/coordination','--authority-key',authority.publicKey,'--client','codex']);
  const profile=readAgentProfile(path),output=write.mock.calls.flat().join('');expect(output).toContain('codex mcp add scopeblind-agent-'+profile.agentKey.slice(0,12));expect(output).toContain('coordination agent --profile');expect(output).not.toContain(profile.privateKey);expect(output).not.toContain('--token');
  expect(output).toContain('each person reviews and signs');
 });
});
