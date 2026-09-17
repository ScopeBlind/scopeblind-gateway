import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
const packed=JSON.parse(readFileSync('packed.json','utf8'))[0];
const dir=mkdtempSync(join(tmpdir(),'scopeblind-release-check-'));
try{
 execFileSync('npm',['install','--prefix',dir,'--ignore-scripts','--no-audit','--no-fund',resolve(packed.filename)],{stdio:'inherit'});
 const bin=join(dir,'node_modules',"protect-mcp","dist/cli.js");
 for(const args of [["--help"], ["init"], ["repository", "keygen", "--output", "receiver-key.json"]])execFileSync(process.execPath,[bin,...args],{cwd:dir,stdio:'inherit',timeout:30000});
 const receiver=join(dir,'node_modules','protect-mcp','dist/repository-receiver-cli.js');
 // Exercise both shipped entry points past option parsing, but stop locally
 // before any network request or GitHub credential lookup can occur.
 const cases=[
  {args:['setup','--repository','example/repository','--owner-key','a'.repeat(64),'--authority-key','b'.repeat(64),'--endpoint','http://127.0.0.1/api/coordination','--output','unused-setup'],error:'setup_invalid_endpoint'},
  {args:['ready','--connection','missing-connection-config.json','--output','unused-readiness.json'],error:'setup_invalid_connection_config'},
  {args:['connect','--link','https://untrusted.example/standard?setup=wrong'],error:'connect_private_link_invalid'},
  {args:['connection-job','--job','wrong'],error:'connect_runtime_arguments'},
  {args:['coding-ready'],error:'connect_runtime_arguments'},
 ];
 for(const [entry,prefix] of [[bin,['repository']],[receiver,[]]])for(const check of cases){
  const result=spawnSync(process.execPath,[entry,...prefix,...check.args],{cwd:dir,encoding:'utf8',timeout:30000,env:{...process.env,GITHUB_TOKEN:'release-check-placeholder',GH_TOKEN:''}});
  assert.equal(result.error,undefined);assert.equal(result.status,1,result.stderr+result.stdout);assert.match(result.stderr,new RegExp(check.error));
 }
 const coding=join(dir,'node_modules','protect-mcp','dist/repository-coding-cli.js');
 const codingResult=spawnSync(process.execPath,[coding,'--invalid-option'],{cwd:dir,encoding:'utf8',timeout:30000,env:{PATH:process.env.PATH}});
 assert.equal(codingResult.error,undefined);assert.equal(codingResult.status,1);assert.match(codingResult.stderr,/coding worker stopped/);
 const trial=join(dir,'node_modules','protect-mcp','dist/repository-trial-cli.js');
 const trialResult=spawnSync(process.execPath,[trial],{cwd:dir,encoding:'utf8',timeout:30000,env:{PATH:process.env.PATH}});
 assert.equal(trialResult.error,undefined);assert.equal(trialResult.status,1);assert.match(trialResult.stderr,/trial_trusted_workflow_required/);
 const installed=await import(pathToFileURL(join(dir,'node_modules','protect-mcp','dist/index.mjs')).href);
 for(const name of ['RepositoryCodingRunner','DockerCodingSandbox','verifyRepositoryCodingEvidence','verifyRepositorySetupState','validateRepositoryPreviewBundle','RepositoryTrialRunner','verifyRepositoryRecoveryObservation','verifyRepositoryTrialState'])assert.equal(typeof installed[name],'function','Packed public API is missing '+name);
 const profile=join(dir,'private-agent.json');
 execFileSync(process.execPath,[bin,'coordination','agent','setup','--client','json','--profile',profile,'--endpoint','https://scopeblind.com/api/coordination','--authority-key','a'.repeat(64)],{cwd:dir,stdio:'pipe',timeout:30000});
 const requests=[{jsonrpc:'2.0',id:1,method:'initialize'},{jsonrpc:'2.0',id:2,method:'tools/list'},{jsonrpc:'2.0',id:3,method:'tools/call',params:{name:'coordination.connections',arguments:{}}}];
 const agent=spawnSync(process.execPath,[bin,'coordination','agent','--profile',profile],{cwd:dir,input:requests.map(r=>JSON.stringify(r)).join('\n')+'\n',encoding:'utf8',timeout:30000});
 assert.equal(agent.error,undefined);assert.equal(agent.status,0,agent.stderr);
 const responses=agent.stdout.trim().split('\n').map(line=>JSON.parse(line)),names=responses.find(r=>r.id===2)?.result?.tools?.map(t=>t.name);
 for(const name of ['inspect_workspace','prepare_repository_review','inspect_repository_review','report_repository_criteria','request_repository_changes'])assert.ok(names?.includes('coordination.'+name),'Packed agent is missing '+name);
 for(const name of ['repository_approve','repository_begin','repository_accept','workspace_adopt'])assert.ok(!names.includes('coordination.'+name),'Packed agent exposes human authority');
 const connections=JSON.parse(responses.find(r=>r.id===3).result.content[0].text);assert.match(connections.agent_key,/^[a-f0-9]{64}$/);assert.deepEqual(connections.connections,[]);
 const privateProfile=JSON.parse(readFileSync(profile,'utf8'));assert.ok(!agent.stdout.includes(privateProfile.privateKey),'Private agent key appeared in MCP output');
 console.log('The packed package installs and its documented entry points run in an empty directory.');
 console.log('Main and standalone guided connection/receiver entry points enforce local input checks; the coding controller and verification exports load from the installed package.');
 console.log('The installed MCP agent exposes all five bounded project/review tools and no human approval or execution tools.');
}finally{rmSync(dir,{recursive:true,force:true});}
