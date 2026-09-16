import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
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
 ];
 for(const [entry,prefix] of [[bin,['repository']],[receiver,[]]])for(const check of cases){
  const result=spawnSync(process.execPath,[entry,...prefix,...check.args],{cwd:dir,encoding:'utf8',timeout:30000,env:{...process.env,GITHUB_TOKEN:'release-check-placeholder',GH_TOKEN:''}});
  assert.equal(result.error,undefined);assert.equal(result.status,1,result.stderr+result.stdout);assert.match(result.stderr,new RegExp(check.error));
 }
 console.log('The packed package installs and its documented entry points run in an empty directory.');
 console.log('Main and standalone repository setup/ready entry points enforce local input checks.');
}finally{rmSync(dir,{recursive:true,force:true});}
