import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {execFileSync} from 'node:child_process';
const packed=JSON.parse(readFileSync('packed.json','utf8'))[0];
const dir=mkdtempSync(join(tmpdir(),'scopeblind-release-check-'));
try{
 execFileSync('npm',['install','--prefix',dir,'--ignore-scripts','--no-audit','--no-fund',resolve(packed.filename)],{stdio:'inherit'});
 const bin=join(dir,'node_modules',"protect-mcp","dist/cli.js");
 for(const args of [["--help"], ["init"], ["repository", "keygen", "--output", "receiver-key.json"]])execFileSync(process.execPath,[bin,...args],{cwd:dir,stdio:'inherit',timeout:30000});
 console.log('The packed package installs and its documented entry points run in an empty directory.');
}finally{rmSync(dir,{recursive:true,force:true});}
