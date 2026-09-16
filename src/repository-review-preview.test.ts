import {describe,it,expect} from 'vitest';
import {observeRepositoryReviewPreview} from './repository-review-preview.js';
import type {Signed} from './coordination-protocol.js';
import type {RepositoryReviewBrief} from './coordination-repository-review.js';
import type {RepositoryProposal} from './coordination-repository.js';
const head='a'.repeat(40),now=1800000000000,at=(delta=0)=>new Date(now+delta).toISOString();
function fixture(){
 const brief={payload:{preview_policy:{environment:'Preview',check:{name:'Deploy preview',app_id:91},allowed_origins:['https://preview.example.com'],required:true}}} as Signed<RepositoryReviewBrief>,proposal={payload:{head_sha:head}} as Signed<RepositoryProposal>;
 const deployment={id:10,sha:head,environment:'Preview',created_at:at(-1000),creator:{id:101}},status={id:20,state:'success',environment:'Preview',environment_url:'https://preview.example.com/pr/7',created_at:at(-900),updated_at:at(-800),creator:{id:202}},check={id:30,name:'Deploy preview',head_sha:head,app:{id:91},status:'completed',conclusion:'success'};
 const data={deployments:[deployment],statuses:[status],runs:{total_count:1,check_runs:[check]}},paths:string[]=[];
 const get=async(path:string)=>{paths.push(path);return {body:path.includes('/statuses?')?data.statuses:path.includes('/check-runs?')?data.runs:data.deployments};};
 return {brief,proposal,deployment,status,check,data,paths,get,observe:()=>observeRepositoryReviewPreview(get,'Owner/Repo',brief,proposal,now)};
}
describe('read-only exact-head preview discovery',()=>{
 it('attests metadata, preserves distinct publishers, and never fetches the external preview',async()=>{const f=fixture(),p=await f.observe();expect(p.status).toBe('available');if(p.status==='available'){expect(p.deployment.deployment_creator_id).toBe(101);expect(p.deployment.status_creator_id).toBe(202);expect(p.deployment.check.app_id).toBe(91);expect(p).not.toHaveProperty('artifact');}expect(f.paths).toHaveLength(3);expect(f.paths.every(p=>p.startsWith('/repos/Owner/Repo/'))).toBe(true);expect(f.paths[0]).toContain(`sha=${head}`);});
 it('does no I/O when no preview policy was signed',async()=>{const f=fixture();delete f.brief.payload.preview_policy;expect((await f.observe()).status).toBe('not_requested');expect(f.paths).toEqual([]);});
 it('does not borrow an older successful deployment when the newest is pending or failed',async()=>{for(const state of ['queued','inactive','failure']){const f=fixture();f.data.deployments.push({...f.deployment,id:11,created_at:at(-700)});f.status.state=state;const result=await f.observe();expect(result.status).toBe(state==='queued'?'pending':'failed');expect(f.paths[1]).toContain('/deployments/11/statuses');}});
 it('rejects changed heads, lookalike provider checks, unsafe URLs, and incomplete lists',async()=>{for(const change of [(f:ReturnType<typeof fixture>)=>{f.deployment.sha='b'.repeat(40);},(f:ReturnType<typeof fixture>)=>{f.check.app.id=92;},(f:ReturnType<typeof fixture>)=>{f.check.head_sha='b'.repeat(40);},(f:ReturnType<typeof fixture>)=>{f.status.environment_url='https://preview.example.com.evil.test/';},(f:ReturnType<typeof fixture>)=>{f.status.environment_url='javascript:alert(1)';},(f:ReturnType<typeof fixture>)=>{f.status.environment_url='https://user:secret@preview.example.com/';},(f:ReturnType<typeof fixture>)=>{f.data.runs.total_count=101;},(f:ReturnType<typeof fixture>)=>{f.data.deployments=Array(100).fill(f.deployment);},(f:ReturnType<typeof fixture>)=>{f.status.updated_at=at(1000);}]){const f=fixture();change(f);expect((await f.observe()).status).toBe('unavailable');}});
 it('reports missing and unavailable without leaking provider response contents or credentials',async()=>{const f=fixture();f.data.deployments=[];expect((await f.observe()).status).toBe('missing');const p=await observeRepositoryReviewPreview(async()=>{throw new Error('token/private provider contents');},'Owner/Repo',f.brief,f.proposal,now);expect(p.status).toBe('unavailable');expect(JSON.stringify(p)).not.toContain('token');});
});

it('offers signed-policy input choices without inferring that a check App published the deployment',async()=>{
 const {discoverRepositoryPreviewChoices}=await import('./repository-review-preview.js'),f=fixture(),choices=await discoverRepositoryPreviewChoices(f.get,'Owner/Repo',head,now);expect(choices.status).toBe('observed');expect(choices.candidates).toEqual([{environment:'Preview',origin:'https://preview.example.com',environment_url:'https://preview.example.com/pr/7',deployment_id:10,status_id:20}]);expect(choices.checks).toEqual([{name:'Deploy preview',app_id:91,id:30}]);
 f.status.environment_url='https://preview.example.com/pr/7?bypass=secret';const privateLink=await discoverRepositoryPreviewChoices(f.get,'Owner/Repo',head,now);expect(privateLink.candidates).toEqual([]);expect(JSON.stringify(privateLink)).not.toContain('secret');
});
