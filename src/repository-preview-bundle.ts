/** The portable static-build format. A digest covers paths, byte lengths and bytes. */
import {canonical,sha256,bytesToHex} from './coordination-protocol.js';
export const REPOSITORY_PREVIEW_MAX_BYTES=512*1024;
export const REPOSITORY_PREVIEW_MAX_FILES=64;
export interface RepositoryPreviewFile {path:string;content_base64:string;sha256:string}
export interface RepositoryPreviewBundle {files:RepositoryPreviewFile[];sha256:string}
export interface RepositoryPreviewEntry {path:string;sha256:string;bytes:number}
export const PREVIEW_TYPES:Record<string,string>={html:'text/html; charset=utf-8',css:'text/css; charset=utf-8',js:'text/javascript; charset=utf-8',mjs:'text/javascript; charset=utf-8',json:'application/json; charset=utf-8',svg:'image/svg+xml',png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',webp:'image/webp',gif:'image/gif',ico:'image/x-icon',woff2:'font/woff2',txt:'text/plain; charset=utf-8'};
export function repositoryPreviewPath(path:unknown):path is string {
 return typeof path==='string'&&path.length<=200&&path.split('/').length<=10&&path.split('/').every(p=>/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(p))&&Object.hasOwn(PREVIEW_TYPES,path.split('.').at(-1)??'');
}
const exact=(v:unknown,keys:string[]):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(' ')===[...keys].sort().join(' ');
function need(value:unknown):asserts value {if(!value)throw new Error('invalid_repository_preview_bundle');}
export async function validateRepositoryPreviewBundle(value:unknown):Promise<{digest:string;entries:RepositoryPreviewEntry[];files:Array<{path:string;bytes:Uint8Array;sha256:string}>}> {
 need(exact(value,['files','sha256'])&&typeof value.sha256==='string'&&/^[a-f0-9]{64}$/.test(value.sha256)&&Array.isArray(value.files)&&value.files.length>0&&value.files.length<=REPOSITORY_PREVIEW_MAX_FILES);
 let total=0,last='';const files:Array<{path:string;bytes:Uint8Array;sha256:string}>=[],entries:RepositoryPreviewEntry[]=[];
 for(const file of value.files){
  need(exact(file,['path','content_base64','sha256'])&&repositoryPreviewPath(file.path)&&file.path>last&&typeof file.sha256==='string'&&/^[a-f0-9]{64}$/.test(file.sha256)&&typeof file.content_base64==='string'&&file.content_base64.length<=Math.ceil(REPOSITORY_PREVIEW_MAX_BYTES/3)*4&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(file.content_base64));
  const raw=atob(file.content_base64);need(btoa(raw)===file.content_base64);const bytes=Uint8Array.from(raw,c=>c.charCodeAt(0));total+=bytes.byteLength;need(total<=REPOSITORY_PREVIEW_MAX_BYTES);
  need(bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)))===file.sha256);last=file.path;
  files.push({path:file.path,bytes,sha256:file.sha256});entries.push({path:file.path,sha256:file.sha256,bytes:bytes.length});
 }
 need(entries.some(f=>f.path==='index.html'));const digest=await sha256(canonical(entries));need(digest===value.sha256);return {digest,entries,files};
}
