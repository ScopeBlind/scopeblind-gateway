import {describe,it,expect} from 'vitest';
import {readAgentResponse} from './coordination-agent-client.js';
describe('bounded agent evidence transport',()=>{
 it('decodes UTF-8 across chunk boundaries',async()=>{const bytes=new TextEncoder().encode('{"text":"Review ✓"}');const body=new ReadableStream<Uint8Array>({start(c){for(const byte of bytes)c.enqueue(Uint8Array.of(byte));c.close();}});expect(await readAgentResponse(new Response(body))).toBe('{"text":"Review ✓"}');});
 it('cancels oversized chunked responses before collecting the rest',async()=>{let cancelled=false;const body=new ReadableStream<Uint8Array>({pull(c){c.enqueue(new Uint8Array(1_000_001));},cancel(){cancelled=true;}});await expect(readAgentResponse(new Response(body))).rejects.toMatchObject({code:'invalid_agent_response'});expect(cancelled).toBe(true);});
 it('rejects an oversized announced body without consuming it',async()=>{let cancelled=false;const body=new ReadableStream<Uint8Array>({cancel(){cancelled=true;}});await expect(readAgentResponse(new Response(body,{headers:{'content-length':'4000001'}}))).rejects.toMatchObject({code:'invalid_agent_response'});expect(cancelled).toBe(true);});
 it('rejects malformed UTF-8 instead of changing signed JSON text',async()=>{await expect(readAgentResponse(new Response(Uint8Array.of(0xc3,0x28)))).rejects.toMatchObject({code:'invalid_agent_response'});});
});
