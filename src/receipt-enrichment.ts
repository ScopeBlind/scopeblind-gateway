/**
 * Receipt enrichment (v1): deterministic, minimum-disclosure fields added to a
 * decision receipt BEFORE it is signed, so they are part of the tamper-evident
 * record and make it queryable by meaning (an "LLM wiki" / knowledge base).
 *
 *  - input_digest: SHA-256 of the canonical tool input. Commits to WHAT was
 *    requested without storing the (possibly sensitive) arguments. Unlike
 *    payload_digest (which only fires for large payloads), this is unconditional,
 *    so you can later prove a specific request was or was not made.
 *  - capabilities: coarse, rule-derived tags (fs.write, net.egress, secret.adjacent,
 *    financial, ...) so the record clusters by meaning. Deterministic given the
 *    input and the rule version (`v`), so reproducible and auditable. These are
 *    heuristic ORGANISATION labels, NOT a security verdict.
 *  - resource: a hashed coarse resource (path / host / command) so decisions that
 *    touch the same thing cluster, without revealing the thing itself. The owner
 *    can re-hash their own paths to recover the mapping; a third party sees only
 *    the digest (minimum disclosure).
 *
 * NOT here, by design: the model's prompt or reasoning. The gate observes tool
 * CALLS, not the LLM's thoughts; claiming to receipt them would be an overclaim.
 * An advisory LLM tagging layer, if ever wanted, belongs OUTSIDE the signed
 * receipt (off the deny hot path, never signed as fact).
 */
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

export const ENRICHMENT_VERSION = 1;

export interface ReceiptEnrichment {
  /** Rule/schema version, so derivations stay reproducible as rules evolve. */
  v: number;
  /** SHA-256 (hex) of the canonical tool input. */
  input_digest: string;
  /** Sorted, deterministic capability tags (heuristic organisation labels). */
  capabilities: string[];
  /** Hashed coarse resource for clustering, when one is derivable. */
  resource?: { kind: 'path' | 'host' | 'command'; digest: string };
}

/**
 * RFC 8785-flavoured canonical JSON: object keys sorted, minimal separators,
 * undefined/function/symbol coerced to null. Deterministic across runs so the
 * input_digest is stable and reproducible.
 */
export function canonicalJson(value: unknown): string {
  const seen = new WeakSet<object>();
  const enc = (v: unknown): string => {
    if (v === null || v === undefined) return 'null';
    const t = typeof v;
    if (t === 'number') return Number.isFinite(v as number) ? JSON.stringify(v) : 'null';
    if (t === 'boolean' || t === 'string') return JSON.stringify(v);
    if (t === 'bigint') return JSON.stringify((v as bigint).toString());
    if (t === 'function' || t === 'symbol') return 'null';
    if (Array.isArray(v)) return '[' + v.map(enc).join(',') + ']';
    if (t === 'object') {
      const o = v as Record<string, unknown>;
      if (seen.has(o)) return '"[circular]"';
      seen.add(o);
      const body = Object.keys(o).sort().map((k) => JSON.stringify(k) + ':' + enc(o[k])).join(',');
      seen.delete(o);
      return '{' + body + '}';
    }
    return 'null';
  };
  return enc(value);
}

function sha256Hex(s: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(s)));
}

// Capability rules. `tool` matches the tool name; `text` matches the canonical
// input. Deterministic and intentionally coarse; false positives are acceptable
// for an organisation label and are clearly derived, not a verdict.
const RULES: Array<{ cap: string; tool?: RegExp; text?: RegExp }> = [
  { cap: 'exec.shell', tool: /bash|shell|exec|terminal|run_command|command/ },
  { cap: 'fs.read', tool: /(^|[_.])(read|cat|glob|grep|search|ls|view|list_files|open)/ },
  { cap: 'fs.write', tool: /write|create_file|save|append|edit|patch|replace|update_file|multiedit|notebook/ },
  { cap: 'fs.delete', tool: /delete|remove|unlink|trash|(^|[_.])rm/ },
  { cap: 'net.egress', tool: /fetch|http|curl|wget|request|download|browse|navigate|webfetch|web_search|scrape/ },
  { cap: 'vcs', tool: /(^|[_.])git/, text: /\bgit\s+(commit|push|pull|clone|reset|checkout|branch|rebase|merge|tag)\b/ },
  { cap: 'package.install', text: /\b(npm|pnpm|yarn)\s+(i|install|add)\b|\bpip3?\s+install\b|\bgo\s+get\b|\bcargo\s+add\b|\bbrew\s+install\b|\bapt(-get)?\s+install\b|\bgem\s+install\b/ },
  { cap: 'secret.adjacent', text: /\.env\b|secret|credential|passwd|password|api[_-]?key|private[_-]?key|\.pem\b|\.key\b|id_rsa|bearer\s|aws_(access|secret)|authorization/ },
  { cap: 'destructive', text: /rm\s+-[a-z]*[rf]|\brmdir\b|drop\s+table|truncate\s+table|delete\s+from|reset\s+--hard|--force\b|\bmkfs\b|\bdd\s+if=|shutdown|reboot|kill\s+-9|>\s*\/dev\/sd/ },
  { cap: 'financial', text: /\b(order|trade|buy|sell|transfer|wire|payment|withdraw|deposit|swap|invoice|charge|refund|settle)\b/ },
  { cap: 'data.query', text: /\bselect\s+[\s\S]+\bfrom\b|\binsert\s+into\b|\bupdate\s+[\s\S]+\bset\b|\bdelete\s+from\b/ },
];

export function deriveCapabilities(tool: string, input: unknown): string[] {
  const t = String(tool || '').toLowerCase();
  let text = '';
  try { text = canonicalJson(input).toLowerCase(); } catch { /* best-effort */ }
  const caps = new Set<string>();
  for (const r of RULES) {
    if (r.tool && r.tool.test(t)) caps.add(r.cap);
    if (r.text && r.text.test(text)) caps.add(r.cap);
  }
  return Array.from(caps).sort();
}

export function deriveResource(input: unknown): ReceiptEnrichment['resource'] {
  const o = (input && typeof input === 'object') ? (input as Record<string, unknown>) : {};
  const path = o.file_path ?? o.path ?? o.filePath ?? o.notebook_path ?? o.filename;
  if (typeof path === 'string' && path.trim()) return { kind: 'path', digest: sha256Hex(path.replace(/\\/g, '/')) };
  const url = o.url ?? o.uri ?? o.endpoint ?? o.href;
  if (typeof url === 'string' && url.trim()) {
    try { return { kind: 'host', digest: sha256Hex(new URL(url).host.toLowerCase()) }; } catch { /* not a URL */ }
  }
  const cmd = o.command ?? o.cmd ?? o.script;
  if (typeof cmd === 'string' && cmd.trim()) {
    const first = cmd.trim().split(/\s+/)[0];
    if (first) return { kind: 'command', digest: sha256Hex(first) };
  }
  return undefined;
}

/** Build the enrichment block for a decision receipt. Always returns input_digest. */
export function buildEnrichment(tool: string, input: unknown): ReceiptEnrichment {
  const e: ReceiptEnrichment = {
    v: ENRICHMENT_VERSION,
    input_digest: sha256Hex(canonicalJson(input ?? {})),
    capabilities: deriveCapabilities(tool, input),
  };
  const resource = deriveResource(input);
  if (resource) e.resource = resource;
  return e;
}
