import {
  sha256
} from "./chunk-AYNQIEN7.mjs";
import {
  bytesToHex
} from "./chunk-D733KAPG.mjs";

// src/receipt-enrichment.ts
var ENRICHMENT_VERSION = 1;
function canonicalJson(value) {
  const seen = /* @__PURE__ */ new WeakSet();
  const enc = (v) => {
    if (v === null || v === void 0) return "null";
    const t = typeof v;
    if (t === "number") return Number.isFinite(v) ? JSON.stringify(v) : "null";
    if (t === "boolean" || t === "string") return JSON.stringify(v);
    if (t === "bigint") return JSON.stringify(v.toString());
    if (t === "function" || t === "symbol") return "null";
    if (Array.isArray(v)) return "[" + v.map(enc).join(",") + "]";
    if (t === "object") {
      const o = v;
      if (seen.has(o)) return '"[circular]"';
      seen.add(o);
      const body = Object.keys(o).sort().map((k) => JSON.stringify(k) + ":" + enc(o[k])).join(",");
      seen.delete(o);
      return "{" + body + "}";
    }
    return "null";
  };
  return enc(value);
}
function sha256Hex(s) {
  return bytesToHex(sha256(new TextEncoder().encode(s)));
}
var RULES = [
  { cap: "exec.shell", tool: /bash|shell|exec|terminal|run_command|command/ },
  { cap: "fs.read", tool: /(^|[_.])(read|cat|glob|grep|search|ls|view|list_files|open)/ },
  { cap: "fs.write", tool: /write|create_file|save|append|edit|patch|replace|update_file|multiedit|notebook/ },
  { cap: "fs.delete", tool: /delete|remove|unlink|trash|(^|[_.])rm/ },
  { cap: "net.egress", tool: /fetch|http|curl|wget|request|download|browse|navigate|webfetch|web_search|scrape/ },
  { cap: "vcs", tool: /(^|[_.])git/, text: /\bgit\s+(commit|push|pull|clone|reset|checkout|branch|rebase|merge|tag)\b/ },
  { cap: "package.install", text: /\b(npm|pnpm|yarn)\s+(i|install|add)\b|\bpip3?\s+install\b|\bgo\s+get\b|\bcargo\s+add\b|\bbrew\s+install\b|\bapt(-get)?\s+install\b|\bgem\s+install\b/ },
  { cap: "secret.adjacent", text: /\.env\b|secret|credential|passwd|password|api[_-]?key|private[_-]?key|\.pem\b|\.key\b|id_rsa|bearer\s|aws_(access|secret)|authorization/ },
  { cap: "destructive", text: /rm\s+-[a-z]*[rf]|\brmdir\b|drop\s+table|truncate\s+table|delete\s+from|reset\s+--hard|--force\b|\bmkfs\b|\bdd\s+if=|shutdown|reboot|kill\s+-9|>\s*\/dev\/sd/ },
  { cap: "financial", text: /\b(order|trade|buy|sell|transfer|wire|payment|withdraw|deposit|swap|invoice|charge|refund|settle)\b/ },
  { cap: "data.query", text: /\bselect\s+[\s\S]+\bfrom\b|\binsert\s+into\b|\bupdate\s+[\s\S]+\bset\b|\bdelete\s+from\b/ }
];
function deriveCapabilities(tool, input) {
  const t = String(tool || "").toLowerCase();
  let text = "";
  try {
    text = canonicalJson(input).toLowerCase();
  } catch {
  }
  const caps = /* @__PURE__ */ new Set();
  for (const r of RULES) {
    if (r.tool && r.tool.test(t)) caps.add(r.cap);
    if (r.text && r.text.test(text)) caps.add(r.cap);
  }
  return Array.from(caps).sort();
}
function deriveResource(input) {
  const o = input && typeof input === "object" ? input : {};
  const path = o.file_path ?? o.path ?? o.filePath ?? o.notebook_path ?? o.filename;
  if (typeof path === "string" && path.trim()) return { kind: "path", digest: sha256Hex(path.replace(/\\/g, "/")) };
  const url = o.url ?? o.uri ?? o.endpoint ?? o.href;
  if (typeof url === "string" && url.trim()) {
    try {
      return { kind: "host", digest: sha256Hex(new URL(url).host.toLowerCase()) };
    } catch {
    }
  }
  const cmd = o.command ?? o.cmd ?? o.script;
  if (typeof cmd === "string" && cmd.trim()) {
    const first = cmd.trim().split(/\s+/)[0];
    if (first) return { kind: "command", digest: sha256Hex(first) };
  }
  return void 0;
}
function buildEnrichment(tool, input) {
  const e = {
    v: ENRICHMENT_VERSION,
    input_digest: sha256Hex(canonicalJson(input ?? {})),
    capabilities: deriveCapabilities(tool, input)
  };
  const resource = deriveResource(input);
  if (resource) e.resource = resource;
  return e;
}

export {
  canonicalJson,
  buildEnrichment
};
