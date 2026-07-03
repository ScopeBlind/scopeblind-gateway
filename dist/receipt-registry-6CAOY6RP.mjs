import "./chunk-PQJP2ZCI.mjs";

// src/receipt-registry.ts
import { createHash, randomUUID } from "crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname, join } from "path";
var ORG_IDENTITY_FILE = ".protect-mcp-org.json";
var REGISTRY_FILE = ".protect-mcp-registry.json";
var VERIFIER_PAGE_FILE = "scopeblind-verifier.html";
function sha256Hex(input) {
  return createHash("sha256").update(input).digest("hex");
}
function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value;
  return `{${Object.keys(obj).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(obj[key])}`).join(",")}}`;
}
function safeReadJson(path) {
  try {
    if (!existsSync(path)) return null;
    return JSON.parse(readFileSync(path, "utf-8"));
  } catch {
    return null;
  }
}
function requestIdFromReceipt(receipt) {
  const direct = receipt.request_id || receipt.scope;
  if (typeof direct === "string") return direct;
  const payload = receipt.payload;
  if (payload && typeof payload === "object") {
    const candidate = payload.request_id || payload.scope;
    if (typeof candidate === "string") return candidate;
  }
  return void 0;
}
function keyIdFromReceipt(receipt) {
  const kid = receipt.kid;
  if (typeof kid === "string") return kid;
  const signature = receipt.signature;
  if (signature && typeof signature === "object") {
    const nested = signature.kid;
    if (typeof nested === "string") return nested;
  }
  return void 0;
}
function issuerFromReceipt(receipt) {
  const issuer = receipt.issuer;
  if (typeof issuer === "string") return issuer;
  const signature = receipt.signature;
  if (signature && typeof signature === "object") {
    const nested = signature.issuer;
    if (typeof nested === "string") return nested;
  }
  return void 0;
}
function receiptType(receipt) {
  return String(receipt.type || receipt.artifact_type || receipt.v || "receipt");
}
function readReceiptDigestRecords(dir) {
  const receiptPath = join(dir, ".protect-mcp-receipts.jsonl");
  if (!existsSync(receiptPath)) return [];
  const raw = readFileSync(receiptPath, "utf-8");
  return raw.split("\n").map((line) => line.trim()).filter(Boolean).flatMap((line) => {
    try {
      const receipt = JSON.parse(line);
      const publicKey = (() => {
        const sig = receipt.signature;
        if (sig && typeof sig === "object" && typeof sig.public_key === "string") {
          return String(sig.public_key);
        }
        return void 0;
      })();
      return [{
        type: "scopeblind.receipt_digest.v1",
        receipt_hash: sha256Hex(line),
        receipt_bytes: Buffer.byteLength(line, "utf-8"),
        receipt_type: receiptType(receipt),
        request_id: requestIdFromReceipt(receipt),
        local_issuer: issuerFromReceipt(receipt),
        local_kid: keyIdFromReceipt(receipt),
        local_public_key_hint: publicKey ? `${publicKey.slice(0, 12)}...${publicKey.slice(-8)}` : void 0,
        observed_at: (/* @__PURE__ */ new Date()).toISOString(),
        source_file: receiptPath
      }];
    } catch {
      return [];
    }
  });
}
function createOrgIdentity(opts) {
  const now = (opts.now || /* @__PURE__ */ new Date()).toISOString();
  const existing = safeReadJson(join(opts.dir, ORG_IDENTITY_FILE));
  const keyData = safeReadJson(join(opts.dir, "keys", "gateway.json")) || {};
  const orgId = opts.orgId || String(existing?.org_id || `org_${randomUUID().slice(0, 12)}`);
  const orgName = opts.orgName || String(existing?.org_name || "Local ScopeBlind Org");
  const billingAccountId = opts.billingAccountId || String(existing?.billing_account_id || `billing_${orgId}`);
  const publicKey = typeof keyData.publicKey === "string" ? keyData.publicKey : "";
  const kid = typeof keyData.kid === "string" ? keyData.kid : publicKey ? `kid_${publicKey.slice(0, 12)}` : "local-key";
  const issuer = typeof keyData.issuer === "string" ? keyData.issuer : "protect-mcp";
  return {
    type: "scopeblind.org_identity.v1",
    org_id: orgId,
    org_name: orgName,
    billing_account_id: billingAccountId,
    created_at: typeof existing?.created_at === "string" ? existing.created_at : now,
    public_key_directory: publicKey ? [{
      type: "scopeblind.org_public_key.v1",
      org_id: orgId,
      key_id: kid,
      issuer,
      algorithm: "Ed25519",
      public_key_hex: publicKey,
      created_at: now,
      source: "local_gateway_key"
    }] : [],
    privacy: {
      raw_prompt_upload: false,
      raw_tool_payload_upload: false,
      raw_receipt_upload: false,
      digest_only: true
    }
  };
}
function writeOrgIdentity(dir, identity) {
  const path = join(dir, ORG_IDENTITY_FILE);
  writeFileSync(path, JSON.stringify(identity, null, 2) + "\n");
  return path;
}
function localAnchors(records, org, now, verifierBaseUrl) {
  return records.map((record) => ({
    type: "scopeblind.timestamp_anchor.v1",
    anchor_id: `local_${record.receipt_hash.slice(0, 16)}`,
    receipt_hash: record.receipt_hash,
    org_id: org.org_id,
    timestamp_utc: now.toISOString(),
    timestamp_source: "local-preview-not-independent",
    verifier_url: verifierBaseUrl ? `${verifierBaseUrl.replace(/\/$/, "")}/verify?digest=${record.receipt_hash}` : void 0
  }));
}
async function hostedAnchors(opts) {
  const endpoint = opts.endpoint.replace(/\/$/, "") + "/v1/receipt-registry/anchor";
  const payload = {
    type: "scopeblind.receipt_registry_anchor_request.v1",
    org: {
      org_id: opts.org.org_id,
      org_name: opts.org.org_name,
      billing_account_id: opts.org.billing_account_id,
      public_key_directory: opts.org.public_key_directory
    },
    privacy: opts.org.privacy,
    billing: {
      metered_unit: "receipt_digest_anchor",
      count: opts.records.length,
      raw_prompt_upload: false,
      raw_data_upload: false
    },
    receipt_digests: opts.records.map((record) => ({
      receipt_hash: record.receipt_hash,
      receipt_bytes: record.receipt_bytes,
      receipt_type: record.receipt_type,
      request_id: record.request_id,
      local_issuer: record.local_issuer,
      local_kid: record.local_kid
    }))
  };
  const bodyText = stableStringify(payload);
  for (const forbidden of ["payload_preview", "raw_receipt", "prompt", "tool_output", "privateKey"]) {
    if (bodyText.includes(`${JSON.stringify(forbidden)}:`)) throw new Error(`hosted anchor payload contains forbidden field: ${forbidden}`);
  }
  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${opts.token}`,
      "user-agent": "protect-mcp/receipt-registry"
    },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`hosted anchor failed: HTTP ${res.status} ${text.slice(0, 200)}`);
  }
  const response = await res.json().catch(() => ({}));
  const anchors = Array.isArray(response.anchors) ? response.anchors : [];
  return opts.records.map((record, index) => {
    const anchor = anchors[index] || anchors.find((candidate) => candidate.receipt_hash === record.receipt_hash) || {};
    return {
      type: "scopeblind.timestamp_anchor.v1",
      anchor_id: String(anchor.anchor_id || `hosted_${record.receipt_hash.slice(0, 16)}`),
      receipt_hash: record.receipt_hash,
      org_id: opts.org.org_id,
      timestamp_utc: String(anchor.timestamp_utc || anchor.anchored_at || (/* @__PURE__ */ new Date()).toISOString()),
      timestamp_source: "scopeblind-hosted",
      registry_url: typeof response.registry_url === "string" ? response.registry_url : void 0,
      verifier_url: typeof anchor.verifier_url === "string" ? anchor.verifier_url : opts.verifierBaseUrl ? `${opts.verifierBaseUrl.replace(/\/$/, "")}/verify?digest=${record.receipt_hash}` : void 0,
      signature: anchor.signature
    };
  });
}
async function createReceiptRegistry(opts) {
  const now = opts.now || /* @__PURE__ */ new Date();
  const org = createOrgIdentity(opts);
  const records = readReceiptDigestRecords(opts.dir);
  if (records.length === 0) throw new Error("No signed receipts found. Run protect-mcp with signing enabled first.");
  let anchors;
  let uploaded = false;
  if (opts.hosted || opts.endpoint || opts.token) {
    if (!opts.endpoint) throw new Error("Hosted anchoring requires --endpoint or SCOPEBLIND_REGISTRY_ENDPOINT.");
    if (!opts.token) throw new Error("Hosted anchoring requires --token or SCOPEBLIND_TOKEN.");
    anchors = await hostedAnchors({ endpoint: opts.endpoint, token: opts.token, org, records, verifierBaseUrl: opts.verifierBaseUrl });
    uploaded = true;
  } else {
    anchors = localAnchors(records, org, now, opts.verifierBaseUrl);
  }
  const registry = {
    type: "scopeblind.receipt_registry.v1",
    version: 1,
    generated_at: now.toISOString(),
    org,
    billing: {
      billing_account_id: org.billing_account_id,
      metered_unit: "receipt_digest_anchor",
      charge_basis: "anchored_receipt_digest_count",
      raw_prompt_upload: false,
      raw_data_upload: false
    },
    privacy: {
      statement: uploaded ? "ScopeBlind hosted registry received receipt digests and public identity metadata only." : "Local preview registry only. No independent timestamp exists until hosted anchoring succeeds.",
      uploaded_fields: ["receipt_hash", "receipt_bytes", "receipt_type", "request_id", "local_issuer", "local_kid", "org_id", "billing_account_id", "org_public_keys"],
      excluded_fields: ["raw_prompt", "raw_tool_payload", "payload_preview", "raw_receipt", "tool_output", "private_key"]
    },
    records,
    anchors,
    verifier: {
      local_page: join(opts.dir, VERIFIER_PAGE_FILE),
      shareable_url_template: opts.verifierBaseUrl ? `${opts.verifierBaseUrl.replace(/\/$/, "")}/verify?digest={receipt_hash}` : "file://scopeblind-verifier.html#digest={receipt_hash}"
    }
  };
  writeOrgIdentity(opts.dir, org);
  const registryPath = opts.outPath || join(opts.dir, REGISTRY_FILE);
  mkdirSync(dirname(registryPath), { recursive: true });
  writeFileSync(registryPath, JSON.stringify(registry, null, 2) + "\n");
  const verifierPath = join(opts.dir, VERIFIER_PAGE_FILE);
  writeFileSync(verifierPath, renderVerifierPage(registry));
  return { registry, registryPath, verifierPath, uploaded };
}
function renderVerifierPage(registry) {
  const embedded = JSON.stringify(registry).replace(/</g, "\\u003c");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ScopeBlind Receipt Verifier</title>
<style>
:root{--ink:#11110f;--muted:#6d675d;--line:#ded7c9;--paper:#f7f3ea;--card:#fffdf7;--ok:#2f6f4e;--warn:#8d620f;--bad:#8f241c}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top left,#fffdf7,#f7f3ea 48%,#e8dfce);color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{width:min(1040px,calc(100vw - 32px));margin:32px auto}.card{background:rgba(255,253,247,.94);border:1px solid var(--line);border-radius:24px;padding:22px;box-shadow:0 24px 70px rgba(36,30,18,.10);margin-bottom:16px}.kicker{text-transform:uppercase;letter-spacing:.17em;color:var(--muted);font-size:11px;font-weight:900}h1{font:520 clamp(36px,6vw,72px)/.94 ui-serif,Georgia,serif;letter-spacing:-.05em;margin:12px 0}input{width:100%;border:1px solid var(--line);border-radius:14px;padding:13px;background:#fffaf0;font:14px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.pill{display:inline-flex;border-radius:999px;padding:5px 9px;font-size:11px;font-weight:900}.ok{background:#dcebdd;color:var(--ok)}.warn{background:#f4e5bd;color:var(--warn)}.bad{background:#f7d9d3;color:var(--bad)}pre{white-space:pre-wrap;background:#181712;color:#f8f1df;border-radius:16px;padding:14px;overflow:auto}.muted{color:var(--muted)}code{background:#f2eadc;border:1px solid var(--line);border-radius:8px;padding:2px 6px}</style>
</head>
<body><main>
<section class="card"><div class="kicker">ScopeBlind verifier</div><h1>Verify that an independent registry saw this receipt digest.</h1><p class="muted">This page contains receipt digests, anchors, public key metadata, and billing metadata. It does not contain raw prompts, payloads, tool outputs, or raw receipts.</p></section>
<section class="card"><label class="kicker" for="digest">Receipt digest</label><input id="digest" placeholder="Paste receipt SHA-256 digest" oninput="render()"><div id="result" style="margin-top:16px"></div></section>
<section class="card"><div class="kicker">Org public key directory</div><pre id="keys"></pre></section>
</main><script>
const registry=${embedded};
function esc(v){return String(v==null?'':v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function render(){const q=document.getElementById('digest').value.trim()||new URLSearchParams(location.search).get('digest')||location.hash.replace(/^#digest=/,'');const rec=registry.records.find(r=>r.receipt_hash===q);const anchor=registry.anchors.find(a=>a.receipt_hash===q);const el=document.getElementById('result');if(!q){el.innerHTML='<p class="muted">Paste a digest to verify registry inclusion.</p>';return;}if(!rec){el.innerHTML='<span class="pill bad">not found</span><p>No matching digest in this registry export.</p>';return;}const independent=anchor&&anchor.timestamp_source==='scopeblind-hosted';el.innerHTML='<span class="pill '+(independent?'ok':'warn')+'">'+(independent?'anchored by ScopeBlind':'local preview only')+'</span><pre>'+esc(JSON.stringify({receipt:rec,anchor:anchor||null,billing:registry.billing,privacy:registry.privacy},null,2))+'</pre>';}
document.getElementById('keys').textContent=JSON.stringify(registry.org.public_key_directory,null,2);render();
</script></body></html>`;
}
export {
  ORG_IDENTITY_FILE,
  REGISTRY_FILE,
  VERIFIER_PAGE_FILE,
  createOrgIdentity,
  createReceiptRegistry,
  readReceiptDigestRecords,
  renderVerifierPage,
  writeOrgIdentity
};
