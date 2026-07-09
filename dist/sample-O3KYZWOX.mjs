import {
  canonicalJson
} from "./chunk-KRKZ2YX7.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/sample.ts
import { existsSync, mkdirSync, writeFileSync } from "fs";
import { join } from "path";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { ed25519 } from "@noble/curves/ed25519";
var SAMPLE_KID = "sample-demo";
var sha256Hex = (s) => bytesToHex(sha256(new TextEncoder().encode(s)));
function signEnvelope(unsigned, privHex) {
  const msg = new TextEncoder().encode(canonicalJson(unsigned));
  const signature = bytesToHex(ed25519.sign(msg, hexToBytes(privHex)));
  return { ...unsigned, signature };
}
function buildSampleKit(dir, opts) {
  const receiptsPath = join(dir, ".protect-mcp-receipts.jsonl");
  const keyPath = join(dir, "keys", "gateway.json");
  if (!opts?.force && (existsSync(receiptsPath) || existsSync(keyPath))) {
    throw Object.assign(
      new Error(`refusing to overwrite an existing record or signing key in ${dir}`),
      { code: "SAMPLE_EXISTS" }
    );
  }
  mkdirSync(join(dir, "keys"), { recursive: true });
  const priv = ed25519.utils.randomPrivateKey();
  const privHex = bytesToHex(priv);
  const pub = bytesToHex(ed25519.getPublicKey(priv));
  writeFileSync(keyPath, JSON.stringify({ privateKey: privHex, publicKey: pub, kid: SAMPLE_KID }, null, 2));
  writeFileSync(join(dir, "keys", ".gitignore"), "# Never commit signing keys\n*.json\n");
  const now = opts?.now ?? /* @__PURE__ */ new Date();
  const stamp = (i) => new Date(now.getTime() - (7 - i) * 5 * 6e4).toISOString();
  const receipt = (i, tool, decision, caps, extra) => {
    const ts = stamp(i);
    const payload = {
      tool,
      decision,
      reason_code: decision === "deny" ? "policy_deny" : "policy_ok",
      policy_digest: SAMPLE_KID,
      scope: `${tool}-${ts}`,
      mode: "enforce",
      request_id: `${tool}-${ts}`,
      spec: "draft-farley-acta-signed-receipts-01",
      issuer_certification: "self-signed",
      public_key: pub,
      hook_event: "PreToolUse",
      enrichment: { v: 2, input_digest: sha256Hex(tool + ts), capabilities: caps, ...extra || {} }
    };
    return signEnvelope({
      v: 2,
      type: decision === "deny" ? "gateway_restraint" : "decision_receipt",
      algorithm: "ed25519",
      kid: SAMPLE_KID,
      issuer: "protect-mcp",
      issued_at: ts,
      payload
    }, privHex);
  };
  const pay = (amount) => ({
    payment: { amount, asset: "USDC", recipient_digest: sha256Hex("sample-merchant"), scheme: "exact" }
  });
  const rows = [
    receipt(0, "Read", "allow", ["fs.read"]),
    receipt(1, "Bash", "allow", ["exec.shell"]),
    receipt(2, "Write", "allow", ["fs.write"]),
    receipt(3, "WebFetch", "deny", ["net.egress"]),
    receipt(4, "x402_pay", "allow", ["financial", "payment"], pay(0.02)),
    receipt(5, "Read", "allow", ["fs.read", "secret.adjacent"]),
    receipt(6, "wallet_send_payment", "allow", ["financial", "payment"], pay(12.5)),
    receipt(7, "Bash", "allow", ["exec.shell", "vcs"])
  ];
  writeFileSync(receiptsPath, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  const tampered = rows.map((r) => JSON.parse(JSON.stringify(r)));
  tampered[3].payload.decision = "allow";
  writeFileSync(join(dir, "demo-tampered.jsonl"), tampered.map((r) => JSON.stringify(r)).join("\n") + "\n");
  return {
    dir,
    publicKey: pub,
    kid: SAMPLE_KID,
    receipts: rows,
    paymentsUsd: [0.02, 12.5],
    files: [".protect-mcp-receipts.jsonl", "demo-tampered.jsonl", "keys/gateway.json"]
  };
}
export {
  SAMPLE_KID,
  buildSampleKit
};
