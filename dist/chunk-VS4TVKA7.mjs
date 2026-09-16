// src/coordination-protocol.ts
var COORDINATION_DOMAIN = "scopeblind.coordination.v1\n";
function invoiceMatchesPurchaseOrder(invoice, fixtures) {
  const order = fixtures.purchase_orders.find((p) => p.id === invoice.purchase_order_id);
  return !!order && order.amount_minor === invoice.amount_minor && order.destination === invoice.destination && order.vendor === invoice.vendor && order.currency === "USD";
}
function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  if (!/^(?:[0-9a-f]{2})+$/i.test(hex)) throw new Error("Invalid hexadecimal data");
  return Uint8Array.from(hex.match(/../g).map((x) => parseInt(x, 16)));
}
function validUnicode(value) {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 55296 && c <= 56319) {
      const n = value.charCodeAt(++i);
      if (!(n >= 56320 && n <= 57343)) return false;
    } else if (c >= 56320 && c <= 57343) return false;
  }
  return true;
}
function canonical(value) {
  if (value === null) return "null";
  if (typeof value === "string") {
    if (!validUnicode(value)) throw new Error("Invalid Unicode");
    return JSON.stringify(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) if (!Object.hasOwn(value, i)) throw new Error("Sparse arrays are not JSON");
    return "[" + value.map(canonical).join(",") + "]";
  }
  if (typeof value === "object") {
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) throw new Error("Expected a plain JSON object");
    const object = value;
    return "{" + Object.keys(object).sort().map((k) => canonical(k) + ":" + canonical(object[k])).join(",") + "}";
  }
  throw new Error("Not a JSON value");
}
async function sha256(value) {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}
async function payloadHash(input) {
  return sha256(canonical(input));
}
async function importIdentity(pkcs8Hex, publicKey) {
  if (!/^[0-9a-f]{64}$/.test(publicKey)) throw new Error("Invalid public key");
  const privateKey = await crypto.subtle.importKey("pkcs8", hexToBytes(pkcs8Hex), { name: "Ed25519" }, false, ["sign"]);
  const identity = { publicKey, privateKey };
  const check = await sign({ type: "scopeblind.coordination.key-check.v1" }, identity);
  if (!await verify(check, publicKey)) throw new Error("Signing key does not match authority key");
  return identity;
}
async function sign(payload, identity) {
  const preimage = COORDINATION_DOMAIN + canonical(payload);
  const signature = await crypto.subtle.sign("Ed25519", identity.privateKey, new TextEncoder().encode(preimage));
  const envelope = { payload, signer: identity.publicKey, digest: await sha256(preimage), signature: bytesToHex(new Uint8Array(signature)) };
  if (identity.deviceAuthorization) {
    envelope.authorization = identity.deviceAuthorization;
    const binding = "scopeblind.coordination.device-authorization.v1\n" + envelope.digest + "\n" + identity.deviceAuthorization.digest;
    envelope.authorization_signature = bytesToHex(new Uint8Array(await crypto.subtle.sign("Ed25519", identity.privateKey, new TextEncoder().encode(binding))));
  }
  return envelope;
}
async function verify(envelope, expectedSigner) {
  try {
    if (!envelope || !/^[0-9a-f]{64}$/.test(envelope.signer) || !/^[0-9a-f]{64}$/.test(envelope.digest) || !/^[0-9a-f]{128}$/.test(envelope.signature)) return false;
    if (expectedSigner && expectedSigner !== envelope.signer) return false;
    const preimage = COORDINATION_DOMAIN + canonical(envelope.payload);
    if (await sha256(preimage) !== envelope.digest) return false;
    const key = await crypto.subtle.importKey("raw", hexToBytes(envelope.signer), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, hexToBytes(envelope.signature), new TextEncoder().encode(preimage));
  } catch {
    return false;
  }
}
function makeRequest(action, room_id, body) {
  return { type: "scopeblind.coordination.request.v1", action, room_id, body, issued_at: (/* @__PURE__ */ new Date()).toISOString(), nonce: crypto.randomUUID() };
}

export {
  COORDINATION_DOMAIN,
  invoiceMatchesPurchaseOrder,
  bytesToHex,
  hexToBytes,
  canonical,
  sha256,
  payloadHash,
  importIdentity,
  sign,
  verify,
  makeRequest
};
