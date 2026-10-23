import {
  digestBuiltinPolicy
} from "./chunk-P2YFFXF2.mjs";

// src/policy.ts
import { readFileSync } from "fs";
function loadPolicy(path) {
  const raw = readFileSync(path, "utf-8");
  const parsed = JSON.parse(raw);
  if (!parsed.tools || typeof parsed.tools !== "object") {
    throw new Error(`Invalid policy file: missing "tools" object in ${path}`);
  }
  const policy = {
    tools: parsed.tools,
    default_tier: parsed.default_tier || "unknown",
    policy_engine: parsed.policy_engine || "built-in",
    ...parsed.external ? { external: parsed.external } : {}
  };
  const digest = computePolicyDigest(policy);
  return {
    policy,
    digest,
    credentials: parsed.credentials,
    signing: parsed.signing
  };
}
function computePolicyDigest(policy) {
  return digestBuiltinPolicy(policy).policy_digest;
}
function ownEntry(table, key) {
  return table && Object.prototype.hasOwnProperty.call(table, key) ? table[key] : void 0;
}
function setOwnEntry(table, key, value) {
  Object.defineProperty(table, key, { value, enumerable: true, writable: true, configurable: true });
}
function getToolPolicy(toolName, policy) {
  if (!policy) {
    return { require: "any" };
  }
  const exact = ownEntry(policy.tools, toolName);
  if (exact) {
    return exact;
  }
  const wildcard = ownEntry(policy.tools, "*");
  if (wildcard) {
    return wildcard;
  }
  return { require: "any" };
}
function parseRateLimit(spec) {
  const match = spec.match(/^(\d+)\/(second|minute|hour|day)$/);
  if (!match) {
    throw new Error(`Invalid rate limit format: "${spec}". Expected "N/unit" (e.g. "5/hour")`);
  }
  const count = parseInt(match[1], 10);
  const unit = match[2];
  const windowMs = {
    second: 1e3,
    minute: 6e4,
    hour: 36e5,
    day: 864e5
  };
  return { count, windowMs: windowMs[unit] };
}
function checkRateLimit(key, limit, store) {
  const now = Date.now();
  const windowStart = now - limit.windowMs;
  const timestamps = (store.get(key) || []).filter((t) => t > windowStart);
  if (timestamps.length >= limit.count) {
    store.set(key, timestamps);
    return { allowed: false, remaining: 0 };
  }
  timestamps.push(now);
  store.set(key, timestamps);
  return { allowed: true, remaining: limit.count - timestamps.length };
}

export {
  loadPolicy,
  ownEntry,
  setOwnEntry,
  getToolPolicy,
  parseRateLimit,
  checkRateLimit
};
