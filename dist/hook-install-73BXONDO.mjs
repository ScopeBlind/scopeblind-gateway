import {
  generateHookSettings,
  generateSampleCedarPolicy,
  generateVerifyReceiptSkill
} from "./chunk-4DFYHQ5M.mjs";
import "./chunk-WE2AYP6X.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/hook-install.ts
import * as fs from "fs";
import { dirname, join, parse, relative, resolve } from "path";
import { randomBytes } from "crypto";
import { isDeepStrictEqual } from "util";
import { ed25519 } from "@noble/curves/ed25519";
import { bytesToHex } from "@noble/hashes/utils";
function object(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be a JSON object; no files changed.`);
  return value;
}
function parseObject(text, label) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`Cannot parse JSON in ${label}; no files changed.`);
  }
  return object(value, label);
}
function json(value) {
  return `${JSON.stringify(value, null, 2)}
`;
}
function safePath(io, root, path, finalKind) {
  const rel = relative(root, path);
  if (rel.startsWith("..") || resolve(root, rel) !== path) throw new Error(`Path is outside selected directory: ${path}`);
  const chain = [];
  for (let cursor = path; ; cursor = dirname(cursor)) {
    chain.unshift(cursor);
    if (cursor === root) break;
  }
  for (const candidate of chain) {
    let stat;
    try {
      stat = io.lstatSync(candidate);
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw error;
    }
    if (stat.isSymbolicLink()) throw new Error(`Refusing symlink: ${candidate}`);
    const kind = candidate === path ? finalKind : "dir";
    if (kind === "dir" ? !stat.isDirectory() : !stat.isFile()) throw new Error(`Expected ${kind}: ${candidate}`);
  }
}
function snapshot(io, root, path) {
  safePath(io, root, path, "file");
  try {
    return { text: io.readFileSync(path, "utf8"), mode: io.statSync(path).mode & 511 };
  } catch (error) {
    if (error.code === "ENOENT") return { text: null, mode: 384 };
    throw error;
  }
}
function readManifest(text, expected) {
  const value = parseObject(text, "hook ownership manifest");
  if (value.version !== 1 || typeof value.hookUrl !== "string" || !/^http:\/\/127\.0\.0\.1:\d+\/hook$/.test(value.hookUrl) || typeof value.originalHooksPresent !== "boolean" || !Array.isArray(value.originalEvents) || !value.originalEvents.every((event) => typeof event === "string") || !Array.isArray(value.entries)) {
    throw new Error("Invalid hook ownership manifest; no files changed.");
  }
  const seen = /* @__PURE__ */ new Set();
  for (const raw of value.entries) {
    const entry = object(raw, "owned hook entry");
    if (typeof entry.event !== "string" || seen.has(entry.event) || !expected[entry.event]?.some((candidate) => isDeepStrictEqual(candidate, entry.entry))) {
      throw new Error("Invalid owned hook entry; no files changed.");
    }
    seen.add(entry.event);
  }
  return value;
}
function installHooks(options, io = fs) {
  const root = resolve(options.dir);
  if (root === parse(root).root) throw new Error("Choose a project directory, not the filesystem root.");
  safePath(io, root, root, "dir");
  const port = options.port ?? 9377;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("--port must be an integer from 1 to 65535.");
  const hookUrl = `http://127.0.0.1:${port}/hook`;
  const settingsPath = join(root, ".claude/settings.json");
  const manifestPath = join(root, ".claude/protect-mcp-hooks.json");
  const settingsBefore = snapshot(io, root, settingsPath);
  const manifestBefore = snapshot(io, root, manifestPath);
  const settings = settingsBefore.text === null ? {} : parseObject(settingsBefore.text, settingsPath);
  const hooks = settings.hooks === void 0 ? {} : object(settings.hooks, `${settingsPath} hooks`);
  for (const [event, entries] of Object.entries(hooks)) {
    if (!Array.isArray(entries)) throw new Error(`Hook event ${event} must be an array; no files changed.`);
  }
  const originalHooksPresent = Object.hasOwn(settings, "hooks");
  const originalEvents = Object.keys(hooks);
  const generated = generateHookSettings(hookUrl).hooks;
  let manifest;
  if (manifestBefore.text !== null) {
    const rawManifest = parseObject(manifestBefore.text, manifestPath);
    const sourceUrl = typeof rawManifest.hookUrl === "string" ? rawManifest.hookUrl : "";
    manifest = readManifest(manifestBefore.text, generateHookSettings(sourceUrl).hooks);
  }
  const result = {
    directory: root,
    hookUrl: manifest?.hookUrl ?? hookUrl,
    mode: options.uninstall ? "uninstall" : "install",
    dryRun: !!options.dryRun,
    changed: [],
    preserved: [],
    warnings: []
  };
  const mutations = [];
  const snapshots = /* @__PURE__ */ new Map([[settingsPath, settingsBefore], [manifestPath, manifestBefore]]);
  const create = (path, content, mode = 384) => {
    const before = snapshot(io, root, path);
    snapshots.set(path, before);
    if (before.text !== null) {
      result.preserved.push(path);
      return;
    }
    mutations.push({ path, after: options.dryRun ? "" : content(), mode });
  };
  if (options.uninstall) {
    if (!manifest) {
      result.warnings.push("No ownership manifest found. Existing hooks were left untouched; remove older or manually installed hooks yourself.");
      return result;
    }
    const unmatched = [];
    for (const owned of manifest.entries) {
      const entries = hooks[owned.event] ?? [];
      const index = entries.findIndex((entry) => isDeepStrictEqual(entry, owned.entry));
      if (index < 0) {
        unmatched.push(owned);
        continue;
      }
      entries.splice(index, 1);
      if (entries.length === 0 && !manifest.originalEvents.includes(owned.event)) delete hooks[owned.event];
    }
    if (!manifest.originalHooksPresent && Object.keys(hooks).length === 0) delete settings.hooks;
    else settings.hooks = hooks;
    if (unmatched.length) {
      result.warnings.push(`${unmatched.length} previously installed hook entries were changed or removed. Unmatched entries were left untouched; review settings manually. The manifest is retained for review.`);
      const next = json({ ...manifest, entries: unmatched });
      if (next !== manifestBefore.text) mutations.push({ path: manifestPath, after: next, mode: 384 });
    } else mutations.push({ path: manifestPath, after: null, mode: 384 });
  } else {
    if (manifest && manifest.hookUrl !== hookUrl) throw new Error(`Hooks were installed for ${manifest.hookUrl}. Uninstall them before changing --port; no files changed.`);
    const owned = manifest?.entries ?? [];
    for (const entry of owned) {
      if (!hooks[entry.event]?.some((candidate) => isDeepStrictEqual(candidate, entry.entry))) {
        throw new Error("Managed hooks were edited or removed. Review settings and run init-hooks --uninstall before reinstalling; no files changed.");
      }
    }
    for (const [event, additions] of Object.entries(generated)) {
      const entries = hooks[event] ?? [];
      for (const entry of additions) {
        if (entries.some((candidate) => isDeepStrictEqual(candidate, entry))) {
          if (!owned.some((item) => item.event === event)) result.warnings.push(`${event}: identical existing hook preserved, not claimed as installer-owned.`);
        } else {
          entries.push(entry);
          owned.push({ event, entry });
        }
      }
      hooks[event] = entries;
    }
    settings.hooks = hooks;
    create(join(root, "keys/gateway.json"), () => {
      const privateKey = randomBytes(32);
      return json({
        privateKey: bytesToHex(privateKey),
        publicKey: bytesToHex(ed25519.getPublicKey(privateKey)),
        kid: `hook-${Date.now()}`,
        generated_at: (/* @__PURE__ */ new Date()).toISOString(),
        warning: "KEEP THIS FILE SECRET. Never commit to version control."
      });
    });
    create(join(root, "keys/.gitignore"), () => "# Never commit signing keys\n*.json\n");
    create(join(root, "policies/agent.cedar"), generateSampleCedarPolicy, 420);
    create(join(root, "protect-mcp.json"), () => json({
      tools: { "*": { rate_limit: "100/hour" } },
      default_tier: "unknown",
      signing: { key_path: "./keys/gateway.json", issuer: "protect-mcp", enabled: true }
    }));
    create(join(root, ".claude/skills/verify-receipt/SKILL.md"), generateVerifyReceiptSkill, 420);
    const nextManifest = manifest ?? { version: 1, hookUrl, originalHooksPresent, originalEvents, entries: owned };
    if (json(nextManifest) !== manifestBefore.text) mutations.push({ path: manifestPath, after: json(nextManifest), mode: 384 });
  }
  const nextSettings = json(settings);
  const settingsChanged = !isDeepStrictEqual(settings, settingsBefore.text === null ? {} : JSON.parse(settingsBefore.text));
  if (settingsChanged) {
    if (settingsBefore.text !== null) {
      const stamp = (/* @__PURE__ */ new Date()).toISOString().replace(/[:.]/g, "-");
      const backup = join(root, `.claude/settings.json.protect-mcp-backup-${stamp}-${randomBytes(4).toString("hex")}`);
      snapshots.set(backup, snapshot(io, root, backup));
      result.backup = backup;
      mutations.unshift({ path: backup, after: settingsBefore.text, mode: 384, backup: true });
      const manifestWrite = mutations.find((m) => m.path === manifestPath && m.after !== null);
      if (manifestWrite && !options.uninstall) {
        const data = JSON.parse(manifestWrite.after);
        data.backup = relative(root, backup);
        manifestWrite.after = json(data);
      }
    }
    mutations.push({ path: settingsPath, after: nextSettings, mode: settingsBefore.mode });
  }
  result.changed = mutations.map((mutation) => mutation.path);
  if (options.dryRun || !mutations.length) return result;
  const createdDirectories = [];
  function ensureDirectory(path) {
    if (io.existsSync(path)) return;
    ensureDirectory(dirname(path));
    io.mkdirSync(path, { mode: 448 });
    createdDirectories.push(path);
  }
  function atomicWrite(path, contents, mode) {
    const temporary = `${path}.protect-mcp-${randomBytes(8).toString("hex")}.tmp`;
    try {
      io.writeFileSync(temporary, contents, { flag: "wx", mode });
      io.renameSync(temporary, path);
    } finally {
      if (io.existsSync(temporary)) io.unlinkSync(temporary);
    }
  }
  const applied = [];
  let lockPath;
  try {
    ensureDirectory(join(root, ".claude"));
    const candidateLock = join(root, ".claude/.protect-mcp-hooks.lock");
    safePath(io, root, candidateLock, "file");
    io.writeFileSync(candidateLock, `${process.pid}
`, { flag: "wx", mode: 384 });
    lockPath = candidateLock;
    for (const mutation of mutations) {
      const expected = snapshots.get(mutation.path) ?? snapshot(io, root, mutation.path);
      snapshots.set(mutation.path, expected);
      if (snapshot(io, root, mutation.path).text !== expected.text) throw new Error(`File changed during setup: ${mutation.path}`);
      ensureDirectory(dirname(mutation.path));
      safePath(io, root, mutation.path, "file");
      if (mutation.after === null) io.unlinkSync(mutation.path);
      else atomicWrite(mutation.path, mutation.after, mutation.mode);
      applied.push(mutation);
    }
  } catch (error) {
    const rollbackErrors = [];
    for (const mutation of applied.reverse()) {
      if (mutation.backup) continue;
      try {
        if (snapshot(io, root, mutation.path).text !== mutation.after) {
          rollbackErrors.push(`Preserved concurrent edit: ${mutation.path}`);
          continue;
        }
        const before = snapshots.get(mutation.path);
        if (before.text === null) io.unlinkSync(mutation.path);
        else atomicWrite(mutation.path, before.text, before.mode);
      } catch (failure) {
        rollbackErrors.push(`${mutation.path}: ${failure.message}`);
      }
    }
    throw new Error(`Hook setup failed: ${error.message}. ${rollbackErrors.length ? `Recovery needs review: ${rollbackErrors.join("; ")}` : "Original files restored."}${result.backup ? ` Backup: ${result.backup}` : ""}`);
  } finally {
    if (lockPath) io.unlinkSync(lockPath);
    for (const path of createdDirectories.reverse()) {
      try {
        io.rmdirSync(path);
      } catch {
      }
    }
  }
  return result;
}
export {
  installHooks
};
