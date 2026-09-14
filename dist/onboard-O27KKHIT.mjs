import {
  getPolicyPack
} from "./chunk-CIQDC3FN.mjs";
import {
  initSigning,
  signDecision
} from "./chunk-WG5V64D7.mjs";
import {
  evaluateCedar,
  policySetFromSource
} from "./chunk-PF7HOTBP.mjs";
import {
  verifyReceipt
} from "./chunk-EIRUB2BZ.mjs";
import {
  createAuditBundle
} from "./chunk-PM2ZO57M.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/onboard.ts
import { createInterface } from "readline/promises";
import { existsSync, mkdirSync, writeFileSync, appendFileSync, readFileSync, rmSync, statSync, readdirSync } from "fs";
import { join } from "path";
import { randomBytes } from "crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { bytesToHex } from "@noble/hashes/utils";
var c = (code) => (s) => process.env.NO_COLOR ? s : `\x1B[${code}m${s}\x1B[0m`;
var bold = c("1");
var dim = c("2");
var green = c("32");
var red = c("31");
var yellow = c("33");
var cyan = c("36");
var out = (s = "") => process.stdout.write(s + "\n");
var ONBOARD_PACKS = [
  {
    id: "research-safe",
    scenario: {
      plainEnglish: "A research agent can read files and search, but cannot email findings out or read your secrets.",
      tradeoff: "Blocks external sends and secret-file reads. If you WANT the agent to send, use email-safe with approval instead.",
      demoActions: [
        { tool: "read_file", input: { path: "/research/macro-notes.md" }, label: "Read a research note", expect: "allow" },
        { tool: "web_search", input: { query: "2026 rate outlook" }, label: "Search the web", expect: "allow" },
        { tool: "read_file", input: { path: "/home/analyst/.env" }, label: "Read a secrets file (.env)", expect: "deny" },
        { tool: "send_email", input: { to: "outside@example.com", subject: "my findings" }, label: "Email findings to an outside address", expect: "deny" }
      ]
    }
  },
  {
    id: "filesystem-safe",
    scenario: {
      plainEnglish: "The agent can read and write project files, but cannot delete files or run destructive shell commands.",
      tradeoff: "Blocks delete_file and rm -rf / mkfs / dd. Writes are still allowed; tighten write_file later if you want.",
      demoActions: [
        { tool: "read_file", input: { path: "/project/README.md" }, label: "Read a project file", expect: "allow" },
        { tool: "write_file", input: { path: "/project/draft.txt" }, label: "Write a draft file", expect: "allow" },
        { tool: "delete_file", input: { path: "/project/database.db" }, label: "Delete a file", expect: "deny" },
        { tool: "Bash", input: {}, context: { command: "rm -rf /project/build" }, label: "Run rm -rf", expect: "deny" }
      ]
    }
  },
  {
    id: "email-safe",
    scenario: {
      plainEnglish: "The agent can draft and read email, but cannot send anything on its own.",
      tradeoff: "Blocks every send tool. Drafting still works; add human approval to allow supervised sends.",
      demoActions: [
        { tool: "read_file", input: { path: "/drafts/reply.md" }, label: "Read a draft reply", expect: "allow" },
        { tool: "send_email", input: { to: "client@example.com", subject: "Update" }, label: "Send an email", expect: "deny" }
      ]
    }
  },
  {
    id: "git-safe",
    scenario: {
      plainEnglish: "The agent can use git normally, but cannot force-push, hard-reset, or delete branches/repos.",
      tradeoff: "Blocks history-rewriting and destructive git. Normal add/commit/status/pull still work.",
      demoActions: [
        { tool: "Bash", input: {}, context: { command: "git status" }, label: "Run git status", expect: "allow" },
        { tool: "Bash", input: {}, context: { command: "git push --force origin main" }, label: "Force-push to main", expect: "deny" }
      ]
    }
  },
  {
    id: "finance-mandate-safe",
    scenario: {
      plainEnglish: "A trading agent can book orders within the mandate, but cannot touch the restricted list or breach concentration caps.",
      tradeoff: "Blocks restricted-list bookings and single-name >10% / gross >200% / net >100%. The example caps are yours to set.",
      demoActions: [
        { tool: "pms.book", input: { symbol: "AAPL", side: "BUY", quantity: 50, on_restricted_list: false }, label: "Book an in-mandate order", expect: "allow" },
        { tool: "pms.book", input: { symbol: "RESTR", side: "BUY", quantity: 100, on_restricted_list: true }, label: "Book a RESTRICTED-list name", expect: "deny" },
        { tool: "order.execute", input: { symbol: "XYZ", post_trade_weight_bps: 1500 }, label: "Push a single name to 15% (cap is 10%)", expect: "deny" }
      ]
    }
  }
];
function scenarioFor(id) {
  return ONBOARD_PACKS.find((p) => p.id === id)?.scenario;
}
function flag(argv, name) {
  const i = argv.indexOf(name);
  return i !== -1 && argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[i + 1] : void 0;
}
function has(argv, name) {
  return argv.includes(name);
}
function keypair() {
  const priv = randomBytes(32);
  return { privateKey: bytesToHex(priv), publicKey: bytesToHex(ed25519.getPublicKey(priv)), kid: "onboard", issuer: "protect-mcp" };
}
async function handleOnboard(argv) {
  const dir = flag(argv, "--dir") || join(process.cwd(), "scopeblind-demo");
  const enforce = has(argv, "--enforce");
  const yes = has(argv, "--yes") || has(argv, "-y");
  const interactive = Boolean(process.stdin.isTTY) && !yes;
  let packId = flag(argv, "--pack") || (interactive ? "" : "research-safe");
  out();
  out(bold("  ScopeBlind protect-mcp \u2014 guided first run"));
  out(dim("  A governed demo and a verified receipt in a few minutes."));
  out(dim("  No account. No credentials. Everything stays on this machine."));
  out();
  out(bold("  Step 1/6  What this does, and what stays local"));
  out("  protect-mcp is a policy gate that sits in front of an AI agent's tools.");
  out("  It decides allow / block / needs-approval, and signs a receipt for each.");
  out(green("  Local by default: ") + "nothing is uploaded. No prompts, files, or keys leave this box.");
  out();
  const rl = interactive ? createInterface({ input: process.stdin, output: process.stdout }) : null;
  try {
    out(bold("  Step 2/6  Choose what the agent is allowed to do"));
    if (interactive && !packId) {
      ONBOARD_PACKS.forEach((p, i) => {
        const pack2 = getPolicyPack(p.id);
        out(`    ${cyan(String(i + 1))}) ${bold(pack2.name)}  ${dim("(" + p.id + ")")}`);
        out(`       ${p.scenario.plainEnglish}`);
        out(dim(`       Tradeoff: ${p.scenario.tradeoff}`));
      });
      const ans = (await rl.question(cyan("  Pick a pack [1-" + ONBOARD_PACKS.length + ", default 1]: "))).trim();
      const idx = ans === "" ? 0 : Number(ans) - 1;
      packId = ONBOARD_PACKS[Number.isInteger(idx) && idx >= 0 && idx < ONBOARD_PACKS.length ? idx : 0].id;
    }
    const pack = getPolicyPack(packId);
    const scenario = scenarioFor(packId);
    if (!pack || !scenario) {
      out(red(`  Unknown onboarding pack: ${packId}. Options: ${ONBOARD_PACKS.map((p) => p.id).join(", ")}`));
      throw new Error(`unknown onboarding pack: ${packId}`);
    }
    out("  Selected: " + bold(pack.name) + dim(" (" + packId + ")"));
    out("  " + scenario.plainEnglish);
    out();
    out(bold("  Step 3/6  Set up a local workspace in " + dir));
    const force = has(argv, "--force");
    const existingCfg = (() => {
      try {
        return existsSync(join(dir, "protect-mcp.json")) ? JSON.parse(readFileSync(join(dir, "protect-mcp.json"), "utf-8")) : null;
      } catch {
        return {};
      }
    })();
    if (existingCfg && existingCfg._scopeblind_onboarding !== true && !force) {
      out(red("  " + join(dir, "protect-mcp.json") + " already exists and was not created by onboard."));
      out(red("  Refusing to overwrite a real workspace. Use --dir <a fresh folder>, or --force if you are sure."));
      throw new Error("onboard: refusing to overwrite a non-onboarding workspace at " + dir);
    }
    if (existingCfg && interactive && !yes) {
      const go = (await rl.question(yellow("  A demo workspace already exists there. Overwrite it? [y/N]: "))).trim().toLowerCase();
      if (go !== "y" && go !== "yes") {
        out(dim("  Cancelled. Pass --dir <path> to use a fresh folder."));
        return;
      }
    }
    mkdirSync(join(dir, "cedar"), { recursive: true });
    mkdirSync(join(dir, "keys"), { recursive: true });
    const kp = keypair();
    const keyPath = join(dir, "keys", "gateway.json");
    writeFileSync(keyPath, JSON.stringify({ ...kp, generated_at: (/* @__PURE__ */ new Date()).toISOString(), warning: "KEEP THIS FILE SECRET." }, null, 2) + "\n");
    writeFileSync(join(dir, "keys", ".gitignore"), "*.json\n");
    writeFileSync(join(dir, "cedar", pack.files[0].path), pack.files[0].contents);
    writeFileSync(join(dir, "protect-mcp.json"), JSON.stringify({
      cedar_dir: "./cedar",
      default_tier: "unknown",
      signing: { key_path: "./keys/gateway.json", issuer: kp.issuer, enabled: true },
      _mode: enforce ? "enforce" : "shadow (default): observe and record, do not block",
      // Marker so `offboard --uninstall` knows this is a disposable onboarding
      // workspace and can safely remove the policy/config, not a real project.
      _scopeblind_onboarding: true
    }, null, 2) + "\n");
    await initSigning({ enabled: true, key_path: keyPath, issuer: kp.issuer });
    out(green("  \u2713 ") + "workspace, signing key, and the " + packId + " policy are ready.");
    out(enforce ? yellow("  Mode: ENFORCE (blocks in real time).") : "  Mode: " + bold("shadow") + dim(" (default) \u2014 observe and record, block nothing yet. Flip to --enforce when ready."));
    out();
    out(bold("  Step 4/6  Run a safe governed demo (synthetic actions, no real credentials)"));
    const policySet = policySetFromSource(pack.files[0].contents, pack.files[0].path);
    const receiptsPath = join(dir, ".protect-mcp-receipts.jsonl");
    const logPath = join(dir, ".protect-mcp-log.jsonl");
    for (const p of [receiptsPath, logPath]) if (existsSync(p)) rmSync(p, { force: true });
    const base = Date.parse("2026-07-10T12:00:00.000Z");
    let cedarEngine = true;
    const rows = [];
    for (const [i, a] of scenario.demoActions.entries()) {
      const context = a.context;
      const decision = await evaluateCedar(policySet, { tool: a.tool, tier: "unknown", toolInput: a.input, context });
      let allowed = decision.allowed;
      let simulated = false;
      if (decision.metadata && decision.metadata.fallback) {
        cedarEngine = false;
        simulated = true;
        allowed = a.expect === "allow";
      }
      const reason_code = simulated ? allowed ? "policy_simulated_allow" : "policy_simulated_deny" : allowed ? "policy_allow" : "cedar_deny";
      const entry = {
        v: 2,
        tool: a.tool,
        decision: allowed ? "allow" : "deny",
        reason_code,
        policy_digest: policySet.digest,
        request_id: `onboard-${i + 1}`,
        timestamp: base + i,
        mode: enforce ? "enforce" : "shadow",
        ...simulated ? {} : { policy_engine: "cedar" }
      };
      appendFileSync(logPath, JSON.stringify(entry) + "\n");
      const signed = signDecision(entry);
      if (signed.signed) appendFileSync(receiptsPath, signed.signed + "\n");
      rows.push({ label: a.label, tool: a.tool, allowed, simulated });
    }
    if (!cedarEngine) out(yellow("  Note: the Cedar engine (optional dep) is not installed here, so decisions are POLICY-SIMULATED from the pack. Install @cedar-policy/cedar-wasm for live evaluation."));
    out();
    out(bold("  Step 5/6  What the gate did"));
    for (const r of rows) {
      const verdict = r.allowed ? green("ALLOW") : red("BLOCK");
      out(`    ${verdict}  ${r.label}  ${dim(r.tool + (r.simulated ? " (simulated)" : ""))}`);
    }
    const blocked = rows.filter((r) => !r.allowed);
    out();
    if (blocked.length) {
      const n = bold(String(blocked.length) + " action" + (blocked.length === 1 ? "" : "s"));
      out("  " + n + (enforce ? " blocked in real time." : " would have been blocked once you turn on --enforce."));
      out(dim("  Every decision above is Ed25519-signed into a receipt you can verify offline."));
    }
    out();
    out(bold("  Step 6/6  Export an evidence pack and verify a receipt"));
    const receipts = readFileSync(receiptsPath, "utf-8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
    const bundle = createAuditBundle({
      tenant: kp.issuer,
      receipts,
      signingKeys: [{ kty: "OKP", crv: "Ed25519", kid: kp.kid, x: Buffer.from(kp.publicKey, "hex").toString("base64url"), use: "sig" }]
    });
    const bundlePath = join(dir, "audit-bundle.json");
    writeFileSync(bundlePath, JSON.stringify(bundle, null, 2) + "\n");
    const firstReceipt = receipts[0];
    const check = verifyReceipt(firstReceipt, kp.publicKey);
    out("  " + green("\u2713 ") + receipts.length + " signed receipts exported to " + dim("audit-bundle.json"));
    out("  " + (check.valid ? green("\u2713 receipt signature VERIFIED") : red("\u2717 receipt did not verify")) + " with your gate's public key, offline (no ScopeBlind account or service).");
    out(dim("  Re-verify the whole pack yourself with the open verifier:  npx @veritasacta/verify " + bundlePath + " --bundle"));
    out();
    out(bold("  What ScopeBlind sees"));
    out("  " + green("Local only.") + " These files live in " + dir + " and were never uploaded:");
    out(dim("    .protect-mcp-receipts.jsonl   the signed decision receipts"));
    out(dim("    audit-bundle.json             the offline-verifiable evidence pack"));
    out("  If you later opt into the hosted layer, it forwards the " + bold("signed decision receipts") + " themselves \u2014");
    out("  tool name, decision, reason, policy digest, request id, your gate's " + bold("public") + " key, and");
    out("  minimized action metadata (e.g. a redacted destination). It does " + bold("not") + " send raw prompts,");
    out("  raw tool inputs/outputs, or your " + bold("private") + " key. Nothing is sent unless you turn it on.");
    out();
    out(bold("  Optional: human approval + phone"));
    out("  To require a person to approve a specific action (with a passkey, and optionally a paired");
    out("  iPhone), set up a governed mandate:  " + cyan("protect-mcp mandate init --cedar " + join(dir, "cedar") + " --controller-id ..."));
    out(dim("  (Desktop localhost WebAuthn is the tested route; paired-iPhone approval is a further step.)"));
    out();
    out(bold("  You are set up."));
    out("  Govern a real agent:  " + cyan("protect-mcp serve --enforce --cedar " + join(dir, "cedar")));
    out("  See the local record:  " + cyan("protect-mcp record --dir " + dir));
    out("  Remove everything:     " + cyan("protect-mcp offboard --dir " + dir + " --uninstall"));
    out();
  } finally {
    rl?.close();
  }
}
async function handleOffboard(argv) {
  const dir = flag(argv, "--dir") || join(process.cwd(), "scopeblind-demo");
  const yes = has(argv, "--yes") || has(argv, "-y");
  const interactive = Boolean(process.stdin.isTTY) && !yes;
  const all = has(argv, "--uninstall") || has(argv, "--all");
  const isOnboardingWorkspace = (() => {
    try {
      return JSON.parse(readFileSync(join(dir, "protect-mcp.json"), "utf-8"))._scopeblind_onboarding === true;
    } catch {
      return false;
    }
  })();
  const fullTeardown = all && isOnboardingWorkspace;
  const deleteData = has(argv, "--delete-data") || fullTeardown;
  const deleteKeys = has(argv, "--delete-keys") || fullTeardown;
  const disable = has(argv, "--disable-enforcement") || all;
  if (!deleteData && !disable && !deleteKeys && !all) {
    out();
    out(bold("  protect-mcp offboard") + " \u2014 remove ScopeBlind cleanly from " + dir);
    out();
    out("  " + cyan("--delete-data") + "           delete local receipts, logs, record, and evidence packs");
    out("  " + cyan("--disable-enforcement") + "   remove protect-mcp hooks (the gate stops intercepting tools)");
    out("  " + cyan("--delete-keys") + "           delete the signing keypair (receipts become unverifiable)");
    out("  " + cyan("--uninstall") + "             all of the above, plus config and policies (workspaces created by onboard)");
    out("  " + dim("add --yes to skip the confirmation prompt"));
    out();
    return;
  }
  const dataFiles = [
    ".protect-mcp-receipts.jsonl",
    ".protect-mcp-log.jsonl",
    ".protect-mcp-approval-resolutions.jsonl",
    "audit-bundle.json",
    "record.html",
    "verification-results.json",
    "receipts"
  ];
  const teardownFiles = ["protect-mcp.json", "cedar", "coverage.json"];
  const targets = [];
  if (deleteData) {
    for (const f of dataFiles) if (existsSync(join(dir, f))) targets.push(f);
  }
  if (deleteKeys && existsSync(join(dir, "keys"))) targets.push("keys");
  if (fullTeardown) {
    for (const f of teardownFiles) if (existsSync(join(dir, f))) targets.push(f);
  }
  if (all && !isOnboardingWorkspace) {
    out();
    out(yellow("  Note: " + dir + " was not created by onboard, so --uninstall will NOT delete your"));
    out(yellow("  config, policies, keys, or receipts. It only removes protect-mcp hooks (below)."));
    out(yellow("  If you really want the local data or keys gone, pass --delete-data / --delete-keys."));
  }
  const settingsPath = join(process.cwd(), ".claude", "settings.json");
  const hookHits = disable ? countProtectHooks(settingsPath) : 0;
  out();
  out(bold("  protect-mcp offboard") + " will remove, in " + dir + ":");
  if (targets.length) targets.forEach((t) => out(red("    - ") + t));
  if (hookHits > 0) out(red("    - ") + hookHits + " protect-mcp hook(s) from " + settingsPath);
  if (!targets.length && hookHits === 0) {
    out(dim("    (nothing to remove)"));
    out();
    return;
  }
  out();
  if (interactive) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    try {
      const go = (await rl.question(yellow("  Proceed? This cannot be undone. [y/N]: "))).trim().toLowerCase();
      if (go !== "y" && go !== "yes") {
        out(dim("  Cancelled."));
        return;
      }
    } finally {
      rl.close();
    }
  }
  for (const t of targets) {
    const p = join(dir, t);
    try {
      rmSync(p, { recursive: statSync(p).isDirectory(), force: true });
      out(green("  \u2713 removed ") + t);
    } catch (e) {
      out(red("  \u2717 could not remove " + t + ": " + (e instanceof Error ? e.message : e)));
    }
  }
  if (hookHits > 0) {
    const removed = removeProtectHooks(settingsPath);
    out(green("  \u2713 removed ") + removed + " protect-mcp hook(s); the gate no longer intercepts tool calls");
  }
  if (fullTeardown && existsSync(dir)) {
    try {
      if (readdirSync(dir).length === 0) {
        rmSync(dir, { recursive: true, force: true });
        out(green("  \u2713 removed ") + "the empty workspace folder");
      }
    } catch {
    }
  }
  out();
  out(bold("  Done.") + " ScopeBlind has been " + (fullTeardown ? "fully uninstalled from this folder." : "cleaned up."));
  out();
}
function countProtectHooks(settingsPath) {
  if (!existsSync(settingsPath)) return 0;
  try {
    const s = JSON.parse(readFileSync(settingsPath, "utf-8"));
    return protectHookCount(s?.hooks);
  } catch {
    return 0;
  }
}
function protectHookCount(hooks) {
  if (!hooks || typeof hooks !== "object") return 0;
  let n = 0;
  for (const groups of Object.values(hooks)) {
    if (!Array.isArray(groups)) continue;
    for (const g of groups) {
      const inner = g?.hooks;
      if (Array.isArray(inner)) {
        for (const h of inner) if (referencesProtect(h)) n++;
      }
    }
  }
  return n;
}
function referencesProtect(h) {
  if (!h || typeof h !== "object") return false;
  const o = h;
  const cmd = typeof o.command === "string" ? o.command : "";
  const url = typeof o.url === "string" ? o.url : "";
  const invokesProtect = /(^|[\s"'/@])protect-mcp(-mcp)?([\s"'/]|$)/.test(cmd);
  return invokesProtect || url.includes("protect-mcp");
}
function removeProtectHooks(settingsPath) {
  if (!existsSync(settingsPath)) return 0;
  let s;
  try {
    s = JSON.parse(readFileSync(settingsPath, "utf-8"));
  } catch {
    return 0;
  }
  if (!s.hooks) return 0;
  let removed = 0;
  for (const [event, groups] of Object.entries(s.hooks)) {
    if (!Array.isArray(groups)) continue;
    const kept = [];
    for (const g of groups) {
      const inner = g?.hooks;
      if (Array.isArray(inner)) {
        const innerKept = inner.filter((h) => {
          if (referencesProtect(h)) {
            removed++;
            return false;
          }
          return true;
        });
        if (innerKept.length) kept.push({ ...g, hooks: innerKept });
      } else {
        kept.push(g);
      }
    }
    s.hooks[event] = kept;
  }
  writeFileSync(settingsPath, JSON.stringify(s, null, 2) + "\n");
  return removed;
}
export {
  ONBOARD_PACKS,
  handleOffboard,
  handleOnboard
};
