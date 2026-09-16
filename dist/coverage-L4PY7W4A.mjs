import {
  getToolPolicy,
  loadPolicy
} from "./chunk-5MQK42SD.mjs";
import {
  getSignerInfo,
  initSigning,
  isSigningEnabled,
  signGenericArtifact
} from "./chunk-GLPAPBKX.mjs";
import {
  loadCedarPolicies,
  runEvaluatorSelfTest
} from "./chunk-YNNVGCWP.mjs";
import "./chunk-SRLE63GU.mjs";
import "./chunk-O3K3FPBT.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/coverage.ts
import { writeFileSync } from "fs";
var DEFAULT_NOT_GOVERNED = [
  "tool calls made to any second, ungated MCP server the agent is also configured to reach",
  "direct network egress from the agent runtime that is not expressed as a gated tool call",
  "in-process capabilities never registered as gated tools (e.g. a code interpreter writing files)",
  "anything a downstream system does after a gated tool call returns"
];
var RESIDUAL_BYPASS_ROUTES = [
  {
    vector: "second ungated tool server",
    closed_by: "single-endpoint configuration; this statement makes the extra server visible",
    residual_risk: "operator misconfiguration (visible, auditable)"
  },
  {
    vector: "direct network egress",
    closed_by: "egress lockdown: the runtime can only reach the gate",
    residual_risk: "container or host escape (shared-tenancy risk)"
  },
  {
    vector: "unregistered in-process capability",
    closed_by: "register every consequential capability as a gated tool; this statement enumerates what is gated",
    residual_risk: "a capability the operator forgot to route (visible in this statement)"
  },
  {
    vector: "harness misconfiguration",
    closed_by: "hook wiring audit; enforce-mode startup checks",
    residual_risk: "harness bug (rare, detectable)"
  },
  {
    vector: "post-return effects",
    closed_by: "out of scope by design: the gate governs the decision to call, not the callee internals",
    residual_risk: "downstream system behavior (not this layer)"
  }
];
var ATTESTATION_NOTE = "This statement enumerates what the gate is configured to govern and declares what it does not see. It is a scope declaration, not a proof of the absence of other action paths: making the gate the only path is a deployment property (single-endpoint configuration, or egress lockdown for a hard guarantee). Shadow enforcement observes and receipts but does not block. The statement reflects configuration at generation time; a statement emitted by the running gateway (observed coverage, with intended-versus-observed mismatch flagging) is on the roadmap. In enforce mode the gate refuses to arm unless the live restraint self-test passes.";
var CHANNEL_DESCRIPTION = {
  hook: "every tool call the agent harness routes through the pre-tool-call hook",
  proxy: "every call made to the gate HTTP endpoint wrapping the tool server"
};
function buildCoverageStatement(input) {
  const extras = (input.extraNotGoverned || []).map((s) => s.trim()).filter(Boolean);
  return {
    type: "scopeblind.coverage_statement.v1",
    generated_at: input.generatedAt || (/* @__PURE__ */ new Date()).toISOString(),
    package: { name: "protect-mcp", version: input.packageVersion },
    deployment: {
      mode: input.mode,
      enforcement: input.enforce ? "enforce" : "shadow",
      governed_channel: CHANNEL_DESCRIPTION[input.mode]
    },
    policy: {
      engine: input.engine,
      digest: input.policyDigest,
      source: input.policySource,
      ...input.policyFiles && input.policyFiles.length > 0 ? { files: input.policyFiles } : {}
    },
    governed: {
      tools_with_explicit_rules: [...input.governedTools].sort(),
      explicitly_blocked_tools: [...input.blockedTools].sort(),
      wildcard_rule: input.wildcardRule ?? null
    },
    not_governed: [...DEFAULT_NOT_GOVERNED, ...extras],
    residual_bypass_routes: RESIDUAL_BYPASS_ROUTES,
    self_test: input.probe,
    ...input.evaluatorSelfTest !== void 0 ? { evaluator_self_test: input.evaluatorSelfTest } : {},
    basis: "configuration-at-generation-time",
    attestation_note: ATTESTATION_NOTE
  };
}
function analyzeBuiltInPolicy(policy) {
  const names = Object.keys(policy.tools).filter((t) => t !== "*");
  const blocked = names.filter((t) => policy.tools[t]?.block === true);
  const wildcard = policy.tools["*"];
  const wildcardRule = wildcard ? Object.entries(wildcard).map(([k, v]) => `${k}: ${v}`).join(", ") : void 0;
  let probe;
  if (blocked.length > 0) {
    const probeTool = blocked[0];
    const effective = getToolPolicy(probeTool, policy);
    probe = {
      method: "static-policy-probe",
      probe_tool: probeTool,
      would_deny: effective.block === true
    };
  } else {
    probe = {
      method: "none",
      reason: "policy declares no explicitly blocked tool to probe"
    };
  }
  return { governedTools: names, blockedTools: blocked, wildcardRule, probe };
}
function parseCoverageArgs(args) {
  let mode;
  let enforce = false;
  let policyPath;
  let cedarDir;
  let out = "scopeblind-coverage.json";
  let json = false;
  const extraNotGoverned = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--mode" && args[i + 1]) mode = args[++i];
    else if (args[i] === "--enforce") enforce = true;
    else if (args[i] === "--policy" && args[i + 1]) policyPath = args[++i];
    else if (args[i] === "--cedar" && args[i + 1]) cedarDir = args[++i];
    else if (args[i] === "--out" && args[i + 1]) out = args[++i];
    else if (args[i] === "--json") json = true;
    else if (args[i] === "--not-governed" && args[i + 1]) {
      extraNotGoverned.push(...args[++i].split(",").map((s) => s.trim()).filter(Boolean));
    }
  }
  return { mode, enforce, policyPath, cedarDir, out, json, extraNotGoverned };
}
async function handleCoverage(args) {
  const opts = parseCoverageArgs(args);
  if (opts.mode !== "hook" && opts.mode !== "proxy") {
    process.stderr.write(
      'Usage: protect-mcp coverage --mode <hook|proxy> [--enforce] [--policy <path> | --cedar <dir>]\n                            [--not-governed "<item>,<item>"] [--out <file>] [--json]\n\n--mode is required: the deployment mode is a fact the operator declares, not one the CLI can guess.\n'
    );
    process.exitCode = 1;
    return;
  }
  const version = process.env.PROTECT_MCP_VERSION || "unknown";
  const evaluatorSelfTest = await runEvaluatorSelfTest();
  let statement;
  let signingConfig;
  if (opts.cedarDir) {
    const set = loadCedarPolicies(opts.cedarDir);
    statement = buildCoverageStatement({
      mode: opts.mode,
      enforce: opts.enforce,
      engine: "cedar",
      policyDigest: set.digest,
      policySource: opts.cedarDir,
      policyFiles: set.files,
      // Cedar governs by predicate over (principal, action, resource), not a
      // static tool list; the enumerable surface is the policy files themselves.
      governedTools: [],
      blockedTools: [],
      probe: {
        method: "none",
        reason: "cedar policies are evaluated per-request; a static probe would not exercise the WASM evaluation path. Run the gate with --enforce to exercise live evaluation."
      },
      extraNotGoverned: opts.extraNotGoverned,
      evaluatorSelfTest,
      packageVersion: version
    });
  } else if (opts.policyPath) {
    const loaded = loadPolicy(opts.policyPath);
    signingConfig = loaded.signing;
    const analyzed = analyzeBuiltInPolicy(loaded.policy);
    statement = buildCoverageStatement({
      mode: opts.mode,
      enforce: opts.enforce,
      engine: "built-in",
      policyDigest: loaded.digest,
      policySource: opts.policyPath,
      governedTools: analyzed.governedTools,
      blockedTools: analyzed.blockedTools,
      wildcardRule: analyzed.wildcardRule,
      probe: analyzed.probe,
      extraNotGoverned: opts.extraNotGoverned,
      evaluatorSelfTest,
      packageVersion: version
    });
  } else {
    statement = buildCoverageStatement({
      mode: opts.mode,
      enforce: opts.enforce,
      engine: "none",
      policyDigest: "none",
      policySource: "no policy loaded (allow-all default)",
      governedTools: [],
      blockedTools: [],
      probe: { method: "none", reason: "no policy loaded; the gate would allow all tool calls" },
      extraNotGoverned: opts.extraNotGoverned,
      evaluatorSelfTest,
      packageVersion: version
    });
  }
  let output;
  if (signingConfig) {
    const warnings = await initSigning(signingConfig);
    for (const w of warnings) process.stderr.write(`[protect-mcp] Warning: ${w}
`);
    if (!isSigningEnabled()) {
      process.stderr.write(
        "[protect-mcp] coverage: signing is configured in the policy but no signer is ready. Refusing to emit an unsigned statement where a signed one was promised.\n"
      );
      process.exitCode = 1;
      return;
    }
    const signed = signGenericArtifact("coverage_statement", statement);
    if (!signed.ok || !signed.signed) {
      process.stderr.write(`[protect-mcp] coverage: signing failed: ${signed.error || "unknown error"}
`);
      process.exitCode = 1;
      return;
    }
    output = JSON.parse(signed.signed);
  } else {
    output = {
      artifact: statement,
      signature: null,
      unsigned_reason: "no signing configured in the policy file; this statement is a declaration, not evidence. Add a signing block (protect-mcp init) to emit a verifiable statement."
    };
  }
  const serialized = JSON.stringify(output, null, 2) + "\n";
  writeFileSync(opts.out, serialized);
  if (opts.json) process.stdout.write(serialized);
  const signer = getSignerInfo();
  process.stderr.write(
    `[protect-mcp] coverage statement written to ${opts.out}
  mode        : ${statement.deployment.mode} (${statement.deployment.enforcement})
  policy      : ${statement.policy.engine} digest ${statement.policy.digest}
  governed    : ${statement.governed.tools_with_explicit_rules.length} tools with explicit rules${statement.governed.explicitly_blocked_tools.length ? `, ${statement.governed.explicitly_blocked_tools.length} explicitly blocked` : ""}
  not governed: ${statement.not_governed.length} declared items (defaults cannot be removed)
  self test   : ${statement.self_test.method}${statement.self_test.would_deny !== void 0 ? ` (would_deny=${statement.self_test.would_deny})` : ""}
  evaluator   : live self-test ${evaluatorSelfTest.passed ? "passed" : "FAILED"} (${evaluatorSelfTest.cases.length} vectors)
  signed      : ${signer ? `yes (kid ${signer.kid})` : "no (unsigned declaration)"}
`
  );
}
export {
  DEFAULT_NOT_GOVERNED,
  RESIDUAL_BYPASS_ROUTES,
  analyzeBuiltInPolicy,
  buildCoverageStatement,
  handleCoverage
};
