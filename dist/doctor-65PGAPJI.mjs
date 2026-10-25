import {
  loadPolicy
} from "./chunk-VJ743MCX.mjs";
import {
  checkCedarPolicyText,
  loadCedarPolicies,
  runEvaluatorSelfTest
} from "./chunk-P2YFFXF2.mjs";
import "./chunk-SRLE63GU.mjs";
import "./chunk-O3K3FPBT.mjs";
import "./chunk-PQJP2ZCI.mjs";

// src/doctor.ts
import { createPrivateKey, createPublicKey, sign, verify } from "crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "fs";
import { join, resolve } from "path";
var object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
function checkKey(path, checks) {
  const add = (status, message, id = "signing_key") => checks.push({ id, status, evidence: "configured", path, message });
  let key;
  try {
    key = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    add("fail", "Cannot read a valid JSON signing key at the configured path. No key was created or replaced.");
    return;
  }
  if (!object(key) || typeof key.privateKey !== "string" || typeof key.publicKey !== "string" || !/^[a-fA-F0-9]{64}$/.test(key.privateKey) || !/^[a-fA-F0-9]{64}$/.test(key.publicKey)) {
    add("fail", "Expected privateKey and publicKey as 32-byte hex Ed25519 keys. Key contents are not included in this report.");
    return;
  }
  try {
    const privateKey = createPrivateKey({
      key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(key.privateKey, "hex")]),
      format: "der",
      type: "pkcs8"
    });
    const publicKey = createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(key.publicKey, "hex")]),
      format: "der",
      type: "spki"
    });
    const challenge = Buffer.from("protect-mcp doctor local key-pair check v1");
    if (!verify(null, challenge, publicKey, sign(null, challenge, privateKey))) {
      add("fail", "The private and public signing keys do not form the same Ed25519 key pair.");
      return;
    }
    add("pass", "Configured Ed25519 key pair passed an in-memory sign/verify check. No receipt was written.");
    if (process.platform !== "win32" && statSync(path).mode & 63) {
      add("warn", "Signing key permissions allow access by other users. Restrict this file to its owner (chmod 600).", "key_permissions");
    }
  } catch {
    add("fail", "The configured Ed25519 key pair could not complete a local sign/verify check.");
  }
}
async function diagnoseDoctor(options = {}) {
  const directory = resolve(options.dir || process.cwd());
  const checks = [];
  let setup = "unconfigured";
  const add = (id, status, evidence, message, path) => checks.push({ id, status, evidence, message, ...path ? { path } : {} });
  const finish = () => {
    const ok = !checks.some((check) => check.status === "fail");
    return {
      schema: "protect-mcp.doctor.v1",
      directory,
      setup,
      ok,
      exitCode: ok ? 0 : 1,
      network: options.hosted ? "hosted_health_requested" : "not_requested",
      checks,
      limits: [
        "Configuration and local self-tests do not establish that a host is connected or enforcement is active.",
        "Log presence does not establish valid signatures, successful execution, or complete action coverage.",
        "The evaluator self-test uses known vectors, not every rule or possible input in your policy."
      ]
    };
  };
  add(
    "node",
    Number(process.versions.node.split(".")[0]) >= 18 ? "pass" : "fail",
    "observed",
    `Running Node.js ${process.version}; this package requires Node.js 18 or later.`
  );
  try {
    if (!statSync(directory).isDirectory()) throw new Error("not a directory");
    readdirSync(directory);
    add("workspace", "pass", "configured", "Selected working directory is readable.", directory);
  } catch {
    add("workspace", "fail", "configured", "Selected working directory is missing, unreadable, or is not a directory.", directory);
    return finish();
  }
  const configPath = resolve(directory, options.policy || "protect-mcp.json");
  let signing;
  let configValid = false;
  const hasConfig = existsSync(configPath);
  if (hasConfig || options.policy) {
    setup = "gateway_config";
    try {
      const raw = JSON.parse(readFileSync(configPath, "utf8"));
      if (!object(raw) || !object(raw.tools)) throw new Error("invalid tools");
      const loaded = loadPolicy(configPath);
      configValid = true;
      add("policy_config", "pass", "configured", "Gateway JSON configuration loaded. This does not prove its rules cover every intended action.", configPath);
      if (raw.signing !== void 0 && (!object(raw.signing) || raw.signing.enabled !== void 0 && typeof raw.signing.enabled !== "boolean")) {
        add("signing_config", "fail", "configured", "Signing configuration must be an object with a boolean enabled value when present.", configPath);
      } else {
        signing = loaded.signing;
      }
    } catch {
      add("policy_config", "fail", "configured", "Cannot load gateway JSON configuration with a tools object. Check the selected path and JSON; no files were changed.", configPath);
    }
  }
  let cedarPath = options.cedar ? resolve(directory, options.cedar) : void 0;
  if (!cedarPath && !options.policy) {
    for (const candidate of ["cedar", "policies", "."]) {
      const path = join(directory, candidate);
      try {
        if (readdirSync(path).some((name) => name.endsWith(".cedar"))) {
          cedarPath = path;
          break;
        }
      } catch {
      }
    }
  }
  const starter = !hasConfig && !options.policy && !options.cedar && cedarPath === directory && existsSync(join(directory, "protect.cedar"));
  if (starter) setup = "starter";
  else if (cedarPath && setup === "unconfigured") setup = "cedar";
  if (cedarPath) {
    try {
      const policy = loadCedarPolicies(cedarPath);
      const parsed = await checkCedarPolicyText(policy.source);
      add(
        "cedar_policy",
        !parsed.checked || !parsed.ok ? "fail" : "pass",
        "configured",
        !parsed.checked ? "Cedar files were found, but the installed engine could not check their syntax." : !parsed.ok ? "The selected Cedar policy set does not parse. Review the policy files locally." : `${policy.fileCount} Cedar file(s) parse. Runtime context, rule coverage and host enforcement are not established.`,
        cedarPath
      );
    } catch {
      add("cedar_policy", "fail", "configured", "Cannot read a nonempty Cedar policy directory at the selected path.", cedarPath);
    }
  }
  if (!hasConfig && !options.policy && !cedarPath) {
    add("policy_config", "fail", "configured", "No local policy setup found. Run init for an MCP wrapper, or init --starter for one-shot hook commands.", configPath);
  }
  if (starter) {
    add("starter_layout", "pass", "configured", "Starter policy layout found. Its key is used by sign --key; the MCP wrapper does not automatically adopt this key.");
    checkKey(join(directory, "protect-mcp.key"), checks);
  } else if (signing?.enabled === false) {
    add("signing_key", "not_checked", "configured", "Signing is explicitly disabled in this configuration; signed receipts should not be expected.", configPath);
  } else if (signing) {
    if (typeof signing.key_path !== "string" || !signing.key_path.trim()) {
      add("signing_key", "fail", "configured", "Signing is enabled but key_path is missing or invalid.", configPath);
    } else {
      checkKey(resolve(directory, signing.key_path), checks);
    }
  } else {
    add("signing_key", "not_checked", "not_checked", configValid || cedarPath ? "No signing configuration is selected. Existing key files alone do not enable receipts." : "Signing cannot be assessed until a valid setup is selected.");
  }
  try {
    const selfTest = await runEvaluatorSelfTest();
    if (!selfTest.wasmAvailable) {
      add("cedar_engine", cedarPath ? "fail" : "warn", "observed", "Cedar WASM is unavailable in this installed package. No package was downloaded.");
    } else {
      add("cedar_engine", "pass", "observed", "Installed Cedar WASM engine loaded locally.");
    }
    add(
      "evaluator_self_test",
      selfTest.passed ? "pass" : "fail",
      "observed",
      `${selfTest.cases.filter((item) => item.pass).length}/${selfTest.cases.length} known evaluator checks passed${!selfTest.wasmAvailable ? " (unavailable-engine denial only)" : ""}. This is not a live-host test.`
    );
  } catch {
    add("evaluator_self_test", "fail", "observed", "The installed evaluator self-test could not finish.");
  }
  for (const [id, filename] of [["decision_log", ".protect-mcp-log.jsonl"], ["receipt_log", ".protect-mcp-receipts.jsonl"]]) {
    const path = join(directory, filename);
    try {
      const stat = statSync(path);
      if (!stat.isFile()) throw new Error("not a file");
      add(id, "pass", "observed", `Local file present (${stat.size} bytes). Its entries and signatures were not checked.`, path);
    } catch {
      add(
        id,
        existsSync(path) ? "warn" : "not_checked",
        "not_checked",
        existsSync(path) ? "Local log path is not a readable regular file." : "No default local log found yet; explicit --receipts paths are not inspected.",
        path
      );
    }
  }
  add("host_connection", "not_checked", "not_checked", "No agent was contacted. Host connection, active policy and enforcement mode have not been established.");
  add("external_verifier", "not_checked", "not_checked", "No external verifier was launched or installed. Use the README receipt-verification example with your expected public key.");
  if (options.hosted) {
    try {
      const response = await fetch("https://api.scopeblind.com/health", { signal: AbortSignal.timeout(5e3), redirect: "error" });
      add(
        "hosted_health",
        response.ok ? "pass" : "fail",
        "observed",
        response.ok ? "Explicit hosted health request succeeded; authentication and receipt delivery were not checked." : `Explicit hosted health request returned HTTP ${response.status}. Local files were not sent.`
      );
      await response.body?.cancel();
    } catch {
      add("hosted_health", "fail", "observed", "Explicit hosted health request failed or timed out. Local files were not sent.");
    }
  } else {
    add("hosted_health", "not_checked", "not_checked", "Hosted connectivity was not requested. Use --hosted only if you want that network check.");
  }
  return finish();
}
function formatDoctorReport(report) {
  const lines = [`protect-mcp doctor \u2014 ${report.directory}`, ""];
  for (const check of report.checks) {
    lines.push(`[${check.status.toUpperCase()} \xB7 ${check.evidence}] ${check.id}: ${check.message}`);
    if (check.path) lines.push(`  ${check.path}`);
  }
  lines.push("", report.ok ? "Local configuration checks passed. Host activity and enforcement remain not checked." : "Local setup checks need attention. Fix the failed checks and run doctor again.");
  return `${lines.join("\n")}
`;
}
async function handleDoctor(argv) {
  const options = {};
  const json = argv.includes("--json");
  let help = false;
  try {
    for (let index = 0; index < argv.length; index++) {
      const arg = argv[index];
      if (arg === "--json") continue;
      if (arg === "--hosted") {
        options.hosted = true;
        continue;
      }
      if (arg === "--help" || arg === "-h") {
        help = true;
        continue;
      }
      if (arg === "--dir" || arg === "--policy" || arg === "--cedar") {
        const value = argv[++index];
        if (!value || value.startsWith("--")) throw new Error(`${arg} requires a path.`);
        options[arg.slice(2)] = value;
      } else {
        throw new Error("Unknown doctor option. Use --help for supported flags.");
      }
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid doctor options.";
    const report2 = { schema: "protect-mcp.doctor.v1", ok: false, exitCode: 2, error: "invalid_arguments", message };
    if (json) process.stdout.write(`${JSON.stringify(report2, null, 2)}
`);
    else process.stderr.write(`protect-mcp doctor: ${message}
`);
    return 2;
  }
  if (help) {
    process.stdout.write("Usage: protect-mcp doctor [--dir PATH] [--policy JSON_PATH] [--cedar DIRECTORY] [--json] [--hosted]\nRead-only and local by default. --hosted explicitly checks API health. Relative paths resolve from --dir.\n");
    return 0;
  }
  const report = await diagnoseDoctor(options);
  process.stdout.write(json ? `${JSON.stringify(report, null, 2)}
` : formatDoctorReport(report));
  return report.exitCode;
}
export {
  diagnoseDoctor,
  formatDoctorReport,
  handleDoctor
};
