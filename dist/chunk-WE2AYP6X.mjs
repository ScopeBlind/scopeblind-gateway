// src/starter-policy.ts
var STARTER_POLICY_VERSION = 1;
var STARTER_POLICY_FILE = "starter.cedar";
var STARTER_POLICY = [
  "// protect-mcp starter policy for coding agents, v1.",
  "// Everything is allowed except the forbids below, and a forbid always wins.",
  "// Shell rules match the raw command text, so they are best effort: a reworded",
  "// command can get past them. Every rule checks `has` first, because the gate",
  "// denies on any policy error. This file is yours to edit.",
  "",
  '@id("starter.allow-by-default")',
  "permit (principal, action, resource);",
  "",
  '@id("starter.delete-root-or-home")',
  '@reason("Recursive delete of /, the home folder or the parent folder. Delete a specific path inside the project instead.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash")',
  "when {",
  "  context has input && context.input has command && (",
  '    context.input.command like "*rm -rf /" || context.input.command like "*rm -rf / *" ||',
  '    context.input.command like "*rm -rf ~" || context.input.command like "*rm -rf ~ *" ||',
  '    context.input.command like "*rm -rf ~/" || context.input.command like "*rm -rf ~/ *" ||',
  '    context.input.command like "*rm -rf $HOME" || context.input.command like "*rm -rf $HOME *" ||',
  '    context.input.command like "*rm -rf $HOME/" || context.input.command like "*rm -rf $HOME/ *" ||',
  '    context.input.command like "*rm -rf \\"$HOME\\"" || context.input.command like "*rm -rf \\"$HOME\\" *" ||',
  '    context.input.command like "*rm -rf .." || context.input.command like "*rm -rf .. *" ||',
  '    context.input.command like "*rm -rf ../" || context.input.command like "*rm -rf ../ *" ||',
  '    context.input.command like "*rm -rf /\\**" || context.input.command like "*rm -rf ~/\\**" ||',
  '    context.input.command like "*rm -rf $HOME/\\**" || context.input.command like "*rm -rf \\"$HOME/\\"\\**" ||',
  '    context.input.command like "*rm -fr /" || context.input.command like "*rm -fr ~" ||',
  '    context.input.command like "*rm -fr ~/" || context.input.command like "*rm -fr $HOME")',
  "};",
  "",
  '@id("starter.force-push-main")',
  '@reason("Force-push to main or master, or a force-push that names no branch. Push a named feature branch instead.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash")',
  "when {",
  "  context has input && context.input has command && (",
  '    context.input.command like "*git push*--force* origin main*" || context.input.command like "*git push*-f origin main*" ||',
  '    context.input.command like "*git push*origin main --force*" || context.input.command like "*git push*origin main -f*" ||',
  '    context.input.command like "*git push*--force*:main*" || context.input.command like "*git push*origin +main*" ||',
  '    context.input.command like "*git push*--force* origin master*" || context.input.command like "*git push*-f origin master*" ||',
  '    context.input.command like "*git push*origin master --force*" || context.input.command like "*git push*origin master -f*" ||',
  '    context.input.command like "*git push*--force*:master*" || context.input.command like "*git push*origin +master*" ||',
  '    context.input.command like "*git push*--force" || context.input.command like "*git push*--force 2>&1*" ||',
  '    context.input.command like "*git push*--force &&*" || context.input.command like "*git push*--force-with-lease" ||',
  '    context.input.command like "*git push*--force-with-lease 2>&1*" || context.input.command like "*git push*--force-with-lease &&*" ||',
  '    context.input.command like "*git push*-f" || context.input.command like "*git push*-f 2>&1*" ||',
  '    context.input.command like "*git push*-f &&*")',
  "};",
  "",
  '@id("starter.read-secret-file")',
  '@reason("Reads a credential file such as .env, ~/.ssh or ~/.aws. Ask the person for the value you need.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource)',
  "when {",
  '  resource == Tool::"Read" && context has input && context.input has file_path && (',
  '    context.input.file_path like "*/.env" || context.input.file_path like "*/.env.*" ||',
  '    context.input.file_path like "*/.ssh/*" || context.input.file_path like "*/.aws/*" ||',
  '    context.input.file_path like "*/.netrc" || context.input.file_path like "*/.git-credentials" ||',
  '    context.input.file_path like "*/.npmrc" || context.input.file_path like "*/.pypirc" ||',
  '    context.input.file_path like "*/.docker/config.json" || context.input.file_path like "*/.kube/config" ||',
  '    context.input.file_path like "*/.config/gh/hosts.yml" || context.input.file_path like "*/.gnupg/*" ||',
  '    context.input.file_path like "*/protect-mcp.key" || context.input.file_path like "*/keys/gateway.json")',
  "}",
  "unless {",
  '  context.input.file_path like "*.pub" || context.input.file_path like "*.example" ||',
  '  context.input.file_path like "*.sample" || context.input.file_path like "*.template"',
  "};",
  "",
  '@id("starter.grep-secret-path")',
  '@reason("Searches inside a credential file or folder. Ask the person for the value you need.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource)',
  "when {",
  '  resource == Tool::"Grep" && context has input && context.input has path && (',
  '    context.input.path like "*/.env" || context.input.path like "*/.env.*" ||',
  '    context.input.path like "*/.ssh*" || context.input.path like "*/.aws*")',
  "};",
  "",
  '@id("starter.shell-reads-secret")',
  '@reason("Prints a credential file in the shell. Ask the person for the value you need.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash")',
  "when {",
  "  context has input && context.input has command && (",
  '    context.input.command like "*cat *" || context.input.command like "*grep *" ||',
  '    context.input.command like "*rg *" || context.input.command like "*head *" ||',
  '    context.input.command like "*tail *" || context.input.command like "*less *" ||',
  '    context.input.command like "*more *" || context.input.command like "*strings *" ||',
  '    context.input.command like "*base64 *" || context.input.command like "*xxd *") && (',
  '    context.input.command like "* .env" || context.input.command like "* .env *" ||',
  '    context.input.command like "*/.env" || context.input.command like "*/.env *" ||',
  '    context.input.command like "* .env.*" || context.input.command like "*/.env.*" ||',
  '    context.input.command like "*.ssh/id_*" || context.input.command like "*.aws/credentials*" ||',
  '    context.input.command like "*.netrc*" || context.input.command like "*.git-credentials*" ||',
  '    context.input.command like "*.docker/config.json*" || context.input.command like "*gh/hosts.yml*")',
  "}",
  "unless {",
  '  context.input.command like "*.env.example*" || context.input.command like "*.env.sample*" ||',
  '  context.input.command like "*.env.template*" || context.input.command like "*.pub*"',
  "};",
  "",
  '@id("starter.pipe-network-to-shell")',
  '@reason("Runs a downloaded script without review. Save it to a file and read it first.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash")',
  "when {",
  "  context has input && context.input has command &&",
  '  (context.input.command like "*curl *" || context.input.command like "*wget *") && (',
  '    context.input.command like "*| sh" || context.input.command like "*| sh *" ||',
  '    context.input.command like "*|sh" || context.input.command like "*|sh *" ||',
  '    context.input.command like "*| bash" || context.input.command like "*| bash *" ||',
  '    context.input.command like "*|bash" || context.input.command like "*|bash *" ||',
  '    context.input.command like "*| zsh" || context.input.command like "*| zsh *" ||',
  '    context.input.command like "*| sudo sh*" || context.input.command like "*| sudo bash*" ||',
  '    context.input.command like "*| sudo -E bash*" || context.input.command like "*sh <(curl*" ||',
  '    context.input.command like "*sh <(wget*" || context.input.command like "*source <(curl*" ||',
  '    context.input.command like "*sh -c \\"$(curl*" || context.input.command like "*sh -c \\"$(wget*" ||',
  '    context.input.command like "*eval \\"$(curl*" || context.input.command like "*eval $(curl*")',
  "};",
  "",
  '@id("starter.write-sensitive-location")',
  '@reason("Writes a system, shell-profile, SSH, credential or agent-control file. A person makes this change.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource)',
  "when {",
  '  (resource == Tool::"Write" || resource == Tool::"Edit" || resource == Tool::"MultiEdit") &&',
  "  context has input && context.input has file_path && (",
  '    context.input.file_path like "/etc/*" || context.input.file_path like "/private/etc/*" ||',
  '    context.input.file_path like "/usr/*" || context.input.file_path like "/bin/*" ||',
  '    context.input.file_path like "/sbin/*" || context.input.file_path like "/System/*" ||',
  '    context.input.file_path like "/Library/*" || context.input.file_path like "*/Library/LaunchAgents/*" ||',
  '    context.input.file_path like "*/.bashrc" || context.input.file_path like "*/.bash_profile" ||',
  '    context.input.file_path like "*/.zshrc" || context.input.file_path like "*/.zprofile" ||',
  '    context.input.file_path like "*/.zshenv" || context.input.file_path like "*/.profile" ||',
  '    context.input.file_path like "*/.config/autostart/*" || context.input.file_path like "*/.gitconfig" ||',
  '    context.input.file_path like "*/.ssh/*" || context.input.file_path like "*/.aws/*" ||',
  '    context.input.file_path like "*/.netrc" || context.input.file_path like "*/.git-credentials" ||',
  '    context.input.file_path like "*/.claude/settings.json" || context.input.file_path like "*/.claude/settings.local.json" ||',
  '    context.input.file_path like "*/.codex/config.toml" || context.input.file_path like "*/.codex/hooks.json" ||',
  '    context.input.file_path like "*/protect.cedar" || context.input.file_path like "*/protect-mcp.key" ||',
  '    context.input.file_path like "*/keys/gateway.json" || context.input.file_path like "*/../*")',
  "};",
  ""
].join("\n");
var STARTER_CONTAIN_TEMPLATE = [
  '@id("starter.write-outside-project")',
  '@reason("Writes outside this project. Work inside the project or a temporary folder, or ask the person.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource)',
  "when {",
  '  (resource == Tool::"Write" || resource == Tool::"Edit" || resource == Tool::"MultiEdit") &&',
  "  context has input && context.input has file_path",
  "}",
  "unless {",
  '  context.input.file_path like "__PROJECT__/*" ||',
  '  context.input.file_path like "/tmp/*" || context.input.file_path like "/private/tmp/*" ||',
  '  context.input.file_path like "/var/folders/*" || context.input.file_path like "/private/var/folders/*" ||',
  '  context.input.file_path like "__HOME__/.claude/projects/*/memory/*" ||',
  '  context.input.file_path like "__HOME__/.claude/plans/*"',
  "};",
  "",
  '@id("starter.delete-outside-project")',
  '@reason("Recursive delete of an absolute path outside this project. Delete inside the project, or ask the person.")',
  'forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash")',
  "when {",
  "  context has input && context.input has command && (",
  '    context.input.command like "*rm -rf /*" || context.input.command like "*rm -rf \\"/*" ||',
  '    context.input.command like "*rm -rf ~/*" || context.input.command like "*rm -rf $HOME/*" ||',
  '    context.input.command like "*rm -rf \\"$HOME/*")',
  "}",
  "unless {",
  '  context.input.command like "*rm -rf __PROJECT__/*" || context.input.command like "*rm -rf \\"__PROJECT__/*" ||',
  '  context.input.command like "*rm -rf __TILDE__/*" ||',
  '  context.input.command like "*rm -rf /tmp/*" || context.input.command like "*rm -rf \\"/tmp/*" ||',
  '  context.input.command like "*rm -rf /private/tmp/*" || context.input.command like "*rm -rf \\"/private/tmp/*" ||',
  '  context.input.command like "*rm -rf /var/folders/*" || context.input.command like "*rm -rf \\"/var/folders/*" ||',
  '  context.input.command like "*rm -rf /private/var/folders/*" || context.input.command like "*rm -rf \\"/private/var/folders/*" ||',
  '  context.input.command like "*rm -rf $TMPDIR*" || context.input.command like "*rm -rf \\"$TMPDIR*"',
  "};",
  ""
].join("\n");
var unescapeCedarString = (s) => s.replace(/\\(.)/g, (_, c) => c === "n" ? "\n" : c === "t" ? "	" : c);
function annotatedRules(source) {
  const rules = [];
  const re = /@id\("((?:[^"\\]|\\.)*)"\)\s*(?:@reason\("((?:[^"\\]|\\.)*)"\))?/g;
  let m;
  while (m = re.exec(source)) rules.push({ id: unescapeCedarString(m[1]), reason: m[2] === void 0 ? "" : unescapeCedarString(m[2]) });
  return rules;
}
function starterRules() {
  return annotatedRules(STARTER_POLICY).filter((rule) => rule.reason !== "");
}
function cedarLikeLiteral(value) {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\*/g, "\\*");
}
function renderContainRules(projectDir, homeDir) {
  const trim = (p) => p.length > 1 ? p.replace(/\/+$/, "") : p;
  const project = trim(projectDir);
  const home = trim(homeDir);
  for (const [label, path] of [["project", project], ["home", home]]) {
    if (!path.startsWith("/")) throw new Error(`--contain needs an absolute POSIX ${label} path; got ${JSON.stringify(path)}`);
    if (/[\u0000-\u001f\u007f]/.test(path)) throw new Error(`--contain cannot use a ${label} path that contains control characters`);
  }
  if (project === "/" || project === home) {
    throw new Error("--contain needs a project folder; it will not treat / or the home folder itself as the project");
  }
  const homePrefix = home === "/" ? "" : home;
  const tilde = project.startsWith(`${homePrefix}/`) && homePrefix !== "" ? `~${project.slice(homePrefix.length)}` : project;
  const values = { PROJECT: project, TILDE: tilde, HOME: homePrefix };
  return STARTER_CONTAIN_TEMPLATE.replace(/__(PROJECT|TILDE|HOME)__/g, (_, key) => cedarLikeLiteral(values[key]));
}
var BUILTIN_POLICY_PREFIX = "builtin:";
var BUILTIN_POLICIES = {
  starter: { file: STARTER_POLICY_FILE, source: STARTER_POLICY }
};
function builtinPolicyNames() {
  return Object.keys(BUILTIN_POLICIES).map((name) => `${BUILTIN_POLICY_PREFIX}${name}`);
}
function isBuiltinPolicySpec(spec) {
  return typeof spec === "string" && spec.startsWith(BUILTIN_POLICY_PREFIX);
}
function resolveBuiltinPolicy(spec) {
  if (!isBuiltinPolicySpec(spec)) return null;
  const name = spec.slice(BUILTIN_POLICY_PREFIX.length);
  const policy = Object.prototype.hasOwnProperty.call(BUILTIN_POLICIES, name) ? BUILTIN_POLICIES[name] : void 0;
  return policy ? { spec, name, file: policy.file, source: policy.source } : null;
}

export {
  STARTER_POLICY_VERSION,
  STARTER_POLICY_FILE,
  STARTER_POLICY,
  STARTER_CONTAIN_TEMPLATE,
  annotatedRules,
  starterRules,
  cedarLikeLiteral,
  renderContainRules,
  BUILTIN_POLICY_PREFIX,
  builtinPolicyNames,
  isBuiltinPolicySpec,
  resolveBuiltinPolicy
};
