/**
 * protect-mcp starter policy for coding agents, v1, and its opt-in project rules.
 *
 * The starter is seven `@id`/`@reason` forbid rules over a default allow, in
 * plain Cedar. The same text is what `--policy builtin:starter` evaluates, what
 * `init --starter` writes to ./protect.cedar, the `coding-starter` policy pack,
 * and the policy `init-hooks` writes. policies/starter.cedar ships the same
 * bytes for reading; src/starter-policy.test.ts holds the two equal, and
 * vectors/starter-policy.v1.json pins the digest and the cases it must decide.
 *
 * Shell rules match the raw command text, so they are a guardrail for an agent
 * working in good faith, not a sandbox: a reworded command can get past them.
 */

export const STARTER_POLICY_VERSION = 1;
/** The name the starter ships under in policies/ and the name the built-in reports. */
export const STARTER_POLICY_FILE = 'starter.cedar';

/** starter.cedar v1, byte for byte (policies/starter.cedar is the same file; a test holds them equal). */
export const STARTER_POLICY: string = [
  "// protect-mcp starter policy for coding agents, v1.",
  "// Everything is allowed except the forbids below, and a forbid always wins.",
  "// Shell rules match the raw command text, so they are best effort: a reworded",
  "// command can get past them. Every rule checks `has` first, because the gate",
  "// denies on any policy error. This file is yours to edit.",
  "",
  "@id(\"starter.allow-by-default\")",
  "permit (principal, action, resource);",
  "",
  "@id(\"starter.delete-root-or-home\")",
  "@reason(\"Recursive delete of /, the home folder or the parent folder. Delete a specific path inside the project instead.\")",
  "forbid (principal, action == Action::\"MCP::Tool::call\", resource == Tool::\"Bash\")",
  "when {",
  "  context has input && context.input has command && (",
  "    context.input.command like \"*rm -rf /\" || context.input.command like \"*rm -rf / *\" ||",
  "    context.input.command like \"*rm -rf ~\" || context.input.command like \"*rm -rf ~ *\" ||",
  "    context.input.command like \"*rm -rf ~/\" || context.input.command like \"*rm -rf ~/ *\" ||",
  "    context.input.command like \"*rm -rf $HOME\" || context.input.command like \"*rm -rf $HOME *\" ||",
  "    context.input.command like \"*rm -rf $HOME/\" || context.input.command like \"*rm -rf $HOME/ *\" ||",
  "    context.input.command like \"*rm -rf \\\"$HOME\\\"\" || context.input.command like \"*rm -rf \\\"$HOME\\\" *\" ||",
  "    context.input.command like \"*rm -rf ..\" || context.input.command like \"*rm -rf .. *\" ||",
  "    context.input.command like \"*rm -rf ../\" || context.input.command like \"*rm -rf ../ *\" ||",
  "    context.input.command like \"*rm -rf /\\**\" || context.input.command like \"*rm -rf ~/\\**\" ||",
  "    context.input.command like \"*rm -rf $HOME/\\**\" || context.input.command like \"*rm -rf \\\"$HOME/\\\"\\**\" ||",
  "    context.input.command like \"*rm -fr /\" || context.input.command like \"*rm -fr ~\" ||",
  "    context.input.command like \"*rm -fr ~/\" || context.input.command like \"*rm -fr $HOME\")",
  "};",
  "",
  "@id(\"starter.force-push-main\")",
  "@reason(\"Force-push to main or master, or a force-push that names no branch. Push a named feature branch instead.\")",
  "forbid (principal, action == Action::\"MCP::Tool::call\", resource == Tool::\"Bash\")",
  "when {",
  "  context has input && context.input has command && (",
  "    context.input.command like \"*git push*--force* origin main*\" || context.input.command like \"*git push*-f origin main*\" ||",
  "    context.input.command like \"*git push*origin main --force*\" || context.input.command like \"*git push*origin main -f*\" ||",
  "    context.input.command like \"*git push*--force*:main*\" || context.input.command like \"*git push*origin +main*\" ||",
  "    context.input.command like \"*git push*--force* origin master*\" || context.input.command like \"*git push*-f origin master*\" ||",
  "    context.input.command like \"*git push*origin master --force*\" || context.input.command like \"*git push*origin master -f*\" ||",
  "    context.input.command like \"*git push*--force*:master*\" || context.input.command like \"*git push*origin +master*\" ||",
  "    context.input.command like \"*git push*--force\" || context.input.command like \"*git push*--force 2>&1*\" ||",
  "    context.input.command like \"*git push*--force &&*\" || context.input.command like \"*git push*--force-with-lease\" ||",
  "    context.input.command like \"*git push*--force-with-lease 2>&1*\" || context.input.command like \"*git push*--force-with-lease &&*\" ||",
  "    context.input.command like \"*git push*-f\" || context.input.command like \"*git push*-f 2>&1*\" ||",
  "    context.input.command like \"*git push*-f &&*\")",
  "};",
  "",
  "@id(\"starter.read-secret-file\")",
  "@reason(\"Reads a credential file such as .env, ~/.ssh or ~/.aws. Ask the person for the value you need.\")",
  "forbid (principal, action == Action::\"MCP::Tool::call\", resource)",
  "when {",
  "  resource == Tool::\"Read\" && context has input && context.input has file_path && (",
  "    context.input.file_path like \"*/.env\" || context.input.file_path like \"*/.env.*\" ||",
  "    context.input.file_path like \"*/.ssh/*\" || context.input.file_path like \"*/.aws/*\" ||",
  "    context.input.file_path like \"*/.netrc\" || context.input.file_path like \"*/.git-credentials\" ||",
  "    context.input.file_path like \"*/.npmrc\" || context.input.file_path like \"*/.pypirc\" ||",
  "    context.input.file_path like \"*/.docker/config.json\" || context.input.file_path like \"*/.kube/config\" ||",
  "    context.input.file_path like \"*/.config/gh/hosts.yml\" || context.input.file_path like \"*/.gnupg/*\" ||",
  "    context.input.file_path like \"*/protect-mcp.key\" || context.input.file_path like \"*/keys/gateway.json\")",
  "}",
  "unless {",
  "  context.input.file_path like \"*.pub\" || context.input.file_path like \"*.example\" ||",
  "  context.input.file_path like \"*.sample\" || context.input.file_path like \"*.template\"",
  "};",
  "",
  "@id(\"starter.grep-secret-path\")",
  "@reason(\"Searches inside a credential file or folder. Ask the person for the value you need.\")",
  "forbid (principal, action == Action::\"MCP::Tool::call\", resource)",
  "when {",
  "  resource == Tool::\"Grep\" && context has input && context.input has path && (",
  "    context.input.path like \"*/.env\" || context.input.path like \"*/.env.*\" ||",
  "    context.input.path like \"*/.ssh*\" || context.input.path like \"*/.aws*\")",
  "};",
  "",
  "@id(\"starter.shell-reads-secret\")",
  "@reason(\"Prints a credential file in the shell. Ask the person for the value you need.\")",
  "forbid (principal, action == Action::\"MCP::Tool::call\", resource == Tool::\"Bash\")",
  "when {",
  "  context has input && context.input has command && (",
  "    context.input.command like \"*cat *\" || context.input.command like \"*grep *\" ||",
  "    context.input.command like \"*rg *\" || context.input.command like \"*head *\" ||",
  "    context.input.command like \"*tail *\" || context.input.command like \"*less *\" ||",
  "    context.input.command like \"*more *\" || context.input.command like \"*strings *\" ||",
  "    context.input.command like \"*base64 *\" || context.input.command like \"*xxd *\") && (",
  "    context.input.command like \"* .env\" || context.input.command like \"* .env *\" ||",
  "    context.input.command like \"*/.env\" || context.input.command like \"*/.env *\" ||",
  "    context.input.command like \"* .env.*\" || context.input.command like \"*/.env.*\" ||",
  "    context.input.command like \"*.ssh/id_*\" || context.input.command like \"*.aws/credentials*\" ||",
  "    context.input.command like \"*.netrc*\" || context.input.command like \"*.git-credentials*\" ||",
  "    context.input.command like \"*.docker/config.json*\" || context.input.command like \"*gh/hosts.yml*\")",
  "}",
  "unless {",
  "  context.input.command like \"*.env.example*\" || context.input.command like \"*.env.sample*\" ||",
  "  context.input.command like \"*.env.template*\" || context.input.command like \"*.pub*\"",
  "};",
  "",
  "@id(\"starter.pipe-network-to-shell\")",
  "@reason(\"Runs a downloaded script without review. Save it to a file and read it first.\")",
  "forbid (principal, action == Action::\"MCP::Tool::call\", resource == Tool::\"Bash\")",
  "when {",
  "  context has input && context.input has command &&",
  "  (context.input.command like \"*curl *\" || context.input.command like \"*wget *\") && (",
  "    context.input.command like \"*| sh\" || context.input.command like \"*| sh *\" ||",
  "    context.input.command like \"*|sh\" || context.input.command like \"*|sh *\" ||",
  "    context.input.command like \"*| bash\" || context.input.command like \"*| bash *\" ||",
  "    context.input.command like \"*|bash\" || context.input.command like \"*|bash *\" ||",
  "    context.input.command like \"*| zsh\" || context.input.command like \"*| zsh *\" ||",
  "    context.input.command like \"*| sudo sh*\" || context.input.command like \"*| sudo bash*\" ||",
  "    context.input.command like \"*| sudo -E bash*\" || context.input.command like \"*sh <(curl*\" ||",
  "    context.input.command like \"*sh <(wget*\" || context.input.command like \"*source <(curl*\" ||",
  "    context.input.command like \"*sh -c \\\"$(curl*\" || context.input.command like \"*sh -c \\\"$(wget*\" ||",
  "    context.input.command like \"*eval \\\"$(curl*\" || context.input.command like \"*eval $(curl*\")",
  "};",
  "",
  "@id(\"starter.write-sensitive-location\")",
  "@reason(\"Writes a system, shell-profile, SSH, credential or agent-control file. A person makes this change.\")",
  "forbid (principal, action == Action::\"MCP::Tool::call\", resource)",
  "when {",
  "  (resource == Tool::\"Write\" || resource == Tool::\"Edit\" || resource == Tool::\"MultiEdit\") &&",
  "  context has input && context.input has file_path && (",
  "    context.input.file_path like \"/etc/*\" || context.input.file_path like \"/private/etc/*\" ||",
  "    context.input.file_path like \"/usr/*\" || context.input.file_path like \"/bin/*\" ||",
  "    context.input.file_path like \"/sbin/*\" || context.input.file_path like \"/System/*\" ||",
  "    context.input.file_path like \"/Library/*\" || context.input.file_path like \"*/Library/LaunchAgents/*\" ||",
  "    context.input.file_path like \"*/.bashrc\" || context.input.file_path like \"*/.bash_profile\" ||",
  "    context.input.file_path like \"*/.zshrc\" || context.input.file_path like \"*/.zprofile\" ||",
  "    context.input.file_path like \"*/.zshenv\" || context.input.file_path like \"*/.profile\" ||",
  "    context.input.file_path like \"*/.config/autostart/*\" || context.input.file_path like \"*/.gitconfig\" ||",
  "    context.input.file_path like \"*/.ssh/*\" || context.input.file_path like \"*/.aws/*\" ||",
  "    context.input.file_path like \"*/.netrc\" || context.input.file_path like \"*/.git-credentials\" ||",
  "    context.input.file_path like \"*/.claude/settings.json\" || context.input.file_path like \"*/.claude/settings.local.json\" ||",
  "    context.input.file_path like \"*/.codex/config.toml\" || context.input.file_path like \"*/.codex/hooks.json\" ||",
  "    context.input.file_path like \"*/protect.cedar\" || context.input.file_path like \"*/protect-mcp.key\" ||",
  "    context.input.file_path like \"*/keys/gateway.json\" || context.input.file_path like \"*/../*\")",
  "};",
  "",
].join('\n');

/**
 * The opt-in project rules (init --starter --contain), with __PROJECT__, __TILDE__ and __HOME__ still to fill.
 */
export const STARTER_CONTAIN_TEMPLATE: string = [
  "@id(\"starter.write-outside-project\")",
  "@reason(\"Writes outside this project. Work inside the project or a temporary folder, or ask the person.\")",
  "forbid (principal, action == Action::\"MCP::Tool::call\", resource)",
  "when {",
  "  (resource == Tool::\"Write\" || resource == Tool::\"Edit\" || resource == Tool::\"MultiEdit\") &&",
  "  context has input && context.input has file_path",
  "}",
  "unless {",
  "  context.input.file_path like \"__PROJECT__/*\" ||",
  "  context.input.file_path like \"/tmp/*\" || context.input.file_path like \"/private/tmp/*\" ||",
  "  context.input.file_path like \"/var/folders/*\" || context.input.file_path like \"/private/var/folders/*\" ||",
  "  context.input.file_path like \"__HOME__/.claude/projects/*/memory/*\" ||",
  "  context.input.file_path like \"__HOME__/.claude/plans/*\"",
  "};",
  "",
  "@id(\"starter.delete-outside-project\")",
  "@reason(\"Recursive delete of an absolute path outside this project. Delete inside the project, or ask the person.\")",
  "forbid (principal, action == Action::\"MCP::Tool::call\", resource == Tool::\"Bash\")",
  "when {",
  "  context has input && context.input has command && (",
  "    context.input.command like \"*rm -rf /*\" || context.input.command like \"*rm -rf \\\"/*\" ||",
  "    context.input.command like \"*rm -rf ~/*\" || context.input.command like \"*rm -rf $HOME/*\" ||",
  "    context.input.command like \"*rm -rf \\\"$HOME/*\")",
  "}",
  "unless {",
  "  context.input.command like \"*rm -rf __PROJECT__/*\" || context.input.command like \"*rm -rf \\\"__PROJECT__/*\" ||",
  "  context.input.command like \"*rm -rf __TILDE__/*\" ||",
  "  context.input.command like \"*rm -rf /tmp/*\" || context.input.command like \"*rm -rf \\\"/tmp/*\" ||",
  "  context.input.command like \"*rm -rf /private/tmp/*\" || context.input.command like \"*rm -rf \\\"/private/tmp/*\" ||",
  "  context.input.command like \"*rm -rf /var/folders/*\" || context.input.command like \"*rm -rf \\\"/var/folders/*\" ||",
  "  context.input.command like \"*rm -rf /private/var/folders/*\" || context.input.command like \"*rm -rf \\\"/private/var/folders/*\" ||",
  "  context.input.command like \"*rm -rf $TMPDIR*\" || context.input.command like \"*rm -rf \\\"$TMPDIR*\"",
  "};",
  "",
].join('\n');

export interface AnnotatedRule {
  /** The rule's `@id` annotation. */
  id: string;
  /** The rule's `@reason` annotation; empty when it has none. */
  reason: string;
}

const unescapeCedarString = (s: string): string => s.replace(/\\(.)/g, (_, c: string) => (c === 'n' ? '\n' : c === 't' ? '\t' : c));

/**
 * The `@id` and `@reason` annotations of a policy text, in source order. A plain
 * reading for display (init prints the rules in words); the evaluator reads the
 * annotations through the Cedar engine itself.
 */
export function annotatedRules(source: string): AnnotatedRule[] {
  const rules: AnnotatedRule[] = [];
  const re = /@id\("((?:[^"\\]|\\.)*)"\)\s*(?:@reason\("((?:[^"\\]|\\.)*)"\))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source))) rules.push({ id: unescapeCedarString(m[1]), reason: m[2] === undefined ? '' : unescapeCedarString(m[2]) });
  return rules;
}

/** The starter's seven forbid rules, in order, each with its reason. */
export function starterRules(): AnnotatedRule[] {
  return annotatedRules(STARTER_POLICY).filter((rule) => rule.reason !== '');
}

/**
 * A literal for a Cedar `like` pattern written inside a Cedar string: a
 * backslash, a double quote and a star are escaped, so a path containing any
 * of them matches only itself.
 */
export function cedarLikeLiteral(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\*/g, '\\*');
}

/**
 * The opt-in project rules with the project filled in: `__PROJECT__` becomes the
 * project's absolute path, `__TILDE__` its `~/` form when it is under home (the
 * absolute path again when it is not), and `__HOME__` the home folder, each
 * escaped as a Cedar `like` literal. POSIX paths only, since the rules name /tmp
 * and /var/folders; the project must be a folder below `/` other than home itself.
 */
export function renderContainRules(projectDir: string, homeDir: string): string {
  const trim = (p: string): string => (p.length > 1 ? p.replace(/\/+$/, '') : p);
  const project = trim(projectDir);
  const home = trim(homeDir);
  for (const [label, path] of [['project', project], ['home', home]] as const) {
    if (!path.startsWith('/')) throw new Error(`--contain needs an absolute POSIX ${label} path; got ${JSON.stringify(path)}`);
    if (/[\u0000-\u001f\u007f]/.test(path)) throw new Error(`--contain cannot use a ${label} path that contains control characters`);
  }
  if (project === '/' || project === home) {
    throw new Error('--contain needs a project folder; it will not treat / or the home folder itself as the project');
  }
  const homePrefix = home === '/' ? '' : home;
  const tilde = project.startsWith(`${homePrefix}/`) && homePrefix !== '' ? `~${project.slice(homePrefix.length)}` : project;
  const values: Record<string, string> = { PROJECT: project, TILDE: tilde, HOME: homePrefix };
  return STARTER_CONTAIN_TEMPLATE.replace(/__(PROJECT|TILDE|HOME)__/g, (_, key: string) => cedarLikeLiteral(values[key]));
}

/** `--policy builtin:<name>` names a bundled policy text instead of a file. */
export const BUILTIN_POLICY_PREFIX = 'builtin:';

const BUILTIN_POLICIES: Record<string, { file: string; source: string }> = {
  starter: { file: STARTER_POLICY_FILE, source: STARTER_POLICY },
};

/** The built-in policy specs, such as `builtin:starter`. */
export function builtinPolicyNames(): string[] {
  return Object.keys(BUILTIN_POLICIES).map((name) => `${BUILTIN_POLICY_PREFIX}${name}`);
}

/** True when a policy argument names a built-in policy rather than a path. */
export function isBuiltinPolicySpec(spec: string | undefined): spec is string {
  return typeof spec === 'string' && spec.startsWith(BUILTIN_POLICY_PREFIX);
}

/**
 * The bundled text a `builtin:<name>` spec names, or null when the name is not a
 * built-in policy (the caller reports that and fails closed).
 */
export function resolveBuiltinPolicy(spec: string): { spec: string; name: string; file: string; source: string } | null {
  if (!isBuiltinPolicySpec(spec)) return null;
  const name = spec.slice(BUILTIN_POLICY_PREFIX.length);
  const policy = Object.prototype.hasOwnProperty.call(BUILTIN_POLICIES, name) ? BUILTIN_POLICIES[name] : undefined;
  return policy ? { spec, name, file: policy.file, source: policy.source } : null;
}
