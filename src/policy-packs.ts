export interface PolicyPack {
  id: string;
  name: string;
  description: string;
  recommendedMode: 'shadow-first' | 'enforce-ready';
  files: Array<{ path: string; contents: string }>;
}

const header = (id: string, description: string) => `// ScopeBlind protect-mcp policy pack: ${id}\n// ${description}\n// Start in shadow mode, review receipts, then run with --enforce.\n\n`;

const defaultPermit = `\n// Default posture: allow non-matching calls so teams can start in shadow mode.\n// Tighten this after reviewing your local action dashboard.\npermit(principal, action == Action::"MCP::Tool::call", resource);\n`;

const filesystemSafe = `${header('filesystem-safe', 'Block common destructive filesystem and secret-file access patterns.')}// Destructive file tools are never safe as an unattended default.
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"delete_file");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"remove_file");

// Secret-like reads by path.
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "path" && (
    context.input.path like "*/.env*" ||
    context.input.path like "*/id_rsa*" ||
    context.input.path like "*/.ssh/*" ||
    context.input.path like "*secret*" ||
    context.input.path like "*credential*"
  )
};

// Dangerous shell operations that mutate or destroy local state.
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*rm -rf*" ||
    context.command like "*mkfs*" ||
    context.command like "*dd if=*" ||
    context.command like "*chmod -R 777*" ||
    context.command like "*chown -R*"
  )
};
${defaultPermit}`;

const gitSafe = `${header('git-safe', 'Prevent unattended history rewrites, force pushes, and destructive repo cleanup.')}forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*git push --force*" ||
    context.command like "*git push -f*" ||
    context.command like "*git reset --hard*" ||
    context.command like "*git clean -fd*" ||
    context.command like "*git checkout --*" ||
    context.command like "*git branch -D*" ||
    context.command like "*gh repo delete*"
  )
};
${defaultPermit}`;

const emailSafe = `${header('email-safe', 'Permit drafting but block unattended external sends.')}forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"mail.send");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"email.send");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"send_email");
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"gmail.send");

// Shell fallbacks that send mail are blocked too.
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*sendmail*" ||
    context.command like "*mailx*" ||
    context.command like "*smtp*"
  )
};
${defaultPermit}`;

const databaseSafe = `${header('database-safe', 'Allow reads, block write/admin SQL unless explicitly approved elsewhere.')}forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "query" && (
    context.input.query like "*DROP *" ||
    context.input.query like "*TRUNCATE *" ||
    context.input.query like "*DELETE *" ||
    context.input.query like "*UPDATE *" ||
    context.input.query like "*INSERT *" ||
    context.input.query like "*ALTER *" ||
    context.input.query like "*GRANT *" ||
    context.input.query like "*REVOKE *"
  )
};
${defaultPermit}`;

const cloudSpendSafe = `${header('cloud-spend-safe', 'Block cloud actions that can create spend or destroy infrastructure.')}forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*terraform destroy*" ||
    context.command like "*terraform apply*" ||
    context.command like "*pulumi up*" ||
    context.command like "*pulumi destroy*" ||
    context.command like "*aws ec2 run-instances*" ||
    context.command like "*aws rds create*" ||
    context.command like "*gcloud compute instances create*" ||
    context.command like "*az vm create*" ||
    context.command like "*kubectl delete*"
  )
};
${defaultPermit}`;

const secretsSafe = `${header('secrets-safe', 'Block secret exfiltration from files, env, shell, and common credential tools.')}forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "path" && (
    context.input.path like "*/.env*" ||
    context.input.path like "*/.aws/credentials*" ||
    context.input.path like "*/.npmrc*" ||
    context.input.path like "*/.netrc*" ||
    context.input.path like "*/id_rsa*" ||
    context.input.path like "*secret*" ||
    context.input.path like "*token*"
  )
};

forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"Bash") when {
  context has "command" && (
    context.command like "*printenv*" ||
    context.command like "*env |*" ||
    context.command like "*security find-generic-password*" ||
    context.command like "*aws secretsmanager get-secret-value*" ||
    context.command like "*gcloud secrets versions access*" ||
    context.command like "*op read*"
  )
};
${defaultPermit}`;

const financeMandateSafe = `${header('finance-mandate-safe', 'Block restricted-list and concentration-limit breaches in booking tools.')}forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"pms.book") when {
  context has "input" && context.input has "on_restricted_list" && context.input.on_restricted_list == true
};
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"booking.execute") when {
  context has "input" && context.input has "on_restricted_list" && context.input.on_restricted_list == true
};
forbid(principal, action == Action::"MCP::Tool::call", resource == Tool::"booking.ticket") when {
  context has "input" && context.input has "on_restricted_list" && context.input.on_restricted_list == true
};

// Default example caps: single-name > 10%, gross > 200%, net > 100%.
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "post_trade_weight_bps" && context.input.post_trade_weight_bps > 1000
};
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "post_trade_gross_exposure_bps" && context.input.post_trade_gross_exposure_bps > 20000
};
forbid(principal, action == Action::"MCP::Tool::call", resource) when {
  context has "input" && context.input has "post_trade_net_exposure_bps" && context.input.post_trade_net_exposure_bps > 10000
};
${defaultPermit}`;

export const POLICY_PACKS: PolicyPack[] = [
  {
    id: 'filesystem-safe',
    name: 'Filesystem Safe',
    description: 'Blocks destructive filesystem calls and secret-like path reads.',
    recommendedMode: 'shadow-first',
    files: [{ path: 'filesystem-safe.cedar', contents: filesystemSafe }],
  },
  {
    id: 'git-safe',
    name: 'Git Safe',
    description: 'Blocks force pushes, hard resets, destructive cleanup, and repo deletion.',
    recommendedMode: 'shadow-first',
    files: [{ path: 'git-safe.cedar', contents: gitSafe }],
  },
  {
    id: 'email-safe',
    name: 'Email Safe',
    description: 'Allows drafting workflows while blocking unattended sends.',
    recommendedMode: 'shadow-first',
    files: [{ path: 'email-safe.cedar', contents: emailSafe }],
  },
  {
    id: 'database-safe',
    name: 'Database Safe',
    description: 'Allows read-oriented DB tools while blocking mutating/admin SQL.',
    recommendedMode: 'shadow-first',
    files: [{ path: 'database-safe.cedar', contents: databaseSafe }],
  },
  {
    id: 'cloud-spend-safe',
    name: 'Cloud Spend Safe',
    description: 'Blocks obvious cloud spend creation and infrastructure destruction.',
    recommendedMode: 'shadow-first',
    files: [{ path: 'cloud-spend-safe.cedar', contents: cloudSpendSafe }],
  },
  {
    id: 'secrets-safe',
    name: 'Secrets Safe',
    description: 'Blocks common file, env, shell, and cloud secret exfiltration paths.',
    recommendedMode: 'enforce-ready',
    files: [{ path: 'secrets-safe.cedar', contents: secretsSafe }],
  },
  {
    id: 'finance-mandate-safe',
    name: 'Finance Mandate Safe',
    description: 'Blocks restricted-list and concentration breaches in booking flows.',
    recommendedMode: 'shadow-first',
    files: [{ path: 'finance-mandate-safe.cedar', contents: financeMandateSafe }],
  },
];

export function getPolicyPack(id: string): PolicyPack | undefined {
  return POLICY_PACKS.find((pack) => pack.id === id);
}

export function policyPackIds(): string[] {
  return POLICY_PACKS.map((pack) => pack.id);
}
