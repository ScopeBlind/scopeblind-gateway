import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const have = existsSync(CLI);
const d = have ? describe : describe.skip;

const STARTER = `permit(
  principal,
  action == Action::"MCP::Tool::call",
  resource == Tool::"Read"
);

// forbid(
//   principal,
//   action == Action::"MCP::Tool::call",
//   resource == Tool::"delete_file"
// );
`;

function freshPolicyDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'pmcp-policycli-'));
  mkdirSync(join(dir, 'policies'));
  writeFileSync(join(dir, 'policies', 'agent.cedar'), STARTER);
  return dir;
}
const run = (cwd: string, ...args: string[]) =>
  spawnSync('node', [CLI, 'policy', ...args], { cwd, encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });

d('cli: policy command', () => {
  it('list shows permit for allowed tools and does NOT read commented-out rules as active', () => {
    const dir = freshPolicyDir();
    const r = run(dir, 'list');
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/permit\s+Read/);
    expect(r.stdout).not.toMatch(/forbid\s+delete_file/); // it is commented out
  });

  it('allow appends a permit rule and is idempotent', () => {
    const dir = freshPolicyDir();
    const file = join(dir, 'policies', 'agent.cedar');
    const r1 = run(dir, 'allow', 'Workflow');
    expect(r1.status).toBe(0);
    expect(r1.stdout).toContain('Allowed Workflow');
    expect(readFileSync(file, 'utf8')).toMatch(/permit\([\s\S]*Tool::"Workflow"/);
    expect(run(dir, 'list').stdout).toMatch(/permit\s+Workflow/);
    const r2 = run(dir, 'allow', 'Workflow');
    expect(r2.status).toBe(0);
    expect(r2.stdout).toContain('No change');
  });

  it('deny appends a forbid rule that list reports', () => {
    const dir = freshPolicyDir();
    const r = run(dir, 'deny', 'Bash');
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Denied Bash');
    expect(run(dir, 'list').stdout).toMatch(/forbid\s+Bash/);
  });

  it('rejects an invalid tool name', () => {
    const dir = freshPolicyDir();
    const r = run(dir, 'allow', 'evil; rm -rf /');
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/not a valid tool name/);
  });

  it('path prints the policy file', () => {
    const dir = freshPolicyDir();
    const r = run(dir, 'path');
    expect(r.status).toBe(0);
    expect(r.stdout.trim()).toMatch(/policies\/agent\.cedar$/);
  });
});
