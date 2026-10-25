import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import childProcess from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import * as cedar from './cedar-evaluator.js';
import { diagnoseDoctor, formatDoctorReport, handleDoctor, type DoctorReport } from './doctor.js';

const folders: string[] = [];
const fresh = () => { const dir = mkdtempSync(join(tmpdir(), 'protect-doctor-')); folders.push(dir); return dir; };
const put = (path: string, value: unknown) => {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value));
};
const keyPair = () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32).toString('hex'),
    publicKey: publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'),
  };
};
function setup(dir: string, configName = 'protect-mcp.json', keyPath = 'keys/gateway.json') {
  const key = keyPair();
  put(join(dir, keyPath), key);
  chmodSync(join(dir, keyPath), 0o600);
  put(join(dir, configName), { tools: { '*': { rate_limit: '100/hour' } }, signing: { key_path: `./${keyPath}`, enabled: true } });
  return key;
}
const check = (report: DoctorReport, id: string) => report.checks.find(item => item.id === id)!;

beforeEach(() => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async () => { throw new Error('Unexpected network access'); });
});
afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of folders.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('local doctor', () => {
  it('fails a fresh directory without creating a config, key, or log', async () => {
    const dir = fresh();
    const report = await diagnoseDoctor({ dir });
    expect(report.ok).toBe(false);
    expect(report.exitCode).toBe(1);
    expect(check(report, 'policy_config').status).toBe('fail');
    expect(check(report, 'host_connection').status).toBe('not_checked');
    expect(check(report, 'decision_log').status).toBe('not_checked');
    expect(readdirSync(dir)).toEqual([]);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('rejects an absent workspace and a file used as --dir', async () => {
    const dir = fresh();
    put(join(dir, 'file'), 'not a directory');
    for (const path of [join(dir, 'missing'), join(dir, 'file')]) {
      const report = await diagnoseDoctor({ dir: path });
      expect(report.exitCode).toBe(1);
      expect(check(report, 'workspace').status).toBe('fail');
    }
  });

  it('checks the actual init output and preserves every file', async () => {
    const dir = fresh();
    const cli = join(__dirname, '..', 'dist', 'cli.js');
    expect(existsSync(cli), 'Build the CLI before this integration test').toBe(true);
    const initialized = childProcess.spawnSync(process.execPath, [cli, 'init', '--dir', dir], {
      cwd: dir, encoding: 'utf8', input: '', timeout: 30_000,
      env: { ...process.env, PROTECT_MCP_TELEMETRY: 'off', NO_COLOR: '1' },
    });
    expect(initialized.status, initialized.stderr).toBe(0);
    const before = readFileSync(join(dir, 'keys/gateway.json'), 'utf8');
    const report = await diagnoseDoctor({ dir });
    expect(report.exitCode).toBe(0);
    expect(report.setup).toBe('gateway_config');
    expect(check(report, 'signing_key').status).toBe('pass');
    expect(check(report, 'policy_config').path).toBe(join(dir, 'protect-mcp.json'));
    expect(check(report, 'evaluator_self_test').status).toBe('pass');
    expect(check(report, 'cedar_engine').status).toBe('pass');
    expect(check(report, 'host_connection').status).toBe('not_checked');
    expect(readFileSync(join(dir, 'keys/gateway.json'), 'utf8')).toBe(before);
    expect(JSON.stringify(report)).not.toContain(JSON.parse(before).privateKey);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('resolves explicit JSON config and its relative key from --dir, not the config parent', async () => {
    const dir = fresh();
    setup(dir, 'config/custom.json', 'keys/custom.json');
    const report = await diagnoseDoctor({ dir, policy: 'config/custom.json' });
    expect(report.exitCode).toBe(0);
    expect(check(report, 'signing_key').path).toBe(join(dir, 'keys/custom.json'));
  });

  it('honors an explicit missing config rather than falling back to a working default', async () => {
    const dir = fresh();
    setup(dir);
    const report = await diagnoseDoctor({ dir, policy: 'missing.json' });
    expect(report.exitCode).toBe(1);
    expect(check(report, 'policy_config').path).toBe(join(dir, 'missing.json'));
    expect(check(report, 'signing_key').status).toBe('not_checked');
  });

  it('rejects malformed config without printing contents or changing it', async () => {
    const dir = fresh();
    const bad = '{"tools":{},"secret":"do-not-include-this-secret",';
    put(join(dir, 'protect-mcp.json'), bad);
    const report = await diagnoseDoctor({ dir });
    expect(report.exitCode).toBe(1);
    expect(JSON.stringify(report)).not.toContain('do-not-include');
    expect(readFileSync(join(dir, 'protect-mcp.json'), 'utf8')).toBe(bad);
  });

  it('does not treat historical scopeblind.config.json as the current gateway setup', async () => {
    const dir = fresh();
    put(join(dir, 'scopeblind.config.json'), { signing: { private_key: 'old' } });
    const report = await diagnoseDoctor({ dir });
    expect(report.exitCode).toBe(1);
    expect(report.setup).toBe('unconfigured');
  });

  it('reports missing configured keys instead of using another key in the folder', async () => {
    const dir = fresh();
    setup(dir);
    put(join(dir, 'protect-mcp.json'), { tools: {}, signing: { key_path: './keys/missing.json' } });
    const report = await diagnoseDoctor({ dir });
    expect(report.exitCode).toBe(1);
    expect(check(report, 'signing_key').path).toBe(join(dir, 'keys/missing.json'));
    expect(check(report, 'signing_key').status).toBe('fail');
  });

  it.each([{}, { key_path: 12 }, { key_path: '' }])('fails enabled signing without a usable key_path: %j', async signing => {
    const dir = fresh();
    put(join(dir, 'protect-mcp.json'), { tools: {}, signing });
    expect(check(await diagnoseDoctor({ dir }), 'signing_key').status).toBe('fail');
  });

  it.each([null, [], 'not signing config', { enabled: 'false' }])('fails malformed signing config: %j', async signing => {
    const dir = fresh();
    put(join(dir, 'protect-mcp.json'), { tools: {}, signing });
    expect(check(await diagnoseDoctor({ dir }), 'signing_config').status).toBe('fail');
  });

  it('reports deliberately disabled and absent signing without claiming receipts', async () => {
    for (const extra of [{ signing: { enabled: false } }, {}]) {
      const dir = fresh();
      put(join(dir, 'protect-mcp.json'), { tools: {}, ...extra });
      const report = await diagnoseDoctor({ dir });
      expect(report.exitCode).toBe(0);
      expect(check(report, 'signing_key').status).toBe('not_checked');
    }
  });

  it('rejects a mismatched key pair and malformed private material without exposing it', async () => {
    const dir = fresh();
    const key = setup(dir);
    put(join(dir, 'keys/gateway.json'), { ...key, publicKey: keyPair().publicKey });
    expect(check(await diagnoseDoctor({ dir }), 'signing_key').message).toMatch(/do not form the same/);
    const secret = 'SECRET-PRIVATE-MATERIAL';
    put(join(dir, 'keys/gateway.json'), `{"privateKey":"${secret}",`);
    const report = await diagnoseDoctor({ dir });
    expect(report.exitCode).toBe(1);
    expect(JSON.stringify(report)).not.toContain(secret);
  });

  it.skipIf(process.platform === 'win32')('reports broad key permissions without modifying them', async () => {
    const dir = fresh();
    setup(dir);
    chmodSync(join(dir, 'keys/gateway.json'), 0o644);
    const report = await diagnoseDoctor({ dir });
    expect(check(report, 'key_permissions').status).toBe('warn');
    expect(check(report, 'signing_key').status).toBe('pass');
  });

  it('recognizes init --starter layout without claiming the wrapper uses its key', async () => {
    const dir = fresh();
    put(join(dir, 'protect.cedar'), 'permit(principal, action, resource);');
    put(join(dir, 'protect-mcp.key'), keyPair());
    chmodSync(join(dir, 'protect-mcp.key'), 0o600);
    const report = await diagnoseDoctor({ dir });
    expect(report.setup).toBe('starter');
    expect(report.exitCode).toBe(0);
    expect(check(report, 'starter_layout').message).toMatch(/wrapper does not automatically/);
    expect(check(report, 'signing_key').path).toBe(join(dir, 'protect-mcp.key'));
    rmSync(join(dir, 'protect-mcp.key'));
    expect((await diagnoseDoctor({ dir })).exitCode).toBe(1);
  });

  it('honors explicit Cedar plus JSON configuration and reports invalid policy syntax', async () => {
    const dir = fresh();
    setup(dir);
    put(join(dir, 'custom/rules.cedar'), 'permit(principal, action, resource);');
    const options = { dir, policy: 'protect-mcp.json', cedar: 'custom' };
    expect((await diagnoseDoctor(options)).exitCode).toBe(0);
    put(join(dir, 'custom/rules.cedar'), 'not a Cedar policy');
    expect(check(await diagnoseDoctor(options), 'cedar_policy').status).toBe('fail');
  });

  it('does not autodetect Cedar when an explicit JSON policy selects a different setup', async () => {
    const dir = fresh();
    setup(dir);
    put(join(dir, 'cedar/invalid.cedar'), 'broken');
    const report = await diagnoseDoctor({ dir, policy: 'protect-mcp.json' });
    expect(report.exitCode).toBe(0);
    expect(check(report, 'cedar_policy')).toBeUndefined();
    expect((await diagnoseDoctor({ dir })).exitCode).toBe(1);
  });

  it('reads actual dot-prefixed log metadata without interpreting or exposing the records', async () => {
    const dir = fresh();
    setup(dir);
    const secret = 'PRIVATE CUSTOMER DATA NOT FOR DIAGNOSTICS';
    put(join(dir, '.protect-mcp-log.jsonl'), secret);
    put(join(dir, '.protect-mcp-receipts.jsonl'), secret);
    const report = await diagnoseDoctor({ dir });
    expect(check(report, 'receipt_log').status).toBe('pass');
    expect(check(report, 'receipt_log').evidence).toBe('observed');
    expect(check(report, 'receipt_log').message).toMatch(/signatures were not checked/);
    expect(JSON.stringify(report)).not.toContain(secret);
  });

  it('does not launch a subprocess or contact a service for default diagnostics', async () => {
    const dir = fresh();
    setup(dir);
    const spawn = vi.spyOn(childProcess, 'spawnSync').mockImplementation(() => { throw new Error('Unexpected subprocess'); });
    const exec = vi.spyOn(childProcess, 'execSync').mockImplementation(() => { throw new Error('Unexpected subprocess'); });
    const report = await diagnoseDoctor({ dir });
    expect(report.network).toBe('not_requested');
    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(spawn).not.toHaveBeenCalled();
    expect(exec).not.toHaveBeenCalled();
  });

  it('runs an explicitly requested hosted health check without credentials or local contents', async () => {
    const dir = fresh();
    setup(dir);
    vi.mocked(globalThis.fetch).mockResolvedValue(new Response('ok', { status: 200 }));
    const report = await diagnoseDoctor({ dir, hosted: true });
    expect(report.exitCode).toBe(0);
    expect(report.network).toBe('hosted_health_requested');
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);
    const [url, init] = vi.mocked(globalThis.fetch).mock.calls[0];
    expect(url).toBe('https://api.scopeblind.com/health');
    expect(init?.body).toBeUndefined();
    expect(init?.headers).toBeUndefined();
    expect(init?.redirect).toBe('error');
    expect(check(report, 'hosted_health').message).toMatch(/authentication and receipt delivery were not checked/);
  });

  it('returns a failure for requested hosted failures, even if local configuration passes', async () => {
    const dir = fresh();
    setup(dir);
    vi.mocked(globalThis.fetch).mockResolvedValue(new Response('', { status: 503 }));
    expect((await diagnoseDoctor({ dir, hosted: true })).exitCode).toBe(1);
  });

  it('does not mistake fail-closed behavior without Cedar for a functioning Cedar installation', async () => {
    const dir = fresh();
    setup(dir);
    put(join(dir, 'cedar/policy.cedar'), 'permit(principal, action, resource);');
    vi.spyOn(cedar, 'runEvaluatorSelfTest').mockResolvedValue({
      wasmAvailable: false, passed: true,
      cases: [{ name: 'engine unavailable denies', expected: 'DENY', actual: 'DENY', pass: true }],
    });
    const report = await diagnoseDoctor({ dir });
    expect(report.exitCode).toBe(1);
    expect(check(report, 'cedar_engine').status).toBe('fail');
    expect(check(report, 'evaluator_self_test').message).toMatch(/unavailable-engine denial only/);
  });

  it('reports a failed evaluator self-test as a failed setup check', async () => {
    const dir = fresh();
    setup(dir);
    vi.spyOn(cedar, 'runEvaluatorSelfTest').mockResolvedValue({ wasmAvailable: true, passed: false, cases: [] });
    expect(check(await diagnoseDoctor({ dir }), 'evaluator_self_test').status).toBe('fail');
  });

  it('formats evidence levels and never describes a merely configured host as active', async () => {
    const dir = fresh();
    setup(dir);
    const report = await diagnoseDoctor({ dir });
    const text = formatDoctorReport(report);
    expect(text).toContain('[PASS · configured]');
    expect(text).toContain('[PASS · observed]');
    expect(text).toContain('[NOT_CHECKED · not_checked] host_connection');
    expect(text).toContain('Host activity and enforcement remain not checked');
    expect(text).not.toContain('Ready to wrap');
  });
});

describe('doctor CLI adapter', () => {
  it('prints a single JSON report and returns the failure code', async () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const exit = await handleDoctor(['--dir', fresh(), '--json']);
    expect(exit).toBe(1);
    expect(stdout).toHaveBeenCalledTimes(1);
    expect(JSON.parse(String(stdout.mock.calls[0][0]))).toMatchObject({ schema: 'protect-mcp.doctor.v1', ok: false, exitCode: 1 });
    expect(stderr).not.toHaveBeenCalled();
  });

  it.each([{ args: ['--dir'] }, { args: ['--policy', '--json'] }, { args: ['--unknown'] }])('rejects invalid flags without performing checks: $args', async ({ args }) => {
    const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const result = await handleDoctor([...args, '--json']);
    expect(result).toBe(2);
    expect(JSON.parse(String(stdout.mock.calls[0][0]))).toMatchObject({ exitCode: 2, error: 'invalid_arguments' });
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('supports help without contacting services or inspecting the cwd', async () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    expect(await handleDoctor(['--help'])).toBe(0);
    expect(String(stdout.mock.calls[0][0])).toContain('Read-only and local by default');
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});
