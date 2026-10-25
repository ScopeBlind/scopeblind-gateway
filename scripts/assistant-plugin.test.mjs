import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const plugin = join(root, 'plugins/protect-mcp-assistant');
const json = path => JSON.parse(readFileSync(path, 'utf8'));
const manifest = json(join(plugin, 'plugin.json'));
const pins = json(join(plugin, 'runtime-versions.json'));
const skills = readdirSync(join(plugin, 'skills')).sort();
const files = path => readdirSync(path, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? files(join(path, entry.name)) : [join(path, entry.name)]);

test('portable manifest and marketplace resolve to the same package', () => {
  assert.equal(manifest.$schema, 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json');
  assert.equal(manifest.name, 'protect-mcp-assistant');
  assert.match(manifest.version, /^\d+\.\d+\.\d+$/);
  const allowed = new Set(['$schema', 'name', 'version', 'description', 'author', 'homepage', 'repository', 'license', 'keywords', 'extensions']);
  for (const key of Object.keys(manifest)) assert.ok(allowed.has(key), `Unknown portable field ${key}`);
  assert.equal(manifest.repository, 'https://github.com/ScopeBlind/scopeblind-gateway');
  assert.equal(manifest.homepage, 'https://scopeblind.com/protect-mcp');
  assert.equal(manifest.license, 'MIT');
  assert.ok(existsSync(join(plugin, 'LICENSE')));
  const marketplace = json(join(root, '.agents/plugins/marketplace.json'));
  const entry = marketplace.plugins.find(value => value.name === manifest.name);
  assert.ok(entry, 'Missing marketplace entry');
  assert.equal(entry.policy.installation, 'AVAILABLE');
  assert.equal(entry.source.source, 'local');
  assert.ok(entry.source.path.startsWith('./'));
  assert.equal(realpathSync(resolve(root, entry.source.path)), realpathSync(plugin));
  const onboarding = manifest.extensions['com.openai'].onboardingSkill;
  assert.ok(onboarding.startsWith('./skills/'));
  assert.ok(realpathSync(resolve(plugin, onboarding)).startsWith(realpathSync(plugin) + sep));
});

test('package has only the intended skills and no automatic tool wiring', () => {
  assert.deepEqual(skills, ['protect-mcp-demo', 'protect-mcp-setup', 'protect-mcp-verify']);
  const overlay = manifest.extensions['com.openai'];
  for (const field of ['hooks', 'apps', 'mcpServers']) assert.equal(overlay[field], undefined);
  for (const path of ['hooks', 'hooks.json', 'mcp.json', '.mcp.json', '.app.json', '.codex-plugin']) {
    assert.equal(existsSync(join(plugin, path)), false, `Unexpected automatic integration ${path}`);
  }
  for (const name of skills) {
    const text = readFileSync(join(plugin, 'skills', name, 'SKILL.md'), 'utf8');
    assert.match(text, new RegExp(`^---\\nname: ${name}\\ndescription: [^\\n]+\\n---`));
    assert.doesNotMatch(text, /\[TODO:|disable-model-invocation/);
    const ui = readFileSync(join(plugin, 'skills', name, 'agents/openai.yaml'), 'utf8');
    assert.ok(ui.includes(`$${name}`));
  }
});

test('listing and composer icons are packaged square PNGs within documented limits', () => {
  const presentation = manifest.extensions['com.openai'].interface;
  for (const field of ['logo', 'composerIcon']) {
    const asset = presentation[field];
    assert.equal(typeof asset, 'string', `Missing ${field}`);
    assert.ok(asset.startsWith('./assets/'), `${field} must be package-relative`);
    const path = realpathSync(resolve(plugin, asset));
    assert.ok(path.startsWith(realpathSync(plugin) + sep), `${field} resolves outside the package`);
    const png = readFileSync(path);
    assert.ok(png.length <= 5 * 1024 * 1024, `${field} exceeds the 5 MiB limit`);
    assert.deepEqual(png.subarray(0, 8), Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
    assert.equal(png.subarray(12, 16).toString('ascii'), 'IHDR');
    const width = png.readUInt32BE(16);
    const height = png.readUInt32BE(20);
    assert.equal(width, height, `${field} must be square`);
    assert.ok(width >= 48 && width <= 4096, `${field} dimensions must be 48 to 4096 pixels`);
  }
});

test('all bundled relative guidance links remain inside the package', () => {
  for (const path of files(plugin).filter(path => path.endsWith('.md'))) {
    const text = readFileSync(path, 'utf8');
    for (const match of text.matchAll(/\]\(([^\s)]+)\)/g)) {
      const href = match[1];
      if (/^(https?:|mailto:|#)/.test(href)) continue;
      const target = realpathSync(resolve(dirname(path), href.split('#')[0]));
      assert.ok(target.startsWith(realpathSync(plugin) + sep), `${path} links outside its install: ${href}`);
    }
  }
});

test('runtime commands stay pinned to the tested releases', () => {
  assert.deepEqual(pins, { 'protect-mcp': '0.32.4', '@veritasacta/verify': '0.11.0' });
  for (const path of files(plugin).filter(path => /\.(md|mjs)$/.test(path))) {
    const text = readFileSync(path, 'utf8');
    for (const match of text.matchAll(/(protect-mcp|@veritasacta\/verify)@([\w.^~*-]+)/g)) {
      assert.equal(match[2], pins[match[1]], `Untested package selector in ${path}`);
    }
  }
  const setup = readFileSync(join(plugin, 'skills/protect-mcp-setup/references/wrapper.md'), 'utf8');
  const policy = JSON.parse(setup.match(/```json\n([\s\S]*?)\n```/)[1]);
  assert.deepEqual(policy.tools['*'], { block: true });
  assert.equal(policy.signing.enabled, true);
  assert.equal(policy.tools.sensitive_tool.require_approval, true);
});
