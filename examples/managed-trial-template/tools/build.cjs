'use strict';
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const source = path.join(root, 'site', 'index.html');
const stat = fs.lstatSync(source);
if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536) throw new Error('Expected one regular HTML file no larger than 64 KiB.');
const output = path.join(root, 'dist');
if (fs.existsSync(output)) {
  const outStat = fs.lstatSync(output);
  if (!outStat.isDirectory() || outStat.isSymbolicLink()) throw new Error('Build output must be a regular directory.');
  fs.rmSync(output, { recursive: true });
}
fs.mkdirSync(output);
fs.copyFileSync(source, path.join(output, 'index.html'));
process.stdout.write('Built dist/index.html from site/index.html.\n');
