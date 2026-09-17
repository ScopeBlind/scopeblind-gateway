'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const file = path.resolve(__dirname, '../site/index.html');
const html = fs.readFileSync(file, 'utf8');

test('the studio remains a self-contained static page', () => {
  assert.ok(fs.lstatSync(file).isFile() && !fs.lstatSync(file).isSymbolicLink(), 'Use a regular HTML file.');
  assert.ok(Buffer.byteLength(html) <= 65536, 'Keep this small page within 64 KiB.');
  assert.match(html, /<!doctype html>/i);
  assert.match(html, /<html\b[^>]*\blang=["']en["']/i);
  assert.match(html, /<meta\b[^>]*\bname=["']viewport["']/i);
  assert.match(html, /<title>[^<]+<\/title>/i);
  assert.match(html, /<h1\b[^>]*>[\s\S]+?<\/h1>/i);
  assert.doesNotMatch(html, /<\s*(?:script|form|iframe|object|embed|base|link|img|video|audio|source|svg)\b/i, 'No scripts, forms, embedded content, or external assets in this trial.');
  assert.doesNotMatch(html, /\bon[a-z]+\s*=|javascript\s*:|@import\b|url\s*\(/i, 'Keep behavior to native document links and local styles.');
  assert.doesNotMatch(html, /<meta\b[^>]*http-equiv\s*=/i, 'No document redirects.');
  for (const match of html.matchAll(/\bhref\s*=\s*(["'])(.*?)\1/gi)) {
    assert.match(match[2], /^#[A-Za-z][A-Za-z0-9_-]*$/, 'Links in this trial stay within the document.');
  }
});

test('the contact button reaches a useful contact section', () => {
  assert.match(html, /<a\b[^>]*\bhref=["']#contact["'][^>]*>[\s\S]*?<\/a>/i, 'Keep the contact button as a native link to #contact.');
  const section = html.match(/<section\b[^>]*\bid=["']contact["'][^>]*>([\s\S]*?)<\/section>/i);
  assert.ok(section, 'The contact link needs a matching contact section.');
  assert.match(section[1], /<h[2-3]\b[^>]*>[^<]+<\/h[2-3]>/i, 'Give the contact section a visible heading.');
  const text = section[1].replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  assert.ok(text.length >= 40, 'Include useful contact information or a clear next step.');
  assert.match(text, /contact|touch|hello|write|email|conversation/i, 'Make the next step understandable.');
  assert.equal([...html.matchAll(/\bid\s*=\s*["']contact["']/gi)].length, 1, 'Use one unambiguous contact destination.');
  assert.doesNotMatch(section[0], /\bhidden(?:\s|=|>)|aria-hidden\s*=\s*["']true["']/i, 'The destination must be visible.');
});
