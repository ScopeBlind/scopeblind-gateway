import {
  RepositoryCodingRunner,
  gitBlob
} from "./chunk-N5HNIKFM.mjs";
import {
  RepositoryReceiver
} from "./chunk-JRJSKQFR.mjs";
import {
  REPOSITORY_HEX,
  REPOSITORY_ID,
  REPOSITORY_SHA,
  validRepositoryEnvelope,
  validRepositoryWorkspace,
  validWorkspaceInvitation,
  verifyRepositoryCodingEvidence,
  verifyRepositoryEvidence,
  verifyRepositoryWorkspaceState
} from "./chunk-S2VKIQZF.mjs";
import {
  canonical,
  importIdentity,
  makeRequest,
  sha256,
  sign,
  verify
} from "./chunk-O3K3FPBT.mjs";

// src/repository-trial-template.ts
var TRIAL_BEFORE_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <meta name="description" content="Fieldwork is a small independent design studio making useful things for thoughtful people.">\n  <title>Fieldwork \u2014 Useful things, thoughtfully made</title>\n  <style>\n    :root { color-scheme: light; --paper:#f6f4ed; --ink:#263c31; --muted:#58685b; --line:#d7dccf; --accent:#d9e7b6; }\n    * { box-sizing:border-box; }\n    html { scroll-behavior:smooth; }\n    body { margin:0; background:var(--paper); color:var(--ink); font:16px/1.65 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }\n    a { color:inherit; text-underline-offset:4px; }\n    a:focus-visible { outline:3px solid var(--ink); outline-offset:5px; }\n    .wrap { width:min(1120px,calc(100% - 80px)); margin:auto; }\n    .nav { display:flex; justify-content:space-between; align-items:center; gap:24px; padding:30px 0; border-bottom:1px solid var(--line); }\n    .wordmark { font-family:Georgia,serif; font-size:30px; font-weight:700; letter-spacing:-1.5px; }\n    .nav-note,.eyebrow { font-size:11px; font-weight:650; letter-spacing:.15em; text-transform:uppercase; }\n    .nav-note { color:var(--muted); }\n    .hero { display:grid; grid-template-columns:1.35fr .8fr; gap:72px; align-items:center; padding:90px 0 84px; }\n    .eyebrow { margin:0 0 22px; color:var(--muted); }\n    h1,h2,h3,p { margin-top:0; }\n    h1,h2 { font-family:Georgia,"Times New Roman",serif; font-weight:400; letter-spacing:-.05em; }\n    h1 { max-width:720px; font-size:clamp(48px,6.2vw,82px); line-height:1.06; margin-bottom:27px; }\n    h1 em { font-weight:400; }\n    .intro { max-width:460px; font-size:17px; color:var(--muted); margin-bottom:28px; }\n    .contact-button { display:inline-flex; align-items:center; justify-content:space-between; gap:35px; min-height:52px; padding:12px 22px; border-radius:4px; background:var(--ink); color:#fff; text-decoration:none; font-size:14px; font-weight:600; }\n    .contact-button:hover { background:#38503f; }\n    .studio-card { position:relative; min-height:345px; display:flex; flex-direction:column; justify-content:space-between; background:var(--accent); border-radius:48% 48% 5px 5px; padding:48px 34px 28px; overflow:hidden; }\n    .studio-card::before { content:""; width:155px; height:155px; border:1px solid #8b9f70; border-radius:50%; position:absolute; top:69px; right:-36px; }\n    .card-mark { font:italic 100px/.95 Georgia,serif; letter-spacing:-9px; }\n    .card-caption { max-width:200px; margin:50px 0 0; font-size:14px; line-height:1.55; }\n    .work { padding:35px 0 70px; border-top:1px solid var(--line); }\n    .section-heading { display:flex; justify-content:space-between; align-items:baseline; gap:24px; margin-bottom:26px; }\n    h2 { font-size:37px; line-height:1.15; margin-bottom:0; }\n    .section-heading p { color:var(--muted); font-size:13px; margin-bottom:0; }\n    .projects { display:grid; grid-template-columns:repeat(3,1fr); gap:22px; }\n    .project { margin:0; }\n    .project-art { min-height:180px; display:flex; align-items:center; justify-content:center; border-radius:4px; margin-bottom:16px; }\n    .project-art span { font:35px/1.1 Georgia,serif; text-align:center; }\n    .project-art.one { background:#e3ddd0; }\n    .project-art.two { background:#dfe6dc; }\n    .project-art.three { background:#e8d8cd; }\n    h3 { margin:0 0 3px; font-size:14px; font-weight:650; }\n    .project p { color:var(--muted); font-size:12px; margin-bottom:0; }\n    .about { display:grid; grid-template-columns:1fr 1.2fr; gap:55px; border-top:1px solid var(--line); padding:40px 0 58px; }\n    .about p { max-width:500px; margin:0; color:var(--muted); }\n    footer { border-top:1px solid var(--line); padding:24px 0 36px; display:flex; justify-content:space-between; gap:18px; font-size:11px; color:var(--muted); }\n    @media(max-width:700px) { .wrap{width:calc(100% - 40px)} .nav{padding:22px 0} .nav-note{max-width:130px;text-align:right;font-size:9px} .hero{grid-template-columns:1fr;gap:36px;padding:52px 0} .intro{font-size:16px} .studio-card{min-height:245px;max-width:390px;width:100%;border-radius:100px 100px 4px 4px;padding:35px 28px 24px} .card-mark{font-size:72px} .card-caption{margin:24px 0 0;max-width:250px} .section-heading{display:block} .section-heading p{margin-top:10px} .projects{grid-template-columns:1fr;gap:28px} .project-art{min-height:210px} .about{grid-template-columns:1fr;gap:20px} h2{font-size:32px} footer{flex-direction:column;gap:5px} }\n    @media(prefers-reduced-motion:reduce) { html{scroll-behavior:auto} }\n  </style>\n</head>\n<body>\n  <div class="wrap">\n    <header class="nav"><span class="wordmark">fieldwork.</span><span class="nav-note">Small studio.<br>Thoughtful work.</span></header>\n    <main>\n      <section class="hero" aria-labelledby="intro-heading">\n        <div>\n          <p class="eyebrow">Independent design, with purpose</p>\n          <h1 id="intro-heading">Good ideas.<br><em>Made useful.</em></h1>\n          <p class="intro">We help small teams turn thoughtful ideas into identities, websites, and everyday things people love to use.</p>\n        </div>\n        <aside class="studio-card" aria-label="Our approach"><span class="card-mark" aria-hidden="true">f.</span><p class="card-caption">A little clarity.<br>A considered detail.<br>Something worth putting into the world.</p></aside>\n      </section>\n      <section class="work" aria-labelledby="work-heading">\n        <div class="section-heading"><h2 id="work-heading">A few good beginnings.</h2><p>Identity \xB7 Digital \xB7 Everyday</p></div>\n        <div class="projects">\n          <article class="project"><div class="project-art one" aria-hidden="true"><span>Oat<br>&amp; Ember</span></div><h3>Oat &amp; Ember</h3><p>A warm welcome for a neighborhood bakery.</p></article>\n          <article class="project"><div class="project-art two" aria-hidden="true"><span>slow<br>season</span></div><h3>Slow Season</h3><p>A quieter kind of online home.</p></article>\n          <article class="project"><div class="project-art three" aria-hidden="true"><span>common<br>ground.</span></div><h3>Common Ground</h3><p>Making a shared space feel like yours.</p></article>\n        </div>\n      </section>\n      <section class="about" aria-labelledby="about-heading"><h2 id="about-heading">Small on purpose.</h2><p>You work with the people making the work. We listen closely, ask useful questions, and leave room for the details that make your project yours.</p></section>\n    </main>\n    <footer><span>Fieldwork Studio \xB7 A fictional studio for this shared trial.</span><span>Made with care. Ready for a fresh pair of eyes.</span></footer>\n  </div>\n</body>\n</html>\n';
var TRIAL_SOURCE_HTML = '<!doctype html>\n<html lang="en">\n<head>\n  <meta charset="utf-8">\n  <meta name="viewport" content="width=device-width, initial-scale=1">\n  <meta name="description" content="Fieldwork is a small independent design studio making useful things for thoughtful people.">\n  <title>Fieldwork \u2014 Useful things, thoughtfully made</title>\n  <style>\n    :root { color-scheme: light; --paper:#f6f4ed; --ink:#263c31; --muted:#58685b; --line:#d7dccf; --accent:#d9e7b6; }\n    * { box-sizing:border-box; }\n    html { scroll-behavior:smooth; }\n    body { margin:0; background:var(--paper); color:var(--ink); font:16px/1.65 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }\n    a { color:inherit; text-underline-offset:4px; }\n    a:focus-visible { outline:3px solid var(--ink); outline-offset:5px; }\n    .wrap { width:min(1120px,calc(100% - 80px)); margin:auto; }\n    .nav { display:flex; justify-content:space-between; align-items:center; gap:24px; padding:30px 0; border-bottom:1px solid var(--line); }\n    .wordmark { font-family:Georgia,serif; font-size:30px; font-weight:700; letter-spacing:-1.5px; }\n    .nav-note,.eyebrow { font-size:11px; font-weight:650; letter-spacing:.15em; text-transform:uppercase; }\n    .nav-note { color:var(--muted); }\n    .hero { display:grid; grid-template-columns:1.35fr .8fr; gap:72px; align-items:center; padding:90px 0 84px; }\n    .eyebrow { margin:0 0 22px; color:var(--muted); }\n    h1,h2,h3,p { margin-top:0; }\n    h1,h2 { font-family:Georgia,"Times New Roman",serif; font-weight:400; letter-spacing:-.05em; }\n    h1 { max-width:720px; font-size:clamp(48px,6.2vw,82px); line-height:1.06; margin-bottom:27px; }\n    h1 em { font-weight:400; }\n    .intro { max-width:460px; font-size:17px; color:var(--muted); margin-bottom:28px; }\n    .contact-button { display:inline-flex; align-items:center; justify-content:space-between; gap:35px; min-height:52px; padding:12px 22px; border-radius:4px; background:var(--ink); color:#fff; text-decoration:none; font-size:14px; font-weight:600; }\n    .contact-button:hover { background:#38503f; }\n    .studio-card { position:relative; min-height:345px; display:flex; flex-direction:column; justify-content:space-between; background:var(--accent); border-radius:48% 48% 5px 5px; padding:48px 34px 28px; overflow:hidden; }\n    .studio-card::before { content:""; width:155px; height:155px; border:1px solid #8b9f70; border-radius:50%; position:absolute; top:69px; right:-36px; }\n    .card-mark { font:italic 100px/.95 Georgia,serif; letter-spacing:-9px; }\n    .card-caption { max-width:200px; margin:50px 0 0; font-size:14px; line-height:1.55; }\n    .work { padding:35px 0 70px; border-top:1px solid var(--line); }\n    .section-heading { display:flex; justify-content:space-between; align-items:baseline; gap:24px; margin-bottom:26px; }\n    h2 { font-size:37px; line-height:1.15; margin-bottom:0; }\n    .section-heading p { color:var(--muted); font-size:13px; margin-bottom:0; }\n    .projects { display:grid; grid-template-columns:repeat(3,1fr); gap:22px; }\n    .project { margin:0; }\n    .project-art { min-height:180px; display:flex; align-items:center; justify-content:center; border-radius:4px; margin-bottom:16px; }\n    .project-art span { font:35px/1.1 Georgia,serif; text-align:center; }\n    .project-art.one { background:#e3ddd0; }\n    .project-art.two { background:#dfe6dc; }\n    .project-art.three { background:#e8d8cd; }\n    h3 { margin:0 0 3px; font-size:14px; font-weight:650; }\n    .project p { color:var(--muted); font-size:12px; margin-bottom:0; }\n    .about { display:grid; grid-template-columns:1fr 1.2fr; gap:55px; border-top:1px solid var(--line); padding:40px 0 58px; }\n    .about p { max-width:500px; margin:0; color:var(--muted); }\n    footer { border-top:1px solid var(--line); padding:24px 0 36px; display:flex; justify-content:space-between; gap:18px; font-size:11px; color:var(--muted); }\n    @media(max-width:700px) { .wrap{width:calc(100% - 40px)} .nav{padding:22px 0} .nav-note{max-width:130px;text-align:right;font-size:9px} .hero{grid-template-columns:1fr;gap:36px;padding:52px 0} .intro{font-size:16px} .studio-card{min-height:245px;max-width:390px;width:100%;border-radius:100px 100px 4px 4px;padding:35px 28px 24px} .card-mark{font-size:72px} .card-caption{margin:24px 0 0;max-width:250px} .section-heading{display:block} .section-heading p{margin-top:10px} .projects{grid-template-columns:1fr;gap:28px} .project-art{min-height:210px} .about{grid-template-columns:1fr;gap:20px} h2{font-size:32px} footer{flex-direction:column;gap:5px} }\n    @media(prefers-reduced-motion:reduce) { html{scroll-behavior:auto} }\n  </style>\n</head>\n<body>\n  <div class="wrap">\n    <header class="nav"><span class="wordmark">fieldwork.</span><span class="nav-note">Small studio.<br>Thoughtful work.</span></header>\n    <main>\n      <section class="hero" aria-labelledby="intro-heading">\n        <div>\n          <p class="eyebrow">Independent design, with purpose</p>\n          <h1 id="intro-heading">Good ideas.<br><em>Made useful.</em></h1>\n          <p class="intro">We help small teams turn thoughtful ideas into identities, websites, and everyday things people love to use.</p>\n          <a class="contact-button" href="#contact">Get in touch <span aria-hidden="true">\u2197</span></a>\n        </div>\n        <aside class="studio-card" aria-label="Our approach"><span class="card-mark" aria-hidden="true">f.</span><p class="card-caption">A little clarity.<br>A considered detail.<br>Something worth putting into the world.</p></aside>\n      </section>\n      <section class="work" aria-labelledby="work-heading">\n        <div class="section-heading"><h2 id="work-heading">A few good beginnings.</h2><p>Identity \xB7 Digital \xB7 Everyday</p></div>\n        <div class="projects">\n          <article class="project"><div class="project-art one" aria-hidden="true"><span>Oat<br>&amp; Ember</span></div><h3>Oat &amp; Ember</h3><p>A warm welcome for a neighborhood bakery.</p></article>\n          <article class="project"><div class="project-art two" aria-hidden="true"><span>slow<br>season</span></div><h3>Slow Season</h3><p>A quieter kind of online home.</p></article>\n          <article class="project"><div class="project-art three" aria-hidden="true"><span>common<br>ground.</span></div><h3>Common Ground</h3><p>Making a shared space feel like yours.</p></article>\n        </div>\n      </section>\n      <section class="about" aria-labelledby="about-heading"><h2 id="about-heading">Small on purpose.</h2><p>You work with the people making the work. We listen closely, ask useful questions, and leave room for the details that make your project yours.</p></section>\n    </main>\n    <footer><span>Fieldwork Studio \xB7 A fictional studio for this shared trial.</span><span>Made with care. Ready for a fresh pair of eyes.</span></footer>\n  </div>\n</body>\n</html>\n';
var TRIAL_TEST_SOURCE = `'use strict';
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
  assert.match(html, /<html\\b[^>]*\\blang=["']en["']/i);
  assert.match(html, /<meta\\b[^>]*\\bname=["']viewport["']/i);
  assert.match(html, /<title>[^<]+<\\/title>/i);
  assert.match(html, /<h1\\b[^>]*>[\\s\\S]+?<\\/h1>/i);
  assert.doesNotMatch(html, /<\\s*(?:script|form|iframe|object|embed|base|link|img|video|audio|source|svg)\\b/i, 'No scripts, forms, embedded content, or external assets in this trial.');
  assert.doesNotMatch(html, /\\bon[a-z]+\\s*=|javascript\\s*:|@import\\b|url\\s*\\(/i, 'Keep behavior to native document links and local styles.');
  assert.doesNotMatch(html, /<meta\\b[^>]*http-equiv\\s*=/i, 'No document redirects.');
  for (const match of html.matchAll(/\\bhref\\s*=\\s*(["'])(.*?)\\1/gi)) {
    assert.match(match[2], /^#[A-Za-z][A-Za-z0-9_-]*$/, 'Links in this trial stay within the document.');
  }
});

test('the contact button reaches a useful contact section', () => {
  assert.match(html, /<a\\b[^>]*\\bhref=["']#contact["'][^>]*>[\\s\\S]*?<\\/a>/i, 'Keep the contact button as a native link to #contact.');
  const section = html.match(/<section\\b[^>]*\\bid=["']contact["'][^>]*>([\\s\\S]*?)<\\/section>/i);
  assert.ok(section, 'The contact link needs a matching contact section.');
  assert.match(section[1], /<h[2-3]\\b[^>]*>[^<]+<\\/h[2-3]>/i, 'Give the contact section a visible heading.');
  const text = section[1].replace(/<[^>]*>/g, ' ').replace(/\\s+/g, ' ').trim();
  assert.ok(text.length >= 40, 'Include useful contact information or a clear next step.');
  assert.match(text, /contact|touch|hello|write|email|conversation/i, 'Make the next step understandable.');
  assert.equal([...html.matchAll(/\\bid\\s*=\\s*["']contact["']/gi)].length, 1, 'Use one unambiguous contact destination.');
  assert.doesNotMatch(section[0], /\\bhidden(?:\\s|=|>)|aria-hidden\\s*=\\s*["']true["']/i, 'The destination must be visible.');
});
`;
var TRIAL_BUILD_SOURCE = "'use strict';\nconst fs = require('node:fs');\nconst path = require('node:path');\nconst root = path.resolve(__dirname, '..');\nconst source = path.join(root, 'site', 'index.html');\nconst stat = fs.lstatSync(source);\nif (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536) throw new Error('Expected one regular HTML file no larger than 64 KiB.');\nconst output = path.join(root, 'dist');\nif (fs.existsSync(output)) {\n  const outStat = fs.lstatSync(output);\n  if (!outStat.isDirectory() || outStat.isSymbolicLink()) throw new Error('Build output must be a regular directory.');\n  fs.rmSync(output, { recursive: true });\n}\nfs.mkdirSync(output);\nfs.copyFileSync(source, path.join(output, 'index.html'));\nprocess.stdout.write('Built dist/index.html from site/index.html.\\n');\n";

// src/coordination-repository-trial.ts
var REPOSITORY_TRIAL_ACTIONS = ["repository_trial_info", "repository_trial_create", "repository_trial_get", "repository_trial_bind", "repository_trial_dispatch", "repository_trial_poll", "repository_trial_complete"];
var TRIAL_REPOSITORY = "ScopeBlind/scopeblind-repository-demo";
var TRIAL_WORKFLOW = ".github/workflows/scopeblind-trial.yml";
var TRIAL_TEMPLATE = "styled-contact-v1";
var TRIAL_SOURCE_CHECK = { name: "ScopeBlind trial source safety", app_id: 15368 };
var TRIAL_CODING_CHECK = { name: "ScopeBlind isolated coding checks", app_id: 15368 };
var TRIAL_LIMITS = { max_jobs: 1, max_attempts: 2, max_model_calls: 8, max_tokens: 98304, max_seconds: 600, max_changed_files: 2, max_changed_bytes: 32768 };
var TRIAL_DOCKER_IMAGE = "node@sha256:e21fc383b50d5347dc7a9f1cae45b8f4e2f0d39f7ade28e4eef7d2934522b752";
var trialBase = (id2) => `scopeblind/trial/${id2}/base`;
var trialSource = (id2) => `scopeblind/trial/${id2}/source`;
var object = (v) => !!v && typeof v === "object" && !Array.isArray(v);
var exact = (v, keys) => Object.keys(v).length === keys.length && keys.every((k) => Object.hasOwn(v, k));
var key = (v) => typeof v === "string" && REPOSITORY_HEX.test(v);
var id = (v) => typeof v === "string" && REPOSITORY_ID.test(v);
var sha = (v) => typeof v === "string" && REPOSITORY_SHA.test(v);
var at = (v) => typeof v === "string" && Number.isFinite(Date.parse(v)) && new Date(v).toISOString() === v;
function validRepositoryTrialRequest(v) {
  return object(v) && exact(v, ["type", "id", "owner_key", "authority_key", "title", "template", "reviewer_secret_hash", "issued_at", "expires_at"]) && v.type === "scopeblind.repository.trial-request.v1" && id(v.id) && key(v.owner_key) && key(v.authority_key) && v.owner_key !== v.authority_key && key(v.reviewer_secret_hash) && v.template === TRIAL_TEMPLATE && typeof v.title === "string" && v.title.trim().length > 0 && v.title.length <= 100 && !/[\u0000-\u001f\u007f]/.test(v.title) && at(v.issued_at) && at(v.expires_at) && Date.parse(String(v.expires_at)) > Date.parse(String(v.issued_at)) && Date.parse(String(v.expires_at)) - Date.parse(String(v.issued_at)) <= 864e5;
}
function validRepositoryTrialProvision(v) {
  return object(v) && exact(v, ["type", "trial_id", "request_digest", "receiver_key", "repository", "template_sha", "base_branch", "source_branch", "base_sha", "source_sha", "pull_number", "before", "source", "source_check", "observed_at"]) && v.type === "scopeblind.repository.trial-provision.v1" && id(v.trial_id) && [v.request_digest, v.receiver_key].every(key) && v.repository === TRIAL_REPOSITORY && [v.template_sha, v.base_sha, v.source_sha].every(sha) && v.base_branch === trialBase(String(v.trial_id)) && v.source_branch === trialSource(String(v.trial_id)) && Number.isSafeInteger(v.pull_number) && Number(v.pull_number) > 0 && [v.before, v.source].every((h) => object(h) && exact(h, ["html", "sha256", "blob_sha"]) && typeof h.html === "string" && new TextEncoder().encode(h.html).length <= 32768 && key(h.sha256) && sha(h.blob_sha)) && object(v.source_check) && exact(v.source_check, ["id", "name", "app_id", "head_sha", "conclusion"]) && Number.isSafeInteger(v.source_check.id) && Number(v.source_check.id) > 0 && v.source_check.name === TRIAL_SOURCE_CHECK.name && v.source_check.app_id === 15368 && v.source_check.head_sha === v.source_sha && v.source_check.conclusion === "success" && at(v.observed_at);
}
async function verifyRepositoryTrialState(value, authority) {
  try {
    if (!validRepositoryEnvelope(value)) return false;
    const signed = value, s = signed.payload, r = s?.request;
    if (!object(s) || !exact(s, ["type", "request", "provision", "workspace", "invitation", "config", "receiver_key", "readiness", "status", "dispatch_status", "jobs", "observed_at"]) || s.type !== "scopeblind.repository.trial-state.v1" || !validRepositoryTrialRequest(r?.payload) || r.payload.authority_key !== authority || !await verify(r, r.payload.owner_key) || !await verify(signed, authority) || !at(s.observed_at) || !key(s.config.worker_key) || !key(s.receiver_key) || (/* @__PURE__ */ new Set([authority, r.payload.owner_key, s.receiver_key, s.config.worker_key])).size !== 4 || canonical(s.config) !== canonical(trialCodingConfig(r.payload.id, s.config.endpoint, authority, s.config.worker_key))) return false;
    const endpoint = new URL(s.config.endpoint);
    if (endpoint.protocol !== "https:" || endpoint.pathname !== "/api/coordination" || endpoint.username || endpoint.password || endpoint.hash || endpoint.search) return false;
    if (s.provision) {
      const p = s.provision.payload;
      if (!validRepositoryEnvelope(s.provision) || !validRepositoryTrialProvision(p) || p.trial_id !== r.payload.id || p.request_digest !== r.digest || p.receiver_key !== s.receiver_key || p.base_sha !== p.template_sha || p.source_sha === p.base_sha || p.before.html !== TRIAL_BEFORE_HTML || p.source.html !== TRIAL_SOURCE_HTML || Date.parse(p.observed_at) > Date.parse(s.observed_at) || !await verify(s.provision, p.receiver_key)) return false;
      for (const h of [p.before, p.source]) {
        if (await sha256(h.html) !== h.sha256) return false;
        const bytes = new TextEncoder().encode(h.html), prefix = new TextEncoder().encode(`blob ${bytes.length}\0`), raw = new Uint8Array(prefix.length + bytes.length);
        raw.set(prefix);
        raw.set(bytes, prefix.length);
        const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-1", raw))).map((n) => n.toString(16).padStart(2, "0")).join("");
        if (hash !== h.blob_sha) return false;
      }
    }
    if (s.workspace === null !== (s.invitation === null)) return false;
    if (s.workspace) {
      const w = s.workspace.payload;
      if (!validRepositoryEnvelope(s.workspace) || !validRepositoryWorkspace(w) || !await verify(s.workspace, r.payload.owner_key) || w.repository !== TRIAL_REPOSITORY || w.base_branch !== trialBase(r.payload.id) || w.authority_key !== authority || w.receiver_key !== s.provision?.payload.receiver_key || w.owner_key !== r.payload.owner_key || Date.parse(w.expires_at) > Date.parse(r.payload.expires_at)) return false;
    }
    if (s.invitation) {
      const i = s.invitation.payload;
      if (!s.workspace || !validWorkspaceInvitation(i) || i.workspace_id !== s.workspace.payload.id || i.workspace_digest !== s.workspace.digest || i.role !== "reviewer" || i.issuer_key !== r.payload.owner_key || i.secret_hash !== r.payload.reviewer_secret_hash || !await verify(s.invitation, r.payload.owner_key)) return false;
    }
    if (s.readiness && (!validRepositoryEnvelope(s.readiness) || !validTrialReadiness(s.readiness.payload) || !await verify(s.readiness, authority) || s.readiness.payload.worker_key !== s.config.worker_key || s.readiness.payload.receiver_key !== s.receiver_key || Date.parse(s.readiness.payload.observed_at) > Date.parse(s.observed_at))) return false;
    return Array.isArray(s.jobs) && s.jobs.length <= 30 && new Set(s.jobs.map((j) => j.id)).size === s.jobs.length && s.jobs.every((j) => object(j) && exact(j, ["id", "kind", "target_id", "status", "attempts", "error", "updated_at"]) && id(j.id) && ["provision", "inspect", "execute", "reconcile", "coding", "coding_reconcile", "coding_ready"].includes(j.kind) && (j.kind === "provision" ? j.target_id === null : id(j.target_id)) && ["queued", "leased", "complete", "failed", "unknown"].includes(j.status) && Number.isInteger(j.attempts) && j.attempts >= 0 && j.attempts <= 3 && (j.error === null || typeof j.error === "string" && /^[a-z0-9_]{3,100}$/.test(j.error)) && at(j.updated_at) && Date.parse(j.updated_at) <= Date.parse(s.observed_at)) && ["queued", "provisioning", "ready", "active", "expired", "failed", "unknown"].includes(s.status) && ["requested", "unconfigured", "unavailable"].includes(s.dispatch_status);
  } catch {
    return false;
  }
}
function trialCodingConfig(id2, endpoint, authority, worker) {
  return { type: "scopeblind.repository.coding-config.v1", endpoint, authority_key: authority, worker_key: worker, repository: TRIAL_REPOSITORY, base_branch: trialBase(id2), runtime: "node22-static-v1", docker_image: TRIAL_DOCKER_IMAGE, test_command: ["node", "--test", "tests/contact.test.cjs"], build_command: ["node", "tools/build.cjs"], preview_directory: "dist" };
}
function validTrialReadiness(value) {
  if (!object(value) || !exact(value, ["type", "receiver_key", "worker_key", "repository", "proof", "observed_at", "expires_at"])) return false;
  const r = value, p = r.proof;
  return r.type === "scopeblind.repository.trial-readiness.v1" && r.repository === TRIAL_REPOSITORY && key(r.receiver_key) && key(r.worker_key) && r.receiver_key !== r.worker_key && at(r.observed_at) && at(r.expires_at) && Date.parse(String(r.expires_at)) > Date.parse(String(r.observed_at)) && Date.parse(String(r.expires_at)) - Date.parse(String(r.observed_at)) <= 864e5 && object(p) && exact(p, ["repository_id", "run_id", "run_attempt", "workflow_ref", "workflow_sha", "token_digest", "verified_at"]) && p.workflow_ref === `${TRIAL_REPOSITORY}/${TRIAL_WORKFLOW}@refs/heads/main` && sha(p.workflow_sha) && key(p.token_digest) && [p.repository_id, p.run_id, p.run_attempt].every((n) => Number.isSafeInteger(n) && Number(n) > 0) && at(p.verified_at) && Date.parse(String(p.verified_at)) <= Date.parse(String(r.observed_at));
}
async function verifyRepositoryTrialConnection(value, authority) {
  try {
    const c = value, r = c?.readiness?.payload;
    if (!c || c.kind !== "managed_trial" || !id(c.setup_id) || !r || !validTrialReadiness(r) || r.type !== "scopeblind.repository.trial-readiness.v1" || r.repository !== TRIAL_REPOSITORY || !key(r.receiver_key) || r.worker_key !== c.config.worker_key || r.receiver_key === r.worker_key || canonical(c.config) !== canonical(trialCodingConfig(c.setup_id, c.config.endpoint, authority, r.worker_key)) || !await verify(c.readiness, authority) || !at(r.observed_at) || !at(r.expires_at) || Date.parse(r.expires_at) <= Date.now() || Date.parse(r.expires_at) - Date.parse(r.observed_at) > 864e5 || Date.parse(r.observed_at) > Date.now() + 1e3) return false;
    const u = new URL(c.config.endpoint), p = r.proof;
    return u.protocol === "https:" && u.pathname === "/api/coordination" && !u.search && !u.hash && !u.username && !u.password && p.workflow_ref === `${TRIAL_REPOSITORY}/${TRIAL_WORKFLOW}@refs/heads/main` && sha(p.workflow_sha) && key(p.token_digest) && Number.isSafeInteger(p.repository_id) && p.repository_id > 0 && Number.isSafeInteger(p.run_id) && p.run_id > 0 && Number.isSafeInteger(p.run_attempt) && p.run_attempt > 0 && at(p.verified_at);
  } catch {
    return false;
  }
}

// src/repository-trial-runner.ts
function need(ok, code) {
  if (!ok) throw Error(code);
}
async function json(response, max = 4e6) {
  const reader = response.body?.getReader();
  need(reader, "trial_response_empty");
  const parts = [];
  let size = 0;
  try {
    for (; ; ) {
      const p = await reader.read();
      if (p.done) break;
      size += p.value.length;
      need(size <= max, "trial_response_limit");
      parts.push(p.value);
    }
  } finally {
    await reader.cancel().catch(() => {
    });
  }
  return JSON.parse(Buffer.concat(parts).toString("utf8"));
}
var RepositoryTrialRunner = class {
  constructor(config, receiver, worker, token, run, fetcher = fetch, sandboxFactory) {
    this.config = config;
    this.receiver = receiver;
    this.worker = worker;
    this.token = token;
    this.run = run;
    this.fetcher = fetcher;
    this.sandboxFactory = sandboxFactory;
    const u = new URL(config.endpoint);
    need(u.protocol === "https:" && u.pathname === "/api/coordination" && !u.username && !u.password && !u.search && !u.hash, "trial_endpoint_invalid");
    need([config.authority_key, config.receiver_key, config.worker_key].every((k) => REPOSITORY_HEX.test(k)) && (/* @__PURE__ */ new Set([config.authority_key, config.receiver_key, config.worker_key])).size === 3 && receiver.publicKey === config.receiver_key && worker.publicKey === config.worker_key && REPOSITORY_SHA.test(config.template_sha) && REPOSITORY_SHA.test(config.workflow_sha) && run.workflow_sha === config.workflow_sha && run.workflow_ref === `${TRIAL_REPOSITORY}/${TRIAL_WORKFLOW}@refs/heads/main` && token, "trial_runner_pins_invalid");
  }
  async rpc(action, id2, body, identity = this.receiver) {
    const request = await sign(makeRequest(action, id2, body), identity), r = await this.fetcher(this.config.endpoint, { method: "POST", headers: { "content-type": "application/json", "x-scopeblind-action": action }, body: JSON.stringify({ request }), redirect: "error", signal: AbortSignal.timeout(55e3) }), value = await json(r);
    need(r.ok && value.ok === true, typeof value.error === "string" ? value.error : "trial_service_refused");
    return value;
  }
  async github(path, init = {}, missing = false) {
    const r = await this.fetcher("https://api.github.com" + path, { ...init, headers: { authorization: "Bearer " + this.token, accept: "application/vnd.github+json", "content-type": "application/json", "x-github-api-version": "2026-03-10" }, redirect: "error", signal: AbortSignal.timeout(2e4) });
    if (missing && r.status === 404) {
      await r.body?.cancel();
      return null;
    }
    const value = await json(r);
    need(r.ok, "trial_github_" + r.status);
    return value;
  }
  get repo() {
    return "/repos/" + TRIAL_REPOSITORY;
  }
  async ref(branch) {
    return (await this.github(this.repo + "/git/ref/heads/" + encodeURIComponent(branch), {}, true))?.object?.sha ?? null;
  }
  async blob(path, sha2) {
    const file = await this.github(this.repo + "/contents/" + path + "?ref=" + sha2);
    need(file.type === "file" && file.encoding === "base64" && file.size <= 65536, "trial_file_invalid");
    const b = Buffer.from(file.content, "base64");
    need(b.length === file.size && gitBlob(b) === file.sha, "trial_blob_mismatch");
    return { bytes: b, sha: file.sha };
  }
  async ensureRef(branch, sha2) {
    const old = await this.ref(branch);
    if (old) {
      need(old === sha2, "trial_ref_conflict");
      return;
    }
    try {
      await this.github(this.repo + "/git/refs", { method: "POST", body: JSON.stringify({ ref: "refs/heads/" + branch, sha: sha2 }) });
    } catch (error) {
      if (await this.ref(branch) !== sha2) throw error;
    }
    need(await this.ref(branch) === sha2, "trial_ref_readback_mismatch");
  }
  async checked(value, lease) {
    need(value && await verify(value, this.config.authority_key), "trial_job_signature_invalid");
    const j = value.payload, r = j.request?.payload;
    need(j.type === "scopeblind.repository.trial-job.v1" && validRepositoryTrialRequest(r) && r.authority_key === this.config.authority_key && await verify(j.request, r.owner_key) && j.lease_id === lease && Date.parse(j.lease_expires_at) > Date.now() && j.receiver_key === this.receiver.publicKey && j.template_sha === this.config.template_sha && canonical(j.config) === canonical(trialCodingConfig(r.id, this.config.endpoint, this.config.authority_key, this.worker.publicKey)) && j.proof.workflow_sha === this.config.workflow_sha && j.proof.workflow_ref === this.run.workflow_ref && j.proof.run_id === this.run.run_id && j.proof.run_attempt === this.run.run_attempt, "trial_job_scope_mismatch");
    need(j.kind === "reconcile" || j.kind === "coding_reconcile" || Date.parse(r.expires_at) > Date.now(), "trial_expired");
    if (j.workspace) {
      need(await verifyRepositoryWorkspaceState(j.workspace, this.config.authority_key), "trial_workspace_invalid");
      const w = j.workspace.payload.workspace.payload;
      need(w.owner_key === r.owner_key && w.repository === TRIAL_REPOSITORY && w.base_branch === trialBase(r.id) && w.receiver_key === this.receiver.publicKey, "trial_workspace_mismatch");
    }
    if (j.provision) need(validRepositoryTrialProvision(j.provision.payload) && await verify(j.provision, this.receiver.publicKey) && j.provision.payload.request_digest === j.request.digest && j.provision.payload.trial_id === r.id, "trial_provision_invalid");
    return j;
  }
  async provision(j) {
    const r = j.request.payload;
    need(j.kind === "provision" && !j.target_id, "trial_provision_scope_mismatch");
    const template = await this.github(this.repo + "/git/commits/" + this.config.template_sha);
    need(template.sha === this.config.template_sha && REPOSITORY_SHA.test(template.tree?.sha), "trial_template_invalid");
    for (const [path, expected] of [["site/index.html", TRIAL_BEFORE_HTML], ["tests/contact.test.cjs", TRIAL_TEST_SOURCE], ["tools/build.cjs", TRIAL_BUILD_SOURCE]]) need((await this.blob(path, this.config.template_sha)).bytes.toString("utf8") === expected, "trial_template_bytes_changed");
    const baseBranch = trialBase(r.id), sourceBranch = trialSource(r.id);
    await this.ensureRef(baseBranch, this.config.template_sha);
    const tree = await this.github(this.repo + "/git/trees", { method: "POST", body: JSON.stringify({ base_tree: template.tree.sha, tree: [{ path: "site/index.html", mode: "100644", type: "blob", content: TRIAL_SOURCE_HTML }] }) });
    need(REPOSITORY_SHA.test(tree.sha), "trial_tree_invalid");
    const person = { name: "ScopeBlind Trial", email: "trial@scopeblind.com", date: new Date(Math.floor(Date.parse(r.issued_at) / 1e3) * 1e3).toISOString() }, commit = await this.github(this.repo + "/git/commits", { method: "POST", body: JSON.stringify({ message: "Unfinished managed trial " + r.id, tree: tree.sha, parents: [this.config.template_sha], author: person, committer: person }) });
    need(REPOSITORY_SHA.test(commit.sha) && commit.tree?.sha === tree.sha && commit.parents?.length === 1 && commit.parents[0].sha === this.config.template_sha, "trial_commit_invalid");
    await this.ensureRef(sourceBranch, commit.sha);
    need((await this.blob("site/index.html", commit.sha)).bytes.toString("utf8") === TRIAL_SOURCE_HTML, "trial_source_bytes_changed");
    let pulls = await this.github(this.repo + "/pulls?state=all&head=" + encodeURIComponent("ScopeBlind:" + sourceBranch) + "&base=" + encodeURIComponent(baseBranch) + "&per_page=100");
    need(Array.isArray(pulls) && pulls.length <= 1, "trial_pull_ambiguous");
    let pull = pulls[0];
    if (!pull) {
      try {
        pull = await this.github(this.repo + "/pulls", { method: "POST", body: JSON.stringify({ title: r.title, head: sourceBranch, base: baseBranch, draft: false, body: "Disposable styled starter for a shared AI coding trial. This initial change is deterministic and intentionally unfinished. A separate signed coding mandate and later exact review are required." }) });
      } catch (error) {
        pulls = await this.github(this.repo + "/pulls?state=all&head=" + encodeURIComponent("ScopeBlind:" + sourceBranch) + "&base=" + encodeURIComponent(baseBranch) + "&per_page=100");
        if (!Array.isArray(pulls) || pulls.length !== 1) throw error;
        pull = pulls[0];
      }
    }
    need(pull.state === "open" && !pull.draft && pull.head?.sha === commit.sha && pull.head?.ref === sourceBranch && pull.base?.ref === baseBranch && pull.base?.repo?.full_name === TRIAL_REPOSITORY && pull.head?.repo?.full_name === TRIAL_REPOSITORY, "trial_pull_mismatch");
    const checkRows = await this.github(this.repo + "/commits/" + commit.sha + "/check-runs?per_page=100&filter=latest");
    let check = checkRows.check_runs?.find((c) => c.name === TRIAL_SOURCE_CHECK.name && c.app?.id === 15368 && c.head_sha === commit.sha && c.conclusion === "success");
    if (!check) {
      need(TRIAL_SOURCE_HTML.includes('href="#contact"') && !/\bid=["']contact["']/.test(TRIAL_SOURCE_HTML) && !/<script\b|<form\b|@import\b|url\s*\(/i.test(TRIAL_SOURCE_HTML), "trial_source_safety_failed");
      check = await this.github(this.repo + "/check-runs", { method: "POST", body: JSON.stringify({ name: TRIAL_SOURCE_CHECK.name, head_sha: commit.sha, status: "completed", conclusion: "success", output: { title: "Reviewed starter bytes match", summary: "The exact fixed static starter and immutable test/build definitions were checked. The contact destination is intentionally absent; improvement tests have not passed and no AI repair is claimed." } }) });
    }
    need(check.app?.id === 15368 && check.head_sha === commit.sha && check.conclusion === "success", "trial_source_check_invalid");
    const html = async (value) => ({ html: value, sha256: await sha256(value), blob_sha: gitBlob(Buffer.from(value)) });
    return sign({ type: "scopeblind.repository.trial-provision.v1", trial_id: r.id, request_digest: j.request.digest, receiver_key: this.receiver.publicKey, repository: TRIAL_REPOSITORY, template_sha: this.config.template_sha, base_branch: baseBranch, source_branch: sourceBranch, base_sha: this.config.template_sha, source_sha: commit.sha, pull_number: pull.number, before: await html(TRIAL_BEFORE_HTML), source: await html(TRIAL_SOURCE_HTML), source_check: { id: check.id, name: TRIAL_SOURCE_CHECK.name, app_id: 15368, head_sha: commit.sha, conclusion: "success" }, observed_at: (/* @__PURE__ */ new Date()).toISOString() }, this.receiver);
  }
  async receive(j) {
    need(j.workspace && j.assignment && j.task && j.provision && j.target_id === j.task.payload.task.payload.id, "trial_task_required");
    need((await verifyRepositoryEvidence({ type: "scopeblind.repository.evidence.v1", state: j.task }, this.config.authority_key)).valid, "trial_task_invalid");
    const w = j.workspace.payload, a = j.assignment.payload, t = j.task.payload.task.payload, r = j.request.payload;
    need(await verify(j.assignment, r.owner_key) && a.workspace_id === w.workspace.payload.id && a.workspace_digest === w.workspace.digest && a.task_digest === j.task.payload.task.digest && a.owner_key === r.owner_key && a.reviewer_key === j.task.payload.reviewer?.payload.reviewer_key && w.assignments.some((x) => x.digest === j.assignment.digest), "trial_assignment_invalid");
    if (j.kind !== "reconcile") for (const [memberId, key2, revision, role] of [[a.owner_member_id, a.owner_key, a.owner_member_revision, "owner"], [a.reviewer_member_id, a.reviewer_key, a.reviewer_member_revision, "reviewer"]]) need(w.members.some((m) => m.member_id === memberId && m.current_key === key2 && m.revision === revision && m.role === role && m.status === "active"), "trial_membership_changed");
    need(t.repository === TRIAL_REPOSITORY && t.base_branch === trialBase(r.id) && t.owner_key === r.owner_key && t.receiver_key === this.receiver.publicKey && canonical(t.allowed_paths) === canonical(["site/**"]), "trial_task_scope_mismatch");
    const source = t.pull_number === j.provision.payload.pull_number;
    need(canonical(t.required_checks) === canonical([source ? TRIAL_SOURCE_CHECK : TRIAL_CODING_CHECK]), "trial_checks_mismatch");
    if (!source) need(j.coding && (await verifyRepositoryCodingEvidence({ type: "scopeblind.repository.coding-evidence.v1", job: j.coding }, this.config.authority_key)).published && j.coding.payload.request.payload.workspace_id === w.workspace.payload.id && j.coding.payload.result.payload.pull_number === t.pull_number, "trial_child_origin_invalid");
    need(j.kind !== "execute" || !source, "trial_source_effect_refused");
    const receiver = new RepositoryReceiver({ type: "scopeblind.repository.receiver-config.v1", endpoint: this.config.endpoint, authority_key: this.config.authority_key, owner_key: r.owner_key, reviewer_key: a.reviewer_key, receiver_key: this.receiver.publicKey, repository: TRIAL_REPOSITORY, base_branch: trialBase(r.id) }, this.receiver, this.token, this.fetcher);
    if (j.kind === "inspect") await receiver.inspect(t.id);
    else if (j.kind === "execute") await receiver.execute(t.id);
    else await receiver.reconcile(t.id);
  }
  async refreshReady(j, resultDigest) {
    const audience = "https://scopeblind.com/repository-trial/" + j.lease_id, oidc_token = await this.run.oidc(audience), response = (await this.rpc("repository_trial_poll", "repository-trial", { lease_id: j.lease_id, run_id: this.run.run_id, run_attempt: this.run.run_attempt, oidc_token, refresh_only: true })).poll;
    need(response && await verify(response, this.config.authority_key) && response.payload.lease_id === j.lease_id && response.payload.job, "trial_ready_lease_required");
    const current = await this.checked(response.payload.job, j.lease_id), c = current.coding, w = current.workspace?.payload, m = c?.payload.mandate.payload;
    need(current.id === j.id && current.kind === j.kind && current.target_id === j.target_id && c?.payload.result?.digest === resultDigest && c.payload.stop === null && w && m && Date.parse(m.expires_at) > Date.now() && Date.parse(current.request.payload.expires_at) > Date.now() && Math.abs(Date.now() - Date.parse(current.observed_at)) <= 3e4, "trial_coding_ready_authority_inactive");
    for (const [memberId, key2, revision, role] of [[m.owner_member_id, m.owner_key, m.owner_member_revision, "owner"], [m.reviewer_member_id, m.reviewer_key, m.reviewer_member_revision, "reviewer"]]) need(w.members.some((x) => x.member_id === memberId && x.current_key === key2 && x.revision === revision && x.role === role && x.status === "active"), "trial_coding_ready_authority_inactive");
  }
  async coding(j) {
    need(j.coding && j.workspace && j.target_id === j.coding.payload.request.payload.id && (await verifyRepositoryCodingEvidence({ type: "scopeblind.repository.coding-evidence.v1", job: j.coding }, this.config.authority_key)).valid && j.coding.payload.request.payload.workspace_id === j.workspace.payload.workspace.payload.id, "trial_coding_scope_mismatch");
    const m = j.coding.payload.mandate.payload;
    need(m.owner_key === j.request.payload.owner_key && m.repository === TRIAL_REPOSITORY && m.base_branch === trialBase(j.request.payload.id) && m.worker_key === this.worker.publicKey && canonical(m.allowed_paths) === canonical(["site/**"]) && canonical(m.required_checks) === canonical([TRIAL_CODING_CHECK]) && Object.entries(TRIAL_LIMITS).every(([k, v]) => m[k] <= v), "trial_coding_limits_mismatch");
    need(!["coding_reconcile", "coding_ready"].includes(j.kind) || j.coding.payload.publication, "trial_coding_publication_required");
    if (j.kind === "coding_ready") need(j.coding.payload.result, "trial_coding_result_required");
    else if (!j.coding.payload.result) {
      const runner = new RepositoryCodingRunner(j.config, this.worker, this.token, this.fetcher, this.sandboxFactory);
      await runner.runOne(j.target_id);
    }
    const current = (await this.rpc("repository_coding_get", m.workspace_id, { job_id: j.target_id }, this.worker)).job;
    need((await verifyRepositoryCodingEvidence({ type: "scopeblind.repository.coding-evidence.v1", job: current }, this.config.authority_key)).published, "trial_coding_not_published");
    const result = current.payload.result.payload, pull = await this.github(this.repo + "/pulls/" + result.pull_number);
    need(pull.head?.sha === result.head_sha && pull.head?.ref === result.branch && pull.base?.ref === trialBase(j.request.payload.id) && pull.base?.sha === current.payload.plan.payload.source_base_sha && await this.ref(trialBase(j.request.payload.id)) === current.payload.plan.payload.source_base_sha && pull.state === "open" && pull.base?.repo?.full_name === TRIAL_REPOSITORY && pull.head?.repo?.full_name === TRIAL_REPOSITORY, "trial_coding_pull_changed");
    if (pull.draft) {
      need(j.kind !== "coding_reconcile", "trial_coding_ready_required");
      need(typeof pull.node_id === "string", "trial_pull_node_missing");
      await this.refreshReady(j, current.payload.result.digest);
      const marked = await this.github("/graphql", { method: "POST", body: JSON.stringify({ query: "mutation($id:ID!){markPullRequestReadyForReview(input:{pullRequestId:$id}){pullRequest{id isDraft}}}", variables: { id: pull.node_id } }) });
      need(!marked.errors?.length && marked.data?.markPullRequestReadyForReview?.pullRequest?.id === pull.node_id && marked.data.markPullRequestReadyForReview.pullRequest.isDraft === false, "trial_ready_readback_required");
    }
    const after = await this.github(this.repo + "/pulls/" + result.pull_number);
    need(after.draft === false && after.head?.sha === result.head_sha && after.base?.ref === trialBase(j.request.payload.id) && after.base?.sha === current.payload.plan.payload.source_base_sha && await this.ref(trialBase(j.request.payload.id)) === current.payload.plan.payload.source_base_sha, "trial_ready_readback_required");
  }
  async runOne() {
    const lease = crypto.randomUUID(), initial = (await this.rpc("repository_trial_poll", "repository-trial", { lease_id: lease })).poll;
    need(initial && await verify(initial, this.config.authority_key) && initial.payload.lease_id === lease && initial.payload.challenge.audience === "https://scopeblind.com/repository-trial/" + lease, "trial_challenge_invalid");
    const token = await this.run.oidc(initial.payload.challenge.audience), response = (await this.rpc("repository_trial_poll", "repository-trial", { lease_id: lease, run_id: this.run.run_id, run_attempt: this.run.run_attempt, oidc_token: token })).poll;
    need(response && await verify(response, this.config.authority_key) && response.payload.lease_id === lease, "trial_poll_invalid");
    if (!response.payload.job) return false;
    const j = await this.checked(response.payload.job, lease);
    let provision = null, error = null;
    try {
      if (j.kind === "provision") provision = await this.provision(j);
      else if (j.kind === "coding" || j.kind === "coding_reconcile" || j.kind === "coding_ready") await this.coding(j);
      else await this.receive(j);
    } catch (e) {
      error = e instanceof Error && /^[a-z0-9_]{3,100}$/.test(e.message) ? e.message : "trial_runner_interrupted";
    }
    const completion = await sign({ type: "scopeblind.repository.trial-completion.v1", job_id: j.id, trial_id: j.request.payload.id, request_digest: j.request.digest, lease_id: lease, receiver_key: this.receiver.publicKey, kind: j.kind, provision, error, observed_at: (/* @__PURE__ */ new Date()).toISOString() }, this.receiver);
    await this.rpc("repository_trial_complete", "repository-trial", { completion });
    if (error) throw Error(error);
    return true;
  }
};
async function runRepositoryTrial() {
  const e = process.env;
  need(e.GITHUB_ACTIONS === "true" && e.GITHUB_REPOSITORY === TRIAL_REPOSITORY && e.GITHUB_REF === "refs/heads/main" && e.GITHUB_EVENT_NAME === "workflow_dispatch", "trial_trusted_workflow_required");
  const config = JSON.parse(e.SCOPEBLIND_TRIAL_CONFIG || "null");
  need(config && e.SCOPEBLIND_TRIAL_RECEIVER_KEY && e.SCOPEBLIND_TRIAL_WORKER_KEY && e.GITHUB_TOKEN && e.ACTIONS_ID_TOKEN_REQUEST_URL && e.ACTIONS_ID_TOKEN_REQUEST_TOKEN, "trial_configuration_required");
  const run = { run_id: Number(e.GITHUB_RUN_ID), run_attempt: Number(e.GITHUB_RUN_ATTEMPT), workflow_ref: e.GITHUB_WORKFLOW_REF, workflow_sha: e.GITHUB_WORKFLOW_SHA, oidc: async (audience) => {
    const u = new URL(e.ACTIONS_ID_TOKEN_REQUEST_URL);
    need(u.protocol === "https:" && u.hostname.endsWith(".actions.githubusercontent.com") && !u.username && !u.password, "trial_oidc_endpoint_invalid");
    u.searchParams.set("audience", audience);
    const r = await fetch(u, { headers: { authorization: "Bearer " + e.ACTIONS_ID_TOKEN_REQUEST_TOKEN }, redirect: "error", signal: AbortSignal.timeout(2e4) }), v = await json(r, 4e4);
    need(r.ok && typeof v.value === "string", "trial_oidc_unavailable");
    return v.value;
  } };
  const runner = new RepositoryTrialRunner(config, await importIdentity(e.SCOPEBLIND_TRIAL_RECEIVER_KEY, config.receiver_key), await importIdentity(e.SCOPEBLIND_TRIAL_WORKER_KEY, config.worker_key), e.GITHUB_TOKEN, run);
  const leaseUntil = Date.now() + 30 * 6e4;
  for (let count = 0; count < 6 && Date.now() < leaseUntil; count++) if (!await runner.runOne()) break;
  process.stdout.write("The managed trial controller finished its bounded queue pass.\n");
}

export {
  REPOSITORY_TRIAL_ACTIONS,
  TRIAL_REPOSITORY,
  TRIAL_WORKFLOW,
  TRIAL_TEMPLATE,
  TRIAL_SOURCE_CHECK,
  TRIAL_CODING_CHECK,
  TRIAL_LIMITS,
  TRIAL_DOCKER_IMAGE,
  trialBase,
  trialSource,
  validRepositoryTrialRequest,
  validRepositoryTrialProvision,
  verifyRepositoryTrialState,
  trialCodingConfig,
  validTrialReadiness,
  verifyRepositoryTrialConnection,
  RepositoryTrialRunner,
  runRepositoryTrial
};
