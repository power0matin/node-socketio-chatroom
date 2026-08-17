'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { execFileSync } = require('child_process');
const { compile } = require('@vue/compiler-dom');

const root = path.resolve(__dirname, '..');
const publicDir = path.join(root, 'public');
const vendorDir = path.join(publicDir, 'vendor');
const assetsDir = path.join(publicDir, 'assets');

async function copyFile(from, to) {
  await fsp.mkdir(path.dirname(to), { recursive: true });
  await fsp.copyFile(from, to);
}

async function copyDirectory(from, to) {
  await fsp.mkdir(to, { recursive: true });
  for (const entry of await fsp.readdir(from, { withFileTypes: true })) {
    const src = path.join(from, entry.name);
    const dst = path.join(to, entry.name);
    if (entry.isDirectory()) await copyDirectory(src, dst);
    else if (entry.isFile()) await copyFile(src, dst);
  }
}

function findTagEnd(html, start) {
  let quote = '';
  for (let i = start; i < html.length; i += 1) {
    const ch = html[i];
    if (quote) {
      if (ch === quote && html[i - 1] !== '\\') quote = '';
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; continue; }
    if (ch === '>') return i;
  }
  throw new Error('Unterminated HTML tag while extracting Vue template.');
}

function extractAppTemplate(html) {
  const start = html.search(/<div\b[^>]*\bid=["']app["'][^>]*>/i);
  if (start < 0) throw new Error('Could not find #app root in public/index.html.');
  const openEnd = findTagEnd(html, start);
  let cursor = openEnd + 1;
  let depth = 1;

  while (cursor < html.length) {
    const lt = html.indexOf('<', cursor);
    if (lt < 0) break;
    if (html.startsWith('<!--', lt)) {
      const commentEnd = html.indexOf('-->', lt + 4);
      if (commentEnd < 0) throw new Error('Unterminated HTML comment while extracting Vue template.');
      cursor = commentEnd + 3;
      continue;
    }
    const tagEnd = findTagEnd(html, lt);
    const token = html.slice(lt, tagEnd + 1);
    if (/^<div\b/i.test(token) && !/\/\s*>$/.test(token)) depth += 1;
    else if (/^<\/div\b/i.test(token)) {
      depth -= 1;
      if (depth === 0) return html.slice(openEnd + 1, lt);
    }
    cursor = tagEnd + 1;
  }
  throw new Error('Could not find matching closing tag for #app.');
}

function compilerModuleToGlobal(code) {
  const importMatch = code.match(/^import\s*\{([\s\S]*?)\}\s*from\s*["']vue["'];?\s*/);
  if (!importMatch) throw new Error('Unexpected Vue compiler output: helper import was not found.');
  const helpers = importMatch[1].replace(/\bas\b/g, ':');
  let body = code.slice(importMatch[0].length);
  body = body.replace(/\bexport\s+function\s+render\b/, 'function render');
  if (/\b(?:import|export)\b/.test(body)) throw new Error('Unexpected module syntax remains in compiled Vue render output.');
  if (!/function\s+render\b/.test(body)) throw new Error('Compiled Vue render function was not generated.');

  return `'use strict';\n(() => {\n  if (!window.Vue) throw new Error('Vue runtime is unavailable.');\n  const {${helpers}} = window.Vue;\n${body}\n  window.__CHATROOM_RENDER__ = render;\n  const originalCreateApp = window.Vue.createApp;\n  window.Vue.createApp = function createAppWithPrecompiledTemplate(rootComponent, ...args) {\n    if (rootComponent && !rootComponent.render && !rootComponent.template) rootComponent.render = render;\n    return originalCreateApp(rootComponent, ...args);\n  };\n})();\n`;
}

async function precompileVueTemplate(html) {
  const template = extractAppTemplate(html);
  const { code } = compile(template, {
    mode: 'module',
    hoistStatic: true,
    onError(error) { throw error; },
  });
  const renderAsset = compilerModuleToGlobal(code);
  if (/\bnew\s+Function\b|\beval\s*\(/.test(renderAsset)) throw new Error('Generated render asset unexpectedly contains dynamic code evaluation.');
  await fsp.mkdir(assetsDir, { recursive: true });
  await fsp.writeFile(path.join(assetsDir, 'render.js'), renderAsset, 'utf8');
}

async function rewriteIndex() {
  const file = path.join(publicDir, 'index.html');
  let html = await fsp.readFile(file, 'utf8');

  html = html.replace(
    /\s*<!-- Tailwind config MUST be before tailwind script -->[\s\S]*?<script src="https:\/\/cdn\.tailwindcss\.com"><\/script>\s*/,
    '\n  <link rel="stylesheet" href="/assets/tailwind.css" />\n',
  );
  html = html.replace(/\s*<link href="https:\/\/fonts\.googleapis\.com[^>]+>\s*/g, '\n');
  html = html.replace(
    /\s*<link rel="stylesheet" href="https:\/\/cdnjs\.cloudflare\.com\/ajax\/libs\/font-awesome[\s\S]*?referrerpolicy="no-referrer" \/>\s*/,
    '\n  <link rel="stylesheet" href="/vendor/fontawesome/all.min.css" />\n',
  );
  html = html.replace(
    /\s*<script src="https:\/\/unpkg\.com\/vue@[^"]+"[\s\S]*?<\/script>\s*/,
    '\n  <script defer src="/vendor/vue.global.prod.js"></script>\n',
  );

  html = html.replace(/<script(?:\s+defer)?\s+src="\/socket\.io\/socket\.io\.js"><\/script>/g, '<script defer src="/socket.io/socket.io.js"></script>');
  html = html.replace(/<script(?:\s+defer)?\s+src="\/vendor\/vue\.global\.prod\.js"><\/script>/g, '<script defer src="/vendor/vue.global.prod.js"></script>');
  html = html.replace(/\s*<script(?:\s+defer)?\s+src="\/assets\/render\.js"><\/script>\s*/g, '\n');
  html = html.replace(/<script(?:\s+defer)?\s+src="\/assets\/app\.js"><\/script>/g, '<script defer src="/assets/render.js"></script>\n  <script defer src="/assets/app.js"></script>');

  if (/cdn\.tailwindcss\.com|unpkg\.com\/vue|fonts\.googleapis\.com|cdnjs\.cloudflare\.com\/ajax\/libs\/font-awesome/.test(html)) {
    throw new Error('Production CDN references remain in public/index.html after build rewrite.');
  }
  for (const required of ['/socket.io/socket.io.js', '/vendor/vue.global.prod.js', '/assets/render.js', '/assets/app.js']) {
    if (!html.includes(`<script defer src="${required}"></script>`)) throw new Error(`Expected deferred script is missing: ${required}`);
  }

  await precompileVueTemplate(html);
  await fsp.writeFile(file, html, 'utf8');
}

async function main() {
  await fsp.rm(vendorDir, { recursive: true, force: true });
  await fsp.mkdir(vendorDir, { recursive: true });

  const tailwindBin = process.platform === 'win32'
    ? path.join(root, 'node_modules', '.bin', 'tailwindcss.cmd')
    : path.join(root, 'node_modules', '.bin', 'tailwindcss');
  execFileSync(tailwindBin, [
    '-c', path.join(root, 'tailwind.config.js'),
    '-i', path.join(root, 'src', 'styles.css'),
    '-o', path.join(publicDir, 'assets', 'tailwind.css'),
    '--minify',
  ], { cwd: root, stdio: 'inherit' });

  await copyFile(
    path.join(root, 'node_modules', 'vue', 'dist', 'vue.runtime.global.prod.js'),
    path.join(vendorDir, 'vue.global.prod.js'),
  );
  await copyFile(
    path.join(root, 'node_modules', '@fortawesome', 'fontawesome-free', 'css', 'all.min.css'),
    path.join(vendorDir, 'fontawesome', 'all.min.css'),
  );
  await copyDirectory(
    path.join(root, 'node_modules', '@fortawesome', 'fontawesome-free', 'webfonts'),
    path.join(vendorDir, 'webfonts'),
  );
  await rewriteIndex();

  console.log('Frontend assets built with a precompiled Vue render function and runtime-only self-hosted dependencies.');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
