'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { execFileSync } = require('child_process');

const root = path.resolve(__dirname, '..');
const publicDir = path.join(root, 'public');
const vendorDir = path.join(publicDir, 'vendor');

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
    '\n  <script src="/vendor/vue.global.prod.js"></script>\n',
  );
  if (/cdn\.tailwindcss\.com|unpkg\.com\/vue|fonts\.googleapis\.com|cdnjs\.cloudflare\.com\/ajax\/libs\/font-awesome/.test(html)) {
    throw new Error('Production CDN references remain in public/index.html after build rewrite.');
  }
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
    path.join(root, 'node_modules', 'vue', 'dist', 'vue.global.prod.js'),
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

  console.log('Frontend assets built into public/assets and public/vendor with no production CDN dependency.');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
