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

  console.log('Frontend assets built into public/assets and public/vendor.');
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
