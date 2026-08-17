'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = fs.promises;
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const { createApplication } = require('../src/server');

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const port = probe.address().port;
      probe.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function findBrowser() {
  const candidates = [
    process.env.CHROME_BIN,
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ].filter(Boolean);
  for (const candidate of candidates) if (fs.existsSync(candidate)) return candidate;
  for (const name of ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser']) {
    const found = spawnSync('which', [name], { encoding: 'utf8' });
    if (found.status === 0 && found.stdout.trim()) return found.stdout.trim();
  }
  throw new Error('A Chromium/Chrome executable is required for the browser smoke test.');
}

async function main() {
  const repo = path.resolve(__dirname, '..');
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'chatroom-browser-smoke-'));
  const dataDir = path.join(root, 'data');
  const backupRoot = path.join(os.tmpdir(), `chatroom-browser-backups-${process.pid}-${Date.now()}`);
  const port = await freePort();
  await fsp.mkdir(dataDir, { recursive: true });
  await fsp.writeFile(path.join(dataDir, 'config.json'), JSON.stringify({
    adminUser: 'admin',
    adminPassHash: '',
    adminSessionVersion: 1,
    port,
    bindHost: '127.0.0.1',
    allowedOrigins: [`http://127.0.0.1:${port}`],
    accessMode: 'open',
    trustProxy: false,
  }, null, 2));

  const runtime = await createApplication({
    rootDir: root,
    dataDir,
    publicDir: path.join(repo, 'public'),
    backupRoot,
    env: {},
  });

  try {
    await runtime.start();
    const response = await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(response.status, 200);
    const csp = response.headers.get('content-security-policy') || '';
    assert.ok(csp.includes("script-src 'self'"), `missing strict self script CSP: ${csp}`);
    assert.ok(!csp.includes("'unsafe-eval'"), 'CSP must not permit unsafe-eval.');

    const browser = findBrowser();
    const dom = execFileSync(browser, [
      '--headless=new',
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--disable-background-networking',
      '--disable-default-apps',
      '--no-first-run',
      '--dump-dom',
      `http://127.0.0.1:${port}/`,
    ], { encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024 });

    assert.match(dom, /ورود\s*\/\s*ثبت نام/);
    assert.ok(!dom.includes('{{ appName }}'), 'Vue template was not rendered; raw interpolation remained in DOM.');
    assert.ok(!dom.includes('v-if="!isLoggedIn"'), 'Vue template directives remained unrendered in DOM.');
    console.log(`PASS headless browser rendered Vue UI under strict CSP using ${browser}`);
  } finally {
    await runtime.stop('browser-smoke').catch(() => {});
    await fsp.rm(root, { recursive: true, force: true });
    await fsp.rm(backupRoot, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
