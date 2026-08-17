'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const fsp = fs.promises;
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
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

function delay(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

async function stopBrowserProcess(child) {
  if (!child) return;
  if (child.exitCode === null && child.signalCode === null) {
    child.kill('SIGTERM');
    await Promise.race([
      new Promise((resolve) => child.once('exit', resolve)),
      delay(2000),
    ]);
  }
  if (child.exitCode === null && child.signalCode === null) {
    child.kill('SIGKILL');
    await Promise.race([
      new Promise((resolve) => child.once('exit', resolve)),
      delay(2000),
    ]);
  }
  // Chrome can release profile files slightly after the main process exit event.
  await delay(200);
}

async function launchBrowser(browser, profileDir, debugPort) {
  const child = spawn(browser, [
    '--headless=new',
    '--no-sandbox',
    '--disable-gpu',
    '--disable-dev-shm-usage',
    '--disable-background-networking',
    '--disable-component-update',
    '--disable-default-apps',
    '--disable-extensions',
    '--disable-features=OptimizationGuideModelDownloading,MediaRouter',
    '--disable-sync',
    '--no-first-run',
    '--remote-debugging-address=127.0.0.1',
    `--remote-debugging-port=${debugPort}`,
    '--remote-allow-origins=*',
    `--user-data-dir=${profileDir}`,
    'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });

  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => {
    stderr += chunk;
    if (stderr.length > 32_000) stderr = stderr.slice(-32_000);
  });

  for (let attempt = 0; attempt < 150; attempt += 1) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`Chrome exited before DevTools became ready (code=${child.exitCode}, signal=${child.signalCode}). stderr=${stderr.slice(-4000)}`);
    }
    try {
      const response = await fetch(`http://127.0.0.1:${debugPort}/json/version`, {
        signal: AbortSignal.timeout(500),
      });
      if (response.ok) {
        const version = await response.json();
        if (version?.webSocketDebuggerUrl) {
          return { child, websocketUrl: version.webSocketDebuggerUrl, stderr: () => stderr };
        }
      }
    } catch {}
    await delay(100);
  }

  child.kill('SIGKILL');
  throw new Error(`Chrome DevTools endpoint did not become reachable on 127.0.0.1:${debugPort}. stderr=${stderr.slice(-4000)}`);
}

class DevToolsClient {
  constructor(url) {
    if (typeof WebSocket !== 'function') throw new Error('Node.js with the built-in WebSocket client is required for browser smoke testing.');
    this.ws = new WebSocket(url);
    this.nextId = 1;
    this.pending = new Map();
    this.waiters = [];
  }

  async open() {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Timed out connecting to Chrome DevTools WebSocket.')), 10_000);
      this.ws.addEventListener('open', () => { clearTimeout(timer); resolve(); }, { once: true });
      this.ws.addEventListener('error', () => { clearTimeout(timer); reject(new Error('Chrome DevTools WebSocket connection failed.')); }, { once: true });
    });
    this.ws.addEventListener('message', (event) => this.onMessage(event));
  }

  onMessage(event) {
    let message;
    try { message = JSON.parse(String(event.data)); } catch { return; }
    if (message.id) {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      clearTimeout(pending.timer);
      if (message.error) pending.reject(new Error(`${pending.method}: ${message.error.message}`));
      else pending.resolve(message.result || {});
      return;
    }
    for (const waiter of [...this.waiters]) {
      if (waiter.method !== message.method) continue;
      if (waiter.sessionId && waiter.sessionId !== message.sessionId) continue;
      this.waiters.splice(this.waiters.indexOf(waiter), 1);
      clearTimeout(waiter.timer);
      waiter.resolve(message.params || {});
    }
  }

  send(method, params = {}, sessionId) {
    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`DevTools command timed out: ${method}`));
      }, 10_000);
      this.pending.set(id, { method, resolve, reject, timer });
      this.ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }

  once(method, sessionId, timeoutMs = 10_000) {
    return new Promise((resolve, reject) => {
      const waiter = { method, sessionId, resolve, reject, timer: null };
      waiter.timer = setTimeout(() => {
        const index = this.waiters.indexOf(waiter);
        if (index >= 0) this.waiters.splice(index, 1);
        reject(new Error(`Timed out waiting for DevTools event: ${method}`));
      }, timeoutMs);
      this.waiters.push(waiter);
    });
  }

  close() {
    try { this.ws.close(); } catch {}
  }
}

async function inspectPage(browser, url) {
  const cdp = new DevToolsClient(browser.websocketUrl);
  await cdp.open();
  const browserErrors = [];

  try {
    const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    await cdp.send('Runtime.enable', {}, sessionId);
    await cdp.send('Page.enable', {}, sessionId);
    await cdp.send('Log.enable', {}, sessionId);

    const originalOnMessage = cdp.onMessage.bind(cdp);
    cdp.onMessage = (event) => {
      let message;
      try { message = JSON.parse(String(event.data)); } catch { return originalOnMessage(event); }
      if (message.sessionId === sessionId && message.method === 'Runtime.exceptionThrown') {
        const detail = message.params?.exceptionDetails;
        browserErrors.push(`exception: ${detail?.text || detail?.exception?.description || 'unknown'}`);
      }
      if (message.sessionId === sessionId && message.method === 'Runtime.consoleAPICalled' && message.params?.type === 'error') {
        const text = (message.params.args || []).map((arg) => arg.value ?? arg.description ?? '').join(' ');
        browserErrors.push(`console.error: ${text}`);
      }
      if (message.sessionId === sessionId && message.method === 'Log.entryAdded' && ['error', 'warning'].includes(message.params?.entry?.level)) {
        const text = String(message.params.entry.text || '');
        if (/content security policy|refused to|uncaught|vue/i.test(text)) browserErrors.push(`browser log: ${text}`);
      }
      return originalOnMessage(event);
    };

    const loaded = cdp.once('Page.loadEventFired', sessionId, 15_000);
    const navigation = await cdp.send('Page.navigate', { url }, sessionId);
    if (navigation.errorText) throw new Error(`Browser navigation failed: ${navigation.errorText}`);
    await loaded;
    await delay(750);

    const { result: htmlResult } = await cdp.send('Runtime.evaluate', {
      expression: 'document.documentElement.outerHTML',
      returnByValue: true,
    }, sessionId);
    const dom = String(htmlResult?.value || '');

    const { result: stateResult } = await cdp.send('Runtime.evaluate', {
      expression: `JSON.stringify({
        appExists: Boolean(document.querySelector('#app')),
        loginText: document.querySelector('#app')?.innerText || '',
        rawInterpolation: document.documentElement.outerHTML.includes('{{ appName }}'),
        rawDirective: document.documentElement.outerHTML.includes('v-if="!isLoggedIn"')
      })`,
      returnByValue: true,
    }, sessionId);
    const state = JSON.parse(String(stateResult?.value || '{}'));

    assert.ok(state.appExists, 'Vue application root is missing.');
    assert.match(String(state.loginText || ''), /ورود\s*\/\s*ثبت نام/);
    assert.equal(state.rawInterpolation, false, 'Vue template was not rendered; raw interpolation remained in DOM.');
    assert.equal(state.rawDirective, false, 'Vue template directives remained unrendered in DOM.');
    assert.ok(dom.length > 1000, 'Rendered DOM is unexpectedly empty.');
    assert.deepEqual(browserErrors, [], `Browser runtime errors detected:\n${browserErrors.join('\n')}`);

    await cdp.send('Target.closeTarget', { targetId }).catch(() => {});
    return { domLength: dom.length };
  } finally {
    await cdp.send('Browser.close').catch(() => {});
    cdp.close();
  }
}

async function main() {
  const repo = path.resolve(__dirname, '..');
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), 'chatroom-browser-smoke-'));
  const dataDir = path.join(root, 'data');
  const backupRoot = path.join(os.tmpdir(), `chatroom-browser-backups-${process.pid}-${Date.now()}`);
  const profileDir = path.join(root, 'chrome-profile');
  const port = await freePort();
  const debugPort = await freePort();
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
  let browserProcess = null;

  try {
    await runtime.start();
    const url = `http://127.0.0.1:${port}/`;
    const response = await fetch(url);
    assert.equal(response.status, 200);
    const csp = response.headers.get('content-security-policy') || '';
    assert.ok(csp.includes("script-src 'self'"), `missing strict self script CSP: ${csp}`);
    assert.ok(!csp.includes("'unsafe-eval'"), 'CSP must not permit unsafe-eval.');

    const executable = findBrowser();
    const browser = await launchBrowser(executable, profileDir, debugPort);
    browserProcess = browser.child;
    const inspected = await inspectPage(browser, url);
    console.log(`PASS headless browser rendered Vue UI under CSP using ${executable} (${inspected.domLength} DOM bytes)`);
  } finally {
    await stopBrowserProcess(browserProcess);
    await runtime.stop('browser-smoke').catch(() => {});
    await fsp.rm(root, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
    await fsp.rm(backupRoot, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
