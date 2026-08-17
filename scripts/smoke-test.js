'use strict';

const fs = require('fs').promises;
const os = require('os');
const path = require('path');
const net = require('net');
const bcrypt = require('bcryptjs');
const { createApplication } = require('../src/server');

async function freePort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const port = probe.address().port;
      probe.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

async function main() {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'chatroom-smoke-'));
  const rootDir = path.join(base, 'app');
  const dataDir = path.join(rootDir, 'data');
  const backupRoot = path.join(base, 'backups');
  const uploadsDir = path.join(rootDir, 'public', 'uploads');
  await fs.mkdir(dataDir, { recursive: true });
  const port = await freePort();
  await fs.writeFile(path.join(dataDir, 'config.json'), JSON.stringify({
    adminUser: 'admin',
    adminPassHash: await bcrypt.hash('SmokeAdmin123!', 4),
    port,
    bindHost: '127.0.0.1',
    allowedOrigins: [`http://127.0.0.1:${port}`],
    accessMode: 'open',
  }, null, 2));
  const runtime = await createApplication({ rootDir, dataDir, backupRoot, uploadsDir, env: {} });
  try {
    await runtime.start();
    const health = await fetch(`http://127.0.0.1:${port}/healthz`);
    const ready = await fetch(`http://127.0.0.1:${port}/readyz`);
    if (health.status !== 200 || ready.status !== 200) throw new Error(`Smoke health failed: health=${health.status}, ready=${ready.status}`);
    console.log('PASS clean runtime start + healthz + readyz');
  } finally {
    await runtime.stop('smoke');
    await fs.rm(base, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
