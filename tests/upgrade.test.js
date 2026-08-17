'use strict';

const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs').promises;
const os = require('os');
const path = require('path');
const test = require('node:test');
const bcrypt = require('bcryptjs');
const { createApplication } = require('../src/server');
const { readEncrypted, writeEncrypted } = require('../src/lib/storage');
const { freePort } = require('./helpers');

async function fixture({ wrongConfigKey = false } = {}) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'upgrade-test-'));
  const rootDir = path.join(base, 'app');
  const dataDir = path.join(rootDir, 'data');
  const uploadsDir = path.join(rootDir, 'public', 'uploads');
  const backupRoot = path.join(base, 'external-backups');
  await fs.mkdir(dataDir, { recursive: true });
  const keyHex = crypto.randomBytes(32).toString('hex');
  const configKey = wrongConfigKey ? crypto.randomBytes(32).toString('hex') : keyHex;
  const key = Buffer.from(keyHex, 'hex');
  const port = await freePort();
  const config = {
    adminUser: 'admin', adminPassHash: await bcrypt.hash('AdminPass123!', 4), port,
    maxFileSizeMB: 10, appName: 'Legacy Chat', hideUserList: false,
    allowedOrigins: [`http://127.0.0.1:${port}`], protectUploads: true,
    accessMode: 'restricted', defaultChannelsForNewUsers: ['General'],
    maxChannelMessages: 100, maxDmMessages: 500, maxSavedMessages: 1000,
    dataEncKey: configKey,
  };
  await fs.writeFile(path.join(dataDir, 'config.json'), JSON.stringify(config, null, 2));
  const users = { alice: { passHash: await bcrypt.hash('AlicePass123!', 4), role: 'vip', isBanned: false, created_at: 1 } };
  const channels = ['General', 'Random'];
  const messages = { General: [{ id: 'legacy-message', sender: 'alice', text: 'keep me', type: 'text', channel: 'General' }] };
  const conversations = { General: { id: 'General', type: 'public', createdBy: 'admin', createdAt: 1 } };
  const memberships = { General: { alice: { role: 'member', joinedAt: 1 }, admin: { role: 'owner', joinedAt: 1 } } };
  const attachments = {};
  for (const [name, value] of Object.entries({ users, channels, messages, conversations, memberships, attachments })) {
    await writeEncrypted(path.join(dataDir, `${name}.json`), key, value);
  }
  return { base, rootDir, dataDir, uploadsDir, backupRoot, port, keyHex, users, messages };
}

test('legacy install migrates with the same key, users, messages and permissions', async (t) => {
  const fx = await fixture();
  t.after(() => fs.rm(fx.base, { recursive: true, force: true }));
  const runtime = await createApplication({ rootDir: fx.rootDir, dataDir: fx.dataDir, uploadsDir: fx.uploadsDir, backupRoot: fx.backupRoot, env: {} });
  t.after(async () => { try { await runtime.stop('test'); } catch {} });
  assert.equal(runtime.state.users.alice.role, 'vip');
  assert.equal(runtime.state.messages.General[0].text, 'keep me');
  assert.ok(runtime.state.memberships.General.alice);
  assert.equal((await fs.readFile(path.join(fx.dataDir, '.data-key'), 'utf8')).trim(), fx.keyHex);
  const cleanedConfig = JSON.parse(await fs.readFile(path.join(fx.dataDir, 'config.json'), 'utf8'));
  assert.equal(Object.prototype.hasOwnProperty.call(cleanedConfig, 'dataEncKey'), false);
  const state = await readEncrypted(path.join(fx.dataDir, 'state.json'), Buffer.from(fx.keyHex, 'hex'));
  assert.equal(state.users.alice.role, 'vip');
  assert.equal(state.messages.General[0].id, 'legacy-message');
  const backupDirs = await fs.readdir(fx.backupRoot);
  assert.equal(backupDirs.length, 1);
  const manifest = JSON.parse(await fs.readFile(path.join(fx.backupRoot, backupDirs[0], 'manifest.json'), 'utf8'));
  assert.ok(manifest.files['users.json'].sha256);
  assert.ok(manifest.files['messages.json'].sha256);
});

test('wrong legacy encryption key fails closed before creating new state or cleaning config', async (t) => {
  const fx = await fixture({ wrongConfigKey: true });
  t.after(() => fs.rm(fx.base, { recursive: true, force: true }));
  const originalUsers = await fs.readFile(path.join(fx.dataDir, 'users.json'), 'utf8');
  await assert.rejects(
    () => createApplication({ rootDir: fx.rootDir, dataDir: fx.dataDir, uploadsDir: fx.uploadsDir, backupRoot: fx.backupRoot, env: {} }),
    (error) => error.code === 'DECRYPT_FAILED',
  );
  await assert.rejects(() => fs.access(path.join(fx.dataDir, 'state.json')));
  assert.equal(await fs.readFile(path.join(fx.dataDir, 'users.json'), 'utf8'), originalUsers);
  const config = JSON.parse(await fs.readFile(path.join(fx.dataDir, 'config.json'), 'utf8'));
  assert.ok(config.dataEncKey, 'legacy key must remain recoverable after failed migration');
});

test('migration backup survives deletion of the application directory', async (t) => {
  const fx = await fixture();
  t.after(() => fs.rm(fx.base, { recursive: true, force: true }));
  const runtime = await createApplication({ rootDir: fx.rootDir, dataDir: fx.dataDir, uploadsDir: fx.uploadsDir, backupRoot: fx.backupRoot, env: {} });
  await runtime.stop('migration-complete');
  const [backup] = await fs.readdir(fx.backupRoot);
  await fs.rm(fx.rootDir, { recursive: true, force: true });
  const manifestPath = path.join(fx.backupRoot, backup, 'manifest.json');
  const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
  assert.ok(manifest.files['users.json']);
  assert.ok(manifest.files['channels.json']);
});
