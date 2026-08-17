'use strict';

const assert = require('node:assert/strict');
const fs = require('fs').promises;
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const test = require('node:test');
const { defaultState, writeEncrypted } = require('../src/lib/storage');

const repo = path.resolve(__dirname, '..');

function run(script, args, env, timeout = 180000) {
  return spawnSync('bash', [script, ...args], {
    cwd: repo,
    env: { ...process.env, ...env },
    encoding: 'utf8',
    timeout,
  });
}

async function makeInstalledTree(base, name = 'live') {
  const live = path.join(base, name);
  await fs.mkdir(path.join(live, 'scripts'), { recursive: true });
  await fs.mkdir(path.join(live, 'data'), { recursive: true });
  await fs.mkdir(path.join(live, 'public', 'uploads'), { recursive: true });
  await fs.cp(path.join(repo, 'scripts'), path.join(live, 'scripts'), { recursive: true });
  await fs.copyFile(path.join(repo, 'package.json'), path.join(live, 'package.json'));
  await fs.copyFile(path.join(repo, 'package-lock.json'), path.join(live, 'package-lock.json'));
  await fs.writeFile(path.join(live, '.chatroom-install'), 'node-socketio-chatroom\n');
  const port = 39000 + Math.floor(Math.random() * 1000);
  const config = {
    adminUser: 'admin', adminPassHash: '', adminSessionVersion: 1, port,
    bindHost: '127.0.0.1', allowedOrigins: [`http://127.0.0.1:${port}`],
    accessMode: 'open',
  };
  await fs.writeFile(path.join(live, 'data', 'config.json'), JSON.stringify(config, null, 2));
  const keyHex = Buffer.alloc(32, 8).toString('hex');
  await fs.writeFile(path.join(live, 'data', '.data-key'), keyHex);
  const state = defaultState();
  state.users.alice = { passHash: '$2a$04$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUV12', role: 'user', isBanned: false, sessionVersion: 1 };
  state.messages.General = [{ id: 'persist-me', sender: 'alice', text: 'original', type: 'text', channel: 'General' }];
  await writeEncrypted(path.join(live, 'data', 'state.json'), Buffer.from(keyHex, 'hex'), state);
  await fs.writeFile(path.join(live, 'public', 'uploads', 'keep.txt'), 'upload-original');
  return { live, port, keyHex };
}

test('verified backup restores data and uploads after destructive modification', async (t) => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'lifecycle-restore-'));
  const backupRoot = path.join(base, 'backups');
  const { live } = await makeInstalledTree(base);
  t.after(() => fs.rm(base, { recursive: true, force: true }));

  const backup = run(path.join(live, 'scripts', 'backup.sh'), [], { CHATROOM_DIR: live, BACKUP_ROOT: backupRoot });
  assert.equal(backup.status, 0, backup.stderr);
  const archive = backup.stdout.trim().split(/\r?\n/).at(-1);
  assert.ok(archive.endsWith('.tar.gz'));
  await fs.writeFile(path.join(live, 'data', 'config.json'), '{"broken":true}\n');
  await fs.rm(path.join(live, 'data', 'state.json'));
  await fs.writeFile(path.join(live, 'public', 'uploads', 'keep.txt'), 'mutated');

  const restored = run(path.join(live, 'scripts', 'restore.sh'), [archive], {
    CHATROOM_DIR: live, BACKUP_ROOT: backupRoot, CHATROOM_SKIP_SERVICE: '1',
  });
  assert.equal(restored.status, 0, `${restored.stdout}\n${restored.stderr}`);
  const config = JSON.parse(await fs.readFile(path.join(live, 'data', 'config.json'), 'utf8'));
  assert.equal(config.adminUser, 'admin');
  assert.equal(await fs.readFile(path.join(live, 'public', 'uploads', 'keep.txt'), 'utf8'), 'upload-original');
  await fs.access(path.join(live, 'data', 'state.json'));
});

test('successful updater can run twice and always cleans its lock', async (t) => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'lifecycle-update-'));
  const backupRoot = path.join(base, 'backups');
  const { live } = await makeInstalledTree(base);
  t.after(() => fs.rm(base, { recursive: true, force: true }));

  for (let i = 0; i < 2; i += 1) {
    const result = run(path.join(live, 'scripts', 'update.sh'), ['--source', repo], {
      CHATROOM_DIR: live, BACKUP_ROOT: backupRoot, CHATROOM_SKIP_SERVICE: '1',
    });
    assert.equal(result.status, 0, `update ${i + 1} failed\n${result.stdout}\n${result.stderr}`);
    await assert.rejects(() => fs.access(path.join(backupRoot, '.update.lock')));
    const pkg = JSON.parse(await fs.readFile(path.join(live, 'package.json'), 'utf8'));
    assert.equal(pkg.version, '1.11.0');
  }
});

test('post-swap validation failure rolls back code and preserves data', async (t) => {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'lifecycle-rollback-'));
  const backupRoot = path.join(base, 'backups');
  const { live, keyHex } = await makeInstalledTree(base);
  const brokenRelease = path.join(base, 'broken-release');
  t.after(() => fs.rm(base, { recursive: true, force: true }));

  // First bring the installed tree to the current release so a rollback has complete executable code.
  const initial = run(path.join(live, 'scripts', 'update.sh'), ['--source', repo], {
    CHATROOM_DIR: live, BACKUP_ROOT: backupRoot, CHATROOM_SKIP_SERVICE: '1',
  });
  assert.equal(initial.status, 0, `${initial.stdout}\n${initial.stderr}`);

  await fs.cp(repo, brokenRelease, {
    recursive: true,
    filter(source) {
      const rel = path.relative(repo, source);
      return rel !== '.git' && !rel.startsWith(`.git${path.sep}`) && rel !== 'node_modules' && !rel.startsWith(`node_modules${path.sep}`);
    },
  });
  await fs.rename(path.join(brokenRelease, 'src', 'server.js'), path.join(brokenRelease, 'src', 'server.real.js'));
  await fs.writeFile(path.join(brokenRelease, 'src', 'server.js'), `
'use strict';
const fs = require('fs');
const path = require('path');
const real = require('./server.real');
module.exports = {
  ...real,
  async createApplication(options = {}) {
    const marker = path.join(options.rootDir || path.join(__dirname, '..'), '.post-swap-marker');
    if (fs.existsSync(marker)) throw new Error('intentional post-swap validation failure');
    fs.writeFileSync(marker, 'preflight-completed');
    return real.createApplication(options);
  }
};
`, 'utf8');

  const failed = run(path.join(live, 'scripts', 'update.sh'), ['--source', brokenRelease], {
    CHATROOM_DIR: live, BACKUP_ROOT: backupRoot, CHATROOM_SKIP_SERVICE: '1',
  });
  assert.notEqual(failed.status, 0, 'forced failing release unexpectedly succeeded');
  await assert.rejects(() => fs.access(path.join(backupRoot, '.update.lock')));
  await assert.rejects(() => fs.access(path.join(live, '.post-swap-marker')));
  const serverSource = await fs.readFile(path.join(live, 'src', 'server.js'), 'utf8');
  assert.equal(serverSource.includes('intentional post-swap validation failure'), false);
  const { readEncrypted } = require('../src/lib/storage');
  const state = await readEncrypted(path.join(live, 'data', 'state.json'), Buffer.from(keyHex, 'hex'));
  assert.equal(state.messages.General[0].text, 'original');
});
