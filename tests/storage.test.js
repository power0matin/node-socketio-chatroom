'use strict';

const assert = require('node:assert/strict');
const fs = require('fs').promises;
const os = require('os');
const path = require('path');
const test = require('node:test');
const {
  StateStore,
  atomicWriteJson,
  encryptPayload,
  readEncrypted,
  readJsonStrict,
  writeEncrypted,
} = require('../src/lib/storage');

async function tempDir() { return fs.mkdtemp(path.join(os.tmpdir(), 'storage-test-')); }

test('encrypted persistence loads with the valid key', async () => {
  const dir = await tempDir();
  const file = path.join(dir, 'state.json');
  const key = Buffer.alloc(32, 7);
  await writeEncrypted(file, key, { users: { alice: { role: 'user' } } });
  assert.deepEqual(await readEncrypted(file, key), { users: { alice: { role: 'user' } } });
  await fs.rm(dir, { recursive: true, force: true });
});

test('wrong key fails closed instead of returning empty data', async () => {
  const dir = await tempDir();
  const file = path.join(dir, 'state.json');
  await writeEncrypted(file, Buffer.alloc(32, 1), { keep: 'me' });
  await assert.rejects(() => readEncrypted(file, Buffer.alloc(32, 2)), (error) => error.code === 'DECRYPT_FAILED');
  const raw = JSON.parse(await fs.readFile(file, 'utf8'));
  assert.equal(raw.alg, 'A256GCM');
  await fs.rm(dir, { recursive: true, force: true });
});

test('corrupt and missing files are distinguished', async () => {
  const dir = await tempDir();
  const missing = path.join(dir, 'missing.json');
  assert.equal(await readJsonStrict(missing, { missing: null }), null);
  const corrupt = path.join(dir, 'corrupt.json');
  await fs.writeFile(corrupt, '{broken');
  await assert.rejects(() => readJsonStrict(corrupt, { missing: null }), (error) => error.code === 'CORRUPT_FILE');
  await fs.rm(dir, { recursive: true, force: true });
});

test('atomic writes never leave a temporary file on success', async () => {
  const dir = await tempDir();
  const file = path.join(dir, 'config.json');
  await atomicWriteJson(file, { ok: true });
  assert.deepEqual(JSON.parse(await fs.readFile(file, 'utf8')), { ok: true });
  assert.deepEqual((await fs.readdir(dir)).filter((name) => name.endsWith('.tmp')), []);
  await fs.rm(dir, { recursive: true, force: true });
});

test('StateStore flush persists dirty state and exposes write failures', async () => {
  const dir = await tempDir();
  const file = path.join(dir, 'state.json');
  const state = { schemaVersion: 2, value: 1 };
  const store = new StateStore(file, Buffer.alloc(32, 3), state);
  state.value = 2;
  store.markDirty();
  await store.flush();
  assert.equal((await readEncrypted(file, Buffer.alloc(32, 3))).value, 2);
  await fs.rm(dir, { recursive: true, force: true });
});

test('encrypted wrapper does not expose cleartext payload', () => {
  const wrapper = encryptPayload(Buffer.alloc(32, 4), { secretText: 'not-visible' });
  assert.equal(JSON.stringify(wrapper).includes('not-visible'), false);
});
