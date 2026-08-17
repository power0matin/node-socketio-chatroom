'use strict';

const crypto = require('crypto');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

class PersistenceError extends Error {
  constructor(message, code = 'PERSISTENCE_ERROR', cause) {
    super(message, cause ? { cause } : undefined);
    this.name = 'PersistenceError';
    this.code = code;
  }
}

function keyFromHex(value) {
  const text = String(value || '').trim();
  if (!/^[0-9a-fA-F]{64}$/.test(text)) return null;
  const key = Buffer.from(text, 'hex');
  return key.length === 32 ? key : null;
}

function encryptedWrapper(value) {
  return Boolean(value && typeof value === 'object' && value.v === 1 && value.alg === 'A256GCM' && value.iv && value.tag && value.data);
}

function encryptPayload(key, value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(value), 'utf8')), cipher.final()]);
  return {
    v: 1,
    alg: 'A256GCM',
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    data: ciphertext.toString('base64'),
  };
}

function decryptPayload(key, wrapper) {
  try {
    const iv = Buffer.from(String(wrapper.iv), 'base64');
    const tag = Buffer.from(String(wrapper.tag), 'base64');
    const data = Buffer.from(String(wrapper.data), 'base64');
    if (iv.length !== 12 || tag.length !== 16 || data.length < 1) throw new Error('invalid encrypted wrapper');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const clear = Buffer.concat([decipher.update(data), decipher.final()]);
    return JSON.parse(clear.toString('utf8'));
  } catch (error) {
    throw new PersistenceError('Encrypted persistence could not be authenticated/decrypted. Refusing to start to prevent data loss.', 'DECRYPT_FAILED', error);
  }
}

async function readJsonStrict(file, { missing = undefined } = {}) {
  let raw;
  try {
    raw = await fsp.readFile(file, 'utf8');
  } catch (error) {
    if (error && error.code === 'ENOENT') return missing;
    throw new PersistenceError(`Unable to read ${file}: ${error.message}`, 'READ_FAILED', error);
  }
  if (!raw.trim()) throw new PersistenceError(`Persistence file is empty: ${file}`, 'CORRUPT_FILE');
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new PersistenceError(`Persistence file is invalid JSON: ${file}`, 'CORRUPT_FILE', error);
  }
}

async function fsyncDirectory(dir) {
  const handle = await fsp.open(dir, fs.constants.O_RDONLY);
  try { await handle.sync(); } finally { await handle.close(); }
}

async function atomicWriteJson(file, value, mode = 0o600) {
  const dir = path.dirname(file);
  await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  const handle = await fsp.open(tmp, 'wx', mode);
  try {
    await handle.writeFile(JSON.stringify(value, null, 2), 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await fsp.rename(tmp, file);
    await fsp.chmod(file, mode);
    await fsyncDirectory(dir);
  } catch (error) {
    await fsp.rm(tmp, { force: true }).catch(() => {});
    throw new PersistenceError(`Atomic write failed for ${file}: ${error.message}`, 'WRITE_FAILED', error);
  }
}

async function readEncrypted(file, key, { missing = undefined, allowPlaintext = false } = {}) {
  const parsed = await readJsonStrict(file, { missing });
  if (parsed === missing) return missing;
  if (encryptedWrapper(parsed)) return decryptPayload(key, parsed);
  if (allowPlaintext) return parsed;
  throw new PersistenceError(`Expected encrypted persistence but found plaintext: ${file}`, 'PLAINTEXT_UNEXPECTED');
}

async function writeEncrypted(file, key, value) {
  await atomicWriteJson(file, encryptPayload(key, value), 0o600);
}

async function copyVerified(src, dst) {
  await fsp.mkdir(path.dirname(dst), { recursive: true, mode: 0o700 });
  await fsp.copyFile(src, dst, fs.constants.COPYFILE_EXCL);
  const [a, b] = await Promise.all([fsp.readFile(src), fsp.readFile(dst)]);
  const ah = crypto.createHash('sha256').update(a).digest('hex');
  const bh = crypto.createHash('sha256').update(b).digest('hex');
  if (ah !== bh) {
    await fsp.rm(dst, { force: true });
    throw new PersistenceError(`Backup verification failed for ${src}`, 'BACKUP_VERIFY_FAILED');
  }
  await fsp.chmod(dst, 0o600).catch(() => {});
  return { sha256: bh, bytes: b.length };
}

async function createVerifiedBackup(files, backupRoot, label = 'migration') {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dir = path.join(backupRoot, `${stamp}-${label}`);
  await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
  const manifest = { version: 1, createdAt: new Date().toISOString(), label, files: {} };
  for (const file of files) {
    try {
      await fsp.access(file, fs.constants.R_OK);
    } catch (error) {
      if (error.code === 'ENOENT') continue;
      throw error;
    }
    const name = path.basename(file);
    manifest.files[name] = await copyVerified(file, path.join(dir, name));
  }
  await atomicWriteJson(path.join(dir, 'manifest.json'), manifest, 0o600);
  return { dir, manifest };
}

async function resolveDataKey({ dataDir, config, env = process.env }) {
  const keyFile = path.join(dataDir, '.data-key');
  const envKey = env.DATA_ENC_KEY ? keyFromHex(env.DATA_ENC_KEY) : null;
  if (env.DATA_ENC_KEY && !envKey) throw new PersistenceError('DATA_ENC_KEY must be exactly 64 hexadecimal characters.', 'INVALID_KEY');
  if (envKey) return { key: envKey, source: 'env', hex: env.DATA_ENC_KEY.trim(), migratedLegacy: false };

  try {
    const raw = (await fsp.readFile(keyFile, 'utf8')).trim();
    const key = keyFromHex(raw);
    if (!key) throw new PersistenceError(`${keyFile} contains an invalid key.`, 'INVALID_KEY');
    return { key, source: 'file', hex: raw, migratedLegacy: false };
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const legacy = config && config.dataEncKey ? String(config.dataEncKey).trim() : '';
  const legacyKey = legacy ? keyFromHex(legacy) : null;
  if (legacy && !legacyKey) throw new PersistenceError('Legacy config.dataEncKey is invalid; refusing to generate a replacement key.', 'INVALID_LEGACY_KEY');
  if (legacyKey) {
    await fsp.writeFile(keyFile, legacy, { mode: 0o600, flag: 'wx' });
    return { key: legacyKey, source: 'legacy-config', hex: legacy, migratedLegacy: true };
  }

  const hex = crypto.randomBytes(32).toString('hex');
  await fsp.writeFile(keyFile, hex, { mode: 0o600, flag: 'wx' });
  return { key: Buffer.from(hex, 'hex'), source: 'generated', hex, migratedLegacy: false };
}

function defaultState() {
  return {
    schemaVersion: 2,
    users: {},
    channels: ['General', 'Random'],
    messages: {},
    conversations: {},
    memberships: {},
    attachments: {},
  };
}

async function loadState({ dataDir, key, backupRoot }) {
  const stateFile = path.join(dataDir, 'state.json');
  const current = await readEncrypted(stateFile, key, { missing: null, allowPlaintext: false });
  if (current) {
    if (current.schemaVersion !== 2) throw new PersistenceError(`Unsupported state schema ${current.schemaVersion}`, 'UNSUPPORTED_SCHEMA');
    return { state: current, migrated: false, backup: null };
  }

  const legacyNames = ['users.json', 'channels.json', 'messages.json', 'conversations.json', 'memberships.json', 'attachments.json'];
  const legacyPaths = legacyNames.map((name) => path.join(dataDir, name));
  const existing = [];
  for (const file of legacyPaths) {
    try { await fsp.access(file); existing.push(file); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  if (!existing.length) return { state: defaultState(), migrated: false, backup: null };

  // Validate every existing legacy file before any migration write.
  const loaded = {};
  for (const file of existing) {
    const name = path.basename(file, '.json');
    loaded[name] = await readEncrypted(file, key, { missing: undefined, allowPlaintext: true });
  }

  const backup = await createVerifiedBackup(existing, backupRoot, 'legacy-state');
  const state = defaultState();
  if (loaded.users && typeof loaded.users === 'object') state.users = loaded.users;
  if (Array.isArray(loaded.channels)) state.channels = loaded.channels;
  if (loaded.messages && typeof loaded.messages === 'object') state.messages = loaded.messages;
  if (loaded.conversations && typeof loaded.conversations === 'object') state.conversations = loaded.conversations;
  if (loaded.memberships && typeof loaded.memberships === 'object') state.memberships = loaded.memberships;
  if (loaded.attachments && typeof loaded.attachments === 'object') state.attachments = loaded.attachments;
  await writeEncrypted(stateFile, key, state);
  return { state, migrated: true, backup };
}

class StateStore {
  constructor(file, key, initialState) {
    this.file = file;
    this.key = key;
    this.state = initialState;
    this.dirty = false;
    this.timer = null;
    this.chain = Promise.resolve();
  }

  markDirty() {
    this.dirty = true;
    if (!this.timer) this.timer = setTimeout(() => { this.timer = null; void this.flush(); }, 250);
  }

  async flush() {
    if (!this.dirty) return;
    this.dirty = false;
    const snapshot = structuredClone(this.state);
    this.chain = this.chain.then(() => writeEncrypted(this.file, this.key, snapshot));
    try { await this.chain; } catch (error) { this.dirty = true; throw error; }
  }
}

module.exports = {
  PersistenceError,
  StateStore,
  atomicWriteJson,
  createVerifiedBackup,
  decryptPayload,
  defaultState,
  encryptPayload,
  encryptedWrapper,
  keyFromHex,
  loadState,
  readEncrypted,
  readJsonStrict,
  resolveDataKey,
  writeEncrypted,
};
