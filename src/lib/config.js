'use strict';

const path = require('path');
const bcrypt = require('bcryptjs');
const { atomicWriteJson, readJsonStrict } = require('./storage');

class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
    this.code = 'CONFIG_ERROR';
  }
}

const DEFAULTS = Object.freeze({
  adminUser: 'admin',
  adminPassHash: '',
  adminSessionVersion: 1,
  port: 3000,
  bindHost: '127.0.0.1',
  maxFileSizeMB: 50,
  maxFilesPerUser: 200,
  userQuotaMB: 1024,
  globalQuotaMB: 10240,
  minFreeDiskMB: 512,
  uploadRetentionDays: 30,
  appName: 'node-socketio-chatroom',
  hideUserList: false,
  allowedOrigins: ['http://localhost:3000'],
  protectUploads: true,
  accessMode: 'restricted',
  defaultChannelsForNewUsers: ['General'],
  maxChannelMessages: 100,
  maxDmMessages: 500,
  maxSavedMessages: 1000,
  sessionTtlHours: 24,
  trustProxy: true,
});

function integer(name, value, min, max) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) throw new ConfigError(`${name} must be an integer between ${min} and ${max}.`);
  return n;
}

function boolean(name, value) {
  if (typeof value !== 'boolean') throw new ConfigError(`${name} must be a boolean.`);
  return value;
}

function validUsername(value) {
  const s = String(value || '').trim();
  return /^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$/.test(s) && !s.includes('_pv_') && !s.startsWith('__saved__');
}

function username(value) {
  const s = String(value || '').trim();
  if (!validUsername(s)) {
    throw new ConfigError('adminUser must be 3-32 characters using letters, digits, dot, dash or underscore and may not contain reserved identifiers.');
  }
  return s;
}

function origins(value) {
  const raw = Array.isArray(value) ? value : String(value || '').split(',');
  const items = raw.map((v) => String(v).trim()).filter(Boolean);
  if (!items.length) throw new ConfigError('allowedOrigins must contain at least one explicit origin. Wildcard origins are not allowed.');
  const out = [];
  for (const item of items) {
    if (item === '*') throw new ConfigError('allowedOrigins cannot be "*" in production-safe mode.');
    let parsed;
    try { parsed = new URL(item); } catch { throw new ConfigError(`Invalid origin: ${item}`); }
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
      throw new ConfigError(`Origin must be scheme + host + optional port only: ${item}`);
    }
    out.push(parsed.origin);
  }
  return [...new Set(out)];
}

function validateConfig(input) {
  const cfg = { ...DEFAULTS, ...(input || {}) };
  cfg.adminUser = username(cfg.adminUser);
  if (cfg.adminPassHash && !String(cfg.adminPassHash).startsWith('$2')) throw new ConfigError('adminPassHash must be a bcrypt hash.');
  cfg.adminSessionVersion = integer('adminSessionVersion', cfg.adminSessionVersion, 1, Number.MAX_SAFE_INTEGER);
  cfg.port = integer('port', cfg.port, 1, 65535);
  cfg.bindHost = String(cfg.bindHost || '').trim();
  if (!['127.0.0.1', '::1', '0.0.0.0', '::'].includes(cfg.bindHost)) throw new ConfigError('bindHost must be a valid supported bind address. Use 127.0.0.1 behind Nginx.');
  cfg.maxFileSizeMB = integer('maxFileSizeMB', cfg.maxFileSizeMB, 1, 100);
  cfg.maxFilesPerUser = integer('maxFilesPerUser', cfg.maxFilesPerUser, 1, 5000);
  cfg.userQuotaMB = integer('userQuotaMB', cfg.userQuotaMB, 1, 102400);
  cfg.globalQuotaMB = integer('globalQuotaMB', cfg.globalQuotaMB, 10, 1048576);
  cfg.minFreeDiskMB = integer('minFreeDiskMB', cfg.minFreeDiskMB, 32, 1048576);
  cfg.uploadRetentionDays = integer('uploadRetentionDays', cfg.uploadRetentionDays, 1, 3650);
  cfg.sessionTtlHours = integer('sessionTtlHours', cfg.sessionTtlHours, 1, 720);
  cfg.maxChannelMessages = integer('maxChannelMessages', cfg.maxChannelMessages, 10, 10000);
  cfg.maxDmMessages = integer('maxDmMessages', cfg.maxDmMessages, 10, 20000);
  cfg.maxSavedMessages = integer('maxSavedMessages', cfg.maxSavedMessages, 10, 20000);
  cfg.hideUserList = boolean('hideUserList', cfg.hideUserList);
  cfg.protectUploads = boolean('protectUploads', cfg.protectUploads);
  cfg.trustProxy = boolean('trustProxy', cfg.trustProxy);
  cfg.allowedOrigins = origins(cfg.allowedOrigins);
  cfg.appName = String(cfg.appName || '').trim().slice(0, 80);
  if (!cfg.appName) throw new ConfigError('appName may not be empty.');
  cfg.accessMode = String(cfg.accessMode || 'restricted');
  if (!['restricted', 'open'].includes(cfg.accessMode)) throw new ConfigError('accessMode must be restricted or open.');
  if (!Array.isArray(cfg.defaultChannelsForNewUsers)) throw new ConfigError('defaultChannelsForNewUsers must be an array.');
  cfg.defaultChannelsForNewUsers = cfg.defaultChannelsForNewUsers.map((v) => String(v).trim()).filter(Boolean).slice(0, 100);
  delete cfg.adminPass;
  delete cfg.dataEncKey;
  return cfg;
}

async function loadConfig(dataDir, env = process.env) {
  const file = path.join(dataDir, 'config.json');
  let raw = await readJsonStrict(file, { missing: null });
  let changed = false;
  if (!raw) { raw = { ...DEFAULTS }; changed = true; }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new ConfigError('config.json must contain a JSON object.');

  const legacyDataEncKey = Object.prototype.hasOwnProperty.call(raw, 'dataEncKey') ? raw.dataEncKey : undefined;

  if (raw.adminPass && !raw.adminPassHash) {
    raw.adminPassHash = await bcrypt.hash(String(raw.adminPass), 12);
    delete raw.adminPass;
    changed = true;
  }
  if (raw.adminPassHash && !String(raw.adminPassHash).startsWith('$2')) {
    raw.adminPassHash = await bcrypt.hash(String(raw.adminPassHash), 12);
    changed = true;
  }

  const merged = { ...DEFAULTS, ...raw };
  if (env.PORT !== undefined) merged.port = env.PORT;
  if (env.BIND_HOST) merged.bindHost = env.BIND_HOST;
  if (env.ALLOWED_ORIGINS) merged.allowedOrigins = env.ALLOWED_ORIGINS;
  if (env.TRUST_PROXY !== undefined) merged.trustProxy = env.TRUST_PROXY === '1';
  const cfg = validateConfig(merged);

  // Crash-safe migration rule: retain legacy dataEncKey on disk until the caller
  // has durably created .data-key AND validated/decrypted all persistence.
  const persistable = { ...cfg };
  if (legacyDataEncKey !== undefined) persistable.dataEncKey = legacyDataEncKey;
  if (changed || JSON.stringify(persistable) !== JSON.stringify(raw)) await atomicWriteJson(file, persistable, 0o600);
  return { config: cfg, file, legacyDataEncKey };
}

async function saveConfig(file, config) {
  const validated = validateConfig(config);
  await atomicWriteJson(file, validated, 0o600);
  return validated;
}

module.exports = { ConfigError, DEFAULTS, loadConfig, saveConfig, validateConfig, origins, validUsername };
