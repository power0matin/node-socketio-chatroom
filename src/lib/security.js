'use strict';

const crypto = require('crypto');
const fsp = require('fs').promises;
const path = require('path');

function timingSafeTextEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

async function getOrCreateSecret(file, bytes = 32) {
  try {
    const raw = (await fsp.readFile(file, 'utf8')).trim();
    if (!/^[0-9a-f]{64,}$/i.test(raw)) throw new Error(`Invalid secret file: ${file}`);
    return Buffer.from(raw, 'hex');
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  await fsp.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const raw = crypto.randomBytes(bytes).toString('hex');
  await fsp.writeFile(file, raw, { flag: 'wx', mode: 0o600 });
  return Buffer.from(raw, 'hex');
}

function signSession(secret, payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifySession(secret, token) {
  const [body, signature, extra] = String(token || '').split('.');
  if (!body || !signature || extra) return null;
  const expected = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  if (!timingSafeTextEqual(signature, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload || payload.v !== 1 || !payload.u || !payload.jti || !payload.exp || Date.now() >= payload.exp) return null;
    return payload;
  } catch { return null; }
}

function createSessionToken(secret, { username, role, sessionVersion, ttlHours }) {
  const now = Date.now();
  const payload = {
    v: 1,
    u: username,
    r: role,
    sv: Number(sessionVersion || 1),
    iat: now,
    exp: now + Number(ttlHours) * 60 * 60 * 1000,
    jti: crypto.randomBytes(16).toString('hex'),
  };
  return { token: signSession(secret, payload), payload };
}

function sessionBucket(sessions, username, create = false) {
  if (!sessions[username] && create) sessions[username] = {};
  return sessions[username] || null;
}

function registerSession(sessions, payload) {
  sessionBucket(sessions, payload.u, true)[payload.jti] = payload.exp;
}

function revokeSession(sessions, username, jti) {
  const bucket = sessionBucket(sessions, username);
  if (!bucket) return;
  delete bucket[jti];
  if (!Object.keys(bucket).length) delete sessions[username];
}

function revokeAllSessions(sessions, username) { delete sessions[username]; }

function cleanupSessions(sessions, now = Date.now()) {
  let changed = false;
  for (const [username, bucket] of Object.entries(sessions || {})) {
    if (!bucket || typeof bucket !== 'object') { delete sessions[username]; changed = true; continue; }
    for (const [jti, exp] of Object.entries(bucket)) {
      if (!Number.isFinite(Number(exp)) || Number(exp) <= now) { delete bucket[jti]; changed = true; }
    }
    if (!Object.keys(bucket).length) { delete sessions[username]; changed = true; }
  }
  return changed;
}

function validateSessionToken(secret, token, { config, persistentUsers, sessions }) {
  const payload = verifySession(secret, token);
  if (!payload) return null;
  const bucket = sessionBucket(sessions || {}, payload.u);
  if (!bucket || Number(bucket[payload.jti]) !== Number(payload.exp)) return null;

  if (payload.u === config.adminUser) {
    if (payload.r !== 'admin' || payload.sv !== config.adminSessionVersion) return null;
    return { username: payload.u, role: 'admin', sessionVersion: payload.sv, payload };
  }
  const record = persistentUsers[payload.u];
  if (!record || record.isBanned) return null;
  const expectedVersion = Number(record.sessionVersion || 1);
  const role = record.role || 'user';
  if (payload.sv !== expectedVersion || payload.r !== role) return null;
  return { username: payload.u, role, sessionVersion: expectedVersion, payload };
}

module.exports = { cleanupSessions, createSessionToken, getOrCreateSecret, registerSession, revokeAllSessions, revokeSession, signSession, validateSessionToken, verifySession };
