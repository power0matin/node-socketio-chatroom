'use strict';

const crypto = require('crypto');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

function timingSafeTextEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

async function getOrCreateSecret(file, bytes = 32) {
  try {
    const raw = (await fsp.readFile(file, 'utf8')).trim();
    if (!/^[0-9a-f]{64,}$/i.test(raw)) throw new Error(`Invalid secret file: ${file}`);
    return Buffer.from(raw, 'hex');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  await fsp.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const raw = crypto.randomBytes(bytes).toString('hex');
  await fsp.writeFile(file, raw, { flag: 'wx', mode: 0o600 });
  return Buffer.from(raw, 'hex');
}

function b64url(value) {
  return Buffer.from(value).toString('base64url');
}

function signSession(secret, payload) {
  const body = b64url(JSON.stringify(payload));
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
    if (!payload || payload.v !== 1 || !payload.u || !payload.exp || Date.now() >= payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function createSessionToken(secret, { username, role, sessionVersion, ttlHours }) {
  const now = Date.now();
  return signSession(secret, {
    v: 1,
    u: username,
    r: role,
    sv: Number(sessionVersion || 1),
    iat: now,
    exp: now + Number(ttlHours) * 60 * 60 * 1000,
    jti: crypto.randomBytes(12).toString('hex'),
  });
}

function validateSessionToken(secret, token, { config, persistentUsers }) {
  const payload = verifySession(secret, token);
  if (!payload) return null;
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

module.exports = { createSessionToken, getOrCreateSecret, signSession, validateSessionToken, verifySession };
