'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  cleanupSessions,
  createSessionToken,
  registerSession,
  revokeAllSessions,
  revokeSession,
  validateSessionToken,
  verifySession,
} = require('../src/lib/security');

const secret = Buffer.alloc(32, 9);
const config = { adminUser: 'admin', adminSessionVersion: 1 };

function context(sessions, users = { alice: { role: 'user', isBanned: false, sessionVersion: 1 } }) {
  return { config, persistentUsers: users, sessions };
}

test('signed sessions validate only while registered', () => {
  const sessions = {};
  const issued = createSessionToken(secret, { username: 'alice', role: 'user', sessionVersion: 1, ttlHours: 1 });
  assert.equal(validateSessionToken(secret, issued.token, context(sessions)), null);
  registerSession(sessions, issued.payload);
  assert.equal(validateSessionToken(secret, issued.token, context(sessions)).username, 'alice');
});

test('tampering invalidates a session', () => {
  const issued = createSessionToken(secret, { username: 'alice', role: 'user', sessionVersion: 1, ttlHours: 1 });
  assert.equal(verifySession(secret, `${issued.token}x`), null);
});

test('individual logout and global revocation are enforced', () => {
  const sessions = {};
  const a = createSessionToken(secret, { username: 'alice', role: 'user', sessionVersion: 1, ttlHours: 1 });
  const b = createSessionToken(secret, { username: 'alice', role: 'user', sessionVersion: 1, ttlHours: 1 });
  registerSession(sessions, a.payload);
  registerSession(sessions, b.payload);
  revokeSession(sessions, 'alice', a.payload.jti);
  assert.equal(validateSessionToken(secret, a.token, context(sessions)), null);
  assert.ok(validateSessionToken(secret, b.token, context(sessions)));
  revokeAllSessions(sessions, 'alice');
  assert.equal(validateSessionToken(secret, b.token, context(sessions)), null);
});

test('ban, role or session version mismatch invalidates old tokens', () => {
  const sessions = {};
  const issued = createSessionToken(secret, { username: 'alice', role: 'vip', sessionVersion: 2, ttlHours: 1 });
  registerSession(sessions, issued.payload);
  assert.equal(validateSessionToken(secret, issued.token, context(sessions, { alice: { role: 'user', isBanned: false, sessionVersion: 2 } })), null);
  assert.equal(validateSessionToken(secret, issued.token, context(sessions, { alice: { role: 'vip', isBanned: true, sessionVersion: 2 } })), null);
  assert.equal(validateSessionToken(secret, issued.token, context(sessions, { alice: { role: 'vip', isBanned: false, sessionVersion: 3 } })), null);
});

test('expired session registry entries are cleaned', () => {
  const sessions = { alice: { dead: Date.now() - 1, live: Date.now() + 10000 } };
  assert.equal(cleanupSessions(sessions), true);
  assert.equal('dead' in sessions.alice, false);
  assert.equal('live' in sessions.alice, true);
});
