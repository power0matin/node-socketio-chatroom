'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createApplication } = require('../src/server');
const { connect, login, makeRuntime, once, resume } = require('./helpers');

async function closeSockets(...sockets) {
  for (const socket of sockets) if (socket?.connected) socket.close();
}

test('health and readiness reflect an operational runtime', async (t) => {
  const ctx = await makeRuntime();
  t.after(() => ctx.cleanup());
  const health = await fetch(`${ctx.url}/healthz`);
  const ready = await fetch(`${ctx.url}/readyz`);
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { status: 'ok' });
  assert.equal(ready.status, 200);
  assert.deepEqual(await ready.json(), { status: 'ready' });
});

test('registration, login failure, restart resume and logout revocation work', async (t) => {
  const ctx = await makeRuntime();
  t.after(() => ctx.cleanup());
  const alice = await connect(ctx.url);
  t.after(() => closeSockets(alice));
  const first = await login(alice, 'alice', 'AlicePass123!');
  assert.equal(first.username, 'alice');
  assert.ok(first.sessionToken);

  const wrong = await connect(ctx.url);
  t.after(() => closeSockets(wrong));
  const wrongError = once(wrong, 'login_error');
  wrong.emit('login', { username: 'alice', password: 'wrong-password' });
  assert.match(await wrongError, /اشتباه/);
  wrong.close();

  alice.close();
  await ctx.runtime.stop('restart-test');
  const restarted = await createApplication({
    rootDir: ctx.rootDir,
    dataDir: ctx.dataDir,
    uploadsDir: ctx.uploadsDir,
    backupRoot: ctx.backupRoot,
    env: {},
  });
  await restarted.start();
  t.after(async () => { try { await restarted.stop('test'); } catch {} });
  const resumedSocket = await connect(ctx.url);
  t.after(() => closeSockets(resumedSocket));
  const resumedEvent = once(resumedSocket, 'session_resumed');
  assert.deepEqual(await resume(resumedSocket, first.sessionToken), { ok: true });
  assert.equal((await resumedEvent).username, 'alice');

  const logoutAck = new Promise((resolve) => resumedSocket.emit('logout', resolve));
  assert.deepEqual(await logoutAck, { ok: true });
  const stale = await connect(ctx.url);
  t.after(() => closeSockets(stale));
  assert.deepEqual(await resume(stale, first.sessionToken), { ok: false, error: 'INVALID_SESSION' });
});

test('password change revokes every other session and refreshes the actor', async (t) => {
  const ctx = await makeRuntime();
  t.after(() => ctx.cleanup());
  const a = await connect(ctx.url);
  const b = await connect(ctx.url);
  t.after(() => closeSockets(a, b));
  const loginA = await login(a, 'alice', 'AlicePass123!');
  const loginB = await login(b, 'alice', 'AlicePass123!');
  const kicked = once(b, 'force_disconnect');
  const refresh = once(a, 'session_refresh');
  const ack = new Promise((resolve) => a.emit('change_password', {
    currentPassword: 'AlicePass123!', newPassword: 'NewAlicePass456!'
  }, resolve));
  assert.deepEqual(await ack, { ok: true });
  assert.match(await kicked, /رمز عبور/);
  const refreshed = await refresh;
  assert.ok(refreshed.sessionToken);
  assert.notEqual(refreshed.sessionToken, loginA.sessionToken);

  const staleA = await connect(ctx.url);
  const staleB = await connect(ctx.url);
  t.after(() => closeSockets(staleA, staleB));
  assert.equal((await resume(staleA, loginA.sessionToken)).ok, false);
  assert.equal((await resume(staleB, loginB.sessionToken)).ok, false);

  const relogin = await connect(ctx.url);
  t.after(() => closeSockets(relogin));
  assert.equal((await login(relogin, 'alice', 'NewAlicePass456!')).username, 'alice');
});

test('role changes synchronize all live sessions and invalidate all old tokens', async (t) => {
  const ctx = await makeRuntime();
  t.after(() => ctx.cleanup());
  const admin = await connect(ctx.url);
  const a = await connect(ctx.url);
  const b = await connect(ctx.url);
  t.after(() => closeSockets(admin, a, b));
  await login(admin, 'admin', ctx.adminPassword);
  const oldA = await login(a, 'alice', 'AlicePass123!');
  const oldB = await login(b, 'alice', 'AlicePass123!');

  const roleA = once(a, 'role_update');
  const roleB = once(b, 'role_update');
  const refreshA = once(a, 'session_refresh');
  const refreshB = once(b, 'session_refresh');
  admin.emit('set_role', { targetUsername: 'alice', role: 'vip' });
  assert.equal(await roleA, 'vip');
  assert.equal(await roleB, 'vip');
  assert.equal((await refreshA).role, 'vip');
  assert.equal((await refreshB).role, 'vip');
  assert.equal(ctx.runtime.state.users.alice.role, 'vip');

  const stale1 = await connect(ctx.url);
  const stale2 = await connect(ctx.url);
  t.after(() => closeSockets(stale1, stale2));
  assert.equal((await resume(stale1, oldA.sessionToken)).ok, false);
  assert.equal((await resume(stale2, oldB.sessionToken)).ok, false);
});

test('DM reaches a recipient that never joined the DM room and crafted targets fail', async (t) => {
  const ctx = await makeRuntime();
  t.after(() => ctx.cleanup());
  const alice = await connect(ctx.url);
  const bob = await connect(ctx.url);
  t.after(() => closeSockets(alice, bob));
  await login(alice, 'alice', 'AlicePass123!');
  await login(bob, 'bob', 'BobPass123!');

  const joinAck = await new Promise((resolve) => alice.emit('join_private', 'bob', resolve));
  assert.equal(joinAck.ok, true);
  const incoming = once(bob, 'receive_message');
  alice.emit('send_message', { conversationId: joinAck.dmId, type: 'text', text: 'hello bob' });
  const message = await incoming;
  assert.equal(message.text, 'hello bob');
  assert.equal(message.sender, 'alice');

  const missing = await new Promise((resolve) => alice.emit('join_private', 'ghost', resolve));
  assert.deepEqual(missing, { ok: false, error: 'TARGET_NOT_FOUND' });
  const craftedError = once(alice, 'error');
  alice.emit('send_message', { conversationId: 'alice_pv_ghost', type: 'text', text: 'nope' });
  assert.match(await craftedError, /نامعتبر/);
});

test('non-admin crafted role event cannot escalate privileges', async (t) => {
  const ctx = await makeRuntime();
  t.after(() => ctx.cleanup());
  const alice = await connect(ctx.url);
  t.after(() => closeSockets(alice));
  await login(alice, 'alice', 'AlicePass123!');
  alice.emit('set_role', { targetUsername: 'alice', role: 'vip' });
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(ctx.runtime.state.users.alice.role, 'user');
});
