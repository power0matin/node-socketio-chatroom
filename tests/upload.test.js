'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { connect, login, makeRuntime } = require('./helpers');

async function upload(url, token, blob, filename) {
  const form = new FormData();
  form.append('file', blob, filename);
  return fetch(`${url}/upload`, {
    method: 'POST',
    headers: { 'X-Auth-Token': token },
    body: form,
  });
}

test('valid upload returns a per-file capability rather than leaking session token', async (t) => {
  const ctx = await makeRuntime();
  t.after(() => ctx.cleanup());
  const socket = await connect(ctx.url);
  t.after(() => socket.close());
  const auth = await login(socket, 'alice', 'AlicePass123!');
  const response = await upload(ctx.url, auth.sessionToken, new Blob(['hello'], { type: 'text/plain' }), 'hello.txt');
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.match(body.url, /^\/uploads\/[0-9a-f]{36}\?d=/);
  assert.equal(body.url.includes(auth.sessionToken), false);
  const download = await fetch(`${ctx.url}${body.url}`);
  assert.equal(download.status, 200);
  assert.equal(await download.text(), 'hello');
});

test('invalid MIME-extension combinations and malformed multipart are rejected', async (t) => {
  const ctx = await makeRuntime();
  t.after(() => ctx.cleanup());
  const socket = await connect(ctx.url);
  t.after(() => socket.close());
  const auth = await login(socket, 'alice', 'AlicePass123!');

  const mismatch = await upload(ctx.url, auth.sessionToken, new Blob(['not png'], { type: 'image/png' }), 'payload.txt');
  assert.equal(mismatch.status, 400);

  const malformedBody = '--broken\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\n';
  const malformed = await fetch(`${ctx.url}/upload`, {
    method: 'POST',
    headers: {
      'X-Auth-Token': auth.sessionToken,
      'Content-Type': 'multipart/form-data; boundary=broken',
      'Content-Length': String(Buffer.byteLength(malformedBody)),
    },
    body: malformedBody,
  });
  assert.equal(malformed.status, 400);
});

test('oversized files are rejected and not committed', async (t) => {
  const ctx = await makeRuntime({ maxFileSizeMB: 1 });
  t.after(() => ctx.cleanup());
  const socket = await connect(ctx.url);
  t.after(() => socket.close());
  const auth = await login(socket, 'alice', 'AlicePass123!');
  const response = await upload(ctx.url, auth.sessionToken, new Blob([Buffer.alloc(1024 * 1024 + 64 * 1024)], { type: 'application/pdf' }), 'large.pdf');
  assert.equal(response.status, 413);
  assert.equal(Object.keys(ctx.runtime.state.attachments).length, 0);
});

test('per-user quota prevents storage exhaustion', async (t) => {
  const ctx = await makeRuntime({ maxFileSizeMB: 1, userQuotaMB: 1 });
  t.after(() => ctx.cleanup());
  const socket = await connect(ctx.url);
  t.after(() => socket.close());
  const auth = await login(socket, 'alice', 'AlicePass123!');
  const payload = Buffer.alloc(700 * 1024, 1);
  const first = await upload(ctx.url, auth.sessionToken, new Blob([payload], { type: 'application/pdf' }), 'a.pdf');
  assert.equal(first.status, 200);
  const second = await upload(ctx.url, auth.sessionToken, new Blob([payload], { type: 'application/pdf' }), 'b.pdf');
  assert.equal(second.status, 507);
  assert.equal(Object.keys(ctx.runtime.state.attachments).length, 1);
});

test('revoked session token cannot upload', async (t) => {
  const ctx = await makeRuntime();
  t.after(() => ctx.cleanup());
  const socket = await connect(ctx.url);
  const auth = await login(socket, 'alice', 'AlicePass123!');
  await new Promise((resolve) => socket.emit('logout', resolve));
  const response = await upload(ctx.url, auth.sessionToken, new Blob(['blocked'], { type: 'text/plain' }), 'blocked.txt');
  assert.equal(response.status, 401);
});
