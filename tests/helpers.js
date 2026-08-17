'use strict';

const fs = require('fs').promises;
const net = require('net');
const os = require('os');
const path = require('path');
const bcrypt = require('bcryptjs');
const { io: clientIo } = require('socket.io-client');
const { createApplication } = require('../src/server');

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

async function makeRuntime(options = {}) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), 'chatroom-test-'));
  const rootDir = path.join(base, 'app');
  const dataDir = path.join(rootDir, 'data');
  const uploadsDir = path.join(rootDir, 'public', 'uploads');
  const backupRoot = path.join(base, 'backups');
  await fs.mkdir(dataDir, { recursive: true });
  const port = await freePort();
  const adminPassword = options.adminPassword || 'AdminPass123!';
  const config = {
    adminUser: 'admin',
    adminPassHash: await bcrypt.hash(adminPassword, 4),
    adminSessionVersion: 1,
    port,
    bindHost: '127.0.0.1',
    maxFileSizeMB: options.maxFileSizeMB || 1,
    maxFilesPerUser: options.maxFilesPerUser || 10,
    userQuotaMB: options.userQuotaMB || 2,
    globalQuotaMB: options.globalQuotaMB || 10,
    minFreeDiskMB: 32,
    uploadRetentionDays: 30,
    appName: 'Test Chatroom',
    hideUserList: false,
    allowedOrigins: [`http://127.0.0.1:${port}`],
    protectUploads: true,
    accessMode: options.accessMode || 'open',
    defaultChannelsForNewUsers: ['General'],
    maxChannelMessages: 100,
    maxDmMessages: 100,
    maxSavedMessages: 100,
    sessionTtlHours: 24,
    trustProxy: true,
  };
  await fs.writeFile(path.join(dataDir, 'config.json'), JSON.stringify(config, null, 2));
  const runtime = await createApplication({ rootDir, dataDir, uploadsDir, backupRoot, env: {} });
  await runtime.start();
  const url = `http://127.0.0.1:${port}`;
  return {
    base, rootDir, dataDir, uploadsDir, backupRoot, port, url, adminPassword, runtime,
    async cleanup() {
      try { await runtime.stop('test'); } catch {}
      await fs.rm(base, { recursive: true, force: true });
    },
  };
}

function connect(url) {
  return new Promise((resolve, reject) => {
    const socket = clientIo(url, { transports: ['websocket'], forceNew: true, reconnection: false });
    const timer = setTimeout(() => { socket.close(); reject(new Error('socket connect timeout')); }, 5000);
    socket.once('connect', () => { clearTimeout(timer); resolve(socket); });
    socket.once('connect_error', (error) => { clearTimeout(timer); reject(error); });
  });
}

function once(socket, event, timeout = 4000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.off(event, handler); reject(new Error(`timeout waiting for ${event}`)); }, timeout);
    const handler = (...args) => { clearTimeout(timer); resolve(args.length <= 1 ? args[0] : args); };
    socket.once(event, handler);
  });
}

async function login(socket, username, password) {
  const success = once(socket, 'login_success');
  const failure = once(socket, 'login_error').then((message) => { throw new Error(`login failed: ${message}`); });
  socket.emit('login', { username, password });
  return Promise.race([success, failure]);
}

async function resume(socket, token) {
  const response = new Promise((resolve) => socket.emit('resume_session', token, resolve));
  const result = await response;
  return result;
}

module.exports = { connect, freePort, login, makeRuntime, once, resume };
