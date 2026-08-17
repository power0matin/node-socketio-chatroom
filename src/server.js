'use strict';

const crypto = require('crypto');
const fs = require('fs');
const fsp = fs.promises;
const http = require('http');
const net = require('net');
const path = require('path');
const bcrypt = require('bcryptjs');
const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const multer = require('multer');
const { Server } = require('socket.io');
const xss = require('xss');

const { loadConfig, saveConfig, validUsername } = require('./lib/config');
const logger = require('./lib/logger');
const {
  StateStore,
  loadState,
  resolveDataKey,
} = require('./lib/storage');
const {
  cleanupSessions,
  createSessionToken,
  getOrCreateSecret,
  registerSession,
  revokeAllSessions,
  revokeSession,
  validateSessionToken,
} = require('./lib/security');
const {
  UploadError,
  attachmentUsage,
  capabilityToken,
  cleanupUploads,
  validateFileMeta,
  verifyCapability,
} = require('./lib/uploads');

const APP_COMPONENT = 'server';
const RESERVED_SAVED_PREFIX = '__saved__';
const DM_SEPARATOR = '_pv_';

function cleanText(value, max = 1000) {
  const text = xss(String(value || ''));
  return text.length > max ? text.slice(0, max) : text;
}

function cleanChannelName(value) {
  return xss(String(value || '').trim()).slice(0, 30);
}

function cleanUsername(value) {
  const valueString = String(value || '').trim();
  return validUsername(valueString) ? valueString : '';
}

function isLoopback(value) {
  const ip = String(value || '').replace(/^::ffff:/, '');
  return ip === '127.0.0.1' || ip === '::1';
}

function exactOriginAllowed(origin, allowedOrigins) {
  if (!origin) return true;
  try {
    const parsed = new URL(origin);
    return allowedOrigins.includes(parsed.origin) && parsed.pathname === '/' && !parsed.search && !parsed.hash;
  } catch {
    return false;
  }
}

function dmKeyFor(a, b) {
  return [String(a), String(b)].sort().join(DM_SEPARATOR);
}

function dmParticipants(id) {
  const parts = String(id || '').split(DM_SEPARATOR);
  if (parts.length !== 2 || !validUsername(parts[0]) || !validUsername(parts[1]) || parts[0] === parts[1]) return null;
  return { a: parts[0], b: parts[1] };
}

function savedConversationId(username) {
  return `${RESERVED_SAVED_PREFIX}${username}`;
}

function isSavedConversation(id) {
  return typeof id === 'string' && id.startsWith(RESERVED_SAVED_PREFIX);
}

function personalRoom(username) {
  return `user:${username}`;
}

function messageAttachmentId(content) {
  if (typeof content !== 'string') return null;
  try {
    const parsed = new URL(content, 'http://localhost');
    const match = parsed.pathname.match(/^\/uploads\/([0-9a-f]{36})$/i);
    return match ? { id: match[1], capability: parsed.searchParams.get('d') || '' } : null;
  } catch {
    return null;
  }
}

async function createApplication(options = {}) {
  const rootDir = path.resolve(options.rootDir || path.join(__dirname, '..'));
  const env = options.env || process.env;
  const dataDir = path.resolve(options.dataDir || env.DATA_DIR || path.join(rootDir, 'data'));
  const publicDir = path.resolve(options.publicDir || path.join(rootDir, 'public'));
  const uploadsDir = path.resolve(options.uploadsDir || path.join(publicDir, 'uploads'));
  const backupRoot = path.resolve(options.backupRoot || env.BACKUP_ROOT || path.join(path.dirname(rootDir), '.node-socketio-chatroom-backups'));
  if (backupRoot === rootDir || backupRoot.startsWith(`${rootDir}${path.sep}`)) {
    throw new Error('BACKUP_ROOT must be outside the application directory so updates cannot delete backups.');
  }

  await fsp.mkdir(dataDir, { recursive: true, mode: 0o700 });
  await fsp.mkdir(uploadsDir, { recursive: true, mode: 0o700 });
  await fsp.mkdir(backupRoot, { recursive: true, mode: 0o700 });

  const loadedConfig = await loadConfig(dataDir, env);
  let config = loadedConfig.config;
  const keyInfo = await resolveDataKey({
    dataDir,
    config: { dataEncKey: loadedConfig.legacyDataEncKey },
    env,
  });
  const loaded = await loadState({ dataDir, key: keyInfo.key, backupRoot });
  const stateFile = path.join(dataDir, 'state.json');
  const state = loaded.state;
  const store = new StateStore(stateFile, keyInfo.key, state);

  if (loadedConfig.legacyDataEncKey !== undefined) {
    config = await saveConfig(loadedConfig.file, config);
    logger.info('migration', 'legacy encryption key migrated to dedicated key file', { source: keyInfo.source });
  }
  if (loaded.migrated) logger.info('migration', 'legacy persistence migrated to atomic state', { backup: loaded.backup?.dir });

  const sessionSecret = await getOrCreateSecret(path.join(dataDir, '.session-key'));
  const downloadSecret = await getOrCreateSecret(path.join(dataDir, '.download-key'));

  state.sessions ||= {};
  state.attachments ||= {};
  state.users ||= {};
  state.messages ||= {};
  state.conversations ||= {};
  state.memberships ||= {};
  if (!Array.isArray(state.channels)) state.channels = ['General', 'Random'];

  function markDirty() { store.markDirty(); }

  function ensureConversationMaps(id) {
    if (!state.memberships[id]) state.memberships[id] = {};
    if (!state.messages[id]) state.messages[id] = [];
  }

  function addMember(id, username, role = 'member') {
    ensureConversationMaps(id);
    if (!state.memberships[id][username]) {
      state.memberships[id][username] = { role, joinedAt: Date.now(), lastReadMessageId: null };
      markDirty();
    }
  }

  function removeMember(id, username) {
    if (state.memberships[id]?.[username]) {
      delete state.memberships[id][username];
      markDirty();
    }
  }

  function isMember(id, username) { return Boolean(state.memberships[id]?.[username]); }

  function ensurePublicConversation(channel, createdBy = 'system') {
    if (!state.conversations[channel]) {
      state.conversations[channel] = { id: channel, type: 'public', title: channel, isHidden: false, createdBy, createdAt: Date.now() };
      markDirty();
    }
    ensureConversationMaps(channel);
  }

  function targetExists(username) {
    return username === config.adminUser || Boolean(state.users[username] && !state.users[username].isBanned);
  }

  function getOrCreateDm(a, b) {
    if (!targetExists(a) || !targetExists(b) || a === b) return null;
    const id = dmKeyFor(a, b);
    if (!state.conversations[id]) {
      state.conversations[id] = { id, type: 'dm', title: `DM: ${a}, ${b}`, isHidden: true, dmKey: id, createdBy: a, createdAt: Date.now() };
      markDirty();
    }
    addMember(id, a, 'owner');
    addMember(id, b, 'member');
    return state.conversations[id];
  }

  function canAccessDm(username, id) {
    const participants = dmParticipants(id);
    return Boolean(participants && (username === participants.a || username === participants.b) && isMember(id, username));
  }

  function canAccessChannel(username, role, channel) {
    if (!state.channels.includes(channel)) return false;
    if (role === 'admin' || config.accessMode === 'open') return true;
    return isMember(channel, username);
  }

  function accessibleChannels(username, role) {
    return state.channels.filter((channel) => canAccessChannel(username, role, channel));
  }

  for (const [username, record] of Object.entries(state.users)) {
    if (!record || typeof record !== 'object') throw new Error(`Invalid user record for ${username}`);
    if (!validUsername(username)) throw new Error(`Legacy username is incompatible with safe identifiers: ${username}`);
    if (record.password && !record.passHash) {
      record.passHash = await bcrypt.hash(String(record.password), 12);
      delete record.password;
      markDirty();
    }
    if (record.passHash && !String(record.passHash).startsWith('$2')) {
      record.passHash = await bcrypt.hash(String(record.passHash), 12);
      markDirty();
    }
    if (!Number.isInteger(record.sessionVersion) || record.sessionVersion < 1) {
      record.sessionVersion = 1;
      markDirty();
    }
  }

  for (const channel of state.channels) ensurePublicConversation(channel);
  if (config.accessMode === 'restricted') {
    for (const channel of state.channels) addMember(channel, config.adminUser, 'owner');
  }
  if (cleanupSessions(state.sessions)) markDirty();
  await store.flush();

  const app = express();
  app.disable('x-powered-by');
  if (config.trustProxy) {
    app.set('trust proxy', (ip) => isLoopback(ip));
  } else {
    app.set('trust proxy', false);
  }

  let shuttingDown = false;
  let ready = false;

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com', 'https://unpkg.com'],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
        imgSrc: ["'self'", 'data:', 'blob:'],
        mediaSrc: ["'self'", 'blob:'],
        connectSrc: ["'self'", 'ws:', 'wss:'],
        objectSrc: ["'none'"],
        frameSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
  }));
  app.use((req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(self), geolocation=()');
    res.setHeader('Referrer-Policy', 'no-referrer');
    if (req.secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
  });
  app.use(express.json({ limit: '16kb' }));

  app.get('/healthz', (_req, res) => res.status(shuttingDown ? 503 : 200).json({ status: shuttingDown ? 'shutting-down' : 'ok' }));
  app.get('/readyz', (_req, res) => {
    const ok = ready && !shuttingDown && store.isReady();
    res.status(ok ? 200 : 503).json({ status: ok ? 'ready' : 'not-ready' });
  });

  const server = http.createServer(app);
  const io = new Server(server, {
    maxHttpBufferSize: 2e6,
    cors: {
      origin(origin, callback) { callback(null, exactOriginAllowed(origin, config.allowedOrigins)); },
      methods: ['GET', 'POST'],
    },
  });

  const sockets = new Map();
  const loginAttempts = new Map();
  const userMessageLimits = new Map();

  function socketIp(socket) {
    const remote = String(socket.handshake.address || '').trim();
    if (config.trustProxy && isLoopback(remote)) {
      const forwarded = String(socket.handshake.headers['x-forwarded-for'] || '').split(',')[0].trim();
      if (net.isIP(forwarded)) return forwarded;
    }
    return remote || 'unknown';
  }

  function loginLimited(ip, username, recordFailure = false) {
    const now = Date.now();
    const key = `${ip}::${String(username).toLowerCase()}`;
    let rec = loginAttempts.get(key);
    if (!rec || now - rec.first > 10 * 60_000) rec = { first: now, count: 0 };
    if (recordFailure) rec.count += 1;
    loginAttempts.set(key, rec);
    return rec.count >= 12;
  }

  function authFromToken(token) {
    return validateSessionToken(sessionSecret, token, { config, persistentUsers: state.users, sessions: state.sessions });
  }

  async function issueSession(username, role, sessionVersion) {
    const issued = createSessionToken(sessionSecret, { username, role, sessionVersion, ttlHours: config.sessionTtlHours });
    registerSession(state.sessions, issued.payload);
    markDirty();
    await store.flush();
    return issued;
  }

  function attachSocket(socket, auth) {
    sockets.set(socket.id, { username: auth.username, role: auth.role, jti: auth.payload.jti });
    socket.data.auth = { username: auth.username, role: auth.role, jti: auth.payload.jti };
    socket.join(personalRoom(auth.username));
  }

  function leaveActiveConversation(socket) {
    const active = socket.data.activeConversation;
    if (active) socket.leave(active);
    socket.data.activeConversation = null;
  }

  function authPayload(username, role, token) {
    return {
      username,
      role,
      channels: accessibleChannels(username, role),
      settings: {
        maxFileSizeMB: config.maxFileSizeMB,
        appName: config.appName,
        hideUserList: config.hideUserList,
        accessMode: config.accessMode,
      },
      sessionToken: token,
      uploadToken: token,
    };
  }

  function onlineUsers() {
    const byName = new Map();
    for (const value of sockets.values()) byName.set(value.username, { username: value.username, role: value.role });
    return [...byName.values()];
  }

  function broadcastUserList() {
    const all = onlineUsers();
    const admins = all.filter((u) => u.role === 'admin');
    for (const socket of io.sockets.sockets.values()) {
      const me = sockets.get(socket.id);
      if (!me) continue;
      if (me.role === 'admin' || !config.hideUserList) socket.emit('user_list', all);
      else socket.emit('user_list', [...admins.filter((u) => u.username !== me.username), { username: me.username, role: me.role }]);
    }
  }

  function refreshChannelLists() {
    for (const socket of io.sockets.sockets.values()) {
      const me = sockets.get(socket.id);
      if (me) socket.emit('channels_list', accessibleChannels(me.username, me.role));
    }
  }

  function joinChannel(socket, channelName) {
    const me = sockets.get(socket.id);
    if (!me) return socket.emit('auth_required');
    const channel = cleanChannelName(channelName);
    if (!channel || !state.channels.includes(channel)) return socket.emit('error', 'کانال وجود ندارد.');
    if (!canAccessChannel(me.username, me.role, channel)) return socket.emit('access_denied', { channel, message: 'شما به این کانال دسترسی ندارید.' });
    ensurePublicConversation(channel);
    if (config.accessMode === 'restricted') addMember(channel, me.username);
    leaveActiveConversation(socket);
    socket.join(channel);
    socket.data.activeConversation = channel;
    socket.emit('channel_joined', { name: channel, isPrivate: false });
    socket.emit('history', state.messages[channel] || []);
  }

  function getReplySnapshot(conversationId, value) {
    const id = typeof value === 'string' ? value : String(value?.id || '');
    if (!id) return null;
    const source = (state.messages[conversationId] || []).find((message) => message?.id === id);
    if (!source) return false;
    return { id: source.id, sender: source.sender, text: cleanText(source.text, 200), type: source.type || 'text' };
  }

  function validateAttachmentMessage(content, username) {
    const parsed = messageAttachmentId(content);
    if (!parsed) return null;
    const record = state.attachments[parsed.id];
    if (!record || record.deletedAt || record.expiresAt <= Date.now() || record.owner !== username) return null;
    if (!verifyCapability(downloadSecret, parsed.id, parsed.capability)) return null;
    return record;
  }

  function emitMessage(conversationId, message) {
    const dm = dmParticipants(conversationId);
    if (dm) io.to(personalRoom(dm.a)).to(personalRoom(dm.b)).emit('receive_message', message);
    else if (isSavedConversation(conversationId)) io.to(personalRoom(message.sender)).emit('receive_message', message);
    else io.to(conversationId).emit('receive_message', message);
  }

  function findMessage(id) {
    for (const [conversationId, list] of Object.entries(state.messages)) {
      if (!Array.isArray(list)) continue;
      const message = list.find((entry) => entry?.id === id);
      if (message) return { conversationId, message };
    }
    return null;
  }

  function canReadConversation(user, role, conversationId) {
    if (isSavedConversation(conversationId)) return conversationId === savedConversationId(user);
    if (dmParticipants(conversationId)) return canAccessDm(user, conversationId);
    return canAccessChannel(user, role, conversationId);
  }

  async function revokeAndDisconnect(username, reason, exceptSocketId = null) {
    revokeAllSessions(state.sessions, username);
    markDirty();
    for (const [socketId, auth] of [...sockets.entries()]) {
      if (auth.username !== username || socketId === exceptSocketId) continue;
      const target = io.sockets.sockets.get(socketId);
      target?.emit('force_disconnect', reason);
      target?.disconnect(true);
      sockets.delete(socketId);
    }
  }

  io.on('connection', (socket) => {
    const safe = (name, handler) => socket.on(name, async (...args) => {
      try { await handler(...args); }
      catch (error) {
        logger.error('socket', `event ${name} failed`, { error: error.message, username: sockets.get(socket.id)?.username });
        socket.emit('error', 'خطای داخلی سرور.');
      }
    });

    safe('login', async (payload = {}) => {
      const ip = socketIp(socket);
      const username = cleanUsername(payload.username);
      const password = String(payload.password || '');
      if (!username || !password) return socket.emit('login_error', 'نام کاربری یا رمز عبور نامعتبر است.');
      if (loginLimited(ip, username)) return socket.emit('login_error', 'تلاش‌های ورود زیاد است. چند دقیقه بعد دوباره امتحان کنید.');

      let role;
      let sessionVersion;
      if (username === config.adminUser) {
        if (!config.adminPassHash || !(await bcrypt.compare(password, config.adminPassHash))) {
          loginLimited(ip, username, true);
          logger.warn('auth', 'admin login failed', { username, ip });
          return socket.emit('login_error', 'نام کاربری یا رمز عبور اشتباه است.');
        }
        role = 'admin';
        sessionVersion = config.adminSessionVersion;
      } else {
        let record = state.users[username];
        if (record) {
          if (record.isBanned || !record.passHash || !(await bcrypt.compare(password, record.passHash))) {
            loginLimited(ip, username, true);
            logger.warn('auth', 'user login failed', { username, ip });
            return socket.emit('login_error', 'نام کاربری یا رمز عبور اشتباه است.');
          }
        } else {
          record = state.users[username] = {
            passHash: await bcrypt.hash(password, 12), role: 'user', isBanned: false, created_at: Date.now(), sessionVersion: 1,
          };
          if (config.accessMode === 'restricted') {
            for (const channel of config.defaultChannelsForNewUsers) if (state.channels.includes(channel)) addMember(channel, username);
          }
          markDirty();
          logger.info('auth', 'user registered', { username, ip });
        }
        record.last_seen = Date.now();
        role = record.role || 'user';
        sessionVersion = record.sessionVersion || 1;
        markDirty();
      }
      loginAttempts.delete(`${ip}::${username.toLowerCase()}`);
      const issued = await issueSession(username, role, sessionVersion);
      attachSocket(socket, { username, role, payload: issued.payload });
      socket.emit('login_success', authPayload(username, role, issued.token));
      const first = accessibleChannels(username, role)[0];
      if (first) joinChannel(socket, first);
      broadcastUserList();
      logger.info('auth', 'login succeeded', { username, ip });
    });

    safe('resume_session', async (token, callback) => {
      const auth = authFromToken(token);
      if (!auth) {
        if (typeof callback === 'function') callback({ ok: false, error: 'INVALID_SESSION' });
        return socket.emit('session_invalid');
      }
      attachSocket(socket, auth);
      socket.emit('session_resumed', authPayload(auth.username, auth.role, token));
      if (typeof callback === 'function') callback({ ok: true });
      broadcastUserList();
    });

    safe('logout', async (callback) => {
      const auth = sockets.get(socket.id);
      if (auth) {
        revokeSession(state.sessions, auth.username, auth.jti);
        markDirty();
        await store.flush();
        sockets.delete(socket.id);
        logger.info('auth', 'session logged out', { username: auth.username });
      }
      if (typeof callback === 'function') callback({ ok: true });
      socket.disconnect(true);
    });

    safe('change_password', async ({ currentPassword, newPassword } = {}, callback) => {
      const auth = sockets.get(socket.id);
      if (!auth) return callback?.({ ok: false, error: 'AUTH_REQUIRED' });
      const next = String(newPassword || '');
      if (next.length < 8 || next.length > 128) return callback?.({ ok: false, error: 'WEAK_PASSWORD' });

      let nextVersion;
      if (auth.role === 'admin') {
        if (!config.adminPassHash || !(await bcrypt.compare(String(currentPassword || ''), config.adminPassHash))) return callback?.({ ok: false, error: 'INVALID_PASSWORD' });
        config.adminPassHash = await bcrypt.hash(next, 12);
        config.adminSessionVersion += 1;
        nextVersion = config.adminSessionVersion;
        config = await saveConfig(loadedConfig.file, config);
      } else {
        const record = state.users[auth.username];
        if (!record || !(await bcrypt.compare(String(currentPassword || ''), record.passHash))) return callback?.({ ok: false, error: 'INVALID_PASSWORD' });
        record.passHash = await bcrypt.hash(next, 12);
        record.sessionVersion = Number(record.sessionVersion || 1) + 1;
        nextVersion = record.sessionVersion;
        markDirty();
      }
      await revokeAndDisconnect(auth.username, 'رمز عبور تغییر کرده است.', socket.id);
      const issued = createSessionToken(sessionSecret, { username: auth.username, role: auth.role, sessionVersion: nextVersion, ttlHours: config.sessionTtlHours });
      registerSession(state.sessions, issued.payload);
      markDirty();
      await store.flush();
      attachSocket(socket, { username: auth.username, role: auth.role, payload: issued.payload });
      socket.emit('session_refresh', { sessionToken: issued.token, uploadToken: issued.token, role: auth.role });
      callback?.({ ok: true });
      logger.info('auth', 'password changed and other sessions revoked', { username: auth.username });
    });

    safe('join_channel', async (channel) => joinChannel(socket, channel));

    safe('join_private', async (targetUser, callback) => {
      const auth = sockets.get(socket.id);
      if (!auth) return callback?.({ ok: false, error: 'AUTH_REQUIRED' });
      const target = cleanUsername(targetUser);
      if (!target || target === auth.username) return callback?.({ ok: false, error: 'INVALID_TARGET' });
      const dm = getOrCreateDm(auth.username, target);
      if (!dm) return callback?.({ ok: false, error: 'TARGET_NOT_FOUND' });
      leaveActiveConversation(socket);
      socket.join(dm.id);
      socket.data.activeConversation = dm.id;
      callback?.({ ok: true, dmId: dm.id });
      socket.emit('channel_joined', { name: dm.id, isPrivate: true, isSaved: false });
      socket.emit('history', state.messages[dm.id] || []);
      await store.flush();
    });

    safe('join_saved', async () => {
      const auth = sockets.get(socket.id);
      if (!auth) return;
      const id = savedConversationId(auth.username);
      ensureConversationMaps(id);
      leaveActiveConversation(socket);
      socket.join(id);
      socket.data.activeConversation = id;
      socket.emit('channel_joined', { name: id, isPrivate: true, isSaved: true });
      socket.emit('history', state.messages[id] || []);
    });

    safe('send_message', async (data = {}) => {
      const auth = sockets.get(socket.id);
      if (!auth) return socket.emit('auth_required');
      const now = Date.now();
      let limiter = userMessageLimits.get(auth.username);
      if (!limiter || now - limiter.started >= 5000) limiter = { started: now, count: 0 };
      if (limiter.count >= 5) return socket.emit('error', 'لطفا آهسته‌تر پیام ارسال کنید.');
      limiter.count += 1;
      userMessageLimits.set(auth.username, limiter);

      const conversationId = String(data.conversationId || '').trim();
      if (!conversationId) return socket.emit('error', 'گفتگو نامعتبر است.');
      if (isSavedConversation(conversationId)) {
        if (conversationId !== savedConversationId(auth.username)) return socket.emit('access_denied', { channel: conversationId, message: 'دسترسی مجاز نیست.' });
        ensureConversationMaps(conversationId);
      } else if (dmParticipants(conversationId)) {
        const participants = dmParticipants(conversationId);
        if (!participants || !targetExists(participants.a) || !targetExists(participants.b)) return socket.emit('error', 'گفتگوی خصوصی نامعتبر است.');
        if (!state.conversations[conversationId]) getOrCreateDm(participants.a, participants.b);
        if (!canAccessDm(auth.username, conversationId)) return socket.emit('access_denied', { channel: conversationId, message: 'دسترسی مجاز نیست.' });
      } else {
        const channel = cleanChannelName(conversationId);
        if (channel !== conversationId || !canAccessChannel(auth.username, auth.role, channel)) return socket.emit('access_denied', { channel, message: 'دسترسی مجاز نیست.' });
      }

      const type = ['text', 'image', 'audio', 'video', 'file'].includes(String(data.type)) ? String(data.type) : 'text';
      const text = cleanText(data.text, 1000);
      let content;
      let fileName;
      if (type !== 'text') {
        const record = validateAttachmentMessage(data.content, auth.username);
        if (!record) return socket.emit('error', 'فایل نامعتبر یا منقضی است.');
        content = `/uploads/${record.id}?d=${encodeURIComponent(capabilityToken(downloadSecret, record.id))}`;
        fileName = cleanText(record.originalName, 120);
      }
      const replyTo = data.replyTo ? getReplySnapshot(conversationId, data.replyTo) : null;
      if (replyTo === false) return socket.emit('error', 'پیام مرجع معتبر نیست.');
      if (!text && type === 'text') return;

      const message = {
        id: crypto.randomBytes(12).toString('hex'), sender: auth.username, text, type, content, fileName,
        conversationId, channel: conversationId, replyTo, timestamp: new Date().toISOString(), role: auth.role,
      };
      ensureConversationMaps(conversationId);
      state.messages[conversationId].push(message);
      const limit = isSavedConversation(conversationId) ? config.maxSavedMessages : (dmParticipants(conversationId) ? config.maxDmMessages : config.maxChannelMessages);
      if (state.messages[conversationId].length > limit) state.messages[conversationId].splice(0, state.messages[conversationId].length - limit);
      markDirty();
      emitMessage(conversationId, message);
      await store.flush();
    });

    safe('save_message', async (payload = {}) => {
      const auth = sockets.get(socket.id);
      if (!auth) return;
      const originalId = String(payload.originalId || payload.id || '').trim();
      const found = findMessage(originalId);
      if (!found || !canReadConversation(auth.username, auth.role, found.conversationId)) return socket.emit('error', 'پیام اصلی پیدا نشد یا قابل دسترسی نیست.');
      const id = savedConversationId(auth.username);
      ensureConversationMaps(id);
      if (state.messages[id].some((message) => message?.meta?.originalId === originalId)) return socket.emit('action_success', 'این پیام قبلاً ذخیره شده است.');
      const source = found.message;
      const message = {
        id: crypto.randomBytes(12).toString('hex'), sender: auth.username, text: cleanText(source.text, 1000), type: source.type || 'text',
        content: source.content, fileName: source.fileName, conversationId: id, channel: id, replyTo: null, timestamp: new Date().toISOString(), role: auth.role,
        meta: { saved: true, savedBy: auth.username, originalId, originalChannel: found.conversationId, originalAt: source.timestamp || null },
      };
      state.messages[id].push(message);
      if (state.messages[id].length > config.maxSavedMessages) state.messages[id].shift();
      markDirty();
      emitMessage(id, message);
      await store.flush();
      socket.emit('action_success', 'پیام ذخیره شد ✅');
    });

    safe('saved_delete', async (messageId) => {
      const auth = sockets.get(socket.id);
      if (!auth) return;
      const id = savedConversationId(auth.username);
      const before = (state.messages[id] || []).length;
      state.messages[id] = (state.messages[id] || []).filter((message) => message?.id !== String(messageId || ''));
      if (state.messages[id].length !== before) {
        markDirty();
        io.to(personalRoom(auth.username)).emit('message_deleted', { channel: id, id: String(messageId) });
        await store.flush();
      }
    });

    safe('create_channel', async (channelName) => {
      const auth = sockets.get(socket.id);
      if (!auth || !['admin', 'vip'].includes(auth.role)) return;
      const channel = cleanChannelName(channelName);
      if (!channel || channel.includes(DM_SEPARATOR) || channel.startsWith(RESERVED_SAVED_PREFIX)) return socket.emit('error', 'نام کانال نامعتبر یا رزرو شده است.');
      if (!state.channels.includes(channel)) {
        state.channels.push(channel);
        ensurePublicConversation(channel, auth.username);
        if (config.accessMode === 'restricted') { addMember(channel, auth.username, 'owner'); addMember(channel, config.adminUser, 'owner'); }
        markDirty();
        await store.flush();
      }
      io.emit('update_channels', state.channels);
      refreshChannelLists();
    });

    safe('delete_channel', async (channelName) => {
      const auth = sockets.get(socket.id);
      if (!auth || !['admin', 'vip'].includes(auth.role)) return;
      const channel = cleanChannelName(channelName);
      if (!channel || channel === 'General' || !state.channels.includes(channel)) return;
      state.channels = state.channels.filter((item) => item !== channel);
      delete state.conversations[channel]; delete state.memberships[channel]; delete state.messages[channel];
      markDirty();
      io.in(channel).socketsLeave(channel);
      io.emit('channel_deleted', channel);
      io.emit('update_channels', state.channels);
      refreshChannelLists();
      await store.flush();
    });

    safe('delete_message', async (messageId) => {
      const auth = sockets.get(socket.id);
      if (!auth || auth.role !== 'admin') return;
      const id = String(messageId || '');
      const found = findMessage(id);
      if (!found) return;
      state.messages[found.conversationId] = state.messages[found.conversationId].filter((message) => message?.id !== id);
      markDirty();
      if (dmParticipants(found.conversationId)) {
        const p = dmParticipants(found.conversationId);
        io.to(personalRoom(p.a)).to(personalRoom(p.b)).emit('message_deleted', { channel: found.conversationId, id });
      } else io.to(found.conversationId).emit('message_deleted', { channel: found.conversationId, id });
      await store.flush();
    });

    safe('update_admin_settings', async (settings = {}) => {
      const auth = sockets.get(socket.id);
      if (!auth || auth.role !== 'admin') return;
      if (typeof settings.hideUserList === 'boolean') config.hideUserList = settings.hideUserList;
      if (['restricted', 'open'].includes(settings.accessMode)) config.accessMode = settings.accessMode;
      config = await saveConfig(loadedConfig.file, config);
      refreshChannelLists();
      broadcastUserList();
      socket.emit('action_success', 'تنظیمات با موفقیت ذخیره شد.');
    });

    safe('admin_get_user_access', async (targetUsername) => {
      const auth = sockets.get(socket.id);
      if (!auth || auth.role !== 'admin') return;
      const target = cleanUsername(targetUsername);
      if (!target || !state.users[target]) return;
      socket.emit('admin_user_access', { username: target, map: Object.fromEntries(state.channels.map((channel) => [channel, isMember(channel, target)])), channels: state.channels });
    });

    safe('admin_set_user_access', async ({ targetUsername, channel, allow } = {}) => {
      const auth = sockets.get(socket.id);
      if (!auth || auth.role !== 'admin') return;
      const target = cleanUsername(targetUsername);
      const cleanChannel = cleanChannelName(channel);
      if (!target || !state.users[target] || !state.channels.includes(cleanChannel)) return;
      if (allow) addMember(cleanChannel, target); else removeMember(cleanChannel, target);
      for (const [socketId, targetAuth] of sockets.entries()) {
        if (targetAuth.username !== target) continue;
        const targetSocket = io.sockets.sockets.get(socketId);
        targetSocket?.emit('channels_list', accessibleChannels(target, targetAuth.role));
        if (!allow) {
          targetSocket?.leave(cleanChannel);
          targetSocket?.emit('access_revoked', { channel: cleanChannel, message: 'دسترسی شما به این کانال برداشته شد.' });
        }
      }
      await store.flush();
      socket.emit('admin_user_access', { username: target, map: Object.fromEntries(state.channels.map((item) => [item, isMember(item, target)])), channels: state.channels });
    });

    safe('ban_user', async (targetUsername) => {
      const auth = sockets.get(socket.id);
      if (!auth || !['admin', 'vip'].includes(auth.role)) return;
      const target = cleanUsername(targetUsername);
      if (!target || target === config.adminUser || !state.users[target]) return;
      state.users[target].isBanned = true;
      state.users[target].sessionVersion = Number(state.users[target].sessionVersion || 1) + 1;
      for (const key of Object.keys(state.messages)) state.messages[key] = (state.messages[key] || []).filter((message) => message?.sender !== target);
      await revokeAndDisconnect(target, 'حساب کاربری شما مسدود شده است.');
      markDirty();
      await store.flush();
      io.emit('bulk_delete_user', target);
      broadcastUserList();
      logger.info('security', 'user banned', { actor: auth.username, target });
    });

    safe('unban_user', async (targetUsername) => {
      const auth = sockets.get(socket.id);
      if (!auth || !['admin', 'vip'].includes(auth.role)) return;
      const target = cleanUsername(targetUsername);
      if (state.users[target]) { state.users[target].isBanned = false; markDirty(); await store.flush(); }
      socket.emit('banned_list', Object.keys(state.users).filter((name) => state.users[name]?.isBanned));
    });

    safe('get_banned_users', async () => {
      const auth = sockets.get(socket.id);
      if (auth && ['admin', 'vip'].includes(auth.role)) socket.emit('banned_list', Object.keys(state.users).filter((name) => state.users[name]?.isBanned));
    });

    safe('set_role', async ({ targetUsername, role } = {}) => {
      const actor = sockets.get(socket.id);
      if (!actor || actor.role !== 'admin' || !['user', 'vip'].includes(role)) return;
      const target = cleanUsername(targetUsername);
      const record = state.users[target];
      if (!record || target === config.adminUser) return;
      record.role = role;
      record.sessionVersion = Number(record.sessionVersion || 1) + 1;
      revokeAllSessions(state.sessions, target);
      const targetSockets = [...sockets.entries()].filter(([, value]) => value.username === target);
      const refreshed = [];
      for (const [socketId] of targetSockets) {
        const issued = createSessionToken(sessionSecret, { username: target, role, sessionVersion: record.sessionVersion, ttlHours: config.sessionTtlHours });
        registerSession(state.sessions, issued.payload);
        refreshed.push({ socketId, issued });
      }
      markDirty();
      await store.flush();
      for (const { socketId, issued } of refreshed) {
        const targetSocket = io.sockets.sockets.get(socketId);
        if (!targetSocket) continue;
        attachSocket(targetSocket, { username: target, role, payload: issued.payload });
        targetSocket.emit('role_update', role);
        targetSocket.emit('session_refresh', { sessionToken: issued.token, uploadToken: issued.token, role });
        targetSocket.emit('channels_list', accessibleChannels(target, role));
      }
      broadcastUserList();
      logger.info('security', 'user role changed', { actor: actor.username, target, role, sessions: refreshed.length });
    });

    safe('search_user', async (query) => {
      const auth = sockets.get(socket.id);
      if (!auth) return;
      const q = String(query || '').trim().toLowerCase();
      if (q.length < 3 || q.length > 32) return socket.emit('search_results', []);
      const names = new Set([config.adminUser, ...Object.keys(state.users)]);
      socket.emit('search_results', [...names].filter((name) => name !== auth.username && name.toLowerCase().includes(q) && !state.users[name]?.isBanned).slice(0, 30));
    });

    socket.on('disconnect', () => {
      sockets.delete(socket.id);
      broadcastUserList();
    });
  });

  const uploadLimiter = rateLimit({ windowMs: 15 * 60_000, limit: 20, standardHeaders: 'draft-7', legacyHeaders: false });
  const uploadStorage = multer.diskStorage({
    destination: (_req, _file, callback) => callback(null, uploadsDir),
    filename: (_req, file, callback) => {
      try {
        const { ext } = validateFileMeta(file.originalname, file.mimetype);
        callback(null, `${crypto.randomBytes(18).toString('hex')}${ext}`);
      } catch (error) { callback(error); }
    },
  });
  const upload = multer({
    storage: uploadStorage,
    limits: {
      fileSize: config.maxFileSizeMB * 1024 * 1024,
      files: 1,
      fields: 0,
      parts: 2,
      fieldNestingDepth: 0,
    },
    fileFilter: (_req, file, callback) => {
      try { validateFileMeta(file.originalname, file.mimetype); callback(null, true); }
      catch (error) { callback(error); }
    },
  }).single('file');

  function requestAuth(req) {
    const token = String(req.get('x-auth-token') || req.get('x-upload-token') || '');
    return authFromToken(token);
  }

  app.post('/upload', uploadLimiter, async (req, res) => {
    const auth = requestAuth(req);
    if (!auth) return res.status(401).json({ error: 'Unauthorized upload.' });
    const origin = req.get('origin');
    if (!exactOriginAllowed(origin, config.allowedOrigins)) return res.status(403).json({ error: 'Origin not allowed.' });

    const contentLength = Number(req.get('content-length') || 0);
    if (!Number.isFinite(contentLength) || contentLength <= 0 || contentLength > config.maxFileSizeMB * 1024 * 1024 + 1024 * 1024) {
      return res.status(413).json({ error: 'Upload request is too large or invalid.' });
    }
    const usageBefore = attachmentUsage(state.attachments, auth.username);
    if (usageBefore.userFiles >= config.maxFilesPerUser) return res.status(429).json({ error: 'Per-user file quota exceeded.' });
    try {
      if (typeof fsp.statfs === 'function') {
        const stat = await fsp.statfs(uploadsDir);
        const free = Number(stat.bavail) * Number(stat.bsize);
        if (free - contentLength < config.minFreeDiskMB * 1024 * 1024) return res.status(507).json({ error: 'Server disk free-space threshold reached.' });
      }
    } catch (error) {
      logger.error('upload', 'disk free-space check failed', { error: error.message });
      return res.status(503).json({ error: 'Storage is temporarily unavailable.' });
    }

    upload(req, res, async (error) => {
      if (error) {
        logger.warn('upload', 'upload rejected', { username: auth.username, code: error.code, error: error.message });
        const status = error instanceof multer.MulterError && error.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
        return res.status(status).json({ error: 'Upload rejected.' });
      }
      if (!req.file) return res.status(400).json({ error: 'No file sent.' });
      try {
        const usage = attachmentUsage(state.attachments, auth.username);
        if (usage.userBytes + req.file.size > config.userQuotaMB * 1024 * 1024 || usage.globalBytes + req.file.size > config.globalQuotaMB * 1024 * 1024) {
          await fsp.rm(req.file.path, { force: true });
          return res.status(507).json({ error: 'Storage quota exceeded.' });
        }
        const id = path.basename(req.file.filename, path.extname(req.file.filename));
        const now = Date.now();
        const record = {
          id, owner: auth.username, storedName: req.file.filename, originalName: cleanText(req.file.originalname, 120), mimetype: req.file.mimetype,
          size: req.file.size, createdAt: now, expiresAt: now + config.uploadRetentionDays * 86400_000,
        };
        state.attachments[id] = record;
        markDirty();
        await store.flush();
        const url = `/uploads/${id}?d=${encodeURIComponent(capabilityToken(downloadSecret, id))}`;
        return res.status(200).json({ url, filename: record.originalName, size: record.size, mimetype: record.mimetype });
      } catch (persistError) {
        await fsp.rm(req.file.path, { force: true }).catch(() => {});
        logger.error('upload', 'failed to persist attachment metadata', { error: persistError.message, username: auth.username });
        return res.status(500).json({ error: 'Upload could not be committed.' });
      }
    });
  });

  app.get('/uploads/:id', async (req, res) => {
    const id = String(req.params.id || '');
    if (!/^[0-9a-f]{36}$/i.test(id)) return res.sendStatus(404);
    const record = state.attachments[id];
    if (!record || record.deletedAt || record.expiresAt <= Date.now()) return res.sendStatus(404);
    if (!verifyCapability(downloadSecret, id, req.query.d)) return res.sendStatus(401);
    res.setHeader('Cache-Control', 'private, no-store');
    res.setHeader('Content-Type', record.mimetype || 'application/octet-stream');
    return res.sendFile(record.storedName, { root: uploadsDir, dotfiles: 'deny' }, (error) => {
      if (error && !res.headersSent) res.sendStatus(error.statusCode || 404);
    });
  });

  app.use(express.static(publicDir, { index: false, dotfiles: 'deny', fallthrough: true }));
  app.get('/', (_req, res) => res.sendFile(path.join(publicDir, 'index.html')));

  async function cleanupTask() {
    try {
      const removed = await cleanupUploads({ uploadsDir, attachments: state.attachments });
      const referenced = new Set();
      for (const list of Object.values(state.messages)) {
        for (const message of Array.isArray(list) ? list : []) {
          const parsed = messageAttachmentId(message?.content);
          if (parsed) referenced.add(parsed.id);
        }
      }
      const now = Date.now();
      for (const [id, record] of Object.entries(state.attachments)) {
        if (!record || record.deletedAt || referenced.has(id) || now - Number(record.createdAt || now) < 60 * 60_000) continue;
        await fsp.rm(path.join(uploadsDir, record.storedName), { force: true }).catch(() => {});
        record.deletedAt = now;
        removed.push(id);
      }
      if (removed.length) { markDirty(); await store.flush(); logger.info('upload', 'retention/orphan cleanup completed', { removed: removed.length }); }
      if (cleanupSessions(state.sessions)) { markDirty(); await store.flush(); }
    } catch (error) { logger.error('maintenance', 'cleanup task failed', { error: error.message }); }
  }
  const cleanupInterval = setInterval(cleanupTask, 60 * 60_000);
  cleanupInterval.unref();

  async function start() {
    if (server.listening) return server.address();
    await new Promise((resolve, reject) => {
      const onError = (error) => { server.off('listening', onListening); reject(error); };
      const onListening = () => { server.off('error', onError); resolve(); };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(config.port, config.bindHost);
    });
    ready = true;
    logger.info(APP_COMPONENT, 'server listening', { host: config.bindHost, port: server.address().port, tls: 'terminated-by-reverse-proxy' });
    return server.address();
  }

  async function stop(signal = 'shutdown') {
    if (shuttingDown) return;
    shuttingDown = true;
    ready = false;
    clearInterval(cleanupInterval);
    logger.info(APP_COMPONENT, 'graceful shutdown started', { signal });
    const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error('graceful shutdown timeout')), 8000));
    const close = (async () => {
      await store.flush();
      await new Promise((resolve) => io.close(resolve));
      if (server.listening) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    })();
    await Promise.race([close, timeout]);
    logger.info(APP_COMPONENT, 'graceful shutdown completed', { signal });
  }

  return {
    app, server, io, start, stop, state, store,
    get config() { return config; },
    paths: { rootDir, dataDir, publicDir, uploadsDir, backupRoot, stateFile },
    helpers: { authFromToken, canAccessChannel, canAccessDm, dmKeyFor, dmParticipants, exactOriginAllowed, messageAttachmentId },
  };
}

async function main() {
  const runtime = await createApplication();
  await runtime.start();
  let exiting = false;
  const shutdown = async (signal) => {
    if (exiting) return;
    exiting = true;
    try { await runtime.stop(signal); process.exitCode = 0; }
    catch (error) { logger.error(APP_COMPONENT, 'graceful shutdown failed', { signal, error: error.message }); process.exitCode = 1; }
  };
  process.once('SIGTERM', () => void shutdown('SIGTERM'));
  process.once('SIGINT', () => void shutdown('SIGINT'));
}

if (require.main === module) {
  main().catch((error) => {
    logger.error(APP_COMPONENT, 'startup failed', { code: error.code, error: error.message });
    process.exitCode = 1;
  });
}

module.exports = { createApplication, cleanChannelName, cleanText, cleanUsername, dmKeyFor, dmParticipants, exactOriginAllowed, messageAttachmentId };
