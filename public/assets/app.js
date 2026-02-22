const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const xss = require("xss");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
const server = http.createServer(app);

// -------------------- Security headers --------------------
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
  }),
);

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("X-Frame-Options", "DENY");
  next();
});

app.use(express.json({ limit: "10kb" }));

// -------------------- Paths --------------------
const DATA_DIR = path.join(__dirname, "data");
const UPLOADS_DIR = path.join(__dirname, "public/uploads");

if (!fs.existsSync(DATA_DIR))
  fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
if (!fs.existsSync(UPLOADS_DIR))
  fs.mkdirSync(UPLOADS_DIR, { recursive: true, mode: 0o700 });

const USERS_FILE = path.join(DATA_DIR, "users.json");
const MESSAGES_FILE = path.join(DATA_DIR, "messages.json");
const CHANNELS_FILE = path.join(DATA_DIR, "channels.json");
const CONFIG_FILE = path.join(DATA_DIR, "config.json");

const CONVERSATIONS_FILE = path.join(DATA_DIR, "conversations.json");
const MEMBERSHIPS_FILE = path.join(DATA_DIR, "memberships.json");
const ATTACHMENTS_FILE = path.join(DATA_DIR, "attachments.json");

function readJsonSafe(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

function atomicWriteJson(file, obj, mode = 0o600) {
  const tmp = file + "." + crypto.randomBytes(6).toString("hex") + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), { mode });
  fs.renameSync(tmp, file);
  try {
    fs.chmodSync(file, mode);
  } catch {}
}

// -------------------- Data-at-rest encryption (AES-256-GCM) --------------------
function keyFromHex(hex) {
  try {
    const h = String(hex || "").trim();
    if (!h) return null;
    const buf = Buffer.from(h, "hex");
    return buf.length === 32 ? buf : null;
  } catch {
    return null;
  }
}

function encryptPayload(key, obj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), "utf8");
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 1,
    alg: "A256GCM",
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: enc.toString("base64"),
  };
}

function decryptPayload(key, wrapper) {
  const iv = Buffer.from(String(wrapper.iv || ""), "base64");
  const tag = Buffer.from(String(wrapper.tag || ""), "base64");
  const data = Buffer.from(String(wrapper.data || ""), "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return JSON.parse(dec.toString("utf8"));
}

function isEncryptedWrapper(obj) {
  return !!(
    obj &&
    typeof obj === "object" &&
    obj.v === 1 &&
    obj.alg === "A256GCM" &&
    obj.iv &&
    obj.tag &&
    obj.data
  );
}

function readJsonSecure(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    const raw = fs.readFileSync(file, "utf8");
    if (!raw) return fallback;

    const parsed = JSON.parse(raw);

    const key = keyFromHex(appConfig.dataEncKey);
    if (key && isEncryptedWrapper(parsed)) return decryptPayload(key, parsed);

    return parsed;
  } catch {
    return fallback;
  }
}

function atomicWriteJsonSecure(file, obj, mode = 0o600) {
  const key = keyFromHex(appConfig.dataEncKey);
  const payload = key ? encryptPayload(key, obj) : obj;
  atomicWriteJson(file, payload, mode);
}

// -------------------- Config --------------------
let appConfig = {
  adminUser: "admin",
  adminPassHash: "",
  port: 3000,
  maxFileSizeMB: 50,
  appName: "node-socketio-chatroom",
  hideUserList: false,
  allowedOrigins: "*",
  protectUploads: true,
  dataEncKey: "",
  // ✅ NEW: channel access policy
  accessMode: "restricted", // 'restricted' | 'open'
  defaultChannelsForNewUsers: [], // e.g. ['General'] if you want
};

function normalizeOrigins(val) {
  if (val === "*" || val === undefined || val === null) return "*";
  if (Array.isArray(val))
    return val.map((s) => String(s).trim()).filter(Boolean);
  const s = String(val).trim();
  if (!s) return "*";
  if (s === "*") return "*";
  return s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

let lastConfigMtimeMs = 0;

function loadAndSecureConfig(force = false) {
  try {
    let stat;
    try {
      stat = fs.statSync(CONFIG_FILE);
    } catch {
      stat = null;
    }

    const mtimeMs = stat ? stat.mtimeMs : 0;
    if (!force && mtimeMs && mtimeMs === lastConfigMtimeMs) return false;

    let saveNeeded = false;
    const fileConfig = readJsonSafe(CONFIG_FILE, null);

    if (fileConfig) appConfig = { ...appConfig, ...fileConfig };
    else saveNeeded = true;

    if (appConfig.adminPass && !appConfig.adminPassHash) {
      appConfig.adminPassHash = bcrypt.hashSync(
        String(appConfig.adminPass),
        12,
      );
      delete appConfig.adminPass;
      saveNeeded = true;
    }

    if (
      appConfig.adminPassHash &&
      !String(appConfig.adminPassHash).startsWith("$2")
    ) {
      appConfig.adminPassHash = bcrypt.hashSync(
        String(appConfig.adminPassHash),
        12,
      );
      saveNeeded = true;
    }

    appConfig.allowedOrigins = normalizeOrigins(appConfig.allowedOrigins);

    if (
      !["restricted", "open"].includes(
        String(appConfig.accessMode || "restricted"),
      )
    ) {
      appConfig.accessMode = "restricted";
      saveNeeded = true;
    }
    if (!Array.isArray(appConfig.defaultChannelsForNewUsers)) {
      appConfig.defaultChannelsForNewUsers = [];
      saveNeeded = true;
    }

    if (saveNeeded) atomicWriteJson(CONFIG_FILE, appConfig, 0o600);

    try {
      const st2 = fs.statSync(CONFIG_FILE);
      lastConfigMtimeMs = st2.mtimeMs;
    } catch {
      lastConfigMtimeMs = mtimeMs || 0;
    }

    return true;
  } catch (e) {
    console.error("Error loading config:", e);
    return false;
  }
}

loadAndSecureConfig(true);

const PORT = Number(process.env.PORT || appConfig.port || 3000);

// -------------------- Socket.io --------------------
const corsOption = (() => {
  const origins = appConfig.allowedOrigins;
  if (origins === "*") return { origin: "*", methods: ["GET", "POST"] };

  return {
    origin: (origin, cb) => {
      // allow no-origin only for same-machine tools or dev
      if (!origin) return cb(null, false);
      return origins.includes(origin) ? cb(null, true) : cb(null, false);
    },
    methods: ["GET", "POST"],
  };
})();

const io = new Server(server, {
  // socket payload should stay small; files go via /upload
  maxHttpBufferSize: 2e6, // ~2MB (adjust if you need bigger)
  cors: corsOption,
});

// -------------------- In-memory state --------------------
let users = {};
let persistentUsers = {};
let channels = ["General", "Random"];

let messages = {};
let userRateLimits = {};

let conversations = {};
let memberships = {};
let attachments = {};

// upload auth: token -> expiry
const uploadTokens = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [t, v] of uploadTokens.entries()) {
    if (!v || v.exp <= now) uploadTokens.delete(t);
  }
}, 60_000).unref();

// Load data
persistentUsers = readJsonSecure(USERS_FILE, {});
channels = readJsonSecure(CHANNELS_FILE, channels);
messages = readJsonSecure(MESSAGES_FILE, {});
conversations = readJsonSecure(CONVERSATIONS_FILE, {});
memberships = readJsonSecure(MEMBERSHIPS_FILE, {});
attachments = readJsonSecure(ATTACHMENTS_FILE, {});

// -------------------- Helpers --------------------
function cleanUsername(username) {
  return xss(String(username || "").trim()).substring(0, 20);
}
function cleanText(text, max = 1000) {
  const s = xss(String(text || ""));
  return s.length > max ? s.substring(0, max) : s;
}
function cleanChannelName(name) {
  return xss(String(name || "").trim()).substring(0, 30);
}

function ensureConversationMaps(conversationId) {
  if (!memberships[conversationId]) memberships[conversationId] = {};
  if (!messages[conversationId]) messages[conversationId] = [];
}

function isMember(conversationId, username) {
  return !!(
    memberships[conversationId] && memberships[conversationId][username]
  );
}

function addMember(conversationId, username, role = "member") {
  ensureConversationMaps(conversationId);
  if (!memberships[conversationId][username]) {
    memberships[conversationId][username] = {
      role,
      joinedAt: Date.now(),
      lastReadMessageId: null,
    };
  }
}

function removeMember(conversationId, username) {
  if (!memberships[conversationId]) return;
  delete memberships[conversationId][username];
}

function ensurePublicConversation(channelName, createdBy = "system") {
  const id = channelName;
  if (!conversations[id]) {
    conversations[id] = {
      id,
      type: "public",
      title: channelName,
      isHidden: false,
      createdBy,
      createdAt: Date.now(),
    };
  }
  ensureConversationMaps(id);
  return conversations[id];
}

function dmKeyFor(u1, u2) {
  const a = String(u1 || "").trim();
  const b = String(u2 || "").trim();
  return [a, b].sort().join("_pv_");
}

function getOrCreateDMConversation(u1, u2) {
  const key = dmKeyFor(u1, u2);
  if (!conversations[key]) {
    conversations[key] = {
      id: key,
      type: "dm",
      title: `DM: ${u1}, ${u2}`,
      isHidden: true,
      dmKey: key,
      createdBy: u1,
      createdAt: Date.now(),
    };
    ensureConversationMaps(key);
  }
  addMember(key, u1, "owner");
  addMember(key, u2, "member");
  return conversations[key];
}

function isValidDMId(dmId) {
  if (!dmId || typeof dmId !== "string") return false;
  if (!dmId.includes("_pv_")) return false;
  const parts = dmId
    .split("_pv_")
    .map((x) => x.trim())
    .filter(Boolean);
  return parts.length === 2 && parts[0] !== parts[1];
}

function dmParticipants(dmId) {
  const parts = String(dmId || "")
    .split("_pv_")
    .map((x) => x.trim());
  if (parts.length !== 2) return null;
  return { a: parts[0], b: parts[1] };
}

function canAccessDM(user, dmId) {
  if (!user) return false;
  if (!isValidDMId(dmId)) return false;
  const p = dmParticipants(dmId);
  if (!p) return false;
  return user.username === p.a || user.username === p.b;
}

function savedConvIdFor(username) {
  return `__saved__${String(username || "").trim()}`;
}

function isSavedConvId(convId) {
  return typeof convId === "string" && convId.startsWith("__saved__");
}

// ✅ NEW: access checks
function canAccessChannel(username, role, channelName) {
  const ch = String(channelName || "").trim();
  if (!ch) return false;
  if (role === "admin") return true;

  // open mode: all users can access public channels
  if (appConfig.accessMode === "open") return true;

  // restricted: must be explicitly member
  return isMember(ch, username);
}

function listAccessibleChannels(username, role) {
  if (role === "admin") return [...channels];
  if (appConfig.accessMode === "open") return [...channels];
  // restricted
  return channels.filter((ch) => isMember(ch, username));
}

function saveData() {
  try {
    atomicWriteJsonSecure(USERS_FILE, persistentUsers, 0o600);
    atomicWriteJsonSecure(CHANNELS_FILE, channels, 0o600);
    atomicWriteJsonSecure(MESSAGES_FILE, messages, 0o600);
    atomicWriteJsonSecure(CONVERSATIONS_FILE, conversations, 0o600);
    atomicWriteJsonSecure(MEMBERSHIPS_FILE, memberships, 0o600);
    atomicWriteJsonSecure(ATTACHMENTS_FILE, attachments, 0o600);
  } catch (e) {
    console.error("Error saving data", e);
  }
}
setInterval(saveData, 30_000).unref();

// migrate users plaintext -> hash (backward compat)
(function migrateUsersIfNeeded() {
  let changed = false;
  for (const [u, data] of Object.entries(persistentUsers)) {
    if (!data) continue;

    if (data.password && !data.passHash) {
      data.passHash = bcrypt.hashSync(String(data.password), 12);
      delete data.password;
      changed = true;
    }
    if (data.passHash && !String(data.passHash).startsWith("$2")) {
      data.passHash = bcrypt.hashSync(String(data.passHash), 12);
      changed = true;
    }
  }
  if (changed) saveData();
})();

// ensure default channels have public conversations
(function ensureDefaults() {
  for (const ch of channels) ensurePublicConversation(ch, "system");
  saveData();
})();

// -------------------- Upload --------------------
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many uploads from this IP, please try again later",
});

const allowedMimes = new Set([
  "image/jpeg",
  "image/png",
  "image/gif",
  "image/webp",
  "audio/webm",
  "audio/mpeg",
  "video/mp4",
  "video/webm",
  "application/pdf",
  "text/plain",
]);

const allowedExt = new Set([
  ".jpg",
  ".jpeg",
  ".png",
  ".gif",
  ".webp",
  ".webm",
  ".mp3",
  ".mp4",
  ".pdf",
  ".txt",
]);

function safeExt(originalname) {
  const ext = path.extname(String(originalname || "")).toLowerCase();
  return allowedExt.has(ext) ? ext : "";
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) => {
    const ext = safeExt(file.originalname);
    const name = crypto.randomBytes(16).toString("hex") + ext;
    cb(null, name);
  },
});

let uploadSingle = null;
let lastUploadLimitBytes = 0;

function rebuildUploadMiddleware() {
  const limitBytes = Number(appConfig.maxFileSizeMB || 50) * 1024 * 1024;
  if (uploadSingle && limitBytes === lastUploadLimitBytes) return;

  lastUploadLimitBytes = limitBytes;

  const upload = multer({
    storage,
    limits: { fileSize: limitBytes },
    fileFilter: (_req, file, cb) => {
      if (!allowedMimes.has(file.mimetype))
        return cb(new Error("DISALLOWED_MIME"));
      if (!safeExt(file.originalname)) return cb(new Error("DISALLOWED_EXT"));
      cb(null, true);
    },
  });

  uploadSingle = upload.single("file");
}

rebuildUploadMiddleware();

setInterval(() => {
  const changed = loadAndSecureConfig(false);
  if (changed) rebuildUploadMiddleware();
}, 5000).unref();

// Protect downloads if enabled
app.use("/uploads", (req, res, next) => {
  if (!appConfig.protectUploads) return next();

  const tok = String(req.headers["x-upload-token"] || req.query.t || "");
  const rec = uploadTokens.get(tok);
  if (!rec || rec.exp <= Date.now())
    return res.status(401).send("Unauthorized");
  next();
});

// Static assets (cache assets, no-cache html)
const PUBLIC_DIR = path.join(__dirname, "public");

app.use(
  "/assets",
  express.static(path.join(PUBLIC_DIR, "assets"), {
    maxAge: "7d",
    etag: true,
  }),
);

// uploads already handled by /uploads middleware + express.static below
app.use(
  express.static(PUBLIC_DIR, {
    etag: true,
    maxAge: "0",
    setHeaders: (res, filePath) => {
      // prevent caching index.html aggressively
      if (filePath.endsWith(path.sep + "index.html")) {
        res.setHeader("Cache-Control", "no-store");
      }
    },
  }),
);

app.post("/upload", uploadLimiter, (req, res) => {
  const tok = String(req.headers["x-upload-token"] || "");
  const rec = uploadTokens.get(tok);
  if (!rec || rec.exp <= Date.now())
    return res.status(401).json({ error: "Unauthorized upload." });

  if (!uploadSingle) rebuildUploadMiddleware();

  uploadSingle(req, res, function (err) {
    if (err instanceof multer.MulterError)
      return res.status(400).json({ error: "File too large or upload error." });
    if (err) return res.status(400).json({ error: "File type not allowed." });
    if (!req.file) return res.status(400).json({ error: "No file sent." });

    const cleanOriginal = xss(String(req.file.originalname || "")).substring(
      0,
      120,
    );
    res.json({
      url: "/uploads/" + req.file.filename,
      filename: cleanOriginal,
      size: req.file.size,
      mimetype: req.file.mimetype,
    });
  });
});

// -------------------- Online users list --------------------
function getUniqueOnlineUsers() {
  const unique = {};
  Object.values(users).forEach((u) => {
    unique[u.username] = u;
  });
  return Object.values(unique);
}

function broadcastUserList() {
  const allUsers = getUniqueOnlineUsers();
  const admins = allUsers.filter((u) => u.role === "admin");

  io.sockets.sockets.forEach((socket) => {
    const user = users[socket.id];
    if (!user) return;

    if (user.role === "admin") socket.emit("user_list", allUsers);
    else {
      if (appConfig.hideUserList) {
        const visible = [...admins];
        if (!visible.find((a) => a.username === user.username))
          visible.push(user);
        socket.emit("user_list", visible);
      } else {
        socket.emit("user_list", allUsers);
      }
    }
  });
}

function getBannedUsers() {
  return Object.keys(persistentUsers).filter(
    (u) => persistentUsers[u]?.isBanned,
  );
}

// -------------------- Login rate limit --------------------
const loginAttempts = new Map();

function getSocketIp(socket) {
  const xf = socket.handshake.headers["x-forwarded-for"];
  if (xf && typeof xf === "string") return xf.split(",")[0].trim();
  return String(socket.handshake.address || "").trim() || "unknown";
}

function loginKey(ip, username) {
  return `${ip}::${String(username || "").toLowerCase()}`;
}

function isLoginLimited(ip, username) {
  const key = loginKey(ip, username);
  const now = Date.now();
  const rec = loginAttempts.get(key);

  const windowMs = 10 * 60 * 1000;
  const max = 12;

  if (!rec) return false;

  if (now - rec.first > windowMs) {
    loginAttempts.delete(key);
    return false;
  }

  return rec.count >= max;
}

function recordLoginFail(ip, username) {
  const key = loginKey(ip, username);
  const now = Date.now();
  const rec = loginAttempts.get(key);

  if (!rec) {
    loginAttempts.set(key, { count: 1, first: now, last: now });
    return;
  }

  rec.count += 1;
  rec.last = now;
  loginAttempts.set(key, rec);
}

function clearLoginFails(ip, username) {
  loginAttempts.delete(loginKey(ip, username));
}

setInterval(() => {
  const now = Date.now();
  const windowMs = 10 * 60 * 1000;
  for (const [k, v] of loginAttempts.entries()) {
    if (!v || now - v.first > windowMs) loginAttempts.delete(k);
  }
}, 60_000).unref();

// -------------------- Socket events --------------------
io.on("connection", (socket) => {
  // ✅ safe channel join (enforced access)
  function joinChannelCompat(sock, channelName) {
    const user = users[sock.id];
    if (!user) return;

    const clean = cleanChannelName(channelName);
    if (!clean) return;

    // channel must exist
    if (!channels.includes(clean))
      return sock.emit("error", "کانال وجود ندارد.");

    // enforce access
    if (!canAccessChannel(user.username, user.role, clean)) {
      return sock.emit("access_denied", {
        channel: clean,
        message: "شما به این کانال دسترسی ندارید.",
      });
    }

    ensurePublicConversation(clean, "system");
    addMember(clean, user.username, "member");

    sock.join(clean);
    sock.emit("channel_joined", { name: clean, isPrivate: false });
    sock.emit("history", Array.isArray(messages[clean]) ? messages[clean] : []);
  }

  socket.on("join_saved", () => {
    const user = users[socket.id];
    if (!user) return;

    const sid = savedConvIdFor(user.username);
    ensureConversationMaps(sid);

    // اینجا room = sid
    socket.join(sid);

    socket.emit("channel_joined", {
      name: sid,
      isPrivate: true,
      isSaved: true,
    });
    socket.emit("history", Array.isArray(messages[sid]) ? messages[sid] : []);
  });

  function emitAccessSnapshotToAdmin(adminSocket) {
    const u = users[adminSocket.id];
    if (!u || u.role !== "admin") return;

    const result = {};
    for (const uname of Object.keys(persistentUsers)) {
      result[uname] = {};
      for (const ch of channels) {
        result[uname][ch] = isMember(ch, uname);
      }
    }
    adminSocket.emit("admin_access_snapshot", { channels, map: result });
  }

  socket.on("login", ({ username, password }) => {
    loadAndSecureConfig();

    const ip = getSocketIp(socket);

    const u = cleanUsername(username);
    const p = String(password || "");
    if (isLoginLimited(ip, u))
      return socket.emit(
        "login_error",
        "تلاش‌های ورود زیاد است. چند دقیقه بعد دوباره امتحان کنید.",
      );
    if (!u || !p) {
      recordLoginFail(ip, u || "");
      return socket.emit("login_error", "نام کاربری و رمز عبور الزامی است");
    }

    // Admin login
    if (u === appConfig.adminUser) {
      const ok =
        appConfig.adminPassHash &&
        bcrypt.compareSync(p, appConfig.adminPassHash);
      if (!ok) {
        recordLoginFail(ip, u);
        return socket.emit("login_error", "رمز عبور ادمین اشتباه است.");
      }

      clearLoginFails(ip, u);
      users[socket.id] = { username: u, role: "admin" };

      const uploadToken = crypto.randomBytes(24).toString("hex");
      uploadTokens.set(uploadToken, {
        username: u,
        exp: Date.now() + 6 * 60 * 60 * 1000,
      });

      for (const ch of channels) ensurePublicConversation(ch, "system");

      // admin always member to all channels in restricted mode
      if (appConfig.accessMode === "restricted") {
        for (const ch of channels) addMember(ch, u, "owner");
      }

      socket.emit("login_success", {
        username: u,
        role: "admin",
        channels: [...channels],
        settings: {
          maxFileSizeMB: appConfig.maxFileSizeMB,
          appName: appConfig.appName,
          hideUserList: appConfig.hideUserList,
          accessMode: appConfig.accessMode,
        },
        uploadToken,
      });

      // auto-join General if exists
      if (channels.includes("General")) joinChannelCompat(socket, "General");

      broadcastUserList();
      emitAccessSnapshotToAdmin(socket);
      return;
    }

    // Normal user login/register
    const existing = persistentUsers[u];
    if (existing) {
      if (existing.isBanned) {
        recordLoginFail(ip, u);
        return socket.emit("login_error", "حساب کاربری شما مسدود شده است.");
      }
      if (!existing.passHash || !bcrypt.compareSync(p, existing.passHash)) {
        recordLoginFail(ip, u);
        return socket.emit("login_error", "رمز عبور اشتباه است.");
      }
    } else {
      persistentUsers[u] = {
        passHash: bcrypt.hashSync(p, 12),
        role: "user",
        isBanned: false,
        created_at: Date.now(),
      };

      // ✅ optional: default channels for new users
      if (
        appConfig.accessMode === "restricted" &&
        Array.isArray(appConfig.defaultChannelsForNewUsers)
      ) {
        for (const ch of appConfig.defaultChannelsForNewUsers) {
          const cleanCh = cleanChannelName(ch);
          if (cleanCh && channels.includes(cleanCh))
            addMember(cleanCh, u, "member");
        }
      }
    }

    clearLoginFails(ip, u);
    persistentUsers[u].last_seen = Date.now();

    const role = persistentUsers[u].role || "user";
    users[socket.id] = { username: u, role };

    const uploadToken = crypto.randomBytes(24).toString("hex");
    uploadTokens.set(uploadToken, {
      username: u,
      exp: Date.now() + 6 * 60 * 60 * 1000,
    });

    for (const ch of channels) ensurePublicConversation(ch, "system");

    const accessible = listAccessibleChannels(u, role);

    socket.emit("login_success", {
      username: u,
      role,
      channels: accessible,
      settings: {
        maxFileSizeMB: appConfig.maxFileSizeMB,
        appName: appConfig.appName,
        hideUserList: appConfig.hideUserList,
        accessMode: appConfig.accessMode,
      },
      uploadToken,
    });

    // auto-join first accessible channel (if any)
    if (accessible.length > 0) joinChannelCompat(socket, accessible[0]);

    saveData();
    broadcastUserList();
  });

  socket.on("join_channel", (channel) => {
    joinChannelCompat(socket, channel);
  });

  socket.on("join_private", (targetUser, cb) => {
    const currentUser = users[socket.id];
    if (!currentUser) return;

    const cleanTarget = cleanUsername(targetUser);
    if (!cleanTarget || cleanTarget === currentUser.username) {
      if (typeof cb === "function") cb({ ok: false, error: "INVALID_TARGET" });
      return;
    }

    // ✅ اجازه DM به ادمین حتی اگر داخل users.json نباشد
    const isAdminTarget = cleanTarget === appConfig.adminUser;

    // ✅ یا کاربر ثبت‌نام‌شده باشد و بن نشده باشد
    const isRegisteredTarget =
      !!persistentUsers[cleanTarget] && !persistentUsers[cleanTarget]?.isBanned;

    if (!isAdminTarget && !isRegisteredTarget) {
      if (typeof cb === "function")
        cb({ ok: false, error: "TARGET_NOT_FOUND" });
      return;
    }

    const dm = getOrCreateDMConversation(currentUser.username, cleanTarget);

    for (const r of socket.rooms) {
      if (r !== socket.id) socket.leave(r);
    }

    socket.join(dm.id);

    if (typeof cb === "function") cb({ ok: true, dmId: dm.id });

    socket.emit("channel_joined", {
      name: dm.id,
      isPrivate: true,
      isSaved: false,
    });
    socket.emit(
      "history",
      Array.isArray(messages[dm.id]) ? messages[dm.id] : [],
    );
  });

  // -------------------- Saved Messages --------------------
  socket.on("saved_delete", (msgId) => {
    const user = users[socket.id];
    if (!user) return;

    const sid = savedConvIdFor(user.username);
    const id = String(msgId || "").trim();
    if (!id) return;

    ensureConversationMaps(sid);

    const before = messages[sid].length;
    messages[sid] = messages[sid].filter((m) => m && m.id !== id);

    if (messages[sid].length !== before) {
      io.to(sid).emit("message_deleted", { channel: sid, id });
      saveData();
    }
  });

  socket.on("save_message", (payload) => {
    const user = users[socket.id];
    if (!user) return;

    const item = payload && typeof payload === "object" ? payload : null;
    if (!item) return;

    const originalId = String(item.originalId || item.id || "").trim();
    const from = cleanUsername(item.from || item.sender || "");
    const srcChannel = cleanChannelName(
      item.channel || item.conversationId || "",
    );
    const type = String(item.type || "text");
    const text = cleanText(item.text || "", 1000);
    const content = typeof item.content === "string" ? item.content : undefined;
    const fileName = item.fileName
      ? xss(String(item.fileName)).substring(0, 120)
      : undefined;

    if (!originalId || !from) return;

    const sid = savedConvIdFor(user.username);
    ensureConversationMaps(sid);

    // جلوگیری از duplicate: داخل saved chat دنبال originalId می‌گردیم
    const exists =
      Array.isArray(messages[sid]) &&
      messages[sid].some(
        (m) => m && m.meta && m.meta.originalId === originalId,
      );
    if (exists)
      return socket.emit("action_success", "این پیام قبلاً ذخیره شده است.");

    const msg = {
      id: crypto.randomBytes(12).toString("hex"),
      sender: from, // برای اینکه تو Saved سمت چپ نمایش داده شود
      text,
      type,
      content,
      fileName,
      conversationId: sid,
      channel: sid,
      replyTo: null,
      timestamp: new Date().toLocaleTimeString("en-US", {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
      }),
      role: "user",
      meta: {
        saved: true,
        savedBy: user.username,
        originalId,
        originalChannel: srcChannel || "(unknown)",
        originalAt: item.originalAt || null,
      },
    };

    messages[sid].push(msg);
    if (messages[sid].length > 1000) messages[sid].shift();

    // اگر الان داخل saved هست همزمان می‌بیند
    io.to(sid).emit("receive_message", msg);

    saveData();
    socket.emit("action_success", "پیام ذخیره شد ✅");
  });

  // -------------------- Channel management --------------------
  socket.on("create_channel", (channelName) => {
    const user = users[socket.id];
    if (!user || (user.role !== "admin" && user.role !== "vip")) return;

    const clean = cleanChannelName(channelName);
    if (!clean) return;

    if (!channels.includes(clean)) channels.push(clean);
    ensurePublicConversation(clean, user.username);

    // creator gets access in restricted mode
    if (appConfig.accessMode === "restricted")
      addMember(clean, user.username, "owner");

    // admin gets access always
    if (appConfig.accessMode === "restricted")
      addMember(clean, appConfig.adminUser, "owner");

    io.emit("update_channels", channels);
    saveData();

    // push filtered channels to each user
    io.sockets.sockets.forEach((s) => {
      const u = users[s.id];
      if (!u) return;
      const list = listAccessibleChannels(u.username, u.role);
      s.emit("channels_list", list);
    });
  });

  socket.on("delete_channel", (channelName) => {
    const user = users[socket.id];
    if (!user || (user.role !== "admin" && user.role !== "vip")) return;

    const clean = cleanChannelName(channelName);
    if (!clean || clean === "General") return;

    channels = channels.filter((c) => c !== clean);

    delete conversations[clean];
    delete memberships[clean];
    delete messages[clean];

    io.in(clean).socketsLeave(clean);

    io.emit("update_channels", channels);
    saveData();

    io.sockets.sockets.forEach((s) => {
      const u = users[s.id];
      if (!u) return;
      const list = listAccessibleChannels(u.username, u.role);
      s.emit("channels_list", list);
      // kick UI if user was in deleted channel
      s.emit("channel_deleted", clean);
    });
  });

  socket.on("update_admin_settings", (newSettings) => {
    const user = users[socket.id];
    if (!user || user.role !== "admin") return;

    if (typeof newSettings?.hideUserList === "boolean") {
      appConfig.hideUserList = newSettings.hideUserList;
    }
    if (
      typeof newSettings?.accessMode === "string" &&
      ["restricted", "open"].includes(newSettings.accessMode)
    ) {
      appConfig.accessMode = newSettings.accessMode;
    }

    atomicWriteJson(CONFIG_FILE, appConfig, 0o600);

    // refresh channels list for everyone
    io.sockets.sockets.forEach((s) => {
      const u = users[s.id];
      if (!u) return;
      const list = listAccessibleChannels(u.username, u.role);
      s.emit("channels_list", list);
    });

    broadcastUserList();
    socket.emit("action_success", "تنظیمات با موفقیت ذخیره شد.");
    emitAccessSnapshotToAdmin(socket);
  });

  // ✅ NEW: admin UI events to grant/revoke channel access
  socket.on("admin_get_user_access", (targetUsername) => {
    const actor = users[socket.id];
    if (!actor || actor.role !== "admin") return;

    const t = cleanUsername(targetUsername);
    if (!t || !persistentUsers[t]) return;

    const map = {};
    for (const ch of channels) map[ch] = isMember(ch, t);

    socket.emit("admin_user_access", { username: t, map, channels });
  });

  socket.on("admin_set_user_access", ({ targetUsername, channel, allow }) => {
    const actor = users[socket.id];
    if (!actor || actor.role !== "admin") return;

    const t = cleanUsername(targetUsername);
    const ch = cleanChannelName(channel);
    const okAllow = !!allow;

    if (!t || !persistentUsers[t]) return;
    if (!ch || !channels.includes(ch)) return;

    if (okAllow) addMember(ch, t, "member");
    else removeMember(ch, t);

    saveData();

    // update target user's channels list live (if online)
    const targetSocketIds = Object.keys(users).filter(
      (id) => users[id]?.username === t,
    );
    for (const sid of targetSocketIds) {
      const s = io.sockets.sockets.get(sid);
      if (!s) continue;
      const list = listAccessibleChannels(t, users[sid].role);
      s.emit("channels_list", list);

      // if they are currently inside revoked channel -> force leave
      if (!okAllow) {
        s.leave(ch);
        s.emit("access_revoked", {
          channel: ch,
          message: "دسترسی شما به این کانال توسط ادمین برداشته شد.",
        });
      }
    }

    socket.emit(
      "action_success",
      `دسترسی ${okAllow ? "داده شد" : "برداشته شد"}: ${t} -> ${ch}`,
    );
    socket.emit("admin_user_access", {
      username: t,
      map: Object.fromEntries(channels.map((c) => [c, isMember(c, t)])),
      channels,
    });
    emitAccessSnapshotToAdmin(socket);
  });

  // -------------------- Moderation --------------------
  socket.on("ban_user", (targetUsername) => {
    const actor = users[socket.id];
    if (!actor || (actor.role !== "admin" && actor.role !== "vip")) return;
    if (targetUsername === appConfig.adminUser) return;

    const t = cleanUsername(targetUsername);
    if (!persistentUsers[t]) return;

    persistentUsers[t].isBanned = true;

    for (const key of Object.keys(messages)) {
      if (Array.isArray(messages[key]))
        messages[key] = messages[key].filter((m) => m.sender !== t);
    }

    saveData();
    io.emit("bulk_delete_user", t);

    const targetSockets = Object.keys(users).filter(
      (id) => users[id].username === t,
    );
    targetSockets.forEach((id) => {
      io.to(id).emit("force_disconnect", "شما توسط ادمین بن شدید.");
      io.sockets.sockets.get(id)?.disconnect(true);
      delete users[id];
    });

    broadcastUserList();
    socket.emit("action_success", `کاربر ${t} بن شد و پیام‌های او حذف گردید.`);
  });

  socket.on("unban_user", (targetUsername) => {
    const actor = users[socket.id];
    if (!actor || (actor.role !== "admin" && actor.role !== "vip")) return;

    const t = cleanUsername(targetUsername);
    if (persistentUsers[t]) {
      persistentUsers[t].isBanned = false;
      saveData();
      socket.emit("action_success", `کاربر ${t} آزاد شد.`);
      socket.emit("banned_list", getBannedUsers());
    }
  });

  socket.on("get_banned_users", () => {
    const actor = users[socket.id];
    if (!actor || (actor.role !== "admin" && actor.role !== "vip")) return;
    socket.emit("banned_list", getBannedUsers());
  });

  socket.on("set_role", ({ targetUsername, role }) => {
    const actor = users[socket.id];
    if (!actor || actor.role !== "admin") return;
    if (targetUsername === appConfig.adminUser) return;

    const t = cleanUsername(targetUsername);
    if (persistentUsers[t] && ["user", "vip"].includes(role)) {
      persistentUsers[t].role = role;
      saveData();

      const targetSocketId = Object.keys(users).find(
        (id) => users[id].username === t,
      );
      if (targetSocketId) {
        users[targetSocketId].role = role;
        io.to(targetSocketId).emit("role_update", role);

        // refresh channels list as role might affect (admin only in our model)
        const s = io.sockets.sockets.get(targetSocketId);
        if (s) s.emit("channels_list", listAccessibleChannels(t, role));
      }

      broadcastUserList();
      socket.emit("action_success", `نقش کاربر ${t} به ${role} تغییر کرد.`);
    }
  });

  // -------------------- Messaging (with access enforcement) --------------------
  socket.on("send_message", (data) => {
    const user = users[socket.id];
    if (!user) return;

    // rate limit
    const now = Date.now();
    if (!userRateLimits[user.username])
      userRateLimits[user.username] = { count: 0, last: now };
    if (now - userRateLimits[user.username].last > 5000)
      userRateLimits[user.username] = { count: 0, last: now };
    if (userRateLimits[user.username].count >= 5) {
      return socket.emit("error", "لطفا آهسته‌تر پیام ارسال کنید.");
    }
    userRateLimits[user.username].count++;
    const conversationId = String(data?.conversationId || "").trim();
    if (!conversationId) return;

    // ✅ Saved Chat
    if (isSavedConvId(conversationId)) {
      const expected = savedConvIdFor(user.username);
      if (conversationId !== expected) {
        return socket.emit("access_denied", {
          channel: conversationId,
          message: "دسترسی به Saved دیگران مجاز نیست.",
        });
      }
      ensureConversationMaps(conversationId);
    }
    // ✅ DM
    else if (conversationId.includes("_pv_")) {
      if (!isValidDMId(conversationId))
        return socket.emit("error", "گفتگوی خصوصی نامعتبر است.");
      if (!canAccessDM(user, conversationId)) {
        return socket.emit("access_denied", {
          channel: conversationId,
          message: "شما به این گفتگوی خصوصی دسترسی ندارید.",
        });
      }
      if (!conversations[conversationId]) {
        const p = dmParticipants(conversationId);
        if (!p) return socket.emit("error", "گفتگوی خصوصی نامعتبر است.");
        getOrCreateDMConversation(p.a, p.b);
      }
    }
    // ✅ Public channel
    else {
      const cleanConv = cleanChannelName(conversationId);
      if (!channels.includes(cleanConv))
        return socket.emit("error", "کانال وجود ندارد.");
      if (!canAccessChannel(user.username, user.role, cleanConv)) {
        return socket.emit("access_denied", {
          channel: cleanConv,
          message: "شما به این کانال دسترسی ندارید.",
        });
      }
      if (!conversations[cleanConv])
        ensurePublicConversation(cleanConv, "system");
    }

    // content sanitization
    const cleanTextVal = cleanText(data?.text, 1000);
    const cleanFileName = data?.fileName
      ? xss(String(data.fileName)).substring(0, 120)
      : undefined;
    const type = String(data?.type || "text");

    // ✅ validate content to prevent javascript:/phishing
    let content = typeof data?.content === "string" ? data.content : undefined;

    function stripUploadToken(u) {
      // keep only the path part, drop ?t=...
      try {
        const s = String(u || "");
        if (!s.startsWith("/uploads/")) return s;
        return s.split("?")[0];
      } catch {
        return u;
      }
    }

    function isSafeUploadsUrl(u) {
      if (!u || typeof u !== "string") return false;
      // accept /uploads/<file> optionally with query
      return u.startsWith("/uploads/");
    }

    // after validating "content" for non-text:
    if (
      type !== "text" &&
      typeof content === "string" &&
      isSafeUploadsUrl(content)
    ) {
      content = stripUploadToken(content);
    }

    function isSafeDataUrl(u, kind) {
      if (!u || typeof u !== "string") return false;
      // allow only audio recording data url (your recorder uses audio/webm)
      if (kind === "audio") return u.startsWith("data:audio/");
      // disallow data:image/video/file from users (you use uploads for those)
      return false;
    }

    if (type !== "text") {
      if (!content) return socket.emit("error", "محتوای پیام نامعتبر است.");
      const ok = isSafeUploadsUrl(content) || isSafeDataUrl(content, type);

      if (!ok) return socket.emit("error", "لینک/محتوا مجاز نیست.");
    }

    if (
      type === "audio" &&
      typeof content === "string" &&
      content.length > 2_500_000
    )
      return socket.emit("error", "فایل صوتی خیلی بزرگ است.");
    if (
      type === "image" &&
      typeof content === "string" &&
      content.length > 3_500_000
    )
      return socket.emit("error", "تصویر خیلی بزرگ است.");
    if (
      type === "video" &&
      typeof content === "string" &&
      content.length > 5_000_000
    )
      return socket.emit("error", "ویدیو خیلی بزرگ است.");

    const msg = {
      id: crypto.randomBytes(12).toString("hex"),
      sender: user.username,
      text: cleanTextVal,
      type,
      content,
      fileName: cleanFileName,
      conversationId,
      channel: conversationId,
      replyTo: data?.replyTo || null,
      timestamp: new Date().toLocaleTimeString("en-US", {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
      }),
      role: user.role,
    };

    ensureConversationMaps(conversationId);
    messages[conversationId].push(msg);
    if (messages[conversationId].length > 100) messages[conversationId].shift();

    io.to(conversationId).emit("receive_message", msg);
    saveData();
  });

  socket.on("delete_message", (msgId) => {
    const user = users[socket.id];
    if (!user || user.role !== "admin") return;

    const id = String(msgId || "");
    if (!id) return;

    let found = false;
    for (const key of Object.keys(messages)) {
      if (!Array.isArray(messages[key])) continue;
      const idx = messages[key].findIndex((m) => m.id === id);
      if (idx !== -1) {
        messages[key].splice(idx, 1);
        found = true;
        io.to(key).emit("message_deleted", { channel: key, id });
        break;
      }
    }
    if (found) saveData();
  });

  socket.on("search_user", (query) => {
    if (!users[socket.id]) return;
    if (!query || String(query).length > 20) return;

    const cleanQuery = xss(String(query)).toLowerCase();
    const matches = Object.keys(persistentUsers)
      .filter((u) => u.toLowerCase().includes(cleanQuery))
      .slice(0, 30);
    socket.emit("search_results", matches);
  });

  socket.on("disconnect", () => {
    delete users[socket.id];
    broadcastUserList();
  });
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
