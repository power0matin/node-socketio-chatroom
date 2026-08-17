'use strict';

const crypto = require('crypto');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

const MIME_EXT = new Map([
  ['image/jpeg', new Set(['.jpg', '.jpeg'])],
  ['image/png', new Set(['.png'])],
  ['image/gif', new Set(['.gif'])],
  ['image/webp', new Set(['.webp'])],
  ['audio/webm', new Set(['.webm'])],
  ['audio/mpeg', new Set(['.mp3'])],
  ['video/mp4', new Set(['.mp4'])],
  ['video/webm', new Set(['.webm'])],
  ['application/pdf', new Set(['.pdf'])],
  ['text/plain', new Set(['.txt'])],
]);

class UploadError extends Error {
  constructor(message, status = 400, code = 'UPLOAD_ERROR') {
    super(message);
    this.name = 'UploadError';
    this.status = status;
    this.code = code;
  }
}

function safeOriginalName(name) {
  const base = path.basename(String(name || '')).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 120);
  if (!base || base === '.' || base === '..') throw new UploadError('Invalid file name.', 400, 'INVALID_NAME');
  return base;
}

function validateFileMeta(name, mime) {
  const cleanName = safeOriginalName(name);
  const cleanMime = String(mime || '').split(';', 1)[0].trim().toLowerCase();
  const ext = path.extname(cleanName).toLowerCase();
  const allowedExts = MIME_EXT.get(cleanMime);
  if (!allowedExts) throw new UploadError('File MIME type is not allowed.', 415, 'DISALLOWED_MIME');
  if (!allowedExts.has(ext)) throw new UploadError('File extension does not match the allowed MIME type.', 415, 'DISALLOWED_EXTENSION');
  return { originalName: cleanName, mime: cleanMime, ext };
}

function attachmentUsage(attachments, username) {
  let userBytes = 0;
  let userFiles = 0;
  let globalBytes = 0;
  for (const rec of Object.values(attachments || {})) {
    if (!rec || rec.deletedAt) continue;
    const bytes = Number(rec.size || 0);
    globalBytes += bytes;
    if (rec.owner === username) { userBytes += bytes; userFiles += 1; }
  }
  return { userBytes, userFiles, globalBytes };
}

async function freeDiskBytes(targetDir) {
  if (typeof fsp.statfs !== 'function') return Number.POSITIVE_INFINITY;
  const st = await fsp.statfs(targetDir);
  return Number(st.bavail) * Number(st.bsize);
}

function capabilityToken(secret, id) {
  return crypto.createHmac('sha256', secret).update(`download:${id}`).digest('base64url').slice(0, 32);
}

function verifyCapability(secret, id, token) {
  const expected = capabilityToken(secret, id);
  const a = Buffer.from(expected);
  const b = Buffer.from(String(token || ''));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function streamUpload(req, { uploadsDir, username, attachments, config, downloadSecret }) {
  const meta = validateFileMeta(req.headers['x-file-name'], req.headers['content-type']);
  const contentLength = Number(req.headers['content-length'] || 0);
  const maxBytes = config.maxFileSizeMB * 1024 * 1024;
  if (!Number.isFinite(contentLength) || contentLength <= 0) throw new UploadError('Content-Length is required.', 411, 'LENGTH_REQUIRED');
  if (contentLength > maxBytes) throw new UploadError('File is too large.', 413, 'FILE_TOO_LARGE');

  const usage = attachmentUsage(attachments, username);
  if (usage.userFiles >= config.maxFilesPerUser) throw new UploadError('Per-user file count quota exceeded.', 429, 'FILE_QUOTA');
  if (usage.userBytes + contentLength > config.userQuotaMB * 1024 * 1024) throw new UploadError('Per-user storage quota exceeded.', 429, 'USER_QUOTA');
  if (usage.globalBytes + contentLength > config.globalQuotaMB * 1024 * 1024) throw new UploadError('Global storage quota exceeded.', 507, 'GLOBAL_QUOTA');
  const free = await freeDiskBytes(uploadsDir);
  if (free - contentLength < config.minFreeDiskMB * 1024 * 1024) throw new UploadError('Server disk free-space threshold would be exceeded.', 507, 'LOW_DISK');

  await fsp.mkdir(uploadsDir, { recursive: true, mode: 0o700 });
  const id = crypto.randomBytes(18).toString('hex');
  const storedName = `${id}${meta.ext}`;
  const finalPath = path.join(uploadsDir, storedName);
  const tmpPath = `${finalPath}.${process.pid}.tmp`;
  const out = fs.createWriteStream(tmpPath, { flags: 'wx', mode: 0o600 });
  let received = 0;
  let failed = null;

  try {
    for await (const chunk of req) {
      received += chunk.length;
      if (received > maxBytes || received > contentLength) {
        failed = new UploadError('Upload exceeded declared or configured size.', 413, 'FILE_TOO_LARGE');
        break;
      }
      if (!out.write(chunk)) await new Promise((resolve) => out.once('drain', resolve));
    }
    if (failed) throw failed;
    if (received !== contentLength) throw new UploadError('Upload body length does not match Content-Length.', 400, 'LENGTH_MISMATCH');
    await new Promise((resolve, reject) => out.end((error) => error ? reject(error) : resolve()));
    await fsp.rename(tmpPath, finalPath);
  } catch (error) {
    out.destroy();
    await fsp.rm(tmpPath, { force: true }).catch(() => {});
    throw error;
  }

  const now = Date.now();
  const record = {
    id,
    owner: username,
    storedName,
    originalName: meta.originalName,
    mime: meta.mime,
    size: received,
    createdAt: now,
    expiresAt: now + config.uploadRetentionDays * 86400_000,
  };
  attachments[id] = record;
  return { record, url: `/uploads/${id}?d=${encodeURIComponent(capabilityToken(downloadSecret, id))}` };
}

async function cleanupUploads({ uploadsDir, attachments, retentionNow = Date.now() }) {
  const removed = [];
  for (const [id, rec] of Object.entries(attachments || {})) {
    if (!rec || rec.deletedAt || !rec.expiresAt || rec.expiresAt > retentionNow) continue;
    await fsp.rm(path.join(uploadsDir, rec.storedName), { force: true }).catch(() => {});
    rec.deletedAt = retentionNow;
    removed.push(id);
  }
  const known = new Set(Object.values(attachments || {}).filter(Boolean).map((r) => r.storedName));
  try {
    for (const entry of await fsp.readdir(uploadsDir, { withFileTypes: true })) {
      if (!entry.isFile() || known.has(entry.name) || entry.name.endsWith('.tmp')) continue;
      const file = path.join(uploadsDir, entry.name);
      const st = await fsp.stat(file);
      if (retentionNow - st.mtimeMs > 86400_000) await fsp.rm(file, { force: true });
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  return removed;
}

module.exports = {
  UploadError,
  attachmentUsage,
  capabilityToken,
  cleanupUploads,
  streamUpload,
  validateFileMeta,
  verifyCapability,
};
