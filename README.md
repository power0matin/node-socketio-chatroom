## ✅ Professional README (copy/paste as `README.md`)

# Node Socket.IO Chatroom (Hardened) — Real-time Multi-Room Chat

A production-ready, real-time chatroom built with **Node.js + Express + Socket.IO** with a **single-command installer**, persistent storage, roles (Admin/VIP/User), multi-channels, private chats, uploads, and security hardening (rate limiting, hashed passwords, upload token protection, MIME/extension allowlists).

> Language/UI: RTL Persian (Fa) client UI, server logs in English.

## ✨ Features

### Chat

- **Real-time messaging** with Socket.IO
- **Public channels** (create/delete for Admin/VIP)
- **Private chats (PV)** with deterministic room naming
- **Reply to message** UX (swipe / context menu)
- **Unread counters** for channels and private chats
- **Notifications** (browser notifications + sound)

### Roles & Moderation

- Roles: **Admin / VIP / User**
- **Ban / Unban** users (Admin/VIP)
- **Message deletion** (Admin)
- Optional **hide user list** for normal users (Admin setting)

### Uploads (Protected)

- Upload endpoint with:
  - **IP rate limiting**
  - **Authenticated uploads via token**
  - **Download protection via token query** (`protectUploads`)
  - **MIME + extension allowlists**
  - Max upload size configurable via config

### Persistence

- Data stored locally under `data/`:
  - users (hashed passwords)
  - messages
  - channels
  - runtime config
- Safe writes using atomic JSON writing

### Security Hardening

- `helmet` enabled (CSP disabled to preserve CDN/inline UI)
- `X-Content-Type-Options: nosniff`
- JSON body limit (`10kb`)
- Input sanitization (`xss`)
- Password hashing with `bcryptjs`
- Upload abuse prevention (token + limits + allowlists)

## 🧱 Tech Stack

- **Backend**: Node.js, Express, Socket.IO
- **Security**: helmet, express-rate-limit, bcryptjs, xss
- **Uploads**: multer
- **Frontend**: Vue 3 (CDN), Tailwind (CDN), FontAwesome (CDN)

## 📁 Project Structure

```text
.
├─ server.js
├─ package.json
├─ public/
│  ├─ index.html
│  └─ uploads/               # uploaded files (restricted permissions)
└─ data/
   ├─ config.json            # runtime configuration (hashed admin password)
   ├─ users.json             # users + roles + ban state (hashed user passwords)
   ├─ messages.json          # per-channel message history
   └─ channels.json          # channels list
```

## 🚀 Quick Start (Local)

### Requirements

- Node.js **20+**
- npm **9+**

### Run

```bash
npm install
node server.js
# open http://localhost:3000
```

## 🧰 One-Command Production Install (Ubuntu/Debian)

This project includes an interactive installer that:

- installs Node.js 20 (if missing) and PM2
- sets up app directory, config, and permissions
- starts the server via PM2
- installs a management CLI command: `chat`

### Usage

1. Copy the installer script to your server (e.g. `install.sh`)
2. Run:

```bash
chmod +x install.sh
./install.sh
```

When finished, you will get:

- URL: `http://<server-ip>:<port>`
- A management command: `chat`

## ⚙️ Configuration

Runtime configuration is stored in:

```text
data/config.json
```

### Supported options

| Key              | Type          | Description                                               |
| ---------------- | ------------- | --------------------------------------------------------- |
| `adminUser`      | string        | Admin username                                            |
| `adminPassHash`  | string        | Admin password hash (bcrypt)                              |
| `port`           | number        | Server port                                               |
| `maxFileSizeMB`  | number        | Upload limit                                              |
| `appName`        | string        | UI app title                                              |
| `hideUserList`   | boolean       | Hide online users from normal users                       |
| `allowedOrigins` | `*` or string | Socket.IO CORS allowlist (`*` or comma-separated origins) |
| `protectUploads` | boolean       | If `true`, downloads require upload token                 |

> Tip: you can edit settings using the built-in CLI (`chat`) without manually editing JSON.

## 🔐 Upload Tokens (How it works)

After login, the server issues a temporary **upload token** (default 6 hours).

- Upload request requires header: `X-Upload-Token: <token>`
- When `protectUploads: true`, download links require: `?t=<token>`

This prevents anonymous disk abuse and protects uploaded content from public access.

## 🧑‍💻 Management CLI

After installer completes:

```bash
chat
```

Menu features:

- status / restart / stop
- view logs
- change admin username/password (stored hashed)
- change max upload size
- change app name
- change allowed origins
- uninstall

## 🧯 Troubleshooting

### Port already in use

Change `port` in `data/config.json` (or via `chat`) and restart PM2.

### Upload returns 401

Make sure the client sends:

- `X-Upload-Token` header
  And if downloads are protected:
- file links include `?t=<token>`

### CORS / connection issues

Set `allowedOrigins` to:

- `*` for open access (not recommended for public internet)
- OR `https://yourdomain.com,http://localhost:3000`

Then restart the server.

## 🗺️ Roadmap (Ideas)

- Optional DB storage (SQLite/Postgres)
- CSP support without CDN/inline scripts (self-hosted assets)
- Admin panel for roles/messages/channels
- Media thumbnails + virus scanning hooks

## 🤝 Contributing

PRs are welcome. Please:

- keep changes minimal and well-scoped
- preserve backward compatibility for `data/*.json`
- add notes for config changes

## 📜 License

Add your chosen license file (e.g. `MIT`, `Apache-2.0`) and update this section.

## 🙏 Credits

Built with Socket.IO, Express, Vue, and TailwindCSS.
