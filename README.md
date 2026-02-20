## ✅ Professional README (copy/paste as `README.md`)

# Node Socket.IO Chatroom (Hardened) — Real-time Multi-Room Chat

[![Node.js](https://img.shields.io/badge/Node.js-20%2B-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![PM2](https://img.shields.io/badge/PM2-Process%20Manager-2B037A?logo=pm2&logoColor=white)](https://pm2.keymetrics.io/)
[![Socket.IO](https://img.shields.io/badge/Socket.IO-4.x-010101?logo=socket.io&logoColor=white)](https://socket.io/)
[![Express](https://img.shields.io/badge/Express-4.x-000000?logo=express&logoColor=white)](https://expressjs.com/)
[![License](https://img.shields.io/badge/License-See%20LICENSE-blue)](./LICENSE)

A production-ready, real-time chatroom built with **Node.js + Express + Socket.IO** with an **interactive installer**, persistent storage, roles (Admin/VIP/User), multi-channels, private chats, uploads, and security hardening (**rate limiting**, **bcrypt hashed passwords**, **upload token protection**, **MIME/extension allowlists**).

> **Client UI:** RTL Persian (Fa)  
> **Server logs:** English

## Table of Contents

- [Features](#-features)
- [Screenshots](#-screenshots)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Quick Start (Local)](#-quick-start-local)
- [Production Install (Ubuntu/Debian)](#-production-install-ubuntudebian)
- [Management CLI](#-management-cli)
- [Configuration](#-configuration)
- [Upload Tokens](#-upload-tokens)
- [Reverse Proxy (Nginx)](#-reverse-proxy-nginx)
- [Security Notes](#-security-notes)
- [Troubleshooting](#-troubleshooting)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

### 💬 Chat

- **Real-time messaging** with Socket.IO
- **Public channels** (create/delete for Admin/VIP)
- **Private chats (PV)** with deterministic room naming (`userA_pv_userB`)
- **Reply to message** UX (swipe / context menu)
- **Unread counters** for channels and private chats
- **Notifications** (browser notifications + sound)

### 🛡️ Roles & Moderation

- Roles: **Admin / VIP / User**
- **Ban / Unban** users (Admin/VIP)
- **Message deletion** (Admin)
- Optional **Hide online user list** for normal users (Admin setting)

### 📎 Uploads (Protected)

- Upload endpoint with:
  - **IP rate limiting**
  - **Authenticated uploads via token** (prevents anonymous disk abuse)
  - Optional **download protection via token query** (`protectUploads`)
  - **MIME + extension allowlists**
  - **Max upload size** configurable

### 💾 Persistence (Local JSON)

Stored under `data/`:

- users (hashed passwords, roles, ban state)
- messages (per channel)
- channels list
- runtime config

Includes **atomic JSON writes** to reduce corruption risk.

### 🔒 Security Hardening

- `helmet` enabled
  - CSP kept **disabled** to preserve CDN + inline scripts in the current UI
- `X-Content-Type-Options: nosniff`
- JSON body limit (`10kb`)
- Input sanitization (`xss`)
- Password hashing with `bcryptjs`
- Upload protection (token + allowlists + limits)
- Message rate-limiting (anti-spam)

## 📸 Screenshots

> Add screenshots/gifs under `./assets/` and update links below.

- `assets/login.png`
- `assets/chat.png`

Example:

```md
![Login](./assets/login.png)
![Chat](./assets/chat.png)
```

## 🧱 Tech Stack

- **Backend**: Node.js, Express, Socket.IO
- **Security**: helmet, express-rate-limit, bcryptjs, xss
- **Uploads**: multer
- **Frontend**: Vue 3 (CDN), TailwindCSS (CDN), FontAwesome (CDN)

## 📁 Project Structure

```text
.
├─ install.sh
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
git clone https://github.com/power0matin/node-socketio-chatroom.git
cd node-socketio-chatroom

npm install
node server.js
```

Open:

- [http://localhost:3000](http://localhost:3000)

> Local run uses `data/config.json` if present. If it does not exist yet, the server will create it using defaults.

## 🧰 Production Install (Ubuntu/Debian)

This repository includes an **interactive one-command installer**: `install.sh`.

It will:

- install Node.js 20 (if missing) and PM2
- set up app directory, config, and permissions
- install dependencies
- start the server via PM2
- install a management CLI command: `node-socketio-chatroom`

### Requirements

- Ubuntu/Debian VPS
- A user with `sudo` access
- Firewall allows your chosen port (default `3000`)

### Install (Recommended)

```bash
sudo apt-get update -y
sudo apt-get install -y git curl ca-certificates

git clone https://github.com/power0matin/node-socketio-chatroom.git
cd node-socketio-chatroom

chmod +x install.sh
./install.sh
```

At the end, you will get:

- URL: `http://<server-ip>:<port>`
- CLI command: `node-socketio-chatroom`

### Notes

- If you use a reverse proxy (Nginx), set `allowedOrigins` to your domain (recommended).
- If you change settings using the CLI, it restarts the PM2 process automatically.

## 🧑‍💻 Management CLI

After installation:

```bash
node-socketio-chatroom
```

Menu actions include:

- status / restart / stop
- view logs
- change admin username/password (stored hashed)
- change max upload size
- change app name
- change allowed origins
- uninstall

## ⚙️ Configuration

Runtime configuration is stored in:

```text
data/config.json
```

### Supported options

| Key              | Type                | Description                                                                 |
| ---------------- | ------------------- | --------------------------------------------------------------------------- |
| `adminUser`      | string              | Admin username                                                              |
| `adminPassHash`  | string              | Admin bcrypt password hash                                                  |
| `port`           | number              | Server port                                                                 |
| `maxFileSizeMB`  | number              | Upload limit                                                                |
| `appName`        | string              | UI title                                                                    |
| `hideUserList`   | boolean             | Hide online users list from normal users                                    |
| `allowedOrigins` | `*` or string/array | Socket.IO CORS allowlist (`*` or comma-separated origins / array in config) |
| `protectUploads` | boolean             | If `true`, downloads require a valid token (`?t=...` or `X-Upload-Token`)   |

> Tip: Prefer using the built-in CLI to edit config safely instead of manual JSON edits.

## 🔐 Upload Tokens

After login, the server issues a temporary **upload token** (default **6 hours**).

- Upload request must include header: `X-Upload-Token: <token>`
- When `protectUploads: true`, file URLs should include: `?t=<token>`
  - The client already appends this automatically when `uploadToken` exists.

This prevents:

- anonymous upload abuse
- public access to uploaded files (when protection is enabled)

## 🌐 Reverse Proxy (Nginx)

Recommended for:

- HTTPS
- domain-based access
- better security and observability

Example Nginx site:

```nginx
server {
  server_name yourdomain.com;

  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_http_version 1.1;

    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;

    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

Then set `allowedOrigins` to `https://yourdomain.com` (recommended) and restart the app.

## 🔒 Security Notes

- Use a **strong admin password** during installation.
- Do **not** keep `allowedOrigins: "*"` on a public server unless you explicitly want open access.
- Keep `protectUploads: true` if you want uploaded content to be non-public.

> CSP is disabled intentionally because the current UI uses inline scripts and CDN resources.
> If you want CSP, migrate the UI to self-hosted assets + remove inline scripts.

## 🧯 Troubleshooting

### Port already in use

Change the port in `data/config.json` (or via CLI), then restart:

```bash
pm2 restart <your-app-name>
```

### Upload returns `401 Unauthorized`

Common causes:

- Missing `X-Upload-Token` header on `/upload`
- Expired token (log out / re-login)
- `protectUploads: true` but the file URL does not include `?t=<token>`

### CORS / Socket.IO connection issues

Set `allowedOrigins` to:

- `https://yourdomain.com` (recommended)
- or `https://yourdomain.com,http://localhost:3000`

Then restart the PM2 process.

## 🗺️ Roadmap

- Optional DB storage (SQLite/Postgres)
- CSP support (self-hosted assets)
- Admin dashboard (web UI) for roles/channels/messages
- Media thumbnails + malware scanning hooks

## 🤝 Contributing

PRs are welcome. Please:

- keep changes small and well-scoped
- preserve backward compatibility for `data/*.json`
- document config changes in the README

## 📜 License

See [`LICENSE`](./LICENSE).
