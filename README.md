# Node Socket.IO Chatroom

A hardened single-host real-time chat application built with Node.js, Express, Socket.IO and a self-hosted Vue/Tailwind frontend.

Version `1.11.0` is the production-hardening release candidate. The repository includes encrypted persistence, session restoration, multi-session authorization, protected uploads, verified backup/restore, transactional updates, a systemd service, health/readiness endpoints and automated CI.

## Supported deployment model

The production architecture is intentionally unambiguous:

```text
Internet
  ↓ HTTPS
Nginx / TLS termination
  ↓ HTTP on loopback only
Node.js (127.0.0.1:<port>)
```

Do not expose the Node backend directly to the Internet in the recommended deployment. The application trusts forwarded client IP information only when the immediate peer is loopback.

## Requirements

Development / CI:

- Node.js 20 or 22 (`>=20` is enforced)
- npm 10+

Production installer:

- Ubuntu/Debian-class Linux with systemd
- root/sudo access
- Node.js 20+
- npm 10+
- `rsync`, `curl`, `tar`, `sha256sum`
- Nginx (recommended for public HTTPS)

The installer does not bootstrap an old embedded copy of the application. It installs the exact checked-out release tree and uses `package-lock.json` with `npm ci`.

## Quick start for local development

```bash
git clone https://github.com/power0matin/node-socketio-chatroom.git
cd node-socketio-chatroom
npm ci
npm run build
npm test
npm start
```

The default local listener is `http://127.0.0.1:3000` unless configuration changes it. The normal-user login path creates a user on first successful login. Production admin credentials should be created by the installer rather than by hand.

Useful commands:

```bash
npm run build
npm run check
npm test
npm run test:unit
npm run test:integration
npm run test:security
npm run smoke
npm run browser-smoke
npm audit --audit-level=high
npm outdated
```

## Production installation

Use a complete checkout of the exact tag/commit you intend to deploy. Do not pipe only `install.sh` from the Internet; the installer intentionally refuses to run without the rest of the release tree.

Example:

```bash
git clone https://github.com/power0matin/node-socketio-chatroom.git
cd node-socketio-chatroom
git checkout <release-tag-or-full-sha>

sudo env \
  INSTALL_DIR=/opt/node-socketio-chatroom \
  BACKUP_ROOT=/var/backups/node-socketio-chatroom \
  PORT=3000 \
  PUBLIC_ORIGIN=https://chat.example.com \
  ADMIN_PASSWORD='replace-with-a-long-random-password' \
  ./install.sh
```

The installer:

1. validates Node/npm and required tools;
2. rejects unsafe or unrelated install paths;
3. stages the exact checked-out source tree;
4. installs the exact locked dependency graph with `npm ci`;
5. builds the self-hosted frontend and runs syntax validation before pruning development-only packages;
6. runs a high-severity production dependency audit;
7. creates a bcrypt-hashed admin credential and validated config;
8. creates an installation sentinel and restrictive permissions;
9. installs/enables a version-controlled systemd unit;
10. starts the service;
11. polls `/readyz` before reporting success.

The service uses `Restart=on-failure`, starts automatically at boot through `WantedBy=multi-user.target`, runs as a dedicated unprivileged user and receives SIGTERM for graceful shutdown.

## Configuration

Runtime configuration is stored in `data/config.json`. Invalid configuration fails fast with a descriptive error before the server listens.

Important fields include:

| Key | Purpose |
| --- | --- |
| `adminUser` | Administrative username. Reserved identifiers are rejected. |
| `adminPassHash` | bcrypt admin password hash. Never store plaintext passwords. |
| `adminSessionVersion` | Revocation generation for admin sessions. |
| `port` | TCP port, integer `1..65535`. |
| `bindHost` | Production default `127.0.0.1`. |
| `allowedOrigins` | Explicit HTTP/HTTPS origins. Wildcard origins are rejected. |
| `trustProxy` | Enables forwarded-IP handling only from a loopback peer. |
| `maxFileSizeMB` | Maximum size of one upload. |
| `maxFilesPerUser` | Per-user file-count ceiling. |
| `userQuotaMB` | Per-user stored upload quota. |
| `globalQuotaMB` | Global stored upload quota. |
| `minFreeDiskMB` | Minimum free disk space that must remain after an upload. |
| `uploadRetentionDays` | Attachment retention period. |
| `accessMode` | `restricted` or `open`. |
| `defaultChannelsForNewUsers` | Initial memberships in restricted mode. |
| `maxChannelMessages` | Bounded public-channel history. |
| `maxDmMessages` | Bounded DM history. |
| `maxSavedMessages` | Bounded saved-message history. |
| `sessionTtlHours` | Signed session lifetime. |

Supported environment overrides include `PORT`, `BIND_HOST`, `ALLOWED_ORIGINS`, `TRUST_PROXY`, `DATA_DIR`, `BACKUP_ROOT` and `DATA_ENC_KEY`. If `DATA_ENC_KEY` is used, it must remain stable for existing encrypted data. A wrong key is treated as a startup failure, not as an empty database.

## Persistence and data safety

Persistent application state is stored as authenticated AES-256-GCM data in `data/state.json`. The encryption key is stored separately in `data/.data-key` unless a validated `DATA_ENC_KEY` is supplied. Session and download-capability secrets are stored separately in the protected data directory.

The loader distinguishes:

- missing state: allowed for a new installation;
- wrong encryption key: fatal;
- corrupt/authentication-failed state: fatal;
- legacy multi-file persistence: migrated only after validation and a verified backup.

State writes use a temporary file, file synchronization, atomic rename and directory synchronization. Persistence errors propagate to readiness/shutdown rather than being silently converted to empty state.

The legacy installer `dataEncKey` is migrated to the dedicated key file before legacy encrypted data is rewritten. Upgrade tests verify users, messages and permissions survive the migration.

## Authentication, reconnect and multi-session behavior

Login sessions are signed and persisted. Socket.IO transport reconnect is not treated as authentication: the browser explicitly resumes its signed session and then rejoins the current view.

The anonymous login screen does not keep an unnecessary Socket.IO connection open. The browser connects when a login is submitted or when a stored session needs to be resumed.

Password changes, bans and role changes revoke or refresh every active session for the affected username, not only one socket/tab. Authorization checks are performed server-side for channels, DMs, replies, saved messages, uploads and administrative actions.

## Direct messages

DM membership and participant identifiers are validated server-side. A connected user joins a personal delivery room after authentication, so a recipient receives persisted DM events and unread updates even when that DM view is not currently open.

## Upload security and disk protection

`POST /upload` requires an authenticated session header. The upload parser accepts one file and zero text fields, with explicit limits on file count, multipart parts and file size. MIME type and extension pairs are allowlisted.

Additional controls include:

- per-IP upload rate limiting;
- exact-origin validation;
- per-user file-count and byte quotas;
- global byte quota;
- minimum free-disk guard;
- retention cleanup;
- orphan cleanup;
- owner validation before an attachment can be sent;
- separate download capability tokens instead of placing the raw session token in file URLs;
- session revocation on logout/password change/ban.

Uploaded files are not exposed through a public static directory. Downloads go through `/uploads/:id` and require a valid capability.

## Health and readiness

```text
GET /healthz
GET /readyz
```

`/healthz` answers whether the process is operational and not shutting down. `/readyz` additionally requires the application persistence layer to be safe to serve traffic.

Install, restart, update and restore operations use readiness checks instead of trusting process-manager status alone.

## Nginx reverse proxy / TLS

Terminate HTTPS at Nginx and proxy to the loopback HTTP backend:

```nginx
server {
    listen 443 ssl http2;
    server_name chat.example.com;

    # ssl_certificate ...;
    # ssl_certificate_key ...;

    client_max_body_size 51m;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Set `allowedOrigins` / `PUBLIC_ORIGIN` to the exact public HTTPS origin, for example `https://chat.example.com`.

Do not configure Nginx to proxy HTTP to a TLS-enabled Node listener; the hardened runtime intentionally has one TLS architecture: TLS at the reverse proxy, HTTP on loopback to Node.

## Frontend and audio

Production frontend dependencies are self-hosted and reproducibly generated by `npm run build`; generated bundles under `public/vendor/`, `public/assets/tailwind.css` and `public/assets/render.js` are intentionally not committed.

The build precompiles the in-DOM Vue template into `public/assets/render.js`, copies the Vue runtime-only build, and loads Socket.IO, Vue, the render function and application code with deferred self-hosted scripts. The generated render function is checked to contain no dynamic `new Function`/`unsafe-eval` requirement. CI performs two independent builds and requires identical hashes, then runs a headless-browser CSP smoke test against the real HTTP application.

Voice recording requests browser microphone permission. The server sends `Permissions-Policy: microphone=(self)` and the client stops `MediaStream` tracks on stop/error/cancel paths. Browser permission can still be denied by the user or browser policy.

## Backup

Backups are stored outside the application directory so updater synchronization cannot delete them.

```bash
sudo env \
  CHATROOM_DIR=/opt/node-socketio-chatroom \
  BACKUP_ROOT=/var/backups/node-socketio-chatroom \
  /opt/node-socketio-chatroom/scripts/backup.sh
```

Each archive receives a collision-safe name and a matching `.sha256`. Creation verifies both archive readability and checksum. Existing backups are never silently overwritten.

## Restore

```bash
sudo env \
  CHATROOM_DIR=/opt/node-socketio-chatroom \
  BACKUP_ROOT=/var/backups/node-socketio-chatroom \
  /opt/node-socketio-chatroom/scripts/restore.sh \
  /var/backups/node-socketio-chatroom/chatroom-backup-<timestamp>-<suffix>.tar.gz
```

Restore verifies the checksum and archive paths, makes a separate pre-restore safety backup, stages restored data, preserves ownership, restarts the service, checks readiness and rolls back to the previous data if the restored service does not become ready.

## Updating

Use an immutable release tag or full commit SHA:

```bash
sudo env \
  CHATROOM_DIR=/opt/node-socketio-chatroom \
  BACKUP_ROOT=/var/backups/node-socketio-chatroom \
  /opt/node-socketio-chatroom/scripts/update.sh --ref <release-tag-or-full-sha>
```

The updater uses an external atomic lock with stale-lock handling, creates and verifies a backup, stages the release, performs a full locked dependency install, rebuilds and validates frontend/runtime assets, prunes development dependencies, audits production dependencies, validates persistence/migration, swaps code without deleting persistent data, restarts and polls readiness. On post-swap failure it restores the previous code and verifies the rollback.

For controlled local testing, `--source /path/to/release-tree` can be used instead of a network ref.

## Management menu

From an installed tree:

```bash
sudo /opt/node-socketio-chatroom/menu.sh
```

The menu exposes status, restart+readiness, recent logs, verified backup, immutable-ref update, verified restore and safe uninstall. It delegates lifecycle behavior to the version-controlled scripts instead of maintaining a second updater implementation.

## Safe uninstall

```bash
sudo env \
  CHATROOM_DIR=/opt/node-socketio-chatroom \
  BACKUP_ROOT=/var/backups/node-socketio-chatroom \
  /opt/node-socketio-chatroom/scripts/uninstall.sh
```

Uninstall requires the project sentinel and package identity, rejects symlinks and protected/broad paths, creates a verified final backup, verifies that any systemd unit points to the same installation, then removes only that installation tree. The external backup is retained.

## Reboot recovery and service operations

```bash
sudo systemctl status node-socketio-chatroom
sudo systemctl restart node-socketio-chatroom
sudo journalctl -u node-socketio-chatroom -n 100 --no-pager
sudo systemctl is-enabled node-socketio-chatroom
```

A production installation enables the unit at boot. After a real host reboot, verify both `systemctl is-active node-socketio-chatroom` and `/readyz`.

## CI and release gate

GitHub Actions tests Node 20 and Node 22. The gate includes:

- `npm ci`;
- two deterministic frontend builds with hash comparison;
- JavaScript syntax checks;
- unit/integration/security/upgrade/lifecycle tests;
- runtime smoke test;
- headless Chrome/Chromium render check under the application CSP;
- `npm audit --audit-level=high`;
- `npm outdated` freshness reporting without treating known major-version availability as a vulnerability;
- Bash parse checks and ShellCheck;
- clean installation into a pre-existing empty directory;
- installed-runtime health/readiness and SIGTERM shutdown;
- safe uninstall with a retained verified backup.

## Repository layout

```text
.github/workflows/ci.yml
deploy/node-socketio-chatroom.service
public/
  index.html
  assets/
    app.js
    app.css
    theme.css
    # tailwind.css + render.js are generated
  vendor/                  # generated by npm run build
scripts/
  backup.sh
  browser-smoke.js
  build-assets.js
  restore.sh
  smoke-test.js
  uninstall.sh
  update.sh
src/
  lib/
  server.js
  styles.css
tests/
install.sh
menu.sh
package.json
package-lock.json
```

Runtime `data/`, uploads, backups, logs, keys, locks and generated frontend bundles are excluded from Git.

## Operational limits

This release intentionally remains a single-host, single-Node-process application with encrypted local JSON state. Histories and upload storage are bounded and filesystem/bcrypt work in hot paths is asynchronous, but each durable state mutation still rewrites the encrypted state snapshot. That is appropriate for a small/moderate single-host chat deployment, not for a high-volume horizontally scaled service. Redis/PostgreSQL/SQLite or a journaled persistence layer should be evaluated before expanding the documented scale profile.

No built-in malware scanner is provided for uploads; MIME/extension validation is not a substitute for malware scanning in hostile file-sharing deployments.

## Troubleshooting

If startup fails, check:

```bash
sudo journalctl -u node-socketio-chatroom -n 200 --no-pager
```

Common causes are invalid config, an unavailable port, a mismatched encryption key, corrupt encrypted state, wrong ownership/permissions or an origin mismatch.

If Nginx returns `502`, confirm Node is listening on the configured loopback port and that Nginx uses `http://127.0.0.1:<port>`.

If uploads return `401`, the browser session may be invalid/revoked. If they return `403`, check the exact configured origin. `413`, `429`, `507` and `503` respectively indicate request-size, file-count/rate, storage-quota/free-space or storage-health rejection paths.

## License

See [LICENSE](./LICENSE).
