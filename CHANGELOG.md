# Changelog

All notable changes to this project are documented here.

## [1.11.0] - 2026-08-17

### Data safety and persistence

- Replaced ambiguous fail-open encrypted JSON loading with strict authenticated persistence handling: missing state is distinct from corrupt state and wrong-key/authentication failures abort startup.
- Added backward-compatible migration of the legacy installer `dataEncKey` into `data/.data-key`.
- Added a verified pre-migration backup and upgrade fixtures that preserve users, messages, roles and configuration.
- Consolidated persistent runtime state into an atomically replaced encrypted `state.json` while preserving legacy migration support.
- Propagated persistence failures to readiness and graceful shutdown instead of silently treating them as success.

### Authentication and authorization

- Added signed persisted sessions with explicit Socket.IO session restoration after reconnect.
- Added logout/session revocation and generation-based invalidation for password, ban and role changes.
- Made role changes, bans and password changes apply to every active session for a username.
- Centralized server-side validation for channel access, DM participants, saved messages, replies and attachment ownership.
- Added personal Socket.IO rooms so DMs reach online recipients even when they are not currently viewing that DM.
- Reserved unsafe username identifiers used by internal DM/saved-message routing.

### Upload and storage security

- Upgraded Multer to the supported 2.2.x line and added regression coverage for malformed multipart data.
- Added explicit one-file/zero-field multipart, MIME, extension and file-size validation.
- Added per-user file and byte quotas, a global quota, free-disk guard, retention and orphan cleanup.
- Split download capabilities from raw session credentials so session tokens are not persisted into attachment URLs.
- Added exact-origin upload validation and proxy-aware rate limiting that trusts forwarded IP only from loopback.
- Fixed a multipart part-count configuration that rejected valid single-file uploads.

### Runtime and deployment

- Standardized production TLS architecture on Nginx TLS termination with a loopback-only HTTP Node backend.
- Added `/healthz` and `/readyz`.
- Added a version-controlled hardened systemd unit with boot enablement and graceful SIGTERM handling.
- Fixed the graceful-shutdown deadline timer so a successful shutdown does not leave the event loop alive until the timeout expires.
- Added structured timestamped logging for authentication, security, migration, upload and lifecycle events without logging credentials.
- Made frontend dependencies reproducible/self-hosted instead of relying on Tailwind/Vue/FontAwesome production CDNs.
- Allowed microphone access for self while retaining camera/geolocation restrictions and added MediaStream cleanup paths.

### Installer, update, backup and recovery

- Removed the embedded legacy application source from the installer; the checked-out release is now the single source of truth.
- Enforced Node.js 20+, npm 10+, lockfile-based `npm ci`, source completeness, safe install paths and readiness verification.
- Fixed installation into a pre-existing empty target directory while still refusing non-empty unrelated directories.
- Added an external verified backup store so updater synchronization cannot delete backups.
- Added transactional update staging, immutable release refs, atomic locking with stale-lock handling, rollback and post-restart readiness checks.
- Added verified restore with pre-restore safety backup, archive path validation and readiness-based rollback.
- Fixed backup filename collisions that could otherwise overwrite the selected restore archive when two backups were created in the same second.
- Added sentinel/package/service identity checks to safe uninstall and a verified final backup before deletion.
- Preserved executable mode for lifecycle shell scripts.

### Configuration and frontend correctness

- Added fail-fast validation for ports, bind host, origins, limits, quotas, session TTL, access mode and reserved identifiers.
- Removed wildcard production-origin fallback and exact-prefix origin matching bugs.
- Added reconnect state restoration, undefined-handler cleanup and bounded message histories.
- Fixed DM notification/unread delivery, reply validation and audio upload/recording cleanup.

### Testing and CI

- Added automated storage, configuration, authentication, authorization, multi-session, DM, upload, upgrade, backup/restore, rollback, update-lock, health/readiness and graceful-shutdown tests.
- Added Node 20/22 GitHub Actions quality gates with reproducible frontend build, syntax checks, full tests, runtime smoke tests and `npm audit`.
- Added clean-install/runtime/uninstall lifecycle validation and ShellCheck.

### Documentation

- Rewrote the operations guide to match the actual systemd + Nginx + encrypted-state architecture and lifecycle tooling.
- Replaced stale claims in `ISSUES.md` with evidence-based hardening status.

### Compatibility notes

- Legacy encrypted multi-file data is migrated automatically only when it validates successfully; wrong keys/corrupt data fail closed instead of starting empty.
- Production now expects TLS termination at the reverse proxy. The Node listener is HTTP and should remain bound to loopback.
- Installer usage changed: `install.sh` must be run from a complete release checkout rather than downloaded as a standalone script.

## [1.10.0] - 2026-07-17

Historical release. This version introduced CSP/origin checks, message limits, audio-over-upload and several UI/runtime fixes, but its installer/runtime lifecycle still contained issues subsequently addressed by `1.11.0`.

## [1.1.18] - Previous release

Historical installer-based release used as a compatibility fixture for upgrade migration tests.
