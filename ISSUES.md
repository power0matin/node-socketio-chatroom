# Production Hardening Verification Status

This file records repository-level issues addressed for the `1.11.0` hardening work. It intentionally avoids blanket claims such as “all issues fixed” unless supported by current source and automated evidence.

## Severity status

### P0 — closed in the hardening branch

1. **Legacy encryption-key migration could lose data**
   - Root cause: the legacy installer stored `dataEncKey` in config while the newer runtime looked only at the environment/dedicated key file.
   - Fix: validated backward-compatible key migration to `data/.data-key`, verified backup before migration, legacy upgrade fixture.
   - Evidence: storage/upgrade tests.

2. **Wrong key/corrupt encrypted persistence could fail open as empty state and later overwrite data**
   - Root cause: decryption/parse failures were indistinguishable from a missing file.
   - Fix: only genuinely missing state is treated as new state; authentication/decryption/corruption errors fail startup and are never converted to `{}`.
   - Evidence: valid/wrong-key/corruption/missing-state tests and atomic-write tests.

3. **Restore backup filename collision** — newly discovered during validation
   - Root cause: backups used second-resolution names. The pre-restore safety backup could overwrite the archive selected for restore when both were created in the same second.
   - Fix: collision-safe backup names derived from a secure temporary filename; existing archive/checksum destinations are never overwritten.
   - Evidence: lifecycle backup/restore regression test.

### P1 — closed in the hardening branch

- Installer/source divergence: embedded legacy server/package removed; installer deploys the exact checked-out release.
- Nginx/backend TLS mismatch: one production architecture is documented/enforced — TLS at Nginx, HTTP Node backend on loopback.
- Backup deletion during updates: backups live outside the application tree.
- Broken nested update locks/traps: updater uses an external atomic lock with stale-lock handling and deterministic cleanup.
- Broken management-setting environment assignments: legacy generated management implementation removed; one version-controlled management menu delegates to lifecycle scripts.
- Installer random-password SIGPIPE path: password generation no longer uses a `tr | head` pipe under `pipefail`.
- Socket reconnect authentication: signed sessions are explicitly resumed and the current view is rejoined.
- Multi-session role/password/ban behavior: all active sessions are revoked/refreshed consistently.
- Vulnerable/deprecated Multer 1.x: upgraded to Multer 2.2.x with multipart regression tests and limits.
- Microphone blocked by Permissions Policy: `microphone=(self)` while camera/geolocation remain disabled.
- DM only delivered while recipient had the room open: authenticated users have a personal delivery room.
- Upload storage exhaustion: file-count/byte/global quotas, free-space threshold, retention and orphan cleanup added.
- Raw forwarded-IP trust: forwarded IP is honored only from a loopback peer; production backend binds to loopback.
- Session credential in attachment history/URLs: downloads use separate capability tokens.
- Session/token revocation: logout, password changes and bans invalidate affected sessions.
- Reboot persistence: version-controlled systemd unit is enabled by the production installer.
- Incorrect Quick Start/runtime requirements: Node>=20/npm>=10, HTTP loopback behavior and install flow are validated/documented.
- Broken fallback updater: duplicate fallback updater removed; management delegates to `scripts/update.sh`.
- Unsafe uninstall: sentinel, package identity, path, symlink and systemd-unit identity guards plus verified final backup.
- Installer existing-empty-directory layout bug — newly discovered: safely removes an empty target before atomic stage move; refuses unrelated non-empty data.
- Graceful shutdown timeout timer — newly discovered: shutdown deadline is cleared on successful close rather than keeping the event loop alive.
- **Vue runtime compiler incompatible with strict CSP** — newly discovered: the full Vue browser build compiles in-DOM templates dynamically; the application CSP deliberately does not permit `unsafe-eval`. The build now precompiles the template, serves the runtime-only Vue build and rejects generated render code requiring dynamic evaluation.
- **Frontend mount race / anonymous persistent socket** — newly discovered: scripts previously ran in `<head>` without `defer`, and the anonymous login page opened a Socket.IO transport immediately. Generated scripts are now deferred in dependency order, and the client connects only for login or stored-session resume.
- **Failed service activation left a partial installation** — newly discovered in the final audit: after the staged tree was moved into `INSTALL_DIR`, a later `systemctl enable/start` or readiness failure could leave the sentinel/tree/unit behind. The installer now explicitly rolls the new installation back after stopping/disabling the generated service; if safe shutdown cannot be confirmed it retains the tree for operator recovery instead of destructively deleting it.

## P2/P3 production-impacting items addressed

- Reserved `_pv_`/saved identifiers are rejected for usernames/internal routes.
- Crafted DM/reply/saved-message operations are authorized server-side.
- Persistence is one encrypted atomic state snapshot rather than independently committed JSON generations.
- Filesystem I/O and bcrypt operations in runtime paths are asynchronous.
- Configuration has centralized fail-fast validation.
- Exact origin parsing replaces prefix matching.
- Local default origins now include both `localhost:3000` and `127.0.0.1:3000`, matching the default loopback bind and documented local URL.
- Production frontend dependencies are self-hosted and generated deterministically from the lockfile.
- Vue templates are build-time precompiled; generated render output is checked for dynamic evaluation.
- Missing frontend handler paths from the legacy UI were removed/aligned with the current client.
- MediaRecorder streams/tracks are cleaned up on stop/error/permission failure.
- `/healthz` and `/readyz` exist and lifecycle scripts poll readiness.
- Graceful-shutdown persistence errors propagate as failures.
- Orphan/expired uploads are cleaned up.
- Message burst limiter is bounded correctly.
- Logs include timestamp, severity and component/context while avoiding passwords, hashes, keys and raw session tokens.
- Runtime artifacts/keys/uploads/backups/locks and generated frontend bundles are excluded from version control.

## Known non-blocking limitations / remaining verification

These are not unresolved P0/P1 source defects, but they define the supported production profile and what repository CI cannot prove by itself:

1. **Single-host persistence scale** — durable mutations still replace the encrypted state snapshot. Histories/uploads are bounded and I/O is asynchronous, but this design targets small/moderate single-host deployments, not horizontal/high-throughput scale.
2. **No built-in malware scanner** — uploads have authentication, quotas, MIME/extension validation and capabilities; deployments accepting hostile public files should add an external malware-scanning pipeline.
3. **Real TLS certificate/Nginx environment** — CI validates the loopback backend and documented proxy architecture, not a real ACME certificate or public DNS endpoint.
4. **Physical host reboot** — systemd boot enablement is version-controlled and installed, but a GitHub-hosted runner does not perform a real machine reboot. Operators should verify `systemctl is-enabled/is-active` and `/readyz` after deployment reboot.
5. **Real microphone device/permission UX** — policy and cleanup paths are implemented and static/runtime code is checked, but CI does not expose a physical microphone or grant interactive user permission.
6. **Performance ceiling** — no claim is made that encrypted JSON persistence is appropriate for high-volume chat. Moving beyond the documented deployment profile should trigger a persistence benchmark and likely a journaled/database backend.

## Automated evidence required for the release gate

The GitHub Actions workflow is the source of truth for the automated gate and includes:

- Node 20 and Node 22 `npm ci`;
- two independent frontend builds with hash comparison;
- generated-render rejection of `new Function`/`unsafe-eval` requirements;
- JavaScript syntax checks;
- storage/config/security/runtime/upload/upgrade/lifecycle tests;
- runtime smoke test;
- Node 22 headless Chrome/Chromium DevTools-protocol render and browser-error check under the application CSP;
- `npm audit --audit-level=high`;
- dependency freshness reporting;
- Bash parsing and ShellCheck;
- a rendered-unit `systemd-analyze verify` check;
- clean install from the checked-out release, including frontend build inside the installer;
- installed `/healthz`/`/readyz` checks;
- installed-process SIGTERM/graceful-shutdown verification;
- safe uninstall with retained verified backup;
- forced `systemctl enable` failure proving a newly moved install tree/unit is rolled back.

A release must not be called production-ready while a required CI gate is red. See the production-hardening PR for the current run status.
