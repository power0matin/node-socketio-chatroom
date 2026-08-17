#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ID="node-socketio-chatroom"
ROOT_DIR="${CHATROOM_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/node-socketio-chatroom}"
SERVICE_NAME="${SERVICE_NAME:-node-socketio-chatroom.service}"
SKIP_SERVICE="${CHATROOM_SKIP_SERVICE:-0}"
SOURCE_DIR=""
REF=""

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '==> %s\n' "$*"; }

while (($#)); do
  case "$1" in
    --source) [[ $# -ge 2 ]] || fail "--source requires a directory"; SOURCE_DIR="$2"; shift 2 ;;
    --ref) [[ $# -ge 2 ]] || fail "--ref requires an immutable tag or commit"; REF="$2"; shift 2 ;;
    *) fail "Unknown argument: $1" ;;
  esac
done
[[ -n "$SOURCE_DIR" || -n "$REF" ]] || fail "Usage: scripts/update.sh --source /path/to/release OR --ref vX.Y.Z|commit"
[[ ! ( -n "$SOURCE_DIR" && -n "$REF" ) ]] || fail "Choose only one update source."
[[ -f "$ROOT_DIR/.chatroom-install" && "$(cat "$ROOT_DIR/.chatroom-install")" == "$PROJECT_ID" ]] || fail "Valid installation sentinel not found in $ROOT_DIR."
[[ "$BACKUP_ROOT" != "$ROOT_DIR" && "$BACKUP_ROOT" != "$ROOT_DIR"/* ]] || fail "BACKUP_ROOT must be outside the application directory."
command -v rsync >/dev/null 2>&1 || fail "rsync is required."
command -v npm >/dev/null 2>&1 || fail "npm is required."
command -v node >/dev/null 2>&1 || fail "node is required."

NODE_MAJOR="$(node -p 'Number(process.versions.node.split(".")[0])')"
(( NODE_MAJOR >= 20 )) || fail "Node.js >=20 is required."

mkdir -p -- "$BACKUP_ROOT"
LOCK_DIR="$BACKUP_ROOT/.update.lock"
acquire_lock() {
  if mkdir -- "$LOCK_DIR" 2>/dev/null; then
    printf '%s\n' "$$" > "$LOCK_DIR/pid"
    return 0
  fi
  local old_pid=""
  [[ -f "$LOCK_DIR/pid" ]] && old_pid="$(cat "$LOCK_DIR/pid" 2>/dev/null || printf '')"
  if [[ "$old_pid" =~ ^[0-9]+$ ]] && kill -0 "$old_pid" 2>/dev/null; then
    fail "Another update is active with PID $old_pid."
  fi
  info "Removing stale update lock"
  rm -rf -- "$LOCK_DIR"
  mkdir -- "$LOCK_DIR" || fail "Could not acquire update lock."
  printf '%s\n' "$$" > "$LOCK_DIR/pid"
}

STAGE=""
DOWNLOAD_TMP=""
ROLLBACK_DIR=""
cleanup() {
  local rc=$?
  [[ -n "$STAGE" && -d "$STAGE" ]] && rm -rf -- "$STAGE"
  [[ -n "$DOWNLOAD_TMP" && -f "$DOWNLOAD_TMP" ]] && rm -f -- "$DOWNLOAD_TMP"
  rm -rf -- "$LOCK_DIR"
  return "$rc"
}
acquire_lock
trap cleanup EXIT INT TERM

PARENT="$(dirname -- "$ROOT_DIR")"
STAGE="$(mktemp -d "${PARENT}/.${PROJECT_ID}.update.XXXXXX")"

if [[ -n "$SOURCE_DIR" ]]; then
  SOURCE_DIR="$(realpath -- "$SOURCE_DIR")"
  [[ "$SOURCE_DIR" != "$ROOT_DIR" ]] || fail "Update source cannot be the live installation."
  [[ -f "$SOURCE_DIR/package.json" && -f "$SOURCE_DIR/package-lock.json" ]] || fail "Update source is not a complete release tree."
  rsync -a --delete \
    --exclude='.git/' --exclude='node_modules/' --exclude='data/' --exclude='public/uploads/' \
    "$SOURCE_DIR/" "$STAGE/"
else
  [[ "$REF" =~ ^[A-Za-z0-9._-]{7,80}$ ]] || fail "REF must be an immutable tag or commit without slashes."
  case "$REF" in main|master|latest|HEAD) fail "Floating refs are not allowed. Use a release tag or full commit SHA." ;; esac
  command -v curl >/dev/null 2>&1 || fail "curl is required for --ref updates."
  DOWNLOAD_TMP="$(mktemp "$BACKUP_ROOT/.release.XXXXXX.tar.gz")"
  curl --fail --location --silent --show-error \
    "https://github.com/power0matin/node-socketio-chatroom/archive/${REF}.tar.gz" \
    --output "$DOWNLOAD_TMP"
  tar -tzf "$DOWNLOAD_TMP" >/dev/null || fail "Downloaded release archive is invalid."
  tar -xzf "$DOWNLOAD_TMP" -C "$STAGE" --strip-components=1
fi

[[ -f "$STAGE/src/server.js" && -f "$STAGE/scripts/update.sh" && -f "$STAGE/public/vendor/vue.global.prod.js" ]] || fail "Release tree is incomplete or frontend assets were not built."
info "Installing exact production dependency graph in staging"
(
  cd "$STAGE"
  npm ci --omit=dev --ignore-scripts
  npm audit --omit=dev --audit-level=high
)

BACKUP_ARCHIVE="$(CHATROOM_DIR="$ROOT_DIR" BACKUP_ROOT="$BACKUP_ROOT" "$ROOT_DIR/scripts/backup.sh")"
info "Verified pre-update backup: $BACKUP_ARCHIVE"

mkdir -p -- "$STAGE/data" "$STAGE/public/uploads"
rsync -a "$ROOT_DIR/data/" "$STAGE/data/"
rsync -a "$ROOT_DIR/public/uploads/" "$STAGE/public/uploads/"
printf '%s\n' "$PROJECT_ID" > "$STAGE/.chatroom-install"

info "Validating staged configuration, encryption key and persistence migration"
(
  cd "$STAGE"
  BACKUP_ROOT="$BACKUP_ROOT" node - <<'NODE'
const path = require('path');
const { createApplication } = require('./src/server');
(async () => {
  const runtime = await createApplication({ rootDir: process.cwd(), backupRoot: process.env.BACKUP_ROOT, env: process.env });
  await runtime.store.flush();
  console.log(`Validated state schema ${runtime.state.schemaVersion}`);
})().catch((error) => { console.error(error); process.exitCode = 1; });
NODE
)

OWNER="$(stat -c '%U' "$ROOT_DIR")"
GROUP="$(stat -c '%G' "$ROOT_DIR")"
chown -R "$OWNER:$GROUP" "$STAGE"
ROLLBACK_DIR="${PARENT}/.${PROJECT_ID}.rollback.$(date -u +%Y%m%dT%H%M%SZ).$$"
PORT="$(node -e 'const c=require(process.argv[1]); const p=Number(c.port||3000); if(!Number.isInteger(p)||p<1||p>65535) process.exit(2); process.stdout.write(String(p))' "$STAGE/data/config.json")"

rollback_swap() {
  info "Rolling back to previous application tree"
  if [[ -d "$ROOT_DIR" ]]; then rm -rf -- "$ROOT_DIR"; fi
  mv -- "$ROLLBACK_DIR" "$ROOT_DIR"
  if [[ "$SKIP_SERVICE" != "1" ]]; then
    systemctl daemon-reload
    systemctl start "$SERVICE_NAME"
  fi
}

if [[ "$SKIP_SERVICE" != "1" ]]; then systemctl stop "$SERVICE_NAME"; fi
mv -- "$ROOT_DIR" "$ROLLBACK_DIR"
mv -- "$STAGE" "$ROOT_DIR"
STAGE=""

if [[ "$SKIP_SERVICE" != "1" ]]; then
  systemctl daemon-reload
  if ! systemctl start "$SERVICE_NAME"; then
    rollback_swap
    fail "New release failed to start; previous release restored."
  fi
  ready=0
  for _ in {1..30}; do
    if curl --fail --silent "http://127.0.0.1:${PORT}/readyz" >/dev/null; then ready=1; break; fi
    sleep 1
  done
  if [[ "$ready" != "1" ]]; then
    systemctl stop "$SERVICE_NAME"
    rollback_swap
    fail "New release failed readiness; previous release restored."
  fi
else
  info "SKIP_SERVICE=1: validating swapped tree without service manager"
  (
    cd "$ROOT_DIR"
    BACKUP_ROOT="$BACKUP_ROOT" node - <<'NODE'
const { createApplication } = require('./src/server');
(async () => {
  const runtime = await createApplication({ rootDir: process.cwd(), backupRoot: process.env.BACKUP_ROOT, env: process.env });
  await runtime.store.flush();
})().catch((error) => { console.error(error); process.exitCode = 1; });
NODE
  ) || {
    rollback_swap
    fail "Post-swap validation failed; previous release restored."
  }
fi

# Keep an immutable code snapshot for manual rollback while data remains in the verified backup.
CODE_ARCHIVE="$BACKUP_ROOT/code-before-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
(
  cd "$ROLLBACK_DIR"
  tar -czf "$CODE_ARCHIVE" --exclude='./data' --exclude='./public/uploads' --exclude='./node_modules' .
)
sha256sum "$CODE_ARCHIVE" > "$CODE_ARCHIVE.sha256"
sha256sum --check "$CODE_ARCHIVE.sha256" >/dev/null
rm -rf -- "$ROLLBACK_DIR"
ROLLBACK_DIR=""

trap - EXIT INT TERM
rm -rf -- "$LOCK_DIR"
info "Update completed successfully. Data backup: $BACKUP_ARCHIVE"
info "Previous code snapshot: $CODE_ARCHIVE"
