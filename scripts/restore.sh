#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="${CHATROOM_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/node-socketio-chatroom}"
SERVICE_NAME="${SERVICE_NAME:-node-socketio-chatroom.service}"
SKIP_SERVICE="${CHATROOM_SKIP_SERVICE:-0}"
PROJECT_ID="node-socketio-chatroom"
ARCHIVE="${1:-}"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ -n "$ARCHIVE" ]] || fail "Usage: scripts/restore.sh /path/to/chatroom-backup-*.tar.gz"
ARCHIVE="$(realpath -- "$ARCHIVE")"
[[ -f "$ARCHIVE" && -f "$ARCHIVE.sha256" ]] || fail "Backup archive and matching .sha256 file are required."
[[ -f "$ROOT_DIR/.chatroom-install" && "$(cat "$ROOT_DIR/.chatroom-install")" == "$PROJECT_ID" ]] || fail "Valid installation sentinel not found."
sha256sum --check "$ARCHIVE.sha256" >/dev/null || fail "Backup integrity verification failed."

mapfile -t entries < <(tar -tzf "$ARCHIVE")
(( ${#entries[@]} > 0 )) || fail "Backup archive is empty."
for entry in "${entries[@]}"; do
  [[ "$entry" != /* ]] || fail "Unsafe absolute path in backup: $entry"
  [[ "/$entry/" != *"/../"* ]] || fail "Unsafe traversal path in backup: $entry"
done
printf '%s\n' "${entries[@]}" | grep -Eq '^data(/|$)' || fail "Backup does not contain data/."

PRE_RESTORE_BACKUP="$(CHATROOM_DIR="$ROOT_DIR" BACKUP_ROOT="$BACKUP_ROOT" "$ROOT_DIR/scripts/backup.sh")"
printf 'Pre-restore safety backup: %s\n' "$PRE_RESTORE_BACKUP"

STAGE="$(mktemp -d "$(dirname -- "$ROOT_DIR")/.chatroom-restore.XXXXXX")"
OLD_DATA="${ROOT_DIR}.restore-old-data.$$"
OLD_UPLOADS="${ROOT_DIR}.restore-old-uploads.$$"
cleanup() {
  [[ -d "${STAGE:-}" ]] && rm -rf -- "$STAGE"
}
trap cleanup EXIT

tar -xzf "$ARCHIVE" -C "$STAGE" --no-same-owner --no-same-permissions
[[ -d "$STAGE/data" && -f "$STAGE/data/config.json" ]] || fail "Restored data directory is incomplete."

OWNER="$(stat -c '%U' "$ROOT_DIR/data")"
GROUP="$(stat -c '%G' "$ROOT_DIR/data")"
PORT="$(node -e 'const c=require(process.argv[1]); const p=Number(c.port||3000); if(!Number.isInteger(p)||p<1||p>65535) process.exit(2); process.stdout.write(String(p))' "$STAGE/data/config.json")"

if [[ "$SKIP_SERVICE" != "1" ]]; then
  systemctl stop "$SERVICE_NAME"
fi

mv -- "$ROOT_DIR/data" "$OLD_DATA"
if [[ -d "$ROOT_DIR/public/uploads" ]]; then mv -- "$ROOT_DIR/public/uploads" "$OLD_UPLOADS"; fi
mv -- "$STAGE/data" "$ROOT_DIR/data"
mkdir -p -- "$ROOT_DIR/public"
if [[ -d "$STAGE/public/uploads" ]]; then mv -- "$STAGE/public/uploads" "$ROOT_DIR/public/uploads"; else mkdir -p -- "$ROOT_DIR/public/uploads"; fi
chown -R "$OWNER:$GROUP" "$ROOT_DIR/data" "$ROOT_DIR/public/uploads"
chmod 700 "$ROOT_DIR/data" "$ROOT_DIR/public/uploads"

rollback() {
  rm -rf -- "$ROOT_DIR/data" "$ROOT_DIR/public/uploads"
  mv -- "$OLD_DATA" "$ROOT_DIR/data"
  if [[ -d "$OLD_UPLOADS" ]]; then mv -- "$OLD_UPLOADS" "$ROOT_DIR/public/uploads"; else mkdir -p -- "$ROOT_DIR/public/uploads"; fi
  if [[ "$SKIP_SERVICE" != "1" ]]; then systemctl start "$SERVICE_NAME"; fi
}

if [[ "$SKIP_SERVICE" != "1" ]]; then
  if ! systemctl start "$SERVICE_NAME"; then
    rollback
    fail "Service could not start after restore; previous data was restored."
  fi
  ready=0
  for _ in {1..30}; do
    if curl --fail --silent "http://127.0.0.1:${PORT}/readyz" >/dev/null; then ready=1; break; fi
    sleep 1
  done
  if [[ "$ready" != "1" ]]; then
    systemctl stop "$SERVICE_NAME"
    rollback
    fail "Readiness failed after restore; previous data was restored."
  fi
fi

rm -rf -- "$OLD_DATA" "$OLD_UPLOADS"
trap - EXIT
rm -rf -- "$STAGE"
printf 'Restore completed and verified from %s\n' "$ARCHIVE"
