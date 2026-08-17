#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="${CHATROOM_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/node-socketio-chatroom}"
PROJECT_ID="node-socketio-chatroom"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ -f "$ROOT_DIR/.chatroom-install" ]] || fail "Installation sentinel missing in $ROOT_DIR"
[[ "$(cat "$ROOT_DIR/.chatroom-install")" == "$PROJECT_ID" ]] || fail "Installation sentinel does not match this project."
command -v tar >/dev/null 2>&1 || fail "tar is required."
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required."

mkdir -p -- "$BACKUP_ROOT"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TMP="$(mktemp "$BACKUP_ROOT/.chatroom-backup.${STAMP}.XXXXXX.tar.gz")"
FINAL="$BACKUP_ROOT/chatroom-backup-${STAMP}.tar.gz"
cleanup() { [[ -f "$TMP" ]] && rm -f -- "$TMP"; }
trap cleanup EXIT

items=(data)
[[ -d "$ROOT_DIR/public/uploads" ]] && items+=(public/uploads)
(
  cd "$ROOT_DIR"
  tar -czf "$TMP" --owner=0 --group=0 "${items[@]}"
)
tar -tzf "$TMP" >/dev/null
[[ -s "$TMP" ]] || fail "Backup archive is empty."
mv -- "$TMP" "$FINAL"
sha256sum "$FINAL" > "$FINAL.sha256"
sha256sum --check "$FINAL.sha256" >/dev/null
trap - EXIT
printf '%s\n' "$FINAL"
