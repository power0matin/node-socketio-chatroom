#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="${CHATROOM_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)}"
SERVICE_NAME="${SERVICE_NAME:-node-socketio-chatroom.service}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/node-socketio-chatroom}"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ -f "$ROOT_DIR/.chatroom-install" ]] || fail "This menu must be run from an installed application tree."

status() {
  systemctl status "$SERVICE_NAME" --no-pager
}

logs() {
  journalctl -u "$SERVICE_NAME" -n 100 --no-pager
}

restart() {
  systemctl restart "$SERVICE_NAME"
  local port
  port="$(node -e 'const c=require(process.argv[1]); process.stdout.write(String(c.port||3000))' "$ROOT_DIR/data/config.json")"
  for _ in {1..20}; do
    if curl --fail --silent "http://127.0.0.1:${port}/readyz" >/dev/null; then
      printf 'Service restarted and readiness passed.\n'
      return 0
    fi
    sleep 1
  done
  fail "Service restarted but readiness did not pass."
}

update_release() {
  local ref
  read -r -p 'Release tag or full commit SHA: ' ref
  [[ -n "$ref" ]] || fail "A release ref is required."
  CHATROOM_DIR="$ROOT_DIR" BACKUP_ROOT="$BACKUP_ROOT" "$ROOT_DIR/scripts/update.sh" --ref "$ref"
}

restore_backup() {
  local archive
  read -r -p 'Backup .tar.gz path: ' archive
  [[ -n "$archive" ]] || fail "A backup path is required."
  CHATROOM_DIR="$ROOT_DIR" BACKUP_ROOT="$BACKUP_ROOT" "$ROOT_DIR/scripts/restore.sh" "$archive"
}

while true; do
  cat <<'MENU'

node-socketio-chatroom
1) Status
2) Restart + readiness
3) Recent logs
4) Verified backup
5) Update from immutable release/tag
6) Restore verified backup
7) Safe uninstall
0) Exit
MENU
  read -r -p '> ' choice
  case "$choice" in
    1) status ;;
    2) restart ;;
    3) logs ;;
    4) CHATROOM_DIR="$ROOT_DIR" BACKUP_ROOT="$BACKUP_ROOT" "$ROOT_DIR/scripts/backup.sh" ;;
    5) update_release ;;
    6) restore_backup ;;
    7) CHATROOM_DIR="$ROOT_DIR" BACKUP_ROOT="$BACKUP_ROOT" "$ROOT_DIR/scripts/uninstall.sh"; exit 0 ;;
    0) exit 0 ;;
    *) printf 'Invalid choice.\n' ;;
  esac
done
