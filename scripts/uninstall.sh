#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ID="node-socketio-chatroom"
ROOT_DIR="${CHATROOM_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/node-socketio-chatroom}"
SERVICE_NAME="${SERVICE_NAME:-node-socketio-chatroom.service}"
SKIP_SERVICE="${CHATROOM_SKIP_SERVICE:-0}"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ -n "${BASH_VERSION:-}" ]] || fail "bash is required."
[[ ! -L "$ROOT_DIR" ]] || fail "Refusing to uninstall through a symlink."
ROOT_DIR="$(realpath -- "$ROOT_DIR")"
case "$ROOT_DIR" in
  /|/root|/home|/usr|/var|/etc|/opt|/srv|/tmp) fail "Protected path cannot be uninstalled: $ROOT_DIR" ;;
esac
[[ "$(dirname -- "$ROOT_DIR")" != "/" ]] || fail "Installation path is too broad."
[[ -f "$ROOT_DIR/.chatroom-install" ]] || fail "Installation sentinel is missing."
[[ "$(cat "$ROOT_DIR/.chatroom-install")" == "$PROJECT_ID" ]] || fail "Installation sentinel belongs to another project."
[[ -f "$ROOT_DIR/package.json" ]] || fail "package.json is missing; refusing destructive removal."
node -e 'const p=require(process.argv[1]); if(p.name!=="node-socketio-chatroom") process.exit(1)' "$ROOT_DIR/package.json" || fail "Repository identity check failed."

FINAL_BACKUP="$(CHATROOM_DIR="$ROOT_DIR" BACKUP_ROOT="$BACKUP_ROOT" "$ROOT_DIR/scripts/backup.sh")"
printf 'Verified final backup: %s\n' "$FINAL_BACKUP"

if [[ "$SKIP_SERVICE" != "1" ]]; then
  UNIT="/etc/systemd/system/$SERVICE_NAME"
  if [[ -f "$UNIT" ]]; then
    grep -Fqx "WorkingDirectory=$ROOT_DIR" "$UNIT" || fail "Service unit does not point at this installation; refusing to remove it."
    systemctl disable --now "$SERVICE_NAME"
    rm -f -- "$UNIT"
    systemctl daemon-reload
  fi
fi

rm -rf --one-file-system -- "$ROOT_DIR"
printf 'Uninstalled %s. Backup retained at %s\n' "$PROJECT_ID" "$FINAL_BACKUP"
