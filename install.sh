#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ID="node-socketio-chatroom"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
INSTALL_DIR="${INSTALL_DIR:-/opt/node-socketio-chatroom}"
INSTALL_USER="${INSTALL_USER:-chatroom}"
INSTALL_GROUP="${INSTALL_GROUP:-$INSTALL_USER}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/node-socketio-chatroom}"
SERVICE_NAME="${SERVICE_NAME:-node-socketio-chatroom.service}"
PORT="${PORT:-3000}"
PUBLIC_ORIGIN="${PUBLIC_ORIGIN:-http://localhost:${PORT}}"
SKIP_SYSTEMD="${SKIP_SYSTEMD:-0}"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }

[[ -n "${BASH_VERSION:-}" ]] || fail "This installer requires bash."
[[ "${EUID}" -eq 0 ]] || fail "Run this installer as root (sudo ./install.sh)."
[[ -f "$SCRIPT_DIR/package.json" && -f "$SCRIPT_DIR/package-lock.json" && -f "$SCRIPT_DIR/src/server.js" && -f "$SCRIPT_DIR/scripts/build-assets.js" ]] || fail "Run install.sh from a complete repository checkout/release, not as a standalone downloaded script."

command -v node >/dev/null 2>&1 || fail "Node.js >=20 is required. Install Node.js first."
command -v npm >/dev/null 2>&1 || fail "npm >=10 is required."
command -v rsync >/dev/null 2>&1 || fail "rsync is required."
command -v curl >/dev/null 2>&1 || fail "curl is required."
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required."

NODE_MAJOR="$(node -p 'Number(process.versions.node.split(".")[0])')"
NPM_MAJOR="$(npm -v | cut -d. -f1)"
if (( NODE_MAJOR < 20 )); then fail "Node.js >=20 is required; found $(node -v)."; fi
if (( NPM_MAJOR < 10 )); then fail "npm >=10 is required; found $(npm -v)."; fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
  fail "PORT must be between 1 and 65535."
fi
if ! node -e 'const u=new URL(process.argv[1]); if(!/^https?:$/.test(u.protocol)||u.pathname!=="/"||u.search||u.hash) process.exit(1)' "$PUBLIC_ORIGIN"; then
  fail "PUBLIC_ORIGIN must be an explicit http(s) origin with no path."
fi

safe_install_path() {
  local raw="$1" resolved parent
  [[ "$raw" = /* ]] || return 1
  resolved="$(realpath -m -- "$raw")"
  case "$resolved" in
    /|/root|/home|/usr|/var|/etc|/opt|/srv|/tmp) return 1 ;;
  esac
  parent="$(dirname -- "$resolved")"
  [[ "$parent" != "/" ]] || return 1
  [[ ! -L "$raw" ]] || return 1
  printf '%s\n' "$resolved"
}

INSTALL_DIR="$(safe_install_path "$INSTALL_DIR")" || fail "Unsafe INSTALL_DIR: $INSTALL_DIR"
case "$INSTALL_DIR" in
  "$SCRIPT_DIR"|"$SCRIPT_DIR"/*) fail "INSTALL_DIR must not be inside the source checkout." ;;
esac
case "$SCRIPT_DIR" in
  "$INSTALL_DIR"/*) fail "Source checkout must not be inside INSTALL_DIR." ;;
esac
BACKUP_ROOT="$(realpath -m -- "$BACKUP_ROOT")"
[[ "$BACKUP_ROOT" != "$INSTALL_DIR" && "$BACKUP_ROOT" != "$INSTALL_DIR"/* ]] || fail "BACKUP_ROOT must be outside INSTALL_DIR."

if [[ -e "$INSTALL_DIR" ]]; then
  if [[ -f "$INSTALL_DIR/.chatroom-install" ]]; then fail "An installation already exists at $INSTALL_DIR. Use scripts/update.sh instead."; fi
  if [[ -n "$(find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
    fail "INSTALL_DIR exists and is not empty; refusing to overwrite unrelated data."
  fi
  rmdir -- "$INSTALL_DIR" || fail "INSTALL_DIR is empty but could not be removed for an atomic installation."
fi

if ! getent group "$INSTALL_GROUP" >/dev/null 2>&1; then groupadd --system "$INSTALL_GROUP"; fi
if ! id "$INSTALL_USER" >/dev/null 2>&1; then
  useradd --system --gid "$INSTALL_GROUP" --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$INSTALL_USER"
fi

PARENT_DIR="$(dirname -- "$INSTALL_DIR")"
mkdir -p -- "$PARENT_DIR" "$BACKUP_ROOT"
STAGE_DIR="$(mktemp -d "${PARENT_DIR}/.${PROJECT_ID}.install.XXXXXX")"
INSTALL_MOVED=0
SERVICE_FILE=""
cleanup() {
  local rc=$?
  if [[ -n "${STAGE_DIR:-}" && -d "$STAGE_DIR" ]]; then rm -rf -- "$STAGE_DIR"; fi

  if (( rc != 0 && INSTALL_MOVED == 1 )); then
    warn "Installation failed after the staged tree was moved into place; attempting rollback."
    local service_stopped=1
    if [[ -n "$SERVICE_FILE" && -f "$SERVICE_FILE" ]]; then
      if command -v systemctl >/dev/null 2>&1; then
        if ! systemctl disable --now "$SERVICE_NAME"; then
          service_stopped=0
          warn "Could not stop/disable $SERVICE_NAME during rollback; leaving the install tree for safe operator recovery."
        fi
      fi
      rm -f -- "$SERVICE_FILE"
      if command -v systemctl >/dev/null 2>&1; then
        if ! systemctl daemon-reload; then warn "systemctl daemon-reload failed during rollback."; fi
      fi
    fi

    if (( service_stopped == 1 )); then
      if [[ -f "$INSTALL_DIR/.chatroom-install" && "$(cat "$INSTALL_DIR/.chatroom-install")" == "$PROJECT_ID" ]]; then
        rm -rf -- "$INSTALL_DIR"
      else
        warn "Refusing to remove $INSTALL_DIR during rollback because the installation sentinel is missing or invalid."
      fi
    fi
  fi
  return "$rc"
}
trap cleanup EXIT

info "Copying the exact checked-out source tree"
rsync -a --delete \
  --exclude='.git/' \
  --exclude='node_modules/' \
  --exclude='data/' \
  --exclude='public/uploads/' \
  --exclude='.update.lock' \
  --exclude='.menu-update.lock' \
  "$SCRIPT_DIR/" "$STAGE_DIR/"

info "Installing the exact dependency graph and building reproducible frontend assets"
(
  cd "$STAGE_DIR"
  npm ci --ignore-scripts
  npm run build
  npm run check
  [[ -s public/assets/render.js && -s public/assets/tailwind.css && -s public/vendor/vue.global.prod.js ]] || exit 1
  if grep -Eq 'new[[:space:]]+Function|unsafe-eval' public/assets/render.js; then
    printf 'Generated Vue render asset contains forbidden dynamic evaluation.\n' >&2
    exit 1
  fi
  npm prune --omit=dev --ignore-scripts
  npm audit --omit=dev --audit-level=high
)

mkdir -p -- "$STAGE_DIR/data" "$STAGE_DIR/public/uploads"
printf '%s\n' "$PROJECT_ID" > "$STAGE_DIR/.chatroom-install"
chmod 600 "$STAGE_DIR/.chatroom-install"

ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(node -e 'process.stdout.write(require("crypto").randomBytes(18).toString("base64url"))')}"
if (( ${#ADMIN_PASSWORD} < 12 )); then fail "ADMIN_PASSWORD must be at least 12 characters."; fi
ADMIN_HASH="$(cd "$STAGE_DIR" && ADMIN_PASSWORD="$ADMIN_PASSWORD" node -e 'require("bcryptjs").hash(process.env.ADMIN_PASSWORD,12).then(v=>process.stdout.write(v))')"

ADMIN_HASH="$ADMIN_HASH" PORT="$PORT" PUBLIC_ORIGIN="$PUBLIC_ORIGIN" node <<'NODE' > "$STAGE_DIR/data/config.json"
const cfg = {
  adminUser: 'admin',
  adminPassHash: process.env.ADMIN_HASH,
  adminSessionVersion: 1,
  port: Number(process.env.PORT),
  bindHost: '127.0.0.1',
  maxFileSizeMB: 50,
  maxFilesPerUser: 200,
  userQuotaMB: 1024,
  globalQuotaMB: 10240,
  minFreeDiskMB: 512,
  uploadRetentionDays: 30,
  appName: 'node-socketio-chatroom',
  hideUserList: false,
  allowedOrigins: [process.env.PUBLIC_ORIGIN],
  protectUploads: true,
  accessMode: 'restricted',
  defaultChannelsForNewUsers: ['General'],
  maxChannelMessages: 100,
  maxDmMessages: 500,
  maxSavedMessages: 1000,
  sessionTtlHours: 24,
  trustProxy: true
};
process.stdout.write(JSON.stringify(cfg, null, 2));
NODE
chmod 600 "$STAGE_DIR/data/config.json"

chown -R "$INSTALL_USER:$INSTALL_GROUP" "$STAGE_DIR"
chown "$INSTALL_USER:$INSTALL_GROUP" "$BACKUP_ROOT"
chmod 700 "$STAGE_DIR/data" "$STAGE_DIR/public/uploads" "$BACKUP_ROOT"
mv -- "$STAGE_DIR" "$INSTALL_DIR"
STAGE_DIR=""
INSTALL_MOVED=1

if [[ "$SKIP_SYSTEMD" == "1" ]]; then
  info "SKIP_SYSTEMD=1: source and configuration installed without service registration."
else
  command -v systemctl >/dev/null 2>&1 || fail "systemd/systemctl is required for production installation."
  NODE_BIN="$(command -v node)"
  SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME"
  sed \
    -e "s|@@USER@@|$INSTALL_USER|g" \
    -e "s|@@GROUP@@|$INSTALL_GROUP|g" \
    -e "s|@@DIR@@|$INSTALL_DIR|g" \
    -e "s|@@NODE@@|$NODE_BIN|g" \
    -e "s|@@BACKUP_ROOT@@|$BACKUP_ROOT|g" \
    "$INSTALL_DIR/deploy/node-socketio-chatroom.service" > "$SERVICE_FILE"
  chmod 644 "$SERVICE_FILE"
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"

  info "Polling readiness endpoint"
  ready=0
  for _ in {1..30}; do
    if curl --fail --silent --show-error "http://127.0.0.1:${PORT}/readyz" >/dev/null; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "$ready" != "1" ]]; then fail "Service did not become ready. Installation is not being reported as successful."; fi
fi

INSTALL_MOVED=0
trap - EXIT
VERSION="$(node -p 'require(process.argv[1]).version' "$INSTALL_DIR/package.json")"
info "Installation completed from repository version $VERSION"
printf 'Admin username: admin\nAdmin password: %s\n' "$ADMIN_PASSWORD"
printf 'Backend: http://127.0.0.1:%s (use Nginx HTTPS termination for production)\n' "$PORT"
