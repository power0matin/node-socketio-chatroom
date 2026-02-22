#!/usr/bin/env bash
set -Eeuo pipefail

# =========================
# node-socketio-chatroom Installer (Enhanced Preflight)
# =========================

cleanup() { true; }
trap cleanup EXIT

# ---- Installer metadata ----
INSTALLER_VERSION="1.1.4"
INSTALLER_BUILD_DATE="2026-02-22"

DIR_DEFAULT="$HOME/chat-node-socketio-chatroom"
APP_NAME_DEFAULT="node-socketio-chatroom"

REPO_URL_DEFAULT="https://github.com/power0matin/node-socketio-chatroom.git"
BRANCH_DEFAULT="main"

need_apt_update=0

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---- pretty logging (auto-disable colors if not a TTY) ----
if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'
  C_DIM=$'\033[2m'
  C_BOLD=$'\033[1m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
else
  C_RESET="" C_DIM="" C_BOLD="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE=""
fi

log()   { echo "${C_BLUE}[INFO]${C_RESET} $*"; }
ok()    { echo "${C_GREEN}[OK]${C_RESET}   $*"; }
warn()  { echo "${C_YELLOW}[WARN]${C_RESET} $*"; }
die()   { echo "${C_RED}[ERR]${C_RESET}  $*" >&2; exit 1; }

# ---- OS / system info ----
os_pretty() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    echo "${PRETTY_NAME:-Linux}"
  else
    echo "Linux"
  fi
}

get_ip() {
  curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null \
    || curl -fsS --max-time 3 https://ifconfig.co 2>/dev/null \
    || echo "UNKNOWN"
}

show_versions_if_present() {
  if have_cmd node; then ok "node: $(node -v 2>/dev/null || echo '?')"; else warn "node: not installed"; fi
  if have_cmd npm;  then ok "npm:  $(npm -v 2>/dev/null || echo '?')";  else warn "npm:  not installed"; fi
  if have_cmd pm2;  then ok "pm2:  $(pm2 -v 2>/dev/null || echo '?')";  else warn "pm2:  not installed"; fi
  if have_cmd git;  then ok "git:  $(git --version 2>/dev/null | awk '{print $3}' || echo '?')"; else warn "git:  not installed"; fi
  if have_cmd curl; then ok "curl: $(curl --version 2>/dev/null | head -n1 | awk '{print $2}' || echo '?')"; else warn "curl: not installed"; fi
}

# ---- preflight checks ----
require_sudo() {
  if [[ "${EUID:-0}" -eq 0 ]]; then
    ok "Running as root"
    return 0
  fi

  if ! have_cmd sudo; then
    die "sudo is required (not found). Run as root or install sudo."
  fi

  # non-interactive sudo test
  if sudo -n true 2>/dev/null; then
    ok "sudo: available (non-interactive)"
  else
    log "sudo: needs password (you may be prompted)"
    sudo true || die "sudo authentication failed"
  fi
}

check_internet() {
  # minimal connectivity check
  if ! have_cmd curl; then
    warn "curl not found yet (will be installed later). Skipping connectivity test."
    return 0
  fi
  curl -fsS --max-time 5 "https://raw.githubusercontent.com/github/gitignore/main/Node.gitignore" >/dev/null 2>&1 \
    && ok "Internet: reachable (raw.githubusercontent.com)" \
    || warn "Internet: could not reach raw.githubusercontent.com (install may fail)"
}

check_repo_reachable() {
  # fast check for repo existence/branch (best-effort)
  if ! have_cmd git; then
    warn "git not found yet (will be installed later). Skipping repo check."
    return 0
  fi
  if git ls-remote --heads "$REPO_URL_DEFAULT" "$BRANCH_DEFAULT" >/dev/null 2>&1; then
    ok "Repo: reachable ($BRANCH_DEFAULT)"
  else
    warn "Repo: could not verify branch '$BRANCH_DEFAULT' (will attempt clone anyway)"
  fi
}

port_in_use() {
  local p="$1"

  if have_cmd ss; then
    ss -lptn "( sport = :$p )" 2>/dev/null | grep -q ":$p" && return 0 || return 1
  fi

  if have_cmd lsof; then
    lsof -iTCP:"$p" -sTCP:LISTEN -n -P >/dev/null 2>&1 && return 0 || return 1
  fi

  if have_cmd netstat; then
    netstat -lntp 2>/dev/null | grep -q ":$p " && return 0 || return 1
  fi

  return 1
}

# ---- apt helpers (unchanged behavior, but safer) ----
apt_update_if_needed() {
  if [[ "$need_apt_update" -eq 1 ]]; then
    sudo apt-get update -y
    need_apt_update=0
  fi
}

apt_install_if_missing() {
  local pkg="$1"
  local cmd="${2:-$1}"
  if ! have_cmd "$cmd"; then
    need_apt_update=1
    apt_update_if_needed
    sudo apt-get install -y "$pkg"
    ok "Installed: $pkg"
  else
    ok "Present: $cmd"
  fi
}

# ---- Banner ----
echo "${C_BOLD}========================================${C_RESET}"
echo "${C_BOLD}  node-socketio-chatroom Installer${C_RESET} ${C_DIM}v${INSTALLER_VERSION} (${INSTALLER_BUILD_DATE})${C_RESET}"
echo "${C_BOLD}========================================${C_RESET}"
echo ""

log "System:  $(os_pretty) | kernel: $(uname -r) | arch: $(uname -m)"
PUBLIC_IP="$(get_ip)"
log "Host:    $(hostname 2>/dev/null || echo '?') | user: $(id -un 2>/dev/null || echo '?') | ip: ${PUBLIC_IP}"
echo ""

log "Tooling versions (if present):"
show_versions_if_present
echo ""

require_sudo
check_internet
check_repo_reachable
echo ""

read -r -p "Install directory [default: ${DIR_DEFAULT}]: " INPUT_DIR
DIR="${INPUT_DIR:-$DIR_DEFAULT}"

read -r -p "Chat Room Name [default: ${APP_NAME_DEFAULT}]: " INPUT_APP_NAME
APP_NAME_VAL="${INPUT_APP_NAME:-$APP_NAME_DEFAULT}"

read -r -p "Admin Username [default: admin]: " INPUT_USER
ADMIN_USER="${INPUT_USER:-admin}"

prompt_password() {
  local pass1 pass2
  while true; do
    read -r -s -p "Admin Password (leave empty to auto-generate): " pass1
    echo ""
    if [[ -z "${pass1}" ]]; then
      ADMIN_PASS="$(LC_ALL=C tr -dc 'A-Za-z0-9@#%_+=-' </dev/urandom | head -c 24)"
      echo "Generated Admin Password: ${ADMIN_PASS}"
      echo "⚠️  Please save it now. It will NOT be shown again."
      return 0
    fi

    if (( ${#pass1} < 10 )); then
      echo "Password must be at least 10 characters."
      continue
    fi

    read -r -s -p "Confirm Password: " pass2
    echo ""
    if [[ "${pass1}" != "${pass2}" ]]; then
      echo "Passwords do not match. Try again."
      continue
    fi

    ADMIN_PASS="${pass1}"
    return 0
  done
}

prompt_password

read -r -p "Port [default: 3000]: " INPUT_PORT
PORT="${INPUT_PORT:-3000}"
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && (( PORT >= 1 && PORT <= 65535 )) || { echo "Invalid port"; exit 1; }

if port_in_use "$PORT"; then
  die "Port $PORT is already in use. Choose another port or stop the conflicting service."
else
  ok "Port $PORT is free"
fi

echo ""
echo "Allowed Origins for CORS (comma-separated)."
echo "Example: https://yourdomain.com,http://localhost:$PORT"
echo "Use * only if you really want open access."
read -r -p "Allowed Origins [default: *]: " INPUT_ORIGINS
ALLOWED_ORIGINS="${INPUT_ORIGINS:-*}"

echo ""
echo "Select Theme Color:"
echo "1) Blue (Default)"
echo "2) Purple"
echo "3) Green"
echo "4) Red"
echo "5) Orange"
echo "6) Teal"
read -r -p "Enter number [1-6]: " COLOR_CHOICE

case "${COLOR_CHOICE:-1}" in
  1) C_DEF="#2563EB"; C_DARK="#1D4ED8"; C_LIGHT="#EFF6FF" ;;
  2) C_DEF="#7C3AED"; C_DARK="#6D28D9"; C_LIGHT="#F5F3FF" ;;
  3) C_DEF="#10B981"; C_DARK="#059669"; C_LIGHT="#ECFDF5" ;;
  4) C_DEF="#F43F5E"; C_DARK="#E11D48"; C_LIGHT="#FFF1F2" ;;
  5) C_DEF="#F59E0B"; C_DARK="#D97706"; C_LIGHT="#FFFBEB" ;;
  6) C_DEF="#14B8A6"; C_DARK="#0F766E"; C_LIGHT="#F0FDFA" ;;
  *) C_DEF="#2563EB"; C_DARK="#1D4ED8"; C_LIGHT="#EFF6FF" ;;
esac

echo ""
log "Summary:"
echo "  DIR:            $DIR"
echo "  App Name:       $APP_NAME_VAL"
echo "  Admin User:     $ADMIN_USER"
echo "  Port:           $PORT"
echo "  AllowedOrigins: $ALLOWED_ORIGINS"
echo "  Theme Color:    $C_DEF"
echo ""
echo "[1/7] Checking system deps..."

# Ensure base deps exist BEFORE NodeSource usage
need_apt_update=1
apt_update_if_needed
apt_install_if_missing ca-certificates update-ca-certificates
apt_install_if_missing curl curl
apt_install_if_missing git git
apt_install_if_missing rsync rsync

echo "[2/7] Installing Node.js 20 & npm if missing..."

if ! have_cmd node; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi

# npm should come with nodejs on NodeSource; fallback if not
if ! have_cmd npm; then
  sudo apt-get install -y npm
fi

# Install pm2 only if missing
if ! have_cmd pm2; then
  sudo npm install -g pm2
fi

node -v
npm -v
pm2 -v

echo "[3/7] Fetching project into: $DIR"
mkdir -p "$DIR"

# If directory has .git => update. If directory not empty and no .git => fail fast.
if [[ -d "$DIR/.git" ]]; then
  echo "Existing git repo detected. Updating..."
  git -C "$DIR" fetch --all --prune
  git -C "$DIR" checkout "$BRANCH_DEFAULT"
  git -C "$DIR" pull --ff-only origin "$BRANCH_DEFAULT"
else
  if [[ -n "$(ls -A "$DIR" 2>/dev/null || true)" ]]; then
    echo "ERROR: Install directory is not empty and is not a git repo: $DIR"
    echo "Choose an empty directory or remove its contents."
    exit 1
  fi
  echo "Cloning from $REPO_URL_DEFAULT ..."
  git clone --depth 1 --branch "$BRANCH_DEFAULT" "$REPO_URL_DEFAULT" "$DIR"
fi

cd "$DIR"

echo "[4/7] Ensuring required directories exist..."
mkdir -p "$DIR/data" "$DIR/public/uploads"
chmod 700 "$DIR/data" "$DIR/public/uploads"

# ---- detect server entry (supports both layouts) ----
SERVER_ENTRY=""
if [[ -f "$DIR/src/server.js" ]]; then
  SERVER_ENTRY="$DIR/src/server.js"
elif [[ -f "$DIR/server.js" ]]; then
  SERVER_ENTRY="$DIR/server.js"
fi

REQ_FILES=(
  "$DIR/package.json"
  "$DIR/public/index.html"
  "$DIR/public/assets/app.js"
  "$DIR/public/assets/app.css"
  "$DIR/public/assets/theme.css"
  "$DIR/menu.sh"
)

missing=0

if [[ -n "$SERVER_ENTRY" ]]; then
  REQ_FILES+=("$SERVER_ENTRY")
else
  echo "ERROR: Missing server entry: expected src/server.js or server.js"
  missing=1
fi

for f in "${REQ_FILES[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "ERROR: Missing required file: $f"
    missing=1
  fi
done

if (( missing == 1 )); then
  echo ""
  echo "Your repository clone does NOT contain required runtime files."
  echo "This usually means you haven't committed/pushed them to GitHub (branch: ${BRANCH_DEFAULT})."
  echo ""
  echo "Expected structure:"
  echo "  src/server.js"
  echo "  package.json"
  echo "  public/index.html"
  echo "  public/assets/{app.js,app.css,theme.css}"
  echo ""
  echo "What I actually see in '$DIR':"
  (cd "$DIR" && ls -la)
  echo ""
  echo "Fix on your dev machine:"
  echo "  git add server.js package.json public/ && git commit -m \"chore: add runtime files\" && git push"
  exit 1
fi

echo "[5/7] Applying configuration (placeholders)..."

esc_sed() { printf '%s' "$1" | sed -e 's/[\/&|]/\\&/g'; }

APP_NAME_ESC="$(esc_sed "$APP_NAME_VAL")"

sed -i "s|__APP_NAME_PLACEHOLDER__|$APP_NAME_ESC|g" "$DIR/public/index.html" || true
sed -i "s|__COLOR_DEFAULT__|$C_DEF|g" "$DIR/public/assets/theme.css" || true
sed -i "s|__COLOR_DARK__|$C_DARK|g" "$DIR/public/assets/theme.css" || true
sed -i "s|__COLOR_LIGHT__|$C_LIGHT|g" "$DIR/public/assets/theme.css" || true

echo "[6/7] Installing npm dependencies (optimized)..."
# speed: disable audit/fund during install
npm config set fund false >/dev/null 2>&1 || true
npm config set audit false >/dev/null 2>&1 || true

if [[ -f package-lock.json ]]; then
  npm ci --omit=dev
else
  npm install --omit=dev
fi

ADMIN_PASS_HASH="$(
  ADMIN_PASS="$ADMIN_PASS" node - <<'NODE'
const bcrypt = require('bcryptjs');
const pass = process.env.ADMIN_PASS || '';
if (!pass) process.exit(2);
process.stdout.write(bcrypt.hashSync(pass, 12));
NODE
)"
if [[ -z "${ADMIN_PASS_HASH}" ]]; then
  echo "ERROR: failed to generate adminPassHash"
  exit 1
fi

DATA_ENC_KEY=""
if have_cmd openssl; then
  DATA_ENC_KEY="$(openssl rand -hex 32)"
else
  DATA_ENC_KEY="$(LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c 64)"
fi
if [[ -z "${DATA_ENC_KEY}" || "${#DATA_ENC_KEY}" -lt 64 ]]; then
  echo "ERROR: failed to generate dataEncKey"
  exit 1
fi

cat > "$DIR/data/config.json" <<EOF
{
  "adminUser": "$(echo "$ADMIN_USER" | sed 's/"/\\"/g')",
  "adminPassHash": "$(echo "$ADMIN_PASS_HASH" | sed 's/"/\\"/g')",
  "port": $PORT,
  "maxFileSizeMB": 50,
  "appName": "$(echo "$APP_NAME_VAL" | sed 's/"/\\"/g')",
  "hideUserList": false,
  "allowedOrigins": "$(echo "$ALLOWED_ORIGINS" | sed 's/"/\\"/g')",
  "protectUploads": true,
  "dataEncKey": "$DATA_ENC_KEY"
}
EOF
chmod 600 "$DIR/data/config.json"
unset ADMIN_PASS

echo "[7/7] Starting server with PM2..."
PM2_NAME="${APP_NAME_VAL}"
pm2 delete "$PM2_NAME" 2>/dev/null || true
PORT="$PORT" pm2 start "$SERVER_ENTRY" --name "$PM2_NAME"
pm2 save

echo "Installing management tool from repo menu.sh ..."
TMP_MENU="$(mktemp)"
cp "$DIR/menu.sh" "$TMP_MENU"
sed -i "s|__DIR__|$DIR|g" "$TMP_MENU"
sed -i "s|__PM2_NAME__|$PM2_NAME|g" "$TMP_MENU"
sudo mv "$TMP_MENU" /usr/local/bin/node-socketio-chatroom
sudo chmod +x /usr/local/bin/node-socketio-chatroom

echo ""
echo "========================================"
echo "      INSTALLATION COMPLETE! 🚀"
echo "========================================"
echo "Admin User: $ADMIN_USER"
echo "Admin Pass: stored hashed in data/config.json (password not shown again)"
echo "Access URL: http://${PUBLIC_IP}:$PORT"
echo ""
echo "Type 'node-socketio-chatroom' to manage your server."
echo "========================================"