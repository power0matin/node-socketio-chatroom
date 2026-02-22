#!/usr/bin/env bash
set -Eeuo pipefail

# node-socketio-chatroom - Interactive Installer (Repo-based, modular-client compatible, optimized)
cleanup() { true; }
trap cleanup EXIT

DIR_DEFAULT="$HOME/chat-node-socketio-chatroom"
APP_NAME_DEFAULT="node-socketio-chatroom"

REPO_URL_DEFAULT="https://github.com/power0matin/node-socketio-chatroom.git"
BRANCH_DEFAULT="main"

need_apt_update=0

have_cmd() { command -v "$1" >/dev/null 2>&1; }

apt_install_if_missing() {
  local pkg="$1"
  local cmd="${2:-$1}"
  if ! have_cmd "$cmd"; then
    need_apt_update=1
    apt_update_if_needed
    sudo apt-get install -y "$pkg"
  fi
}

apt_update_if_needed() {
  if [[ "$need_apt_update" -eq 1 ]]; then
    sudo apt-get update -y
    need_apt_update=0
  fi
}

echo "========================================"
echo "    node-socketio-chatroom Installer"
echo "========================================"
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

REQ_FILES=(
  "$DIR/src/server.js"
  "$DIR/package.json"
  "$DIR/public/index.html"
  "$DIR/public/assets/app.js"
  "$DIR/public/assets/app.css"
  "$DIR/public/assets/theme.css"
  "$DIR/menu.sh"
)

# PORT="$PORT" pm2 start "$DIR/src/server.js" --name "$PM2_NAME"

missing=0
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
sed -i "s|__APP_NAME_PLACEHOLDER__|$APP_NAME_VAL|g" "$DIR/public/index.html" || true
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
PORT="$PORT" pm2 start "$DIR/src/server.js" --name "$PM2_NAME"
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
IP="$(curl -fsS https://api.ipify.org 2>/dev/null || curl -fsS https://ifconfig.co 2>/dev/null || echo 'YOUR_SERVER_IP')"
echo "Access URL: http://$IP:$PORT"
echo ""
echo "Type 'node-socketio-chatroom' to manage your server."
echo "========================================"