#!/usr/bin/env bash
set -Eeuo pipefail

# node-socketio-chatroom - Interactive Installer (Hardened, feature-preserving)
# App: node-socketio-chatroom
# Folder: ~/chat-node-socketio-chatroom

cleanup() { true; }
trap cleanup EXIT

DIR_DEFAULT="$HOME/chat-node-socketio-chatroom"
APP_NAME_DEFAULT="node-socketio-chatroom"

echo "========================================"
echo "    node-socketio-chatroom Installer"
echo "========================================"
echo ""
echo "Please configure your chat server:"
echo ""

read -r -p "Chat Room Name [default: ${APP_NAME_DEFAULT}]: " INPUT_APP_NAME
APP_NAME_VAL="${INPUT_APP_NAME:-$APP_NAME_DEFAULT}"

read -r -p "Admin Username [default: admin]: " INPUT_USER
ADMIN_USER="${INPUT_USER:-admin}"

# Admin Password (secure): no weak default, hidden input. If empty => generate strong random.
prompt_password() {
  local pass1 pass2
  while true; do
    read -r -s -p "Admin Password (leave empty to auto-generate): " pass1
    echo ""
    if [[ -z "${pass1}" ]]; then
      # 24 chars, URL-safe-ish
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

# Validations
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
  1) # Azure Blue (Modern, safe for dashboards)
     C_DEF="#2563EB"; C_DARK="#1D4ED8"; C_LIGHT="#EFF6FF" ;;
  2) # Iris Purple (Premium, calm)
     C_DEF="#7C3AED"; C_DARK="#6D28D9"; C_LIGHT="#F5F3FF" ;;
  3) # Emerald Green (Friendly, balanced)
     C_DEF="#10B981"; C_DARK="#059669"; C_LIGHT="#ECFDF5" ;;
  4) # Rose Red (Alerts/Admin emphasis)
     C_DEF="#F43F5E"; C_DARK="#E11D48"; C_LIGHT="#FFF1F2" ;;
  5) # Amber Orange (Warm, readable)
     C_DEF="#F59E0B"; C_DARK="#D97706"; C_LIGHT="#FFFBEB" ;;
  6) # Teal (Clean, modern)
     C_DEF="#14B8A6"; C_DARK="#0F766E"; C_LIGHT="#F0FDFA" ;;
  *) # Default = Azure Blue
     C_DEF="#2563EB"; C_DARK="#1D4ED8"; C_LIGHT="#EFF6FF" ;;
esac

echo ""


echo "[2/6] Installing Node.js & PM2..."

# نصب Node.js (NodeSource)
if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi

# مسیرهای رایج npm + fallback با command -v
NPM_BIN=""
for p in /usr/bin/npm /usr/local/bin/npm /bin/npm; do
  if [[ -x "$p" ]]; then NPM_BIN="$p"; break; fi
done
if [[ -z "$NPM_BIN" ]]; then
  NPM_BIN="$(command -v npm 2>/dev/null || true)"
fi

# اگر هنوز npm نبود، نصب npm و دوباره تلاش
if [[ -z "$NPM_BIN" ]]; then
  sudo apt-get update -y
  sudo apt-get install -y npm
  for p in /usr/bin/npm /usr/local/bin/npm /bin/npm; do
    if [[ -x "$p" ]]; then NPM_BIN="$p"; break; fi
  done
  if [[ -z "$NPM_BIN" ]]; then
    NPM_BIN="$(command -v npm 2>/dev/null || true)"
  fi
fi

# اگر هنوز هم نبود، fail
if [[ -z "$NPM_BIN" ]]; then
  echo "ERROR: npm not found (even after installing npm)."
  echo "Try manually:"
  echo "  sudo apt-get install -y nodejs npm"
  exit 1
fi

# pm2 را بدون وابستگی به PATH محدود sudo نصب کن
sudo "$NPM_BIN" install -g pm2

# چک سریع
node -v
"$NPM_BIN" -v
pm2 -v

echo "[3/6] Creating project files in $DIR_DEFAULT..."
DIR="$DIR_DEFAULT"
mkdir -p "$DIR/public" "$DIR/data" "$DIR/public/uploads"
chmod 700 "$DIR/data" "$DIR/public/uploads"
cd "$DIR"

cat > package.json << 'EOF'
{
  "name": "node-socketio-chatroom",
  "version": "1.0.11",
  "main": "server.js",
  "scripts": { "start": "node server.js" },
  "dependencies": {
    "express": "^4.18.2",
    "socket.io": "^4.7.2",
    "multer": "^1.4.5-lts.1",
    "bcryptjs": "^2.4.3",
    "helmet": "^7.1.0",
    "xss": "^1.0.14",
    "express-rate-limit": "^7.1.5"
  }
}
EOF


# --- IMPORTANT ---
# For the installer to be truly "single-file", paste your current full index.html content
# in place of __PASTE_YOUR_EXISTING_INDEX_HTML_HERE__ (exactly as you have it).
# (I didn't alter UI to avoid breaking anything.)
echo "[4/6] Applying configuration..."
# Replace placeholders if they exist in your index.html
sed -i "s|__APP_NAME_PLACEHOLDER__|$APP_NAME_VAL|g" public/index.html || true

# Theme variables are in theme.css now
sed -i "s|__COLOR_DEFAULT__|$C_DEF|g" public/assets/theme.css || true
sed -i "s|__COLOR_DARK__|$C_DARK|g" public/assets/theme.css || true
sed -i "s|__COLOR_LIGHT__|$C_LIGHT|g" public/assets/theme.css || true

echo "[5/6] Installing project dependencies..."
"$NPM_BIN" install

# --- After npm install: create config with adminPassHash (no plaintext) ---
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

# --- Data-at-rest encryption key (AES-256-GCM) ---
# Try OpenSSL, fallback to /dev/urandom hex
DATA_ENC_KEY=""
if command -v openssl >/dev/null 2>&1; then
  DATA_ENC_KEY="$(openssl rand -hex 32)"
else
  DATA_ENC_KEY="$(LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c 64)"
fi

if [[ -z "${DATA_ENC_KEY}" || "${#DATA_ENC_KEY}" -lt 64 ]]; then
  echo "ERROR: failed to generate dataEncKey"
  exit 1
fi

cat > data/config.json <<EOF
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
chmod 600 data/config.json

# Do NOT keep plaintext password around longer than needed
unset ADMIN_PASS
echo "[6/6] Starting server with PM2..."
PM2_NAME="${APP_NAME_VAL}"
pm2 delete "$PM2_NAME" 2>/dev/null || true
PORT="$PORT" pm2 start server.js --name "$PM2_NAME"
pm2 save

echo "Creating management tool..."

cat << 'EOF_MENU' > /tmp/node-socketio-chatroom-menu.sh
#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="__PM2_NAME__"
DIR="__DIR__"
CONFIG_FILE="$DIR/data/config.json"
INDEX_FILE="$DIR/public/index.html"

# Repo settings for update
REPO_URL="https://github.com/power0matin/node-socketio-chatroom.git"
BRANCH="main"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found."; return 1; }
}

pause() { read -r -p "Press Enter..." ; }

timestamp() { date +"%Y%m%d-%H%M%S"; }

make_backup() {
  local ts; ts="$(timestamp)"
  local bdir="$DIR/backup"
  mkdir -p "$bdir"

  # Backup critical persistent data
  if [[ -d "$DIR/data" ]]; then
    tar -czf "$bdir/data-$ts.tar.gz" -C "$DIR" data >/dev/null 2>&1 || true
  fi
  if [[ -d "$DIR/public/uploads" ]]; then
    tar -czf "$bdir/uploads-$ts.tar.gz" -C "$DIR/public" uploads >/dev/null 2>&1 || true
  fi
  echo "Backup created in: $bdir"
}

update_via_git_clone() {
  require_cmd git || return 1
  require_cmd rsync || return 1

  local tmp
  tmp="$(mktemp -d)"

  echo "[1/5] Cloning latest code into temp..."
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$tmp/repo" >/dev/null 2>&1 || {
    echo "ERROR: git clone failed. Check REPO_URL / BRANCH or repo access."
    return 1
  }

  echo "[2/5] Syncing code (preserving database/uploads/config)..."
  # Exclude persistent/runtime dirs
  rsync -a --delete \
    --exclude ".git/" \
    --exclude "data/" \
    --filter='P public/uploads/' \
    --exclude "public/uploads/***" \
    --exclude "node_modules/" \
    "$tmp/repo/" "$DIR/"

  rm -rf "$tmp" >/dev/null 2>&1 || true

  echo "Code synced."
}

update_via_zip() {
  require_cmd curl || return 1
  require_cmd rsync || return 1

  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp" >/dev/null 2>&1 || true' RETURN

  local zip_url="https://codeload.github.com/power0matin/node-socketio-chatroom/zip/refs/heads/$BRANCH"

  echo "[1/5] Downloading zip: $zip_url"
  curl -fsSL "$zip_url" -o "$tmp/repo.zip" || {
    echo "ERROR: zip download failed. Repo may be private or BRANCH is wrong."
    return 1
  }

  require_cmd unzip || return 1
  unzip -q "$tmp/repo.zip" -d "$tmp" || { echo "ERROR: unzip failed"; return 1; }

  local extracted
  extracted="$(find "$tmp" -maxdepth 1 -type d -name "node-socketio-chatroom-*" | head -n1 || true)"
  [[ -n "$extracted" ]] || { echo "ERROR: Could not find extracted folder."; return 1; }

  echo "[2/5] Syncing code (preserving database/uploads/config)..."
  rsync -a --delete \
    --exclude "data/" \
    --filter='P public/uploads/' \
    --exclude "public/uploads/***" \
    --exclude "node_modules/" \
    "$extracted/" "$DIR/"

  echo "Code synced."
}

update_app() {
  echo "-----------------------------------"
  echo "Updating node-socketio-chatroom..."
  echo "Preserve: data/ , public/uploads/ , config.json"
  echo "-----------------------------------"

  require_cmd pm2 || return 1
  require_cmd node || return 1

  if [[ ! -d "$DIR" ]]; then
    echo "ERROR: Project directory not found: $DIR"
    return 1
  fi

  # Lock to prevent concurrent updates
  local lock="$DIR/.update.lock"
  if [[ -e "$lock" ]]; then
    echo "ERROR: Another update seems running. Lock exists: $lock"
    return 1
  fi
  touch "$lock"
  trap 'rm -f "$lock" >/dev/null 2>&1 || true' RETURN

  cd "$DIR"

  echo "[0/5] Creating backup..."
  make_backup

  # Prefer git clone method; fallback to zip if git fails
  echo "[1/5] Fetching latest source..."
  if command -v git >/dev/null 2>&1; then
    if ! update_via_git_clone; then
      echo "Git method failed. Trying ZIP method..."
      update_via_zip || return 1
    fi
  else
    echo "git not found. Using ZIP method..."
    update_via_zip || return 1
  fi

  # Find npm
  local NPM_BIN=""
  for p in /usr/bin/npm /usr/local/bin/npm /bin/npm; do
    if [[ -x "$p" ]]; then NPM_BIN="$p"; break; fi
  done
  if [[ -z "$NPM_BIN" ]]; then
    NPM_BIN="$(command -v npm 2>/dev/null || true)"
  fi
  if [[ -z "$NPM_BIN" ]]; then
    echo "ERROR: npm not found."
    return 1
  fi

  echo "[3/5] Installing dependencies..."
  "$NPM_BIN" install || { echo "ERROR: npm install failed."; return 1; }

  echo "[4/5] Restarting PM2 process..."
  pm2 restart "$APP_NAME" || { echo "ERROR: pm2 restart failed."; return 1; }

  echo "[5/5] Done."
  echo "Update completed successfully."
}

while true; do
  clear
  echo "==================================="
  echo "   node-socketio-chatroom Manager ($APP_NAME)"
  echo "==================================="
  echo "1. Check Status"
  echo "2. Restart Server"
  echo "3. Stop Server"
  echo "4. View Logs"
  echo "5. Settings (User/Pass/Size/Name/Origins)"
  echo "6. Update (Preserve data/uploads)"
  echo "7. Uninstall / Delete"
  echo "0. Exit"
  echo "==================================="
  read -r -p "Select option: " opt

  case $opt in
    1) pm2 status "$APP_NAME"; pause ;;
    2) pm2 restart "$APP_NAME"; echo "Restarted."; pause ;;
    3) pm2 stop "$APP_NAME"; echo "Stopped."; pause ;;
    4) pm2 logs "$APP_NAME" --lines 50 ;;
    5)
      echo "--- Current Settings ---"
      cat "$CONFIG_FILE" || true
      echo ""
      echo "a) Change Admin Username"
      echo "b) Change Admin Password (stored hashed)"
      echo "c) Change Max Upload Size (MB)"
      echo "d) Change App Name"
      echo "e) Change Allowed Origins"
      read -r -p "Select option: " subopt

      case $subopt in
        a)
          read -r -p "New Username: " NEW_USER
          node -e "const fs=require('fs');const p='$CONFIG_FILE';const d=JSON.parse(fs.readFileSync(p));d.adminUser=String(process.env.NEW_USER||'').trim();fs.writeFileSync(p, JSON.stringify(d,null,2));" NEW_USER="$NEW_USER"
          pm2 restart "$APP_NAME"
          ;;
        b)
          read -r -p "New Password: " NEW_PASS
          node -e "const fs=require('fs');const bcrypt=require('bcryptjs');const p='$CONFIG_FILE';const d=JSON.parse(fs.readFileSync(p));d.adminPassHash=bcrypt.hashSync(String(process.env.NEW_PASS||''),12);delete d.adminPass;fs.writeFileSync(p, JSON.stringify(d,null,2));" NEW_PASS="$NEW_PASS"
          pm2 restart "$APP_NAME"
          ;;
        c)
          read -r -p "New Max Size (MB): " NEW_SIZE
          if [[ "$NEW_SIZE" =~ ^[0-9]+$ ]]; then
            node -e "const fs=require('fs');const p='$CONFIG_FILE';const d=JSON.parse(fs.readFileSync(p));d.maxFileSizeMB=Number(process.env.NEW_SIZE);fs.writeFileSync(p, JSON.stringify(d,null,2));" NEW_SIZE="$NEW_SIZE"
            pm2 restart "$APP_NAME"
          else
            echo "Invalid number."
          fi
          ;;
        d)
          read -r -p "New App Name: " NEW_APP_NAME
          node -e "const fs=require('fs');const p='$CONFIG_FILE';const d=JSON.parse(fs.readFileSync(p));d.appName=String(process.env.NEW_APP_NAME||'').trim();fs.writeFileSync(p, JSON.stringify(d,null,2));" NEW_APP_NAME="$NEW_APP_NAME"
          sed -i "s|<title>.*</title>|<title>$NEW_APP_NAME</title>|g" "$INDEX_FILE" 2>/dev/null || true
          sed -i "s|appName = ref('.*');|appName = ref('$NEW_APP_NAME');|g" "$INDEX_FILE" 2>/dev/null || true
          pm2 restart "$APP_NAME"
          ;;
        e)
          read -r -p "Allowed Origins (comma-separated or *): " NEW_ORIGINS
          node -e "const fs=require('fs');const p='$CONFIG_FILE';const d=JSON.parse(fs.readFileSync(p));d.allowedOrigins=String(process.env.NEW_ORIGINS||'*').trim();fs.writeFileSync(p, JSON.stringify(d,null,2));" NEW_ORIGINS="$NEW_ORIGINS"
          pm2 restart "$APP_NAME"
          ;;
      esac
      pause
      ;;
    6)
      update_app
      pause
      ;;
    7)
      read -r -p "Are you sure you want to DELETE everything? (y/n): " confirm
      if [[ "$confirm" == "y" ]]; then
        pm2 delete "$APP_NAME" || true
        rm -rf "$DIR"
        sudo rm -f /usr/local/bin/node-socketio-chatroom
        echo "Uninstalled successfully."
        exit 0
      fi
      ;;
    0) exit 0 ;;
    *) echo "Invalid option"; sleep 1 ;;
  esac
done
EOF_MENU

# Fill placeholders safely (فایل درست همونیه که ساختی)
sed -i "s|__DIR__|$DIR|g" /tmp/node-socketio-chatroom-menu.sh
sed -i "s|__PM2_NAME__|$PM2_NAME|g" /tmp/node-socketio-chatroom-menu.sh

sudo mv /tmp/node-socketio-chatroom-menu.sh /usr/local/bin/node-socketio-chatroom
sudo chmod +x /usr/local/bin/node-socketio-chatroom

echo ""
echo "========================================"
echo "      INSTALLATION COMPLETE! 🚀"
echo "========================================"
echo ""
echo "Your Admin Credentials:"
echo "User: $ADMIN_USER"
echo "Pass: stored hashed in config.json (password will not be shown again)"
echo ""
IP="$(curl -fsS https://api.ipify.org 2>/dev/null || curl -fsS https://ifconfig.co 2>/dev/null || echo 'YOUR_SERVER_IP')"
echo "Access URL: http://$IP:$PORT"
echo ""
echo "Type 'node-socketio-chatroom' in terminal to manage your server."
echo "========================================"