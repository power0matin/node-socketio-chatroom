#!/usr/bin/env bash
set -Eeuo pipefail

cleanup() { true; }
trap cleanup EXIT

APP_NAME="HyperSentry"
DIR_DEFAULT="$HOME/chat-node-socketio-chatroom"
MANAGER_BIN="/usr/local/bin/node-socketio-chatroom"

REPO_URL="https://github.com/power0matin/node-socketio-chatroom.git"
BRANCH="main"

INSTALL_URL="https://raw.githubusercontent.com/power0matin/node-socketio-chatroom/main/install.sh"

pause() { read -r -p "Press Enter..." ; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found."; return 1; }
}

ensure_deps() {
  sudo apt-get update -y
  sudo apt-get install -y curl ca-certificates git rsync
}

is_installed() {
  [[ -d "$DIR_DEFAULT" && -f "$DIR_DEFAULT/server.js" && -d "$DIR_DEFAULT/data" ]]
}

manager_exists() {
  [[ -x "$MANAGER_BIN" ]]
}

run_installer() {
  ensure_deps
  bash <(curl -fsSL "$INSTALL_URL")
}

run_manager() {
  if manager_exists; then
    "$MANAGER_BIN"
  else
    echo "Manager tool not found at: $MANAGER_BIN"
    echo "If you already installed, re-run install or create manager from install script."
  fi
}

run_update() {
  # Update should be done from installed manager (best), but if not present, do minimal safe update here:
  ensure_deps

  if ! is_installed; then
    echo "Not installed yet. Please run Install first."
    return 0
  fi

  if manager_exists; then
    echo "Opening installed manager (recommended) ..."
    "$MANAGER_BIN"
    return 0
  fi

  echo "Manager not found. Running safe update here..."

  require_cmd pm2 || { echo "PM2 not found. Run Install first."; return 1; }

  LOCK="$DIR_DEFAULT/.menu-update.lock"
  if [[ -e "$LOCK" ]]; then
    echo "Another update is running. Lock exists: $LOCK"
    return 1
  fi
  touch "$LOCK"
  trap 'rm -f "$LOCK" >/dev/null 2>&1 || true' RETURN

  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP" >/dev/null 2>&1 || true' RETURN

  echo "[1/4] Fetching latest source..."
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$TMP/repo" >/dev/null 2>&1 || {
    echo "ERROR: git clone failed."
    return 1
  }

  echo "[2/4] Syncing code (preserving data/uploads/node_modules)..."
  rsync -a --delete \
    --exclude ".git/" \
    --exclude "data/" \
    --exclude "public/uploads/" \
    --exclude "node_modules/" \
    "$TMP/repo/" "$DIR_DEFAULT/"

  echo "[3/4] npm install..."
  cd "$DIR_DEFAULT"
  npm install

  echo "[4/4] pm2 restart..."
  pm2 restart "$APP_NAME" || true

  echo "Update completed."
}

uninstall_all() {
  if ! is_installed; then
    echo "Nothing to uninstall."
    return 0
  fi

  read -r -p "Are you sure you want to DELETE everything? (y/n): " confirm
  if [[ "$confirm" != "y" ]]; then
    echo "Canceled."
    return 0
  fi

  if command -v pm2 >/dev/null 2>&1; then
    pm2 delete "$APP_NAME" 2>/dev/null || true
  fi

  rm -rf "$DIR_DEFAULT"
  sudo rm -f "$MANAGER_BIN"
  echo "Uninstalled successfully."
}

while true; do
  clear
  echo "==================================="
  echo "  node-socketio-chatroom Menu"
  echo "==================================="
  echo "Install Dir: $DIR_DEFAULT"
  echo "-----------------------------------"

  if is_installed; then
    echo "1) Manage (open installed manager)"
    echo "2) Update (preserve data/uploads)"
    echo "3) Uninstall / Delete"
    echo "0) Exit"
  else
    echo "1) Install"
    echo "0) Exit"
  fi

  echo "==================================="
  read -r -p "Select option: " opt

  if is_installed; then
    case "$opt" in
      1) run_manager; pause ;;
      2) run_update; pause ;;
      3) uninstall_all; pause ;;
      0) exit 0 ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
  else
    case "$opt" in
      1) run_installer; pause ;;
      0) exit 0 ;;
      *) echo "Invalid option"; sleep 1 ;;
    esac
  fi
done