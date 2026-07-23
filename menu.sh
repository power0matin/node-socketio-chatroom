#!/usr/bin/env bash
set -Eeuo pipefail

cleanup() { true; }
trap cleanup EXIT

# -------------------- Config --------------------
DIR_DEFAULT="$HOME/chat-node-socketio-chatroom"
MANAGER_BIN="/usr/local/bin/node-socketio-chatroom"
REPO_URL="https://github.com/power0matin/node-socketio-chatroom.git"
BRANCH="main"
INSTALL_URL="https://raw.githubusercontent.com/power0matin/node-socketio-chatroom/main/install.sh"

# -------------------- Colors --------------------
R='\033[0m'        # Reset
BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
CYAN='\033[36m'
BLUE='\033[34m'
WHITE='\033[97m'
BG_DARK='\033[48;5;235m'

# -------------------- Helpers --------------------
clear_screen() { clear; }

print_header() {
  echo ""
  echo -e "  ${CYAN}${BOLD}╔══════════════════════════════════════════╗${R}"
  echo -e "  ${CYAN}${BOLD}║${R}   ${WHITE}${BOLD}node-socketio-chatroom${R}                ${CYAN}${BOLD}║${R}"
  echo -e "  ${CYAN}${BOLD}╚══════════════════════════════════════════╝${R}"
  echo ""
}

print_status() {
  local status_text="$1"
  local status_color="$2"
  echo -e "  ${DIM}Install dir:${R} ${DIR_DEFAULT}"
  echo -e "  ${DIM}Status:${R}      ${status_color}${BOLD}${status_text}${R}"
  echo ""
}

print_separator() {
  echo -e "  ${DIM}──────────────────────────────────────────${R}"
}

pause() {
  echo ""
  read -r -p "  Press Enter to continue..." 
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo -e "  ${RED}ERROR:${R} '$1' not found."; return 1; }
}

ensure_deps() {
  echo -e "  ${YELLOW}Installing dependencies...${R}"
  sudo apt-get update -y >/dev/null 2>&1
  sudo apt-get install -y curl ca-certificates git rsync >/dev/null 2>&1
}

detect_app_name() {
  local config="$DIR_DEFAULT/data/config.json"
  if [[ -f "$config" ]]; then
    local name
    name="$(node -e "try{const d=JSON.parse(require('fs').readFileSync('$config','utf8'));process.stdout.write(d.appName||'')}catch{}" 2>/dev/null || true)"
    if [[ -n "$name" ]]; then
      echo "$name"
      return
    fi
  fi
  echo "node-socketio-chatroom"
}

APP_NAME="$(detect_app_name)"

is_installed() {
  [[ -d "$DIR_DEFAULT" && -d "$DIR_DEFAULT/data" && \
     ( -f "$DIR_DEFAULT/server.js" || -f "$DIR_DEFAULT/src/server.js" ) ]]
}

get_version() {
  local pkg="$DIR_DEFAULT/package.json"
  if [[ -f "$pkg" ]]; then
    node -e "try{process.stdout.write(JSON.parse(require('fs').readFileSync('$pkg','utf8')).version||'')}catch{}" 2>/dev/null || echo "unknown"
  else
    echo "—"
  fi
}

is_running() {
  if command -v pm2 >/dev/null 2>&1; then
    pm2 list 2>/dev/null | grep -q "$APP_NAME" && return 0
  fi
  return 1
}

manager_exists() {
  [[ -x "$MANAGER_BIN" ]]
}

# -------------------- Actions --------------------
run_installer() {
  ensure_deps
  echo ""
  bash <(curl -fsSL "$INSTALL_URL")
}

run_manager() {
  if manager_exists; then
    "$MANAGER_BIN"
  else
    echo -e "  ${RED}Manager not found at:${R} $MANAGER_BIN"
    echo -e "  ${DIM}Re-run Install to set it up.${R}"
  fi
}

run_update() {
  ensure_deps

  if ! is_installed; then
    echo -e "  ${YELLOW}Not installed yet.${R} Please install first."
    return 0
  fi

  if manager_exists; then
    echo -e "  ${GREEN}Opening installed manager...${R}"
    "$MANAGER_BIN"
    return 0
  fi

  echo -e "  ${YELLOW}Manager not found. Running update...${R}"
  echo ""

  require_cmd pm2 || { echo -e "  ${RED}PM2 not found. Run Install first.${R}"; return 1; }

  LOCK="$DIR_DEFAULT/.menu-update.lock"
  if [[ -e "$LOCK" ]]; then
    echo -e "  ${RED}Another update is already running.${R}"
    return 1
  fi
  touch "$LOCK"
  trap 'rm -f "$LOCK" >/dev/null 2>&1 || true' RETURN

  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP" >/dev/null 2>&1 || true' RETURN

  echo -e "  ${CYAN}[1/4]${R} Fetching latest source..."
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$TMP/repo" >/dev/null 2>&1 || {
    echo -e "  ${RED}ERROR:${R} git clone failed."
    return 1
  }

  echo -e "  ${CYAN}[2/4]${R} Syncing code..."
  rsync -a --delete \
    --exclude ".git/" \
    --exclude "data/" \
    --exclude "public/uploads/" \
    --exclude "node_modules/" \
    "$TMP/repo/" "$DIR_DEFAULT/"

  echo -e "  ${CYAN}[3/4]${R} Installing dependencies..."
  cd "$DIR_DEFAULT"
  npm install

  echo -e "  ${CYAN}[4/4]${R} Restarting service..."
  pm2 restart "$APP_NAME" || true

  echo ""
  echo -e "  ${GREEN}Update completed successfully!${R}"
}

uninstall_all() {
  if ! is_installed; then
    echo -e "  ${DIM}Nothing to uninstall.${R}"
    return 0
  fi

  echo ""
  echo -e "  ${RED}${BOLD}WARNING: This will delete ALL data, uploads, and config.${R}"
  echo -e "  ${DIM}This action cannot be undone.${R}"
  echo ""
  read -r -p "  Type 'yes' to confirm uninstall: " confirm
  if [[ "$confirm" != "yes" ]]; then
    echo -e "  ${DIM}Uninstall canceled.${R}"
    return 0
  fi

  echo ""
  echo -e "  ${YELLOW}Uninstalling...${R}"

  if command -v pm2 >/dev/null 2>&1; then
    pm2 delete "$APP_NAME" 2>/dev/null || true
  fi

  rm -rf "$DIR_DEFAULT"
  sudo rm -f "$MANAGER_BIN"
  echo -e "  ${GREEN}Uninstalled successfully.${R}"
}

show_info() {
  echo ""
  echo -e "  ${CYAN}App Name:${R}    $APP_NAME"
  echo -e "  ${CYAN}Version:${R}     $(get_version)"
  echo -e "  ${CYAN}Install Dir:${R} $DIR_DEFAULT"
  echo -e "  ${CYAN}Manager:${R}     $(manager_exists && echo -e "${GREEN}Available${R}" || echo -e "${YELLOW}Not installed${R}")"
  echo -e "  ${CYAN}Running:${R}     $(is_running && echo -e "${GREEN}Yes${R}" || echo -e "${DIM}No${R}")"
}

# -------------------- Menu --------------------
while true; do
  clear_screen
  print_header

  if is_installed; then
    local_ver="$(get_version)"
    running_state="$(is_running && echo -e "${GREEN}running${R}" || echo -e "${YELLOW}stopped${R}")"
    print_status "Installed v${local_ver} — ${running_state}" "${GREEN}"

    echo -e "  ${WHITE}${BOLD}  1${R}   Manage    ${DIM}— Open the management panel${R}"
    echo -e "  ${WHITE}${BOLD}  2${R}   Update    ${DIM}— Pull latest & restart${R}"
    echo -e "  ${WHITE}${BOLD}  3${R}   Info      ${DIM}— Show details${R}"
    echo -e "  ${WHITE}${BOLD}  4${R}   Uninstall ${DIM}— Remove everything${R}"
    echo ""
    print_separator
    echo -e "  ${WHITE}${BOLD}  0${R}   Exit"
    echo ""
  else
    print_status "Not installed" "${YELLOW}"

    echo -e "  ${WHITE}${BOLD}  1${R}   Install   ${DIM}— Set up the chatroom${R}"
    echo ""
    print_separator
    echo -e "  ${WHITE}${BOLD}  0${R}   Exit"
    echo ""
  fi

  read -r -p "  Select: " opt
  echo ""

  if is_installed; then
    case "${opt:-}" in
      1) run_manager; pause ;;
      2) run_update; pause ;;
      3) show_info; pause ;;
      4) uninstall_all; pause ;;
      0) echo -e "  ${DIM}Goodbye!${R}"; exit 0 ;;
      *) echo -e "  ${RED}Invalid option.${R}"; sleep 1 ;;
    esac
  else
    case "${opt:-}" in
      1) run_installer; pause ;;
      0) echo -e "  ${DIM}Goodbye!${R}"; exit 0 ;;
      *) echo -e "  ${RED}Invalid option.${R}"; sleep 1 ;;
    esac
  fi
done
