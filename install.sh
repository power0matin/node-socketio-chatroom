#!/usr/bin/env bash
set -Eeuo pipefail

# node-socketio-chatroom - Interactive Installer (Hardened + Enhanced Preflight)
# App: node-socketio-chatroom
# Folder: ~/chat-node-socketio-chatroom

cleanup() { true; }
trap cleanup EXIT

# ---- Installer metadata (dynamic, auto-sync with GitHub) ----
REPO_URL_DEFAULT="https://github.com/power0matin/node-socketio-chatroom.git"
REPO_BRANCH_DEFAULT="main"

# اگر بعداً خواستی از فورک/برنچ دیگر استفاده کنی فقط همین دو تا را عوض می‌کنی
REPO_URL="${REPO_URL:-$REPO_URL_DEFAULT}"
REPO_BRANCH="${REPO_BRANCH:-$REPO_BRANCH_DEFAULT}"

repo_raw_base() {
  # https://github.com/owner/repo(.git) -> https://raw.githubusercontent.com/owner/repo/<branch>
  printf '%s' "$REPO_URL" \
    | sed -E "s#^https?://github.com/([^/]+/[^/.]+)(\.git)?\$#https://raw.githubusercontent.com/\\1/${REPO_BRANCH}#"
}

fetch_installer_version() {
  local raw pkg ver
  raw="$(repo_raw_base)"
  pkg="${raw}/package.json"

  command -v curl >/dev/null 2>&1 || return 1

  ver="$(curl -fsSL "$pkg" 2>/dev/null \
    | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p' \
    | head -n1)"
  [[ -n "$ver" ]] || return 1
  printf '%s' "$ver"
}

fetch_installer_build_date() {
  local raw inst lm d
  raw="$(repo_raw_base)"
  inst="${raw}/install.sh"

  command -v curl >/dev/null 2>&1 || return 1

  lm="$(curl -fsSI "$inst" 2>/dev/null | tr -d '\r' \
    | awk -F': ' 'tolower($1)=="last-modified"{print $2}' | head -n1)"
  [[ -n "$lm" ]] || return 1

  # GNU date (روی Ubuntu/Debian اوکیه)
  d="$(date -d "$lm" +%Y-%m-%d 2>/dev/null || true)"
  [[ -n "$d" ]] || return 1
  printf '%s' "$d"
}

INSTALLER_VERSION="$(fetch_installer_version || echo "unknown")"
INSTALLER_BUILD_DATE="$(fetch_installer_build_date || date -u +%Y-%m-%d)"

DIR_DEFAULT="$HOME/chat-node-socketio-chatroom"
APP_NAME_DEFAULT="node-socketio-chatroom"

need_apt_update=0
CERTBOT_DRYRUN_OK=0

have_cmd() { command -v "$1" >/dev/null 2>&1; }
find_npm_bin() {
  local b=""
  for p in /usr/bin/npm /usr/local/bin/npm /bin/npm; do
    if [[ -x "$p" ]]; then b="$p"; break; fi
  done
  if [[ -z "$b" ]]; then b="$(command -v npm 2>/dev/null || true)"; fi
  [[ -n "$b" ]] || die "npm not found."
  printf '%s' "$b"
}

find_pm2_bin() {
  local b=""
  for p in /usr/bin/pm2 /usr/local/bin/pm2 /bin/pm2; do
    if [[ -x "$p" ]]; then b="$p"; break; fi
  done
  if [[ -z "$b" ]]; then b="$(command -v pm2 2>/dev/null || true)"; fi
  [[ -n "$b" ]] || die "pm2 not found."
  printf '%s' "$b"
}
detect_app_entry() {
  local dir="$1"

  # 1) classic root server.js
  if [[ -f "$dir/server.js" ]]; then
    echo "$dir/server.js"
    return 0
  fi

  # 2) new repo layout: src/server.js
  if [[ -f "$dir/src/server.js" ]]; then
    echo "$dir/src/server.js"
    return 0
  fi

  # 3) package.json "main"
  if [[ -f "$dir/package.json" ]]; then
    local main
    main="$(node -e "const p=require('${dir}/package.json');process.stdout.write(p.main||'')" 2>/dev/null || true)"
    if [[ -n "$main" && -f "$dir/$main" ]]; then
      echo "$dir/$main"
      return 0
    fi
  fi

  return 1
}
get_listener_pid() {
  local p="$1"
  local pid=""

  if have_cmd ss; then
    # نمونه خروجی: users:(("node",pid=1234,fd=21))
    pid="$(ss -lptn "( sport = :$p )" 2>/dev/null \
      | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' \
      | head -n1 || true)"
  fi

  if [[ -z "$pid" ]] && have_cmd lsof; then
    pid="$(lsof -tiTCP:"$p" -sTCP:LISTEN -n -P 2>/dev/null | head -n1 || true)"
  fi

  if [[ -z "$pid" ]] && have_cmd netstat; then
    # netstat format: ... LISTEN  pid/program
    pid="$(netstat -lntp 2>/dev/null \
      | awk -v port=":$p" '$4 ~ port && $6=="LISTEN" {print $7}' \
      | sed -n 's/^\([0-9]\+\)\/.*/\1/p' \
      | head -n1 || true)"
  fi

  echo "$pid"
}

pid_cmdline() {
  local pid="$1"
  [[ -n "$pid" ]] || return 1
  ps -p "$pid" -o args= 2>/dev/null || true
}

# تشخیص اینکه پردازش روی پورت، مربوط به همین نصب است یا نه
is_our_listener() {
  local pid="$1"
  local dir="$2"
  [[ -n "$pid" ]] || return 1

  local cmd
  cmd="$(pid_cmdline "$pid")"
  [[ -n "$cmd" ]] || return 1

  # must be a node process
  echo "$cmd" | grep -qiE '(^|[[:space:]])node([[:space:]]|$)' || return 1

  # must reference project entry (root server.js or src/server.js)
  echo "$cmd" | grep -qE "$(printf '%s' "$dir" | sed 's/[.[\()*^$+?{|]/\\&/g')/(server\.js|src/server\.js)" || return 1

  return 0
}


kill_listener_pid() {
  local pid="$1"
  [[ -n "$pid" ]] || return 0

  # اول graceful
  kill -TERM "$pid" >/dev/null 2>&1 || true
  sleep 1
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill -KILL "$pid" >/dev/null 2>&1 || true
  fi
}

confirm_yn_default_yes() {
  local prompt="$1"
  local ans=""
  read -r -p "$prompt [Y/n]: " ans
  ans="${ans:-Y}"
  [[ "$ans" =~ ^[Yy]$ ]]
}

# ---- HTTPS helpers ----
validate_fqdn() {
  # basic FQDN validation (labels 1-63, total <=253, must contain at least one dot)
  local d="${1:-}"
  [[ -n "$d" ]] || return 1
  [[ "$d" != *".."* ]] || return 1
  [[ "$d" == *.* ]] || return 1
  [[ ${#d} -le 253 ]] || return 1
  [[ "$d" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]] || return 1
  return 0
}

validate_email_loose() {
  local e="${1:-}"
  [[ -n "$e" ]] || return 1
  [[ "$e" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || return 1
  return 0
}

read_secret() {
  # read secret from TTY (hidden input)
  local prompt="$1"
  local outvar="$2"
  local v=""
  while true; do
    read -r -s -p "$prompt: " v
    echo ""
    [[ -n "$v" ]] && break
    echo "Value cannot be empty. Try again."
  done
  printf -v "$outvar" '%s' "$v"
}

make_backup_tar() {
  local dir="$1"
  [[ -d "$dir" ]] || return 0
  local ts; ts="$(date +%Y%m%d-%H%M%S)"
  local out="${dir}.backup-${ts}.tar.gz"
  tar -czf "$out" -C "$(dirname "$dir")" "$(basename "$dir")" >/dev/null 2>&1 || true
  [[ -f "$out" ]] && echo "$out" || true
}

safe_rm_dir() {
  local dir="$1"
  # محافظت: حذف فقط زیر $HOME
  case "$dir" in
    "$HOME"|"$HOME/"|"/"|"") return 1 ;;
  esac
  [[ "$dir" == "$HOME/"* ]] || return 1
  rm -rf -- "$dir"
}
merge_update_preserve_data() {
  local dir="$1"

  have_cmd rsync || die "rsync is required for safe update (not found)."
  have_cmd curl  || die "curl is required for safe update (not found)."

  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp" >/dev/null 2>&1 || true' RETURN

  log "Downloading latest source (zip) ..."
  local zip_url="https://codeload.github.com/power0matin/node-socketio-chatroom/zip/refs/heads/${REPO_BRANCH}"
  curl -fsSL "$zip_url" -o "$tmp/repo.zip" || die "Failed to download repo zip."

  apt_install_if_missing unzip unzip
  unzip -q "$tmp/repo.zip" -d "$tmp" || die "Failed to unzip repo."

  local extracted
  extracted="$(find "$tmp" -maxdepth 1 -type d -name "node-socketio-chatroom-*" | head -n1 || true)"
  [[ -n "$extracted" ]] || die "Could not find extracted repo folder."

  log "Updating code but preserving data/ and public/uploads/ ..."
  rsync -a --delete \
    --exclude "data/" \
    --exclude "public/uploads/" \
    --exclude "node_modules/" \
    "$extracted/" "$dir/"

  ok "Code updated (data preserved)."
}
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

  if sudo -n true 2>/dev/null; then
    ok "sudo: available (non-interactive)"
  else
    log "sudo: needs password (you may be prompted)"
    sudo true || die "sudo authentication failed"
  fi
}

check_internet() {
  if ! have_cmd curl; then
    warn "curl not found yet (will be installed later). Skipping connectivity test."
    return 0
  fi
  curl -fsS --max-time 5 "https://raw.githubusercontent.com/github/gitignore/main/Node.gitignore" >/dev/null 2>&1 \
    && ok "Internet: reachable (raw.githubusercontent.com)" \
    || warn "Internet: could not reach raw.githubusercontent.com (install may fail)"
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

# ---- apt helpers (safe) ----
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

# ---- HTTPS (Nginx + Certbot DNS-01) ----
ensure_nginx_installed() {
  apt_install_if_missing nginx nginx
  sudo systemctl enable --now nginx >/dev/null 2>&1 || true

  # If nginx config is already broken, do NOT attempt cleanup.
  local out=""
  if ! out="$(sudo nginx -t 2>&1)"; then
    echo "$out"
    die "Nginx config test failed. Please fix existing Nginx configuration and re-run the installer."
  fi
  ok "Nginx: running and config OK"
}

ensure_certbot_installed() {
  apt_install_if_missing certbot certbot
  # optional plugin (not required, but requested as optional)
  apt_install_if_missing python3-certbot-nginx python3-certbot-nginx || true
}

issue_cert_cloudflare() {
  local domain="$1"
  local email="$2"
  local token="$3"

  apt_install_if_missing python3-certbot-dns-cloudflare python3-certbot-dns-cloudflare

  sudo mkdir -p /root/.secrets
  sudo chmod 700 /root/.secrets

  # Write credentials file (exact format expected by certbot-dns-cloudflare)
  local tmp
  tmp="$(mktemp)"
  cat > "$tmp" <<EOF
dns_cloudflare_api_token = ${token}
EOF
  sudo mv "$tmp" "/root/.secrets/cloudflare-${domain}.ini"
  sudo chmod 600 "/root/.secrets/cloudflare-${domain}.ini"

  local live_ok=0
  if [[ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" && -f "/etc/letsencrypt/live/${domain}/privkey.pem" ]]; then
    live_ok=1
  fi

  local renew_conf="/etc/letsencrypt/renewal/${domain}.conf"
  local need_migrate=0

  # If renewal config exists and uses manual authenticator, we MUST migrate it
  if [[ -f "$renew_conf" ]] && grep -qE '^[[:space:]]*authenticator[[:space:]]*=[[:space:]]*manual[[:space:]]*$' "$renew_conf"; then
    need_migrate=1
    warn "Existing renewal config for ${domain} uses manual authenticator; migrating to Cloudflare DNS plugin..."
  fi

  # If cert exists but a dry-run fails, also migrate (token/headers/old config issues)
  if [[ "$live_ok" -eq 1 && "$need_migrate" -eq 0 ]]; then
    if ! sudo certbot renew --cert-name "$domain" --dry-run >/dev/null 2>&1; then
      need_migrate=1
      warn "Cert exists but renewal dry-run failed for ${domain}; forcing Cloudflare re-issue to repair renewal config..."
    fi
  fi

  # If cert exists AND no migration needed -> skip issuance
  if [[ "$live_ok" -eq 1 && "$need_migrate" -eq 0 ]]; then
    ok "Existing certificate found for ${domain} and renewal dry-run looks OK (skipping issuance)."
    return 0
  fi

  log "Issuing/Repairing Let's Encrypt certificate via Cloudflare DNS-01 for: ${domain}"
  sudo certbot certonly \
    --dns-cloudflare \
    --dns-cloudflare-credentials "/root/.secrets/cloudflare-${domain}.ini" \
    --dns-cloudflare-propagation-seconds 60 \
    -d "$domain" \
    --cert-name "$domain" \
    --agree-tos -m "$email" \
    --non-interactive \
    --force-renewal

  [[ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" && -f "/etc/letsencrypt/live/${domain}/privkey.pem" ]] \
    || die "Certificate issuance failed (Cloudflare). Expected cert files not found for: ${domain}"
  ok "Certificate issued/repaired for ${domain}"
}

issue_cert_manual() {
  local domain="$1"

  if [[ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" && -f "/etc/letsencrypt/live/${domain}/privkey.pem" ]]; then
    ok "Existing certificate found for ${domain} (skipping issuance)."
    return 0
  fi

  warn "Manual DNS-01 cert issuance will prompt you to create a TXT record."
  warn "After you add the TXT record in Cloudflare DNS, wait for propagation, then continue in certbot."
  sudo certbot certonly --manual --preferred-challenges dns -d "$domain"

  [[ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" && -f "/etc/letsencrypt/live/${domain}/privkey.pem" ]] \
    || die "Certificate issuance failed (manual). Expected cert files not found for: ${domain}"
  ok "Certificate issued for ${domain}"
}

write_nginx_site_conf() {
  local domain="$1"
  local port="$2"
  local conf="/etc/nginx/sites-available/${domain}"

  sudo tee "$conf" >/dev/null <<EOF
server {
  listen 80;
  server_name ${domain};
  return 301 https://\$host\$request_uri;
}

server {
  listen 443 ssl http2;
  server_name ${domain};

  ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;

  location / {
    proxy_pass http://127.0.0.1:${port};
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 3600;
    proxy_send_timeout 3600;
  }
}
EOF
  ok "Wrote Nginx site config: ${conf}"
}

enable_nginx_site() {
  local domain="$1"
  local conf="/etc/nginx/sites-available/${domain}"
  local link="/etc/nginx/sites-enabled/${domain}"

  [[ -f "$conf" ]] || die "Nginx site config not found: $conf"

  if [[ -L "$link" || -e "$link" ]]; then
    ok "Nginx site already enabled: ${domain}"
  else
    sudo ln -s "$conf" "$link"
    ok "Enabled Nginx site: ${domain}"
  fi

  # Only disable default site after nginx config passes
  local out=""
  if ! out="$(sudo nginx -t 2>&1)"; then
    echo "$out"
    die "Nginx config test failed after enabling site. Aborting (no destructive cleanup)."
  fi

  if [[ -L /etc/nginx/sites-enabled/default ]]; then
    sudo rm -f /etc/nginx/sites-enabled/default
    ok "Disabled default Nginx site symlink"
  fi
}

reload_nginx_safe() {
  local domain="$1"

  local out=""
  if ! out="$(sudo nginx -t 2>&1)"; then
    echo "$out"
    die "Nginx config test failed. Not reloading."
  fi

  sudo systemctl reload nginx
  ok "Nginx reloaded"

  if ss -lntp 2>/dev/null | grep -q ':443'; then
    ok "Port 443: listening"
  else
    warn "Port 443 not detected as listening (ss output did not match)."
  fi

  # Local TLS validation with Host header; -k to ignore cert verify (IP mismatch)
  if have_cmd curl; then
    curl -Ik -k https://127.0.0.1 -H "Host: ${domain}" >/dev/null 2>&1 \
      && ok "Local TLS check: OK (https://127.0.0.1 with Host=${domain})" \
      || warn "Local TLS check failed (curl)."
  fi
}

ensure_certbot_renewal() {
  local domain="$1"
  # Certbot can be installed via apt (certbot.timer) or snap (snap.certbot.renew.timer).
  local timer=""
  if systemctl list-unit-files 2>/dev/null | grep -qE '^[[:space:]]*certbot\.timer[[:space:]]'; then
    timer="certbot.timer"
  elif systemctl list-unit-files 2>/dev/null | grep -qE '^[[:space:]]*snap\.certbot\.renew\.timer[[:space:]]'; then
    timer="snap.certbot.renew.timer"
  fi

  if [[ -n "$timer" ]]; then
    if ! systemctl is-enabled "$timer" >/dev/null 2>&1; then
      sudo systemctl enable "$timer" >/dev/null 2>&1 || true
    fi
    sudo systemctl start "$timer" >/dev/null 2>&1 || true

    if systemctl is-active "$timer" >/dev/null 2>&1; then
      ok "${timer}: active"
    else
      warn "${timer} is not active. You may need to enable/start it manually."
    fi
  else
    warn "No certbot systemd timer found (certbot.timer or snap.certbot.renew.timer)."
  fi

  if sudo certbot renew --cert-name "$domain" --dry-run; then
    ok "certbot renew --dry-run (${domain}): OK"
    CERTBOT_DRYRUN_OK=1
  else
    warn "certbot renew --dry-run (${domain}) failed (check /var/log/letsencrypt/letsencrypt.log)"
    CERTBOT_DRYRUN_OK=0
  fi
}

setup_https_nginx() {
  local domain="$1"
  local email="$2"
  local mode="$3"
  local token="$4"
  local port="$5"

  [[ -n "$domain" ]] || die "setup_https_nginx: domain is empty"
  [[ -n "$email" ]] || die "setup_https_nginx: email is empty"

  ensure_nginx_installed
  ensure_certbot_installed

  if [[ "$mode" == "cloudflare" ]]; then
    [[ -n "$token" ]] || die "Cloudflare mode selected but API token is empty."
    issue_cert_cloudflare "$domain" "$email" "$token"
  else
    issue_cert_manual "$domain"
  fi

  write_nginx_site_conf "$domain" "$port"
  enable_nginx_site "$domain"
  reload_nginx_safe "$domain"

  if [[ "$mode" == "cloudflare" ]]; then
    ensure_certbot_renewal "$domain"
  else
    warn "Manual mode: renewal is NOT automatic. Re-run certbot certonly --manual --preferred-challenges dns -d ${domain} before expiry."
  fi
}

echo "${C_BOLD}========================================${C_RESET}"
echo "${C_BOLD}  node-socketio-chatroom Installer${C_RESET} ${C_DIM}v${INSTALLER_VERSION} (${INSTALLER_BUILD_DATE})${C_RESET}"
echo "${C_BOLD}========================================${C_RESET}"
echo ""
echo ""

log "System:  $(os_pretty) | kernel: $(uname -r) | arch: $(uname -m)"
PUBLIC_IP="$(get_ip)"
log "Host:    $(hostname 2>/dev/null || echo '?') | user: $(id -un 2>/dev/null || echo '?') | ip: ${PUBLIC_IP}"
echo ""

log "Tooling versions (if present):"
show_versions_if_present
echo ""

require_sudo

# حداقل پیش‌نیازها برای تست اینترنت
need_apt_update=1
apt_update_if_needed
apt_install_if_missing ca-certificates update-ca-certificates
apt_install_if_missing curl curl

# Refresh installer metadata now that curl is available
INSTALLER_VERSION="$(fetch_installer_version || echo "unknown")"
INSTALLER_BUILD_DATE="$(fetch_installer_build_date || date -u +%Y-%m-%d)"

echo "${C_BOLD}========================================${C_RESET}"
echo "${C_BOLD}  node-socketio-chatroom Installer${C_RESET} ${C_DIM}v${INSTALLER_VERSION} (${INSTALLER_BUILD_DATE})${C_RESET}"
echo "${C_BOLD}========================================${C_RESET}"
echo ""

check_internet
echo ""

echo "Please configure your chat server:"
echo ""

read -r -p "Install directory [default: ${DIR_DEFAULT}]: " INPUT_DIR
DIR="${INPUT_DIR:-$DIR_DEFAULT}"

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

# ---- HTTPS (Nginx + Let's Encrypt) questions (DNS-01 only) ----
ENABLE_HTTPS=1
if confirm_yn_default_yes "Enable HTTPS now?"; then
  ENABLE_HTTPS=1
else
  ENABLE_HTTPS=0
fi

DOMAIN_FQDN=""
EMAIL=""
DNS_MODE=""
CF_API_TOKEN=""
CF_ZONE_NAME=""

if [[ "$ENABLE_HTTPS" -eq 1 ]]; then
  while true; do
    read -r -p "DOMAIN_FQDN (e.g. subdomain.example.com): " DOMAIN_FQDN
    DOMAIN_FQDN="${DOMAIN_FQDN,,}"
    if validate_fqdn "$DOMAIN_FQDN"; then
      break
    fi
    echo "Invalid FQDN format. Try again."
  done

  while true; do
    read -r -p "Let's Encrypt Email (for expiry/security notices): " EMAIL
    EMAIL="${EMAIL,,}"
    if validate_email_loose "$EMAIL"; then
      break
    fi
    echo "Invalid email. Try again."
  done

  echo ""
  echo "DNS-01 Validation Mode (HTTP-01 is NOT used). Choose one:"
  echo "1) Auto Cloudflare DNS mode (recommended, auto-renewing)"
  echo "2) Manual DNS mode (NOT auto-renewing; you must renew manually)"
  read -r -p "Enter number [1-2]: " DNS_CHOICE

  case "${DNS_CHOICE:-1}" in
    1)
      DNS_MODE="cloudflare"
      echo ""
      echo "Cloudflare API token needs permission: Zone:DNS:Edit (scoped to the zone)."
      read_secret "Cloudflare API Token (hidden input)" CF_API_TOKEN
      read -r -p "Cloudflare Zone Name (e.g. hypersentry.shop) [leave empty to auto-detect]: " CF_ZONE_NAME
      CF_ZONE_NAME="${CF_ZONE_NAME,,}"
      ;;
    2)
      DNS_MODE="manual"
      warn "Manual DNS mode selected. Renewal will be MANUAL (no automatic renew)."
      ;;
    *)
      DNS_MODE="cloudflare"
      echo ""
      echo "Cloudflare API token needs permission: Zone:DNS:Edit (scoped to the zone)."
      read_secret "Cloudflare API Token (hidden input)" CF_API_TOKEN
      read -r -p "Cloudflare Zone Name (e.g. hypersentry.shop) [leave empty to auto-detect]: " CF_ZONE_NAME
      CF_ZONE_NAME="${CF_ZONE_NAME,,}"
      ;;
  esac
fi

# If directory already has an installation but port is free (service stopped), still offer update/preserve flow
if [[ -d "$DIR" && -d "$DIR/data" ]] && detect_app_entry "$DIR" >/dev/null 2>&1; then
  warn "Existing installation directory detected: $DIR"
  echo ""
  echo "Do you want to DELETE ALL DATA? (users/messages/uploads/config)"
  echo " - YES  => full reinstall (data will be removed)"
  echo " - NO   => update code only (data will be preserved)"
  echo ""

  if confirm_yn_default_yes "Delete ALL DATA and reinstall from scratch?"; then
    warn "User chose FULL WIPE."
    warn "Creating tar backup..."
    btar="$(make_backup_tar "$DIR" || true)"
    [[ -n "$btar" ]] && ok "Backup created: $btar" || warn "Backup failed/skipped (continuing)."

    warn "Removing old directory safely: $DIR"
    safe_rm_dir "$DIR" || die "Refusing to delete unsafe path: $DIR"

    ok "Old instance removed. Continuing FULL installation..."
  else
    warn "User chose PRESERVE DATA (safe update)."

    merge_update_preserve_data "$DIR"

    ok "Installing dependencies..."
    cd "$DIR"

    # Find npm/pm2 locally (do not rely on global NPM_BIN/PM2_BIN here)
    NPM_BIN_LOCAL="$(find_npm_bin)"
    PM2_BIN_LOCAL="$(find_pm2_bin)"

    "$NPM_BIN_LOCAL" config set fund false >/dev/null 2>&1 || true
    "$NPM_BIN_LOCAL" config set audit false >/dev/null 2>&1 || true
    if [[ -f package-lock.json ]]; then
      "$NPM_BIN_LOCAL" ci --omit=dev
    else
      "$NPM_BIN_LOCAL" install --omit=dev
    fi

    # If process exists -> restart; otherwise -> start
    ok "Restarting PM2..."
    PM2_NAME="${APP_NAME_VAL}"

    APP_ENTRY="$(detect_app_entry "$DIR")" || die "Could not find app entrypoint (server.js or src/server.js or package.json main)."

    # restart does NOT change script path; delete+start does.
    "$PM2_BIN_LOCAL" delete "$PM2_NAME" >/dev/null 2>&1 || true
    "$PM2_BIN_LOCAL" start "$APP_ENTRY" --name "$PM2_NAME" --update-env --cwd "$DIR"
    "$PM2_BIN_LOCAL" save

    # ---- Optional: enable HTTPS via Nginx + Let's Encrypt (DNS-01) ----
    if [[ "${ENABLE_HTTPS:-0}" -eq 1 ]]; then
      log "Configuring HTTPS for: ${DOMAIN_FQDN} (mode: ${DNS_MODE})"
      setup_https_nginx "$DOMAIN_FQDN" "$EMAIL" "$DNS_MODE" "${CF_API_TOKEN:-}" "$PORT"
      ok "HTTPS configured for: https://${DOMAIN_FQDN}"
    fi

    ok "Update complete (data preserved)."
    exit 0
  fi
fi

# Validations
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && (( PORT >= 1 && PORT <= 65535 )) || { die "Invalid port"; }

if port_in_use "$PORT"; then
  pid="$(get_listener_pid "$PORT")"
  cmd="$(pid_cmdline "$pid")"

  warn "Port $PORT is already in use."
  [[ -n "$pid" ]] && warn "Listener PID: $pid"
  [[ -n "$cmd" ]] && warn "Listener CMD: $cmd"

    # تشخیص "مال ما" (اگر cmdline شامل entrypoint این پروژه باشد: server.js یا src/server.js)
    if [[ -n "$pid" ]] && is_our_listener "$pid" "$DIR"; then
    warn "It looks like this port is used by an existing instance of this chatroom in: $DIR"
    echo "Replace will:"
    echo " - Stop PM2 process (if exists): $APP_NAME_VAL"
    echo " - Stop listener on port: $PORT"
    echo " - Backup directory as: $DIR.backup-*.tar.gz"
    echo " - Remove old directory: $DIR"
    echo ""

    if confirm_yn_default_yes "Detected existing installation in $DIR. Continue and UPDATE it?"; then
      ok "User confirmed update."

      # 1) Stop PM2 process (safe)
      if have_cmd pm2; then
        warn "Stopping PM2 process (if exists): $APP_NAME_VAL"
        pm2 stop "$APP_NAME_VAL" >/dev/null 2>&1 || true
      fi

      # 2) Stop listener PID (only because we already validated it's ours)
      new_pid="$(get_listener_pid "$PORT")"
      if [[ -n "$new_pid" && "$new_pid" != "$pid" ]]; then
        die "Listener PID changed (was $pid, now $new_pid). Refusing to kill for safety."
      fi
      warn "Stopping listener on port $PORT (PID: $pid)"
      kill_listener_pid "$pid"

      echo ""
      echo "Existing installation detected."
      echo "Do you want to DELETE ALL DATA? (users/messages/uploads/config)"
      echo " - YES  => full reinstall (data will be removed)"
      echo " - NO   => update code only (data will be preserved)"
      echo ""

      if confirm_yn_default_yes "Delete ALL DATA and reinstall from scratch?"; then
        warn "User chose FULL WIPE."
        warn "Creating tar backup..."
        btar="$(make_backup_tar "$DIR" || true)"
        [[ -n "$btar" ]] && ok "Backup created: $btar" || warn "Backup failed/skipped (continuing)."

        warn "Removing old directory safely: $DIR"
        safe_rm_dir "$DIR" || die "Refusing to delete unsafe path: $DIR"

        ok "Old instance removed. Continuing FULL installation..."
      else
        warn "User chose PRESERVE DATA (safe update)."

        # Update code only, keep data/ and uploads
        merge_update_preserve_data "$DIR"

        ok "Installing dependencies..."
        cd "$DIR"

        # Find npm/pm2 locally (do not rely on global NPM_BIN/PM2_BIN here)
        NPM_BIN_LOCAL="$(find_npm_bin)"
        PM2_BIN_LOCAL="$(find_pm2_bin)"

        "$NPM_BIN_LOCAL" config set fund false >/dev/null 2>&1 || true
        "$NPM_BIN_LOCAL" config set audit false >/dev/null 2>&1 || true
        if [[ -f package-lock.json ]]; then
          "$NPM_BIN_LOCAL" ci --omit=dev
        else
          "$NPM_BIN_LOCAL" install --omit=dev
        fi

        ok "Restarting PM2..."
        PM2_NAME="${APP_NAME_VAL}"

        APP_ENTRY="$(detect_app_entry "$DIR")" || die "Could not find app entrypoint (server.js or src/server.js or package.json main)."

        # restart does NOT change script path; delete+start does.
        "$PM2_BIN_LOCAL" delete "$PM2_NAME" >/dev/null 2>&1 || true
        "$PM2_BIN_LOCAL" start "$APP_ENTRY" --name "$PM2_NAME" --update-env --cwd "$DIR"
        "$PM2_BIN_LOCAL" save

        # ---- Optional: enable HTTPS via Nginx + Let's Encrypt (DNS-01) ----
        if [[ "${ENABLE_HTTPS:-0}" -eq 1 ]]; then
          log "Configuring HTTPS for: ${DOMAIN_FQDN} (mode: ${DNS_MODE})"
          setup_https_nginx "$DOMAIN_FQDN" "$EMAIL" "$DNS_MODE" "${CF_API_TOKEN:-}" "$PORT"
          ok "HTTPS configured for: https://${DOMAIN_FQDN}"
        fi

        ok "Update complete (data preserved)."
        echo ""
        ok "Done. You can refresh the browser."
        exit 0
      fi
    else
      die "Canceled by user. Please choose another port or stop the conflicting service."
    fi
  else
    die "Port $PORT is already in use by another service. Choose another port or stop the conflicting service."
  fi
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


echo "[2/6] Checking system deps..."

apt_install_if_missing git git
apt_install_if_missing rsync rsync

echo "[3/6] Installing Node.js & PM2..."

# نصب Node.js (NodeSource)
if ! have_cmd node; then
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
  need_apt_update=1
  apt_update_if_needed
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
  die "npm not found (even after installing npm). Try: sudo apt-get install -y nodejs npm"
fi

# Install pm2 only if missing
if ! have_cmd pm2; then
  sudo "$NPM_BIN" install -g pm2
fi

PM2_BIN=""
for p in /usr/bin/pm2 /usr/local/bin/pm2 /bin/pm2; do
  if [[ -x "$p" ]]; then PM2_BIN="$p"; break; fi
done
if [[ -z "$PM2_BIN" ]]; then
  PM2_BIN="$(command -v pm2 2>/dev/null || true)"
fi
if [[ -z "$PM2_BIN" ]]; then
  die "pm2 not found after installation. Try: sudo npm install -g pm2"
fi

node -v
"$NPM_BIN" -v
"$PM2_BIN" -v

echo "[4/6] Creating project files in $DIR..."

mkdir -p "$DIR"
if [[ -n "$(ls -A "$DIR" 2>/dev/null || true)" ]]; then
  warn "Install directory is not empty: $DIR"
  warn "Existing files may be overwritten."
fi

mkdir -p "$DIR/public" "$DIR/data" "$DIR/public/uploads"
chmod 700 "$DIR/data" "$DIR/public/uploads"
cd "$DIR"

cat > package.json << 'EOF'
{
  "name": "node-socketio-chatroom",
  "version": "1.1.16",
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

# server.js (same features, hardened)
cat > server.js << 'EOF'
'use strict';

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const xss = require('xss');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
const server = http.createServer(app);

// -------------------- Security headers --------------------
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: false
}));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

app.use(express.json({ limit: '10kb' }));

// -------------------- Paths --------------------
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'public/uploads');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true, mode: 0o700 });

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const CHANNELS_FILE = path.join(DATA_DIR, 'channels.json');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');

const CONVERSATIONS_FILE = path.join(DATA_DIR, 'conversations.json');
const MEMBERSHIPS_FILE   = path.join(DATA_DIR, 'memberships.json');
const ATTACHMENTS_FILE   = path.join(DATA_DIR, 'attachments.json');


function readJsonSafe(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function atomicWriteJson(file, obj, mode = 0o600) {
  const tmp = file + '.' + crypto.randomBytes(6).toString('hex') + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), { mode });
  fs.renameSync(tmp, file);
  try { fs.chmodSync(file, mode); } catch {}
}

// -------------------- Data-at-rest encryption (AES-256-GCM) --------------------
function keyFromHex(hex) {
  try {
    const h = String(hex || '').trim();
    if (!h) return null;
    const buf = Buffer.from(h, 'hex');
    return buf.length === 32 ? buf : null;
  } catch {
    return null;
  }
}

function encryptPayload(key, obj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 1,
    alg: 'A256GCM',
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    data: enc.toString('base64')
  };
}

function decryptPayload(key, wrapper) {
  const iv = Buffer.from(String(wrapper.iv || ''), 'base64');
  const tag = Buffer.from(String(wrapper.tag || ''), 'base64');
  const data = Buffer.from(String(wrapper.data || ''), 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return JSON.parse(dec.toString('utf8'));
}

function isEncryptedWrapper(obj) {
  return !!(obj && typeof obj === 'object' && obj.v === 1 && obj.alg === 'A256GCM' && obj.iv && obj.tag && obj.data);
}

function readJsonSecure(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    const raw = fs.readFileSync(file, 'utf8');
    if (!raw) return fallback;

    const parsed = JSON.parse(raw);

    const key = keyFromHex(appConfig.dataEncKey);
    if (key && isEncryptedWrapper(parsed)) return decryptPayload(key, parsed);

    return parsed;
  } catch {
    return fallback;
  }
}

function atomicWriteJsonSecure(file, obj, mode = 0o600) {
  const key = keyFromHex(appConfig.dataEncKey);
  const payload = key ? encryptPayload(key, obj) : obj;
  atomicWriteJson(file, payload, mode);
}

// -------------------- Config --------------------
let appConfig = {
  adminUser: 'admin',
  adminPassHash: '',
  port: 3000,
  maxFileSizeMB: 50,
  appName: 'node-socketio-chatroom',
  hideUserList: false,
  allowedOrigins: '*',
  protectUploads: true,
  dataEncKey: '',
  // ✅ NEW: channel access policy
  accessMode: 'restricted', // 'restricted' | 'open'
  defaultChannelsForNewUsers: [] // e.g. ['General'] if you want
};

function normalizeOrigins(val) {
  if (val === '*' || val === undefined || val === null) return '*';
  if (Array.isArray(val)) return val.map(s => String(s).trim()).filter(Boolean);
  const s = String(val).trim();
  if (!s) return '*';
  if (s === '*') return '*';
  return s.split(',').map(x => x.trim()).filter(Boolean);
}

let lastConfigMtimeMs = 0;

function loadAndSecureConfig(force = false) {
  try {
    let stat;
    try { stat = fs.statSync(CONFIG_FILE); } catch { stat = null; }

    const mtimeMs = stat ? stat.mtimeMs : 0;
    if (!force && mtimeMs && mtimeMs === lastConfigMtimeMs) return false;

    let saveNeeded = false;
    const fileConfig = readJsonSafe(CONFIG_FILE, null);

    if (fileConfig) appConfig = { ...appConfig, ...fileConfig };
    else saveNeeded = true;

    if (appConfig.adminPass && !appConfig.adminPassHash) {
      appConfig.adminPassHash = bcrypt.hashSync(String(appConfig.adminPass), 12);
      delete appConfig.adminPass;
      saveNeeded = true;
    }

    if (appConfig.adminPassHash && !String(appConfig.adminPassHash).startsWith('$2')) {
      appConfig.adminPassHash = bcrypt.hashSync(String(appConfig.adminPassHash), 12);
      saveNeeded = true;
    }

    appConfig.allowedOrigins = normalizeOrigins(appConfig.allowedOrigins);

    if (!['restricted', 'open'].includes(String(appConfig.accessMode || 'restricted'))) {
      appConfig.accessMode = 'restricted';
      saveNeeded = true;
    }
    if (!Array.isArray(appConfig.defaultChannelsForNewUsers)) {
      appConfig.defaultChannelsForNewUsers = [];
      saveNeeded = true;
    }

    if (saveNeeded) atomicWriteJson(CONFIG_FILE, appConfig, 0o600);

    try {
      const st2 = fs.statSync(CONFIG_FILE);
      lastConfigMtimeMs = st2.mtimeMs;
    } catch {
      lastConfigMtimeMs = mtimeMs || 0;
    }

    return true;
  } catch (e) {
    console.error('Error loading config:', e);
    return false;
  }
}

loadAndSecureConfig(true);

const PORT = (() => {
  const raw = (process.env.PORT ?? appConfig.port ?? 3000);
  const p = parseInt(String(raw), 10);
  return Number.isFinite(p) && p >= 1 && p <= 65535 ? p : 3000;
})();

// -------------------- Socket.io --------------------
const corsOption = (() => {
  const origins = appConfig.allowedOrigins;
  if (origins === '*') return { origin: '*', methods: ['GET', 'POST'] };

  return {
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      return origins.includes(origin) ? cb(null, true) : cb(null, false);
    },
    methods: ['GET', 'POST']
  };
})();

const io = new Server(server, {
  maxHttpBufferSize: 1e8,
  cors: corsOption
});

// -------------------- In-memory state --------------------
let users = {};
let persistentUsers = {};
let channels = ['General', 'Random'];

let messages = {};
let userRateLimits = {};

let conversations = {};
let memberships = {};
let attachments = {};


// upload auth: token -> expiry
const uploadTokens = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [t, v] of uploadTokens.entries()) {
    if (!v || v.exp <= now) uploadTokens.delete(t);
  }
}, 60_000).unref();

// Load data
persistentUsers = readJsonSecure(USERS_FILE, {});
channels = readJsonSecure(CHANNELS_FILE, channels);
messages = readJsonSecure(MESSAGES_FILE, {});
conversations = readJsonSecure(CONVERSATIONS_FILE, {});
memberships = readJsonSecure(MEMBERSHIPS_FILE, {});
attachments = readJsonSecure(ATTACHMENTS_FILE, {});

// -------------------- Helpers --------------------
function cleanUsername(username) {
  return xss(String(username || '').trim()).substring(0, 20);
}
function cleanText(text, max = 1000) {
  const s = xss(String(text || ''));
  return s.length > max ? s.substring(0, max) : s;
}
function cleanChannelName(name) {
  return xss(String(name || '').trim()).substring(0, 30);
}

function ensureConversationMaps(conversationId) {
  if (!memberships[conversationId]) memberships[conversationId] = {};
  if (!messages[conversationId]) messages[conversationId] = [];
}

function isMember(conversationId, username) {
  return !!(memberships[conversationId] && memberships[conversationId][username]);
}

function addMember(conversationId, username, role = 'member') {
  ensureConversationMaps(conversationId);
  if (!memberships[conversationId][username]) {
    memberships[conversationId][username] = { role, joinedAt: Date.now(), lastReadMessageId: null };
  }
}

function removeMember(conversationId, username) {
  if (!memberships[conversationId]) return;
  delete memberships[conversationId][username];
}

function ensurePublicConversation(channelName, createdBy = 'system') {
  const id = channelName;
  if (!conversations[id]) {
    conversations[id] = {
      id,
      type: 'public',
      title: channelName,
      isHidden: false,
      createdBy,
      createdAt: Date.now()
    };
  }
  ensureConversationMaps(id);
  return conversations[id];
}

function dmKeyFor(u1, u2) {
  const a = String(u1 || '').trim();
  const b = String(u2 || '').trim();
  return [a, b].sort().join('_pv_');
}

function getOrCreateDMConversation(u1, u2) {
  const key = dmKeyFor(u1, u2);
  if (!conversations[key]) {
    conversations[key] = {
      id: key,
      type: 'dm',
      title: `DM: ${u1}, ${u2}`,
      isHidden: true,
      dmKey: key,
      createdBy: u1,
      createdAt: Date.now()
    };
    ensureConversationMaps(key);
  }
  addMember(key, u1, 'owner');
  addMember(key, u2, 'member');
  return conversations[key];
}

function isValidDMId(dmId) {
  if (!dmId || typeof dmId !== 'string') return false;
  if (!dmId.includes('_pv_')) return false;
  const parts = dmId.split('_pv_').map(x => x.trim()).filter(Boolean);
  return parts.length === 2 && parts[0] !== parts[1];
}

function dmParticipants(dmId) {
  const parts = String(dmId || '').split('_pv_').map(x => x.trim());
  if (parts.length !== 2) return null;
  return { a: parts[0], b: parts[1] };
}

function canAccessDM(user, dmId) {
  if (!user) return false;
  if (!isValidDMId(dmId)) return false;
  const p = dmParticipants(dmId);
  if (!p) return false;
  return user.username === p.a || user.username === p.b;
}

function savedConvIdFor(username) {
  return `__saved__${String(username || '').trim()}`;
}

function isSavedConvId(convId) {
  return typeof convId === 'string' && convId.startsWith('__saved__');
}

// ✅ NEW: access checks
function canAccessChannel(username, role, channelName) {
  const ch = String(channelName || '').trim();
  if (!ch) return false;
  if (role === 'admin') return true;

  // open mode: all users can access public channels
  if (appConfig.accessMode === 'open') return true;

  // restricted: must be explicitly member
  return isMember(ch, username);
}

function listAccessibleChannels(username, role) {
  if (role === 'admin') return [...channels];
  if (appConfig.accessMode === 'open') return [...channels];
  // restricted
  return channels.filter(ch => isMember(ch, username));
}

function saveData() {
  try {
    atomicWriteJsonSecure(USERS_FILE, persistentUsers, 0o600);
    atomicWriteJsonSecure(CHANNELS_FILE, channels, 0o600);
    atomicWriteJsonSecure(MESSAGES_FILE, messages, 0o600);
    atomicWriteJsonSecure(CONVERSATIONS_FILE, conversations, 0o600);
    atomicWriteJsonSecure(MEMBERSHIPS_FILE, memberships, 0o600);
    atomicWriteJsonSecure(ATTACHMENTS_FILE, attachments, 0o600);
  } catch (e) {
    console.error('Error saving data', e);
  }
}
setInterval(saveData, 30_000).unref();

// migrate users plaintext -> hash (backward compat)
(function migrateUsersIfNeeded() {
  let changed = false;
  for (const [u, data] of Object.entries(persistentUsers)) {
    if (!data) continue;

    if (data.password && !data.passHash) {
      data.passHash = bcrypt.hashSync(String(data.password), 12);
      delete data.password;
      changed = true;
    }
    if (data.passHash && !String(data.passHash).startsWith('$2')) {
      data.passHash = bcrypt.hashSync(String(data.passHash), 12);
      changed = true;
    }
  }
  if (changed) saveData();
})();

// ensure default channels have public conversations
(function ensureDefaults() {
  for (const ch of channels) ensurePublicConversation(ch, 'system');
  saveData();
})();

// -------------------- Upload --------------------
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many uploads from this IP, please try again later'
});

const allowedMimes = new Set([
  'image/jpeg', 'image/png', 'image/gif', 'image/webp',
  'audio/webm', 'audio/mpeg',
  'video/mp4', 'video/webm',
  'application/pdf', 'text/plain'
]);

const allowedExt = new Set([
  '.jpg', '.jpeg', '.png', '.gif', '.webp',
  '.webm', '.mp3', '.mp4', '.pdf', '.txt'
]);

function safeExt(originalname) {
  const ext = path.extname(String(originalname || '')).toLowerCase();
  return allowedExt.has(ext) ? ext : '';
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
  filename: (_req, file, cb) => {
    const ext = safeExt(file.originalname);
    const name = crypto.randomBytes(16).toString('hex') + ext;
    cb(null, name);
  }
});

let uploadSingle = null;
let lastUploadLimitBytes = 0;

function rebuildUploadMiddleware() {
  const limitBytes = Number(appConfig.maxFileSizeMB || 50) * 1024 * 1024;
  if (uploadSingle && limitBytes === lastUploadLimitBytes) return;

  lastUploadLimitBytes = limitBytes;

  const upload = multer({
    storage,
    limits: { fileSize: limitBytes },
    fileFilter: (_req, file, cb) => {
      if (!allowedMimes.has(file.mimetype)) return cb(new Error('DISALLOWED_MIME'));
      if (!safeExt(file.originalname)) return cb(new Error('DISALLOWED_EXT'));
      cb(null, true);
    }
  });

  uploadSingle = upload.single('file');
}

rebuildUploadMiddleware();

setInterval(() => {
  const changed = loadAndSecureConfig(false);
  if (changed) rebuildUploadMiddleware();
}, 5000).unref();

// Protect downloads if enabled
app.use('/uploads', (req, res, next) => {
  if (!appConfig.protectUploads) return next();

  const tok = String(req.headers['x-upload-token'] || req.query.t || '');
  const rec = uploadTokens.get(tok);
  if (!rec || rec.exp <= Date.now()) return res.status(401).send('Unauthorized');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

app.post('/upload', uploadLimiter, (req, res) => {
  const tok = String(req.headers['x-upload-token'] || '');
  const rec = uploadTokens.get(tok);
  if (!rec || rec.exp <= Date.now()) return res.status(401).json({ error: 'Unauthorized upload.' });

  if (!uploadSingle) rebuildUploadMiddleware();

  uploadSingle(req, res, function (err) {
    if (err instanceof multer.MulterError) return res.status(400).json({ error: 'File too large or upload error.' });
    if (err) return res.status(400).json({ error: 'File type not allowed.' });
    if (!req.file) return res.status(400).json({ error: 'No file sent.' });

    const cleanOriginal = xss(String(req.file.originalname || '')).substring(0, 120);
    res.json({ url: '/uploads/' + req.file.filename, filename: cleanOriginal, size: req.file.size, mimetype: req.file.mimetype });
  });
});

// -------------------- Online users list --------------------
function getUniqueOnlineUsers() {
  const unique = {};
  Object.values(users).forEach(u => { unique[u.username] = u; });
  return Object.values(unique);
}

function broadcastUserList() {
  const allUsers = getUniqueOnlineUsers();
  const admins = allUsers.filter(u => u.role === 'admin');

  io.sockets.sockets.forEach((socket) => {
    const user = users[socket.id];
    if (!user) return;

    if (user.role === 'admin') socket.emit('user_list', allUsers);
    else {
      if (appConfig.hideUserList) {
        const visible = [...admins];
        if (!visible.find(a => a.username === user.username)) visible.push(user);
        socket.emit('user_list', visible);
      } else {
        socket.emit('user_list', allUsers);
      }
    }
  });
}

function getBannedUsers() {
  return Object.keys(persistentUsers).filter(u => persistentUsers[u]?.isBanned);
}

// -------------------- Login rate limit --------------------
const loginAttempts = new Map();

function getSocketIp(socket) {
  const xf = socket.handshake.headers['x-forwarded-for'];
  if (xf && typeof xf === 'string') return xf.split(',')[0].trim();
  return String(socket.handshake.address || '').trim() || 'unknown';
}

function loginKey(ip, username) {
  return `${ip}::${String(username || '').toLowerCase()}`;
}

function isLoginLimited(ip, username) {
  const key = loginKey(ip, username);
  const now = Date.now();
  const rec = loginAttempts.get(key);

  const windowMs = 10 * 60 * 1000;
  const max = 12;

  if (!rec) return false;

  if (now - rec.first > windowMs) {
    loginAttempts.delete(key);
    return false;
  }

  return rec.count >= max;
}

function recordLoginFail(ip, username) {
  const key = loginKey(ip, username);
  const now = Date.now();
  const rec = loginAttempts.get(key);

  if (!rec) {
    loginAttempts.set(key, { count: 1, first: now, last: now });
    return;
  }

  rec.count += 1;
  rec.last = now;
  loginAttempts.set(key, rec);
}

function clearLoginFails(ip, username) {
  loginAttempts.delete(loginKey(ip, username));
}

setInterval(() => {
  const now = Date.now();
  const windowMs = 10 * 60 * 1000;
  for (const [k, v] of loginAttempts.entries()) {
    if (!v || (now - v.first > windowMs)) loginAttempts.delete(k);
  }
}, 60_000).unref();

// -------------------- Socket events --------------------
io.on('connection', (socket) => {

  // ✅ safe channel join (enforced access)
  function joinChannelCompat(sock, channelName) {
    const user = users[sock.id];
    if (!user) return;

    const clean = cleanChannelName(channelName);
    if (!clean) return;

    // channel must exist
    if (!channels.includes(clean)) return sock.emit('error', 'کانال وجود ندارد.');

    // enforce access
    if (!canAccessChannel(user.username, user.role, clean)) {
      return sock.emit('access_denied', { channel: clean, message: 'شما به این کانال دسترسی ندارید.' });
    }

    ensurePublicConversation(clean, 'system');
    addMember(clean, user.username, 'member');

    sock.join(clean);
    sock.emit('channel_joined', { name: clean, isPrivate: false });
    sock.emit('history', Array.isArray(messages[clean]) ? messages[clean] : []);
  }

    socket.on('join_saved', () => {
    const user = users[socket.id];
    if (!user) return;

    const sid = savedConvIdFor(user.username);
    ensureConversationMaps(sid);

    // اینجا room = sid
    socket.join(sid);

    socket.emit('channel_joined', { name: sid, isPrivate: true, isSaved: true });
    socket.emit('history', Array.isArray(messages[sid]) ? messages[sid] : []);
    });

  function emitAccessSnapshotToAdmin(adminSocket) {
    const u = users[adminSocket.id];
    if (!u || u.role !== 'admin') return;

    const result = {};
    for (const uname of Object.keys(persistentUsers)) {
      result[uname] = {};
      for (const ch of channels) {
        result[uname][ch] = isMember(ch, uname);
      }
    }
    adminSocket.emit('admin_access_snapshot', { channels, map: result });
  }

  socket.on('login', ({ username, password }) => {
    loadAndSecureConfig();

    const ip = getSocketIp(socket);

    const u = cleanUsername(username);
    const p = String(password || '');
    if (isLoginLimited(ip, u)) return socket.emit('login_error', 'تلاش‌های ورود زیاد است. چند دقیقه بعد دوباره امتحان کنید.');
    if (!u || !p) { recordLoginFail(ip, u || ''); return socket.emit('login_error', 'نام کاربری و رمز عبور الزامی است'); }

    // Admin login
    if (u === appConfig.adminUser) {
      const ok = appConfig.adminPassHash && bcrypt.compareSync(p, appConfig.adminPassHash);
      if (!ok) { recordLoginFail(ip, u); return socket.emit('login_error', 'رمز عبور ادمین اشتباه است.'); }

      clearLoginFails(ip, u);
      users[socket.id] = { username: u, role: 'admin' };

      const uploadToken = crypto.randomBytes(24).toString('hex');
      uploadTokens.set(uploadToken, { username: u, exp: Date.now() + 6 * 60 * 60 * 1000 });

      for (const ch of channels) ensurePublicConversation(ch, 'system');

      // admin always member to all channels in restricted mode
      if (appConfig.accessMode === 'restricted') {
        for (const ch of channels) addMember(ch, u, 'owner');
      }

      socket.emit('login_success', {
        username: u,
        role: 'admin',
        channels: [...channels],
        settings: {
          maxFileSizeMB: appConfig.maxFileSizeMB,
          appName: appConfig.appName,
          hideUserList: appConfig.hideUserList,
          accessMode: appConfig.accessMode
        },
        uploadToken
      });

      // auto-join General if exists
      if (channels.includes('General')) joinChannelCompat(socket, 'General');

      broadcastUserList();
      emitAccessSnapshotToAdmin(socket);
      return;
    }

    // Normal user login/register
    const existing = persistentUsers[u];
    if (existing) {
      if (existing.isBanned) { recordLoginFail(ip, u); return socket.emit('login_error', 'حساب کاربری شما مسدود شده است.'); }
      if (!existing.passHash || !bcrypt.compareSync(p, existing.passHash)) { recordLoginFail(ip, u); return socket.emit('login_error', 'رمز عبور اشتباه است.'); }
    } else {
      persistentUsers[u] = {
        passHash: bcrypt.hashSync(p, 12),
        role: 'user',
        isBanned: false,
        created_at: Date.now()
      };

      // ✅ optional: default channels for new users
      if (appConfig.accessMode === 'restricted' && Array.isArray(appConfig.defaultChannelsForNewUsers)) {
        for (const ch of appConfig.defaultChannelsForNewUsers) {
          const cleanCh = cleanChannelName(ch);
          if (cleanCh && channels.includes(cleanCh)) addMember(cleanCh, u, 'member');
        }
      }
    }

    clearLoginFails(ip, u);
    persistentUsers[u].last_seen = Date.now();

    const role = persistentUsers[u].role || 'user';
    users[socket.id] = { username: u, role };

    const uploadToken = crypto.randomBytes(24).toString('hex');
    uploadTokens.set(uploadToken, { username: u, exp: Date.now() + 6 * 60 * 60 * 1000 });

    for (const ch of channels) ensurePublicConversation(ch, 'system');

    const accessible = listAccessibleChannels(u, role);

    socket.emit('login_success', {
      username: u,
      role,
      channels: accessible,
      settings: {
        maxFileSizeMB: appConfig.maxFileSizeMB,
        appName: appConfig.appName,
        hideUserList: appConfig.hideUserList,
        accessMode: appConfig.accessMode
      },
      uploadToken
    });

    // auto-join first accessible channel (if any)
    if (accessible.length > 0) joinChannelCompat(socket, accessible[0]);

    saveData();
    broadcastUserList();
  });

  socket.on('join_channel', (channel) => {
    joinChannelCompat(socket, channel);
  });

socket.on('join_private', (targetUser, cb) => {
  const currentUser = users[socket.id];
  if (!currentUser) return;

  const cleanTarget = cleanUsername(targetUser);
  if (!cleanTarget || cleanTarget === currentUser.username) {
    if (typeof cb === 'function') cb({ ok: false, error: 'INVALID_TARGET' });
    return;
  }

  // ✅ اجازه DM به ادمین حتی اگر داخل users.json نباشد
  const isAdminTarget = cleanTarget === appConfig.adminUser;

  // ✅ یا کاربر ثبت‌نام‌شده باشد و بن نشده باشد
  const isRegisteredTarget = !!persistentUsers[cleanTarget] && !persistentUsers[cleanTarget]?.isBanned;

  if (!isAdminTarget && !isRegisteredTarget) {
    if (typeof cb === 'function') cb({ ok: false, error: 'TARGET_NOT_FOUND' });
    return;
  }

  const dm = getOrCreateDMConversation(currentUser.username, cleanTarget);

  for (const r of socket.rooms) {
    if (r !== socket.id) socket.leave(r);
  }

  socket.join(dm.id);

  if (typeof cb === 'function') cb({ ok: true, dmId: dm.id });

  socket.emit('channel_joined', { name: dm.id, isPrivate: true, isSaved: false });
  socket.emit('history', Array.isArray(messages[dm.id]) ? messages[dm.id] : []);
});

  // -------------------- Saved Messages --------------------
  socket.on('saved_delete', (msgId) => {
  const user = users[socket.id];
  if (!user) return;

  const sid = savedConvIdFor(user.username);
  const id = String(msgId || '').trim();
  if (!id) return;

  ensureConversationMaps(sid);

  const before = messages[sid].length;
  messages[sid] = messages[sid].filter(m => m && m.id !== id);

  if (messages[sid].length !== before) {
    io.to(sid).emit('message_deleted', { channel: sid, id });
    saveData();
  }
});

    socket.on('save_message', (payload) => {
    const user = users[socket.id];
    if (!user) return;

    const item = payload && typeof payload === 'object' ? payload : null;
    if (!item) return;

    const originalId = String(item.originalId || item.id || '').trim();
    const from = cleanUsername(item.from || item.sender || '');
    const srcChannel = cleanChannelName(item.channel || item.conversationId || '');
    const type = String(item.type || 'text');
    const text = cleanText(item.text || '', 1000);
    const content = (typeof item.content === 'string') ? item.content : undefined;
    const fileName = item.fileName ? xss(String(item.fileName)).substring(0, 120) : undefined;

    if (!originalId || !from) return;

    const sid = savedConvIdFor(user.username);
    ensureConversationMaps(sid);

    // جلوگیری از duplicate: داخل saved chat دنبال originalId می‌گردیم
    const exists = Array.isArray(messages[sid]) && messages[sid].some(m => m && m.meta && m.meta.originalId === originalId);
    if (exists) return socket.emit('action_success', 'این پیام قبلاً ذخیره شده است.');

    const msg = {
        id: crypto.randomBytes(12).toString('hex'),
        sender: from,              // برای اینکه تو Saved سمت چپ نمایش داده شود
        text,
        type,
        content,
        fileName,
        conversationId: sid,
        channel: sid,
        replyTo: null,
        timestamp: new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }),
        role: 'user',
        meta: {
        saved: true,
        savedBy: user.username,
        originalId,
        originalChannel: srcChannel || '(unknown)',
        originalAt: item.originalAt || null
        }
    };

    messages[sid].push(msg);
    if (messages[sid].length > 1000) messages[sid].shift();

    // اگر الان داخل saved هست همزمان می‌بیند
    io.to(sid).emit('receive_message', msg);

    saveData();
    socket.emit('action_success', 'پیام ذخیره شد ✅');
    });

  // -------------------- Channel management --------------------
  socket.on('create_channel', (channelName) => {
    const user = users[socket.id];
    if (!user || (user.role !== 'admin' && user.role !== 'vip')) return;

    const clean = cleanChannelName(channelName);
    if (!clean) return;

    if (!channels.includes(clean)) channels.push(clean);
    ensurePublicConversation(clean, user.username);

    // creator gets access in restricted mode
    if (appConfig.accessMode === 'restricted') addMember(clean, user.username, 'owner');

    // admin gets access always
    if (appConfig.accessMode === 'restricted') addMember(clean, appConfig.adminUser, 'owner');

    io.emit('update_channels', channels);
    saveData();

    // push filtered channels to each user
    io.sockets.sockets.forEach((s) => {
      const u = users[s.id];
      if (!u) return;
      const list = listAccessibleChannels(u.username, u.role);
      s.emit('channels_list', list);
    });
  });

  socket.on('delete_channel', (channelName) => {
    const user = users[socket.id];
    if (!user || (user.role !== 'admin' && user.role !== 'vip')) return;

    const clean = cleanChannelName(channelName);
    if (!clean || clean === 'General') return;

    channels = channels.filter(c => c !== clean);

    delete conversations[clean];
    delete memberships[clean];
    delete messages[clean];

    io.in(clean).socketsLeave(clean);

    io.emit('update_channels', channels);
    saveData();

    io.sockets.sockets.forEach((s) => {
      const u = users[s.id];
      if (!u) return;
      const list = listAccessibleChannels(u.username, u.role);
      s.emit('channels_list', list);
      // kick UI if user was in deleted channel
      s.emit('channel_deleted', clean);
    });
  });

  socket.on('update_admin_settings', (newSettings) => {
    const user = users[socket.id];
    if (!user || user.role !== 'admin') return;

    if (typeof newSettings?.hideUserList === 'boolean') {
      appConfig.hideUserList = newSettings.hideUserList;
    }
    if (typeof newSettings?.accessMode === 'string' && ['restricted', 'open'].includes(newSettings.accessMode)) {
      appConfig.accessMode = newSettings.accessMode;
    }

    atomicWriteJson(CONFIG_FILE, appConfig, 0o600);

    // refresh channels list for everyone
    io.sockets.sockets.forEach((s) => {
      const u = users[s.id];
      if (!u) return;
      const list = listAccessibleChannels(u.username, u.role);
      s.emit('channels_list', list);
    });

    broadcastUserList();
    socket.emit('action_success', 'تنظیمات با موفقیت ذخیره شد.');
    emitAccessSnapshotToAdmin(socket);
  });

  // ✅ NEW: admin UI events to grant/revoke channel access
  socket.on('admin_get_user_access', (targetUsername) => {
    const actor = users[socket.id];
    if (!actor || actor.role !== 'admin') return;

    const t = cleanUsername(targetUsername);
    if (!t || !persistentUsers[t]) return;

    const map = {};
    for (const ch of channels) map[ch] = isMember(ch, t);

    socket.emit('admin_user_access', { username: t, map, channels });
  });

  socket.on('admin_set_user_access', ({ targetUsername, channel, allow }) => {
    const actor = users[socket.id];
    if (!actor || actor.role !== 'admin') return;

    const t = cleanUsername(targetUsername);
    const ch = cleanChannelName(channel);
    const okAllow = !!allow;

    if (!t || !persistentUsers[t]) return;
    if (!ch || !channels.includes(ch)) return;

    if (okAllow) addMember(ch, t, 'member');
    else removeMember(ch, t);

    saveData();

    // update target user's channels list live (if online)
    const targetSocketIds = Object.keys(users).filter(id => users[id]?.username === t);
    for (const sid of targetSocketIds) {
      const s = io.sockets.sockets.get(sid);
      if (!s) continue;
      const list = listAccessibleChannels(t, users[sid].role);
      s.emit('channels_list', list);

      // if they are currently inside revoked channel -> force leave
      if (!okAllow) {
        s.leave(ch);
        s.emit('access_revoked', { channel: ch, message: 'دسترسی شما به این کانال توسط ادمین برداشته شد.' });
      }
    }

    socket.emit('action_success', `دسترسی ${okAllow ? 'داده شد' : 'برداشته شد'}: ${t} -> ${ch}`);
    socket.emit('admin_user_access', {
      username: t,
      map: Object.fromEntries(channels.map(c => [c, isMember(c, t)])),
      channels
    });
    emitAccessSnapshotToAdmin(socket);
  });

  // -------------------- Moderation --------------------
  socket.on('ban_user', (targetUsername) => {
    const actor = users[socket.id];
    if (!actor || (actor.role !== 'admin' && actor.role !== 'vip')) return;
    if (targetUsername === appConfig.adminUser) return;

    const t = cleanUsername(targetUsername);
    if (!persistentUsers[t]) return;

    persistentUsers[t].isBanned = true;

    for (const key of Object.keys(messages)) {
      if (Array.isArray(messages[key])) messages[key] = messages[key].filter(m => m.sender !== t);
    }

    saveData();
    io.emit('bulk_delete_user', t);

    const targetSockets = Object.keys(users).filter(id => users[id].username === t);
    targetSockets.forEach(id => {
      io.to(id).emit('force_disconnect', 'شما توسط ادمین بن شدید.');
      io.sockets.sockets.get(id)?.disconnect(true);
      delete users[id];
    });

    broadcastUserList();
    socket.emit('action_success', `کاربر ${t} بن شد و پیام‌های او حذف گردید.`);
  });

  socket.on('unban_user', (targetUsername) => {
    const actor = users[socket.id];
    if (!actor || (actor.role !== 'admin' && actor.role !== 'vip')) return;

    const t = cleanUsername(targetUsername);
    if (persistentUsers[t]) {
      persistentUsers[t].isBanned = false;
      saveData();
      socket.emit('action_success', `کاربر ${t} آزاد شد.`);
      socket.emit('banned_list', getBannedUsers());
    }
  });

  socket.on('get_banned_users', () => {
    const actor = users[socket.id];
    if (!actor || (actor.role !== 'admin' && actor.role !== 'vip')) return;
    socket.emit('banned_list', getBannedUsers());
  });

  socket.on('set_role', ({ targetUsername, role }) => {
    const actor = users[socket.id];
    if (!actor || actor.role !== 'admin') return;
    if (targetUsername === appConfig.adminUser) return;

    const t = cleanUsername(targetUsername);
    if (persistentUsers[t] && ['user', 'vip'].includes(role)) {
      persistentUsers[t].role = role;
      saveData();

      const targetSocketId = Object.keys(users).find(id => users[id].username === t);
      if (targetSocketId) {
        users[targetSocketId].role = role;
        io.to(targetSocketId).emit('role_update', role);

        // refresh channels list as role might affect (admin only in our model)
        const s = io.sockets.sockets.get(targetSocketId);
        if (s) s.emit('channels_list', listAccessibleChannels(t, role));
      }

      broadcastUserList();
      socket.emit('action_success', `نقش کاربر ${t} به ${role} تغییر کرد.`);
    }
  });

  // -------------------- Messaging (with access enforcement) --------------------
    socket.on('send_message', (data) => {
    const user = users[socket.id];
    if (!user) return;

    // rate limit
    const now = Date.now();
    if (!userRateLimits[user.username]) userRateLimits[user.username] = { count: 0, last: now };
    if (now - userRateLimits[user.username].last > 5000) userRateLimits[user.username] = { count: 0, last: now };
    if (userRateLimits[user.username].count > 5) return socket.emit('error', 'لطفا آهسته‌تر پیام ارسال کنید.');
    userRateLimits[user.username].count++;

    const conversationId = String(data?.conversationId || '').trim();
    if (!conversationId) return;

    // ✅ Saved Chat
    if (isSavedConvId(conversationId)) {
        const expected = savedConvIdFor(user.username);
        if (conversationId !== expected) {
        return socket.emit('access_denied', { channel: conversationId, message: 'دسترسی به Saved دیگران مجاز نیست.' });
        }
        ensureConversationMaps(conversationId);
    }
    // ✅ DM
    else if (conversationId.includes('_pv_')) {
        if (!isValidDMId(conversationId)) return socket.emit('error', 'گفتگوی خصوصی نامعتبر است.');
        if (!canAccessDM(user, conversationId)) {
        return socket.emit('access_denied', { channel: conversationId, message: 'شما به این گفتگوی خصوصی دسترسی ندارید.' });
        }
        if (!conversations[conversationId]) {
        const p = dmParticipants(conversationId);
        if (!p) return socket.emit('error', 'گفتگوی خصوصی نامعتبر است.');
        getOrCreateDMConversation(p.a, p.b);
        }
    }
    // ✅ Public channel
    else {
        const cleanConv = cleanChannelName(conversationId);
        if (!channels.includes(cleanConv)) return socket.emit('error', 'کانال وجود ندارد.');
        if (!canAccessChannel(user.username, user.role, cleanConv)) {
        return socket.emit('access_denied', { channel: cleanConv, message: 'شما به این کانال دسترسی ندارید.' });
        }
        if (!conversations[cleanConv]) ensurePublicConversation(cleanConv, 'system');
    }

    // content sanitization
    const cleanTextVal = cleanText(data?.text, 1000);
    const cleanFileName = data?.fileName ? xss(String(data.fileName)).substring(0, 120) : undefined;
    const type = String(data?.type || 'text');

    // ✅ validate content to prevent javascript:/phishing
    let content = (typeof data?.content === 'string') ? data.content : undefined;

    function isSafeUploadsUrl(u) {
      if (!u || typeof u !== 'string') return false;
      // allow: /uploads/<file> or /uploads/<file>?t=...
      if (u.startsWith('/uploads/')) return true;
      return false;
    }

    function isSafeDataUrl(u, kind) {
      if (!u || typeof u !== 'string') return false;
      // allow only audio recording data url (your recorder uses audio/webm)
      if (kind === 'audio') return u.startsWith('data:audio/');
      // disallow data:image/video/file from users (you use uploads for those)
      return false;
    }

    if (type !== 'text') {
      if (!content) return socket.emit('error', 'محتوای پیام نامعتبر است.');
      const ok =
        isSafeUploadsUrl(content) ||
        isSafeDataUrl(content, type);

      if (!ok) return socket.emit('error', 'لینک/محتوا مجاز نیست.');
    }

    if (type === 'audio' && typeof content === 'string' && content.length > 2_500_000) return socket.emit('error', 'فایل صوتی خیلی بزرگ است.');
    if (type === 'image' && typeof content === 'string' && content.length > 3_500_000) return socket.emit('error', 'تصویر خیلی بزرگ است.');
    if (type === 'video' && typeof content === 'string' && content.length > 5_000_000) return socket.emit('error', 'ویدیو خیلی بزرگ است.');

    const msg = {
        id: crypto.randomBytes(12).toString('hex'),
        sender: user.username,
        text: cleanTextVal,
        type,
        content,
        fileName: cleanFileName,
        conversationId,
        channel: conversationId,
        replyTo: data?.replyTo || null,
        timestamp: new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }),
        role: user.role
    };

    ensureConversationMaps(conversationId);
    messages[conversationId].push(msg);
    if (messages[conversationId].length > 100) messages[conversationId].shift();

    io.to(conversationId).emit('receive_message', msg);
    saveData();
    });

  socket.on('delete_message', (msgId) => {
    const user = users[socket.id];
    if (!user || user.role !== 'admin') return;

    const id = String(msgId || '');
    if (!id) return;

    let found = false;
    for (const key of Object.keys(messages)) {
      if (!Array.isArray(messages[key])) continue;
      const idx = messages[key].findIndex(m => m.id === id);
      if (idx !== -1) {
        messages[key].splice(idx, 1);
        found = true;
        io.to(key).emit('message_deleted', { channel: key, id });
        break;
      }
    }
    if (found) saveData();
  });

  socket.on('search_user', (query) => {
    if (!users[socket.id]) return;
    if (!query || String(query).length > 20) return;

    const cleanQuery = xss(String(query)).toLowerCase();
    const matches = Object.keys(persistentUsers).filter(u => u.toLowerCase().includes(cleanQuery)).slice(0, 30);
    socket.emit('search_results', matches);
  });

  socket.on('disconnect', () => {
    delete users[socket.id];
    broadcastUserList();
  });
});

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

EOF

# index.html (Client)
cat > public/index.html << 'EOF'

<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>
  <meta charset="UTF-8">
  <meta name="viewport"
    content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
  <title>__APP_NAME_PLACEHOLDER__</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;700&display=swap" rel="stylesheet">
  <script src="/socket.io/socket.io.js"></script>
  <script src="https://unpkg.com/vue@3/dist/vue.global.js"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">

  <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            brand: {
              DEFAULT: 'var(--brand-color)',
              dark: 'var(--brand-dark)',
              light: 'var(--brand-light)',
            }
          }
        }
      }
    }
  </script>

  <style>
    :root {
      --brand-color: __COLOR_DEFAULT__;
      --brand-dark: __COLOR_DARK__;
      --brand-light: __COLOR_LIGHT__;

      --bg-app: #F7F8FC;
      --bg-chat: #F2F4F8;

      --panel: rgba(255, 255, 255, 0.82);
      --panel-2: rgba(255, 255, 255, 0.66);

      --text: #0B1220;
      --muted: rgba(15, 23, 42, 0.62);

      --border: rgba(15, 23, 42, 0.10);
      --border-strong: rgba(15, 23, 42, 0.14);

      --shadow: 0 18px 55px rgba(2, 6, 23, 0.10);
      --shadow-soft: 0 10px 28px rgba(2, 6, 23, 0.08);

      --radius-xl: 22px;
      --radius-lg: 16px;
      --radius-md: 14px;

      --ring: 0 0 0 4px color-mix(in srgb, var(--brand-color) 22%, transparent);
    }

    html,
    body {
      height: 100%;
    }

    body {
      font-family: 'Vazirmatn', sans-serif;
      background:
        radial-gradient(1100px 600px at 78% -10%, color-mix(in srgb, var(--brand-color) 14%, transparent), transparent 60%),
        radial-gradient(900px 520px at 12% 18%, color-mix(in srgb, var(--brand-dark) 10%, transparent), transparent 55%),
        linear-gradient(180deg, #FFFFFF 0%, var(--bg-app) 42%, var(--bg-app) 100%);
      color: var(--text);
      overscroll-behavior-y: none;
      height: 100vh;
      height: 100dvh;
      -webkit-tap-highlight-color: transparent;
      text-rendering: optimizeLegibility;
    }

    .dir-rtl {
      direction: rtl;
    }

    .safe-pb {
      padding-bottom: env(safe-area-inset-bottom);
    }

    :focus-visible {
      outline: none;
      box-shadow: var(--ring);
      border-radius: 12px;
    }

    ::-webkit-scrollbar {
      width: 6px;
      height: 6px;
    }

    ::-webkit-scrollbar-thumb {
      background: rgba(107, 114, 128, 0.28);
      border-radius: 999px;
    }

    ::-webkit-scrollbar-thumb:hover {
      background: rgba(107, 114, 128, 0.42);
    }

    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius-xl);
      box-shadow: var(--shadow);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
    }

    .panel-soft {
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-radius: var(--radius-xl);
      box-shadow: var(--shadow-soft);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
    }

    .msg-bubble {
      max-width: min(85%, 720px);
      position: relative;
      will-change: transform;
    }

    .context-menu {
      position: absolute;
      background: rgba(255, 255, 255, 0.90);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      border-radius: 14px;
      box-shadow: 0 16px 44px rgba(0, 0, 0, 0.14);
      padding: 6px;
      z-index: 120;
      min-width: 180px;
      overflow: hidden;
      border: 1px solid rgba(15, 23, 42, 0.08);
      color: var(--text);
    }

    .unread-badge {
      background-color: #ef4444;
      color: #ffffff;
      font-size: 10px;
      height: 18px;
      min-width: 18px;
      border-radius: 999px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0 6px;
      font-weight: 800;
      letter-spacing: 0.2px;
      box-shadow: 0 6px 14px rgba(239, 68, 68, 0.22);
    }

    .tap {
      transition: transform 120ms ease, filter 120ms ease;
    }

    .tap:active {
      transform: scale(0.985);
      filter: brightness(0.985);
    }

    textarea::placeholder {
      color: rgba(107, 114, 128, 0.78);
    }
  </style>
</head>

<body class="w-full overflow-hidden flex flex-col dir-rtl">
  <div id="app" class="h-full flex flex-col w-full">

    <!-- Login Screen -->
    <div v-if="!isLoggedIn"
      class="fixed inset-0 bg-white/75 backdrop-blur-md flex items-center justify-center z-50 p-4">
      <div class="panel w-full max-w-sm text-center overflow-hidden">
        <div class="p-6 md:p-8">
          <div
            class="w-16 h-16 bg-brand rounded-2xl mx-auto flex items-center justify-center mb-4 text-white text-2xl shadow-lg shadow-brand/25">
            <i class="fas fa-comments"></i>
          </div>
          <h1 class="text-2xl font-extrabold mb-2 text-brand-dark tracking-tight">{{ appName }}</h1>
          <p class="text-xs text-gray-500 mb-6 leading-relaxed">برای ورود یا ثبت نام اطلاعات زیر را وارد کنید</p>

          <div class="space-y-3">
            <input v-model="loginForm.username" @keyup.enter="login" placeholder="نام کاربری" autocomplete="username"
              class="w-full p-3 border rounded-xl bg-white/90 focus:ring-2 focus:ring-brand outline-none text-center dir-rtl">

            <input v-model="loginForm.password" @keyup.enter="login" type="password" placeholder="رمز عبور"
              autocomplete="current-password"
              class="w-full p-3 border rounded-xl bg-white/90 focus:ring-2 focus:ring-brand outline-none text-center dir-rtl">

            <button @click="login" :disabled="isAuthBusy || !loginForm.username || !loginForm.password"
              class="w-full bg-brand text-white py-3 rounded-xl font-extrabold hover:bg-brand-dark transition shadow-lg shadow-brand/25 disabled:opacity-60 disabled:cursor-not-allowed tap">
              <span v-if="!isAuthBusy">ورود / ثبت نام</span>
              <span v-else class="inline-flex items-center gap-2 justify-center">
                <i class="fas fa-circle-notch fa-spin"></i>
                در حال اتصال...
              </span>
            </button>

            <p v-if="error" class="text-red-600 text-sm mt-2 bg-red-50 p-2 rounded-lg border border-red-100">{{ error }}
            </p>
          </div>

          <div class="mt-5 text-[11px] text-gray-400 leading-relaxed">
            با ورود شما، یک حساب کاربری (در صورت نبود) ساخته می‌شود.
          </div>
        </div>
      </div>
    </div>

    <!-- Chat Interface -->
    <div v-else class="flex h-full relative w-full overflow-hidden">

      <!-- Sidebar -->
      <div
        :class="['absolute md:relative z-20 h-full bg-white border-l shadow-xl md:shadow-none transition-transform duration-300 w-72 flex flex-col shrink-0', showSidebar ? 'translate-x-0' : 'translate-x-full md:translate-x-0']">

        <!-- User Info -->
        <div class="p-4 bg-gradient-to-l from-brand to-brand-dark text-white shadow shrink-0">
          <div class="flex justify-between items-center">
            <div>
              <h2 class="font-bold text-lg">{{ appName }}</h2>
              <p class="text-xs opacity-90 mt-1 flex items-center gap-1">
                <i class="fas fa-user-circle"></i> {{ user.username }}
                <span v-if="user.role === 'admin'"
                  class="bg-yellow-400 text-black px-1 rounded text-[9px] font-bold">مدیر</span>
                <span v-else-if="user.role === 'vip'"
                  class="bg-blue-400 text-white px-1 rounded text-[9px] font-bold">ویژه</span>
              </p>
            </div>
            <div class="flex gap-1">
              <button v-if="user.role === 'admin'" @click="showAdminSettings = true"
                class="text-xs bg-white/20 p-2 rounded hover:bg-white/30" title="تنظیمات"><i
                  class="fas fa-cog"></i></button>
              <button @click="logout" class="text-xs bg-white/20 p-2 rounded hover:bg-white/30" title="خروج"><i
                  class="fas fa-sign-out-alt"></i></button>
            </div>
          </div>
        </div>

        <!-- Tools -->
        <div class="p-2 border-b bg-gray-50 flex gap-2 overflow-x-auto shrink-0">
          <button @click="openSavedView" 
            class="bg-brand/10 text-brand px-3 py-1 rounded text-xs whitespace-nowrap">
            <i class="fas fa-bookmark"></i> پیام‌های ذخیره‌شده
          </button>

          <button v-if="canBan" @click="openBanList"
            class="bg-red-100 text-red-600 px-3 py-1 rounded text-xs whitespace-nowrap">
            <i class="fas fa-ban"></i> لیست سیاه
          </button>
        </div>

        <!-- Search -->
        <div class="p-2 border-b bg-white shrink-0">
          <input v-model="searchQuery" @input="searchUser" placeholder="جستجوی کاربر..."
            class="w-full px-3 py-1.5 rounded-lg border text-sm bg-gray-50 focus:outline-none focus:border-brand">
        </div>

        <!-- Lists -->
        <div class="flex-1 overflow-y-auto p-2 space-y-4">

          <!-- Search Results -->
          <div v-if="searchResults.length > 0">
            <h3 class="text-xs font-bold text-gray-400 mb-2 px-2">نتایج جستجو</h3>
            <ul>
              <li v-for="u in searchResults" :key="u" @click="startPrivateChat(u)"
                class="flex items-center gap-2 p-2 rounded hover:bg-gray-100 cursor-pointer">
                <div class="w-8 h-8 rounded-full bg-gray-200 flex items-center justify-center text-gray-500"><i
                    class="fas fa-user"></i></div>
                <span class="text-sm font-medium">{{ u }}</span>
              </li>
            </ul>
            <hr class="my-2">
          </div>

          <!-- Channels -->
          <div>
            <h3 class="text-xs font-bold text-gray-400 mb-2 px-2 flex justify-between items-center">
              کانال‌ها
              <button v-if="canCreateChannel" @click="toggleCreateChannel"
                class="text-brand hover:text-brand-dark text-xs bg-brand/10 w-5 h-5 rounded-full flex items-center justify-center">
                <i class="fas fa-plus"></i>
              </button>
            </h3>

            <div v-if="showCreateChannelInput" class="mb-2 px-2 flex gap-1 animate-fade-in">
              <input v-model="newChannelName" class="w-full text-xs p-1 border rounded" placeholder="نام کانال...">
              <button @click="createChannel" class="bg-green-500 text-white px-2 rounded text-xs"><i
                  class="fas fa-check"></i></button>
            </div>

            <div v-if="channels.length === 0" class="px-2 py-3 text-xs text-gray-400 leading-relaxed">
              هیچ کانالی برای شما فعال نیست.
              <div class="mt-1">ادمین باید دسترسی کانال‌ها را به شما بدهد.</div>
            </div>

            <ul class="space-y-1">
              <li v-for="ch in channels" :key="ch"
                class="group relative p-2 rounded-lg cursor-pointer flex items-center justify-between transition"
                :class="currentChannel === ch ? 'bg-brand/10 text-brand font-bold' : 'hover:bg-gray-100 text-gray-600'">
                <div class="flex items-center gap-2 w-full" @click="joinChannel(ch)">
                  <i class="fas fa-hashtag text-xs opacity-50"></i>
                  <span class="text-sm truncate">{{ ch }}</span>
                </div>
                <div v-if="unreadCounts[ch] > 0" class="unread-badge">{{ unreadCounts[ch] }}</div>
                <button v-if="canCreateChannel && ch !== 'General'" @click.stop="deleteChannel(ch)"
                  class="text-red-400 hover:text-red-600 px-2 hidden group-hover:block"><i
                    class="fas fa-trash text-xs"></i></button>
              </li>
            </ul>
          </div>

          <!-- Online Users -->
          <div>
            <h3 class="text-xs font-bold text-gray-400 mb-2 px-2 mt-4">کاربران آنلاین ({{ sortedUsers.length }})</h3>
            <ul class="space-y-1">
              <li v-for="u in sortedUsers" :key="u.username" @click="handleUserClick(u)"
                @contextmenu.prevent="showUserContext($event, u.username)"
                class="flex items-center gap-2 p-2 rounded hover:bg-gray-100 cursor-pointer transition">
                <div class="relative">
                  <div
                    class="w-9 h-9 rounded-full flex items-center justify-center text-gray-600 text-xs font-bold shadow-sm"
                    :class="{'bg-yellow-100 text-yellow-700': u.role === 'admin', 'bg-blue-100 text-blue-700': u.role === 'vip', 'bg-gray-200': u.role === 'user'}">
                    <i v-if="u.role === 'admin'" class="fas fa-crown text-sm"></i>
                    <i v-else-if="u.role === 'vip'" class="fas fa-gem text-sm"></i>
                    <span v-else>{{ u.username.substring(0,2).toUpperCase() }}</span>
                  </div>
                  <div class="absolute bottom-0 right-0 w-2.5 h-2.5 bg-green-500 border-2 border-white rounded-full">
                  </div>
                </div>
                <div class="flex flex-col flex-1">
                  <span class="text-sm font-medium flex items-center gap-1">
                    {{ u.username }}
                    <span v-if="u.username === user.username" class="text-[10px] text-gray-400">(شما)</span>
                  </span>
                  <span class="text-[10px] text-gray-400">
                    {{ u.role === 'admin' ? 'مدیر کل' : (u.role === 'vip' ? 'کاربر ویژه' : 'کاربر') }}
                  </span>
                </div>
                <div v-if="unreadCounts[u.username] > 0" class="unread-badge">{{ unreadCounts[u.username] }}</div>
              </li>
            </ul>
          </div>
        </div>
      </div>

      <!-- Mobile Sidebar Overlay -->
      <div v-if="showSidebar" @click="showSidebar = false"
        class="absolute inset-0 bg-white/70 backdrop-blur-sm z-10 md:hidden"></div>

      <!-- Chat Area -->
      <div class="flex-1 flex flex-col relative h-full min-w-0" style="background: var(--bg-chat);">

        <!-- Wallpaper -->
        <div class="absolute inset-0 opacity-5 pointer-events-none"
          style="background-image: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAYAAACp8Z5+AAAAIklEQVQIW2NkQAKrVq36zwjjgzhhYWGMYAEYB8RmROaABADeOQ8CXl/xfgAAAABJRU5ErkJggg==')">
        </div>

        <!-- Header -->
        <div
          class="bg-white/90 backdrop-blur-md border-b border-black/5 p-3 flex items-center gap-3 z-20 shrink-0 sticky top-0">
          <button class="md:hidden text-gray-600 p-2 rounded-lg hover:bg-black/5 tap" @click="showSidebar = true"
            aria-label="باز کردن منو">
            <i class="fas fa-bars"></i>
          </button>

          <div class="flex-1 min-w-0">
            <h2 class="font-extrabold text-gray-900 flex items-center gap-2 truncate">
              <span v-if="isSavedView" class="text-brand"><i class="fas fa-bookmark"></i></span>
              <span v-else-if="isPrivateChat" class="text-brand"><i class="fas fa-user-lock"></i></span>
              <span v-else class="text-gray-500"><i class="fas fa-hashtag"></i></span>
              <span class="truncate">{{ displayChannelName }}</span>
            </h2>

            <div class="mt-0.5 flex items-center gap-2 text-[11px] text-gray-500">
              <span :class="isConnected ? 'text-green-600' : 'text-red-600'" class="inline-flex items-center gap-1">
                <span class="inline-block w-2 h-2 rounded-full"
                  :class="isConnected ? 'bg-green-500' : 'bg-red-500'"></span>
                <span v-if="isConnected">متصل</span>
                <span v-else>قطع</span>
              </span>
              <span class="opacity-60">•</span>
              <span class="truncate">برای رفتن به خط جدید: Shift + Enter</span>
            </div>
          </div>

          <button v-if="showScrollDown" @click="scrollToBottom(true)"
            class="w-10 h-10 rounded-full bg-black/5 hover:bg-black/10 text-gray-700 flex items-center justify-center tap"
            aria-label="رفتن به آخر گفتگو">
            <i class="fas fa-arrow-down"></i>
          </button>
        </div>

        <!-- Upload Progress -->
        <div v-if="isUploading"
          class="bg-brand-light/20 p-2 text-center text-xs text-brand-dark border-b border-brand-light/30">
          <div class="flex items-center justify-between px-4 mb-1">
            <span>در حال ارسال فایل...</span>
            <span>{{ uploadProgress }}%</span>
          </div>
          <div class="w-full bg-gray-200 rounded-full h-1.5">
            <div class="bg-brand h-1.5 rounded-full transition-all duration-200"
              :style="{ width: uploadProgress + '%' }"></div>
          </div>
        </div>

        <!-- Access Denied Banner -->
        <div v-if="accessDeniedBanner"
          class="bg-red-50 border-b border-red-100 text-red-700 text-xs p-2 px-4 flex items-center justify-between">
          <div class="flex items-center gap-2">
            <i class="fas fa-lock"></i>
            <span>{{ accessDeniedBanner }}</span>
          </div>
          <button class="text-red-700/70 hover:text-red-700" @click="accessDeniedBanner = ''">
            <i class="fas fa-times"></i>
          </button>
        </div>

            <!-- Messages -->
            <div class="flex-1 overflow-y-auto p-4 space-y-2 min-h-0" id="messages-container" ref="msgContainer">

            <div v-for="msg in messages" :key="msg.id"
                :class="['flex w-full', msg.sender === user.username ? 'justify-end' : 'justify-start']"
                :id="'msg-row-' + msg.id">

                <div @touchstart="touchStart($event, msg)" @touchmove="touchMove($event)" @touchend="touchEnd($event)"
                @contextmenu.prevent="showContext($event, msg)" :style="getSwipeStyle(msg.id)"
                class="msg-bubble transition-transform duration-75 ease-out select-none" :id="'msg-' + msg.id">

                <div
                    class="absolute right-[-40px] top-1/2 transform -translate-y-1/2 text-brand text-lg opacity-0 transition-opacity"
                    :class="{'opacity-100': swipeId === msg.id && swipeOffset < -40}">
                    <i class="fas fa-reply"></i>
                </div>

                <div
                    :class="['rounded-2xl px-4 py-2 shadow-sm text-sm relative border', 
                                            msg.sender === user.username ? 'bg-brand-light border-brand/20 rounded-tr-none' : 'bg-white border-gray-100 rounded-tl-none']">

                    <div v-if="msg.replyTo" @click="scrollToMessage(msg.replyTo.id)"
                    class="mb-2 p-2 rounded bg-black/5 border-r-4 border-brand cursor-pointer text-xs">
                    <div class="font-bold text-brand-dark mb-1">{{ msg.replyTo.sender }}</div>
                    <div class="truncate opacity-70">{{ msg.replyTo.text || 'Media' }}</div>
                    </div>

                    <div v-if="msg.sender !== user.username"
                    class="font-bold text-xs mb-1 text-brand-dark flex items-center gap-1">
                    {{ msg.sender }}
                    <i v-if="msg.role === 'admin'" class="fas fa-crown text-yellow-500 text-[10px]"></i>
                    <i v-else-if="msg.role === 'vip'" class="fas fa-gem text-blue-500 text-[10px]"></i>
                    </div>

                    <div class="break-words leading-relaxed" v-if="msg.type === 'text'">{{ msg.text }}</div>
                    <img v-if="msg.type === 'image'" :src="msg.content"
                    class="max-w-full rounded-lg mt-1 cursor-pointer hover:opacity-90 transition"
                    @click="viewImage(msg.content)">
                    <video v-if="msg.type === 'video'" :src="msg.content" controls class="max-w-full rounded-lg mt-1"></video>
                    <audio v-if="msg.type === 'audio'" :src="msg.content" controls class="mt-1 w-full min-w-[200px]"></audio>

                    <div v-if="msg.type === 'file'" class="mt-1 bg-black/5 p-3 rounded flex items-center gap-3">
                    <div class="w-10 h-10 bg-brand/20 rounded flex items-center justify-center text-brand text-xl">
                        <i class="fas fa-file-alt"></i>
                    </div>
                    <div class="flex-1 overflow-hidden">
                        <div class="truncate font-bold text-xs">{{ msg.fileName || 'File' }}</div>
                        <a :href="safeLink(msg.content)" target="_blank" rel="noopener noreferrer"
                          class="text-[10px] text-blue-500 hover:underline">دانلود فایل</a>
                    </div>
                    </div>

                    <div
                    :class="['text-[9px] mt-1 text-left', msg.sender === user.username ? 'text-brand-dark/50' : 'text-gray-400']">
                    {{ msg.timestamp }}
                    <i v-if="msg.sender === user.username" class="fas fa-check-double ml-1 text-blue-400"></i>
                    </div>

                </div>
                </div>
            </div>

            </div>

        <!-- Reply Input -->
        <div v-if="replyingTo && !isSavedView"
          class="bg-gray-50 border-t p-2 flex justify-between items-center border-b border-gray-200 shrink-0">
          <div class="flex-1 text-sm border-r-4 border-brand pr-3">
            <div class="font-bold text-brand text-xs">پاسخ به {{ replyingTo.sender }}</div>
            <div class="text-gray-500 text-xs truncate">{{ replyingTo.text || 'File' }}</div>
          </div>
          <button @click="cancelReply" class="p-2 text-gray-500 hover:text-red-500"><i
              class="fas fa-times"></i></button>
        </div>

        <!-- Input Area -->
        <div class="p-2 safe-pb bg-white/90 backdrop-blur-md border-t border-black/5 flex items-end gap-2 z-20 shrink-0">
            <div class="flex pb-2 gap-1">
              <button class="w-10 h-10 rounded-full hover:bg-black/5 text-gray-600 text-lg transition tap"
              @click="$refs.fileInput.click()" aria-label="ارسال فایل">
              <i class="fas fa-paperclip"></i>
            </button>
            <input ref="fileInput" type="file" class="hidden" @change="handleFileUpload">

            <button @click="toggleRecording"
              :class="['w-10 h-10 rounded-full transition text-lg tap', isRecording ? 'text-red-600 bg-red-50 animate-pulse' : 'hover:bg-black/5 text-gray-600']"
              aria-label="ضبط صدا">
              <i class="fas fa-microphone"></i>
            </button>
          </div>

          <div
            class="flex-1 bg-gray-100/80 rounded-2xl flex items-end p-2 border border-black/5 focus-within:ring-1 focus-within:ring-brand focus-within:bg-white transition">
            <textarea v-model="messageText" @keydown="handleComposerKeydown" @input="autoResize" ref="textarea"
              placeholder="پیام..."
              class="flex-1 bg-transparent outline-none max-h-40 min-h-[44px] resize-none py-2 px-2 text-sm leading-6"></textarea>
          </div>

          <button @click="sendMessage" :disabled="!canSend"
            class="w-12 h-12 rounded-full bg-brand text-white shadow-lg hover:bg-brand-dark transition flex items-center justify-center mb-0.5 disabled:opacity-60 disabled:cursor-not-allowed tap"
            aria-label="ارسال">
            <i class="fas fa-paper-plane text-lg translate-x-[-2px] translate-y-[1px]"></i>
          </button>
        </div>

        <!-- Context Menu -->
        <div v-if="contextMenu.visible" :style="{ top: contextMenu.y + 'px', left: contextMenu.x + 'px' }"
          class="context-menu" @click.stop>

          <template v-if="contextMenu.type === 'message'">
            <div @click="saveThisMessage(contextMenu.target); contextMenu.visible = false"
              class="px-3 py-2 hover:bg-gray-100 cursor-pointer text-sm flex items-center gap-2">
              <i class="fas fa-bookmark text-gray-400 w-4"></i> ذخیره پیام
            </div>

            <div @click="setReply(contextMenu.target); contextMenu.visible = false"
              class="px-3 py-2 hover:bg-gray-100 cursor-pointer text-sm flex items-center gap-2 border-t">
              <i class="fas fa-reply text-gray-400 w-4"></i> پاسخ
            </div>

            <div v-if="user.role === 'admin'" @click="deleteMessage(contextMenu.target.id); contextMenu.visible = false"
              class="px-3 py-2 hover:bg-red-50 text-red-600 cursor-pointer text-sm flex items-center gap-2 border-t">
              <i class="fas fa-trash w-4"></i> حذف پیام
            </div>

            <div v-if="canBan && contextMenu.target.sender !== user.username"
              @click="banUser(contextMenu.target.sender); contextMenu.visible = false"
              class="px-3 py-2 hover:bg-red-50 text-red-600 cursor-pointer text-sm flex items-center gap-2 border-t">
              <i class="fas fa-ban w-4"></i> بن کردن کاربر
            </div>
          </template>

          <template v-if="contextMenu.type === 'user'">
            <div @click="startPrivateChat(contextMenu.target); contextMenu.visible = false"
              class="px-3 py-2 hover:bg-gray-100 cursor-pointer text-sm flex items-center gap-2">
              <i class="fas fa-comment text-gray-400 w-4"></i> پیام خصوصی
            </div>

            <template v-if="user.role === 'admin' && contextMenu.target !== user.username">
              <div @click="openAccessModal(contextMenu.target); contextMenu.visible = false"
                class="px-3 py-2 hover:bg-gray-100 cursor-pointer text-sm flex items-center gap-2 border-t">
                <i class="fas fa-key text-brand w-4"></i> مدیریت دسترسی کانال‌ها
              </div>

              <div @click="setRole(contextMenu.target, 'vip'); contextMenu.visible = false"
                class="px-3 py-2 hover:bg-gray-100 cursor-pointer text-sm flex items-center gap-2 border-t">
                <i class="fas fa-gem text-blue-500 w-4"></i> تبدیل به ویژه
              </div>

              <div @click="setRole(contextMenu.target, 'user'); contextMenu.visible = false"
                class="px-3 py-2 hover:bg-gray-100 cursor-pointer text-sm flex items-center gap-2 border-t">
                <i class="fas fa-user text-gray-400 w-4"></i> تبدیل به عادی
              </div>
            </template>

            <div v-if="canBan && contextMenu.target !== user.username"
              @click="banUser(contextMenu.target); contextMenu.visible = false"
              class="px-3 py-2 hover:bg-red-50 text-red-600 cursor-pointer text-sm flex items-center gap-2 border-t">
              <i class="fas fa-ban w-4"></i> بن کردن
            </div>
          </template>
        </div>
      </div>
    </div>

    <!-- Admin Settings Modal -->
    <div v-if="showAdminSettings"
      class="fixed inset-0 bg-white/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div class="bg-white rounded-xl shadow-xl w-full max-w-sm overflow-hidden flex flex-col border border-black/5">
        <div class="p-4 border-b flex justify-between items-center bg-gray-50">
          <h3 class="font-bold text-gray-700">تنظیمات چت روم</h3>
          <button @click="showAdminSettings = false" class="text-gray-400 hover:text-gray-600"><i
              class="fas fa-times"></i></button>
        </div>
        <div class="p-6 space-y-4">
          <div class="flex items-center justify-between">
            <label class="text-sm font-bold text-gray-700">مخفی کردن لیست کاربران</label>
            <input type="checkbox" v-model="adminSettings.hideUserList" class="w-5 h-5 accent-brand">
          </div>

          <div class="border-t pt-4">
            <div class="flex items-center justify-between">
              <label class="text-sm font-bold text-gray-700">حالت دسترسی کانال‌ها</label>
              <select v-model="adminSettings.accessMode" class="border rounded-lg px-2 py-1 text-sm bg-white">
                <option value="restricted">Restricted (فقط با اجازه ادمین)</option>
                <option value="open">Open (همه کاربران)</option>
              </select>
            </div>
            <p class="text-xs text-gray-500 text-justify leading-relaxed mt-2">
              در حالت Restricted، کاربر فقط کانال‌هایی که ادمین برای او فعال کرده را می‌بیند و می‌تواند چت کند.
            </p>
          </div>

          <button @click="saveAdminSettings"
            class="w-full bg-brand text-white py-2 rounded-lg text-sm font-bold shadow hover:bg-brand-dark transition">
            ذخیره تنظیمات
          </button>
        </div>
      </div>
    </div>

    <!-- Ban List Modal -->
    <div v-if="showBanModal"
      class="fixed inset-0 bg-white/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div
        class="bg-white rounded-xl shadow-xl w-full max-w-md overflow-hidden flex flex-col max-h-[80vh] border border-black/5">
        <div class="p-4 border-b flex justify-between items-center bg-gray-50">
          <h3 class="font-bold text-gray-700">لیست سیاه (بن شده‌ها)</h3>
          <button @click="showBanModal = false" class="text-gray-400 hover:text-gray-600"><i
              class="fas fa-times"></i></button>
        </div>
        <div class="overflow-y-auto p-4 flex-1">
          <div v-if="bannedUsers.length === 0" class="text-center text-gray-400 py-4">هیچ کاربری بن نشده است.</div>
          <ul class="divide-y">
            <li v-for="u in bannedUsers" :key="u" class="py-3 flex justify-between items-center">
              <span class="font-bold text-gray-700">{{ u }}</span>
              <button @click="unbanUser(u)"
                class="text-xs bg-green-100 text-green-700 px-3 py-1 rounded hover:bg-green-200">آزاد کردن</button>
            </li>
          </ul>
        </div>
      </div>
    </div>

    <!-- Admin Access Modal -->
    <div v-if="showAccessModal"
      class="fixed inset-0 bg-white/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div class="bg-white rounded-xl shadow-xl w-full max-w-lg overflow-hidden flex flex-col max-h-[85vh] border border-black/5">
        <div class="p-4 border-b flex justify-between items-center bg-gray-50">
          <h3 class="font-bold text-gray-700">
            <i class="fas fa-key text-brand"></i>
            مدیریت دسترسی کانال‌ها: {{ accessModalUser }}
          </h3>
          <button @click="showAccessModal = false" class="text-gray-400 hover:text-gray-600">
            <i class="fas fa-times"></i>
          </button>
        </div>

        <div class="p-4 overflow-y-auto flex-1">
          <div class="text-xs text-gray-500 mb-3 leading-relaxed">
            با فعال/غیرفعال کردن هر کانال، دسترسی کاربر به مشاهده و چت در آن کانال کنترل می‌شود.
          </div>

          <div v-if="accessChannels.length === 0" class="text-center text-gray-400 py-6">
            هیچ کانالی وجود ندارد.
          </div>

          <div class="space-y-2">
            <div v-for="ch in accessChannels" :key="ch" class="flex items-center justify-between border rounded-lg px-3 py-2">
              <div class="flex items-center gap-2">
                <i class="fas fa-hashtag text-xs opacity-60"></i>
                <span class="font-bold text-sm text-gray-700">{{ ch }}</span>
              </div>

              <label class="inline-flex items-center gap-2 text-xs text-gray-600">
                <input type="checkbox" class="w-5 h-5 accent-brand"
                  :checked="!!accessMap[ch]"
                  @change="toggleUserAccess(ch, $event.target.checked)">
                دسترسی
              </label>
            </div>
          </div>
        </div>

        <div class="p-4 border-t bg-gray-50 flex items-center justify-between">
          <button class="text-xs bg-gray-200 text-gray-700 px-3 py-2 rounded" @click="refreshAccessModal">
            بروزرسانی
          </button>
          <button class="text-xs bg-brand text-white px-3 py-2 rounded shadow hover:bg-brand-dark" @click="showAccessModal = false">
            بستن
          </button>
        </div>
      </div>
    </div>

    <!-- Lightbox -->
    <div v-if="lightboxImage" @click="lightboxImage = null"
      class="fixed inset-0 bg-white/90 backdrop-blur-md z-50 flex items-center justify-center p-4">
      <img :src="lightboxImage" class="max-w-full max-h-full rounded shadow-2xl">
      <button class="absolute top-4 right-4 text-gray-700 text-3xl">&times;</button>
    </div>
  </div>

  <script>
    const { createApp, ref, onMounted, nextTick, computed } = Vue;
    const socket = io();

    const notifyAudio = new Audio('data:audio/mp3;base64,//NExAAAAANIAAAAAExBTUUzLjEwMKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq//NExAAAAANIAAAAAExBTUUzLjEwMKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq//NExAAAAANIAAAAAExBTUUzLjEwMKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq//NExAAAAANIAAAAAExBTUUzLjEwMKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq');

    createApp({
      setup() {
        const isLoggedIn = ref(false);
        const user = ref({ username: '', role: 'user' });
        const loginForm = ref({ username: '', password: '' });
        const error = ref('');
        const appName = ref('__APP_NAME_PLACEHOLDER__');

        const channels = ref([]);
        const currentChannel = ref('');
        const isPrivateChat = ref(false);
        const isSavedView = ref(false);
        const displayChannelName = ref('');
        const messages = ref([]);
        const onlineUsers = ref([]);
        const searchResults = ref([]);
        const searchQuery = ref('');
        const bannedUsers = ref([]);
        const appSettings = ref({ maxFileSizeMB: 50, accessMode: 'restricted' });
        const uploadToken = ref('');
        const unreadCounts = ref({});

        const showSidebar = ref(false);
        const messageText = ref('');
        const showCreateChannelInput = ref(false);
        const newChannelName = ref('');
        const lightboxImage = ref(null);
        const showBanModal = ref(false);
        const showAdminSettings = ref(false);

        const adminSettings = ref({ hideUserList: false, accessMode: 'restricted' });

        const replyingTo = ref(null);
        const contextMenu = ref({ visible: false, x: 0, y: 0, target: null, type: null });

        const swipeId = ref(null);
        const swipeStartX = ref(0);
        const swipeOffset = ref(0);

        const isRecording = ref(false);
        const isUploading = ref(false);
        const uploadProgress = ref(0);

        const isConnected = ref(socket.connected);
        const isAuthBusy = ref(false);
        const showScrollDown = ref(false);

        // ✅ NEW: access UI
        const showAccessModal = ref(false);
        const accessModalUser = ref('');
        const accessChannels = ref([]);
        const accessMap = ref({});
        const accessDeniedBanner = ref('');

const canSend = computed(() => {
  const t = messageText.value.trim();
  if (!t) return false;
  if (!isConnected.value) return false;
  if (!currentChannel.value) return false;   // ✅ مهم
  return true;
});

        const sortedUsers = computed(() => {
          return [...onlineUsers.value].sort((a, b) => {
            const roles = { admin: 3, vip: 2, user: 1 };
            return roles[b.role] - roles[a.role];
          });
        });

        const canCreateChannel = computed(() => user.value.role === 'admin' || user.value.role === 'vip');
        const canBan = computed(() => user.value.role === 'admin' || user.value.role === 'vip');

        onMounted(() => {
          const storedUser = localStorage.getItem('chat_user_name');
          if (storedUser) loginForm.value.username = storedUser;

          document.addEventListener('click', () => { contextMenu.value.visible = false; });

          if ('Notification' in window && Notification.permission !== 'granted' && Notification.permission !== 'denied') {
            Notification.requestPermission();
          }

          const c = document.getElementById('messages-container');
          if (!c) return;

          c.addEventListener('scroll', () => {
            const isNearBottom = c.scrollTop + c.clientHeight >= c.scrollHeight - 150;
            showScrollDown.value = !isNearBottom;
          }, { passive: true });
        });

        const scrollToBottom = (force = false) => {
          nextTick(() => {
            const c = document.getElementById('messages-container');
            if (!c) return;
            if (force) { c.scrollTop = c.scrollHeight; return; }
            c.scrollTop = c.scrollHeight;
          });
        };

        const playSound = () => {
          try { notifyAudio.currentTime = 0; notifyAudio.play().catch(() => { }); } catch (e) { }
        };

        const notify = (title, body) => {
          playSound();
          if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(title, { body, icon: '/favicon.ico' });
          }
        };

        const formatTime = (ts) => {
          try {
            const d = new Date(Number(ts));
            return d.toLocaleString('fa-IR');
          } catch {
            return '';
          }
        };

        // --- AUTH ---
        const login = () => {
          if (!loginForm.value.username || !loginForm.value.password) {
            error.value = 'نام کاربری و رمز عبور الزامی است';
            return;
          }
          error.value = '';
          isAuthBusy.value = true;
          socket.emit('login', loginForm.value);
          if ('Notification' in window) Notification.requestPermission();
        };

        const logout = () => {
          localStorage.removeItem('chat_user_name');
          window.location.reload();
        };

        // --- Channels / Views ---
        const setChatView = (name, pv = false) => {
          isSavedView.value = false;
          isPrivateChat.value = pv;
          currentChannel.value = name;
          displayChannelName.value = pv ? displayChannelName.value : name;
        };

        const joinChannel = (ch) => {
          if (!ch) return;
          isSavedView.value = false;
          socket.emit('join_channel', ch);
          showSidebar.value = false;
          unreadCounts.value[ch] = 0;
        };

const startPrivateChat = (targetUsername) => {
  isSavedView.value = false;

  // جلوگیری از ارسال اشتباهی
  currentChannel.value = '';
  messages.value = [];
  isPrivateChat.value = true;
  displayChannelName.value = targetUsername;
  showSidebar.value = false;
  searchResults.value = [];
  searchQuery.value = '';
  unreadCounts.value[targetUsername] = 0;

    socket.emit('join_private', targetUsername, (res) => {
    if (!res || !res.ok) {
        accessDeniedBanner.value = 'خطا در شروع پیام خصوصی: ' + (res?.error || 'NO_ACK');
        return;
    }
    currentChannel.value = res.dmId;
    });
};

        const openSavedView = () => {
        isSavedView.value = true;
        isPrivateChat.value = true; // چون مثل private room است
        displayChannelName.value = 'پیام‌های ذخیره‌شده';
        showSidebar.value = false;

        socket.emit('join_saved');
        };


        // --- Messaging ---
        const sendMessage = () => {
          if (!canSend.value) return;
          socket.emit('send_message', {
            text: messageText.value,
            type: 'text',
            channel: currentChannel.value,
            conversationId: currentChannel.value,
            replyTo: replyingTo.value
          });
          messageText.value = '';
          replyingTo.value = null;
          scrollToBottom(true);
        };

        const handleComposerKeydown = (e) => {
          if (e.key !== 'Enter') return;
          if (e.shiftKey) return;
          e.preventDefault();
          if (!canSend.value) return;
          sendMessage();
        };

        // --- Save message ---
        const saveThisMessage = (msg) => {
          if (!msg) return;
          socket.emit('save_message', {
            originalId: msg.id,
            from: msg.sender,
            channel: msg.channel || msg.conversationId,
            type: msg.type,
            text: msg.text,
            content: msg.content,
            fileName: msg.fileName,
            originalAt: msg.timestamp || null
          });
        };

        const unsave = (id) => {
        if (!id) return;
        socket.emit('saved_delete', id);
        };

        // --- UPLOAD LOGIC ---
        let mediaRecorder = null;
        let audioChunks = [];
        const fileInput = ref(null);

        const handleFileUpload = (e) => {
          const file = e.target.files[0];
          if (!file) return;

          if (file.size > appSettings.value.maxFileSizeMB * 1024 * 1024) {
            alert('حجم فایل بیشتر از حد مجاز است (' + appSettings.value.maxFileSizeMB + 'MB)');
            e.target.value = '';
            return;
          }

          const formData = new FormData();
          formData.append('file', file);

          isUploading.value = true;
          uploadProgress.value = 0;

          const xhr = new XMLHttpRequest();
          xhr.open('POST', '/upload', true);
          if (uploadToken.value) xhr.setRequestHeader('X-Upload-Token', uploadToken.value);

          xhr.upload.onprogress = (event) => {
            if (event.lengthComputable) {
              uploadProgress.value = Math.round((event.loaded / event.total) * 100);
            }
          };

          xhr.onload = () => {
            if (xhr.status === 200) {
              try {
                const res = JSON.parse(xhr.responseText);
                let type = 'file';
                if (res.mimetype.startsWith('image/')) type = 'image';
                else if (res.mimetype.startsWith('video/')) type = 'video';
                else if (res.mimetype.startsWith('audio/')) type = 'audio';

                const securedUrl = uploadToken.value ? (res.url + '?t=' + encodeURIComponent(uploadToken.value)) : res.url;

                socket.emit('send_message', {
                  text: '',
                  type: type,
                  content: securedUrl,
                  fileName: res.filename,
                  channel: currentChannel.value,
                  conversationId: currentChannel.value,
                  replyTo: replyingTo.value
                });

                replyingTo.value = null;
                scrollToBottom(true);
              } catch (e) { console.error(e); }
            } else {
              alert('Upload Failed: Server Error');
            }
            isUploading.value = false;
            if (fileInput.value) fileInput.value.value = '';
          };

          xhr.onerror = () => {
            isUploading.value = false;
            alert('Upload Network Error');
            if (fileInput.value) fileInput.value.value = '';
          };

          xhr.send(formData);
        };

        // --- Admin Actions ---
        const deleteMessage = (msgId) => {
          if (confirm('آیا مطمئن هستید؟')) socket.emit('delete_message', msgId);
        };

        const createChannel = () => {
          if (newChannelName.value) {
            socket.emit('create_channel', newChannelName.value);
            newChannelName.value = '';
            showCreateChannelInput.value = false;
          }
        };

        const deleteChannel = (ch) => {
          if (confirm('حذف کانال؟')) socket.emit('delete_channel', ch);
        };

        const banUser = (target) => {
          if (confirm('بن کردن کاربر ' + target + ' و حذف پیام‌ها؟')) socket.emit('ban_user', target);
        };

        const unbanUser = (target) => socket.emit('unban_user', target);

        const setRole = (target, role) => socket.emit('set_role', { targetUsername: target, role });

        const openBanList = () => { socket.emit('get_banned_users'); showBanModal.value = true; };

        const saveAdminSettings = () => {
          socket.emit('update_admin_settings', adminSettings.value);
          showAdminSettings.value = false;
        };

        // ✅ Access Modal
        const openAccessModal = (targetUsername) => {
          accessModalUser.value = targetUsername;
          showAccessModal.value = true;
          accessChannels.value = [];
          accessMap.value = {};
          socket.emit('admin_get_user_access', targetUsername);
        };

        const refreshAccessModal = () => {
          if (!accessModalUser.value) return;
          socket.emit('admin_get_user_access', accessModalUser.value);
        };

        const toggleUserAccess = (channel, allow) => {
          if (!accessModalUser.value) return;
          socket.emit('admin_set_user_access', { targetUsername: accessModalUser.value, channel, allow });
        };

        // --- Helpers ---
        const handleUserClick = (u) => { if (u.username !== user.value.username) startPrivateChat(u.username); };
        const showContext = (e, msg) => { contextMenu.value = { visible: true, x: e.pageX, y: e.pageY, target: msg, type: 'message' }; };
        const showUserContext = (e, targetUsername) => { contextMenu.value = { visible: true, x: e.pageX, y: e.pageY, target: targetUsername, type: 'user' }; };

        socket.on('connect', () => { isConnected.value = true; });
        socket.on('disconnect', () => { isConnected.value = false; });

        // --- Socket Events ---
        socket.on('login_success', (data) => {
          isLoggedIn.value = true;
          user.value = { username: data.username, role: data.role };

          channels.value = Array.isArray(data.channels) ? data.channels : [];
          uploadToken.value = data.uploadToken || '';

          if (data.settings) {
            appSettings.value = data.settings;
            if (data.settings.appName) {
              appName.value = data.settings.appName;
              document.title = data.settings.appName;
            }
            if (typeof data.settings.hideUserList === 'boolean') adminSettings.value.hideUserList = data.settings.hideUserList;
            if (typeof data.settings.accessMode === 'string') adminSettings.value.accessMode = data.settings.accessMode;
          }

          localStorage.setItem('chat_user_name', data.username);
          isAuthBusy.value = false;

          // if no accessible channels -> show empty state
          if (channels.value.length > 0) {
            // will be joined via server 'channel_joined'
          } else {
            currentChannel.value = '';
            displayChannelName.value = 'بدون دسترسی';
            messages.value = [];
          }
        });

        socket.on('login_error', (msg) => { error.value = msg; isAuthBusy.value = false; });

        socket.on('force_disconnect', (msg) => { alert(msg); window.location.reload(); });

        socket.on('channel_joined', (data) => {
        currentChannel.value = data.name;

        const saved = !!(data && data.isSaved);
        isSavedView.value = saved;

        isPrivateChat.value = !!data.isPrivate;

        if (saved) {
            displayChannelName.value = 'پیام‌های ذخیره‌شده';
            return;
        }

        if (data.isPrivate) {
            const parts = data.name.split('_pv_');
            displayChannelName.value = parts.find(u => u !== user.value.username) || 'Private';
        } else {
            displayChannelName.value = data.name;
        }
        });

        socket.on('history', (msgs) => {
        messages.value = Array.isArray(msgs) ? msgs : [];
        scrollToBottom(true);
        });

        socket.on('receive_message', (msg) => {
        if (msg.channel === currentChannel.value) {
            const c = document.getElementById('messages-container');
            const isNearBottom = c ? (c.scrollTop + c.clientHeight >= c.scrollHeight - 150) : true;

            messages.value.push(msg);

            if (msg.sender === user.value.username || isNearBottom) scrollToBottom();

            // نوتیف فقط وقتی خارج صفحه است و پیام از خودت نیست
            if (document.hidden && msg.sender !== user.value.username) {
            notify(`پیام جدید در ${displayChannelName.value}`, `${msg.sender}: ${msg.text || 'مدیا'}`);
            }
        } else {
            // unread برای DM و کانال‌ها
            if (msg.channel.includes('_pv_')) {
            const parts = msg.channel.split('_pv_');
            const partner = parts.find(p => p !== user.value.username);
            if (partner) {
                unreadCounts.value[partner] = (unreadCounts.value[partner] || 0) + 1;
                notify(`پیام خصوصی از ${partner}`, msg.text || 'فایل ارسال شد');
            }
            } else {
            unreadCounts.value[msg.channel] = (unreadCounts.value[msg.channel] || 0) + 1;
            }
        }
        });

        socket.on('message_deleted', (data) => {
          if (data.channel === currentChannel.value) {
            messages.value = messages.value.filter(m => m.id !== data.id);
          }
        });

        socket.on('bulk_delete_user', (targetUser) => {
          messages.value = messages.value.filter(m => m.sender !== targetUser);
        });

        socket.on('user_list', (list) => onlineUsers.value = list);
        socket.on('update_channels', (list) => { /* admin-only broadcast; actual per-user list is channels_list */ });

        // ✅ NEW: server sends filtered list here
        socket.on('channels_list', (list) => {
          channels.value = Array.isArray(list) ? list : [];
          // if current channel revoked or deleted, move away
          if (currentChannel.value && !isPrivateChat.value && !isSavedView.value) {
            if (!channels.value.includes(currentChannel.value)) {
              messages.value = [];
              currentChannel.value = '';
              displayChannelName.value = 'بدون دسترسی';
            }
          }
        });

        socket.on('channel_deleted', (ch) => {
          if (currentChannel.value === ch) {
            messages.value = [];
            currentChannel.value = '';
            displayChannelName.value = 'کانال حذف شد';
          }
        });

        socket.on('access_denied', (data) => {
          accessDeniedBanner.value = (data && data.message) ? data.message : 'دسترسی ندارید.';
        });

        socket.on('access_revoked', (data) => {
          accessDeniedBanner.value = (data && data.message) ? data.message : 'دسترسی شما برداشته شد.';
          if (currentChannel.value === (data && data.channel)) {
            messages.value = [];
            currentChannel.value = '';
            displayChannelName.value = 'بدون دسترسی';
          }
        });

        socket.on('banned_list', (list) => bannedUsers.value = list);
        socket.on('action_success', (msg) => { try { alert(msg); } catch { } });
        socket.on('role_update', (newRole) => { user.value.role = newRole; alert('نقش شما تغییر کرد: ' + newRole); });

        // ✅ Access modal data
        socket.on('admin_user_access', (payload) => {
          if (!payload) return;
          if (payload.username !== accessModalUser.value) return;
          accessChannels.value = Array.isArray(payload.channels) ? payload.channels : [];
          accessMap.value = (payload.map && typeof payload.map === 'object') ? payload.map : {};
        });

        // --- UI Utils ---
        const setReply = (msg) => { replyingTo.value = msg; nextTick(() => document.querySelector('textarea')?.focus()); };
        const cancelReply = () => replyingTo.value = null;

        const scrollToMessage = (id) => { document.getElementById('msg-' + id)?.scrollIntoView({ behavior: 'smooth', block: 'center' }); };

        const touchStart = (e, msg) => { swipeStartX.value = e.touches[0].clientX; swipeId.value = msg.id; swipeOffset.value = 0; };
        const touchMove = (e) => { if (!swipeId.value) return; const diff = e.touches[0].clientX - swipeStartX.value; if (diff < 0 && diff > -100) swipeOffset.value = diff; };
        const touchEnd = () => { if (swipeOffset.value < -50) { const msg = messages.value.find(m => m.id === swipeId.value); if (msg) setReply(msg); } swipeId.value = null; swipeOffset.value = 0; };
        const getSwipeStyle = (id) => (swipeId.value === id ? { transform: `translateX(${swipeOffset.value}px)` } : {});

        const searchUser = () => { if (searchQuery.value.length > 2) socket.emit('search_user', searchQuery.value); else searchResults.value = []; };
        const toggleCreateChannel = () => showCreateChannelInput.value = !showCreateChannelInput.value;

        const viewImage = (src) => lightboxImage.value = src;

        const safeLink = (u) => {
          try {
            const s = String(u || '').trim();
            if (!s) return '#';
            // فقط لینک‌های داخلی آپلود
            if (s.startsWith('/uploads/')) return s;
            // data url فقط برای audio (لینک دانلود فایل نیست)
            if (s.startsWith('data:')) return '#';
            // هر چیز دیگه بلاک
            return '#';
          } catch {
            return '#';
          }
        };

        const autoResize = (e) => { e.target.style.height = 'auto'; e.target.style.height = e.target.scrollHeight + 'px'; };

        const toggleRecording = async () => {
          if (isRecording.value) {
            mediaRecorder.stop();
            isRecording.value = false;
          } else {
            try {
              const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
              mediaRecorder = new MediaRecorder(stream);
              audioChunks = [];
              mediaRecorder.ondataavailable = event => audioChunks.push(event.data);
              mediaRecorder.onstop = () => {
                const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
                const reader = new FileReader();
                reader.readAsDataURL(audioBlob);
                reader.onloadend = () => {
                  socket.emit('send_message', {
                    text: '',
                    type: 'audio',
                    content: reader.result,
                    channel: currentChannel.value,
                    conversationId: currentChannel.value,
                    replyTo: replyingTo.value
                  });
                  replyingTo.value = null;
                };
              };
              mediaRecorder.start();
              isRecording.value = true;
            } catch (e) {
              alert('Microphone access denied');
            }
          }
        };

        return {
          // core
          isLoggedIn, user, loginForm, error, login, logout,
          channels, currentChannel, joinChannel, displayChannelName, isPrivateChat, isSavedView,
          messages, messageText, sendMessage, handleFileUpload, fileInput,
          onlineUsers, sortedUsers, searchUser, searchQuery, searchResults, startPrivateChat, handleUserClick,
          showSidebar, toggleCreateChannel, showCreateChannelInput, newChannelName, createChannel, deleteChannel,
          replyingTo, setReply, cancelReply, deleteMessage,
          contextMenu, showContext, showUserContext,
          swipeId, swipeOffset, touchStart, touchMove, touchEnd, getSwipeStyle,
          isRecording, isUploading, uploadProgress, toggleRecording, viewImage, lightboxImage, autoResize, scrollToMessage,
          canCreateChannel, canBan, banUser, unbanUser, setRole,
          showBanModal, openBanList, bannedUsers, unreadCounts, appName,
          showAdminSettings, adminSettings, saveAdminSettings, uploadToken,
          isConnected, isAuthBusy, canSend, handleComposerKeydown, showScrollDown, scrollToBottom,
          // saved
          openSavedView, unsave, saveThisMessage,
          // access UI
          showAccessModal, accessModalUser, accessChannels, accessMap, openAccessModal, toggleUserAccess, refreshAccessModal,
          accessDeniedBanner,
          safeLink
        };
      }
    });


    function safeMount() {

      const el = document.getElementById('app');

      if (!el) {

        console.error('[FATAL] #app not found. Vue cannot mount. Check public/index.html contains <div id="app">.');

        return;

      }

      app.mount(el);

    }



    if (document.readyState === 'loading') {

      document.addEventListener('DOMContentLoaded', safeMount, { once: true });

    } else {

      safeMount();

    }

  </script>
</body>

</html>

EOF


# --- IMPORTANT ---
# For the installer to be truly "single-file", paste your current full index.html content
# in place of __PASTE_YOUR_EXISTING_INDEX_HTML_HERE__ (exactly as you have it).
# (I didn't alter UI to avoid breaking anything.)
echo "[4/6] Applying configuration..."
sed_escape() {
  # escape: \  &  |
  printf '%s' "$1" | sed -e 's/[\/&|\\]/\\&/g'
}
APP_NAME_ESC="$(sed_escape "$APP_NAME_VAL")"
C_DEF_ESC="$(sed_escape "$C_DEF")"
C_DARK_ESC="$(sed_escape "$C_DARK")"
C_LIGHT_ESC="$(sed_escape "$C_LIGHT")"

sed -i "s|__APP_NAME_PLACEHOLDER__|$APP_NAME_ESC|g" public/index.html || true
sed -i "s|__COLOR_DEFAULT__|$C_DEF_ESC|g" public/index.html || true
sed -i "s|__COLOR_DARK__|$C_DARK_ESC|g" public/index.html || true
sed -i "s|__COLOR_LIGHT__|$C_LIGHT_ESC|g" public/index.html || true
echo "[5/6] Installing project dependencies (optimized)..."
# speed: disable audit/fund during install
"$NPM_BIN" config set fund false >/dev/null 2>&1 || true
"$NPM_BIN" config set audit false >/dev/null 2>&1 || true

if [[ -f package-lock.json ]]; then
  "$NPM_BIN" ci --omit=dev
else
  "$NPM_BIN" install --omit=dev
fi

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

json_escape() {
  # Escape JSON string safely:
  # - remove newlines
  # - escape backslash and double-quote
  printf '%s' "$1" | tr -d '\r\n' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

cat > data/config.json <<EOF
{
  "adminUser": "$(json_escape "$ADMIN_USER")",
  "adminPassHash": "$(json_escape "$ADMIN_PASS_HASH")",
  "port": $PORT,
  "maxFileSizeMB": 50,
  "appName": "$(json_escape "$APP_NAME_VAL")",
  "hideUserList": false,
  "allowedOrigins": "$(json_escape "$ALLOWED_ORIGINS")",
  "protectUploads": true,
  "dataEncKey": "$DATA_ENC_KEY"
}
EOF
chmod 600 data/config.json

APP_ENTRY="$(detect_app_entry "$DIR")" || die "Install incomplete: cannot locate app entrypoint."

REQ_FILES=(
  "$DIR/package.json"
  "$APP_ENTRY"
  "$DIR/public/index.html"
  "$DIR/data/config.json"
)

missing=0
for f in "${REQ_FILES[@]}"; do
  if [[ ! -f "$f" ]]; then
    warn "Missing required file: $f"
    missing=1
  fi
done

if (( missing == 1 )); then
  die "Install incomplete: required runtime files are missing."
fi

# Do NOT keep plaintext password around longer than needed
unset ADMIN_PASS
echo "[6/6] Starting server with PM2..."
PM2_NAME="${APP_NAME_VAL}"
APP_ENTRY="$(detect_app_entry "$DIR")" || die "Could not find app entrypoint after install."
"$PM2_BIN" delete "$PM2_NAME" 2>/dev/null || true
PORT="$PORT" "$PM2_BIN" start "$APP_ENTRY" --name "$PM2_NAME" --cwd "$DIR" --update-env
"$PM2_BIN" save

# ---- Optional: enable HTTPS via Nginx + Let's Encrypt (DNS-01) ----
if [[ "${ENABLE_HTTPS:-0}" -eq 1 ]]; then
  log "Configuring HTTPS for: ${DOMAIN_FQDN} (mode: ${DNS_MODE})"
  setup_https_nginx "$DOMAIN_FQDN" "$EMAIL" "$DNS_MODE" "${CF_API_TOKEN:-}" "$PORT"
  ok "HTTPS configured for: https://${DOMAIN_FQDN}"
fi

echo "Creating management tool..."

cat << 'EOF_MENU' > /tmp/node-socketio-chatroom-menu.sh
#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="__PM2_NAME__"
DIR="__DIR__"
CONFIG_FILE="$DIR/data/config.json"
INDEX_FILE="$DIR/public/index.html"

PM2_BIN=""
for p in /usr/bin/pm2 /usr/local/bin/pm2 /bin/pm2; do
  if [[ -x "$p" ]]; then PM2_BIN="$p"; break; fi
done
if [[ -z "$PM2_BIN" ]]; then
  PM2_BIN="$(command -v pm2 2>/dev/null || true)"
fi
if [[ -z "$PM2_BIN" ]]; then
  echo "ERROR: pm2 not found."
  exit 1
fi

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
  trap 'rm -rf "$tmp" >/dev/null 2>&1 || true' RETURN

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
    --exclude "public/uploads/" \
    --exclude "node_modules/" \
    "$tmp/repo/" "$DIR/"

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
    --exclude "public/uploads/" \
    --exclude "node_modules/" \
    "$extracted/" "$DIR/"

  echo "Code synced."
}

update_app() {
  echo "-----------------------------------"
  echo "Updating node-socketio-chatroom..."
  echo "Preserve: data/ , public/uploads/ , config.json"
  echo "-----------------------------------"

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

  echo "[4/5] Restarting PM2 process (refresh script path)..."

  APP_ENTRY=""
  if [[ -f "$DIR/server.js" ]]; then
    APP_ENTRY="$DIR/server.js"
  elif [[ -f "$DIR/src/server.js" ]]; then
    APP_ENTRY="$DIR/src/server.js"
  elif [[ -f "$DIR/package.json" ]]; then
    APP_ENTRY="$(node -e "const p=require('$DIR/package.json');process.stdout.write(p.main||'')" 2>/dev/null || true)"
    [[ -n "$APP_ENTRY" ]] && APP_ENTRY="$DIR/$APP_ENTRY"
  fi

  if [[ -z "$APP_ENTRY" || ! -f "$APP_ENTRY" ]]; then
    echo "ERROR: Could not detect app entrypoint after update."
    return 1
  fi

  "$PM2_BIN" delete "$APP_NAME" >/dev/null 2>&1 || true
  "$PM2_BIN" start "$APP_ENTRY" --name "$APP_NAME" --cwd "$DIR" --update-env || {
    echo "ERROR: pm2 start failed."
    return 1
  }
  "$PM2_BIN" save >/dev/null 2>&1 || true

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
    1) "$PM2_BIN" status "$APP_NAME"; pause ;;
    2) "$PM2_BIN" restart "$APP_NAME"; echo "Restarted."; pause ;;
    3) "$PM2_BIN" stop "$APP_NAME"; echo "Stopped."; pause ;;
    4) "$PM2_BIN" logs "$APP_NAME" --lines 50 ;;
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
          "$PM2_BIN" restart "$APP_NAME"
          ;;
        b)
          read -r -p "New Password: " NEW_PASS
          node -e "const fs=require('fs');const bcrypt=require('bcryptjs');const p='$CONFIG_FILE';const d=JSON.parse(fs.readFileSync(p));d.adminPassHash=bcrypt.hashSync(String(process.env.NEW_PASS||''),12);delete d.adminPass;fs.writeFileSync(p, JSON.stringify(d,null,2));" NEW_PASS="$NEW_PASS"
          "$PM2_BIN" restart "$APP_NAME"
          ;;
        c)
          read -r -p "New Max Size (MB): " NEW_SIZE
          if [[ "$NEW_SIZE" =~ ^[0-9]+$ ]]; then
            node -e "const fs=require('fs');const p='$CONFIG_FILE';const d=JSON.parse(fs.readFileSync(p));d.maxFileSizeMB=Number(process.env.NEW_SIZE);fs.writeFileSync(p, JSON.stringify(d,null,2));" NEW_SIZE="$NEW_SIZE"
            "$PM2_BIN" restart "$APP_NAME"
          else
            echo "Invalid number."
          fi
          ;;
        d)
          read -r -p "New App Name: " NEW_APP_NAME
          node -e "const fs=require('fs');const p='$CONFIG_FILE';const d=JSON.parse(fs.readFileSync(p));d.appName=String(process.env.NEW_APP_NAME||'').trim();fs.writeFileSync(p, JSON.stringify(d,null,2));" NEW_APP_NAME="$NEW_APP_NAME"

          # Escape for sed replacement
          NEW_APP_ESC="$(printf '%s' "$NEW_APP_NAME" | tr -d '\r\n' | sed -e 's/[\/&|\\]/\\&/g')"

          sed -i "s|<title>.*</title>|<title>$NEW_APP_ESC</title>|g" "$INDEX_FILE" 2>/dev/null || true
          sed -i "s|appName = ref('.*');|appName = ref('$NEW_APP_ESC');|g" "$INDEX_FILE" 2>/dev/null || true

          "$PM2_BIN" restart "$APP_NAME"
          ;;
        e)
          read -r -p "Allowed Origins (comma-separated or *): " NEW_ORIGINS
          node -e "const fs=require('fs');const p='$CONFIG_FILE';const d=JSON.parse(fs.readFileSync(p));d.allowedOrigins=String(process.env.NEW_ORIGINS||'*').trim();fs.writeFileSync(p, JSON.stringify(d,null,2));" NEW_ORIGINS="$NEW_ORIGINS"
          "$PM2_BIN" restart "$APP_NAME"
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
        "$PM2_BIN" delete "$APP_NAME" || true
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

DIR_ESC="$(sed_escape "$DIR")"
PM2_NAME_ESC="$(sed_escape "$PM2_NAME")"

sed -i "s|__DIR__|$DIR_ESC|g" /tmp/node-socketio-chatroom-menu.sh
sed -i "s|__PM2_NAME__|$PM2_NAME_ESC|g" /tmp/node-socketio-chatroom-menu.sh

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

if [[ "${ENABLE_HTTPS:-0}" -eq 1 ]]; then
  echo "Access URL (HTTPS): https://${DOMAIN_FQDN}"
  echo ""
  echo "Nginx is reverse-proxying to: http://127.0.0.1:${PORT} (WebSocket enabled)"
  echo "HTTP -> HTTPS redirect: enabled"
  echo ""
  if [[ "${DNS_MODE:-}" == "manual" ]]; then
    echo "NOTE: Manual DNS mode = renewal is MANUAL (no auto-renew)."
    echo "You must renew before expiry using:"
    echo "  sudo certbot certonly --manual --preferred-challenges dns -d ${DOMAIN_FQDN}"
  else
    if [[ "${CERTBOT_DRYRUN_OK:-0}" -eq 1 ]]; then
      echo "Auto-renew: certbot timer should handle renewals."
      echo "You can test with:"
      echo "  sudo certbot renew --dry-run"
    else
      echo "Auto-renew: WARNING — renewal dry-run failed."
      echo "Fix Cloudflare token/permissions and check logs:"
      echo "  sudo certbot renew --dry-run"
      echo "  sudo tail -n 200 /var/log/letsencrypt/letsencrypt.log"
    fi
  fi
else
  echo "Access URL: http://$IP:$PORT"
fi

echo ""
echo "Type 'node-socketio-chatroom' in terminal to manage your server."
echo "========================================"