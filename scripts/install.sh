#!/usr/bin/env bash
# =============================================================================
# Oosoft SecurePanel — One-Command Production Installer
# =============================================================================
# Supported:  AlmaLinux 8 / 9  ·  Ubuntu 22.04 LTS
#
# Basic usage (SSL configured later):
#   curl -sSL https://oosoft.co.in/install.sh | bash
#
# With automatic SSL provisioning (DNS must already point here):
#   curl -sSL https://oosoft.co.in/install.sh | \
#     PANEL_DOMAIN=panel.example.com ADMIN_EMAIL=admin@example.com bash
#
# Non-interactive / CI:
#   PANEL_DOMAIN=panel.example.com ADMIN_EMAIL=admin@example.com \
#   PANEL_YES=1 bash install.sh
#
# Environment overrides:
#   PANEL_DOMAIN   Hostname for the panel (e.g. panel.example.com)
#   ADMIN_EMAIL    Email for Let's Encrypt notifications
#   PANEL_YES=1    Skip all confirmation prompts
#   REPO_URL       Override Git repository URL
#   DB_PASSWORD    Use a specific DB password (auto-generated if unset)
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

# ─── Constants ────────────────────────────────────────────────────────────────
readonly INSTALLER_VERSION="1.0.0"
readonly INSTALL_DIR="/opt/oosoft-securepanel"
readonly VENV_DIR="${INSTALL_DIR}/venv"
readonly BACKEND_DIR="${INSTALL_DIR}/backend"
readonly SYSTEMD_SRC="${INSTALL_DIR}/systemd"
readonly LOG_DIR="/var/log/securepanel"
readonly RUN_DIR="/run/securepanel"
readonly STATE_DIR="/var/securepanel"
readonly ACME_WEBROOT="/var/www/letsencrypt"
readonly PANEL_USER="securepanel"
readonly PANEL_GROUP="securepanel"
readonly HOSTING_GROUP="securepanel_users"
readonly NGINX_CONF_D="/etc/nginx/conf.d"
readonly NGINX_SNIPPETS="/etc/nginx/snippets"
readonly INSTALL_LOG="/var/log/securepanel-install.log"

# Operator-configurable (via env vars, not readonly)
PANEL_DOMAIN="${PANEL_DOMAIN:-}"
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
PANEL_YES="${PANEL_YES:-0}"
REPO_URL="${REPO_URL:-https://github.com/oosoft-tech/oosoft-securepanel.git}"
DB_PASSWORD="${DB_PASSWORD:-}"
SECRET_KEY="${SECRET_KEY:-}"

# Runtime state
OS_FAMILY=""    # "rhel" | "debian"
OS_CODENAME=""  # "al8" | "al9" | "jammy"

# ─── Colours (disabled when stdout is not a terminal) ─────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

# ─── Logging ──────────────────────────────────────────────────────────────────
# Pre-create the log file parent (LOG_DIR may not exist yet at script start)
mkdir -p "$(dirname "$INSTALL_LOG")"

_ts()  { date '+%H:%M:%S'; }
log()  { echo -e "${GREEN}▶${NC}  [$(_ts)] $*"   | tee -a "$INSTALL_LOG"; }
info() { echo -e "      ${DIM}$*${NC}"            | tee -a "$INSTALL_LOG"; }
warn() { echo -e "${YELLOW}⚠${NC}  [$(_ts)] $*"  | tee -a "$INSTALL_LOG"; }
err()  { echo -e "${RED}✗${NC}  [$(_ts)] $*"      | tee -a "$INSTALL_LOG" >&2; }
die()  { err "$*"; exit 1; }
step() {
    echo | tee -a "$INSTALL_LOG"
    echo -e "${CYAN}${BOLD}━━  $*  ━━${NC}" | tee -a "$INSTALL_LOG"
}

# ─── Error trap ───────────────────────────────────────────────────────────────
trap '_on_error $LINENO' ERR
_on_error() {
    err "Fatal error at line $1."
    err "Full log: $INSTALL_LOG"
    err "Fix the issue and re-run — the installer is idempotent."
    exit 1
}

# =============================================================================
# OS DETECTION
# =============================================================================

detect_os() {
    step "Detecting operating system"

    [[ -f /etc/os-release ]] || die "/etc/os-release not found — cannot determine OS."

    # shellcheck source=/dev/null
    source /etc/os-release

    local id="${ID:-unknown}"
    local ver="${VERSION_ID:-0}"

    case "$id" in
        almalinux|alma)
            OS_FAMILY="rhel"
            case "${ver%%.*}" in
                8) OS_CODENAME="al8" ;;
                9) OS_CODENAME="al9" ;;
                *) die "AlmaLinux ${ver} is not supported. Supported: 8, 9." ;;
            esac
            ;;
        ubuntu)
            OS_FAMILY="debian"
            case "$ver" in
                22.04) OS_CODENAME="jammy" ;;
                *)     die "Ubuntu ${ver} is not supported. Supported: 22.04." ;;
            esac
            ;;
        *)
            die "OS '${id}' is not supported. Supported: AlmaLinux 8/9, Ubuntu 22.04."
            ;;
    esac

    log "OS: ${PRETTY_NAME:-${id} ${ver}}  (family=${OS_FAMILY}, codename=${OS_CODENAME})"
}

# =============================================================================
# PREFLIGHT CHECKS
# =============================================================================

check_root() {
    [[ $EUID -eq 0 ]] || die "Must be run as root.  Try:  sudo bash $0"
}

check_resources() {
    local ram_kb disk_avail_kb
    ram_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
    disk_avail_kb=$(df --output=avail / 2>/dev/null | tail -1 || echo 0)

    (( ram_kb >= 786432 )) || \
        warn "< 1 GB RAM detected (${ram_kb} kB). Panel may run slowly."
    (( disk_avail_kb >= 4194304 )) || \
        warn "< 4 GB free on /  (${disk_avail_kb} kB). Ensure enough disk space."

    info "RAM:  $(( ram_kb / 1024 )) MB    Disk free: $(( disk_avail_kb / 1024 )) MB"
}

confirm() {
    # Usage: confirm "Do you want to ...?" || die "cancelled"
    [[ "$PANEL_YES" == "1" ]] && return 0
    local answer
    # Works even when stdin is a pipe (curl | bash) by reading from /dev/tty
    if [[ -e /dev/tty ]]; then
        read -r -p "$* [y/N] " answer </dev/tty
    else
        answer="n"
    fi
    [[ "${answer,,}" == "y" ]]
}

# =============================================================================
# PACKAGE INSTALLATION
# =============================================================================

install_packages() {
    step "Installing system packages"

    case "$OS_FAMILY" in
        rhel)   _install_packages_rhel ;;
        debian) _install_packages_debian ;;
    esac

    command -v python3.11 &>/dev/null || die "python3.11 not found after package install."
    log "Python: $(python3.11 --version)"
    log "nginx:  $(nginx -v 2>&1 | head -1)"
    log "git:    $(git --version)"
}

_install_packages_rhel() {
    log "Updating system (dnf)..."
    dnf -y -q update

    log "Installing EPEL repository..."
    dnf -y -q install epel-release

    # Enable CodeReady Builder / PowerTools (provides -devel packages)
    dnf -y -q install dnf-plugins-core
    if [[ "$OS_CODENAME" == "al9" ]]; then
        dnf config-manager --set-enabled crb 2>/dev/null || true
    else
        dnf config-manager --set-enabled powertools 2>/dev/null || \
        dnf config-manager --set-enabled PowerTools 2>/dev/null || true
    fi

    log "Installing core packages..."
    dnf -y -q install \
        curl wget git tar unzip openssl \
        nginx \
        redis \
        certbot python3-certbot-nginx \
        python3.11 python3.11-devel python3.11-pip \
        postgresql-server postgresql postgresql-contrib \
        libpq-devel \
        gcc gcc-c++ make \
        firewalld \
        logrotate \
        rsync \
        bind-utils       # provides getent / nslookup for DNS checks

    # python3.11 might need module install on older AL8 builds
    if ! command -v python3.11 &>/dev/null; then
        dnf -y -q module enable python3.11 2>/dev/null && \
        dnf -y -q module install python3.11 || \
        die "Could not install Python 3.11. Install it manually and re-run."
    fi
}

_install_packages_debian() {
    export DEBIAN_FRONTEND=noninteractive

    log "Updating package cache (apt)..."
    apt-get -y -qq update

    log "Installing prerequisites..."
    apt-get -y -qq install \
        curl wget git tar unzip openssl software-properties-common \
        gnupg2 lsb-release

    # Python 3.11 is in deadsnakes PPA for reliable install on 22.04
    log "Adding deadsnakes PPA for Python 3.11..."
    add-apt-repository -y ppa:deadsnakes/python 2>/dev/null || true
    apt-get -y -qq update

    log "Installing core packages..."
    apt-get -y -qq install \
        nginx \
        redis-server \
        certbot python3-certbot-nginx \
        python3.11 python3.11-dev python3.11-venv \
        postgresql postgresql-client libpq-dev \
        gcc g++ make \
        ufw \
        logrotate \
        rsync \
        dnsutils       # provides getent / dig for DNS checks
}

# =============================================================================
# SYSTEM USERS AND GROUPS
# =============================================================================

setup_users() {
    step "Creating system users and groups"

    # Panel service group
    if ! getent group "$PANEL_GROUP" &>/dev/null; then
        groupadd --system "$PANEL_GROUP"
        info "Created group: $PANEL_GROUP"
    else
        info "Group '$PANEL_GROUP' already exists."
    fi

    # Hosting isolation group (all per-domain Linux users join this)
    if ! getent group "$HOSTING_GROUP" &>/dev/null; then
        groupadd --system "$HOSTING_GROUP"
        info "Created group: $HOSTING_GROUP"
    else
        info "Group '$HOSTING_GROUP' already exists."
    fi

    # Panel service account — no interactive login
    if ! id -u "$PANEL_USER" &>/dev/null; then
        useradd \
            --system \
            --gid    "$PANEL_GROUP" \
            --shell  /sbin/nologin \
            --home   "$INSTALL_DIR" \
            --no-create-home \
            "$PANEL_USER"
        info "Created system user: $PANEL_USER"
    else
        info "User '$PANEL_USER' already exists."
    fi

    # Add nginx worker to securepanel group so it can traverse /run/securepanel
    # and read the Unix socket created by the agent.
    if id nginx &>/dev/null; then
        usermod -aG "$PANEL_GROUP" nginx 2>/dev/null || true
        info "nginx added to group '$PANEL_GROUP'."
    elif id www-data &>/dev/null; then
        usermod -aG "$PANEL_GROUP" www-data 2>/dev/null || true
        info "www-data added to group '$PANEL_GROUP'."
    fi
}

# =============================================================================
# DIRECTORY STRUCTURE
# =============================================================================

setup_directories() {
    step "Creating directory structure"

    # Application root — root:root, group-readable
    mkdir -p "$INSTALL_DIR"
    chown root:root "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"

    # Persistent logs — owned by the panel service account
    mkdir -p "$LOG_DIR"
    chown "$PANEL_USER:$PANEL_GROUP" "$LOG_DIR"
    chmod 750 "$LOG_DIR"

    # State / upload directory
    mkdir -p "${STATE_DIR}/migration_uploads"
    chown -R "$PANEL_USER:$PANEL_GROUP" "$STATE_DIR"
    chmod 750 "$STATE_DIR"

    # ACME webroot — nginx must be able to read challenges
    mkdir -p "${ACME_WEBROOT}/.well-known/acme-challenge"
    chmod 755 "$ACME_WEBROOT"
    # Determine nginx user
    local nginx_user="nginx"
    id nginx &>/dev/null || nginx_user="www-data"
    chown -R "${nginx_user}:${nginx_user}" "$ACME_WEBROOT"

    # Volatile runtime directory (/run is tmpfs, wiped on reboot)
    # Create now for immediate use; tmpfiles.d re-creates it on next boot.
    mkdir -p "$RUN_DIR"
    chown "root:$PANEL_GROUP" "$RUN_DIR"
    chmod 750 "$RUN_DIR"

    # tmpfiles.d — survives reboots
    cat > /etc/tmpfiles.d/securepanel.conf << EOF
# Oosoft SecurePanel — recreate volatile runtime dir on boot
# Mode 0750: root can read/write/exec; securepanel group can read/exec
d ${RUN_DIR} 0750 root ${PANEL_GROUP} -
EOF
    systemd-tmpfiles --create /etc/tmpfiles.d/securepanel.conf
    info "tmpfiles.d: $RUN_DIR will be recreated on every boot."

    # nginx dirs
    mkdir -p "$NGINX_CONF_D" "$NGINX_SNIPPETS"

    log "Directory structure: OK"
    info "  $INSTALL_DIR     (application root)"
    info "  $LOG_DIR         (logs)"
    info "  $STATE_DIR        (state / uploads)"
    info "  $ACME_WEBROOT (ACME webroot)"
    info "  $RUN_DIR    (agent + API sockets)"
}

# =============================================================================
# REPOSITORY CLONE / UPDATE
# =============================================================================

clone_repo() {
    step "Deploying application from repository"

    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        log "Repository already present — pulling latest code..."
        git -C "$INSTALL_DIR" fetch --quiet origin
        git -C "$INSTALL_DIR" reset --hard origin/main 2>/dev/null || \
        git -C "$INSTALL_DIR" reset --hard origin/master 2>/dev/null || \
        warn "Could not update repository — continuing with existing code."
    else
        log "Cloning $REPO_URL ..."
        git clone --depth=1 "$REPO_URL" "$INSTALL_DIR"
    fi

    # Sanity checks
    [[ -d "$BACKEND_DIR" ]]                  || die "backend/ not found in repo."
    [[ -f "${BACKEND_DIR}/requirements.txt" ]] || die "requirements.txt not found."

    # Ownership: root owns the code, securepanel group can read it
    chown -R "root:$PANEL_GROUP" "$INSTALL_DIR"
    chmod -R o-rwx "$INSTALL_DIR"    # no world access
    chmod -R g+rX  "$INSTALL_DIR"    # group can read + traverse

    # The .env will be written here — ensure the directory is writable by root
    chmod 750 "$BACKEND_DIR"

    log "Repository: $INSTALL_DIR"
}

# =============================================================================
# PYTHON VIRTUAL ENVIRONMENT
# =============================================================================

setup_venv() {
    step "Setting up Python 3.11 virtual environment"

    log "Creating venv at $VENV_DIR ..."
    python3.11 -m venv "$VENV_DIR"

    log "Upgrading pip / setuptools / wheel..."
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip setuptools wheel

    log "Installing Python dependencies (this may take a few minutes)..."
    "$VENV_DIR/bin/pip" install --quiet -r "${BACKEND_DIR}/requirements.txt"

    # Ownership: root owns, group can execute
    chown -R "root:$PANEL_GROUP" "$VENV_DIR"
    chmod -R o-rwx "$VENV_DIR"
    chmod -R g+rX  "$VENV_DIR"

    log "venv: OK  (Python: $("$VENV_DIR/bin/python" --version))"
}

# =============================================================================
# POSTGRESQL SETUP
# =============================================================================

setup_postgresql() {
    step "Configuring PostgreSQL"

    # Generate a secure random password if not provided
    if [[ -z "$DB_PASSWORD" ]]; then
        DB_PASSWORD=$("${VENV_DIR}/bin/python" -c \
            "import secrets; print(secrets.token_urlsafe(32))")
    fi

    case "$OS_FAMILY" in
        rhel)
            # AlmaLinux ships PostgreSQL without an initialised data directory
            if [[ ! -f /var/lib/pgsql/data/PG_VERSION ]]; then
                log "Initialising PostgreSQL data directory..."
                postgresql-setup --initdb
            fi
            systemctl enable --now postgresql
            ;;
        debian)
            # Ubuntu auto-initialises on package install
            systemctl enable --now postgresql
            ;;
    esac

    # Wait up to 20 s for PostgreSQL to accept connections
    log "Waiting for PostgreSQL to be ready..."
    local retries=10
    until sudo -u postgres pg_isready -q 2>/dev/null; do
        (( retries-- ))
        (( retries > 0 )) || die "PostgreSQL did not become ready after 20 seconds."
        sleep 2
    done
    info "PostgreSQL: accepting connections."

    # Idempotent: create the securepanel role (or update its password)
    sudo -u postgres psql -v ON_ERROR_STOP=0 -q <<SQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'securepanel') THEN
        CREATE USER securepanel WITH LOGIN PASSWORD '${DB_PASSWORD}';
    ELSE
        ALTER USER securepanel WITH PASSWORD '${DB_PASSWORD}';
    END IF;
END
\$\$;
SQL

    # Create the database (idempotent — error suppressed if it already exists)
    sudo -u postgres createdb -O securepanel securepanel 2>/dev/null \
        || info "Database 'securepanel' already exists."

    # On RHEL/AlmaLinux the default pg_hba.conf uses ident auth for localhost.
    # Add an explicit md5 entry for the securepanel user so asyncpg can connect.
    if [[ "$OS_FAMILY" == "rhel" ]]; then
        local pg_hba
        pg_hba=$(sudo -u postgres psql -At -c "SHOW hba_file;" 2>/dev/null \
                 | tr -d ' ')
        if [[ -n "$pg_hba" ]] && ! grep -q "^host.*securepanel.*securepanel" "$pg_hba" 2>/dev/null; then
            # Insert before the first "host" line
            sed -i '/^host/i # Oosoft SecurePanel — md5 auth for securepanel user\nhost    securepanel     securepanel     127.0.0.1\/32     md5\nhost    securepanel     securepanel     ::1\/128          md5' \
                "$pg_hba"
            systemctl reload postgresql
            info "pg_hba.conf: md5 auth added for securepanel@127.0.0.1"
        fi
    fi

    log "PostgreSQL: database 'securepanel' ready."
}

# =============================================================================
# REDIS CHECK
# =============================================================================

setup_redis() {
    step "Configuring Redis"

    # Service name differs between distros
    local redis_svc="redis"
    systemctl enable "$redis_svc" 2>/dev/null \
        || { redis_svc="redis-server"; systemctl enable "$redis_svc"; }
    systemctl start "$redis_svc" || warn "Could not start Redis — check: journalctl -u $redis_svc"

    # Connectivity test
    if command -v redis-cli &>/dev/null; then
        local pong
        pong=$(redis-cli ping 2>/dev/null || echo "FAIL")
        if [[ "$pong" == "PONG" ]]; then
            log "Redis: OK (PONG received)"
        else
            warn "Redis did not respond to PING ($pong) — check the service."
        fi
    fi
}

# =============================================================================
# ENVIRONMENT FILE (.env)
# =============================================================================

generate_env() {
    step "Generating application configuration (.env)"

    local env_file="${BACKEND_DIR}/.env"
    local python_bin="${VENV_DIR}/bin/python"

    # Preserve an existing .env (operator may have already customised it)
    if [[ -f "$env_file" ]]; then
        local backup="${env_file}.bak.$(date +%Y%m%d%H%M%S)"
        cp "$env_file" "$backup"
        info "Existing .env backed up to: $backup"

        # Re-use secrets already in place to avoid invalidating sessions
        local old_secret
        old_secret=$(grep -Po '(?<=^SECRET_KEY=).+' "$env_file" 2>/dev/null || true)
        [[ -n "$old_secret" ]] && SECRET_KEY="$old_secret" \
            && info "Reusing existing SECRET_KEY."
    fi

    # Generate any missing secrets
    [[ -z "$SECRET_KEY"   ]] && \
        SECRET_KEY=$("$python_bin" -c "import secrets; print(secrets.token_hex(32))")
    [[ -z "$DB_PASSWORD"  ]] && \
        DB_PASSWORD=$("$python_bin" -c "import secrets; print(secrets.token_urlsafe(32))")

    # Build ALLOWED_HOSTS / CORS_ORIGINS from the panel domain
    local allowed_hosts='["*"]'
    local cors_origins='[]'
    if [[ -n "$PANEL_DOMAIN" ]]; then
        allowed_hosts="[\"${PANEL_DOMAIN}\"]"
        cors_origins="[\"https://${PANEL_DOMAIN}\"]"
    fi

    cat > "$env_file" << ENV
# ============================================================
# Oosoft SecurePanel — Runtime Configuration
# Generated by installer $(date -Iseconds)
# !! KEEP SECRET — contains credentials and signing keys !!
# ============================================================

APP_ENV=production

# ── JWT signing key ─────────────────────────────────────────
# WARNING: changing this after first start invalidates ALL
# active user sessions. Rotate only when required.
SECRET_KEY=${SECRET_KEY}

# ── Allowed hosts / CORS ────────────────────────────────────
ALLOWED_HOSTS=${allowed_hosts}
CORS_ORIGINS=${cors_origins}

# ── Database ────────────────────────────────────────────────
DATABASE_URL=postgresql+asyncpg://securepanel:${DB_PASSWORD}@127.0.0.1:5432/securepanel

# ── Redis / Celery ──────────────────────────────────────────
REDIS_URL=redis://127.0.0.1:6379/0
CELERY_BROKER_URL=redis://127.0.0.1:6379/1
CELERY_RESULT_BACKEND=redis://127.0.0.1:6379/2

# ── Mail ────────────────────────────────────────────────────
# Set to the primary domain this server handles mail for.
MAIL_DOMAIN=${PANEL_DOMAIN:-example.com}

# ── SSL / Certbot ───────────────────────────────────────────
# Used as the --email argument to certbot for expiry notices.
PANEL_ADMIN_EMAIL=${ADMIN_EMAIL:-ssl-admin@localhost}

# ── AI Assistant (optional) ─────────────────────────────────
# Leave blank to disable. Get a key at console.anthropic.com
ANTHROPIC_API_KEY=

# ── MySQL admin (for database management features) ──────────
# Set this to the MySQL root password if MySQL is installed.
DB_ADMIN_PASSWORD=
ENV

    # Secure permissions: only root and the panel group can read
    chown "root:$PANEL_GROUP" "$env_file"
    chmod 640 "$env_file"

    log ".env written: $env_file  (mode 640, root:${PANEL_GROUP})"
    info "  SECRET_KEY:   generated (${#SECRET_KEY} chars)"
    info "  DATABASE_URL: postgresql+asyncpg://securepanel:***@127.0.0.1:5432/securepanel"
    info "  REDIS_URL:    redis://127.0.0.1:6379/0"
}

# =============================================================================
# DATABASE MIGRATIONS
# =============================================================================

run_migrations() {
    step "Running database migrations (Alembic)"

    local alembic_ini="${BACKEND_DIR}/alembic.ini"
    if [[ ! -f "$alembic_ini" ]]; then
        warn "alembic.ini not found — skipping migrations."
        info "Run manually:  cd $BACKEND_DIR && $VENV_DIR/bin/alembic upgrade head"
        return 0
    fi

    # Export DATABASE_URL from the .env so alembic can connect
    local db_url
    db_url=$(grep -Po '(?<=^DATABASE_URL=).+' "${BACKEND_DIR}/.env" || true)
    if [[ -z "$db_url" ]]; then
        warn "DATABASE_URL not found in .env — skipping migrations."
        return 0
    fi

    log "Running:  alembic upgrade head"
    (
        cd "$BACKEND_DIR"
        DATABASE_URL="$db_url" "$VENV_DIR/bin/alembic" upgrade head
    ) && log "Migrations: OK" \
      || warn "Alembic reported an error. Run manually and check logs."
}

# =============================================================================
# SYSTEMD SERVICE UNITS
# =============================================================================

install_systemd_services() {
    step "Installing systemd service units"

    local services=(
        securepanel-agent
        securepanel
        securepanel-worker
        securepanel-beat
    )

    for svc in "${services[@]}"; do
        local src="${SYSTEMD_SRC}/${svc}.service"
        local dst="/etc/systemd/system/${svc}.service"

        if [[ ! -f "$src" ]]; then
            warn "  Service file not found: $src — skipping."
            continue
        fi

        cp "$src" "$dst"

        # Patch securepanel-agent: the service file shipped in the repo
        # still references /etc/nginx/sites-enabled (Ubuntu-style path).
        # The nginx handler code uses /etc/nginx/conf.d — fix it here.
        if [[ "$svc" == "securepanel-agent" ]]; then
            sed -i "s|/etc/nginx/sites-enabled|${NGINX_CONF_D}|g" "$dst"
            # Also add /var/www to ReadWritePaths so the agent can create webroots
            sed -i "s|ReadWritePaths=|ReadWritePaths=/var/www |" "$dst"
            info "  Patched agent ReadWritePaths: sites-enabled → conf.d, added /var/www"
        fi

        chmod 644 "$dst"
        info "  Installed: ${svc}.service"
    done

    # certbot-renewal: create inline if not in repo
    _install_certbot_units

    systemctl daemon-reload
    log "systemd: daemon-reload complete."
}

_install_certbot_units() {
    local svc_src="${SYSTEMD_SRC}/certbot-renewal.service"
    local tmr_src="${SYSTEMD_SRC}/certbot-renewal.timer"

    # Service
    if [[ -f "$svc_src" ]]; then
        cp "$svc_src" /etc/systemd/system/certbot-renewal.service
    else
        cat > /etc/systemd/system/certbot-renewal.service << 'EOF'
[Unit]
Description=Certbot Certificate Renewal
Documentation=https://certbot.eff.org/docs/
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet --no-random-sleep-on-renew
PrivateTmp=yes
EOF
        info "  Created certbot-renewal.service (inline)."
    fi
    chmod 644 /etc/systemd/system/certbot-renewal.service

    # Timer
    if [[ -f "$tmr_src" ]]; then
        cp "$tmr_src" /etc/systemd/system/certbot-renewal.timer
    else
        cat > /etc/systemd/system/certbot-renewal.timer << 'EOF'
[Unit]
Description=Twice-daily Let's Encrypt certificate renewal
Documentation=https://certbot.eff.org/docs/
After=network-online.target

[Timer]
# Run at a random time within ±1 hour of 04:00 and 16:00 each day.
OnCalendar=*-*-* 04:00:00
OnCalendar=*-*-* 16:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF
        info "  Created certbot-renewal.timer (inline)."
    fi
    chmod 644 /etc/systemd/system/certbot-renewal.timer

    info "  Installed: certbot-renewal.service + certbot-renewal.timer"
}

# =============================================================================
# LOG ROTATION
# =============================================================================

setup_logrotate() {
    step "Configuring log rotation"

    cat > /etc/logrotate.d/securepanel << 'EOF'
/var/log/securepanel/*.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0640 securepanel securepanel
    sharedscripts
    postrotate
        # Signal gunicorn to re-open log file handles after rotation.
        systemctl kill --signal=USR1 securepanel 2>/dev/null || true
    endscript
}
EOF
    log "logrotate: daily, 90-day retention, compress — /var/log/securepanel/*.log"
}

# =============================================================================
# NGINX CONFIGURATION (BOOTSTRAP)
# =============================================================================

setup_nginx() {
    step "Configuring nginx (HTTP bootstrap)"

    local bootstrap_src="${INSTALL_DIR}/nginx/panel-bootstrap.conf"
    local panel_conf="${NGINX_CONF_D}/panel.conf"

    if [[ -f "$bootstrap_src" ]]; then
        if [[ -n "$PANEL_DOMAIN" ]]; then
            sed "s/panel\.example\.com/$PANEL_DOMAIN/g" "$bootstrap_src" \
                > "$panel_conf"
        else
            cp "$bootstrap_src" "$panel_conf"
        fi
    else
        # Fallback: write minimal bootstrap inline
        _write_nginx_bootstrap "$panel_conf"
    fi
    chmod 644 "$panel_conf"

    # Validate and enable
    if nginx -t 2>/dev/null; then
        systemctl enable nginx
        systemctl restart nginx 2>/dev/null || systemctl start nginx
        log "nginx: running  (bootstrap config active)."
    else
        warn "nginx -t failed — check $panel_conf. nginx not started."
        nginx -t  # print the actual error
    fi
}

_write_nginx_bootstrap() {
    local dest="$1"
    local sn="${PANEL_DOMAIN:-_}"
    cat > "$dest" << NGINXEOF
# Oosoft SecurePanel — HTTP Bootstrap
# Replace with HTTPS config after running ssl-setup.sh

server {
    listen      80 default_server;
    listen      [::]:80 default_server;
    server_name ${sn};

    # ACME challenge path (required for certbot to obtain the certificate)
    location /.well-known/acme-challenge/ {
        root         /var/www/letsencrypt;
        default_type "text/plain";
        try_files    \$uri =404;
    }

    # Block all other requests until SSL is configured
    location / {
        return 503 "Panel configuration in progress.";
        add_header Content-Type "text/plain" always;
    }
}
NGINXEOF
}

# =============================================================================
# FIREWALL
# =============================================================================

setup_firewall() {
    step "Configuring firewall"

    case "$OS_FAMILY" in
        rhel)   _setup_firewall_firewalld ;;
        debian) _setup_firewall_ufw ;;
    esac
}

_setup_firewall_firewalld() {
    if ! command -v firewall-cmd &>/dev/null; then
        warn "firewalld not found — skipping firewall setup."
        return
    fi

    systemctl enable --now firewalld

    # Ensure SSH is not accidentally removed
    firewall-cmd --permanent --add-service=ssh   --quiet 2>/dev/null || true
    # Open HTTP and HTTPS for the panel and hosted sites
    firewall-cmd --permanent --add-service=http  --quiet
    firewall-cmd --permanent --add-service=https --quiet
    # Remove Cockpit (often enabled by default on AlmaLinux, unnecessary here)
    firewall-cmd --permanent --remove-service=cockpit --quiet 2>/dev/null || true

    firewall-cmd --reload --quiet
    log "firewalld: SSH(22) + HTTP(80) + HTTPS(443) open."
    info "  Verify:  firewall-cmd --list-all"
}

_setup_firewall_ufw() {
    if ! command -v ufw &>/dev/null; then
        warn "ufw not found — skipping firewall setup."
        return
    fi

    # Allow SSH before enabling to prevent lockout
    ufw allow OpenSSH  --force 2>/dev/null || ufw allow 22/tcp --force
    ufw allow 80/tcp   --force
    ufw allow 443/tcp  --force
    ufw --force enable

    log "ufw: SSH(22) + HTTP(80) + HTTPS(443) allowed."
    info "  Verify:  ufw status verbose"
}

# =============================================================================
# START SERVICES
# =============================================================================

start_services() {
    step "Enabling and starting panel services"

    # 1. Agent must start before the API (API checks for agent socket at startup)
    systemctl enable securepanel-agent
    if ! systemctl restart securepanel-agent; then
        warn "securepanel-agent failed to start."
        warn "Check:  journalctl -u securepanel-agent --no-pager -n 30"
    fi

    # Give the agent up to 8 s to create its Unix socket
    local socket="${RUN_DIR}/agent.sock"
    local retries=8
    while [[ ! -S "$socket" ]] && (( retries-- > 0 )); do sleep 1; done
    if [[ -S "$socket" ]]; then
        info "  Agent socket:  $socket  ✓"
    else
        warn "  Agent socket not visible yet — API will retry on start."
    fi

    # 2. API + async workers
    for svc in securepanel securepanel-worker securepanel-beat; do
        systemctl enable "$svc"
        if ! systemctl restart "$svc"; then
            warn "$svc failed to start — check: journalctl -u $svc --no-pager -n 30"
        fi
        local st
        st=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
        info "  ${svc}: $st"
    done

    # 3. Certbot renewal timer
    systemctl enable --now certbot-renewal.timer 2>/dev/null || true
    info "  certbot-renewal.timer: enabled"

    log "Services started."
}

# =============================================================================
# SSL SETUP (OPTIONAL — runs only when PANEL_DOMAIN + ADMIN_EMAIL are set)
# =============================================================================

maybe_setup_ssl() {
    step "SSL Certificate Setup"

    local ssl_script="${INSTALL_DIR}/scripts/ssl-setup.sh"

    # Guard: need both domain and email
    if [[ -z "$PANEL_DOMAIN" ]] || [[ -z "$ADMIN_EMAIL" ]]; then
        info "PANEL_DOMAIN or ADMIN_EMAIL not set — skipping automatic SSL."
        info "Run ssl-setup.sh manually once DNS is configured:"
        info "  PANEL_DOMAIN=panel.example.com \\"
        info "  ADMIN_EMAIL=admin@example.com \\"
        info "  bash ${ssl_script}"
        return
    fi

    if [[ ! -f "$ssl_script" ]]; then
        warn "ssl-setup.sh not found at $ssl_script — skipping SSL."
        return
    fi

    # DNS check: abort early rather than burning a certbot rate-limit attempt
    local resolved_ip
    resolved_ip=$(getent hosts "$PANEL_DOMAIN" | awk '{print $1}' 2>/dev/null || true)
    if [[ -z "$resolved_ip" ]]; then
        warn "DNS: $PANEL_DOMAIN does not resolve yet."
        info "Point an A record here, then run ssl-setup.sh manually."
        return
    fi
    log "DNS: $PANEL_DOMAIN → $resolved_ip"

    log "Launching ssl-setup.sh for $PANEL_DOMAIN ..."
    PANEL_DOMAIN="$PANEL_DOMAIN" \
    ADMIN_EMAIL="$ADMIN_EMAIL" \
    INSTALL_DIR="$INSTALL_DIR" \
    PANEL_YES="$PANEL_YES" \
    bash "$ssl_script" \
        && log "SSL setup: OK" \
        || warn "ssl-setup.sh encountered an error — check its output above."
}

# =============================================================================
# FINAL BANNER
# =============================================================================

print_banner() {
    # Determine panel URL
    local proto="http"
    [[ -f "/etc/letsencrypt/live/${PANEL_DOMAIN:-}/fullchain.pem" ]] && proto="https"
    local panel_url="${proto}://${PANEL_DOMAIN:-$(hostname -I | awk '{print $1}')}"

    echo
    echo -e "${GREEN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════════════╗"
    echo "  ║                                                                  ║"
    echo "  ║      ✓  Oosoft SecurePanel — Installation Complete              ║"
    echo "  ║                                                                  ║"
    echo "  ╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # Access info
    echo -e "  ${CYAN}Panel URL:${NC}         ${BOLD}${panel_url}${NC}"
    echo -e "  ${CYAN}Install directory:${NC} $INSTALL_DIR"
    echo -e "  ${CYAN}Configuration:${NC}     ${BACKEND_DIR}/.env"
    echo -e "  ${CYAN}Logs:${NC}              $LOG_DIR"
    echo -e "  ${CYAN}Install log:${NC}       $INSTALL_LOG"
    echo

    # Service status table
    echo -e "  ${BOLD}Service status:${NC}"
    for svc in securepanel-agent securepanel securepanel-worker securepanel-beat; do
        local st
        st=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
        if [[ "$st" == "active" ]]; then
            echo -e "    ${GREEN}●${NC} $svc"
        else
            echo -e "    ${RED}●${NC} $svc  (${YELLOW}${st}${NC})"
        fi
    done
    echo

    # Pending tasks (SSL, configuration)
    local needs_attention=0

    if [[ -z "$PANEL_DOMAIN" ]] || \
       [[ ! -f "/etc/letsencrypt/live/${PANEL_DOMAIN:-}/fullchain.pem" ]]; then
        (( needs_attention++ ))
        echo -e "  ${YELLOW}${BOLD}Action required — SSL not yet configured:${NC}"
        echo
        echo    "    1. Edit the configuration file and fill in any remaining values:"
        echo    "         nano ${BACKEND_DIR}/.env"
        echo
        echo    "    2. Point your DNS A record for your panel domain to this server's IP."
        echo
        echo    "    3. Run ssl-setup.sh to obtain a Let's Encrypt certificate:"
        echo    "         PANEL_DOMAIN=panel.example.com \\"
        echo    "         ADMIN_EMAIL=admin@example.com \\"
        echo    "         bash ${INSTALL_DIR}/scripts/ssl-setup.sh"
        echo
        echo    "    4. After .env changes, restart panel services:"
        echo    "         systemctl restart securepanel securepanel-worker securepanel-beat"
        echo
    fi

    echo -e "  ${BOLD}Useful commands:${NC}"
    echo    "    journalctl -u securepanel        -f    # API logs (live)"
    echo    "    journalctl -u securepanel-agent  -f    # Agent logs (live)"
    echo    "    journalctl -u securepanel-worker -f    # Worker logs (live)"
    echo    "    systemctl  status  securepanel         # Service status"
    echo    "    bash ${INSTALL_DIR}/scripts/hardening.sh  # Post-install hardening"
    echo
    echo -e "  ${DIM}Install log saved to: $INSTALL_LOG${NC}"
    echo
}

# =============================================================================
# ENTRY POINT
# =============================================================================

main() {
    # ── Header ────────────────────────────────────────────────────────────────
    echo -e "${CYAN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════════════╗"
    echo "  ║     Oosoft SecurePanel — Production Installer v${INSTALLER_VERSION}            ║"
    echo "  ║     $(date '+%Y-%m-%d  %H:%M:%S  %Z')                              ║"
    echo "  ╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${DIM}Full log:  $INSTALL_LOG${NC}"
    echo

    # ── Preflight ─────────────────────────────────────────────────────────────
    check_root
    detect_os
    check_resources

    if [[ "$PANEL_YES" != "1" ]] && [[ -t 1 ]]; then
        echo -e "  This will install Oosoft SecurePanel on ${BOLD}$(hostname -f)${NC}."
        if [[ -n "$PANEL_DOMAIN" ]]; then
            echo -e "  Panel domain:  ${BOLD}$PANEL_DOMAIN${NC}"
        fi
        confirm "  Proceed with installation?" \
            || die "Installation cancelled."
    fi

    # ── Install steps ─────────────────────────────────────────────────────────
    install_packages
    setup_users
    setup_directories
    clone_repo
    setup_venv
    setup_postgresql
    setup_redis
    generate_env
    run_migrations
    install_systemd_services
    setup_logrotate
    setup_nginx
    setup_firewall
    start_services
    maybe_setup_ssl

    # ── Done ──────────────────────────────────────────────────────────────────
    print_banner
}

main "$@"
