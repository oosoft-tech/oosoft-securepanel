#!/usr/bin/env bash
# =============================================================================
# Oosoft SecurePanel — One-Command Production Installer
# =============================================================================
# Supported:  AlmaLinux 8 / 9  ·  Ubuntu 22.04 LTS
#
# Idempotent — safe to run on a fresh server or on an existing installation.
# Re-running upgrades code, fixes permissions, and restarts only what changed.
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
#   PANEL_DOMAIN      Hostname for the panel  (e.g. panel.example.com)
#   ADMIN_EMAIL       Email for Let's Encrypt notifications
#   PANEL_YES=1       Skip all confirmation prompts
#   REPO_URL          Override Git repository URL
#   DB_PASSWORD       Use a specific DB password (auto-generated if unset)
#   FORCE_VENV=1      Recreate the Python venv even if it already looks good
#   FORCE_NGINX=1     Overwrite the nginx config even if HTTPS is already live
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

# ─── Version ──────────────────────────────────────────────────────────────────
readonly INSTALLER_VERSION="1.1.0"

# ─── Paths ────────────────────────────────────────────────────────────────────
readonly INSTALL_DIR="/opt/oosoft-securepanel"
readonly VENV_DIR="${INSTALL_DIR}/venv"
readonly BACKEND_DIR="${INSTALL_DIR}/backend"
readonly SYSTEMD_SRC="${INSTALL_DIR}/systemd"
readonly LOG_DIR="/var/log/securepanel"
readonly RUN_DIR="/run/securepanel"
readonly STATE_DIR="/var/securepanel"
readonly ACME_WEBROOT="/var/www/letsencrypt"
readonly NGINX_CONF_D="/etc/nginx/conf.d"
readonly NGINX_SNIPPETS="/etc/nginx/snippets"
readonly INSTALL_LOG="/var/log/securepanel-install.log"

# State file — persists metadata about the installed panel across runs
readonly STATE_FILE="${INSTALL_DIR}/.panel-state"

# ─── Fixed identities ────────────────────────────────────────────────────────
readonly PANEL_USER="securepanel"
readonly PANEL_GROUP="securepanel"
readonly HOSTING_GROUP="securepanel_users"
readonly REQUIRED_PYTHON_MINOR="11"   # require 3.11.x

# ─── Operator-configurable (env vars) ────────────────────────────────────────
PANEL_DOMAIN="${PANEL_DOMAIN:-}"
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
PANEL_YES="${PANEL_YES:-0}"
REPO_URL="${REPO_URL:-https://github.com/oosoft-tech/oosoft-securepanel.git}"
DB_PASSWORD="${DB_PASSWORD:-}"
SECRET_KEY="${SECRET_KEY:-}"
FORCE_VENV="${FORCE_VENV:-0}"
FORCE_NGINX="${FORCE_NGINX:-0}"

# ─── Runtime state (set during execution) ────────────────────────────────────
OS_FAMILY=""            # "rhel" | "debian"
OS_CODENAME=""          # "al8" | "al9" | "jammy"
IS_UPGRADE=0            # 1 when an existing installation is detected
PREV_VERSION=""         # version string from the state file
UNITS_CHANGED=0         # 1 when at least one systemd unit was updated

# ─── Colours (disabled when stdout is not a terminal) ─────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

# ─── Logging ──────────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$INSTALL_LOG")"
_ts()  { date '+%H:%M:%S'; }
log()  { echo -e "${GREEN}▶${NC}  [$(_ts)] $*"   | tee -a "$INSTALL_LOG"; }
info() { echo -e "      ${DIM}$*${NC}"            | tee -a "$INSTALL_LOG"; }
warn() { echo -e "${YELLOW}⚠${NC}  [$(_ts)] $*"  | tee -a "$INSTALL_LOG"; }
err()  { echo -e "${RED}✗${NC}  [$(_ts)] $*"      | tee -a "$INSTALL_LOG" >&2; }
skip() { echo -e "      ${DIM}↷  $* — skipped (already done)${NC}" | tee -a "$INSTALL_LOG"; }
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
    err "The installer is idempotent — fix the issue and re-run."
    exit 1
}

# =============================================================================
# .ENV HELPERS
# Interact with backend/.env safely — never lose existing values.
# =============================================================================

# Return the value of KEY from .env, or empty string.
_env_get() {
    local key="$1" env="${BACKEND_DIR}/.env"
    [[ -f "$env" ]] || { echo ""; return; }
    grep -Po "(?<=^${key}=).+" "$env" 2>/dev/null || echo ""
}

# Return 0 if KEY is present and non-empty in .env.
_env_has() {
    local key="$1"
    local val
    val=$(_env_get "$key")
    [[ -n "$val" ]]
}

# Append KEY=VALUE to .env only if KEY is not already set.
# Never overwrites an existing value — safe to call unconditionally.
_env_ensure() {
    local key="$1" value="$2" env="${BACKEND_DIR}/.env"
    if _env_has "$key"; then
        return 0  # already there — leave it alone
    fi
    echo "${key}=${value}" >> "$env"
    info "  .env ← added: $key"
}

# =============================================================================
# STATE FILE
# Tracks installed version and first-install metadata across runs.
# =============================================================================

_read_state() {
    [[ -f "$STATE_FILE" ]] || return 0
    # shellcheck source=/dev/null
    source "$STATE_FILE" 2>/dev/null || true
    PREV_VERSION="${PANEL_STATE_VERSION:-}"
}

_write_state() {
    mkdir -p "$(dirname "$STATE_FILE")"
    cat > "$STATE_FILE" << EOF
# Oosoft SecurePanel — installation state
# Written by install.sh — do not edit manually.
PANEL_STATE_VERSION=${INSTALLER_VERSION}
PANEL_STATE_DATE=$(date -Iseconds)
PANEL_STATE_DOMAIN=${PANEL_DOMAIN:-}
PANEL_STATE_OS=${OS_CODENAME:-unknown}
EOF
    chmod 600 "$STATE_FILE"
}

# =============================================================================
# OS DETECTION AND STRICT VALIDATION
#
# Single source of truth for supported platforms.
# Any OS / version / architecture not in SUPPORTED_PLATFORMS causes an
# immediate exit with a clear, actionable error message.
# =============================================================================

# Each entry: "os_id:version_prefix:os_family:os_codename"
#   os_id          — value of ID from /etc/os-release (lowercase)
#   version_prefix — prefix-matched against VERSION_ID (e.g. "8" matches "8.9")
#   os_family      — "rhel" or "debian"  (controls package manager branch)
#   os_codename    — internal token used throughout the script
readonly -a SUPPORTED_PLATFORMS=(
    "almalinux:8:rhel:al8"
    "almalinux:9:rhel:al9"
    "ubuntu:22.04:debian:jammy"
)

# Human-readable list — printed in every OS error message.
_os_supported_list() {
    echo "    • AlmaLinux 8  (8.x)"
    echo "    • AlmaLinux 9  (9.x)"
    echo "    • Ubuntu 22.04 LTS  (Jammy Jellyfish)"
}

# Full-width error banner printed on any validation failure, then exits 1.
# Args: $1 = detected pretty name, $2 = os_id, $3 = os_ver, $4 = arch,
#       $5 = optional suggestion string
_os_die() {
    local pretty="$1" os_id="$2" os_ver="${3:-<unknown>}"
    local arch="$4"   suggestion="${5:-}"

    # Flush stdout before writing to stderr so log lines appear in order
    echo | tee -a "$INSTALL_LOG" >/dev/null

    {
        echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}${BOLD}║                                                                  ║${NC}"
        echo -e "${RED}${BOLD}║         ✗  UNSUPPORTED OPERATING SYSTEM                          ║${NC}"
        echo -e "${RED}${BOLD}║                                                                  ║${NC}"
        echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
        echo
        echo -e "  ${BOLD}Detected:${NC}"
        echo    "    OS:           ${pretty}"
        echo    "    ID:           ${os_id}"
        echo    "    Version:      ${os_ver}"
        echo    "    Architecture: ${arch}"
        echo
        echo -e "  ${BOLD}Supported platforms:${NC}"
        _os_supported_list
        if [[ -n "$suggestion" ]]; then
            echo
            echo -e "  ${YELLOW}${BOLD}Suggestion:${NC}"
            # Print each suggestion line indented
            while IFS= read -r line; do
                echo "    ${line}"
            done <<< "$suggestion"
        fi
        echo
        echo -e "  ${DIM}Provision a supported server and re-run:${NC}"
        echo -e "  ${DIM}    curl -sSL https://oosoft.co.in/install.sh | bash${NC}"
        echo
    } | tee -a "$INSTALL_LOG" >&2

    exit 1
}

detect_os() {
    step "Validating operating system"

    # ── 1. /etc/os-release must exist ────────────────────────────────────────
    if [[ ! -f /etc/os-release ]]; then
        {
            echo -e "${RED}${BOLD}ERROR:${NC} /etc/os-release not found."
            echo    "  Cannot identify the operating system."
            echo    "  Supported platforms:"
            _os_supported_list
        } | tee -a "$INSTALL_LOG" >&2
        exit 1
    fi

    # ── 2. Source and validate required fields ────────────────────────────────
    # shellcheck source=/dev/null
    source /etc/os-release

    local os_id="${ID:-}"
    local os_ver="${VERSION_ID:-}"
    local os_pretty="${PRETTY_NAME:-${os_id} ${os_ver}}"

    if [[ -z "$os_id" ]]; then
        echo -e "${RED}ERROR:${NC} /etc/os-release is missing the 'ID' field." \
            | tee -a "$INSTALL_LOG" >&2
        exit 1
    fi
    if [[ -z "$os_ver" ]]; then
        echo -e "${RED}ERROR:${NC} /etc/os-release is missing the 'VERSION_ID' field." \
            | tee -a "$INSTALL_LOG" >&2
        exit 1
    fi

    # ── 3. Architecture: x86_64 only ─────────────────────────────────────────
    local arch
    arch=$(uname -m 2>/dev/null || echo "unknown")
    if [[ "$arch" != "x86_64" ]]; then
        {
            echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${RED}${BOLD}║         ✗  UNSUPPORTED ARCHITECTURE                              ║${NC}"
            echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"
            echo
            echo    "  Detected:  ${arch}"
            echo    "  Required:  x86_64  (64-bit Intel / AMD)"
            echo
            echo    "  ARM, i686, and other architectures are not supported."
            echo
        } | tee -a "$INSTALL_LOG" >&2
        exit 1
    fi

    # ── 4. Normalise ID to lowercase ──────────────────────────────────────────
    os_id="${os_id,,}"

    # ── 5. Match against strict allowlist ────────────────────────────────────
    local matched=0
    for platform in "${SUPPORTED_PLATFORMS[@]}"; do
        IFS=':' read -r p_id p_ver_prefix p_family p_codename <<< "$platform"

        # ID match: "almalinux" also matches the rare alias "alma"
        local id_ok=0
        [[ "$os_id" == "$p_id"                          ]] && id_ok=1
        [[ "$p_id"  == "almalinux" && "$os_id" == "alma" ]] && id_ok=1
        (( id_ok )) || continue

        # Version prefix match: "8" matches "8.0", "8.7", "8.10", etc.
        [[ "$os_ver" == "${p_ver_prefix}"   ]] && { matched=1; OS_FAMILY="$p_family"; OS_CODENAME="$p_codename"; break; }
        [[ "$os_ver" == "${p_ver_prefix}."* ]] && { matched=1; OS_FAMILY="$p_family"; OS_CODENAME="$p_codename"; break; }
    done

    # ── 6. Unsupported — build suggestion and exit ────────────────────────────
    if (( ! matched )); then
        local suggestion=""
        case "$os_id" in
            centos)
                suggestion="CentOS is end-of-life and not supported.\nMigrate to AlmaLinux 8 or 9 (1:1 binary compatible).\nGuide: https://wiki.almalinux.org/documentation/migration-guide.html"
                ;;
            rocky|rockylinux)
                suggestion="Rocky Linux is not supported.\nAlmaLinux 8 or 9 is the recommended alternative."
                ;;
            rhel|redhat)
                local rv="${os_ver%%.*}"
                if [[ "$rv" == "8" || "$rv" == "9" ]]; then
                    suggestion="RHEL ${rv} is not supported directly.\nAlmaLinux ${rv} is a free, 1:1 RHEL-compatible alternative."
                else
                    suggestion="RHEL is not supported. Use AlmaLinux 8 or 9."
                fi
                ;;
            ubuntu)
                local uv="${os_ver%%.*}"
                case "$uv" in
                    18|20) suggestion="Ubuntu ${os_ver} is no longer supported for new installs.\nUpgrade to Ubuntu 22.04 LTS." ;;
                    23|24) suggestion="Ubuntu ${os_ver} is not an LTS release and is not supported.\nUse Ubuntu 22.04 LTS." ;;
                    *)     suggestion="Ubuntu ${os_ver} is not supported. Use Ubuntu 22.04 LTS." ;;
                esac
                ;;
            debian)
                suggestion="Debian is not supported. Use Ubuntu 22.04 LTS instead."
                ;;
            fedora)
                suggestion="Fedora is not supported.\nFor an RPM-based server, use AlmaLinux 9."
                ;;
            opensuse*|sles)
                suggestion="openSUSE / SLES are not supported.\nUse AlmaLinux 9 or Ubuntu 22.04 LTS."
                ;;
            arch|manjaro)
                suggestion="Arch-based distributions are not supported.\nUse Ubuntu 22.04 LTS or AlmaLinux 9."
                ;;
        esac

        _os_die "$os_pretty" "$os_id" "$os_ver" "$arch" "$suggestion"
    fi

    # ── 7. Validation passed — report and continue ────────────────────────────
    log "OS validated: ${os_pretty}"
    info "  ID: ${os_id}  |  Version: ${os_ver}  |  Arch: ${arch}"
    info "  Family: ${OS_FAMILY}  |  Codename: ${OS_CODENAME}"
}

# =============================================================================
# PREFLIGHT
# =============================================================================

check_root() {
    [[ $EUID -eq 0 ]] || die "Must run as root.  Try:  sudo bash $0"
}

check_resources() {
    local ram_kb disk_kb
    ram_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
    disk_kb=$(df --output=avail / 2>/dev/null | tail -1 || echo 0)
    (( ram_kb  >= 786432  )) || warn "< 1 GB RAM (${ram_kb} kB). Panel may be slow."
    (( disk_kb >= 4194304 )) || warn "< 4 GB free on / (${disk_kb} kB)."
    info "RAM: $(( ram_kb / 1024 )) MB   Disk free: $(( disk_kb / 1024 )) MB"
}

confirm() {
    [[ "$PANEL_YES" == "1" ]] && return 0
    local answer
    if [[ -e /dev/tty ]]; then
        read -r -p "$* [y/N] " answer </dev/tty
    else
        answer="n"
    fi
    [[ "${answer,,}" == "y" ]]
}

# =============================================================================
# PACKAGE INSTALLATION
# Idempotent: dnf/apt skip already-installed packages automatically.
# =============================================================================

install_packages() {
    step "Installing system packages"

    case "$OS_FAMILY" in
        rhel)   _install_packages_rhel ;;
        debian) _install_packages_debian ;;
    esac

    command -v python3.11 &>/dev/null || die "python3.11 not found after install."
    log "Python: $(python3.11 --version)"
    log "nginx:  $(nginx -v 2>&1 | head -1)"
    log "git:    $(git --version)"
}

_install_packages_rhel() {
    log "Updating packages (dnf)..."
    dnf -y -q update

    # EPEL — idempotent (dnf skips if already installed)
    dnf -y -q install epel-release

    # Enable CRB/PowerTools repo for -devel packages
    dnf -y -q install dnf-plugins-core
    if [[ "$OS_CODENAME" == "al9" ]]; then
        dnf config-manager --set-enabled crb          2>/dev/null || true
    else
        dnf config-manager --set-enabled powertools   2>/dev/null || \
        dnf config-manager --set-enabled PowerTools   2>/dev/null || true
    fi

    dnf -y -q install \
        curl wget git tar unzip openssl \
        nginx redis \
        certbot python3-certbot-nginx \
        python3.11 python3.11-devel python3.11-pip \
        postgresql-server postgresql postgresql-contrib libpq-devel \
        gcc gcc-c++ make firewalld logrotate rsync bind-utils

    # Fallback for older AL8 builds where python3.11 needs module install
    if ! command -v python3.11 &>/dev/null; then
        dnf -y -q module enable  python3.11 2>/dev/null && \
        dnf -y -q module install python3.11 || \
        die "Could not install Python 3.11. Install manually and re-run."
    fi
}

_install_packages_debian() {
    export DEBIAN_FRONTEND=noninteractive

    log "Updating package cache (apt)..."
    apt-get -y -qq update

    apt-get -y -qq install \
        curl wget git tar unzip openssl \
        software-properties-common gnupg2 lsb-release

    # Add deadsnakes PPA only if not already present — prevents duplicate entries
    if ! grep -rq "deadsnakes/python" /etc/apt/sources.list.d/ /etc/apt/sources.list \
            2>/dev/null; then
        log "Adding deadsnakes PPA for Python 3.11..."
        add-apt-repository -y ppa:deadsnakes/python 2>/dev/null || true
        apt-get -y -qq update
    else
        info "deadsnakes PPA already configured — skipping."
    fi

    apt-get -y -qq install \
        nginx redis-server \
        certbot python3-certbot-nginx \
        python3.11 python3.11-dev python3.11-venv \
        postgresql postgresql-client libpq-dev \
        gcc g++ make ufw logrotate rsync dnsutils
}

# =============================================================================
# SYSTEM USERS AND GROUPS
# Idempotent: all creation paths are guarded with existence checks.
# =============================================================================

setup_users() {
    step "Creating system users and groups"

    if ! getent group "$PANEL_GROUP" &>/dev/null; then
        groupadd --system "$PANEL_GROUP"
        info "Created group: $PANEL_GROUP"
    else
        skip "Group '$PANEL_GROUP'"
    fi

    if ! getent group "$HOSTING_GROUP" &>/dev/null; then
        groupadd --system "$HOSTING_GROUP"
        info "Created group: $HOSTING_GROUP"
    else
        skip "Group '$HOSTING_GROUP'"
    fi

    if ! id -u "$PANEL_USER" &>/dev/null; then
        useradd --system \
            --gid "$PANEL_GROUP" \
            --shell /sbin/nologin \
            --home "$INSTALL_DIR" \
            --no-create-home \
            "$PANEL_USER"
        info "Created system user: $PANEL_USER"
    else
        skip "User '$PANEL_USER'"
    fi

    # Add the nginx worker user to securepanel group so it can reach the socket.
    # usermod -aG is idempotent — adding an already-member is a no-op.
    if id nginx &>/dev/null; then
        usermod -aG "$PANEL_GROUP" nginx 2>/dev/null || true
        info "nginx → member of '$PANEL_GROUP'"
    elif id www-data &>/dev/null; then
        usermod -aG "$PANEL_GROUP" www-data 2>/dev/null || true
        info "www-data → member of '$PANEL_GROUP'"
    fi
}

# =============================================================================
# DIRECTORY STRUCTURE
# mkdir -p, chown, and chmod are all idempotent by definition.
# The tmpfiles.d content is deterministic — overwriting is harmless.
# =============================================================================

setup_directories() {
    step "Creating directory structure"

    # Application root
    mkdir -p "$INSTALL_DIR"
    chown root:root "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"

    # Log directory
    mkdir -p "$LOG_DIR"
    chown "$PANEL_USER:$PANEL_GROUP" "$LOG_DIR"
    chmod 750 "$LOG_DIR"

    # Persistent state / uploads
    mkdir -p "${STATE_DIR}/migration_uploads"
    chown -R "$PANEL_USER:$PANEL_GROUP" "$STATE_DIR"
    chmod 750 "$STATE_DIR"

    # ACME webroot
    mkdir -p "${ACME_WEBROOT}/.well-known/acme-challenge"
    chmod 755 "$ACME_WEBROOT"
    local nginx_user="nginx"
    id nginx &>/dev/null || nginx_user="www-data"
    chown -R "${nginx_user}:${nginx_user}" "$ACME_WEBROOT"

    # Volatile runtime dir — wiped on reboot, tmpfiles.d recreates it
    mkdir -p "$RUN_DIR"
    chown "root:$PANEL_GROUP" "$RUN_DIR"
    chmod 750 "$RUN_DIR"

    # tmpfiles.d entry
    cat > /etc/tmpfiles.d/securepanel.conf << EOF
# Oosoft SecurePanel — volatile runtime directory
d ${RUN_DIR} 0750 root ${PANEL_GROUP} -
EOF
    systemd-tmpfiles --create /etc/tmpfiles.d/securepanel.conf
    info "tmpfiles.d: $RUN_DIR recreated on every boot."

    mkdir -p "$NGINX_CONF_D" "$NGINX_SNIPPETS"

    log "Directories: OK"
}

# =============================================================================
# REPOSITORY CLONE / UPDATE
# Fresh server: clone.  Existing install: fast-forward pull only.
# =============================================================================

clone_repo() {
    step "Deploying application from repository"

    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        log "Repository present — pulling latest code..."
        git -C "$INSTALL_DIR" fetch --quiet origin
        # Reset to remote HEAD (upgrade path)
        git -C "$INSTALL_DIR" reset --hard origin/main  2>/dev/null || \
        git -C "$INSTALL_DIR" reset --hard origin/master 2>/dev/null || \
        warn "Could not update repository — continuing with existing code."
    else
        log "Cloning $REPO_URL ..."
        git clone --depth=1 "$REPO_URL" "$INSTALL_DIR"
    fi

    [[ -d "$BACKEND_DIR" ]]                   || die "backend/ not found in repo."
    [[ -f "${BACKEND_DIR}/requirements.txt" ]] || die "requirements.txt not found."

    # root owns the code; securepanel group can read and traverse; no world access
    chown -R "root:$PANEL_GROUP" "$INSTALL_DIR"
    chmod -R o-rwx "$INSTALL_DIR"
    chmod -R g+rX  "$INSTALL_DIR"
    chmod 750 "$BACKEND_DIR"   # .env lives here

    log "Repository: OK"
}

# =============================================================================
# PYTHON VIRTUAL ENVIRONMENT
# Skip recreation if the venv already exists with the correct Python version.
# On upgrade: only pip-install upgraded/new packages.
# =============================================================================

setup_venv() {
    step "Setting up Python virtual environment"

    local python_bin="${VENV_DIR}/bin/python"
    local recreate=1

    if [[ "$FORCE_VENV" != "1" ]] && [[ -x "$python_bin" ]]; then
        # Check if the existing venv uses the required Python minor version
        local existing_ver
        existing_ver=$("$python_bin" --version 2>/dev/null \
                       | grep -oP '3\.\K\d+' | head -1 || echo "0")
        if [[ "$existing_ver" == "$REQUIRED_PYTHON_MINOR" ]]; then
            skip "venv (Python 3.${REQUIRED_PYTHON_MINOR} already in place)"
            recreate=0
        else
            warn "Existing venv uses Python 3.${existing_ver} (need 3.${REQUIRED_PYTHON_MINOR}) — recreating."
            rm -rf "$VENV_DIR"
        fi
    fi

    if [[ "$recreate" == "1" ]]; then
        log "Creating venv at $VENV_DIR ..."
        python3.11 -m venv "$VENV_DIR"
    fi

    log "Upgrading pip / setuptools / wheel..."
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip setuptools wheel

    log "Installing / upgrading Python dependencies..."
    "$VENV_DIR/bin/pip" install --quiet --upgrade -r "${BACKEND_DIR}/requirements.txt"

    chown -R "root:$PANEL_GROUP" "$VENV_DIR"
    chmod -R o-rwx "$VENV_DIR"
    chmod -R g+rX  "$VENV_DIR"

    log "venv: OK  (Python: $("$python_bin" --version))"
}

# =============================================================================
# POSTGRESQL SETUP
# Idempotent: role + DB creation are guarded; pg_hba only patched once.
# =============================================================================

setup_postgresql() {
    step "Configuring PostgreSQL"

    # On upgrade: read DB password from existing .env rather than generating
    # a new one (which would break the database connection).
    if [[ -z "$DB_PASSWORD" ]]; then
        local existing_url
        existing_url=$(_env_get "DATABASE_URL")
        if [[ -n "$existing_url" ]]; then
            # Extract password from: postgresql+asyncpg://user:PASS@host/db
            DB_PASSWORD=$(echo "$existing_url" \
                | grep -oP '(?<=://securepanel:)[^@]+' || true)
            [[ -n "$DB_PASSWORD" ]] \
                && info "Reusing DB password from existing .env." \
                || DB_PASSWORD=""
        fi
    fi

    # Generate only if still unset
    if [[ -z "$DB_PASSWORD" ]]; then
        DB_PASSWORD=$("${VENV_DIR}/bin/python" -c \
            "import secrets; print(secrets.token_urlsafe(32))")
        info "Generated new DB password."
    fi

    case "$OS_FAMILY" in
        rhel)
            if [[ ! -f /var/lib/pgsql/data/PG_VERSION ]]; then
                log "Initialising PostgreSQL data directory..."
                postgresql-setup --initdb
            else
                skip "PostgreSQL data directory (already initialised)"
            fi
            systemctl enable --now postgresql
            ;;
        debian)
            systemctl enable --now postgresql
            ;;
    esac

    log "Waiting for PostgreSQL..."
    local retries=10
    until sudo -u postgres pg_isready -q 2>/dev/null; do
        (( retries-- ))
        (( retries > 0 )) || die "PostgreSQL did not become ready in time."
        sleep 2
    done

    # Idempotent role management: create if absent, otherwise just update password
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

    sudo -u postgres createdb -O securepanel securepanel 2>/dev/null \
        || skip "Database 'securepanel' (already exists)"

    # RHEL only: inject md5 auth row if not already present
    if [[ "$OS_FAMILY" == "rhel" ]]; then
        local pg_hba
        pg_hba=$(sudo -u postgres psql -At -c "SHOW hba_file;" 2>/dev/null \
                 | tr -d ' ')
        if [[ -n "$pg_hba" ]] \
           && ! grep -q "^host.*securepanel.*securepanel" "$pg_hba" 2>/dev/null; then
            sed -i \
                '/^host/i # Oosoft SecurePanel\nhost    securepanel     securepanel     127.0.0.1\/32     md5\nhost    securepanel     securepanel     ::1\/128          md5' \
                "$pg_hba"
            systemctl reload postgresql
            info "pg_hba.conf: md5 auth added."
        else
            skip "pg_hba.conf (securepanel entry already present)"
        fi
    fi

    log "PostgreSQL: ready."
}

# =============================================================================
# REDIS
# =============================================================================

setup_redis() {
    step "Configuring Redis"

    local redis_svc="redis"
    if ! systemctl enable "$redis_svc" 2>/dev/null; then
        redis_svc="redis-server"
        systemctl enable "$redis_svc" \
            || warn "Could not enable Redis — start it manually."
    fi
    systemctl start "$redis_svc" 2>/dev/null \
        || warn "Could not start Redis — check: journalctl -u $redis_svc"

    if command -v redis-cli &>/dev/null; then
        local pong
        pong=$(redis-cli ping 2>/dev/null || echo "FAIL")
        [[ "$pong" == "PONG" ]] \
            && log "Redis: OK" \
            || warn "Redis PING failed ($pong)."
    fi
}

# =============================================================================
# ENVIRONMENT FILE (.env)
#
# Idempotency rules:
#   • Fresh install  — write the full template.
#   • Re-run / upgrade — NEVER overwrite existing keys.
#     We only append keys that are entirely missing from the file.
#     SECRET_KEY and DATABASE_URL are preserved 100% of the time.
# =============================================================================

generate_env() {
    step "Configuring .env"

    local env_file="${BACKEND_DIR}/.env"
    local python_bin="${VENV_DIR}/bin/python"

    if [[ -f "$env_file" ]]; then
        # ── Upgrade path: file already exists ────────────────────────────────
        log ".env already exists — preserving all existing values."
        info "Checking for any missing keys and adding defaults..."

        # Derive SECRET_KEY from file so generate logic below is consistent
        SECRET_KEY=$(_env_get "SECRET_KEY")
        [[ -n "$SECRET_KEY" ]] || \
            SECRET_KEY=$("$python_bin" -c "import secrets; print(secrets.token_hex(32))")

        # Build ALLOWED_HOSTS / CORS values if not already in file
        local allowed_hosts='["*"]'
        local cors_origins='[]'
        if [[ -n "$PANEL_DOMAIN" ]]; then
            allowed_hosts="[\"${PANEL_DOMAIN}\"]"
            cors_origins="[\"https://${PANEL_DOMAIN}\"]"
        fi

        # Ensure every expected key is present — _env_ensure is a no-op
        # if the key already exists, so this is always safe.
        _env_ensure "APP_ENV"              "production"
        _env_ensure "SECRET_KEY"           "$SECRET_KEY"
        _env_ensure "ALLOWED_HOSTS"        "$allowed_hosts"
        _env_ensure "CORS_ORIGINS"         "$cors_origins"
        _env_ensure "DATABASE_URL"         "postgresql+asyncpg://securepanel:${DB_PASSWORD}@127.0.0.1:5432/securepanel"
        _env_ensure "REDIS_URL"            "redis://127.0.0.1:6379/0"
        _env_ensure "CELERY_BROKER_URL"    "redis://127.0.0.1:6379/1"
        _env_ensure "CELERY_RESULT_BACKEND" "redis://127.0.0.1:6379/2"
        _env_ensure "MAIL_DOMAIN"          "${PANEL_DOMAIN:-example.com}"
        _env_ensure "PANEL_ADMIN_EMAIL"    "${ADMIN_EMAIL:-ssl-admin@localhost}"
        _env_ensure "ANTHROPIC_API_KEY"    ""
        _env_ensure "DB_ADMIN_PASSWORD"    ""

        log ".env: all required keys present."
    else
        # ── Fresh install: write the full template ────────────────────────────
        log "Writing .env (fresh install)..."

        [[ -z "$SECRET_KEY"  ]] && \
            SECRET_KEY=$("$python_bin" -c "import secrets; print(secrets.token_hex(32))")
        [[ -z "$DB_PASSWORD" ]] && \
            DB_PASSWORD=$("$python_bin" -c "import secrets; print(secrets.token_urlsafe(32))")

        local allowed_hosts='["*"]'
        local cors_origins='[]'
        if [[ -n "$PANEL_DOMAIN" ]]; then
            allowed_hosts="[\"${PANEL_DOMAIN}\"]"
            cors_origins="[\"https://${PANEL_DOMAIN}\"]"
        fi

        cat > "$env_file" << ENV
# ============================================================
# Oosoft SecurePanel — Runtime Configuration
# Generated: $(date -Iseconds)
# !! KEEP SECRET — contains credentials and signing keys !!
# ============================================================

APP_ENV=production

# ── JWT signing key ──────────────────────────────────────────
# Changing this invalidates ALL active sessions. Rotate only
# when absolutely required.
SECRET_KEY=${SECRET_KEY}

# ── Allowed hosts / CORS ─────────────────────────────────────
ALLOWED_HOSTS=${allowed_hosts}
CORS_ORIGINS=${cors_origins}

# ── Database ─────────────────────────────────────────────────
DATABASE_URL=postgresql+asyncpg://securepanel:${DB_PASSWORD}@127.0.0.1:5432/securepanel

# ── Redis / Celery ───────────────────────────────────────────
REDIS_URL=redis://127.0.0.1:6379/0
CELERY_BROKER_URL=redis://127.0.0.1:6379/1
CELERY_RESULT_BACKEND=redis://127.0.0.1:6379/2

# ── Mail ─────────────────────────────────────────────────────
MAIL_DOMAIN=${PANEL_DOMAIN:-example.com}

# ── SSL / Certbot ────────────────────────────────────────────
PANEL_ADMIN_EMAIL=${ADMIN_EMAIL:-ssl-admin@localhost}

# ── AI Assistant (optional) ──────────────────────────────────
ANTHROPIC_API_KEY=

# ── MySQL admin (for database-management features) ───────────
DB_ADMIN_PASSWORD=
ENV
    fi

    # Enforce strict permissions on every run
    chown "root:$PANEL_GROUP" "$env_file"
    chmod 640 "$env_file"

    info "  $env_file  (mode 640, owner root:${PANEL_GROUP})"
}

# =============================================================================
# DATABASE MIGRATIONS
# alembic upgrade head is idempotent — no-op if schema is already current.
# =============================================================================

run_migrations() {
    step "Running database migrations (Alembic)"

    local alembic_ini="${BACKEND_DIR}/alembic.ini"
    if [[ ! -f "$alembic_ini" ]]; then
        warn "alembic.ini not found — skipping."
        info "Run: cd ${BACKEND_DIR} && ${VENV_DIR}/bin/alembic upgrade head"
        return 0
    fi

    local db_url
    db_url=$(_env_get "DATABASE_URL")
    if [[ -z "$db_url" ]]; then
        warn "DATABASE_URL missing from .env — skipping migrations."
        return 0
    fi

    log "alembic upgrade head..."
    (
        cd "$BACKEND_DIR"
        DATABASE_URL="$db_url" "$VENV_DIR/bin/alembic" upgrade head
    ) && log "Migrations: OK" \
      || warn "Alembic error — run manually and check logs."
}

# =============================================================================
# SYSTEMD SERVICE UNITS
#
# Idempotency: compare source and destination with cmp before copying.
# Copy only when content differs.  daemon-reload only if anything changed.
# Services are restarted only when their unit file was updated.
# =============================================================================

install_systemd_services() {
    step "Installing systemd service units"
    UNITS_CHANGED=0

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
            warn "  Unit file not found: $src — skipping."
            continue
        fi

        # Prepare a patched copy in a temp file, then compare with destination
        local tmp
        tmp=$(mktemp)
        cp "$src" "$tmp"

        if [[ "$svc" == "securepanel-agent" ]]; then
            sed -i "s|/etc/nginx/sites-enabled|${NGINX_CONF_D}|g" "$tmp"
            sed -i "s|ReadWritePaths=|ReadWritePaths=/var/www |"   "$tmp"
        fi

        if [[ -f "$dst" ]] && cmp -s "$tmp" "$dst"; then
            skip "  ${svc}.service (unchanged)"
        else
            cp "$tmp" "$dst"
            chmod 644 "$dst"
            UNITS_CHANGED=1
            info "  Installed: ${svc}.service"
        fi
        rm -f "$tmp"
    done

    _install_certbot_units

    if (( UNITS_CHANGED )); then
        systemctl daemon-reload
        log "systemd: daemon-reload complete (units changed)."
    else
        skip "systemd daemon-reload (no units changed)"
    fi
}

_install_certbot_units() {
    local svc_src="${SYSTEMD_SRC}/certbot-renewal.service"
    local tmr_src="${SYSTEMD_SRC}/certbot-renewal.timer"
    local svc_dst="/etc/systemd/system/certbot-renewal.service"
    local tmr_dst="/etc/systemd/system/certbot-renewal.timer"

    # Service unit
    if [[ -f "$svc_src" ]]; then
        if [[ -f "$svc_dst" ]] && cmp -s "$svc_src" "$svc_dst"; then
            skip "  certbot-renewal.service (unchanged)"
        else
            cp "$svc_src" "$svc_dst"
            chmod 644 "$svc_dst"
            UNITS_CHANGED=1
            info "  Installed: certbot-renewal.service"
        fi
    elif [[ ! -f "$svc_dst" ]]; then
        cat > "$svc_dst" << 'EOF'
[Unit]
Description=Certbot Certificate Renewal
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --quiet --no-random-sleep-on-renew
PrivateTmp=yes
EOF
        chmod 644 "$svc_dst"
        UNITS_CHANGED=1
        info "  Created: certbot-renewal.service (inline)"
    else
        skip "  certbot-renewal.service (already present)"
    fi

    # Timer unit
    if [[ -f "$tmr_src" ]]; then
        if [[ -f "$tmr_dst" ]] && cmp -s "$tmr_src" "$tmr_dst"; then
            skip "  certbot-renewal.timer (unchanged)"
        else
            cp "$tmr_src" "$tmr_dst"
            chmod 644 "$tmr_dst"
            UNITS_CHANGED=1
            info "  Installed: certbot-renewal.timer"
        fi
    elif [[ ! -f "$tmr_dst" ]]; then
        cat > "$tmr_dst" << 'EOF'
[Unit]
Description=Twice-daily Let's Encrypt certificate renewal
After=network-online.target

[Timer]
OnCalendar=*-*-* 04:00:00
OnCalendar=*-*-* 16:00:00
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
EOF
        chmod 644 "$tmr_dst"
        UNITS_CHANGED=1
        info "  Created: certbot-renewal.timer (inline)"
    else
        skip "  certbot-renewal.timer (already present)"
    fi
}

# =============================================================================
# LOG ROTATION
# Write only if the file does not yet exist or content has changed.
# =============================================================================

setup_logrotate() {
    step "Configuring log rotation"

    local dest="/etc/logrotate.d/securepanel"
    local tmp
    tmp=$(mktemp)

    cat > "$tmp" << 'EOF'
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
        systemctl kill --signal=USR1 securepanel 2>/dev/null || true
    endscript
}
EOF

    if [[ -f "$dest" ]] && cmp -s "$tmp" "$dest"; then
        skip "logrotate config (unchanged)"
    else
        cp "$tmp" "$dest"
        log "logrotate: daily, 90 days, compress — /var/log/securepanel/*.log"
    fi
    rm -f "$tmp"
}

# =============================================================================
# NGINX CONFIGURATION
#
# Idempotency rules:
#   1. If panel.conf already contains ssl_certificate directives, SSL is live —
#      NEVER overwrite it with the HTTP bootstrap (would break HTTPS).
#   2. If panel.conf already exists with the correct domain, leave it alone.
#   3. On fresh install, or when FORCE_NGINX=1, deploy the bootstrap config.
# =============================================================================

setup_nginx() {
    step "Configuring nginx"

    local panel_conf="${NGINX_CONF_D}/panel.conf"

    if [[ -f "$panel_conf" ]]; then
        # Guard: don't touch a live HTTPS config
        if grep -q "ssl_certificate" "$panel_conf" 2>/dev/null; then
            if [[ "$FORCE_NGINX" != "1" ]]; then
                skip "nginx panel.conf (SSL config already active — use FORCE_NGINX=1 to override)"
                # Ensure nginx is enabled and running even when skipping config write
                systemctl enable nginx 2>/dev/null || true
                systemctl is-active --quiet nginx || systemctl start nginx
                return
            else
                warn "FORCE_NGINX=1 set — overwriting existing nginx config."
            fi
        fi

        # If the domain hasn't changed and it's already a bootstrap config,
        # skip the write to avoid an unnecessary reload.
        if [[ -n "$PANEL_DOMAIN" ]] \
           && grep -q "server_name.*${PANEL_DOMAIN}" "$panel_conf" 2>/dev/null \
           && ! grep -q "ssl_certificate" "$panel_conf" 2>/dev/null; then
            skip "nginx bootstrap config (domain already set to $PANEL_DOMAIN)"
            systemctl enable nginx 2>/dev/null || true
            systemctl is-active --quiet nginx || systemctl start nginx
            return
        fi
    fi

    # Write bootstrap config
    local bootstrap_src="${INSTALL_DIR}/nginx/panel-bootstrap.conf"
    local tmp
    tmp=$(mktemp)

    if [[ -f "$bootstrap_src" ]]; then
        if [[ -n "$PANEL_DOMAIN" ]]; then
            sed "s/panel\.example\.com/$PANEL_DOMAIN/g" "$bootstrap_src" > "$tmp"
        else
            cp "$bootstrap_src" "$tmp"
        fi
    else
        _write_nginx_bootstrap_to "$tmp"
    fi

    # Only write if different from what's already on disk
    if [[ -f "$panel_conf" ]] && cmp -s "$tmp" "$panel_conf"; then
        skip "nginx panel.conf (content unchanged)"
    else
        cp "$tmp" "$panel_conf"
        chmod 644 "$panel_conf"
        log "nginx: bootstrap config written → $panel_conf"
    fi
    rm -f "$tmp"

    if nginx -t 2>/dev/null; then
        systemctl enable nginx
        systemctl restart nginx 2>/dev/null || systemctl start nginx
        log "nginx: running."
    else
        warn "nginx -t FAILED — check $panel_conf"
        nginx -t   # print the actual errors
    fi
}

_write_nginx_bootstrap_to() {
    local dest="$1"
    local sn="${PANEL_DOMAIN:-_}"
    cat > "$dest" << NGINXEOF
# Oosoft SecurePanel — HTTP bootstrap config
# Replace with HTTPS config after running ssl-setup.sh

server {
    listen      80 default_server;
    listen      [::]:80 default_server;
    server_name ${sn};

    location /.well-known/acme-challenge/ {
        root         /var/www/letsencrypt;
        default_type "text/plain";
        try_files    \$uri =404;
    }

    location / {
        return 503 "Panel configuration in progress.";
        add_header Content-Type "text/plain" always;
    }
}
NGINXEOF
}

# =============================================================================
# FIREWALL
# firewall-cmd --permanent --add-service is idempotent (no error if already set).
# ufw allow is idempotent.
# =============================================================================

setup_firewall() {
    step "Configuring firewall"

    case "$OS_FAMILY" in
        rhel)   _setup_firewall_firewalld ;;
        debian) _setup_firewall_ufw ;;
    esac
}

_setup_firewall_firewalld() {
    command -v firewall-cmd &>/dev/null \
        || { warn "firewalld not found — skipping."; return; }

    systemctl enable --now firewalld

    firewall-cmd --permanent --add-service=ssh    --quiet 2>/dev/null || true
    firewall-cmd --permanent --add-service=http   --quiet
    firewall-cmd --permanent --add-service=https  --quiet
    firewall-cmd --permanent --remove-service=cockpit --quiet 2>/dev/null || true
    firewall-cmd --reload --quiet

    log "firewalld: SSH(22) + HTTP(80) + HTTPS(443) open."
}

_setup_firewall_ufw() {
    command -v ufw &>/dev/null \
        || { warn "ufw not found — skipping."; return; }

    ufw allow OpenSSH  --force 2>/dev/null || ufw allow 22/tcp  --force
    ufw allow 80/tcp   --force
    ufw allow 443/tcp  --force
    ufw --force enable

    log "ufw: SSH(22) + HTTP(80) + HTTPS(443) allowed."
}

# =============================================================================
# START / RESTART SERVICES
#
# Idempotency notes:
#   • systemctl enable   — idempotent (no-op if already enabled)
#   • systemctl restart  — always restarts; intentional on upgrade
#     (new code was deployed; services must pick it up)
#   • On unit-file-unchanged upgrades where only Python deps changed,
#     restart is still correct — workers load Python code at startup.
# =============================================================================

start_services() {
    step "Enabling and starting panel services"

    # Agent first — API refuses to start without its socket
    systemctl enable securepanel-agent
    systemctl restart securepanel-agent \
        || warn "securepanel-agent failed — check: journalctl -u securepanel-agent -n 30"

    # Wait for the agent socket (up to 10 s)
    local socket="${RUN_DIR}/agent.sock"
    local retries=10
    while [[ ! -S "$socket" ]] && (( retries-- > 0 )); do sleep 1; done
    [[ -S "$socket" ]] \
        && info "  Agent socket: $socket  ✓" \
        || warn "  Agent socket not visible yet — API will retry."

    # API + workers
    for svc in securepanel securepanel-worker securepanel-beat; do
        systemctl enable "$svc"
        systemctl restart "$svc" \
            || warn "$svc failed — check: journalctl -u $svc -n 30"
        local st
        st=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
        info "  ${svc}: $st"
    done

    systemctl enable --now certbot-renewal.timer 2>/dev/null || true
    info "  certbot-renewal.timer: enabled"

    log "Services started."
}

# =============================================================================
# SSL — optional; only runs when PANEL_DOMAIN + ADMIN_EMAIL are set and
# DNS already resolves. ssl-setup.sh is itself idempotent.
# =============================================================================

maybe_setup_ssl() {
    step "SSL Certificate Setup"

    local ssl_script="${INSTALL_DIR}/scripts/ssl-setup.sh"

    # Skip if cert already exists for this domain — ssl-setup.sh would no-op
    # but we avoid the DNS check overhead and confusing output.
    if [[ -n "$PANEL_DOMAIN" ]] \
       && [[ -f "/etc/letsencrypt/live/${PANEL_DOMAIN}/fullchain.pem" ]]; then
        skip "SSL (certificate already present for $PANEL_DOMAIN)"
        return
    fi

    if [[ -z "$PANEL_DOMAIN" ]] || [[ -z "$ADMIN_EMAIL" ]]; then
        info "PANEL_DOMAIN or ADMIN_EMAIL not set — skipping SSL."
        info "Run manually:  PANEL_DOMAIN=... ADMIN_EMAIL=... bash ${ssl_script}"
        return
    fi

    [[ -f "$ssl_script" ]] || { warn "ssl-setup.sh not found — skipping."; return; }

    local resolved
    resolved=$(getent hosts "$PANEL_DOMAIN" | awk '{print $1}' 2>/dev/null || true)
    if [[ -z "$resolved" ]]; then
        warn "DNS: $PANEL_DOMAIN does not resolve yet."
        info "Point an A record here, then re-run this script or run ssl-setup.sh."
        return
    fi
    log "DNS: $PANEL_DOMAIN → $resolved"

    PANEL_DOMAIN="$PANEL_DOMAIN" \
    ADMIN_EMAIL="$ADMIN_EMAIL"   \
    INSTALL_DIR="$INSTALL_DIR"   \
    PANEL_YES="$PANEL_YES"       \
    bash "$ssl_script" \
        && log "SSL setup: OK" \
        || warn "ssl-setup.sh error — check output above."
}

# =============================================================================
# FINAL BANNER
# =============================================================================

print_banner() {
    local proto="http"
    [[ -f "/etc/letsencrypt/live/${PANEL_DOMAIN:-}/fullchain.pem" ]] && proto="https"
    local panel_url="${proto}://${PANEL_DOMAIN:-$(hostname -I | awk '{print $1}')}"
    local mode_label="Installation"
    (( IS_UPGRADE )) && mode_label="Upgrade"

    echo
    echo -e "${GREEN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════════════╗"
    echo "  ║                                                                  ║"
    echo "  ║      ✓  Oosoft SecurePanel — ${mode_label} Complete               ║"
    echo "  ║                                                                  ║"
    echo "  ╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    local mode_str
    if (( IS_UPGRADE )); then
        mode_str="Upgrade  (${PREV_VERSION} → ${INSTALLER_VERSION})"
    else
        mode_str="Fresh install  (${INSTALLER_VERSION})"
    fi
    echo -e "  ${CYAN}Mode:${NC}              ${mode_str}"
    echo -e "  ${CYAN}Panel URL:${NC}         ${BOLD}${panel_url}${NC}"
    echo -e "  ${CYAN}Install directory:${NC} $INSTALL_DIR"
    echo -e "  ${CYAN}Configuration:${NC}     ${BACKEND_DIR}/.env"
    echo -e "  ${CYAN}Logs:${NC}              $LOG_DIR"
    echo -e "  ${CYAN}Install log:${NC}       $INSTALL_LOG"
    echo

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

    if [[ -z "$PANEL_DOMAIN" ]] \
       || [[ ! -f "/etc/letsencrypt/live/${PANEL_DOMAIN:-}/fullchain.pem" ]]; then
        echo -e "  ${YELLOW}${BOLD}Next steps:${NC}"
        echo    "    1. Complete configuration (if needed):"
        echo    "         nano ${BACKEND_DIR}/.env"
        echo    "    2. Point DNS A record to this server's IP."
        echo    "    3. Run SSL setup once DNS propagates:"
        echo    "         PANEL_DOMAIN=panel.example.com \\"
        echo    "         ADMIN_EMAIL=admin@example.com \\"
        echo    "         bash ${INSTALL_DIR}/scripts/ssl-setup.sh"
        echo    "    4. Apply post-install hardening:"
        echo    "         bash ${INSTALL_DIR}/scripts/hardening.sh"
        echo
    fi

    echo -e "  ${BOLD}Useful commands:${NC}"
    echo    "    journalctl -u securepanel       -f   # API logs"
    echo    "    journalctl -u securepanel-agent -f   # Agent logs"
    echo    "    systemctl status securepanel         # Service overview"
    echo
    echo -e "  ${DIM}Full install log: $INSTALL_LOG${NC}"
    echo
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    # Header
    echo -e "${CYAN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════════════╗"
    echo "  ║     Oosoft SecurePanel — Production Installer v${INSTALLER_VERSION}            ║"
    echo "  ║     $(date '+%Y-%m-%d  %H:%M:%S  %Z')                              ║"
    echo "  ╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "  ${DIM}Log: $INSTALL_LOG${NC}"
    echo

    # Preflight
    check_root
    detect_os
    check_resources

    # Detect existing installation
    _read_state
    if [[ -n "$PREV_VERSION" ]]; then
        IS_UPGRADE=1
        echo -e "  ${YELLOW}${BOLD}Upgrade mode${NC} — existing installation v${PREV_VERSION} detected."
    else
        echo -e "  ${GREEN}${BOLD}Fresh install${NC} — no existing installation found."
    fi

    if [[ -n "$PANEL_DOMAIN" ]]; then
        echo -e "  Panel domain:  ${BOLD}$PANEL_DOMAIN${NC}"
    fi
    echo

    # Confirmation prompt
    if [[ "$PANEL_YES" != "1" ]] && [[ -t 1 ]]; then
        local action="Install"
        (( IS_UPGRADE )) && action="Upgrade"
        confirm "  ${action} Oosoft SecurePanel on $(hostname -f)?" \
            || die "Cancelled."
    fi

    # Execute steps
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

    # Persist state for future runs
    _write_state

    print_banner
}

main "$@"
