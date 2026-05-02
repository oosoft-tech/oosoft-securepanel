#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# install.sh — Oosoft SecurePanel base installer
# Target: CloudLinux 8+ with CageFS
#
# This script installs all panel components EXCEPT SSL certificates.
# After this script completes, run ssl-setup.sh to configure HTTPS.
#
# Usage:
#   sudo bash install.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
IFS=$'\n\t'

INSTALL_DIR="/opt/oosoft-securepanel"
LOG_DIR="/var/log/securepanel"
RUN_DIR="/run/securepanel"
PANEL_USER="securepanel"

# ─────────────────────────────────────────────────────────────────────────────
echo "==> [1/7] Creating system user and groups"
# ─────────────────────────────────────────────────────────────────────────────
groupadd -f securepanel
groupadd -f securepanel_users

if ! id -u "$PANEL_USER" &>/dev/null; then
    useradd \
        --system \
        --gid    securepanel \
        --shell  /sbin/nologin \
        --home   "$INSTALL_DIR" \
        --no-create-home \
        "$PANEL_USER"
    echo "    Created system user: $PANEL_USER"
else
    echo "    User $PANEL_USER already exists — skipping."
fi

# ─────────────────────────────────────────────────────────────────────────────
echo "==> [2/7] Creating runtime and log directories"
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p \
    "$LOG_DIR" \
    "$RUN_DIR" \
    /var/securepanel/migration_uploads \
    /var/www/letsencrypt/.well-known/acme-challenge

# Ownership: API/worker write to logs; agent (root) writes to agent.log separately
chown "$PANEL_USER:securepanel" "$LOG_DIR" "$RUN_DIR" /var/securepanel
chmod 750 "$LOG_DIR" "$RUN_DIR"

# ACME webroot accessible by nginx
chown root:nginx /var/www/letsencrypt 2>/dev/null || \
    chown root:www-data /var/www/letsencrypt 2>/dev/null || true
chmod 755 /var/www/letsencrypt

# ─────────────────────────────────────────────────────────────────────────────
echo "==> [3/7] Creating /run/securepanel on boot (tmpfiles.d)"
# ─────────────────────────────────────────────────────────────────────────────
cat > /etc/tmpfiles.d/securepanel.conf << 'EOF'
# Recreate the agent socket directory after reboot.
# Mode 0750 means only root and the securepanel group can enter.
d /run/securepanel 0750 root securepanel -
EOF

# Apply immediately without reboot
systemd-tmpfiles --create /etc/tmpfiles.d/securepanel.conf

# ─────────────────────────────────────────────────────────────────────────────
echo "==> [4/7] Installing Python virtual environment and dependencies"
# ─────────────────────────────────────────────────────────────────────────────
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/backend/requirements.txt"
echo "    Python dependencies installed."

# ─────────────────────────────────────────────────────────────────────────────
echo "==> [5/7] Installing systemd service units"
# ─────────────────────────────────────────────────────────────────────────────
for service in \
    securepanel-agent \
    securepanel \
    securepanel-worker \
    securepanel-beat \
    certbot-renewal
do
    src="$INSTALL_DIR/systemd/${service}.service"
    if [[ -f "$src" ]]; then
        cp "$src" /etc/systemd/system/
        echo "    Installed: ${service}.service"
    else
        echo "    WARNING: $src not found — skipping"
    fi
done

# Install certbot renewal timer
src="$INSTALL_DIR/systemd/certbot-renewal.timer"
if [[ -f "$src" ]]; then
    cp "$src" /etc/systemd/system/
    echo "    Installed: certbot-renewal.timer"
fi

systemctl daemon-reload

# ─────────────────────────────────────────────────────────────────────────────
echo "==> [6/7] Configuring log rotation"
# ─────────────────────────────────────────────────────────────────────────────
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
        # Reload the API process to re-open log file handles.
        systemctl kill --signal=USR1 securepanel 2>/dev/null || true
    endscript
}
EOF
echo "    Log rotation configured."

# ─────────────────────────────────────────────────────────────────────────────
echo "==> [7/7] Nginx panel configuration (HTTP bootstrap)"
# ─────────────────────────────────────────────────────────────────────────────
# Install the bootstrap config (HTTP only) so nginx can start.
# ssl-setup.sh replaces this with the production HTTPS config.
NGINX_CONF_DIR="/etc/nginx/conf.d"
BOOTSTRAP_SRC="$INSTALL_DIR/nginx/panel-bootstrap.conf"

if [[ -f "$BOOTSTRAP_SRC" ]]; then
    if [[ ! -f "$NGINX_CONF_DIR/panel.conf" ]]; then
        cp "$BOOTSTRAP_SRC" "$NGINX_CONF_DIR/panel.conf"
        echo "    Bootstrap nginx config installed: $NGINX_CONF_DIR/panel.conf"
    else
        echo "    $NGINX_CONF_DIR/panel.conf already exists — not overwriting."
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
echo
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  Base installation complete.                                     ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  Next steps:                                                     ║"
echo "║                                                                  ║"
echo "║  1. Configure /opt/oosoft-securepanel/backend/.env              ║"
echo "║     (copy from .env.example and fill in all values)             ║"
echo "║                                                                  ║"
echo "║  2. Start panel services:                                        ║"
echo "║     systemctl enable --now \\                                    ║"
echo "║       securepanel-agent securepanel \\                          ║"
echo "║       securepanel-worker securepanel-beat                       ║"
echo "║                                                                  ║"
echo "║  3. Configure SSL (run AFTER DNS is pointed here):              ║"
echo "║     PANEL_DOMAIN=panel.example.com \\                           ║"
echo "║     ADMIN_EMAIL=admin@example.com \\                            ║"
echo "║     bash /opt/oosoft-securepanel/scripts/ssl-setup.sh           ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
