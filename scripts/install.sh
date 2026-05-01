#!/bin/bash
# Oosoft SecurePanel Installer
# Target: CloudLinux 8+ with CageFS
set -euo pipefail

INSTALL_DIR="/opt/oosoft-securepanel"
LOG_DIR="/var/log/securepanel"
RUN_DIR="/run/securepanel"
PANEL_USER="securepanel"

echo "==> Creating system user and directories"
groupadd -f securepanel
groupadd -f securepanel_users
id -u "$PANEL_USER" &>/dev/null || useradd -r -g securepanel -s /sbin/nologin -d /opt/oosoft-securepanel "$PANEL_USER"

mkdir -p "$LOG_DIR" "$RUN_DIR" /var/securepanel/migration_uploads
chown "$PANEL_USER:securepanel" "$LOG_DIR" "$RUN_DIR" /var/securepanel
chmod 750 "$LOG_DIR"

echo "==> Installing Python dependencies"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/backend/requirements.txt"

echo "==> Installing systemd services"
for service in securepanel-agent securepanel securepanel-worker securepanel-beat; do
    cp "$INSTALL_DIR/systemd/${service}.service" /etc/systemd/system/
done
systemctl daemon-reload

echo "==> Setting up log rotation"
cat > /etc/logrotate.d/securepanel << 'EOF'
/var/log/securepanel/*.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        systemctl reload securepanel 2>/dev/null || true
    endscript
}
EOF

echo "==> Creating /run/securepanel on boot"
cat > /etc/tmpfiles.d/securepanel.conf << 'EOF'
d /run/securepanel 0750 root securepanel -
EOF

echo "==> Installation complete. Configure .env then run:"
echo "    systemctl enable --now securepanel-agent securepanel securepanel-worker securepanel-beat"
