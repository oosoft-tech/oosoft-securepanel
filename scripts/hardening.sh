#!/bin/bash
# Post-install hardening for Oosoft SecurePanel
set -euo pipefail

echo "==> Disabling dangerous PHP functions globally"
for ini in /etc/php*/*/php.ini /etc/php.ini; do
    [ -f "$ini" ] || continue
    sed -i 's/^disable_functions\s*=.*/disable_functions = exec,shell_exec,system,passthru,popen,proc_open,pcntl_exec,pcntl_fork,pfsockopen,dl/' "$ini"
    echo "Patched: $ini"
done

echo "==> Hardening SSH"
sshd_conf="/etc/ssh/sshd_config"
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' "$sshd_conf"
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' "$sshd_conf"
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' "$sshd_conf"
sed -i 's/^#\?LoginGraceTime.*/LoginGraceTime 30/' "$sshd_conf"
systemctl reload sshd

echo "==> Setting kernel security parameters"
cat >> /etc/sysctl.d/99-securepanel.conf << 'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
sysctl -p /etc/sysctl.d/99-securepanel.conf

echo "==> Initializing nftables ruleset"
systemctl enable --now nftables

echo "==> Enabling CageFS"
cagefsctl --enable-all || echo "CageFS not available — install CloudLinux kernel"

echo "==> Hardening complete"
