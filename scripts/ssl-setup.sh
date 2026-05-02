#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# ssl-setup.sh — Let's Encrypt initial certificate acquisition
# Oosoft SecurePanel
#
# Run ONCE after DNS for PANEL_DOMAIN points to this server.
#
# What this script does:
#   1. Validates prerequisites (root, certbot, nginx, DNS reachability)
#   2. Generates a 2048-bit DH parameter file for DHE cipher suites
#   3. Installs the reusable ssl-params.conf snippet
#   4. Deploys the HTTP-only bootstrap nginx config
#   5. Creates the ACME webroot directory
#   6. Obtains the certificate via certbot --webroot
#   7. Deploys the production HTTPS nginx config
#   8. Installs the certbot renewal systemd timer
#   9. Runs a test renewal (dry-run) to verify the renewal hook works
#  10. Verifies the live certificate with openssl
#
# Usage:
#   sudo PANEL_DOMAIN=panel.example.com \
#        ADMIN_EMAIL=admin@example.com  \
#        bash ssl-setup.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
IFS=$'\n\t'

# ─── Colour helpers ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }

# ─── Configuration ────────────────────────────────────────────────────────────
PANEL_DOMAIN="${PANEL_DOMAIN:-}"
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
INSTALL_DIR="${INSTALL_DIR:-/opt/oosoft-securepanel}"
ACME_WEBROOT="/var/www/letsencrypt"
NGINX_SNIPPET_DIR="/etc/nginx/snippets"
NGINX_CONF_DIR="/etc/nginx/conf.d"
LE_LIVE_DIR="/etc/letsencrypt/live"
DH_PARAM_FILE="/etc/nginx/dhparam.pem"
DH_BITS=2048

# ─── Prerequisite checks ──────────────────────────────────────────────────────
check_prerequisites() {
    info "Checking prerequisites..."

    [[ $EUID -eq 0 ]] || die "This script must run as root"

    [[ -n "$PANEL_DOMAIN" ]] || die "PANEL_DOMAIN is not set. Usage: PANEL_DOMAIN=panel.example.com bash ssl-setup.sh"
    [[ -n "$ADMIN_EMAIL"  ]] || die "ADMIN_EMAIL is not set.  Usage: ADMIN_EMAIL=admin@example.com bash ssl-setup.sh"

    # Validate domain format
    if ! [[ "$PANEL_DOMAIN" =~ ^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$ ]]; then
        die "PANEL_DOMAIN '$PANEL_DOMAIN' does not look like a valid domain name"
    fi

    # Validate email format
    if ! [[ "$ADMIN_EMAIL" =~ ^[^@]+@[^@]+\.[^@]+$ ]]; then
        die "ADMIN_EMAIL '$ADMIN_EMAIL' does not look like a valid email address"
    fi

    command -v certbot  >/dev/null 2>&1 || die "certbot is not installed. Run: dnf install certbot"
    command -v nginx    >/dev/null 2>&1 || die "nginx is not installed"
    command -v openssl  >/dev/null 2>&1 || die "openssl is not installed"
    command -v systemctl>/dev/null 2>&1 || die "systemd is required"

    systemctl is-active --quiet nginx || die "nginx is not running. Start it first: systemctl start nginx"

    info "All prerequisites satisfied."
}

# ─── DNS reachability check ───────────────────────────────────────────────────
check_dns() {
    info "Checking DNS resolution for $PANEL_DOMAIN ..."

    # Get the server's public IP (tries multiple services, falls back gracefully)
    SERVER_IP=""
    for url in "https://api.ipify.org" "https://ifconfig.me" "https://icanhazip.com"; do
        SERVER_IP=$(curl -4 --silent --max-time 5 "$url" 2>/dev/null || true)
        [[ -n "$SERVER_IP" ]] && break
    done

    if [[ -z "$SERVER_IP" ]]; then
        warn "Could not determine public IP — skipping DNS match check"
        return
    fi

    RESOLVED_IP=$(getent hosts "$PANEL_DOMAIN" | awk '{print $1}' || true)

    if [[ -z "$RESOLVED_IP" ]]; then
        die "DNS: $PANEL_DOMAIN does not resolve. Point an A record to $SERVER_IP and retry."
    fi

    if [[ "$RESOLVED_IP" != "$SERVER_IP" ]]; then
        warn "DNS: $PANEL_DOMAIN resolves to $RESOLVED_IP but this server's IP appears to be $SERVER_IP"
        warn "Certificate issuance will fail if the domain doesn't point here."
        read -r -p "Continue anyway? [y/N] " answer
        [[ "${answer,,}" == "y" ]] || die "Aborted by user."
    else
        info "DNS OK: $PANEL_DOMAIN → $RESOLVED_IP"
    fi
}

# ─── DH parameter generation ─────────────────────────────────────────────────
generate_dhparam() {
    if [[ -f "$DH_PARAM_FILE" ]]; then
        info "DH params already exist at $DH_PARAM_FILE — skipping generation."
        return
    fi

    info "Generating ${DH_BITS}-bit DH parameters (this takes ~30-60 seconds)..."
    openssl dhparam -out "$DH_PARAM_FILE" "$DH_BITS"
    chmod 0640 "$DH_PARAM_FILE"
    info "DH params written to $DH_PARAM_FILE"
}

# ─── SSL snippet installation ─────────────────────────────────────────────────
install_ssl_snippet() {
    info "Installing ssl-params.conf snippet..."

    mkdir -p "$NGINX_SNIPPET_DIR"

    # Copy ssl-params.conf from the repo
    local src="$INSTALL_DIR/nginx/ssl-params.conf"
    [[ -f "$src" ]] || die "Source file not found: $src"

    cp "$src" "$NGINX_SNIPPET_DIR/ssl-params.conf"
    chmod 0644 "$NGINX_SNIPPET_DIR/ssl-params.conf"

    # Uncomment ssl_dhparam line now that we have the file
    if [[ -f "$DH_PARAM_FILE" ]]; then
        sed -i "s|^# ssl_dhparam|ssl_dhparam|" "$NGINX_SNIPPET_DIR/ssl-params.conf"
        info "ssl_dhparam enabled in snippet."
    fi

    info "ssl-params.conf installed at $NGINX_SNIPPET_DIR/ssl-params.conf"
}

# ─── ACME webroot setup ───────────────────────────────────────────────────────
setup_acme_webroot() {
    info "Creating ACME webroot at $ACME_WEBROOT ..."
    mkdir -p "$ACME_WEBROOT/.well-known/acme-challenge"
    chmod -R 755 "$ACME_WEBROOT"
    chown -R nginx:nginx "$ACME_WEBROOT" 2>/dev/null || \
        chown -R www-data:www-data "$ACME_WEBROOT" 2>/dev/null || true
}

# ─── Bootstrap nginx config ───────────────────────────────────────────────────
deploy_bootstrap_config() {
    info "Deploying HTTP-only bootstrap nginx config..."

    local src="$INSTALL_DIR/nginx/panel-bootstrap.conf"
    [[ -f "$src" ]] || die "Bootstrap config not found: $src"

    # Substitute the actual domain into the config
    sed "s/panel\.example\.com/$PANEL_DOMAIN/g" "$src" \
        > "$NGINX_CONF_DIR/panel.conf"

    # Backup any existing production config (it will be replaced post-cert)
    if [[ -L "$NGINX_CONF_DIR/panel.conf.bak" ]] || [[ -f "$NGINX_CONF_DIR/panel.conf.bak" ]]; then
        rm -f "$NGINX_CONF_DIR/panel.conf.bak"
    fi

    nginx -t 2>/dev/null || die "Bootstrap nginx config failed validation — check syntax"
    systemctl reload nginx
    info "Bootstrap config deployed and nginx reloaded."
}

# ─── Certificate issuance ─────────────────────────────────────────────────────
issue_certificate() {
    info "Requesting certificate from Let's Encrypt for $PANEL_DOMAIN ..."

    certbot certonly \
        --webroot \
        --webroot-path   "$ACME_WEBROOT" \
        --domain         "$PANEL_DOMAIN" \
        --email          "$ADMIN_EMAIL" \
        --agree-tos      \
        --no-eff-email   \
        --non-interactive \
        --rsa-key-size   4096 \
        --cert-name      "$PANEL_DOMAIN"

    # Verify the certificate files exist
    local cert_dir="$LE_LIVE_DIR/$PANEL_DOMAIN"
    [[ -f "$cert_dir/fullchain.pem" ]] || die "fullchain.pem missing after issuance"
    [[ -f "$cert_dir/privkey.pem"   ]] || die "privkey.pem missing after issuance"
    [[ -f "$cert_dir/chain.pem"     ]] || die "chain.pem missing after issuance"

    info "Certificate issued successfully."
}

# ─── Production nginx config deployment ──────────────────────────────────────
deploy_production_config() {
    info "Deploying production HTTPS nginx config..."

    local src="$INSTALL_DIR/nginx/panel.conf"
    [[ -f "$src" ]] || die "Production config not found: $src"

    # Substitute domain into the config
    sed "s/panel\.example\.com/$PANEL_DOMAIN/g" "$src" \
        > "$NGINX_CONF_DIR/panel.conf"

    nginx -t 2>/dev/null || die "Production nginx config failed validation — check $NGINX_CONF_DIR/panel.conf"
    systemctl reload nginx
    info "Production HTTPS config deployed and nginx reloaded."
}

# ─── Renewal hook ─────────────────────────────────────────────────────────────
install_renewal_hook() {
    info "Installing certbot post-renewal hook..."

    local hook_dir="/etc/letsencrypt/renewal-hooks/post"
    mkdir -p "$hook_dir"

    cat > "$hook_dir/reload-nginx.sh" << 'HOOK'
#!/usr/bin/env bash
# Reload nginx after certbot renews any certificate.
# Called by certbot with no arguments when at least one cert was renewed.
set -euo pipefail

logger -t certbot-hook "Certificate renewed — reloading nginx"

if nginx -t -q 2>/dev/null; then
    systemctl reload nginx
    logger -t certbot-hook "nginx reloaded successfully"
else
    logger -t certbot-hook "nginx -t FAILED after renewal — NOT reloading"
    exit 1
fi
HOOK

    chmod 0750 "$hook_dir/reload-nginx.sh"
    info "Renewal hook installed: $hook_dir/reload-nginx.sh"
}

# ─── Systemd renewal timer ────────────────────────────────────────────────────
install_renewal_timer() {
    info "Installing certbot renewal systemd timer..."

    local src_service="$INSTALL_DIR/systemd/certbot-renewal.service"
    local src_timer="$INSTALL_DIR/systemd/certbot-renewal.timer"

    [[ -f "$src_service" ]] || die "certbot-renewal.service not found: $src_service"
    [[ -f "$src_timer"   ]] || die "certbot-renewal.timer not found:   $src_timer"

    cp "$src_service" /etc/systemd/system/certbot-renewal.service
    cp "$src_timer"   /etc/systemd/system/certbot-renewal.timer

    systemctl daemon-reload
    systemctl enable --now certbot-renewal.timer

    info "certbot-renewal.timer enabled and started."
    systemctl status certbot-renewal.timer --no-pager || true
}

# ─── Dry-run renewal test ─────────────────────────────────────────────────────
test_renewal() {
    info "Running certbot renewal dry-run to verify configuration..."

    if certbot renew --dry-run --cert-name "$PANEL_DOMAIN" --non-interactive 2>&1 | grep -q "Congratulations"; then
        info "Dry-run renewal: PASSED"
    else
        # dry-run output goes to stdout; capture and show it
        certbot renew --dry-run --cert-name "$PANEL_DOMAIN" --non-interactive || true
        warn "Dry-run renewal did not print 'Congratulations'. Review output above."
    fi
}

# ─── Live certificate verification ────────────────────────────────────────────
verify_certificate() {
    info "Verifying live certificate for $PANEL_DOMAIN ..."

    local cert="$LE_LIVE_DIR/$PANEL_DOMAIN/cert.pem"

    # Subject
    SUBJECT=$(openssl x509 -noout -subject  -in "$cert" 2>/dev/null)
    EXPIRY=$(openssl x509  -noout -enddate  -in "$cert" 2>/dev/null)
    ISSUER=$(openssl x509  -noout -issuer   -in "$cert" 2>/dev/null)

    info "Certificate details:"
    info "  $SUBJECT"
    info "  $EXPIRY"
    info "  $ISSUER"

    # Check expiry is more than 30 days away
    EXPIRY_DATE=$(echo "$EXPIRY" | sed 's/notAfter=//')
    EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s 2>/dev/null || \
                   date -j -f "%b %d %H:%M:%S %Y %Z" "$EXPIRY_DATE" +%s 2>/dev/null)
    NOW_EPOCH=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

    if [[ "$DAYS_LEFT" -gt 30 ]]; then
        info "Certificate valid for $DAYS_LEFT days. ✓"
    else
        warn "Certificate expires in only $DAYS_LEFT days — check renewal setup."
    fi
}

# ─── Summary ──────────────────────────────────────────────────────────────────
print_summary() {
    echo
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN} SSL setup complete for: $PANEL_DOMAIN${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
    echo "  Certificate : $LE_LIVE_DIR/$PANEL_DOMAIN/fullchain.pem"
    echo "  Private key : $LE_LIVE_DIR/$PANEL_DOMAIN/privkey.pem"
    echo "  DH params   : $DH_PARAM_FILE"
    echo "  SSL snippet : $NGINX_SNIPPET_DIR/ssl-params.conf"
    echo "  Nginx config: $NGINX_CONF_DIR/panel.conf"
    echo "  Renewal hook: /etc/letsencrypt/renewal-hooks/post/reload-nginx.sh"
    echo "  Systemd     : certbot-renewal.timer (runs twice daily)"
    echo
    echo "  Panel URL   : https://$PANEL_DOMAIN"
    echo
    echo "  Test renewal: certbot renew --dry-run --cert-name $PANEL_DOMAIN"
    echo "  Timer status: systemctl status certbot-renewal.timer"
    echo "  SSL grade   : https://www.ssllabs.com/ssltest/analyze.html?d=$PANEL_DOMAIN"
    echo
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
    echo -e "${GREEN}"
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║   Oosoft SecurePanel — SSL Setup      ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo -e "${NC}"

    check_prerequisites
    check_dns
    generate_dhparam
    install_ssl_snippet
    setup_acme_webroot
    deploy_bootstrap_config
    issue_certificate
    deploy_production_config
    install_renewal_hook
    install_renewal_timer
    test_renewal
    verify_certificate
    print_summary
}

main "$@"
