# Oosoft SecurePanel — Security Checklist

## Authentication & Access
- [ ] JWT tokens use HS256 with 256-bit secret, rotate monthly
- [ ] Refresh tokens stored as httpOnly cookies; access tokens in memory only
- [ ] Token revocation list in Redis with TTL matching token expiry
- [ ] Failed login rate limiting: 5 attempts → 15-minute lockout
- [ ] MFA (TOTP) mandatory for admin accounts
- [ ] Session invalidated on password change

## Privilege Separation
- [ ] Backend runs as unprivileged `securepanel` user (UID 999)
- [ ] All root operations go through Unix socket agent only
- [ ] Agent has strict action allowlist with regex validation on every param
- [ ] Agent logs every executed action with timestamp and params
- [ ] No `shell=True` in any subprocess call — all calls use list form
- [ ] Privileged agent socket permissions: 0660, owned root:securepanel

## Network
- [ ] Panel accessible only via HTTPS (TLS 1.2+, prefer 1.3)
- [ ] nftables custom chain initialized on boot
- [ ] Default-deny INPUT policy (whitelist only panel and SSH ports)
- [ ] Panel port firewalled to admin IPs only
- [ ] Brute-force detection active (auto-block after 10 failures)
- [ ] Login endpoint rate limited at Nginx level (5 req/min)

## User Isolation
- [ ] CageFS enabled for every hosting account on creation
- [ ] PHP-FPM pool per user (separate Unix socket, UID/GID)
- [ ] PHP dangerous functions disabled: exec, shell_exec, system, passthru, popen, proc_open, pcntl_exec
- [ ] `open_basedir` set per virtual host to restrict file access
- [ ] Symlink protection enabled (CloudLinux kernel feature)
- [ ] Each user's Nginx vhost runs with their own PHP-FPM socket

## File Integrity
- [ ] Imunify360 real-time scanning active on all home directories
- [ ] Alerts configured for malware detections
- [ ] Panel installation directory monitored for unauthorized changes
- [ ] Backup archives SHA-256 verified before migration restore

## Email Security
- [ ] DKIM 2048-bit keys generated per domain on creation
- [ ] SPF records auto-added to DNS zone on domain creation
- [ ] DMARC policy minimum: `p=quarantine`
- [ ] Postfix `reject_unknown_sender_domain` enabled
- [ ] TLS enforced for SMTP relay (opportunistic + mandatory where possible)
- [ ] Email password hashes migrated without re-hashing (Dovecot SHA-512-CRYPT compatible)

## Migration Security
- [ ] Backup archives scanned with Imunify before extraction
- [ ] Tar path traversal protection: reject members with `..` or absolute paths
- [ ] Database imports run as restricted MySQL user (not root)
- [ ] Email password hashes migrated directly — no plaintext exposure
- [ ] All restored file ownership corrected via agent post-restore
- [ ] Upload size limit enforced (10 GB max)

## Monitoring & Logging
- [ ] Centralized logs in `/var/log/securepanel/` (not user-accessible)
- [ ] Log rotation configured (90-day retention, compressed)
- [ ] Real-time anomaly detection on Nginx access logs (Celery task)
- [ ] Admin email alerts on: login failures, IP blocks, malware detections
- [ ] Resource per-user quotas enforced (disk, PHP-FPM limits)
- [ ] Agent audit log separate from application log

## Server Hardening
- [ ] Root SSH login disabled
- [ ] SSH password auth disabled (keys only)
- [ ] Kernel sysctl: rp_filter, syncookies, ASLR, protected symlinks/hardlinks
- [ ] PHP dangerous functions disabled in all php.ini files
- [ ] No world-writable directories in home paths
- [ ] `/tmp` mounted with `noexec,nosuid` flags

## Deployment
- [ ] `.env` file permissions: 0600, owned by `securepanel`
- [ ] SECRET_KEY is 256-bit random, not default
- [ ] DB_ADMIN_PASSWORD is strong random, not default
- [ ] API docs endpoints disabled (`docs_url=None`, `redoc_url=None`)
- [ ] CORS origins explicitly set (no wildcard in production)
- [ ] ALLOWED_HOSTS explicitly set to panel domain only
