# Oosoft SecurePanel — Security Checklist

> This document outlines the security architecture and controls of Oosoft SecurePanel.
> Certain implementation details are intentionally abstracted to prevent misuse and reduce attack surface exposure.

---

## Authentication & Access

- [ ] JWT tokens use a strong signing algorithm with secrets rotated on a regular schedule
- [ ] Refresh tokens stored as `httpOnly`, `Secure`, `SameSite=Strict` cookies; access tokens held in memory only
- [ ] Token revocation mechanism in place with expiry-matched invalidation
- [ ] Failed login attempts trigger progressive rate limiting and temporary account lockout
- [ ] Multi-factor authentication (TOTP) enforced for all administrator accounts
- [ ] All active sessions invalidated immediately upon password change
- [ ] Login activity logged with IP, timestamp, and outcome

---

## Privilege Separation

- [ ] Application backend runs as a dedicated unprivileged system user — never as root
- [ ] All privileged system operations are routed exclusively through a controlled internal agent
- [ ] The agent enforces a strict allowlist of permitted operations; no arbitrary command execution is possible
- [ ] Every agent action is logged with a timestamp, actor, and parameters before execution
- [ ] No shell interpolation used in subprocess calls — all invocations use structured argument lists
- [ ] Inter-process communication channels are permission-restricted to authorized processes only
- [ ] Least-privilege principle applied to all service accounts and database users

---

## Network Security

- [ ] Panel accessible only over HTTPS with TLS 1.2 as the minimum; TLS 1.3 preferred
- [ ] Firewall initialized on boot with a default-deny inbound policy
- [ ] Panel management port restricted to trusted admin IP ranges only (not publicly accessible)
- [ ] SSH access restricted by IP allowlist; exposed only where operationally required
- [ ] Brute-force detection active with automatic IP blocking upon threshold breach
- [ ] Login and authentication endpoints rate-limited at the reverse proxy level
- [ ] All outbound connections reviewed; unnecessary egress rules removed

---

## User Isolation

- [ ] Each hosting account is jailed at the filesystem level using CageFS on creation
- [ ] PHP processes run under per-user pools with separate execution contexts
- [ ] High-risk PHP functions disabled globally across all user environments
- [ ] File access restricted per virtual host via `open_basedir` or equivalent
- [ ] Symlink following between user directories is blocked at the kernel/OS level
- [ ] No shared writable paths between tenants
- [ ] Resource limits (CPU, memory, disk I/O) enforced per user to prevent abuse

---

## File Integrity

- [ ] Real-time malware scanning active on all user home directories
- [ ] Alerts triggered immediately on malware detection or quarantine events
- [ ] Critical system directories (internal paths not disclosed) monitored for unauthorized modification
- [ ] Backup archives cryptographically verified before any migration restore operation
- [ ] File permission audits run periodically on sensitive configuration directories

---

## Email Security

- [ ] DKIM keys (minimum 2048-bit RSA) generated automatically per domain at creation time
- [ ] SPF records provisioned in DNS automatically on domain creation
- [ ] DMARC policy set to at least `p=quarantine` with a reporting address configured
- [ ] Mail server configured to reject messages from unverifiable sender domains
- [ ] TLS encryption enforced for SMTP relay; opportunistic TLS used where mandatory is not supported
- [ ] Email credentials stored as one-way hashes; plaintext passwords never retained or transmitted
- [ ] Migrations preserve existing credential hashes — no forced password resets required

---

## Migration Security

- [ ] All uploaded backup archives scanned for malware before extraction begins
- [ ] Archive extraction enforces path traversal protection — absolute paths and `..` sequences are rejected
- [ ] Database imports executed under a restricted database user, not the administrative account
- [ ] Email password hashes transferred directly; no intermediate plaintext representation
- [ ] File ownership and permissions corrected programmatically after every restore operation
- [ ] Upload size limits enforced to prevent resource exhaustion
- [ ] Migration jobs run asynchronously and are audited end-to-end

---

## Monitoring & Logging

- [ ] Centralized logging to critical system directories (internal paths not disclosed), inaccessible to hosted users
- [ ] Log rotation and retention policies configured in compliance with operational requirements
- [ ] Real-time anomaly detection active on web server access logs
- [ ] Admin alerts triggered on: failed logins, IP blocks, malware events, and abnormal traffic patterns
- [ ] Per-user resource quotas monitored and enforced
- [ ] Privileged agent audit log maintained separately from the application log
- [ ] All log data protected from tampering; integrity checks applied where feasible

---

## Server Hardening

- [ ] Root login over SSH disabled; key-based authentication required
- [ ] SSH password authentication disabled system-wide
- [ ] Kernel hardening parameters applied: reverse path filtering, SYN cookie protection, ASLR, and link protection
- [ ] Dangerous PHP functions disabled in all active PHP configurations
- [ ] No world-writable directories permitted in user home paths
- [ ] Temporary filesystems mounted with `noexec` and `nosuid` flags
- [ ] Unused system services and network daemons disabled
- [ ] OS and security packages kept up to date on a defined patch schedule

---

## Secrets Management

- [ ] No secrets, credentials, or API keys stored in source code or version control
- [ ] All secrets provided via environment variables or a dedicated secret management system
- [ ] API keys and tokens rotated on a defined periodic schedule
- [ ] Access to production credentials restricted to authorized personnel only
- [ ] Secret management tooling audited for access and usage
- [ ] Secrets scanning integrated into the CI/CD pipeline to prevent accidental exposure
- [ ] Compromised credentials revoked and rotated immediately upon detection

---

## Deployment

- [ ] Environment configuration files restricted to owner read/write; no group or world access
- [ ] All default secrets replaced with cryptographically strong random values before deployment
- [ ] API documentation endpoints disabled in production builds
- [ ] CORS policy explicitly configured — wildcard origins prohibited in production
- [ ] Allowed host headers explicitly defined and restricted to the panel domain
- [ ] Container or service images built from minimal base images and regularly rebuilt
- [ ] Dependency versions pinned and audited for known vulnerabilities before release
