import tarfile
import re
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class MigrationAccount:
    username: str
    domain: str
    email_accounts: list[dict] = field(default_factory=list)
    databases: list[dict] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    dns_records: list[dict] = field(default_factory=list)
    homedir_path: Optional[Path] = None
    php_version: str = "8.1"


class CpanelParser:
    def parse(self, backup_path: Path) -> MigrationAccount:
        account = MigrationAccount(username="", domain="")

        # Validate archive before opening (prevent path traversal)
        self._validate_archive(backup_path)

        with tarfile.open(backup_path, "r:gz") as tar:
            members = {m.name: m for m in tar.getmembers()}
            account = self._parse_userdata(tar, members, account)
            account = self._parse_email_accounts(tar, members, account)
            account = self._parse_databases(tar, members, account)
            account = self._parse_subdomains(tar, members, account)

        return account

    def _validate_archive(self, path: Path) -> None:
        with tarfile.open(path, "r:gz") as tar:
            for member in tar.getmembers():
                # Block absolute paths and traversal attempts
                if member.name.startswith("/") or ".." in member.name:
                    raise ValueError(f"Unsafe path in archive: {member.name}")

    def _parse_userdata(
        self, tar: tarfile.TarFile, members: dict, account: MigrationAccount
    ) -> MigrationAccount:
        for key in members:
            if key.endswith("userdata/main"):
                f = tar.extractfile(members[key])
                if f:
                    for line in f.read().decode().splitlines():
                        if line.startswith("user:"):
                            account.username = line.split(":", 1)[1].strip()
                        elif line.startswith("main_domain:"):
                            account.domain = line.split(":", 1)[1].strip()
        return account

    def _parse_email_accounts(
        self, tar: tarfile.TarFile, members: dict, account: MigrationAccount
    ) -> MigrationAccount:
        shadow_key = f"homedir/etc/{account.domain}/shadow"
        if shadow_key not in members:
            return account

        shadow_file = tar.extractfile(members[shadow_key])
        if not shadow_file:
            return account

        quota_map = self._parse_quota(tar, members, account.domain)

        for line in shadow_file.read().decode().splitlines():
            parts = line.split(":")
            if len(parts) < 2:
                continue
            local_user = parts[0]
            hashed_pw = parts[1]

            account.email_accounts.append({
                "local": local_user,
                "domain": account.domain,
                "full_address": f"{local_user}@{account.domain}",
                "hashed_password": hashed_pw,
                "quota_mb": quota_map.get(local_user, 1024),
            })

        logger.info(f"Parsed {len(account.email_accounts)} email accounts from cPanel backup")
        return account

    def _parse_quota(self, tar: tarfile.TarFile, members: dict, domain: str) -> dict:
        quota_key = f"homedir/etc/{domain}/quota"
        if quota_key not in members:
            return {}
        f = tar.extractfile(members[quota_key])
        if not f:
            return {}
        result = {}
        for line in f.read().decode().splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                try:
                    result[parts[0]] = int(parts[1])
                except ValueError:
                    pass
        return result

    def _parse_databases(
        self, tar: tarfile.TarFile, members: dict, account: MigrationAccount
    ) -> MigrationAccount:
        for name in members:
            if name.startswith("mysql/") and name.endswith(".sql.gz"):
                db_name = Path(name).name.replace(".sql.gz", "")
                account.databases.append({
                    "name": db_name,
                    "dump_member": name,
                })
        return account

    def _parse_subdomains(
        self, tar: tarfile.TarFile, members: dict, account: MigrationAccount
    ) -> MigrationAccount:
        for key in members:
            match = re.match(r"homedir/etc/([^/]+)/subdomains$", key)
            if match:
                f = tar.extractfile(members[key])
                if f:
                    for line in f.read().decode().splitlines():
                        subdomain = line.strip()
                        if subdomain:
                            account.subdomains.append(subdomain)
        return account
