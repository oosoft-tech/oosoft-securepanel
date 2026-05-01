import tarfile
import re
import logging
from pathlib import Path
from app.services.migration.cpanel_parser import MigrationAccount

logger = logging.getLogger(__name__)


class DirectAdminParser:
    """
    Parse DirectAdmin backup archives.
    DA backup structure differs from cPanel:
    - backup.tar.gz contains domains/, databases/, email/
    """

    def parse(self, backup_path: Path) -> MigrationAccount:
        self._validate_archive(backup_path)
        account = MigrationAccount(username="", domain="")

        with tarfile.open(backup_path, "r:gz") as tar:
            members = {m.name: m for m in tar.getmembers()}
            account = self._parse_domain_conf(tar, members, account)
            account = self._parse_email(tar, members, account)
            account = self._parse_databases(tar, members, account)

        return account

    def _validate_archive(self, path: Path) -> None:
        with tarfile.open(path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.startswith("/") or ".." in member.name:
                    raise ValueError(f"Unsafe path in archive: {member.name}")

    def _parse_domain_conf(
        self, tar: tarfile.TarFile, members: dict, account: MigrationAccount
    ) -> MigrationAccount:
        for key in members:
            if re.match(r"^[^/]+/domain\.conf$", key):
                f = tar.extractfile(members[key])
                if f:
                    for line in f.read().decode().splitlines():
                        if "=" in line:
                            k, v = line.split("=", 1)
                            if k.strip() == "domain":
                                account.domain = v.strip()
                            elif k.strip() == "username":
                                account.username = v.strip()
        return account

    def _parse_email(
        self, tar: tarfile.TarFile, members: dict, account: MigrationAccount
    ) -> MigrationAccount:
        for key in members:
            # DA stores: email/user@domain/passwd
            match = re.match(r"email/([^@]+)@([^/]+)/passwd$", key)
            if match:
                local = match.group(1)
                domain = match.group(2)
                f = tar.extractfile(members[key])
                if f:
                    hashed_pw = f.read().decode().strip()
                    account.email_accounts.append({
                        "local": local,
                        "domain": domain,
                        "full_address": f"{local}@{domain}",
                        "hashed_password": hashed_pw,
                        "quota_mb": 1024,
                    })
        logger.info(f"Parsed {len(account.email_accounts)} email accounts from DirectAdmin backup")
        return account

    def _parse_databases(
        self, tar: tarfile.TarFile, members: dict, account: MigrationAccount
    ) -> MigrationAccount:
        for name in members:
            if name.startswith("databases/") and name.endswith(".sql.gz"):
                db_name = Path(name).name.replace(".sql.gz", "")
                account.databases.append({
                    "name": db_name,
                    "dump_member": name,
                })
        return account
