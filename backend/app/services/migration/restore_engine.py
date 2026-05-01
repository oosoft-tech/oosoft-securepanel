import gzip
import tarfile
import shutil
import logging
from pathlib import Path

from app.services.mail_manager import MailManager
from app.services.db_manager import DatabaseManager
from app.services.nginx_manager import NginxManager
from app.services.cagefs_manager import CageFSManager
from app.core.agent_client import AgentClient
from app.services.migration.cpanel_parser import MigrationAccount

logger = logging.getLogger(__name__)

HOME_BASE = Path("/home")


class RestoreEngine:
    def __init__(self):
        self.mail = MailManager()
        self.db = DatabaseManager()
        self.nginx = NginxManager()
        self.cagefs = CageFSManager()
        self.agent = AgentClient()

    async def restore_account(
        self,
        account: MigrationAccount,
        backup_path: Path,
        task_id: str,
    ) -> dict:
        results = {"task_id": task_id, "domain": account.domain, "steps": []}

        try:
            # 1. Create system user
            await self.agent.call("user.create", {
                "username": account.username,
                "uid": "auto",
                "shell": "/bin/false",
            })
            results["steps"].append({"step": "user_created", "status": "ok"})

            # 2. Restore home directory
            await self._restore_homedir(account, backup_path)
            results["steps"].append({"step": "homedir_restored", "status": "ok"})

            # 3. Restore email accounts (preserve hashed passwords)
            email_errors = []
            for email_acc in account.email_accounts:
                try:
                    await self.mail.create_mailbox(
                        email=email_acc["full_address"],
                        hashed_password=email_acc["hashed_password"],
                        quota_mb=email_acc.get("quota_mb", 1024),
                    )
                except Exception as e:
                    email_errors.append({"email": email_acc["full_address"], "error": str(e)})
            results["steps"].append({
                "step": "email_restored",
                "count": len(account.email_accounts) - len(email_errors),
                "errors": email_errors,
                "status": "ok" if not email_errors else "partial",
            })

            # 4. Restore databases
            db_errors = []
            for db in account.databases:
                try:
                    await self._restore_database(account, backup_path, db)
                except Exception as e:
                    db_errors.append({"db": db["name"], "error": str(e)})
            results["steps"].append({
                "step": "databases_restored",
                "count": len(account.databases) - len(db_errors),
                "errors": db_errors,
                "status": "ok" if not db_errors else "partial",
            })

            # 5. Create Nginx vhost
            await self.nginx.create_vhost(
                username=account.username,
                domain=account.domain,
                php_version=account.php_version,
            )
            results["steps"].append({"step": "vhost_created", "status": "ok"})

            # 6. Create PHP-FPM pool
            await self.nginx.create_phpfpm_pool(account.username, account.php_version)
            results["steps"].append({"step": "phpfpm_pool_created", "status": "ok"})

            # 7. Enable CageFS
            await self.cagefs.enable_user(account.username)
            results["steps"].append({"step": "cagefs_enabled", "status": "ok"})

        except Exception as e:
            logger.exception(f"Restore failed for {account.username}: {e}")
            results["error"] = str(e)

        return results

    async def _restore_homedir(self, account: MigrationAccount, backup_path: Path) -> None:
        user_home = HOME_BASE / account.username
        user_home.mkdir(parents=True, exist_ok=True)

        with tarfile.open(backup_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.startswith("homedir/"):
                    # Strip "homedir/" prefix, write to user home
                    member.name = member.name[len("homedir/"):]
                    if not member.name:
                        continue
                    # Security: no absolute paths or traversal
                    if member.name.startswith("/") or ".." in member.name:
                        continue
                    tar.extract(member, path=user_home)

        # Fix ownership via agent
        await self.agent.call("user.fix_ownership", {"username": account.username})

    async def _restore_database(
        self, account: MigrationAccount, backup_path: Path, db: dict
    ) -> None:
        db_name = f"{account.username}_{db['name']}"

        with tarfile.open(backup_path, "r:gz") as tar:
            member = tar.getmember(db["dump_member"])
            fileobj = tar.extractfile(member)
            sql_data = gzip.decompress(fileobj.read())

        await self.db.create_database(db_name, account.username)
        await self.db.import_sql(db_name, sql_data)
        logger.info(f"Database restored: {db_name}")
