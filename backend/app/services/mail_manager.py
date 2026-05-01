import re
import subprocess
import logging
from pathlib import Path

from app.core.config import settings

logger = logging.getLogger(__name__)

EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}$")


class MailManager:
    def _validate_email(self, address: str) -> bool:
        return bool(EMAIL_PATTERN.fullmatch(address))

    async def create_mailbox(
        self,
        email: str,
        password: str | None = None,
        hashed_password: str | None = None,
        quota_mb: int = 1024,
    ) -> dict:
        if not self._validate_email(email):
            raise ValueError(f"Invalid email address: {email}")

        local, domain = email.split("@", 1)

        if hashed_password:
            pw_hash = hashed_password
        elif password:
            pw_hash = self._dovecot_hash(password)
        else:
            raise ValueError("Must provide password or hashed_password")

        maildir = Path(settings.VIRTUAL_MAILBOX_BASE) / domain / local
        maildir.mkdir(parents=True, exist_ok=True)
        for subdir in ["cur", "new", "tmp"]:
            (maildir / subdir).mkdir(exist_ok=True)

        self._append_dovecot_user(email, pw_hash, maildir, quota_mb)
        self._append_postfix_mailbox(email, domain, local)

        subprocess.run(["postmap", settings.POSTFIX_VMAILBOX_MAP], check=True)
        logger.info(f"Mailbox created: {email}")
        return {"email": email, "maildir": str(maildir), "quota_mb": quota_mb}

    def _dovecot_hash(self, password: str) -> str:
        result = subprocess.run(
            ["doveadm", "pw", "-s", "SHA512-CRYPT", "-p", password],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()

    def _append_dovecot_user(self, email: str, pw_hash: str, maildir: Path, quota_mb: int):
        line = f"{email}:{pw_hash}:5000:5000:::{maildir}::userdb_quota_rule=*:storage={quota_mb}M\n"
        with open(settings.DOVECOT_PASSWD_FILE, "a") as f:
            f.write(line)

    def _append_postfix_mailbox(self, email: str, domain: str, local: str):
        line = f"{email}  {domain}/{local}/\n"
        with open(settings.POSTFIX_VMAILBOX_MAP, "a") as f:
            f.write(line)

    async def delete_mailbox(self, email: str) -> None:
        if not self._validate_email(email):
            raise ValueError(f"Invalid email address: {email}")
        local, domain = email.split("@", 1)

        for path in [settings.DOVECOT_PASSWD_FILE, settings.POSTFIX_VMAILBOX_MAP]:
            with open(path, "r") as f:
                lines = f.readlines()
            with open(path, "w") as f:
                f.writelines(l for l in lines if not l.startswith(email))

        subprocess.run(["postmap", settings.POSTFIX_VMAILBOX_MAP], check=True)
        logger.info(f"Mailbox deleted: {email}")

    async def setup_dkim(self, domain: str) -> dict:
        key_dir = Path(f"/etc/opendkim/keys/{domain}")
        key_dir.mkdir(parents=True, exist_ok=True)

        subprocess.run([
            "opendkim-genkey", "-b", "2048",
            "-d", domain, "-D", str(key_dir),
            "-s", "default", "-v"
        ], check=True)

        pub_key_file = key_dir / "default.txt"
        dns_record = pub_key_file.read_text().strip()

        return {
            "domain": domain,
            "selector": "default",
            "dkim_dns": dns_record,
            "spf": f"v=spf1 mx a ~all",
            "dmarc": f'v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}; adkim=r; aspf=r',
        }
