import re
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

VSFTPD_USERS_DIR = Path("/etc/vsftpd/users")
USERNAME_PATTERN = re.compile(r"^[a-z0-9_]{1,32}$")


class FTPManager:
    def _validate_username(self, username: str) -> None:
        if not USERNAME_PATTERN.fullmatch(username):
            raise ValueError(f"Invalid FTP username: {username}")

    async def create_ftp_account(
        self,
        username: str,
        password: str,
        home_dir: str,
    ) -> dict:
        self._validate_username(username)

        result = subprocess.run(
            ["htpasswd", "-b", "-c", str(VSFTPD_USERS_DIR / username), username, password],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to create FTP account: {result.stderr}")

        user_conf = VSFTPD_USERS_DIR / f"{username}.conf"
        user_conf.write_text(
            f"local_root={home_dir}\n"
            f"write_enable=YES\n"
            f"local_umask=022\n"
        )

        subprocess.run(["systemctl", "reload", "vsftpd"], check=True)
        logger.info(f"FTP account created: {username} -> {home_dir}")
        return {"username": username, "home_dir": home_dir}

    async def delete_ftp_account(self, username: str) -> None:
        self._validate_username(username)
        for path in [
            VSFTPD_USERS_DIR / username,
            VSFTPD_USERS_DIR / f"{username}.conf",
        ]:
            if path.exists():
                path.unlink()
        subprocess.run(["systemctl", "reload", "vsftpd"], check=True)
        logger.info(f"FTP account deleted: {username}")
