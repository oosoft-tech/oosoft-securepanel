import re
import logging
import aiomysql

from app.core.config import settings

logger = logging.getLogger(__name__)

NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]{1,64}$")


def _validate_name(name: str) -> None:
    if not NAME_PATTERN.fullmatch(name):
        raise ValueError(f"Invalid database/user name: {name}")


class DatabaseManager:
    def __init__(self):
        self._pool = None

    async def _get_pool(self):
        if not self._pool:
            self._pool = await aiomysql.create_pool(
                host="127.0.0.1", port=3306,
                user="securepanel_admin",
                password=settings.DB_ADMIN_PASSWORD,
                autocommit=True,
            )
        return self._pool

    async def create_database(self, db_name: str, owner_username: str) -> None:
        _validate_name(db_name)
        _validate_name(owner_username)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
                db_user = f"{owner_username}_usr"
                await cur.execute(
                    f"CREATE USER IF NOT EXISTS %s@'localhost' IDENTIFIED BY %s",
                    (db_user, self._random_password())
                )
                await cur.execute(
                    f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO %s@'localhost'",
                    (db_user,)
                )
                await cur.execute("FLUSH PRIVILEGES")
        logger.info(f"Database created: {db_name} owner={owner_username}")

    async def drop_database(self, db_name: str) -> None:
        _validate_name(db_name)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            async with conn.cursor() as cur:
                await cur.execute(f"DROP DATABASE IF EXISTS `{db_name}`")
        logger.info(f"Database dropped: {db_name}")

    async def import_sql(self, db_name: str, sql_data: bytes) -> None:
        _validate_name(db_name)
        import asyncio
        proc = await asyncio.create_subprocess_exec(
            "mysql", db_name,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate(input=sql_data)
        if proc.returncode != 0:
            raise RuntimeError(f"MySQL import failed: {stderr.decode()}")
        logger.info(f"SQL imported into {db_name}")

    def _random_password(self, length: int = 24) -> str:
        import secrets, string
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))
