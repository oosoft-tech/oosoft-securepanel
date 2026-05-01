import re
import logging
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.agent_client import AgentClient
from app.core.config import settings

TEMPLATE_DIR = Path("/opt/oosoft-securepanel/nginx/templates")
logger = logging.getLogger(__name__)


class NginxManager:
    def __init__(self):
        self.agent = AgentClient()
        self.jinja = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["conf"]),
        )

    def _validate_domain(self, domain: str) -> bool:
        pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        return bool(re.fullmatch(pattern, domain))

    def _validate_php_version(self, version: str) -> bool:
        return bool(re.fullmatch(r"^(7\.4|8\.[0-3])$", version))

    async def create_vhost(
        self,
        username: str,
        domain: str,
        php_version: str = "8.1",
        ssl: bool = False,
    ) -> None:
        if not self._validate_domain(domain):
            raise ValueError(f"Invalid domain: {domain}")
        if not self._validate_php_version(php_version):
            raise ValueError(f"Invalid PHP version: {php_version}")

        template_name = "ssl_vhost.conf.j2" if ssl else "vhost.conf.j2"
        template = self.jinja.get_template(template_name)

        config = template.render(
            domain=domain,
            username=username,
            webroot=f"/home/{username}/public_html/{domain}",
            php_socket=f"/run/php-fpm/{php_version}/{username}.sock",
            log_dir=f"/var/log/securepanel/users/{username}",
        )

        await self.agent.call("nginx.write_vhost", {
            "username": username,
            "domain": domain,
            "config_content": config,
        })
        await self.agent.call("nginx.reload", {})
        logger.info(f"Vhost created for domain={domain} user={username}")

    async def delete_vhost(self, username: str, domain: str) -> None:
        if not self._validate_domain(domain):
            raise ValueError(f"Invalid domain: {domain}")
        await self.agent.call("nginx.delete_vhost", {"username": username, "domain": domain})
        await self.agent.call("nginx.reload", {})
        logger.info(f"Vhost deleted for domain={domain} user={username}")

    async def create_phpfpm_pool(self, username: str, php_version: str = "8.1") -> None:
        if not self._validate_php_version(php_version):
            raise ValueError(f"Invalid PHP version: {php_version}")

        pool_config = f"""[{username}]
user = {username}
group = {username}
listen = /run/php-fpm/{php_version}/{username}.sock
listen.owner = nginx
listen.group = nginx
listen.mode = 0660

pm = ondemand
pm.max_children = 10
pm.process_idle_timeout = 10s

php_admin_value[open_basedir] = /home/{username}/:/tmp/
php_admin_value[disable_functions] = exec,shell_exec,system,passthru,popen,proc_open,pcntl_exec
php_admin_value[error_log] = /var/log/securepanel/users/{username}/php_error.log
php_admin_flag[log_errors] = on
"""
        await self.agent.call("phpfpm.write_pool", {
            "username": username,
            "php_version": php_version,
            "config_content": pool_config,
        })
        await self.agent.call("phpfpm.reload", {"version": php_version})
