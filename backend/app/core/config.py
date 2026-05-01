from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # App
    APP_ENV: str = "production"
    SECRET_KEY: str
    ALLOWED_HOSTS: List[str] = ["*"]
    CORS_ORIGINS: List[str] = []

    # JWT
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database
    DATABASE_URL: str

    # Redis / Celery
    REDIS_URL: str = "redis://127.0.0.1:6379/0"
    CELERY_BROKER_URL: str = "redis://127.0.0.1:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://127.0.0.1:6379/2"

    # Mail
    MAIL_DOMAIN: str = "localhost"
    POSTFIX_VMAILBOX_MAP: str = "/etc/postfix/vmailbox"
    DOVECOT_PASSWD_FILE: str = "/etc/dovecot/users"
    VIRTUAL_MAILBOX_BASE: str = "/var/mail/vhosts"

    # Paths
    NGINX_VHOST_DIR: str = "/etc/nginx/sites-enabled"
    PHPFPM_CONF_DIR: str = "/etc/php-fpm.d"
    LETSENCRYPT_WEBROOT: str = "/var/www/letsencrypt"

    # Anthropic AI (optional)
    ANTHROPIC_API_KEY: str = ""

    # Imunify360
    IMUNIFY_SOCKET: str = "/var/run/imunify360/imunify360.sock"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
