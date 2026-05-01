import re
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

ZONE_DIR = Path("/etc/bind/zones")
DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV"}


class DNSManager:
    def _validate_domain(self, domain: str) -> None:
        if not DOMAIN_PATTERN.fullmatch(domain):
            raise ValueError(f"Invalid domain: {domain}")

    def _validate_record_type(self, rtype: str) -> None:
        if rtype.upper() not in RECORD_TYPES:
            raise ValueError(f"Invalid record type: {rtype}")

    async def create_zone(self, domain: str, server_ip: str) -> None:
        self._validate_domain(domain)

        zone_content = f"""$ORIGIN {domain}.
$TTL 3600
@   IN  SOA ns1.{domain}. hostmaster.{domain}. (
            2024010101 ; serial
            3600       ; refresh
            900        ; retry
            604800     ; expire
            300 )      ; minimum TTL

@       IN  NS  ns1.{domain}.
@       IN  NS  ns2.{domain}.
@       IN  A   {server_ip}
www     IN  A   {server_ip}
mail    IN  A   {server_ip}
@       IN  MX  10 mail.{domain}.
"""
        zone_file = ZONE_DIR / f"{domain}.zone"
        zone_file.write_text(zone_content)

        self._add_to_named_conf(domain, zone_file)
        subprocess.run(["rndc", "reload"], check=True)
        logger.info(f"DNS zone created: {domain}")

    def _add_to_named_conf(self, domain: str, zone_file: Path) -> None:
        named_conf = Path("/etc/bind/named.conf.local")
        entry = f"""
zone "{domain}" {{
    type master;
    file "{zone_file}";
    allow-transfer {{ none; }};
}};
"""
        with open(named_conf, "a") as f:
            f.write(entry)

    async def add_record(
        self, domain: str, name: str, rtype: str, value: str, ttl: int = 3600
    ) -> None:
        self._validate_domain(domain)
        self._validate_record_type(rtype)

        zone_file = ZONE_DIR / f"{domain}.zone"
        if not zone_file.exists():
            raise FileNotFoundError(f"Zone file not found for {domain}")

        record_line = f"{name}  {ttl}  IN  {rtype.upper()}  {value}\n"
        with open(zone_file, "a") as f:
            f.write(record_line)

        self._increment_serial(zone_file)
        subprocess.run(["rndc", "reload", domain], check=True)
        logger.info(f"DNS record added: {name}.{domain} {rtype} {value}")

    def _increment_serial(self, zone_file: Path) -> None:
        from datetime import date
        content = zone_file.read_text()
        today = date.today().strftime("%Y%m%d")
        new_serial = f"{today}01"
        content = re.sub(r"\d{10}\s*;\s*serial", f"{new_serial} ; serial", content)
        zone_file.write_text(content)
