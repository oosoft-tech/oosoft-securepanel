import re
import logging
from collections import defaultdict, deque, Counter
from datetime import datetime, timezone
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

SUSPICIOUS_PATTERNS = [
    (re.compile(r"\.\./", re.IGNORECASE), "path_traversal"),
    (re.compile(r"union\s+select", re.IGNORECASE), "sql_injection"),
    (re.compile(r"<script", re.IGNORECASE), "xss_attempt"),
    (re.compile(r"etc/passwd", re.IGNORECASE), "lfi_attempt"),
    (re.compile(r"(cmd|exec|system)\s*=", re.IGNORECASE), "rce_attempt"),
    (re.compile(r"wp-login\.php", re.IGNORECASE), "wordpress_bruteforce"),
    (re.compile(r"\.php\?.*=(https?://|//)", re.IGNORECASE), "remote_file_include"),
]

ACCESS_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<size>\d+)'
)


@dataclass
class AnomalyEvent:
    timestamp: datetime
    severity: str
    category: str
    description: str
    source_ip: str | None
    username: str | None
    raw_evidence: list[str] = field(default_factory=list)
    suggested_action: str = ""


class LogAnomalyDetector:
    def __init__(self, window_size: int = 1000, rate_threshold_multiplier: float = 3.0):
        self.request_counts: dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))
        self.baselines: dict[str, float] = {}
        self.rate_threshold_multiplier = rate_threshold_multiplier

    def ingest_access_log_line(self, line: str) -> AnomalyEvent | None:
        match = ACCESS_LOG_PATTERN.match(line)
        if not match:
            return None

        ip = match.group("ip")
        status = int(match.group("status"))
        path = match.group("path")

        now = datetime.now(timezone.utc).timestamp()
        self.request_counts[ip].append(now)

        # Check traffic rate anomaly
        rate = self._calculate_rate(ip)
        baseline = self.baselines.get(ip, 10.0)
        if rate > baseline * self.rate_threshold_multiplier:
            return AnomalyEvent(
                timestamp=datetime.now(timezone.utc),
                severity="high",
                category="traffic",
                description=f"Traffic spike from {ip}: {rate:.0f} req/s (baseline {baseline:.0f})",
                source_ip=ip,
                username=None,
                raw_evidence=[line],
                suggested_action=f"Rate-limit or block {ip}",
            )

        # Check suspicious path patterns
        for pattern, category in SUSPICIOUS_PATTERNS:
            if pattern.search(path):
                return AnomalyEvent(
                    timestamp=datetime.now(timezone.utc),
                    severity="medium",
                    category=category,
                    description=f"Suspicious request from {ip}: {path[:120]}",
                    source_ip=ip,
                    username=None,
                    raw_evidence=[line],
                    suggested_action=f"Review and consider blocking {ip}",
                )

        # Update baseline (exponential moving average)
        self._update_baseline(ip, rate)
        return None

    def _calculate_rate(self, ip: str) -> float:
        counts = list(self.request_counts[ip])
        if len(counts) < 2:
            return 0.0
        duration = counts[-1] - counts[0]
        return len(counts) / max(duration, 1.0)

    def _update_baseline(self, ip: str, rate: float) -> None:
        alpha = 0.05
        current = self.baselines.get(ip, rate)
        self.baselines[ip] = alpha * rate + (1 - alpha) * current

    def analyze_auth_log(self, log_lines: list[str]) -> list[AnomalyEvent]:
        failed_pattern = re.compile(
            r"Failed (password|publickey) for .+ from (\d+\.\d+\.\d+\.\d+)"
        )
        ip_counts: Counter = Counter()
        ip_lines: dict[str, list[str]] = defaultdict(list)

        for line in log_lines:
            m = failed_pattern.search(line)
            if m:
                ip = m.group(2)
                ip_counts[ip] += 1
                ip_lines[ip].append(line)

        events = []
        for ip, count in ip_counts.items():
            if count > 10:
                events.append(AnomalyEvent(
                    timestamp=datetime.now(timezone.utc),
                    severity="high" if count > 50 else "medium",
                    category="auth",
                    description=f"Brute force from {ip}: {count} failed attempts",
                    source_ip=ip,
                    username=None,
                    raw_evidence=ip_lines[ip][:5],
                    suggested_action=f"Block {ip} immediately",
                ))
        return events
