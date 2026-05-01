import re
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FirewallSuggestion:
    ip: str
    reason: str
    confidence: str   # low / medium / high
    rule_type: str    # block / rate_limit


class FirewallAdvisor:
    """
    Analyze recent access/auth logs and suggest firewall rules.
    Purely heuristic — no external API calls needed.
    """

    def analyze(
        self,
        access_log_lines: list[str],
        auth_log_lines: list[str],
    ) -> list[FirewallSuggestion]:
        suggestions: list[FirewallSuggestion] = []
        suggestions.extend(self._analyze_access_patterns(access_log_lines))
        suggestions.extend(self._analyze_auth_patterns(auth_log_lines))
        return suggestions

    def _analyze_access_patterns(self, lines: list[str]) -> list[FirewallSuggestion]:
        ip_requests: Counter = Counter()
        ip_errors: dict[str, Counter] = defaultdict(Counter)

        pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) .+ "(?:GET|POST) ([^"]+)" (\d+)')

        for line in lines:
            m = pattern.search(line)
            if m:
                ip = m.group(1)
                status = int(m.group(3))
                ip_requests[ip] += 1
                if status in (400, 403, 404, 429, 500):
                    ip_errors[ip][status] += 1

        suggestions = []
        for ip, count in ip_requests.items():
            errors = sum(ip_errors[ip].values())
            error_rate = errors / count if count > 0 else 0

            if count > 1000 and error_rate > 0.5:
                suggestions.append(FirewallSuggestion(
                    ip=ip,
                    reason=f"High volume ({count} reqs) with {error_rate:.0%} error rate",
                    confidence="high",
                    rule_type="block",
                ))
            elif count > 500:
                suggestions.append(FirewallSuggestion(
                    ip=ip,
                    reason=f"High request volume: {count} requests",
                    confidence="medium",
                    rule_type="rate_limit",
                ))

        return suggestions

    def _analyze_auth_patterns(self, lines: list[str]) -> list[FirewallSuggestion]:
        fail_pattern = re.compile(r"Failed .+ from (\d+\.\d+\.\d+\.\d+)")
        ip_fails: Counter = Counter()

        for line in lines:
            m = fail_pattern.search(line)
            if m:
                ip_fails[m.group(1)] += 1

        suggestions = []
        for ip, fails in ip_fails.items():
            if fails > 20:
                suggestions.append(FirewallSuggestion(
                    ip=ip,
                    reason=f"Brute force: {fails} auth failures",
                    confidence="high",
                    rule_type="block",
                ))
            elif fails > 5:
                suggestions.append(FirewallSuggestion(
                    ip=ip,
                    reason=f"Repeated auth failures: {fails}",
                    confidence="medium",
                    rule_type="rate_limit",
                ))
        return suggestions
