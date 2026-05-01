import re
import logging
import anthropic

from app.core.config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a server administration assistant for Oosoft SecurePanel running on CloudLinux.
You help administrators diagnose hosting issues, interpret logs, and troubleshoot services.
You have access to sanitized log excerpts and system status information.

Rules:
- Never suggest bypassing security controls (CageFS, firewall, Imunify360)
- Never suggest running commands as root directly; recommend using the panel's agent
- Be concise and specific; prefer actionable steps
- Flag security concerns immediately"""


def _sanitize_logs(lines: list[str]) -> list[str]:
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    return [ip_pattern.sub("[IP_REDACTED]", line) for line in lines[:50]]


async def ask_assistant(
    question: str,
    context_logs: list[str] | None = None,
) -> str:
    if not settings.ANTHROPIC_API_KEY:
        return "AI assistant is not configured. Set ANTHROPIC_API_KEY in settings."

    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)

    content = question
    if context_logs:
        sanitized = _sanitize_logs(context_logs)
        content += "\n\nRelevant log excerpt:\n" + "\n".join(sanitized)

    try:
        response = client.messages.create(
            model="claude-opus-4-7",
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": content}],
        )
        return response.content[0].text
    except anthropic.APIError as e:
        logger.error(f"Anthropic API error: {e}")
        return f"AI assistant temporarily unavailable: {e}"
