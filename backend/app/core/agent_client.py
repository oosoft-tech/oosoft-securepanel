"""
Privileged agent client.

Communicates with the root-level agent over a Unix socket.
Sends authenticated JSON requests; returns the result dict on success.

The token is read once at import time from the environment so every
AgentClient instance shares the same token without repeated env lookups.
"""
import asyncio
import json
import logging
import os

AGENT_SOCKET   = "/run/securepanel/agent.sock"
CONNECT_TIMEOUT = 5.0    # seconds to establish the socket connection
READ_TIMEOUT    = 60.0   # seconds to wait for the agent to respond
MAX_RESPONSE    = 1 << 20  # 1 MB — generous ceiling for response payloads

logger = logging.getLogger(__name__)


def _load_token() -> str:
    token = os.environ.get("SECUREPANEL_AGENT_TOKEN", "")
    if len(token) < 32:
        raise RuntimeError(
            "SECUREPANEL_AGENT_TOKEN is not set or too short. "
            "The backend cannot call the privileged agent without it."
        )
    return token


# Load once at module import — fails loudly if not configured
_AGENT_TOKEN = _load_token()


class AgentError(RuntimeError):
    """Raised when the agent returns a non-ok status."""


class AgentClient:
    """
    Lightweight async client for the SecurePanel privileged agent.

    Usage::

        client = AgentClient()
        result = await client.call("nginx.create_domain", {"domain": "example.com", ...})
    """

    async def call(self, action: str, params: dict) -> dict:
        """
        Send an action request to the agent and return the result dict.

        Raises:
            RuntimeError  – socket not found / connection refused
            AgentError    – agent returned a non-ok response
            TimeoutError  – agent did not respond within READ_TIMEOUT
        """
        # Build payload including shared-secret token
        payload = json.dumps({
            "action": action,
            "params": params,
            "token":  _AGENT_TOKEN,
        }).encode("utf-8")

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(AGENT_SOCKET),
                timeout=CONNECT_TIMEOUT,
            )
        except FileNotFoundError:
            raise RuntimeError("Privileged agent socket not found — is securepanel-agent running?")
        except ConnectionRefusedError as exc:
            raise RuntimeError(f"Privileged agent refused connection: {exc}") from exc
        except asyncio.TimeoutError:
            raise RuntimeError("Timed out connecting to privileged agent")

        try:
            writer.write(payload)
            await writer.drain()

            raw = await asyncio.wait_for(
                reader.read(MAX_RESPONSE),
                timeout=READ_TIMEOUT,
            )
        except asyncio.TimeoutError:
            raise TimeoutError(f"Agent did not respond within {READ_TIMEOUT}s for action={action!r}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        # Parse response — treat decode/parse errors as agent-side failures
        try:
            response = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AgentError(f"Unparseable response from agent for action={action!r}") from exc

        if not isinstance(response, dict):
            raise AgentError(f"Unexpected response type from agent for action={action!r}")

        if response.get("status") != "ok":
            # Surface the agent's message but never log it at ERROR level —
            # the agent already logged the detail internally.
            msg = response.get("message", "unknown error")
            logger.warning("Agent returned non-ok for action=%r: %s", action, msg)
            raise AgentError(f"Agent error: {msg}")

        logger.debug("Agent call succeeded: action=%r", action)
        return response.get("result") or {}
