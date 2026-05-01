#!/usr/bin/env python3
"""
Oosoft SecurePanel Privileged Agent
Runs as root. Exposes a Unix socket with strict command allowlist validation,
shared-secret authentication, request size enforcement, sanitized logging,
and lightweight rate limiting.

Architecture: Unix socket → authentication → size check → JSON validation
              → allowlist check → handler execution → sanitized response
"""
import asyncio
import grp
import hmac
import json
import logging
import os
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Configuration — all tunables in one place
# ---------------------------------------------------------------------------

SOCKET_PATH        = "/run/securepanel/agent.sock"
LOG_PATH           = "/var/log/securepanel/agent.log"
SOCKET_DIR_MODE    = 0o750
SOCKET_FILE_MODE   = 0o660
SOCKET_GROUP       = "securepanel"

MAX_REQUEST_BYTES  = 65_536          # 64 KB hard limit
REQUEST_TIMEOUT    = 10.0            # seconds to receive a complete request
HANDLER_TIMEOUT    = 60.0            # seconds a handler is allowed to run

# Rate limiting: max requests per IP-equivalent (PID bucket) per window
RATE_LIMIT_MAX     = 30              # max requests
RATE_LIMIT_WINDOW  = 60.0           # per 60 seconds

# Fields whose values must never appear in logs
_SENSITIVE_FIELDS  = frozenset({"password", "secret", "token", "key", "passwd", "hash"})

# Maximum length of any single param value written to a log line
_LOG_PARAM_MAX_LEN = 200

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("agent")


# ---------------------------------------------------------------------------
# Safe logging helpers
# ---------------------------------------------------------------------------

def _sanitize_value(key: str, value: Any) -> str:
    """Return a log-safe representation of a param value."""
    if key.lower() in _SENSITIVE_FIELDS:
        return "[REDACTED]"
    text = str(value)
    # Strip newlines and carriage returns to prevent log injection
    text = text.replace("\n", " ").replace("\r", " ")
    if len(text) > _LOG_PARAM_MAX_LEN:
        text = text[:_LOG_PARAM_MAX_LEN] + "…[truncated]"
    return text


def _sanitize_params(params: dict) -> str:
    """Return a single-line, log-safe rendering of a params dict."""
    if not isinstance(params, dict):
        return "[invalid-params]"
    parts = [f"{k}={_sanitize_value(k, v)}" for k, v in params.items()]
    return "{" + ", ".join(parts) + "}"


def _sanitize_action(action: str) -> str:
    """Strip whitespace/newlines from the action name for safe logging."""
    return str(action).replace("\n", "").replace("\r", "")[:128]


# ---------------------------------------------------------------------------
# Shared-secret authentication
# ---------------------------------------------------------------------------

def _load_agent_token() -> bytes:
    """
    Load the shared secret from the environment.
    Abort startup if it is missing or too short.
    """
    token = os.environ.get("SECUREPANEL_AGENT_TOKEN", "")
    if len(token) < 32:
        raise RuntimeError(
            "SECUREPANEL_AGENT_TOKEN is missing or too short (minimum 32 characters). "
            "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
        )
    return token.encode()


def _verify_token(provided: str, expected: bytes) -> bool:
    """Constant-time comparison to prevent timing-based token leakage."""
    if not isinstance(provided, str):
        return False
    return hmac.compare_digest(provided.encode(), expected)


# ---------------------------------------------------------------------------
# In-memory rate limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    """
    Sliding-window rate limiter keyed on peer identity.
    Uses asyncio.Lock for safe concurrent access.
    """

    def __init__(self, max_requests: int, window: float) -> None:
        self._max = max_requests
        self._window = window
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def is_allowed(self, peer: str) -> bool:
        now = time.monotonic()
        cutoff = now - self._window
        async with self._lock:
            timestamps = self._buckets[peer]
            # Discard timestamps outside the current window
            self._buckets[peer] = [t for t in timestamps if t > cutoff]
            if len(self._buckets[peer]) >= self._max:
                return False
            self._buckets[peer].append(now)
            return True

    async def purge_stale(self) -> None:
        """Remove buckets that have been idle for longer than the window."""
        now = time.monotonic()
        cutoff = now - self._window
        async with self._lock:
            stale = [k for k, ts in self._buckets.items() if not any(t > cutoff for t in ts)]
            for k in stale:
                del self._buckets[k]


# ---------------------------------------------------------------------------
# Validator — initialized once at startup
# ---------------------------------------------------------------------------

def _load_validator():
    try:
        from validator import CommandValidator
        return CommandValidator()
    except Exception as exc:
        raise RuntimeError(f"Failed to load CommandValidator: {exc}") from exc


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    validator,
    rate_limiter: _RateLimiter,
    agent_token: bytes,
) -> None:
    # Use the file descriptor as a lightweight peer identifier for rate limiting.
    # True per-process identity would require SCM_CREDENTIALS (Linux-only ancillary data);
    # fd-based bucketing provides sufficient DoS protection for this threat model.
    peer_id = str(writer.get_extra_info("socket").fileno())
    response: dict = {}

    try:
        # ----------------------------------------------------------------
        # Rate limit check — before reading any data
        # ----------------------------------------------------------------
        if not await rate_limiter.is_allowed(peer_id):
            logger.warning(f"RATE_LIMITED peer={peer_id}")
            response = {"status": "error", "message": "Rate limit exceeded"}
            return

        # ----------------------------------------------------------------
        # Enforce request size — read at most MAX_REQUEST_BYTES + 1 byte
        # The extra byte lets us detect oversized payloads without loading them.
        # ----------------------------------------------------------------
        raw = await asyncio.wait_for(
            reader.read(MAX_REQUEST_BYTES + 1),
            timeout=REQUEST_TIMEOUT,
        )

        if len(raw) > MAX_REQUEST_BYTES:
            logger.warning(f"OVERSIZED_REQUEST peer={peer_id} size={len(raw)}")
            response = {"status": "error", "message": "Request too large"}
            return

        if not raw:
            response = {"status": "error", "message": "Empty request"}
            return

        # ----------------------------------------------------------------
        # JSON parsing
        # ----------------------------------------------------------------
        try:
            request = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.warning(f"MALFORMED_JSON peer={peer_id}")
            response = {"status": "error", "message": "Malformed request"}
            return

        # ----------------------------------------------------------------
        # Schema enforcement — must be a flat object with required keys
        # ----------------------------------------------------------------
        if not isinstance(request, dict):
            logger.warning(f"INVALID_SCHEMA peer={peer_id}")
            response = {"status": "error", "message": "Malformed request"}
            return

        action = request.get("action")
        params = request.get("params")
        token  = request.get("token")

        if not isinstance(action, str) or not isinstance(params, dict) or not isinstance(token, str):
            logger.warning(f"SCHEMA_MISMATCH peer={peer_id}")
            response = {"status": "error", "message": "Malformed request"}
            return

        # Reject unexpected top-level keys to prevent parameter smuggling
        allowed_keys = {"action", "params", "token"}
        if set(request.keys()) - allowed_keys:
            logger.warning(f"EXTRA_KEYS peer={peer_id} keys={list(request.keys())}")
            response = {"status": "error", "message": "Malformed request"}
            return

        # ----------------------------------------------------------------
        # Authentication — constant-time token comparison
        # ----------------------------------------------------------------
        if not _verify_token(token, agent_token):
            logger.warning(f"AUTH_FAILED peer={peer_id} action={_sanitize_action(action)}")
            response = {"status": "error", "message": "Unauthorized"}
            return

        # ----------------------------------------------------------------
        # Allowlist validation
        # ----------------------------------------------------------------
        safe_action = _sanitize_action(action)
        safe_params = _sanitize_params(params)

        if not validator.is_allowed(action, params):
            logger.warning(f"BLOCKED peer={peer_id} action={safe_action} params={safe_params}")
            response = {"status": "error", "message": "Action not permitted"}
            return

        # ----------------------------------------------------------------
        # Handler execution
        # ----------------------------------------------------------------
        logger.info(f"EXEC peer={peer_id} action={safe_action} params={safe_params}")
        handler = validator.get_handler(action)

        try:
            result = await asyncio.wait_for(handler(params), timeout=HANDLER_TIMEOUT)
        except asyncio.TimeoutError:
            logger.error(f"HANDLER_TIMEOUT peer={peer_id} action={safe_action}")
            response = {"status": "error", "message": "Handler timed out"}
            return
        except Exception:
            # Log the full traceback internally; return a generic message to the caller.
            logger.exception(f"HANDLER_ERROR peer={peer_id} action={safe_action}")
            response = {"status": "error", "message": "Internal error"}
            return

        logger.info(f"OK peer={peer_id} action={safe_action}")
        response = {"status": "ok", "result": result}

    except asyncio.TimeoutError:
        logger.warning(f"READ_TIMEOUT peer={peer_id}")
        response = {"status": "error", "message": "Request timed out"}

    except Exception:
        # Catch-all: log internally, never expose traceback to client
        logger.exception(f"UNEXPECTED_ERROR peer={peer_id}")
        response = {"status": "error", "message": "Internal error"}

    finally:
        try:
            writer.write(json.dumps(response).encode("utf-8"))
            await writer.drain()
        except Exception:
            logger.exception(f"WRITE_ERROR peer={peer_id}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Background maintenance task
# ---------------------------------------------------------------------------

async def _maintenance_loop(rate_limiter: _RateLimiter) -> None:
    """Periodically purge stale rate-limiter buckets to prevent memory growth."""
    while True:
        await asyncio.sleep(300)
        await rate_limiter.purge_stale()


# ---------------------------------------------------------------------------
# Socket setup
# ---------------------------------------------------------------------------

def _get_gid(name: str) -> int:
    return grp.getgrnam(name).gr_gid


def _setup_socket_directory() -> None:
    socket_dir = Path(SOCKET_PATH).parent
    socket_dir.mkdir(parents=True, exist_ok=True)
    # Restrict directory: only root and securepanel group may enter
    try:
        gid = _get_gid(SOCKET_GROUP)
        os.chown(socket_dir, 0, gid)
    except KeyError:
        logger.warning(f"Group '{SOCKET_GROUP}' not found — directory permissions may be insecure")
    os.chmod(socket_dir, SOCKET_DIR_MODE)


def _setup_socket_permissions() -> None:
    try:
        gid = _get_gid(SOCKET_GROUP)
        os.chown(SOCKET_PATH, 0, gid)
    except KeyError:
        logger.warning(f"Group '{SOCKET_GROUP}' not found — socket permissions may be insecure")
    os.chmod(SOCKET_PATH, SOCKET_FILE_MODE)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    # Load authentication token — aborts if not configured
    agent_token = _load_agent_token()

    # Initialize validator once; fail fast if handlers can't be loaded
    validator = _load_validator()

    # Initialize rate limiter
    rate_limiter = _RateLimiter(max_requests=RATE_LIMIT_MAX, window=RATE_LIMIT_WINDOW)

    # Prepare socket directory with hardened permissions
    _setup_socket_directory()

    # Remove stale socket from a previous run
    socket_path = Path(SOCKET_PATH)
    if socket_path.exists():
        socket_path.unlink()

    # Bind all injected dependencies via a closure so handle_client stays
    # compatible with asyncio.start_unix_server (which passes only reader/writer)
    async def _bound_handler(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        await handle_client(
            reader, writer,
            validator=validator,
            rate_limiter=rate_limiter,
            agent_token=agent_token,
        )

    server = await asyncio.start_unix_server(_bound_handler, path=SOCKET_PATH)

    # Harden socket file permissions after bind
    _setup_socket_permissions()

    logger.info(
        f"SecurePanel privileged agent started — "
        f"socket={SOCKET_PATH} rate_limit={RATE_LIMIT_MAX}req/{RATE_LIMIT_WINDOW}s"
    )

    async with asyncio.TaskGroup() as tg:
        tg.create_task(server.serve_forever())
        tg.create_task(_maintenance_loop(rate_limiter))


if __name__ == "__main__":
    if os.getuid() != 0:
        raise SystemExit("Agent must run as root")
    asyncio.run(main())
