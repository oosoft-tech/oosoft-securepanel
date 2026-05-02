"""
backend/agent/utils/exec.py
─────────────────────────────────────────────────────────────────────────────
Centralised safe command execution layer for the Oosoft SecurePanel agent.

This module is the ONLY place in the entire agent codebase where
subprocesses are spawned.  Every handler must call run_command() instead
of using asyncio.create_subprocess_exec() directly.

Security guarantees
───────────────────
1. Executable allowlist   — only binaries registered in _ALLOWED_BINARIES
                            may be run; everything else raises CommandError
                            before a process is ever created.

2. Binary path pinning    — the resolved (real) path of the executable must
                            live under one of the SAFE_PATH_PREFIXES; a
                            trojan "nginx" in /tmp will be rejected.

3. No shell=True          — ever. asyncio.create_subprocess_exec is used
                            with an explicit argument list; the OS kernel
                            never sees a shell command string.

4. Argument sanity        — every argument is verified to be a non-empty
                            str with no null bytes before the process starts.

5. Enforced timeout       — per-binary default timeouts; caller may tighten
                            but never exceed the registered maximum.
                            On timeout: SIGTERM → 2-second grace → SIGKILL.

6. Output size cap        — stdout and stderr are each capped at
                            MAX_OUTPUT_BYTES; excess is truncated and flagged.
                            This prevents a runaway process from filling RAM.

7. Safe logging           — only the binary basename and argument count are
                            written to the log; argument values are never
                            logged (they may contain usernames / paths).
                            Duration is recorded for performance monitoring.

8. Structured error       — CommandError carries the full CommandResult so
                            callers can inspect returncode/stderr without the
                            exec layer leaking details to the network layer.
"""
import asyncio
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from typing import FrozenSet

logger = logging.getLogger("agent.exec")

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

# Maximum bytes captured from stdout or stderr (each).
# Output beyond this limit is truncated; a marker is appended.
MAX_OUTPUT_BYTES: int = 65_536  # 64 KB

# Directories the resolved binary path must start with.
# Binaries outside these prefixes are rejected unconditionally.
SAFE_PATH_PREFIXES: tuple[str, ...] = (
    "/usr/sbin/",
    "/usr/bin/",
    "/sbin/",
    "/bin/",
)

# ─────────────────────────────────────────────────────────────────────────────
# Per-binary registry
#
# Schema per entry:
#   "max_timeout"  : hard ceiling on timeout in seconds — callers cannot exceed
#   "default_timeout": used when caller passes timeout=None
#   "allow_nonzero" : frozenset of additional acceptable return codes
#                     (e.g. useradd returns 9 when the user already exists)
# ─────────────────────────────────────────────────────────────────────────────

_REGISTRY: dict[str, dict] = {
    "nginx": {
        "max_timeout": 30,
        "default_timeout": 15,
        "allow_nonzero": frozenset(),
    },
    "systemctl": {
        "max_timeout": 60,
        "default_timeout": 30,
        "allow_nonzero": frozenset(),
    },
    "nft": {
        "max_timeout": 15,
        "default_timeout": 10,
        "allow_nonzero": frozenset(),
    },
    "certbot": {
        "max_timeout": 360,
        "default_timeout": 300,
        "allow_nonzero": frozenset(),
    },
    "openssl": {
        "max_timeout": 15,
        "default_timeout": 10,
        "allow_nonzero": frozenset(),
    },
    "useradd": {
        "max_timeout": 15,
        "default_timeout": 10,
        "allow_nonzero": frozenset({9}),   # 9 = user already exists
    },
    "userdel": {
        "max_timeout": 15,
        "default_timeout": 10,
        "allow_nonzero": frozenset({6}),   # 6 = user does not exist
    },
    "chown": {
        "max_timeout": 60,
        "default_timeout": 30,
        "allow_nonzero": frozenset(),
    },
    "cagefsctl": {
        "max_timeout": 120,
        "default_timeout": 60,
        "allow_nonzero": frozenset(),
    },
    "postmap": {
        "max_timeout": 15,
        "default_timeout": 10,
        "allow_nonzero": frozenset(),
    },
    "doveadm": {
        "max_timeout": 15,
        "default_timeout": 10,
        "allow_nonzero": frozenset(),
    },
    "opendkim-genkey": {
        "max_timeout": 30,
        "default_timeout": 20,
        "allow_nonzero": frozenset(),
    },
    "rndc": {
        "max_timeout": 15,
        "default_timeout": 10,
        "allow_nonzero": frozenset(),
    },
}

# Derived set for fast membership checks
_ALLOWED_BINARIES: FrozenSet[str] = frozenset(_REGISTRY.keys())


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CommandResult:
    """
    Structured result returned by run_command().

    success      True when returncode is in the allowed set for this binary.
    stdout       Captured standard output (truncated to MAX_OUTPUT_BYTES).
    stderr       Captured standard error  (truncated to MAX_OUTPUT_BYTES).
    returncode   Raw OS exit code.
    binary       Basename of the executed binary (safe to log/expose).
    elapsed      Wall-clock seconds the process ran.
    truncated    True if either output stream was truncated.
    """
    success: bool
    stdout: str
    stderr: str
    returncode: int
    binary: str
    elapsed: float
    truncated: bool = False


class CommandError(RuntimeError):
    """
    Raised by run_command() when the command fails.

    result  The full CommandResult (returncode, stderr, etc.).
            Internal callers may inspect it; it must NEVER be forwarded
            verbatim to the network response.
    """
    def __init__(self, message: str, result: CommandResult) -> None:
        super().__init__(message)
        self.result = result


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_binary(name: str) -> str:
    """
    Locate *name* on PATH and verify it sits under a trusted prefix.

    Returns the absolute path string on success.
    Raises CommandError (with a dummy result) on any failure.
    """
    resolved = shutil.which(name)
    if resolved is None:
        raise CommandError(
            f"Binary not found on PATH: {name!r}",
            CommandResult(False, "", "binary not found", -1, name, 0.0),
        )

    # Canonicalise: follow symlinks, collapse ..
    try:
        real = os.path.realpath(resolved)
    except OSError as exc:
        raise CommandError(
            f"Cannot resolve binary path for {name!r}",
            CommandResult(False, "", str(exc), -1, name, 0.0),
        ) from exc

    if not any(real.startswith(prefix) for prefix in SAFE_PATH_PREFIXES):
        raise CommandError(
            f"Binary {name!r} resolved to untrusted path",
            CommandResult(False, "", f"untrusted path: {real}", -1, name, 0.0),
        )

    return real


def _validate_args(cmd: list) -> None:
    """
    Ensure every element of cmd is a non-empty string with no null bytes.
    Raises TypeError or ValueError on the first offending argument.
    """
    for i, arg in enumerate(cmd):
        if not isinstance(arg, str):
            raise TypeError(
                f"Command argument at index {i} is {type(arg).__name__!r}, expected str"
            )
        if not arg:
            raise ValueError(f"Command argument at index {i} is an empty string")
        if "\x00" in arg:
            raise ValueError(f"Command argument at index {i} contains a null byte")


def _truncate(raw: bytes) -> tuple[str, bool]:
    """
    Decode up to MAX_OUTPUT_BYTES of *raw*; return (text, was_truncated).
    Decoding errors are replaced with the Unicode replacement character.
    """
    truncated = len(raw) > MAX_OUTPUT_BYTES
    data = raw[:MAX_OUTPUT_BYTES]
    text = data.decode("utf-8", errors="replace")
    if truncated:
        text += "\n[...output truncated...]"
    return text, truncated


async def _kill_process(proc: asyncio.subprocess.Process, binary: str) -> None:
    """
    Gracefully terminate *proc*: SIGTERM first, SIGKILL after 2 seconds.
    """
    try:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
    except ProcessLookupError:
        pass  # process already exited
    logger.warning("Killed process binary=%s pid=%s after timeout", binary, proc.pid)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def run_command(
    cmd: list[str],
    *,
    stdin_data: bytes | None = None,
    timeout: float | None = None,
) -> CommandResult:
    """
    Execute *cmd* safely and return a CommandResult.

    Parameters
    ----------
    cmd         Argument list.  cmd[0] must be a basename in _ALLOWED_BINARIES.
                Full paths (e.g. "/usr/sbin/nginx") are also accepted; the
                basename is extracted for registry and logging purposes.
    stdin_data  Optional bytes piped to the process's stdin.
    timeout     Maximum execution time in seconds.  If None, the binary's
                default_timeout is used.  Cannot exceed the binary's
                max_timeout.

    Returns
    -------
    CommandResult on success (returncode in allowed set).

    Raises
    ------
    CommandError   if returncode is not in the allowed set, or if pre-flight
                   checks fail (unknown binary, untrusted path, bad args).
    TimeoutError   if the process exceeds its timeout (process is killed
                   before this exception propagates).
    """
    if not cmd:
        raise ValueError("cmd must be a non-empty list")

    # ── Pre-flight: argument validation ──────────────────────────────────────
    _validate_args(cmd)

    binary_name = os.path.basename(cmd[0])

    # ── Allowlist check ───────────────────────────────────────────────────────
    if binary_name not in _ALLOWED_BINARIES:
        raise CommandError(
            f"Binary {binary_name!r} is not in the execution allowlist",
            CommandResult(False, "", "not in allowlist", -1, binary_name, 0.0),
        )

    spec = _REGISTRY[binary_name]

    # ── Timeout resolution ────────────────────────────────────────────────────
    if timeout is None:
        effective_timeout = float(spec["default_timeout"])
    else:
        effective_timeout = min(float(timeout), float(spec["max_timeout"]))

    # ── Binary path resolution + trust check ─────────────────────────────────
    resolved_path = _resolve_binary(binary_name)

    # Replace cmd[0] with the resolved, trusted absolute path
    safe_cmd = [resolved_path] + cmd[1:]

    # ── Safe log entry (binary + arg count only — no values) ─────────────────
    logger.info(
        "EXEC binary=%s argc=%d timeout=%.0fs",
        binary_name,
        len(safe_cmd) - 1,
        effective_timeout,
    )

    # ── Spawn process ─────────────────────────────────────────────────────────
    stdin_pipe = asyncio.subprocess.PIPE if stdin_data is not None else asyncio.subprocess.DEVNULL

    t_start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *safe_cmd,
        stdin=stdin_pipe,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # ── Communicate with timeout ──────────────────────────────────────────────
    try:
        raw_out, raw_err = await asyncio.wait_for(
            proc.communicate(input=stdin_data),
            timeout=effective_timeout,
        )
    except asyncio.TimeoutError:
        await _kill_process(proc, binary_name)
        elapsed = time.monotonic() - t_start
        logger.error(
            "TIMEOUT binary=%s after %.1fs (limit=%.0fs)",
            binary_name, elapsed, effective_timeout,
        )
        raise TimeoutError(
            f"Command {binary_name!r} timed out after {effective_timeout:.0f}s"
        )

    elapsed = time.monotonic() - t_start

    # ── Decode and cap output ─────────────────────────────────────────────────
    stdout_text, out_truncated = _truncate(raw_out)
    stderr_text, err_truncated = _truncate(raw_err)
    truncated = out_truncated or err_truncated

    # ── Determine success ─────────────────────────────────────────────────────
    allowed_codes: FrozenSet[int] = frozenset({0}) | spec["allow_nonzero"]
    success = proc.returncode in allowed_codes

    result = CommandResult(
        success=success,
        stdout=stdout_text,
        stderr=stderr_text,
        returncode=proc.returncode,
        binary=binary_name,
        elapsed=elapsed,
        truncated=truncated,
    )

    # ── Log outcome ───────────────────────────────────────────────────────────
    if success:
        logger.info(
            "OK binary=%s rc=%d elapsed=%.2fs%s",
            binary_name,
            proc.returncode,
            elapsed,
            " [output truncated]" if truncated else "",
        )
    else:
        # Log stderr internally — never propagate raw stderr to the caller's
        # network response (the handler decides what to expose).
        logger.error(
            "FAILED binary=%s rc=%d elapsed=%.2fs stderr=%s",
            binary_name,
            proc.returncode,
            elapsed,
            # Limit stderr in the log line itself to 500 chars
            stderr_text[:500].replace("\n", " "),
        )
        raise CommandError(
            f"Command {binary_name!r} exited with code {proc.returncode}",
            result,
        )

    return result
