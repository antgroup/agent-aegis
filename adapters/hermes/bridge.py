"""
AgentAegis JSON-RPC subprocess bridge.

Manages a Node.js child process running the AgentAegis RPC server and
provides a synchronous ``call(method, params)`` interface for the Hermes
plugin hooks and tool wrappers.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .paths import find_rpc_server

logger = logging.getLogger("agent-aegis.bridge")

# Maximum restarts after unexpected process death
_MAX_RESTARTS = 3
# Timeout for a single RPC call (seconds)
_CALL_TIMEOUT = 5.0


def _find_node() -> str:
    """Find the node binary, checking common nvm/hermes locations."""
    for candidate in [
        "node",
        os.path.expanduser("~/.hermes/node/bin/node"),
        os.path.expanduser("~/.local/bin/node"),
        "/opt/taobao/nvm/current/bin/node",
    ]:
        try:
            result = subprocess.run(
                [candidate, "--version"],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                return candidate
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    raise FileNotFoundError("Cannot find node binary")


class AegisEngine:
    """Manages a long-lived Node.js subprocess for AgentAegis RPC."""

    def __init__(self) -> None:
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._id_counter = 0
        self._restarts = 0
        self._node_bin: Optional[str] = None
        self._rpc_server: Optional[str] = None
        self._stderr_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the Node.js RPC server subprocess."""
        if self._node_bin is None:
            self._node_bin = _find_node()
        if self._rpc_server is None:
            self._rpc_server = find_rpc_server()

        logger.info(
            "Starting AgentAegis RPC: %s %s", self._node_bin, self._rpc_server,
        )
        self._proc = subprocess.Popen(
            [self._node_bin, self._rpc_server],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # line-buffered
        )

        # Background thread to drain stderr and forward to Python logging
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, daemon=True,
        )
        self._stderr_thread.start()

    def stop(self) -> None:
        """Terminate the subprocess."""
        proc = self._proc
        if proc and proc.poll() is None:
            try:
                proc.stdin.close()
            except Exception:
                pass
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        self._proc = None

    def _restart_if_needed(self) -> bool:
        """Restart the process if it died and we haven't exceeded retries."""
        if self._proc is not None and self._proc.poll() is None:
            return True  # still alive
        if self._restarts >= _MAX_RESTARTS:
            logger.error("AgentAegis RPC process died; max restarts reached")
            return False
        self._restarts += 1
        logger.warning(
            "AgentAegis RPC process died; restarting (%d/%d)",
            self._restarts, _MAX_RESTARTS,
        )
        self.start()
        return self._proc is not None and self._proc.poll() is None

    def _drain_stderr(self) -> None:
        """Read stderr from the subprocess and forward to Python logging."""
        proc = self._proc
        if not proc or not proc.stderr:
            return
        try:
            for line in proc.stderr:
                stripped = line.rstrip("\n")
                if stripped:
                    logger.debug("[node] %s", stripped)
        except (ValueError, OSError):
            pass  # pipe closed

    # ------------------------------------------------------------------
    # RPC call
    # ------------------------------------------------------------------

    def call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send a JSON-RPC request and return the result dict.

        Raises RuntimeError on communication failure or error responses.
        """
        with self._lock:
            if not self._restart_if_needed():
                raise RuntimeError("AgentAegis RPC process is not running")

            self._id_counter += 1
            request = {
                "id": self._id_counter,
                "method": method,
                "params": params or {},
            }

            proc = self._proc
            assert proc is not None
            assert proc.stdin is not None
            assert proc.stdout is not None

            try:
                request_line = json.dumps(request, ensure_ascii=False) + "\n"
                proc.stdin.write(request_line)
                proc.stdin.flush()

                # Read one response line
                response_line = proc.stdout.readline()
                if not response_line:
                    raise RuntimeError("AgentAegis RPC: empty response (process may have died)")

                response = json.loads(response_line)
            except (BrokenPipeError, OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"AgentAegis RPC communication error: {exc}") from exc

            if "error" in response and response["error"]:
                err = response["error"]
                raise RuntimeError(
                    f"AgentAegis RPC error ({err.get('code', '?')}): {err.get('message', '?')}"
                )

            return response.get("result", {})

    def call_safe(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Like call() but returns an empty dict on failure instead of raising."""
        try:
            return self.call(method, params)
        except Exception as exc:
            logger.warning("AgentAegis RPC call %s failed: %s", method, exc)
            return {}

    @property
    def alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None
