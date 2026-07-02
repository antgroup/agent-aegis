"""
AgentAegis Web Server manager for Hermes.

This module provides an optional Web UI server that can be started alongside
the RPC engine. It manages the Node.js web API process and ensures proper
lifecycle management.
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

from .paths import find_web_api, get_state_directory, get_config_directory, get_plugin_directory

logger = logging.getLogger("agent-aegis.web")

# Default web server port
_DEFAULT_PORT = 3800
# Maximum restarts after unexpected process death
_MAX_RESTARTS = 3


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


class AegisWebServer:
    """Manages the Node.js web API server subprocess."""

    def __init__(self, port: int = _DEFAULT_PORT) -> None:
        self._port = port
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._restarts = 0
        self._node_bin: Optional[str] = None
        self._web_api: Optional[str] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._started = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the Node.js web API server subprocess."""
        if self._started:
            logger.debug("Web server already started")
            return

        if self._node_bin is None:
            self._node_bin = _find_node()
        if self._web_api is None:
            self._web_api = find_web_api()

        # Use paths module for directory locations
        config_dir = get_config_directory()
        state_dir = get_state_directory()

        # Ensure directories exist
        Path(config_dir).mkdir(parents=True, exist_ok=True)
        Path(state_dir).mkdir(parents=True, exist_ok=True)

        env = os.environ.copy()
        env["AEGIS_PORT"] = str(self._port)
        env["AEGIS_CONFIG_DIR"] = config_dir
        env["AEGIS_STATE_DIR"] = state_dir
        # Don't serve frontend from API server - it's handled separately
        env["AEGIS_STATIC_DIR"] = ""

        logger.info(
            "Starting AgentAegis Web API: %s %s (port %d)",
            self._node_bin, self._web_api, self._port,
        )

        try:
            self._proc = subprocess.Popen(
                [self._node_bin, self._web_api],
                stdin=subprocess.DEVNULL,  # Web server doesn't need stdin
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=env,
            )
            self._started = True

            # Check whether the process survived startup BEFORE any drain thread
            # touches stderr — otherwise the drain thread and communicate() would
            # race on the same pipe and swallow the real error. On failure,
            # communicate() returns BOTH streams for a useful diagnostic.
            time.sleep(0.5)
            if self._proc.poll() is not None:
                stdout, stderr = self._proc.communicate(timeout=1)
                logger.error(
                    "Web server failed to start: stdout=%s stderr=%s", stdout, stderr
                )
                self._started = False
                raise RuntimeError("Web server process exited immediately")

            # Process is alive — now it is safe to drain stderr in the background.
            self._stderr_thread = threading.Thread(
                target=self._drain_stderr, daemon=True,
            )
            self._stderr_thread.start()

            logger.info(
                "AgentAegis Web API started at http://localhost:%d",
                self._port,
            )

        except Exception as exc:
            logger.error("Failed to start web server: %s", exc)
            self._started = False
            raise

    def stop(self) -> None:
        """Terminate the subprocess."""
        self._started = False
        proc = self._proc
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        self._proc = None
        logger.info("AgentAegis Web API stopped")

    def _drain_stderr(self) -> None:
        """Read stderr from the subprocess and forward to Python logging."""
        proc = self._proc
        if not proc or not proc.stderr:
            return
        try:
            for line in proc.stderr:
                stripped = line.rstrip("\n")
                if stripped:
                    # Web server logs to stderr, forward to Python logging
                    if "error" in stripped.lower():
                        logger.error("[web] %s", stripped)
                    else:
                        logger.info("[web] %s", stripped)
        except (ValueError, OSError):
            pass  # pipe closed

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def is_alive(self) -> bool:
        """Check if the web server process is running."""
        return self._started and self._proc is not None and self._proc.poll() is None

    def health_check(self) -> Dict[str, Any]:
        """Perform a health check by querying the API."""
        if not self.is_alive():
            return {"healthy": False, "error": "Process not running"}

        try:
            import urllib.request
            url = f"http://localhost:{self._port}/api/v1/health"
            with urllib.request.urlopen(url, timeout=2) as response:
                data = json.loads(response.read().decode())
                return {
                    "healthy": data.get("status") == "ok",
                    "data": data,
                }
        except Exception as exc:
            return {"healthy": False, "error": str(exc)}

    @property
    def url(self) -> str:
        """Return the URL of the web server."""
        return f"http://localhost:{self._port}"


# Singleton instance for the web server
_web_server_instance: Optional[AegisWebServer] = None


def start_web_server(port: int = _DEFAULT_PORT) -> AegisWebServer:
    """Start the web server singleton."""
    global _web_server_instance
    if _web_server_instance is None:
        _web_server_instance = AegisWebServer(port)
        _web_server_instance.start()
    return _web_server_instance


def stop_web_server() -> None:
    """Stop the web server singleton."""
    global _web_server_instance
    if _web_server_instance is not None:
        _web_server_instance.stop()
        _web_server_instance = None


def get_web_server() -> Optional[AegisWebServer]:
    """Get the web server singleton instance."""
    return _web_server_instance
