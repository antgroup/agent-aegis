"""
AgentAegis plugin for Hermes Agent.

This plugin bridges the AgentAegis TypeScript security engine into Hermes
via a Node.js subprocess running a JSON-RPC server.  It registers lifecycle
hooks and wraps high-risk tool handlers to enforce the same defense-in-depth
protections available in the OpenClaw version.

Installation:
    cp -r /path/to/AgentAegis/adapters/hermes ~/.hermes/plugins/agent-aegis
    cd /path/to/AgentAegis && npm run build

Or use the install script:
    bash adapters/hermes/install.sh

Note on Hermes Integration:
    - Hermes has no built-in plugin install command; plugins are auto-loaded
      from ~/.hermes/plugins/ directory
    - Hermes' pre_tool_call hook cannot block tool execution (observer only)
    - AgentAegis uses tool wrapper replacement for actual blocking
    - Consider setting 'approvals.mode: off' in Hermes config to avoid double prompts
"""

from __future__ import annotations

import atexit
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from .paths import (
    resolve_hermes_paths,
    get_config_directory,
    find_config_template,
)

logger = logging.getLogger("agent-aegis")

# ---------------------------------------------------------------------------
# Session state tracking (module-level so hooks and wrappers share it)
# ---------------------------------------------------------------------------

_current_session_id: str = "default"
_current_run_id: str = "unknown"


def _get_session_key() -> str:
    return _current_session_id


def _get_run_id() -> str:
    return _current_run_id


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    """Load AgentAegis config from plugin config directory
    or fall back to defaults (all defenses enabled, enforce mode).
    """
    try:
        import yaml
    except ImportError:
        logger.debug("PyYAML not available, using default config")
        return {}

    config_path = Path(get_config_directory()) / "config.yaml"
    if not config_path.is_file():
        logger.debug("No config.yaml found at %s, using defaults", config_path)
        return {}

    try:
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        logger.warning("Failed to load config.yaml: %s", exc)
        return {}


def _check_hermes_config() -> dict:
    """Check Hermes configuration for potential conflicts."""
    issues = []
    suggestions = []

    # Check Hermes config
    hermes_config_path = Path(os.path.expanduser("~/.hermes/config.yaml"))
    if hermes_config_path.is_file():
        try:
            import yaml
            with open(hermes_config_path) as f:
                hermes_config = yaml.safe_load(f) or {}

            approvals = hermes_config.get("approvals", {})
            approval_mode = approvals.get("mode", "manual")

            if approval_mode == "manual":
                issues.append("Hermes approvals.mode is 'manual' - you may see double prompts")
                suggestions.append("Set 'approvals.mode: off' in ~/.hermes/config.yaml")
            elif approval_mode == "smart":
                suggestions.append("Consider 'approvals.mode: off' to let AgentAegis handle all blocking")

        except Exception as exc:
            logger.debug("Could not check Hermes config: %s", exc)

    return {"issues": issues, "suggestions": suggestions}


def _resolve_paths() -> dict:
    """Resolve Hermes-specific paths for the AgentAegis runtime."""
    return resolve_hermes_paths()


# ---------------------------------------------------------------------------
# Hook handlers
# ---------------------------------------------------------------------------

def _make_session_start_handler(engine):
    def handler(**kwargs):
        global _current_session_id
        session_id = kwargs.get("session_id", "default")
        _current_session_id = session_id
        logger.debug("Session started: %s", session_id)
    return handler


def _make_session_end_handler(engine):
    def handler(**kwargs):
        session_id = kwargs.get("session_id", _current_session_id)
        engine.call_safe("update_state", {
            "method": "clear_session",
            "sessionKey": session_id,
        })
        logger.debug("Session ended: %s", session_id)
    return handler


def _make_pre_llm_call_handler(engine):
    def handler(**kwargs):
        global _current_run_id
        session_id = kwargs.get("session_id", _current_session_id)
        _current_run_id = f"{session_id}:{id(kwargs)}"

        user_message = kwargs.get("user_message", "")
        context_parts: list = []

        # 1. Check user input for jailbreak / exfiltration intent
        if user_message:
            result = engine.call_safe("check_user_input", {
                "content": str(user_message),
                "sessionKey": session_id,
            })
            if result.get("riskFlags"):
                logger.info(
                    "User risk flags detected: %s", result["riskFlags"],
                )

            # Track user input for state
            engine.call_safe("update_state", {
                "method": "note_user_input",
                "sessionKey": session_id,
                "data": {"content": str(user_message)[:500]},
            })

        # 2. Get prompt guard context to inject
        guard_result = engine.call_safe("get_prompt_guard", {
            "sessionKey": session_id,
        })
        if guard_result.get("context"):
            # Enhance context to make it more prominent in user message
            enhanced_context = f"""[SECURITY POLICY - MUST FOLLOW]
{guard_result['context']}
[END SECURITY POLICY]

"""
            context_parts.append(enhanced_context)

        if context_parts:
            return {"context": "\n\n".join(context_parts)}
        return None

    return handler


def _make_post_tool_call_handler(engine):
    def handler(**kwargs):
        tool_name = kwargs.get("tool_name", "")
        args = kwargs.get("args", {})
        result = kwargs.get("result", "")

        if not tool_name:
            return

        # Scan tool results for injection / exfiltration patterns
        engine.call_safe("check_tool_result", {
            "tool": tool_name,
            "args": args if isinstance(args, dict) else {},
            "result": str(result)[:65536],
            "sessionKey": _current_session_id,
            "runId": _current_run_id,
        })

    return handler


def _make_pre_tool_call_handler(engine):
    """Observation-only handler — logs but cannot block (Hermes limitation)."""
    def handler(**kwargs):
        tool_name = kwargs.get("tool_name", "")
        args = kwargs.get("args", {})
        # This is for observability; actual blocking is done via tool wrapping
        logger.debug("pre_tool_call observed: %s", tool_name)
    return handler


# ---------------------------------------------------------------------------
# Plugin entry point
# ---------------------------------------------------------------------------

def register(ctx):
    """Hermes plugin entry point — register hooks and wrap tools."""
    from .bridge import AegisEngine
    from .tool_wrappers import wrap_dangerous_tools
    from .paths import find_rpc_server

    logger.info("AgentAegis: Initializing security plugin...")

    # 0. Pre-initialization check (especially for GitHub installs)
    try:
        find_rpc_server()
    except FileNotFoundError:
        root = Path(__file__).resolve().parent.parent.parent
        logger.error("=" * 60)
        logger.error("AgentAegis is not built! Defense will not be active.")
        logger.error(f"Please run the following commands in: {root}")
        logger.error("    npm install && npm run build")
        logger.error("=" * 60)
        return

    # Check Hermes configuration for potential conflicts
    hermes_check = _check_hermes_config()
    if hermes_check["issues"]:
        for issue in hermes_check["issues"]:
            logger.warning(f"AgentAegis: {issue}")
    if hermes_check["suggestions"]:
        for suggestion in hermes_check["suggestions"]:
            logger.info(f"AgentAegis: Suggestion: {suggestion}")

    engine = AegisEngine()

    try:
        engine.start()
    except FileNotFoundError as exc:
        logger.error("AgentAegis startup failed: %s", exc)
        logger.error("Ensure Node.js is installed and run 'npm run build' in the AgentAegis directory.")
        return
    except Exception as exc:
        logger.error("AgentAegis startup failed with unexpected error: %s", exc)
        return

    # Initialize the RPC runtime
    config = _load_config()
    paths = _resolve_paths()

    # Ensure state directory exists
    Path(paths["state_dir"]).mkdir(parents=True, exist_ok=True)

    try:
        engine.call("init", {
            "config": config,
            "stateDir": paths["state_dir"],
            "pluginRootDir": paths["plugin_root"],
            "skillRoots": paths["skill_roots"],
            "protectedRoots": paths["protected_roots"],
        })
    except Exception as exc:
        logger.error("AgentAegis init failed: %s", exc)
        engine.stop()
        return

    # Register hooks
    ctx.register_hook("on_session_start", _make_session_start_handler(engine))
    ctx.register_hook("on_session_end", _make_session_end_handler(engine))
    ctx.register_hook("pre_llm_call", _make_pre_llm_call_handler(engine))
    ctx.register_hook("post_tool_call", _make_post_tool_call_handler(engine))
    # Note: pre_tool_call is observer-only in Hermes, actual blocking is done via tool wrapping
    ctx.register_hook("pre_tool_call", _make_pre_tool_call_handler(engine))

    # Wrap high-risk tool handlers for blocking capability
    # This is necessary because Hermes' pre_tool_call hook cannot block
    wrapped_count = wrap_dangerous_tools(engine, _get_session_key, _get_run_id)

    # Cleanup on exit
    atexit.register(engine.stop)

    # Optionally start Web UI server
    web_port = config.get("webPort", 0)
    if web_port and isinstance(web_port, int) and web_port > 0:
        try:
            from .web_server import start_web_server, stop_web_server
            web = start_web_server(port=web_port)
            atexit.register(stop_web_server)
            logger.info(f"AgentAegis: Web UI available at {web.url}")
        except Exception as exc:
            logger.warning(f"AgentAegis: Failed to start Web UI: {exc}")

    logger.info(f"AgentAegis: Security plugin active ({wrapped_count} tools wrapped)")
