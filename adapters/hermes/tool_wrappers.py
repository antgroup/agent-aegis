"""
Tool handler wrappers for AgentAegis on Hermes.

Intercepts high-risk tool handlers (terminal, write_file, etc.) by
replacing them in the Hermes tool registry with safety-checked wrappers
that consult the AgentAegis RPC engine before executing.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, Optional

from .bridge import AegisEngine

logger = logging.getLogger("agent-aegis.wrappers")

# Tools to wrap and the RPC method to call for each.
# All use check_before_tool; the tool name and args are passed through.
TOOLS_TO_WRAP = [
    "terminal",
    "write_file",
    "patch",
    "read_file",
    "execute_code",
]


def _make_safe_handler(
    engine: AegisEngine,
    original_handler: Callable,
    tool_name: str,
    is_async: bool,
    session_key_fn: Callable[[], str],
    run_id_fn: Callable[[], str],
) -> Callable:
    """Create a wrapped handler that checks AgentAegis before executing."""

    def sync_handler(args: dict, **kwargs: Any) -> str:
        # Consult AgentAegis
        try:
            result = engine.call("check_before_tool", {
                "tool": tool_name,
                "args": args,
                "sessionKey": session_key_fn(),
                "runId": run_id_fn(),
            })
        except Exception as exc:
            # Fail-open: if RPC is down, allow the tool call
            logger.warning("AgentAegis check failed for %s, allowing: %s", tool_name, exc)
            return original_handler(args, **kwargs)

        if result.get("block"):
            blocked_msg = {
                "error": f"[AgentAegis] Blocked: {result.get('reason', 'security violation')}",
                "defense": result.get("defense", "unknown"),
                "severity": result.get("severity", "unknown"),
                "mode": result.get("mode", "enforce"),
            }
            logger.warning(
                "AgentAegis blocked %s: defense=%s reason=%s",
                tool_name, result.get("defense"), result.get("reason"),
            )
            return json.dumps(blocked_msg, ensure_ascii=False)

        if result.get("mode") == "observe" and result.get("defense"):
            logger.info(
                "AgentAegis observed %s: defense=%s reason=%s",
                tool_name, result.get("defense"), result.get("reason"),
            )

        return original_handler(args, **kwargs)

    async def async_handler(args: dict, **kwargs: Any) -> str:
        # Same logic but for async handlers — the check itself is sync
        # (short RPC call), only the original handler is awaited
        try:
            result = engine.call("check_before_tool", {
                "tool": tool_name,
                "args": args,
                "sessionKey": session_key_fn(),
                "runId": run_id_fn(),
            })
        except Exception as exc:
            logger.warning("AgentAegis check failed for %s, allowing: %s", tool_name, exc)
            return await original_handler(args, **kwargs)

        if result.get("block"):
            blocked_msg = {
                "error": f"[AgentAegis] Blocked: {result.get('reason', 'security violation')}",
                "defense": result.get("defense", "unknown"),
                "severity": result.get("severity", "unknown"),
                "mode": result.get("mode", "enforce"),
            }
            logger.warning(
                "AgentAegis blocked %s: defense=%s reason=%s",
                tool_name, result.get("defense"), result.get("reason"),
            )
            return json.dumps(blocked_msg, ensure_ascii=False)

        return await original_handler(args, **kwargs)

    return async_handler if is_async else sync_handler


def wrap_dangerous_tools(
    engine: AegisEngine,
    session_key_fn: Callable[[], str],
    run_id_fn: Callable[[], str],
) -> int:
    """Replace handlers for high-risk tools with AgentAegis-checked wrappers.

    This must be called after Hermes has loaded all built-in tools
    (i.e. during plugin register(), which runs after tool discovery).

    Returns:
        Number of tools successfully wrapped
    """
    try:
        from tools.registry import registry
    except ImportError as exc:
        logger.error("Cannot import tools.registry — tool wrapping skipped: %s", exc)
        return 0

    wrapped_count = 0
    for tool_name in TOOLS_TO_WRAP:
        entry = registry._tools.get(tool_name)
        if entry is None:
            logger.debug("Tool %s not found in registry, skipping wrap", tool_name)
            continue

        # Check if already wrapped (avoid double-wrapping)
        if hasattr(entry.handler, '_agent_aegis_wrapped'):
            logger.debug("Tool %s already wrapped, skipping", tool_name)
            wrapped_count += 1
            continue

        # Save original handler
        original_handler = entry.handler
        original_is_async = entry.is_async

        # Create wrapped handler
        safe_handler = _make_safe_handler(
            engine=engine,
            original_handler=original_handler,
            tool_name=tool_name,
            is_async=original_is_async,
            session_key_fn=session_key_fn,
            run_id_fn=run_id_fn,
        )

        # Mark as wrapped to prevent double-wrapping
        safe_handler._agent_aegis_wrapped = True

        # Replace in registry via deregister + register (clean approach)
        schema = entry.schema
        toolset = entry.toolset
        check_fn = entry.check_fn
        requires_env = entry.requires_env
        description = entry.description
        emoji = entry.emoji
        max_result_size = getattr(entry, 'max_result_size_chars', None)

        try:
            registry.deregister(tool_name)
            registry.register(
                name=tool_name,
                toolset=toolset,
                schema=schema,
                handler=safe_handler,
                check_fn=check_fn,
                requires_env=requires_env,
                is_async=original_is_async,
                description=description,
                emoji=emoji,
                max_result_size_chars=max_result_size,
            )
            logger.info("Wrapped tool %s with AgentAegis safety check", tool_name)
            wrapped_count += 1
        except Exception as exc:
            logger.error("Failed to wrap tool %s: %s", tool_name, exc)

    return wrapped_count
