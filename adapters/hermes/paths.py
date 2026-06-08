"""
Path resolution for AgentAegis Hermes adapter.

This module handles finding AgentAegis files in multiple locations:
1. Plugin directory (for installed/standalone mode)
2. Source repository (for development mode or direct GitHub install)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


# Marker file that indicates the plugin directory
AGENTAEGIS_ROOT_MARKER = ".agentaegis-root"


def get_plugin_root() -> Path:
    """Get the root directory of the AgentAegis repository/plugin.
    
    Works whether installed via install.sh or direct hermes plugins install.
    """
    # This file is at: ~/.hermes/plugins/agent-aegis/paths.py (installed)
    # or AgentAegis/adapters/hermes/paths.py (source)
    this_file = Path(__file__).resolve()
    
    # 1. Check for the marker file in the directory of this file
    marker = _read_plugin_root_marker(this_file.parent)
    if marker:
        return marker
        
    # 2. Check if we are in adapters/hermes/
    if this_file.parent.name == "hermes" and this_file.parent.parent.name == "adapters":
        return this_file.parent.parent.parent
    
    # 3. Check if there is a marker in the parent directory (standard install layout)
    marker = _read_plugin_root_marker(this_file.parent.parent)
    if marker:
        return marker

    # Fallback to directory containing this file
    return this_file.parent


def _read_plugin_root_marker(plugin_dir: Path) -> Optional[Path]:
    """Read the source root path from the marker file in plugin directory."""
    marker_file = plugin_dir / AGENTAEGIS_ROOT_MARKER
    if marker_file.exists():
        try:
            root_path = Path(marker_file.read_text().strip()).resolve()
            if root_path.exists():
                return root_path
        except Exception:
            pass
    return None


def get_plugin_directory() -> Path:
    """Get the directory where the plugin is registered in Hermes."""
    # Hermes plugins are directories in ~/.hermes/plugins/
    # We find it by walking up from this file until we find plugin.yaml
    curr = Path(__file__).resolve().parent
    for _ in range(4):
        if (curr / "plugin.yaml").exists():
            return curr
        curr = curr.parent
    return Path(__file__).resolve().parent


def get_source_root() -> Path:
    """Get the AgentAegis source repository root."""
    return get_plugin_root()


def find_rpc_server() -> str:
    """Find the rpc-server.js file."""
    # Check plugin directory first (installed files)
    plugin_dir = get_plugin_directory()
    candidate = plugin_dir / "rpc-server.js"
    if candidate.exists():
        return str(candidate)

    # Check root directory (source mode)
    root = get_plugin_root()
    candidate = root / "rpc-server.js"
    if candidate.exists():
        return str(candidate)

    raise FileNotFoundError(
        f"Cannot find rpc-server.js. "
        f"Please run 'npm run build' in the AgentAegis directory."
    )


def find_web_api() -> str:
    """Find the web API entry point."""
    # Check plugin directory first (installed files)
    plugin_dir = get_plugin_directory()
    candidate = plugin_dir / "web" / "index.js"
    if candidate.exists():
        return str(candidate)

    # Check source layout
    root = get_plugin_root()
    
    # Try generic web/api (standard layout)
    candidate = root / "web" / "api" / "dist" / "index.js"
    if candidate.exists():
        return str(candidate)
        
    # Try api-hermes (specialized legacy for Hermes)
    candidate = root / "web" / "api-hermes" / "dist" / "index.js"
    if candidate.exists():
        return str(candidate)

    raise FileNotFoundError(
        f"Cannot find Web API. "
        f"Please run 'npm run build' in the web directory."
    )


def find_config_template() -> Optional[str]:
    """Find the default config.yaml template."""
    root = get_plugin_root()
    
    # Check root
    candidate = root / "config.yaml"
    if candidate.exists():
        return str(candidate)

    # Check adapters/hermes
    candidate = root / "adapters" / "hermes" / "config.yaml"
    if candidate.exists():
        return str(candidate)

    return None


def get_state_directory() -> str:
    """Get the state directory for AgentAegis in Hermes."""
    return os.path.expanduser("~/.hermes/agent-aegis-state")


def get_config_directory() -> str:
    """Get the config directory (same as plugin directory for Hermes)."""
    return str(get_plugin_directory())


def resolve_hermes_paths() -> dict:
    """Resolve all Hermes-specific paths for AgentAegis runtime."""
    hermes_home = Path(os.path.expanduser("~/.hermes"))
    plugin_dir = get_plugin_directory()
    plugin_root = get_plugin_root()

    state_dir = str(hermes_home / "agent-aegis-state")
    config_dir = str(plugin_dir)

    skill_roots = []
    skills_dir = hermes_home / "skills"
    if skills_dir.is_dir():
        skill_roots.append(str(skills_dir))

    # Protected roots for self-protection
    protected_roots = [
        str(plugin_dir),
        str(plugin_root),
        str(hermes_home),
        str(hermes_home / ".env"),
        str(hermes_home / "config.yaml"),
        str(hermes_home / "plugins"),
        str(hermes_home / "skills"),
        str(state_dir),
    ]

    return {
        "state_dir": state_dir,
        "config_dir": config_dir,
        "plugin_root": str(plugin_root),
        "skill_roots": skill_roots,
        "protected_roots": list(set(protected_roots)),
    }
