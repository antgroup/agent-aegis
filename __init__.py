"""
ClawAegis plugin for Hermes Agent (Proxy Entry).

This file allows Hermes to recognize the repository root as a valid plugin.
It delegates all logic to the core adapter in adapters/hermes/.
"""

from .adapters.hermes import register
