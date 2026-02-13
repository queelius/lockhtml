"""Viewer plugin system for pagevault.

Provides the API for defining, discovering, and resolving
file viewers used by the wrap module.
"""

from .base import ViewerPlugin
from .registry import discover_viewers, filter_by_config, resolve_viewer

__all__ = [
    "ViewerPlugin",
    "discover_viewers",
    "resolve_viewer",
    "filter_by_config",
]
