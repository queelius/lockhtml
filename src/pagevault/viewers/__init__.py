"""Viewer plugin system for pagevault.

Provides the API for defining, discovering, and resolving
file viewers used by the wrap module.

Viewer discovery scans directories for .py files that define
ViewerPlugin subclasses. Built-in viewers ship in ``builtins/``.
Users can add custom viewers via the ``viewers_dir`` config option.
"""

from .base import ViewerPlugin
from .registry import discover_viewers, filter_by_config, resolve_viewer, scan_directory

__all__ = [
    "ViewerPlugin",
    "discover_viewers",
    "resolve_viewer",
    "filter_by_config",
    "scan_directory",
]
