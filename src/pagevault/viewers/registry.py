"""Viewer plugin discovery and resolution.

Discovery scans directories for .py files containing ViewerPlugin subclasses.
Built-in viewers ship in ``viewers/builtins/``. Users can add custom viewers
by placing .py files in a directory specified by ``viewers_dir`` in config.
"""

from __future__ import annotations

import importlib.util
import inspect
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from .base import ViewerPlugin

if TYPE_CHECKING:
    from ..config import PagevaultConfig

logger = logging.getLogger(__name__)

# Path to the built-in viewers directory (ships with pagevault)
_BUILTINS_DIR = Path(__file__).parent / "builtins"


def discover_viewers(config: PagevaultConfig | None = None) -> list[ViewerPlugin]:
    """Discover all available viewer plugins.

    Loads built-in viewers from ``viewers/builtins/``, then scans the
    user's ``viewers_dir`` (if configured). User viewers override builtins
    on name collision (even at equal priority). Deduplicates by name,
    then filters by config's ``viewers:`` section.

    Args:
        config: Optional configuration with viewers overrides.

    Returns:
        List of active ViewerPlugin instances.
    """
    # Built-ins first
    viewers = scan_directory(_BUILTINS_DIR)

    # User directory overrides builtins
    if config is not None and getattr(config, "viewers_dir", None) is not None:
        user_dir = Path(config.viewers_dir)
        if user_dir.is_dir():
            user_viewers = scan_directory(user_dir)
            viewers.extend(user_viewers)
        else:
            logger.warning("viewers_dir does not exist: %s", user_dir)

    viewers = _deduplicate_by_name(viewers)

    if config is not None:
        viewers = filter_by_config(viewers, config)

    return viewers


def resolve_viewer(mime: str, viewers: list[ViewerPlugin]) -> ViewerPlugin | None:
    """Find the best viewer for a MIME type.

    Resolution order:
        1. Exact MIME match — highest priority wins
        2. Wildcard prefix match (e.g. "image/*") — highest priority wins
        3. None (caller should use download fallback)

    Args:
        mime: MIME type string (e.g. "image/png").
        viewers: List of available viewers.

    Returns:
        Best matching ViewerPlugin, or None.
    """
    exact = [v for v in viewers if mime in v.mime_types]
    if exact:
        return max(exact, key=lambda v: v.priority)

    prefix = mime.split("/")[0] + "/*"
    wildcard = [v for v in viewers if prefix in v.mime_types]
    if wildcard:
        return max(wildcard, key=lambda v: v.priority)

    return None


def filter_by_config(
    viewers: list[ViewerPlugin], config: PagevaultConfig
) -> list[ViewerPlugin]:
    """Filter viewers by the ``viewers:`` config section.

    If ``config.viewers`` is None (absent from YAML), all viewers pass.
    An explicit empty dict ``viewers: {}`` also passes all viewers through,
    but is semantically distinct (the user declared the section).

    Args:
        viewers: List of discovered viewers.
        config: Configuration with optional viewers overrides.

    Returns:
        Filtered list of viewers.
    """
    viewer_config = getattr(config, "viewers", None)
    if viewer_config is None:
        return viewers

    return [v for v in viewers if viewer_config.get(v.name, True)]


def scan_directory(directory: Path) -> list[ViewerPlugin]:
    """Scan a directory for .py files containing ViewerPlugin subclasses.

    Each .py file is imported as a module and inspected for concrete
    ViewerPlugin subclasses. Files starting with ``_`` are skipped.

    Args:
        directory: Path to directory to scan.

    Returns:
        List of ViewerPlugin instances found.
    """
    viewers: list[ViewerPlugin] = []
    if not directory.is_dir():
        return viewers

    for py_file in sorted(directory.glob("*.py")):
        if py_file.name.startswith("_"):
            continue

        try:
            module = _import_file(py_file)
        except Exception:
            logger.warning("Failed to import viewer file: %s", py_file)
            continue

        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, ViewerPlugin)
                and obj is not ViewerPlugin
                and not getattr(obj, "__abstractmethods__", None)
            ):
                try:
                    viewers.append(obj())
                except Exception:
                    logger.warning(
                        "Failed to instantiate viewer %s from %s",
                        obj.__name__,
                        py_file,
                    )

    return viewers


def _deduplicate_by_name(viewers: list[ViewerPlugin]) -> list[ViewerPlugin]:
    """Deduplicate viewers by name, keeping the best for each.

    When two viewers share a name, the higher priority wins. On equal
    priority, the later one wins (so user viewers override builtins).

    Args:
        viewers: List of discovered viewers (may contain duplicates).

    Returns:
        Deduplicated list of viewers.
    """
    best: dict[str, ViewerPlugin] = {}
    for v in viewers:
        existing = best.get(v.name)
        if existing is None:
            best[v.name] = v
        elif v.priority >= existing.priority:
            if v.priority > existing.priority:
                logger.warning(
                    "Viewer %r (priority %d) overrides %r (priority %d)",
                    type(v).__name__,
                    v.priority,
                    type(existing).__name__,
                    existing.priority,
                )
            best[v.name] = v
        else:
            logger.debug(
                "Ignoring duplicate viewer %r (priority %d < %d)",
                v.name,
                v.priority,
                existing.priority,
            )
    return list(best.values())


def _import_file(path: Path):
    """Import a Python file as a module.

    Uses importlib.util to load a .py file without requiring it to be
    on sys.path or part of a package.
    """
    module_name = f"pagevault_viewer_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot create module spec for {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
