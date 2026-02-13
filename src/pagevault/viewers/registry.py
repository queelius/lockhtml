"""Viewer plugin discovery and resolution."""

from __future__ import annotations

import importlib.metadata
import logging
from typing import TYPE_CHECKING

from .base import ViewerPlugin

if TYPE_CHECKING:
    from ..config import PagevaultConfig

logger = logging.getLogger(__name__)


def discover_viewers(config: PagevaultConfig | None = None) -> list[ViewerPlugin]:
    """Discover all available viewer plugins.

    Loads viewers from entry points (group="pagevault.viewers"),
    with a fallback to direct import for uninstalled development mode.
    Deduplicates by name (highest priority wins), then filters by
    config's ``viewers:`` section.

    Args:
        config: Optional configuration with viewers overrides.

    Returns:
        List of active ViewerPlugin instances.
    """
    viewers = _load_from_entry_points()

    # Fallback: if entry points aren't registered (e.g. running tests
    # without pip install), load built-ins directly.
    if not viewers:
        viewers = _load_builtins()

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


def _deduplicate_by_name(viewers: list[ViewerPlugin]) -> list[ViewerPlugin]:
    """Deduplicate viewers by name, keeping the highest priority for each.

    When a third-party plugin registers with the same name as a built-in
    (e.g. both define ``name = "image"``), only the highest-priority one
    is kept. Ties are broken by order (first seen wins).

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
        elif v.priority > existing.priority:
            logger.warning(
                "Viewer %r (priority %d) overrides %r (priority %d)",
                type(v).__name__,
                v.priority,
                type(existing).__name__,
                existing.priority,
            )
            best[v.name] = v
        elif v is not existing:
            logger.debug(
                "Ignoring duplicate viewer %r (priority %d <= %d)",
                v.name,
                v.priority,
                existing.priority,
            )
    return list(best.values())


def _load_from_entry_points() -> list[ViewerPlugin]:
    """Load viewer plugins from entry points."""
    viewers: list[ViewerPlugin] = []
    for ep in importlib.metadata.entry_points(group="pagevault.viewers"):
        try:
            cls = ep.load()
            viewers.append(cls())
        except Exception:
            logger.warning("Failed to load viewer plugin: %s", ep.name)
    return viewers


def _load_builtins() -> list[ViewerPlugin]:
    """Load built-in viewers directly (fallback when entry points unavailable)."""
    from .builtin import (
        HtmlViewer,
        ImageViewer,
        MarkdownViewer,
        PdfViewer,
        TextViewer,
    )

    return [
        ImageViewer(),
        PdfViewer(),
        HtmlViewer(),
        TextViewer(),
        MarkdownViewer(),
    ]
