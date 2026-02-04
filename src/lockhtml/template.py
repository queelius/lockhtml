"""Template generation for lockhtml.

Provides functions to generate standalone JavaScript and CSS files
for the lockhtml Web Component, useful for advanced customization.
"""

from pathlib import Path

from .config import DefaultsConfig, LockhtmlConfig, TemplateConfig
from .parser import _get_css, _get_javascript


def generate_css(config: LockhtmlConfig | None = None) -> str:
    """Generate CSS for the lockhtml component.

    Args:
        config: Optional configuration for template customization.

    Returns:
        CSS string.
    """
    template = config.template if config else TemplateConfig()
    return _get_css(template)


def generate_javascript(config: LockhtmlConfig | None = None) -> str:
    """Generate JavaScript for the lockhtml Web Component.

    Args:
        config: Optional configuration for template customization.

    Returns:
        JavaScript string.
    """
    template = config.template if config else TemplateConfig()
    defaults = config.defaults if config else DefaultsConfig()
    return _get_javascript(template, defaults)


def write_assets(
    output_dir: Path,
    config: LockhtmlConfig | None = None,
) -> tuple[Path, Path]:
    """Write CSS and JavaScript files to a directory.

    Args:
        output_dir: Directory to write files to.
        config: Optional configuration for template customization.

    Returns:
        Tuple of (css_path, js_path).
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    css_path = output_dir / "lockhtml.css"
    js_path = output_dir / "lockhtml.js"

    css_path.write_text(generate_css(config))
    js_path.write_text(generate_javascript(config))

    return css_path, js_path
