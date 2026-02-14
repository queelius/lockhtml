"""Tests for template.py — standalone CSS/JS generation."""

from pagevault.config import (
    DefaultsConfig,
    PagevaultConfig,
    TemplateConfig,
)
from pagevault.template import generate_css, generate_javascript, write_assets


class TestGenerateCss:
    """Tests for generate_css()."""

    def test_returns_css_string(self):
        css = generate_css()
        assert isinstance(css, str)
        assert len(css) > 0

    def test_contains_default_color(self):
        css = generate_css()
        assert "#4CAF50" in css

    def test_custom_color(self):
        config = PagevaultConfig(template=TemplateConfig(color_primary="#ff0000"))
        css = generate_css(config)
        assert "#ff0000" in css
        assert "#4CAF50" not in css

    def test_none_config_uses_defaults(self):
        css_none = generate_css(None)
        css_default = generate_css()
        assert css_none == css_default


class TestGenerateJavascript:
    """Tests for generate_javascript()."""

    def test_returns_js_string(self):
        js = generate_javascript()
        assert isinstance(js, str)
        assert len(js) > 0

    def test_contains_handler_class(self):
        js = generate_javascript()
        assert "PagevaultHandler" in js

    def test_contains_default_texts(self):
        js = generate_javascript()
        assert "Protected Content" in js
        assert "Unlock" in js

    def test_custom_template(self):
        config = PagevaultConfig(
            template=TemplateConfig(
                title="Members Only",
                button_text="Open",
            )
        )
        js = generate_javascript(config)
        assert "Members Only" in js
        assert "Open" in js

    def test_custom_defaults(self):
        config = PagevaultConfig(
            defaults=DefaultsConfig(remember="local", remember_days=30)
        )
        js = generate_javascript(config)
        assert "local" in js

    def test_none_config_uses_defaults(self):
        js_none = generate_javascript(None)
        js_default = generate_javascript()
        assert js_none == js_default

    def test_contains_escape_html(self):
        """Verify escapeHtml is present for XSS prevention."""
        js = generate_javascript()
        assert "escapeHtml" in js


class TestWriteAssets:
    """Tests for write_assets()."""

    def test_creates_files(self, tmp_path):
        css_path, js_path = write_assets(tmp_path)
        assert css_path.exists()
        assert js_path.exists()
        assert css_path.name == "pagevault.css"
        assert js_path.name == "pagevault.js"

    def test_creates_output_directory(self, tmp_path):
        out = tmp_path / "nested" / "dir"
        css_path, js_path = write_assets(out)
        assert out.is_dir()
        assert css_path.exists()
        assert js_path.exists()

    def test_file_contents_match_generators(self, tmp_path):
        css_path, js_path = write_assets(tmp_path)
        assert css_path.read_text() == generate_css()
        assert js_path.read_text() == generate_javascript()

    def test_with_custom_config(self, tmp_path):
        config = PagevaultConfig(template=TemplateConfig(color_primary="#123456"))
        css_path, js_path = write_assets(tmp_path, config)
        assert "#123456" in css_path.read_text()

    def test_accepts_string_path(self, tmp_path):
        out = str(tmp_path / "assets")
        css_path, js_path = write_assets(out)
        assert css_path.exists()
        assert js_path.exists()

    def test_overwrites_existing(self, tmp_path):
        write_assets(tmp_path)
        css_path, js_path = write_assets(tmp_path)
        assert css_path.exists()
        assert js_path.exists()
