"""Tests for lockhtml.wrap module."""

import base64
from pathlib import Path

import pytest
from bs4 import BeautifulSoup
from click.testing import CliRunner

from lockhtml.cli import main
from lockhtml.config import CONFIG_FILENAME
from lockhtml.crypto import LockhtmlError, decrypt
from lockhtml.wrap import (
    _get_marked_js,
    _get_renderer_js,
    _get_wrap_css,
    detect_mime,
    wrap_file,
    wrap_site,
)


class TestDetectMime:
    """Tests for MIME type detection."""

    def test_png(self):
        assert detect_mime(Path("image.png")) == "image/png"

    def test_jpg(self):
        assert detect_mime(Path("photo.jpg")) == "image/jpeg"

    def test_pdf(self):
        assert detect_mime(Path("document.pdf")) == "application/pdf"

    def test_markdown(self):
        assert detect_mime(Path("README.md")) == "text/markdown"

    def test_html(self):
        assert detect_mime(Path("index.html")) == "text/html"

    def test_svg(self):
        assert detect_mime(Path("icon.svg")) == "image/svg+xml"

    def test_webp(self):
        assert detect_mime(Path("photo.webp")) == "image/webp"

    def test_css(self):
        assert detect_mime(Path("styles.css")) == "text/css"

    def test_unknown(self):
        assert detect_mime(Path("file.xyz123")) == "application/octet-stream"

    def test_text(self):
        assert detect_mime(Path("notes.txt")) == "text/plain"


class TestWrapFile:
    """Tests for wrap_file function."""

    def test_basic_wrap(self, tmp_path):
        """Test wrapping a simple text file."""
        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello, World!")

        output = wrap_file(test_file, password="password")

        assert output.exists()
        assert output.suffix == ".html"

        content = output.read_text()
        assert "data-encrypted=" in content
        assert 'data-wrap-type="file"' in content
        assert 'data-filename="test.txt"' in content
        assert "Protected: test.txt" in content

    def test_wrap_with_custom_output(self, tmp_path):
        """Test wrapping with custom output path."""
        test_file = tmp_path / "data.csv"
        test_file.write_text("a,b,c\n1,2,3")

        output_path = tmp_path / "output" / "data.html"
        result = wrap_file(test_file, password="pw", output_path=output_path)

        assert result == output_path
        assert output_path.exists()

    def test_wrap_binary_file(self, tmp_path):
        """Test wrapping a binary file (e.g., PNG header)."""
        test_file = tmp_path / "image.png"
        # Write a minimal PNG-like binary
        test_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        output = wrap_file(test_file, password="password")
        assert output.exists()

        content = output.read_text()
        assert 'data-wrap-type="file"' in content
        assert 'data-filename="image.png"' in content

    def test_wrap_pdf(self, tmp_path):
        """Test wrapping a PDF file."""
        test_file = tmp_path / "document.pdf"
        test_file.write_bytes(b"%PDF-1.4" + b"\x00" * 100)

        output = wrap_file(test_file, password="password")

        content = output.read_text()
        assert 'data-wrap-type="file"' in content

    def test_encrypted_payload_is_decryptable(self, tmp_path):
        """Test that the encrypted payload can be decrypted."""
        test_file = tmp_path / "secret.txt"
        test_file.write_text("Secret data!")

        output = wrap_file(test_file, password="test-pw")
        content = output.read_text()

        # Extract encrypted payload
        soup = BeautifulSoup(content, "html.parser")
        elem = soup.find("lockhtml-encrypt")
        encrypted = elem["data-encrypted"]

        # Decrypt
        plaintext, meta = decrypt(encrypted, "test-pw")

        # The plaintext should be the base64-encoded file content
        decoded = base64.b64decode(plaintext)
        assert decoded == b"Secret data!"

        # Meta should have file info
        assert meta["type"] == "file"
        assert meta["filename"] == "secret.txt"
        assert meta["mime"] == "text/plain"
        assert meta["size"] == len(b"Secret data!")

    def test_wrap_nonexistent_file(self, tmp_path):
        """Test wrapping a nonexistent file raises error."""
        with pytest.raises(LockhtmlError, match="File not found"):
            wrap_file(tmp_path / "nonexistent.txt", password="pw")

    def test_wrap_with_content_hash(self, tmp_path):
        """Test that content hash is included."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hash test")

        output = wrap_file(test_file, password="pw")
        content = output.read_text()

        assert "data-content-hash=" in content

    def test_wrap_multiuser(self, tmp_path):
        """Test wrapping with multi-user encryption."""
        test_file = tmp_path / "shared.txt"
        test_file.write_text("Shared secret")

        output = wrap_file(
            test_file,
            users={"alice": "pw-a", "bob": "pw-b"},
        )

        content = output.read_text()
        assert 'data-mode="user"' in content

        # Both users should be able to decrypt
        soup = BeautifulSoup(content, "html.parser")
        elem = soup.find("lockhtml-encrypt")
        encrypted = elem["data-encrypted"]

        text_a, _ = decrypt(encrypted, "pw-a", username="alice")
        text_b, _ = decrypt(encrypted, "pw-b", username="bob")
        assert base64.b64decode(text_a) == b"Shared secret"
        assert base64.b64decode(text_b) == b"Shared secret"

    def test_html_is_self_contained(self, tmp_path):
        """Test output HTML contains all needed runtime."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        output = wrap_file(test_file, password="pw")
        content = output.read_text()

        # Should have crypto JS
        assert "crypto.subtle" in content
        assert "PBKDF2" in content
        assert "AES-GCM" in content

        # Should have renderer JS
        assert "renderFile" in content

        # Should have CSS
        assert ".lockhtml-container" in content
        assert ".lockhtml-button" in content

    def test_wrap_large_file(self, tmp_path):
        """Test wrapping a larger file."""
        test_file = tmp_path / "large.bin"
        test_file.write_bytes(b"x" * 100000)

        output = wrap_file(test_file, password="pw")
        assert output.exists()

        # Verify decryptability
        soup = BeautifulSoup(output.read_text(), "html.parser")
        elem = soup.find("lockhtml-encrypt")
        encrypted = elem["data-encrypted"]
        plaintext, meta = decrypt(encrypted, "pw")
        decoded = base64.b64decode(plaintext)
        assert decoded == b"x" * 100000

    def test_wrap_unicode_filename(self, tmp_path):
        """Test wrapping a file with unicode in the name."""
        test_file = tmp_path / "日本語ファイル.txt"
        test_file.write_text("日本語テスト")

        output = wrap_file(test_file, password="pw")
        assert output.exists()

        content = output.read_text()
        assert "日本語ファイル.txt" in content


class TestWrapSite:
    """Tests for wrap_site function."""

    def test_basic_site_wrap(self, tmp_path):
        """Test wrapping a simple site directory."""
        # Create a minimal site
        site_dir = tmp_path / "my-site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body><h1>Home</h1></body></html>")
        (site_dir / "style.css").write_text("body { color: red; }")

        output = wrap_site(site_dir, password="password")

        assert output.exists()
        assert output.name == "my-site.html"

        content = output.read_text()
        assert 'data-wrap-type="site"' in content
        assert 'data-entry="index.html"' in content
        assert "data-encrypted=" in content

    def test_site_custom_output(self, tmp_path):
        """Test wrapping site with custom output path."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Hi</body></html>")

        output_path = tmp_path / "output.html"
        result = wrap_site(site_dir, password="pw", output_path=output_path)

        assert result == output_path
        assert output_path.exists()

    def test_site_custom_entry(self, tmp_path):
        """Test wrapping site with custom entry point."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "home.html").write_text("<html><body>Home</body></html>")

        output = wrap_site(site_dir, password="pw", entry="home.html")

        content = output.read_text()
        assert 'data-entry="home.html"' in content

    def test_site_encrypted_payload_contains_zip(self, tmp_path):
        """Test encrypted payload contains a valid zip with all files."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<h1>Hello</h1>")
        (site_dir / "style.css").write_text("body { margin: 0; }")

        output = wrap_site(site_dir, password="pw")

        # Extract and decrypt
        soup = BeautifulSoup(output.read_text(), "html.parser")
        elem = soup.find("lockhtml-encrypt")
        encrypted = elem["data-encrypted"]

        plaintext, meta = decrypt(encrypted, "pw")

        # Meta should list files
        assert meta["type"] == "site"
        assert meta["entry"] == "index.html"
        assert "index.html" in meta["files"]
        assert "style.css" in meta["files"]

        # Plaintext should be base64 zip
        import zipfile
        from io import BytesIO

        zip_bytes = base64.b64decode(plaintext)
        with zipfile.ZipFile(BytesIO(zip_bytes)) as zf:
            names = zf.namelist()
            assert "index.html" in names
            assert "style.css" in names
            assert zf.read("index.html") == b"<h1>Hello</h1>"
            assert zf.read("style.css") == b"body { margin: 0; }"

    def test_site_with_subdirectories(self, tmp_path):
        """Test wrapping site with nested directories."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Home</body></html>")
        images_dir = site_dir / "images"
        images_dir.mkdir()
        (images_dir / "logo.png").write_bytes(b"\x89PNG" + b"\x00" * 50)
        css_dir = site_dir / "css"
        css_dir.mkdir()
        (css_dir / "main.css").write_text("body { margin: 0; }")

        output = wrap_site(site_dir, password="pw")

        # Verify all files in metadata
        soup = BeautifulSoup(output.read_text(), "html.parser")
        elem = soup.find("lockhtml-encrypt")
        encrypted = elem["data-encrypted"]
        _, meta = decrypt(encrypted, "pw")

        assert "index.html" in meta["files"]
        assert "images/logo.png" in meta["files"]
        assert "css/main.css" in meta["files"]

    def test_site_missing_entry(self, tmp_path):
        """Test error when entry point doesn't exist."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "page.html").write_text("<html>Page</html>")

        with pytest.raises(LockhtmlError, match="Entry point"):
            wrap_site(site_dir, password="pw", entry="index.html")

    def test_site_empty_directory(self, tmp_path):
        """Test error on empty directory."""
        site_dir = tmp_path / "empty"
        site_dir.mkdir()

        with pytest.raises(LockhtmlError, match="empty"):
            wrap_site(site_dir, password="pw")

    def test_site_nonexistent_directory(self, tmp_path):
        """Test error on nonexistent directory."""
        with pytest.raises(LockhtmlError, match="Directory not found"):
            wrap_site(tmp_path / "nope", password="pw")

    def test_site_includes_jszip_shim(self, tmp_path):
        """Test site output includes JSZip shim and site renderer."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html>Hi</html>")

        output = wrap_site(site_dir, password="pw")
        content = output.read_text()

        assert "ZipReader" in content
        assert "__lockhtml_renderSite" in content
        assert "rewriteUrls" in content

    def test_site_multiuser(self, tmp_path):
        """Test wrapping site with multi-user encryption."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html>Secret site</html>")

        output = wrap_site(
            site_dir,
            users={"alice": "pw-a", "bob": "pw-b"},
        )

        content = output.read_text()
        assert 'data-mode="user"' in content

        # Both users can decrypt
        soup = BeautifulSoup(content, "html.parser")
        elem = soup.find("lockhtml-encrypt")
        encrypted = elem["data-encrypted"]

        _, meta_a = decrypt(encrypted, "pw-a", username="alice")
        _, meta_b = decrypt(encrypted, "pw-b", username="bob")
        assert meta_a["type"] == "site"
        assert meta_b["type"] == "site"


class TestWrapFileCli:
    """Tests for 'lockhtml wrap file' CLI command."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.fixture
    def sample_config(self):
        return """
password: "test-password"
salt: "0123456789abcdef0123456789abcdef"
"""

    def test_wrap_file_basic(self, runner, tmp_path, sample_config):
        """Test basic wrap file command."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Hello!")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output = tmp_path / "test.html"

        result = runner.invoke(
            main,
            [
                "wrap",
                "file",
                str(test_file),
                "-c",
                str(config_path),
                "-o",
                str(output),
            ],
        )

        assert result.exit_code == 0
        assert "Wrapped:" in result.output
        assert output.exists()

    def test_wrap_file_with_password(self, runner, tmp_path):
        """Test wrap file with -p flag."""
        test_file = tmp_path / "secret.txt"
        test_file.write_text("Secret!")

        output = tmp_path / "secret.html"

        result = runner.invoke(
            main,
            [
                "wrap",
                "file",
                str(test_file),
                "-p",
                "my-password",
                "-o",
                str(output),
            ],
        )

        assert result.exit_code == 0
        assert output.exists()

    def test_wrap_file_prompts_password(self, runner, tmp_path):
        """Test wrap file prompts for password when not provided."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        output = tmp_path / "test.html"

        result = runner.invoke(
            main,
            [
                "wrap",
                "file",
                str(test_file),
                "-o",
                str(output),
            ],
            input="prompted-password\n",
        )

        assert result.exit_code == 0
        assert output.exists()


class TestWrapSiteCli:
    """Tests for 'lockhtml wrap site' CLI command."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    @pytest.fixture
    def sample_config(self):
        return """
password: "test-password"
salt: "0123456789abcdef0123456789abcdef"
"""

    def test_wrap_site_basic(self, runner, tmp_path, sample_config):
        """Test basic wrap site command."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Hi</body></html>")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output = tmp_path / "site.html"

        result = runner.invoke(
            main,
            [
                "wrap",
                "site",
                str(site_dir),
                "-c",
                str(config_path),
                "-o",
                str(output),
            ],
        )

        assert result.exit_code == 0
        assert "Wrapped:" in result.output
        assert output.exists()

    def test_wrap_site_with_entry(self, runner, tmp_path, sample_config):
        """Test wrap site with custom entry point."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "home.html").write_text("<html><body>Home</body></html>")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output = tmp_path / "site.html"

        result = runner.invoke(
            main,
            [
                "wrap",
                "site",
                str(site_dir),
                "-c",
                str(config_path),
                "-o",
                str(output),
                "--entry",
                "home.html",
            ],
        )

        assert result.exit_code == 0
        assert output.exists()

        content = output.read_text()
        assert 'data-entry="home.html"' in content

    def test_wrap_site_missing_entry_fails(self, runner, tmp_path, sample_config):
        """Test wrap site fails when entry point doesn't exist."""
        site_dir = tmp_path / "site"
        site_dir.mkdir()
        (site_dir / "page.html").write_text("<html>Page</html>")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        result = runner.invoke(
            main,
            [
                "wrap",
                "site",
                str(site_dir),
                "-c",
                str(config_path),
            ],
        )

        assert result.exit_code != 0
        assert "Entry point" in result.output


class TestVendoredMarked:
    """Tests for the vendored marked.js library."""

    def test_get_marked_js_returns_content(self):
        """Vendored marked.js loads and returns substantial JS."""
        js = _get_marked_js()
        assert len(js) > 10000  # ~41KB expected
        assert "marked" in js

    def test_marked_js_is_mit_licensed(self):
        """Vendored file contains MIT license header."""
        js = _get_marked_js()
        assert "MIT" in js


class TestMarkdownViewer:
    """Tests for markdown viewer with marked.js conditional inclusion."""

    def test_markdown_file_includes_marked(self, tmp_path):
        """Wrapping a .md file should include marked.js."""
        md_file = tmp_path / "readme.md"
        md_file.write_text("# Hello\n\nSome text.")

        output = wrap_file(md_file, password="pw")
        content = output.read_text()

        # marked.js should be included
        assert "marked v" in content
        # Renderer should reference marked.parse
        assert "marked.parse" in content

    def test_markdown_extension_includes_marked(self, tmp_path):
        """Both .md and .markdown extensions should include marked.js."""
        md_file = tmp_path / "readme.markdown"
        md_file.write_text("# Test")

        output = wrap_file(md_file, password="pw")
        content = output.read_text()
        assert "marked v" in content

    def test_non_markdown_excludes_marked(self, tmp_path):
        """Non-markdown files should NOT include marked.js."""
        txt_file = tmp_path / "notes.txt"
        txt_file.write_text("Just plain text.")

        output = wrap_file(txt_file, password="pw")
        content = output.read_text()
        assert "marked v" not in content

    def test_image_excludes_marked(self, tmp_path):
        """Image files should NOT include marked.js."""
        img_file = tmp_path / "photo.png"
        img_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)

        output = wrap_file(img_file, password="pw")
        content = output.read_text()
        assert "marked v" not in content


class TestMarkdownToggle:
    """Tests for markdown source/rendered toggle."""

    def test_toggle_button_in_renderer(self):
        """Renderer JS should contain toggle button code."""
        js = _get_renderer_js()
        assert "toolbar-toggle" in js
        assert "renderMarkdownViewer" in js
        assert "Source" in js
        assert "Rendered" in js

    def test_simplemarkdown_fallback_preserved(self):
        """simpleMarkdown fallback should still exist in renderer."""
        js = _get_renderer_js()
        assert "simpleMarkdown" in js


class TestViewerToolbar:
    """Tests for the shared toolbar component."""

    def test_create_toolbar_in_renderer(self):
        """Renderer JS should contain createToolbar function."""
        js = _get_renderer_js()
        assert "createToolbar" in js
        assert "toolbar-filename" in js
        assert "toolbar-size" in js

    def test_toolbar_css_present(self):
        """CSS should contain toolbar styles."""
        from lockhtml.config import TemplateConfig

        css = _get_wrap_css(TemplateConfig())
        assert ".lockhtml-toolbar" in css
        assert ".toolbar-filename" in css
        assert ".toolbar-btn" in css


class TestImageViewer:
    """Tests for the enhanced image viewer."""

    def test_render_image_viewer_in_renderer(self):
        """Renderer JS should contain renderImageViewer function."""
        js = _get_renderer_js()
        assert "renderImageViewer" in js

    def test_zoom_class_in_renderer(self):
        """Renderer JS should toggle 'zoomed' class on click."""
        js = _get_renderer_js()
        assert "zoomed" in js

    def test_image_zoom_css(self):
        """CSS should contain zoom styles for images."""
        from lockhtml.config import TemplateConfig

        css = _get_wrap_css(TemplateConfig())
        assert ".lockhtml-image-viewer" in css
        assert "img.zoomed" in css
        assert "zoom-in" in css
        assert "zoom-out" in css


class TestTextViewer:
    """Tests for the enhanced text viewer with line numbers."""

    def test_render_text_viewer_in_renderer(self):
        """Renderer JS should contain renderTextViewer function."""
        js = _get_renderer_js()
        assert "renderTextViewer" in js
        assert "line-numbers" in js

    def test_line_numbers_css(self):
        """CSS should contain line-number gutter styles."""
        from lockhtml.config import TemplateConfig

        css = _get_wrap_css(TemplateConfig())
        assert ".line-numbers" in css
        assert "user-select: none" in css
        assert ".lockhtml-text-viewer" in css


class TestWrapFileViewers:
    """End-to-end tests: verify correct viewer functions appear per MIME type."""

    @pytest.mark.parametrize(
        "filename, content, expected_fn",
        [
            ("doc.md", b"# Heading\n\nParagraph", "renderMarkdownViewer"),
            ("notes.txt", b"line1\nline2\nline3", "renderTextViewer"),
            ("photo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 50, "renderImageViewer"),
            ("doc.pdf", b"%PDF-1.4" + b"\x00" * 50, "renderPdfViewer"),
        ],
    )
    def test_viewer_function_present(self, tmp_path, filename, content, expected_fn):
        """Each MIME type's viewer function should be present in output HTML."""
        f = tmp_path / filename
        f.write_bytes(content)

        output = wrap_file(f, password="pw")
        html = output.read_text()

        assert expected_fn in html
        # All outputs should have toolbar
        assert "createToolbar" in html

    def test_markdown_gets_marked_js(self, tmp_path):
        """Markdown output should include marked.js library."""
        f = tmp_path / "test.md"
        f.write_text("# Title\n\n| a | b |\n|---|---|\n| 1 | 2 |")

        output = wrap_file(f, password="pw")
        html = output.read_text()

        assert "marked v" in html
        assert "marked.parse" in html

    def test_text_does_not_get_marked_js(self, tmp_path):
        """Text output should NOT include marked.js library."""
        f = tmp_path / "data.csv"
        f.write_text("a,b,c\n1,2,3")

        output = wrap_file(f, password="pw")
        html = output.read_text()

        assert "marked v" not in html
