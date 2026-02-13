"""Tests for unified lock command (HTML, non-HTML files, and --site mode)."""

import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from pagevault.cli import main


@pytest.fixture
def runner():
    """Create a CLI runner."""
    return CliRunner()


@pytest.fixture
def temp_dir():
    """Create a temporary directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


# ============================================================================
# TestLockRouting - verify operation mode detection
# ============================================================================
class TestLockRouting:
    """Test mode detection and routing."""

    def test_lock_html_file(self, runner, temp_dir):
        """HTML file should use lock_html mode."""
        html_file = temp_dir / "index.html"
        html_file.write_text("<html><body><pagevault>secret</pagevault></body></html>")

        result = runner.invoke(
            main,
            ["lock", str(html_file), "-p", "password", "-d", str(temp_dir / "out")],
        )
        assert result.exit_code == 0
        assert "Locked:" in result.output

    def test_lock_non_html_file(self, runner, temp_dir):
        """Non-HTML file should use wrap_file mode."""
        pdf_file = temp_dir / "document.pdf"
        pdf_file.write_text("PDF content")

        result = runner.invoke(main, ["lock", str(pdf_file), "-p", "password"])
        assert result.exit_code == 0
        assert "Wrapped:" in result.output
        assert (temp_dir / "document.html").exists()

    def test_lock_directory_without_site(self, runner, temp_dir):
        """Directory without --site should use lock_html mode."""
        site_dir = temp_dir / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text(
            "<html><body><pagevault>secret</pagevault></body></html>"
        )

        result = runner.invoke(
            main,
            [
                "lock",
                str(site_dir),
                "-p",
                "password",
                "-d",
                str(temp_dir / "out"),
            ],
        )
        assert result.exit_code == 0
        assert "Locked:" in result.output

    def test_lock_directory_with_site_flag(self, runner, temp_dir):
        """Directory with --site should use wrap_site mode."""
        site_dir = temp_dir / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Home</body></html>")
        (site_dir / "about.html").write_text("<html><body>About</body></html>")

        result = runner.invoke(
            main,
            ["lock", str(site_dir), "--site", "-p", "password"],
        )
        assert result.exit_code == 0
        assert "Wrapped site:" in result.output
        assert (temp_dir / "site.html").exists()

    def test_lock_multiple_non_html_files(self, runner, temp_dir):
        """Multiple non-HTML files should be wrapped individually."""
        file1 = temp_dir / "doc1.txt"
        file2 = temp_dir / "doc2.csv"
        file1.write_text("Document 1")
        file2.write_text("doc,value\n1,2")

        result = runner.invoke(main, ["lock", str(file1), str(file2), "-p", "password"])
        assert result.exit_code == 0
        assert "Wrapped:" in result.output
        assert (temp_dir / "doc1.html").exists()
        assert (temp_dir / "doc2.html").exists()


# ============================================================================
# TestFlagValidation - verify flag compatibility
# ============================================================================
class TestFlagValidation:
    """Test flag validation for each mode."""

    def test_selector_with_non_html_error(self, runner, temp_dir):
        """--selector with non-HTML file should error."""
        pdf_file = temp_dir / "doc.pdf"
        pdf_file.write_text("PDF")

        result = runner.invoke(
            main, ["lock", str(pdf_file), "-s", "#secret", "-p", "password"]
        )
        assert result.exit_code != 0
        assert "Selector" in result.output or "selector" in result.output.lower()

    def test_css_with_non_html_error(self, runner, temp_dir):
        """--css with non-HTML file should error."""
        pdf_file = temp_dir / "doc.pdf"
        css_file = temp_dir / "style.css"
        pdf_file.write_text("PDF")
        css_file.write_text("body { color: red; }")

        result = runner.invoke(
            main, ["lock", str(pdf_file), "--css", str(css_file), "-p", "password"]
        )
        assert result.exit_code != 0

    def test_selector_with_site_error(self, runner, temp_dir):
        """--selector with --site should error."""
        site_dir = temp_dir / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Home</body></html>")

        result = runner.invoke(
            main,
            ["lock", str(site_dir), "--site", "-s", "#secret", "-p", "password"],
        )
        assert result.exit_code != 0

    def test_site_with_file_error(self, runner, temp_dir):
        """--site with file path should error."""
        html_file = temp_dir / "index.html"
        html_file.write_text("<html><body>Home</body></html>")

        result = runner.invoke(
            main, ["lock", str(html_file), "--site", "-p", "password"]
        )
        assert result.exit_code != 0

    def test_both_output_flags_error(self, runner, temp_dir):
        """Both -d and -o should error for HTML."""
        html_file = temp_dir / "index.html"
        html_file.write_text("<html><body><pagevault>secret</pagevault></body></html>")

        result = runner.invoke(
            main,
            [
                "lock",
                str(html_file),
                "-d",
                str(temp_dir / "out1"),
                "-o",
                str(temp_dir / "out.html"),
                "-p",
                "password",
            ],
        )
        assert result.exit_code != 0

    def test_directory_output_with_non_html_error(self, runner, temp_dir):
        """Non-HTML should not accept -d/--directory flag."""
        pdf_file = temp_dir / "doc.pdf"
        pdf_file.write_text("PDF")

        result = runner.invoke(
            main,
            [
                "lock",
                str(pdf_file),
                "-d",
                str(temp_dir / "out"),
                "-p",
                "password",
            ],
        )
        assert result.exit_code != 0


# ============================================================================
# TestWrapFileBehavior - verify non-HTML wrapping
# ============================================================================
class TestWrapFileBehavior:
    """Test wrapping of non-HTML files."""

    def test_lock_pdf_creates_html(self, runner, temp_dir):
        """Locking PDF creates HTML wrapper."""
        pdf_file = temp_dir / "document.pdf"
        pdf_file.write_text("PDF content")

        result = runner.invoke(main, ["lock", str(pdf_file), "-p", "password"])
        assert result.exit_code == 0

        html_file = temp_dir / "document.html"
        assert html_file.exists()
        content = html_file.read_text()
        assert "pagevault" in content.lower() or "encrypted" in content.lower()

    def test_lock_image_creates_html(self, runner, temp_dir):
        """Locking image creates HTML wrapper."""
        img_file = temp_dir / "photo.png"
        img_file.write_text("fake PNG data")

        result = runner.invoke(main, ["lock", str(img_file), "-p", "password"])
        assert result.exit_code == 0
        assert (temp_dir / "photo.html").exists()

    def test_lock_text_creates_html(self, runner, temp_dir):
        """Locking text file creates HTML wrapper."""
        txt_file = temp_dir / "notes.txt"
        txt_file.write_text("Secret notes")

        result = runner.invoke(main, ["lock", str(txt_file), "-p", "password"])
        assert result.exit_code == 0
        assert (temp_dir / "notes.html").exists()

    def test_lock_non_html_custom_output(self, runner, temp_dir):
        """Non-HTML with -o flag uses custom output path."""
        pdf_file = temp_dir / "doc.pdf"
        out_file = temp_dir / "custom.html"
        pdf_file.write_text("PDF")

        result = runner.invoke(
            main,
            ["lock", str(pdf_file), "-o", str(out_file), "-p", "password"],
        )
        assert result.exit_code == 0
        assert out_file.exists()
        assert not (temp_dir / "doc.html").exists()


# ============================================================================
# TestWrapSiteBehavior - verify --site mode
# ============================================================================
class TestWrapSiteBehavior:
    """Test directory wrapping with --site flag."""

    def test_lock_site_creates_bundle(self, runner, temp_dir):
        """--site creates single bundle HTML."""
        site_dir = temp_dir / "mysite"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Home</body></html>")
        (site_dir / "about.html").write_text("<html><body>About</body></html>")
        (site_dir / "style.css").write_text("body { color: blue; }")

        result = runner.invoke(
            main,
            ["lock", str(site_dir), "--site", "-p", "password"],
        )
        assert result.exit_code == 0
        assert (temp_dir / "mysite.html").exists()

    def test_lock_site_custom_output(self, runner, temp_dir):
        """--site with -o uses custom output path."""
        site_dir = temp_dir / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Home</body></html>")

        out_file = temp_dir / "custom_bundle.html"
        result = runner.invoke(
            main,
            ["lock", str(site_dir), "--site", "-o", str(out_file), "-p", "password"],
        )
        assert result.exit_code == 0
        assert out_file.exists()

    def test_lock_site_custom_entry(self, runner, temp_dir):
        """--site with --entry uses custom entry point."""
        site_dir = temp_dir / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Home</body></html>")
        (site_dir / "home.html").write_text("<html><body>Custom Home</body></html>")

        result = runner.invoke(
            main,
            [
                "lock",
                str(site_dir),
                "--site",
                "--entry",
                "home.html",
                "-p",
                "password",
            ],
        )
        assert result.exit_code == 0
        assert (temp_dir / "site.html").exists()

    def test_lock_site_multiple_dirs(self, runner, temp_dir):
        """--site can process multiple directories."""
        site1 = temp_dir / "site1"
        site2 = temp_dir / "site2"
        site1.mkdir()
        site2.mkdir()
        (site1 / "index.html").write_text("<html><body>Site1</body></html>")
        (site2 / "index.html").write_text("<html><body>Site2</body></html>")

        result = runner.invoke(
            main,
            ["lock", str(site1), str(site2), "--site", "-p", "password"],
        )
        assert result.exit_code == 0
        assert (temp_dir / "site1.html").exists()
        assert (temp_dir / "site2.html").exists()


# ============================================================================
# TestOutputHandling - verify output path behavior
# ============================================================================
class TestOutputHandling:
    """Test output path handling for different modes."""

    def test_html_uses_output_dir(self, runner, temp_dir):
        """HTML locking uses -d/--directory for output."""
        html_file = temp_dir / "index.html"
        out_dir = temp_dir / "encrypted"
        html_file.write_text("<html><body><pagevault>secret</pagevault></body></html>")

        result = runner.invoke(
            main,
            ["lock", str(html_file), "-p", "password", "-d", str(out_dir)],
        )
        assert result.exit_code == 0
        assert (out_dir / "index.html").exists()

    def test_non_html_uses_output_file(self, runner, temp_dir):
        """Non-HTML wrapping uses -o/--output for output."""
        pdf_file = temp_dir / "doc.pdf"
        out_file = temp_dir / "doc_locked.html"
        pdf_file.write_text("PDF")

        result = runner.invoke(
            main,
            ["lock", str(pdf_file), "-o", str(out_file), "-p", "password"],
        )
        assert result.exit_code == 0
        assert out_file.exists()

    def test_site_uses_output_file(self, runner, temp_dir):
        """Site wrapping uses -o/--output for output."""
        site_dir = temp_dir / "site"
        out_file = temp_dir / "bundle.html"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Home</body></html>")

        result = runner.invoke(
            main,
            ["lock", str(site_dir), "--site", "-o", str(out_file), "-p", "password"],
        )
        assert result.exit_code == 0
        assert out_file.exists()

    def test_html_default_output_dir_warning(self, runner, temp_dir):
        """HTML locking shows warning for default _locked directory."""
        html_file = temp_dir / "index.html"
        html_file.write_text("<html><body><pagevault>secret</pagevault></body></html>")

        result = runner.invoke(
            main,
            ["lock", str(html_file), "-p", "password"],
        )
        assert result.exit_code == 0
        assert "_locked" in result.output or "Writing to" in result.output


# ============================================================================
# TestDryRun - verify dry-run mode for all modes
# ============================================================================
class TestDryRun:
    """Test dry-run mode across all operation modes."""

    def test_dry_run_html_lock(self, runner, temp_dir):
        """Dry-run shows what would happen for HTML locking."""
        html_file = temp_dir / "index.html"
        html_file.write_text("<html><body><pagevault>secret</pagevault></body></html>")

        out_dir = str(temp_dir / "out")
        result = runner.invoke(
            main,
            ["lock", str(html_file), "-p", "password", "-d", out_dir, "--dry-run"],
        )
        assert result.exit_code == 0
        assert "Would lock:" in result.output
        assert not (temp_dir / "out" / "index.html").exists()

    def test_dry_run_wrap_file(self, runner, temp_dir):
        """Dry-run shows what would happen for file wrapping."""
        pdf_file = temp_dir / "doc.pdf"
        pdf_file.write_text("PDF")

        result = runner.invoke(
            main,
            ["lock", str(pdf_file), "-p", "password", "--dry-run"],
        )
        assert result.exit_code == 0
        assert "Would wrap:" in result.output
        assert not (temp_dir / "doc.html").exists()

    def test_dry_run_wrap_site(self, runner, temp_dir):
        """Dry-run shows what would happen for site wrapping."""
        site_dir = temp_dir / "site"
        site_dir.mkdir()
        (site_dir / "index.html").write_text("<html><body>Home</body></html>")

        result = runner.invoke(
            main,
            ["lock", str(site_dir), "--site", "-p", "password", "--dry-run"],
        )
        assert result.exit_code == 0
        assert "Would wrap site:" in result.output
        assert not (temp_dir / "site.html").exists()


# ============================================================================
# TestMixedFileTypes - verify error handling for mixed types
# ============================================================================
class TestMixedFileTypes:
    """Test handling of mixed file types."""

    def test_mixed_html_and_non_html_error(self, runner, temp_dir):
        """Mixing HTML and non-HTML files should error."""
        html_file = temp_dir / "index.html"
        pdf_file = temp_dir / "doc.pdf"
        html_file.write_text("<html><body><pagevault>secret</pagevault></body></html>")
        pdf_file.write_text("PDF")

        result = runner.invoke(
            main, ["lock", str(html_file), str(pdf_file), "-p", "password"]
        )
        assert result.exit_code != 0

    def test_process_html_and_non_html_separately(self, runner, temp_dir):
        """Should work when processing separately."""
        html_file = temp_dir / "index.html"
        pdf_file = temp_dir / "doc.pdf"
        html_file.write_text("<html><body><pagevault>secret</pagevault></body></html>")
        pdf_file.write_text("PDF")

        # Process HTML
        html_out = str(temp_dir / "html_out")
        result1 = runner.invoke(
            main,
            ["lock", str(html_file), "-p", "password", "-d", html_out],
        )
        assert result1.exit_code == 0

        # Process non-HTML
        result2 = runner.invoke(main, ["lock", str(pdf_file), "-p", "password"])
        assert result2.exit_code == 0


# ============================================================================
# TestMultiUserMode - verify multi-user works with new routing
# ============================================================================
class TestMultiUserMode:
    """Test multi-user mode with unified lock command."""

    def test_lock_with_users_config_html(self, runner, temp_dir):
        """HTML locking works with multi-user config."""
        config_file = temp_dir / ".pagevault.yaml"
        config_file.write_text("users:\n  alice: alice-pw\n  bob: bob-pw\n")
        html_file = temp_dir / "index.html"
        html_file.write_text("<html><body><pagevault>secret</pagevault></body></html>")

        out_dir = str(temp_dir / "out")
        result = runner.invoke(
            main,
            ["lock", str(html_file), "-c", str(config_file), "-d", out_dir],
        )
        assert result.exit_code == 0

    def test_lock_with_users_config_wrap_file(self, runner, temp_dir):
        """File wrapping works with multi-user config."""
        config_file = temp_dir / ".pagevault.yaml"
        config_file.write_text("users:\n  alice: alice-pw\n  bob: bob-pw\n")
        pdf_file = temp_dir / "doc.pdf"
        pdf_file.write_text("PDF")

        result = runner.invoke(main, ["lock", str(pdf_file), "-c", str(config_file)])
        assert result.exit_code == 0
