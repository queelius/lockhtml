"""Tests for lockhtml.cli module."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from lockhtml.cli import main
from lockhtml.config import CONFIG_FILENAME


@pytest.fixture
def runner():
    """Create a CLI runner."""
    return CliRunner()


@pytest.fixture
def sample_html():
    """Sample HTML with lockhtml-encrypt element."""
    return """<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<header>Public Header</header>
<lockhtml-encrypt hint="Password hint">
<main>Secret content here</main>
</lockhtml-encrypt>
<footer>Public Footer</footer>
</body>
</html>"""


@pytest.fixture
def sample_config():
    """Sample configuration file content."""
    return """
password: "test-password"
salt: "0123456789abcdef0123456789abcdef"
defaults:
  remember: "ask"
  remember_days: 0
  auto_prompt: true
"""


class TestConfigInit:
    """Tests for config init command."""

    def test_creates_config_file(self, runner, tmp_path):
        """Test creating a new config file."""
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["config", "init"])

            assert result.exit_code == 0
            assert "Created:" in result.output
            assert Path(CONFIG_FILENAME).exists()

    def test_creates_in_directory(self, runner, tmp_path):
        """Test creating config in specified directory."""
        result = runner.invoke(main, ["config", "init", "-d", str(tmp_path)])

        assert result.exit_code == 0
        assert (tmp_path / CONFIG_FILENAME).exists()

    def test_fails_if_exists(self, runner, tmp_path):
        """Test fails if config already exists."""
        (tmp_path / CONFIG_FILENAME).write_text("existing")

        result = runner.invoke(main, ["config", "init", "-d", str(tmp_path)])

        assert result.exit_code != 0
        assert "already exists" in result.output


class TestConfigShow:
    """Tests for config show command."""

    def test_shows_config(self, runner, tmp_path, sample_config):
        """Test showing configuration."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        result = runner.invoke(main, ["config", "show", "-c", str(config_path)])

        assert result.exit_code == 0
        assert "password: '********'" in result.output
        assert "salt:" in result.output
        assert "remember: ask" in result.output


class TestConfigWhere:
    """Tests for config where command."""

    def test_finds_config(self, runner, tmp_path, sample_config):
        """Test finding config file."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        result = runner.invoke(main, ["config", "where", "-d", str(tmp_path)])

        assert result.exit_code == 0
        assert str(config_path) in result.output

    def test_not_found(self, runner, tmp_path):
        """Test when config not found."""
        result = runner.invoke(main, ["config", "where", "-d", str(tmp_path)])

        assert result.exit_code == 0
        assert "No .lockhtml.yaml found" in result.output


class TestEncrypt:
    """Tests for encrypt command."""

    def test_encrypts_file(self, runner, tmp_path, sample_html, sample_config):
        """Test encrypting a single file."""
        # Create test files
        html_path = tmp_path / "index.html"
        html_path.write_text(sample_html)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
            ],
        )

        assert result.exit_code == 0
        assert "Encrypted:" in result.output
        assert "1 file(s) encrypted" in result.output

        # Check output file
        output_path = output_dir / "index.html"
        assert output_path.exists()

        content = output_path.read_text()
        assert "data-encrypted=" in content
        assert "Secret content" not in content
        assert "Public Header" in content

    def test_encrypts_directory_recursive(
        self, runner, tmp_path, sample_html, sample_config
    ):
        """Test encrypting directory recursively."""
        # Create test files
        (tmp_path / "site").mkdir()
        (tmp_path / "site" / "sub").mkdir()
        (tmp_path / "site" / "index.html").write_text(sample_html)
        (tmp_path / "site" / "sub" / "page.html").write_text(sample_html)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(tmp_path / "site"),
                "-r",
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
            ],
        )

        assert result.exit_code == 0
        assert "2 file(s) encrypted" in result.output

        assert (output_dir / "index.html").exists()
        assert (output_dir / "sub" / "page.html").exists()

    def test_dry_run(self, runner, tmp_path, sample_html, sample_config):
        """Test dry run mode."""
        html_path = tmp_path / "index.html"
        html_path.write_text(sample_html)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "--dry-run",
            ],
        )

        assert result.exit_code == 0
        assert "Would encrypt:" in result.output
        assert not output_dir.exists()

    def test_skips_files_without_elements(self, runner, tmp_path, sample_config):
        """Test skips files with empty body (nothing to wrap or encrypt)."""
        html_path = tmp_path / "normal.html"
        html_path.write_text("<html><body></body></html>")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
            ],
        )

        assert result.exit_code == 0
        assert "0 file(s) encrypted" in result.output
        assert "1 skipped" in result.output

    def test_prompts_for_password(self, runner, tmp_path, sample_html):
        """Test prompts for password when not in config."""
        html_path = tmp_path / "index.html"
        html_path.write_text(sample_html)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-d",
                str(output_dir),
            ],
            input="test-password\n",
        )

        assert result.exit_code == 0
        assert "1 file(s) encrypted" in result.output

    def test_password_override(self, runner, tmp_path, sample_html, sample_config):
        """Test password can be overridden via CLI."""
        html_path = tmp_path / "index.html"
        html_path.write_text(sample_html)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-p",
                "override-password",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) encrypted" in result.output


class TestDecrypt:
    """Tests for decrypt command."""

    def test_decrypts_file(self, runner, tmp_path, sample_html, sample_config):
        """Test decrypting a single file."""
        # Create and encrypt test file
        html_path = tmp_path / "index.html"
        html_path.write_text(sample_html)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        encrypted_dir = tmp_path / "encrypted"
        decrypted_dir = tmp_path / "decrypted"

        # Encrypt first
        runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(encrypted_dir),
            ],
        )

        # Then decrypt
        result = runner.invoke(
            main,
            [
                "decrypt",
                str(encrypted_dir / "index.html"),
                "-c",
                str(config_path),
                "-d",
                str(decrypted_dir),
            ],
        )

        assert result.exit_code == 0
        assert "Decrypted:" in result.output
        assert "1 file(s) decrypted" in result.output

        # Check content is restored
        content = (decrypted_dir / "index.html").read_text()
        assert "Secret content" in content
        assert "Public Header" in content

    def test_roundtrip(self, runner, tmp_path, sample_html, sample_config):
        """Test encrypt/decrypt roundtrip preserves structure."""
        html_path = tmp_path / "index.html"
        html_path.write_text(sample_html)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        encrypted_dir = tmp_path / "encrypted"
        decrypted_dir = tmp_path / "decrypted"

        # Encrypt
        runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(encrypted_dir),
            ],
        )

        # Decrypt
        runner.invoke(
            main,
            [
                "decrypt",
                str(encrypted_dir),
                "-r",
                "-c",
                str(config_path),
                "-d",
                str(decrypted_dir),
            ],
        )

        # Compare key elements
        html_path.read_text()
        restored = (decrypted_dir / "index.html").read_text()

        assert "Public Header" in restored
        assert "Public Footer" in restored
        assert "Secret content" in restored
        assert 'hint="Password hint"' in restored


class TestSelectorEncrypt:
    """Tests for encrypt command with --selector option."""

    @pytest.fixture
    def html_without_lockhtml(self):
        """HTML without lockhtml-encrypt elements."""
        return """<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<header>Public Header</header>
<div id="secret-content">Secret content here</div>
<div class="private">Private section</div>
<footer>Public Footer</footer>
</body>
</html>"""

    def test_selector_by_id(
        self, runner, tmp_path, html_without_lockhtml, sample_config
    ):
        """Test encrypting element by ID selector."""
        html_path = tmp_path / "index.html"
        html_path.write_text(html_without_lockhtml)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                "#secret-content",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) encrypted" in result.output

        content = (output_dir / "index.html").read_text()
        assert "data-encrypted=" in content
        assert "Secret content here" not in content
        assert "Public Header" in content

    def test_selector_by_class(
        self, runner, tmp_path, html_without_lockhtml, sample_config
    ):
        """Test encrypting element by class selector."""
        html_path = tmp_path / "index.html"
        html_path.write_text(html_without_lockhtml)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                ".private",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) encrypted" in result.output

        content = (output_dir / "index.html").read_text()
        assert "data-encrypted=" in content
        assert "Private section" not in content

    def test_multiple_selectors(
        self, runner, tmp_path, html_without_lockhtml, sample_config
    ):
        """Test encrypting multiple elements with multiple selectors."""
        html_path = tmp_path / "index.html"
        html_path.write_text(html_without_lockhtml)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                "#secret-content",
                "-s",
                ".private",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) encrypted" in result.output

        content = (output_dir / "index.html").read_text()
        assert content.count("data-encrypted=") == 2
        assert "Secret content here" not in content
        assert "Private section" not in content

    def test_selector_with_hint(
        self, runner, tmp_path, html_without_lockhtml, sample_config
    ):
        """Test selector with password hint."""
        html_path = tmp_path / "index.html"
        html_path.write_text(html_without_lockhtml)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                "#secret-content",
                "--hint",
                "Use the magic word",
            ],
        )

        assert result.exit_code == 0

        content = (output_dir / "index.html").read_text()
        assert 'data-hint="Use the magic word"' in content

    def test_selector_with_remember(
        self, runner, tmp_path, html_without_lockhtml, sample_config
    ):
        """Test selector with remember mode."""
        html_path = tmp_path / "index.html"
        html_path.write_text(html_without_lockhtml)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                "#secret-content",
                "--remember",
                "local",
            ],
        )

        assert result.exit_code == 0

        content = (output_dir / "index.html").read_text()
        assert 'data-remember="local"' in content

    def test_selector_dry_run(
        self, runner, tmp_path, html_without_lockhtml, sample_config
    ):
        """Test selector with dry run mode."""
        html_path = tmp_path / "index.html"
        html_path.write_text(html_without_lockhtml)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                "#secret-content",
                "--dry-run",
            ],
        )

        assert result.exit_code == 0
        assert "Would encrypt:" in result.output
        assert not output_dir.exists()

    def test_selector_no_match_skips(
        self, runner, tmp_path, html_without_lockhtml, sample_config
    ):
        """Test that files with no matching selectors are skipped."""
        html_path = tmp_path / "index.html"
        html_path.write_text(html_without_lockhtml)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                "#nonexistent",
            ],
        )

        assert result.exit_code == 0
        assert "0 file(s) encrypted" in result.output
        assert "1 skipped" in result.output

    def test_selector_with_title(
        self, runner, tmp_path, html_without_lockhtml, sample_config
    ):
        """Test selector with custom title."""
        html_path = tmp_path / "index.html"
        html_path.write_text(html_without_lockhtml)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                "#secret-content",
                "--title",
                "Admin Panel",
            ],
        )

        assert result.exit_code == 0

        content = (output_dir / "index.html").read_text()
        assert 'data-title="Admin Panel"' in content

    def test_multi_password_workflow(self, runner, tmp_path, sample_config):
        """Test encrypting elements with different passwords."""
        html = """<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<div id="admin">Admin content</div>
<div id="member">Member content</div>
</body>
</html>"""

        html_path = tmp_path / "index.html"
        html_path.write_text(html)

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        # First pass: encrypt admin section with password1
        pass1_dir = tmp_path / "pass1"
        result1 = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(pass1_dir),
                "-s",
                "#admin",
                "-p",
                "admin-password",
                "--title",
                "Admin Area",
            ],
        )

        assert result1.exit_code == 0
        assert "1 file(s) encrypted" in result1.output

        # Second pass: encrypt member section with different password
        pass2_dir = tmp_path / "pass2"
        result2 = runner.invoke(
            main,
            [
                "encrypt",
                str(pass1_dir / "index.html"),
                "-c",
                str(config_path),
                "-d",
                str(pass2_dir),
                "-s",
                "#member",
                "-p",
                "member-password",
                "--title",
                "Members Only",
            ],
        )

        assert result2.exit_code == 0
        assert "1 file(s) encrypted" in result2.output

        # Final file should have both sections encrypted
        content = (pass2_dir / "index.html").read_text()
        assert content.count("data-encrypted=") == 2
        assert "Admin content" not in content
        assert "Member content" not in content
        assert 'data-title="Admin Area"' in content
        assert 'data-title="Members Only"' in content


class TestDefaultBodyEncrypt:
    """Tests for default body wrapping behavior (no selectors, no lockhtml elements)."""

    @pytest.fixture
    def sample_config(self):
        """Sample configuration file content."""
        return """
password: "test-password"
salt: "0123456789abcdef0123456789abcdef"
defaults:
  remember: "ask"
  remember_days: 0
  auto_prompt: true
"""

    def test_encrypts_body_without_lockhtml_elements(
        self, runner, tmp_path, sample_config
    ):
        """Test HTML without lockhtml elements gets body wrapped."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<h1>Hello World</h1>
<p>Some public content that should be encrypted.</p>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) encrypted" in result.output

        content = (output_dir / "index.html").read_text()
        assert "data-encrypted=" in content
        assert "Hello World" not in content

    def test_preserves_head_during_body_encrypt(self, runner, tmp_path, sample_config):
        """Test head section is preserved when body is auto-wrapped."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head>
<title>My Page</title>
<meta name="description" content="Test page">
<link rel="stylesheet" href="styles.css">
</head>
<body>
<p>Body content to encrypt</p>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) encrypted" in result.output

        content = (output_dir / "index.html").read_text()
        assert "<title>My Page</title>" in content
        assert 'href="styles.css"' in content
        assert "Body content to encrypt" not in content
        assert "data-encrypted=" in content

    def test_body_encrypt_with_password_flag(self, runner, tmp_path, sample_config):
        """Test using -p flag with body encryption works."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body><p>Secret stuff</p></body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-p",
                "override-password",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) encrypted" in result.output

        content = (output_dir / "index.html").read_text()
        assert "data-encrypted=" in content
        assert "Secret stuff" not in content

    def test_selector_overrides_body_wrap(self, runner, tmp_path, sample_config):
        """Test using --selector prevents automatic body wrapping."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<div id="public">Public content</div>
<div id="secret">Secret content</div>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
                "-s",
                "#secret",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) encrypted" in result.output

        content = (output_dir / "index.html").read_text()
        # Only the selected element is encrypted, public content remains
        assert "Public content" in content
        assert "Secret content" not in content
        assert "data-encrypted=" in content


class TestMultiUserCli:
    """Tests for multi-user encryption/decryption via CLI."""

    @pytest.fixture
    def sample_users_config(self):
        """Multi-user configuration file content."""
        return """
password: "fallback"
salt: "0123456789abcdef0123456789abcdef"
users:
  alice: "pw-alice"
  bob: "pw-bob"
"""

    def test_encrypt_with_users_config(self, runner, tmp_path, sample_users_config):
        """Test encrypting with users config produces data-mode='user' output."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<lockhtml-encrypt hint="Multi-user">
<p>Secret for multiple users</p>
</lockhtml-encrypt>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_users_config)

        output_dir = tmp_path / "encrypted"

        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) encrypted" in result.output

        content = (output_dir / "index.html").read_text()
        assert 'data-mode="user"' in content
        assert "data-encrypted=" in content
        assert "Secret for multiple users" not in content

    def test_decrypt_with_username_flag(self, runner, tmp_path, sample_users_config):
        """Test encrypt with users config, decrypt with -u alice -p pw."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<lockhtml-encrypt>
<p>Alice and Bob's secret</p>
</lockhtml-encrypt>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_users_config)

        encrypted_dir = tmp_path / "encrypted"
        decrypted_dir = tmp_path / "decrypted"

        # Encrypt with users
        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(encrypted_dir),
            ],
        )
        assert result.exit_code == 0

        # Decrypt as alice
        result = runner.invoke(
            main,
            [
                "decrypt",
                str(encrypted_dir / "index.html"),
                "-u",
                "alice",
                "-p",
                "pw-alice",
                "-d",
                str(decrypted_dir),
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) decrypted" in result.output

        content = (decrypted_dir / "index.html").read_text()
        assert "Alice and Bob's secret" in content

    def test_password_flag_overrides_users(self, runner, tmp_path, sample_users_config):
        """Test -p flag overrides users config for single-user encryption."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<lockhtml-encrypt>
<p>Single user override</p>
</lockhtml-encrypt>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_users_config)

        encrypted_dir = tmp_path / "encrypted"
        decrypted_dir = tmp_path / "decrypted"

        # Encrypt with -p flag (should override users)
        result = runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(encrypted_dir),
                "-p",
                "single-password",
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) encrypted" in result.output

        content = (encrypted_dir / "index.html").read_text()
        # Should NOT have data-mode="user" since -p overrides users
        assert 'data-mode="user"' not in content

        # Should be decryptable with the single password (no username)
        result = runner.invoke(
            main,
            [
                "decrypt",
                str(encrypted_dir / "index.html"),
                "-p",
                "single-password",
                "-d",
                str(decrypted_dir),
            ],
        )

        assert result.exit_code == 0
        assert "1 file(s) decrypted" in result.output

        content = (decrypted_dir / "index.html").read_text()
        assert "Single user override" in content


class TestSyncCommand:
    """Tests for sync command."""

    @pytest.fixture
    def sample_users_config(self):
        """Multi-user configuration file content."""
        return """
password: "fallback"
salt: "0123456789abcdef0123456789abcdef"
users:
  alice: "pw-alice"
  bob: "pw-bob"
"""

    def test_sync_basic(self, runner, tmp_path, sample_users_config):
        """Test basic sync with users config."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<lockhtml-encrypt>
<p>Sync test content</p>
</lockhtml-encrypt>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_users_config)

        encrypted_dir = tmp_path / "encrypted"

        # Encrypt first
        runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(encrypted_dir),
            ],
        )

        # Sync the encrypted file
        result = runner.invoke(
            main,
            [
                "sync",
                str(encrypted_dir / "index.html"),
                "-c",
                str(config_path),
            ],
        )

        assert result.exit_code == 0

        # File should still be valid and decryptable
        decrypted_dir = tmp_path / "decrypted"
        result = runner.invoke(
            main,
            [
                "decrypt",
                str(encrypted_dir / "index.html"),
                "-u",
                "alice",
                "-p",
                "pw-alice",
                "-d",
                str(decrypted_dir),
            ],
        )

        assert result.exit_code == 0
        content = (decrypted_dir / "index.html").read_text()
        assert "Sync test content" in content

    def test_sync_dry_run(self, runner, tmp_path, sample_users_config):
        """Test sync --dry-run shows what would happen without modifying files."""
        html_path = tmp_path / "index.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<lockhtml-encrypt>
<p>Dry run content</p>
</lockhtml-encrypt>
</body>
</html>""")

        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_users_config)

        encrypted_dir = tmp_path / "encrypted"

        # Encrypt first
        runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(encrypted_dir),
            ],
        )

        # Capture file content before sync
        encrypted_before = (encrypted_dir / "index.html").read_text()

        # Sync with --dry-run
        result = runner.invoke(
            main,
            [
                "sync",
                str(encrypted_dir / "index.html"),
                "-c",
                str(config_path),
                "--dry-run",
            ],
        )

        assert result.exit_code == 0
        assert "Would sync:" in result.output

        # File should be unchanged
        encrypted_after = (encrypted_dir / "index.html").read_text()
        assert encrypted_before == encrypted_after

    def test_sync_requires_users(self, runner, tmp_path):
        """Test sync fails when config has no users defined."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text("""
password: "test-password"
salt: "0123456789abcdef0123456789abcdef"
""")

        html_path = tmp_path / "index.html"
        html_path.write_text("<lockhtml-encrypt>content</lockhtml-encrypt>")

        result = runner.invoke(
            main,
            [
                "sync",
                str(html_path),
                "-c",
                str(config_path),
            ],
        )

        assert result.exit_code != 0
        assert "users" in result.output.lower()

    def test_sync_no_paths_no_managed(self, runner, tmp_path, sample_users_config):
        """Test sync fails when no paths given and no managed globs in config."""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(sample_users_config)

        result = runner.invoke(
            main,
            [
                "sync",
                "-c",
                str(config_path),
            ],
        )

        assert result.exit_code != 0
        assert "managed" in result.output.lower() or "paths" in result.output.lower()

    def test_sync_with_managed_globs(self, runner, tmp_path):
        """Test sync using managed globs from config (no paths argument)."""
        # Config with managed globs
        encrypted_dir = tmp_path / "encrypted"
        encrypted_dir.mkdir()

        config_content = """
password: "fallback"
salt: "0123456789abcdef0123456789abcdef"
users:
  alice: "pw-alice"
  bob: "pw-bob"
managed:
  - "encrypted/**/*.html"
"""
        config_path = tmp_path / CONFIG_FILENAME
        config_path.write_text(config_content)

        # Create and encrypt a file
        html_path = tmp_path / "source.html"
        html_path.write_text("""<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<lockhtml-encrypt>
<p>Managed content</p>
</lockhtml-encrypt>
</body>
</html>""")

        runner.invoke(
            main,
            [
                "encrypt",
                str(html_path),
                "-c",
                str(config_path),
                "-d",
                str(encrypted_dir),
            ],
        )

        assert (encrypted_dir / "source.html").exists()

        # Sync using managed globs (no paths argument)
        result = runner.invoke(
            main,
            [
                "sync",
                "-c",
                str(config_path),
            ],
        )

        assert result.exit_code == 0


class TestVersion:
    """Tests for version command."""

    def test_version(self, runner):
        """Test version output."""
        result = runner.invoke(main, ["--version"])

        assert result.exit_code == 0
        assert "lockhtml" in result.output
        assert "0.1.0" in result.output
