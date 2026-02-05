"""Integration tests for pagevault.

Tests the full workflow from CLI to browser-compatible output.
"""

import base64
import json

import pytest
from bs4 import BeautifulSoup
from click.testing import CliRunner

from pagevault import encrypt
from pagevault.cli import main
from pagevault.config import PagevaultConfig, create_default_config, load_config
from pagevault.parser import (
    lock_html,
    mark_body,
    sync_html_keys,
    unlock_html,
)


class TestCryptoCompatibility:
    """Tests for crypto format compatibility with WebCrypto."""

    def test_ciphertext_format_is_webcrypto_compatible(self):
        """Test ciphertext format can be parsed by browser."""
        ciphertext = encrypt("test content", password="password")

        # Decode to get JSON
        outer = base64.b64decode(ciphertext)
        data = json.loads(outer)

        # Verify format matches what WebCrypto expects
        assert data["v"] == 2
        assert data["alg"] == "aes-256-gcm"
        assert data["kdf"] == "pbkdf2-sha256"
        assert data["iter"] == 310000

        # Verify keys field exists and is a list
        assert "keys" in data
        assert isinstance(data["keys"], list)
        assert len(data["keys"]) > 0

        # Verify base64-encoded components
        salt = base64.b64decode(data["salt"])
        iv = base64.b64decode(data["iv"])
        ct = base64.b64decode(data["ct"])

        assert len(salt) == 16  # 128-bit salt
        assert len(iv) == 12  # 96-bit IV for GCM
        assert len(ct) > 0  # Ciphertext with auth tag


class TestHtmlOutput:
    """Tests for HTML output structure."""

    def test_encrypted_html_has_valid_structure(self):
        """Test encrypted HTML is valid and self-contained."""
        html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Test Page</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <header>Navigation</header>
    <pagevault hint="Contact admin for password">
        <main>
            <h1>Secret Documentation</h1>
            <p>This is protected content.</p>
        </main>
    </pagevault>
    <footer>Copyright 2024</footer>
</body>
</html>"""

        encrypted = lock_html(html, "password")
        soup = BeautifulSoup(encrypted, "lxml")

        # Document structure preserved
        assert soup.find("html") is not None
        assert soup.find("head") is not None
        assert soup.find("body") is not None

        # Head elements preserved (lxml may normalize charset to lowercase)
        meta = soup.find("meta")
        assert meta is not None
        charset = meta.get("charset", "").lower()
        assert charset == "utf-8"
        assert soup.find("title") is not None
        assert soup.find("link", {"rel": "stylesheet"}) is not None

        # Public content preserved
        assert soup.find("header") is not None
        assert "Navigation" in soup.find("header").text
        assert soup.find("footer") is not None
        assert "Copyright" in soup.find("footer").text

        # Encrypted element present
        lock_elem = soup.find("pagevault")
        assert lock_elem is not None
        assert lock_elem.has_attr("data-encrypted")
        assert lock_elem.has_attr("data-hint")
        assert lock_elem["data-hint"] == "Contact admin for password"

        # Runtime injected
        runtime_style = soup.find("style", {"data-pagevault-runtime": True})
        runtime_script = soup.find("script", {"data-pagevault-runtime": True})
        assert runtime_style is not None
        assert runtime_script is not None

        # Secret content NOT present
        assert "Secret Documentation" not in encrypted

    def test_encrypted_html_contains_web_component(self):
        """Test encrypted HTML contains Web Component definition."""
        html = "<pagevault>Secret</pagevault>"
        encrypted = lock_html(html, "password")

        # Web Component registration
        assert "customElements.define" in encrypted
        assert "'pagevault'" in encrypted

        # Key WebCrypto functions
        assert "crypto.subtle" in encrypted
        assert "PBKDF2" in encrypted
        assert "AES-GCM" in encrypted

        # UI elements
        assert ".pagevault-container" in encrypted
        assert ".pagevault-input" in encrypted
        assert ".pagevault-button" in encrypted


class TestBrowserFeatures:
    """Tests for browser-side features in generated JS."""

    def test_auto_decrypt_from_storage(self):
        """Test JS includes localStorage auto-decrypt logic."""
        html = "<pagevault>Secret</pagevault>"
        encrypted = lock_html(html, "password")

        assert "localStorage" in encrypted
        assert "sessionStorage" in encrypted
        assert "getStoredCredentials" in encrypted

    def test_url_fragment_handling(self):
        """Test JS includes URL fragment handling."""
        html = "<pagevault>Secret</pagevault>"
        encrypted = lock_html(html, "password")

        assert "pagevault_pwd" in encrypted
        assert "pagevault_logout" in encrypted
        assert "location.hash" in encrypted

    def test_remember_me_options(self):
        """Test JS handles remember-me options."""
        html = "<pagevault>Secret</pagevault>"
        config = PagevaultConfig()
        encrypted = lock_html(html, "password", config)

        assert "storeCredentials" in encrypted
        assert "clearStoredPasswords" in encrypted
        assert "rememberDays" in encrypted

    def test_decryption_event_dispatched(self):
        """Test JS dispatches event after decryption."""
        html = "<pagevault>Secret</pagevault>"
        encrypted = lock_html(html, "password")

        assert "pagevault:decrypted" in encrypted
        assert "CustomEvent" in encrypted
        assert "dispatchEvent" in encrypted


class TestFullWorkflow:
    """Tests for complete workflow scenarios."""

    def test_static_site_workflow(self, tmp_path):
        """Test typical static site workflow."""
        runner = CliRunner()

        # 1. Create site structure
        site_dir = tmp_path / "my-site"
        site_dir.mkdir()

        (site_dir / "index.html").write_text("""<!DOCTYPE html>
<html>
<head><title>My Site</title></head>
<body>
<nav>Home | About | Members</nav>
<pagevault hint="Members only">
<section class="members-area">
    <h1>Member Content</h1>
    <p>Secret member information.</p>
</section>
</pagevault>
<footer>Public footer</footer>
</body>
</html>""")

        (site_dir / "about.html").write_text("""<!DOCTYPE html>
<html>
<head><title>About</title></head>
<body>
<h1>About Us</h1>
<p>Public information.</p>
</body>
</html>""")

        # 2. Initialize config
        result = runner.invoke(main, ["config", "init", "-d", str(site_dir)])
        assert result.exit_code == 0

        # Update password in config
        config_path = site_dir / ".pagevault.yaml"
        config_content = config_path.read_text()
        config_content = config_content.replace(
            'password: "your-strong-passphrase"', 'password: "member-secret"'
        )
        config_path.write_text(config_content)

        # 3. Lock site
        output_dir = tmp_path / "dist"
        result = runner.invoke(
            main,
            [
                "lock",
                str(site_dir),
                "-r",
                "-c",
                str(config_path),
                "-d",
                str(output_dir),
            ],
        )
        assert result.exit_code == 0
        # Both files get locked: index.html has pagevault elements,
        # about.html gets default body wrapping (v2 behavior)
        assert "2 file(s) locked" in result.output

        # 4. Verify output
        index_encrypted = (output_dir / "index.html").read_text()
        (output_dir / "about.html").read_text() if (
            output_dir / "about.html"
        ).exists() else ""

        # Index is encrypted
        assert "data-encrypted=" in index_encrypted
        assert "Member Content" not in index_encrypted
        assert "Public footer" in index_encrypted

        # 5. Unlock to verify
        restored_dir = tmp_path / "restored"
        result = runner.invoke(
            main,
            [
                "unlock",
                str(output_dir),
                "-r",
                "-c",
                str(config_path),
                "-d",
                str(restored_dir),
            ],
        )
        assert result.exit_code == 0

        restored = (restored_dir / "index.html").read_text()
        assert "Member Content" in restored
        assert "Secret member information" in restored

    def test_config_inheritance(self, tmp_path):
        """Test config is found by traversing up directory tree."""
        # Create nested structure
        root = tmp_path / "project"
        root.mkdir()

        # Config at root
        create_default_config(root)
        config_path = root / ".pagevault.yaml"
        content = config_path.read_text().replace(
            'password: "your-strong-passphrase"', 'password: "inherited-password"'
        )
        config_path.write_text(content)

        # HTML in nested directory
        nested = root / "docs" / "internal"
        nested.mkdir(parents=True)

        html_path = nested / "secret.html"
        html_path.write_text("<pagevault>Nested secret</pagevault>")

        # Should find config from nested dir
        config = load_config(start_path=nested)
        assert config.password == "inherited-password"

    def test_env_override_workflow(self, tmp_path, monkeypatch):
        """Test environment variable override for CI/CD."""
        # Create minimal config without password
        config_path = tmp_path / ".pagevault.yaml"
        config_path.write_text("""
salt: "0123456789abcdef0123456789abcdef"
defaults:
  remember: "local"
""")

        # Set password via env
        monkeypatch.setenv("PAGEVAULT_PASSWORD", "ci-password")

        config = load_config(config_path=config_path)
        assert config.password == "ci-password"
        assert config.defaults.remember == "local"


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_special_characters_in_content(self):
        """Test content with special HTML/JS characters."""
        html = """<pagevault>
<script>alert('test');</script>
<p>HTML entities: &amp; &lt; &gt; &quot;</p>
<p>Unicode: 日本語 🔒 émoji</p>
</pagevault>"""

        encrypted = lock_html(html, "password")
        decrypted = unlock_html(encrypted, "password")

        assert "&amp;" in decrypted
        assert "日本語" in decrypted
        assert "🔒" in decrypted

    def test_nested_elements_preserved(self):
        """Test nested HTML structure is preserved."""
        html = """<pagevault>
<div class="outer">
    <div class="middle">
        <div class="inner">
            <span>Deep content</span>
        </div>
    </div>
</div>
</pagevault>"""

        encrypted = lock_html(html, "password")
        decrypted = unlock_html(encrypted, "password")

        soup = BeautifulSoup(decrypted, "html.parser")
        inner = soup.select_one(".outer .middle .inner span")
        assert inner is not None
        assert inner.text == "Deep content"

    def test_attributes_preserved(self):
        """Test element attributes are preserved."""
        html = """<pagevault>
<div id="main" class="container" data-custom="value" style="color: red;">
    Content
</div>
</pagevault>"""

        encrypted = lock_html(html, "password")
        decrypted = unlock_html(encrypted, "password")

        soup = BeautifulSoup(decrypted, "html.parser")
        div = soup.find("div", {"id": "main"})
        assert div is not None
        assert "container" in div.get("class", [])
        assert div.get("data-custom") == "value"
        assert "color: red" in div.get("style", "")

    def test_whitespace_preservation(self):
        """Test significant whitespace is preserved."""
        html = """<pagevault>
<pre>
    Indented
        code
    block
</pre>
</pagevault>"""

        encrypted = lock_html(html, "password")
        decrypted = unlock_html(encrypted, "password")

        # Pre tag content should be preserved
        assert "<pre>" in decrypted
        soup = BeautifulSoup(decrypted, "html.parser")
        pre = soup.find("pre")
        assert "Indented" in pre.text


class TestMultiUserWorkflow:
    """Tests for multi-user encrypt/decrypt/sync workflows."""

    def test_multiuser_encrypt_decrypt_cycle(self):
        """Test full cycle with users config: encrypt then decrypt as each user."""
        html = """<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<pagevault hint="Team access">
<p>Team secret content</p>
</pagevault>
</body>
</html>"""

        users = {"alice": "pw-alice", "bob": "pw-bob"}

        encrypted = lock_html(html, users=users)

        # Both users should be able to decrypt
        for username, password in users.items():
            decrypted = unlock_html(encrypted, password, username=username)
            assert "Team secret content" in decrypted
            assert "data-encrypted" not in decrypted

    def test_sync_after_adding_user(self):
        """Test encrypt with alice, add bob via sync, bob can decrypt."""
        html = """<pagevault>
<p>Original content</p>
</pagevault>"""

        # Encrypt with alice only
        initial_users = {"alice": "pw-alice"}
        encrypted = lock_html(html, users=initial_users)
        assert "Original content" not in encrypted

        # Sync to add bob
        updated_users = {"alice": "pw-alice", "bob": "pw-bob"}
        synced = sync_html_keys(
            encrypted,
            old_users=initial_users,
            new_users=updated_users,
        )

        # Bob should now be able to decrypt
        decrypted = unlock_html(synced, "pw-bob", username="bob")
        assert "Original content" in decrypted

        # Alice should still be able to decrypt
        decrypted = unlock_html(synced, "pw-alice", username="alice")
        assert "Original content" in decrypted

    def test_sync_after_removing_user(self):
        """Test encrypt with alice+bob, remove bob via sync, bob fails."""
        html = """<pagevault>
<p>Restricted content</p>
</pagevault>"""

        # Encrypt with both users
        initial_users = {"alice": "pw-alice", "bob": "pw-bob"}
        encrypted = lock_html(html, users=initial_users)

        # Sync to remove bob
        reduced_users = {"alice": "pw-alice"}
        synced = sync_html_keys(
            encrypted,
            old_users=initial_users,
            new_users=reduced_users,
        )

        # Alice should still be able to decrypt
        decrypted = unlock_html(synced, "pw-alice", username="alice")
        assert "Restricted content" in decrypted

        # Bob should no longer be able to decrypt
        from pagevault.crypto import PagevaultError

        with pytest.raises(PagevaultError):
            unlock_html(synced, "pw-bob", username="bob")

    def test_sync_with_rekey(self):
        """Test encrypt then sync --rekey, verify content still decryptable."""
        html = """<pagevault>
<p>Rekeyed content</p>
</pagevault>"""

        users = {"alice": "pw-alice", "bob": "pw-bob"}
        encrypted = lock_html(html, users=users)

        # Sync with rekey (generates new CEK)
        synced = sync_html_keys(
            encrypted,
            old_users=users,
            new_users=users,
            rekey=True,
        )

        # Content should still be decryptable by both users
        for username, password in users.items():
            decrypted = unlock_html(synced, password, username=username)
            assert "Rekeyed content" in decrypted


class TestBodyWrapWorkflow:
    """Tests for default body wrapping workflow."""

    def test_body_wrap_roundtrip(self):
        """Test HTML without pagevault elements: encrypt wraps body, decrypt restores."""

        html = """<!DOCTYPE html>
<html>
<head><title>My Page</title></head>
<body>
<h1>Welcome</h1>
<p>This is public-looking content that gets wrapped.</p>
</body>
</html>"""

        # Wrap body (simulates what CLI does before encrypt)
        wrapped = mark_body(html)
        assert "<pagevault>" in wrapped

        # Encrypt
        encrypted = lock_html(wrapped, "password")
        assert "Welcome" not in encrypted
        assert "data-encrypted=" in encrypted

        # Decrypt
        decrypted = unlock_html(encrypted, "password")
        assert "Welcome" in decrypted
        assert "public-looking content" in decrypted
