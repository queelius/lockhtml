"""Tests for lockhtml.parser module."""

import pytest
from bs4 import BeautifulSoup

from lockhtml.config import DefaultsConfig, LockhtmlConfig, TemplateConfig
from lockhtml.crypto import LockhtmlError, content_hash, decrypt, generate_salt
from lockhtml.parser import (
    extract_element_content,
    find_lockhtml_elements,
    has_lockhtml_elements,
    is_already_encrypted,
    lock_html,
    mark_body,
    mark_elements,
    sync_html_keys,
    unlock_html,
)


class TestMarkElements:
    """Tests for mark_elements function."""

    def test_wraps_single_element_by_id(self):
        """Test wrapping element by ID selector."""
        html = '<html><body><div id="secret">Secret content</div></body></html>'

        result = mark_elements(html, ["#secret"])

        assert "<lockhtml-encrypt>" in result
        assert "</lockhtml-encrypt>" in result
        assert "Secret content" in result

    def test_wraps_element_by_class(self):
        """Test wrapping element by class selector."""
        html = '<html><body><div class="private">Private content</div></body></html>'

        result = mark_elements(html, [".private"])

        soup = BeautifulSoup(result, "html.parser")
        wrapper = soup.find("lockhtml-encrypt")
        assert wrapper is not None
        assert "Private content" in str(wrapper)

    def test_wraps_multiple_selectors(self):
        """Test wrapping elements with multiple selectors."""
        html = """<html><body>
            <div id="first">First</div>
            <div class="second">Second</div>
        </body></html>"""

        result = mark_elements(html, ["#first", ".second"])

        assert result.count("<lockhtml-encrypt>") == 2

    def test_wraps_multiple_matching_elements(self):
        """Test wrapping multiple elements matching same selector."""
        html = """<html><body>
            <div class="secret">One</div>
            <div class="secret">Two</div>
        </body></html>"""

        result = mark_elements(html, [".secret"])

        assert result.count("<lockhtml-encrypt>") == 2

    def test_adds_hint_attribute(self):
        """Test hint attribute is added to wrapper."""
        html = '<html><body><div id="secret">Secret</div></body></html>'

        result = mark_elements(html, ["#secret"], hint="Password hint")

        assert 'hint="Password hint"' in result

    def test_adds_remember_attribute(self):
        """Test remember attribute is added to wrapper."""
        html = '<html><body><div id="secret">Secret</div></body></html>'

        result = mark_elements(html, ["#secret"], remember="local")

        assert 'remember="local"' in result

    def test_adds_both_hint_and_remember(self):
        """Test both hint and remember are added."""
        html = '<html><body><div id="secret">Secret</div></body></html>'

        result = mark_elements(html, ["#secret"], hint="The hint", remember="session")

        assert 'hint="The hint"' in result
        assert 'remember="session"' in result

    def test_wraps_lockhtml_encrypt_elements(self):
        """Test can wrap existing lockhtml-encrypt elements for composability."""
        html = (
            "<html><body><lockhtml-encrypt>"
            "Already wrapped</lockhtml-encrypt></body></html>"
        )

        result = mark_elements(html, ["lockhtml-encrypt"])

        # Should be wrapped in another lockhtml-encrypt (closure property)
        assert result.count("<lockhtml-encrypt") == 2

    def test_skips_already_wrapped_elements(self):
        """Test skips elements already inside lockhtml-encrypt."""
        html = (
            "<html><body><lockhtml-encrypt>"
            '<div id="inner">Content</div>'
            "</lockhtml-encrypt></body></html>"
        )

        result = mark_elements(html, ["#inner"])

        # Should not wrap the inner div
        assert result.count("<lockhtml-encrypt>") == 1

    def test_no_selectors_returns_unchanged(self):
        """Test returns unchanged HTML when no selectors provided."""
        html = '<html><body><div id="secret">Secret</div></body></html>'

        result = mark_elements(html, [])

        # No lockhtml-encrypt should be added
        assert "<lockhtml-encrypt>" not in result

    def test_no_matching_elements(self):
        """Test handles no matching elements gracefully."""
        html = "<html><body><div>Regular content</div></body></html>"

        result = mark_elements(html, ["#nonexistent", ".missing"])

        assert "<lockhtml-encrypt>" not in result

    def test_complex_selector(self):
        """Test complex CSS selector."""
        html = """<html><body>
            <article class="post">
                <div class="content">Article content</div>
            </article>
        </body></html>"""

        result = mark_elements(html, ["article.post .content"])

        soup = BeautifulSoup(result, "html.parser")
        wrapper = soup.find("lockhtml-encrypt")
        assert wrapper is not None
        assert "Article content" in str(wrapper)

    def test_integration_with_lock_html(self):
        """Test marked elements can be encrypted."""
        html = (
            "<html><head><title>Test</title></head>"
            '<body><div id="secret">Secret content'
            "</div></body></html>"
        )

        wrapped = mark_elements(html, ["#secret"])
        encrypted = lock_html(wrapped, "password")

        # Content should be encrypted
        assert "Secret content" not in encrypted
        assert "data-encrypted=" in encrypted


class TestHasLockhtmlElements:
    """Tests for has_lockhtml_elements function."""

    def test_detects_element(self):
        """Test detecting lockhtml-encrypt elements."""
        html = "<html><lockhtml-encrypt>secret</lockhtml-encrypt></html>"
        assert has_lockhtml_elements(html) is True

    def test_detects_self_closing(self):
        """Test detecting self-closing elements."""
        html = '<html><lockhtml-encrypt data-encrypted="x"/></html>'
        assert has_lockhtml_elements(html) is True

    def test_case_insensitive(self):
        """Test case-insensitive detection."""
        html = "<html><LOCKHTML-ENCRYPT>secret</LOCKHTML-ENCRYPT></html>"
        assert has_lockhtml_elements(html) is True

    def test_no_elements(self):
        """Test returns False when no elements."""
        html = "<html><body>normal content</body></html>"
        assert has_lockhtml_elements(html) is False


class TestFindLockhtmlElements:
    """Tests for find_lockhtml_elements function."""

    def test_finds_single_element(self):
        """Test finding a single element."""
        html = "<html><lockhtml-encrypt>secret</lockhtml-encrypt></html>"
        soup = BeautifulSoup(html, "html.parser")

        elements = find_lockhtml_elements(soup)
        assert len(elements) == 1

    def test_finds_multiple_elements(self):
        """Test finding multiple elements."""
        html = """
        <html>
            <lockhtml-encrypt>one</lockhtml-encrypt>
            <lockhtml-encrypt>two</lockhtml-encrypt>
        </html>
        """
        soup = BeautifulSoup(html, "html.parser")

        elements = find_lockhtml_elements(soup)
        assert len(elements) == 2


class TestExtractElementContent:
    """Tests for extract_element_content function."""

    def test_extracts_text(self):
        """Test extracting text content."""
        html = "<lockhtml-encrypt>secret text</lockhtml-encrypt>"
        soup = BeautifulSoup(html, "html.parser")
        element = soup.find("lockhtml-encrypt")

        content = extract_element_content(element)
        assert content == "secret text"

    def test_extracts_nested_html(self):
        """Test extracting nested HTML."""
        html = "<lockhtml-encrypt><div><p>nested</p></div></lockhtml-encrypt>"
        soup = BeautifulSoup(html, "html.parser")
        element = soup.find("lockhtml-encrypt")

        content = extract_element_content(element)
        assert "<div>" in content
        assert "<p>nested</p>" in content


class TestIsAlreadyEncrypted:
    """Tests for is_already_encrypted function."""

    def test_encrypted_element(self):
        """Test detecting encrypted element."""
        html = '<lockhtml-encrypt data-encrypted="ciphertext"></lockhtml-encrypt>'
        soup = BeautifulSoup(html, "html.parser")
        element = soup.find("lockhtml-encrypt")

        assert is_already_encrypted(element) is True

    def test_unencrypted_element(self):
        """Test detecting unencrypted element."""
        html = "<lockhtml-encrypt>plaintext</lockhtml-encrypt>"
        soup = BeautifulSoup(html, "html.parser")
        element = soup.find("lockhtml-encrypt")

        assert is_already_encrypted(element) is False


class TestLockHtml:
    """Tests for lock_html function."""

    def test_basic_encryption(self):
        """Test basic HTML encryption."""
        html = """<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<lockhtml-encrypt>Secret content</lockhtml-encrypt>
</body>
</html>"""

        result = lock_html(html, "password")

        # Should have data-encrypted attribute
        assert "data-encrypted=" in result
        # Original content should be gone
        assert "Secret content" not in result
        # Should have injected runtime
        assert "lockhtml-encrypt" in result.lower()

    def test_preserves_hint(self):
        """Test hint attribute is preserved."""
        html = '<lockhtml-encrypt hint="Use the magic word">Secret</lockhtml-encrypt>'

        result = lock_html(html, "password")
        assert 'data-hint="Use the magic word"' in result

    def test_preserves_remember(self):
        """Test remember attribute is preserved."""
        html = '<lockhtml-encrypt remember="local">Secret</lockhtml-encrypt>'

        result = lock_html(html, "password")
        assert 'data-remember="local"' in result

    def test_uses_config_defaults(self):
        """Test uses config defaults for remember."""
        html = "<lockhtml-encrypt>Secret</lockhtml-encrypt>"
        config = LockhtmlConfig(defaults=DefaultsConfig(remember="session"))

        result = lock_html(html, "password", config)
        assert 'data-remember="session"' in result

    def test_injects_runtime(self):
        """Test runtime JS/CSS is injected."""
        html = """<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<lockhtml-encrypt>Secret</lockhtml-encrypt>
</body>
</html>"""

        result = lock_html(html, "password")

        assert "data-lockhtml-runtime" in result
        assert "customElements.define" in result
        assert ".lockhtml-container" in result

    def test_no_elements_returns_unchanged(self):
        """Test HTML without elements is unchanged."""
        html = "<html><body>Normal content</body></html>"

        result = lock_html(html, "password")
        assert result == html

    def test_reencrypts_already_encrypted(self):
        """Test encrypting already-encrypted elements (composability)."""
        html = (
            '<lockhtml-encrypt data-encrypted="x">Already encrypted</lockhtml-encrypt>'
        )

        result = lock_html(html, "password")

        # Should be re-encrypted (composable encryption)
        assert "data-encrypted=" in result
        # The original "x" value should be replaced with new encrypted data
        assert 'data-encrypted="x"' not in result

    def test_uses_explicit_salt(self):
        """Test encryption uses explicit salt."""
        html = "<lockhtml-encrypt>Secret</lockhtml-encrypt>"
        salt = generate_salt()

        result1 = lock_html(html, "password", salt=salt)
        result2 = lock_html(html, "password", salt=salt)

        # Both should decrypt correctly with same password
        soup1 = BeautifulSoup(result1, "html.parser")
        soup2 = BeautifulSoup(result2, "html.parser")

        encrypted1 = soup1.find("lockhtml-encrypt")["data-encrypted"]
        encrypted2 = soup2.find("lockhtml-encrypt")["data-encrypted"]

        content1, _meta1 = decrypt(encrypted1, "password")
        assert content1 == "Secret"
        content2, _meta2 = decrypt(encrypted2, "password")
        assert content2 == "Secret"


class TestUnlockHtml:
    """Tests for unlock_html function."""

    def test_basic_decryption(self):
        """Test basic HTML decryption."""
        original = "<lockhtml-encrypt>Secret content</lockhtml-encrypt>"
        encrypted = lock_html(original, "password")

        decrypted = unlock_html(encrypted, "password")

        assert "Secret content" in decrypted
        assert "data-encrypted" not in decrypted

    def test_roundtrip_preserves_content(self):
        """Test encrypt/decrypt roundtrip preserves content."""
        html = """<!DOCTYPE html>
<html>
<head><title>Test Page</title></head>
<body>
<header>Public Header</header>
<lockhtml-encrypt hint="Hint text">
    <main>
        <h1>Secret Title</h1>
        <p>Secret paragraph.</p>
    </main>
</lockhtml-encrypt>
<footer>Public Footer</footer>
</body>
</html>"""

        encrypted = lock_html(html, "password")
        decrypted = unlock_html(encrypted, "password")

        # Public content should be present
        assert "Public Header" in decrypted
        assert "Public Footer" in decrypted

        # Encrypted content should be restored
        assert "Secret Title" in decrypted
        assert "Secret paragraph" in decrypted

    def test_removes_runtime(self):
        """Test runtime is removed after decryption."""
        html = "<lockhtml-encrypt>Secret</lockhtml-encrypt>"
        encrypted = lock_html(html, "password")

        assert "data-lockhtml-runtime" in encrypted

        decrypted = unlock_html(encrypted, "password")
        assert "data-lockhtml-runtime" not in decrypted

    def test_wrong_password_fails(self):
        """Test decryption with wrong password fails."""
        html = "<lockhtml-encrypt>Secret</lockhtml-encrypt>"
        encrypted = lock_html(html, "correct")

        with pytest.raises(LockhtmlError, match="wrong password"):
            unlock_html(encrypted, "wrong")

    def test_no_elements_returns_unchanged(self):
        """Test HTML without elements is unchanged."""
        html = "<html><body>Normal content</body></html>"

        result = unlock_html(html, "password")
        assert result == html

    def test_preserves_hint_for_reencryption(self):
        """Test hint is preserved as original attribute after decryption."""
        html = '<lockhtml-encrypt hint="Remember the hint">Secret</lockhtml-encrypt>'

        encrypted = lock_html(html, "password")
        decrypted = unlock_html(encrypted, "password")

        assert 'hint="Remember the hint"' in decrypted


class TestMultipleElements:
    """Tests for multiple lockhtml-encrypt elements."""

    def test_encryption_with_multiple_elements(self):
        """Test encrypting multiple elements."""
        html = """
        <lockhtml-encrypt hint="hint1">First</lockhtml-encrypt>
        <lockhtml-encrypt hint="hint2">Second</lockhtml-encrypt>
        """

        result = lock_html(html, "password")

        # Both should be encrypted
        assert "First" not in result
        assert "Second" not in result
        assert result.count("data-encrypted=") == 2
        assert 'data-hint="hint1"' in result
        assert 'data-hint="hint2"' in result

    def test_roundtrip_multiple_elements(self):
        """Test encrypt/decrypt roundtrip with multiple elements."""
        html = """
        <lockhtml-encrypt>First content</lockhtml-encrypt>
        <p>Public content</p>
        <lockhtml-encrypt>Second content</lockhtml-encrypt>
        """

        encrypted = lock_html(html, "password")
        decrypted = unlock_html(encrypted, "password")

        assert "First content" in decrypted
        assert "Second content" in decrypted
        assert "Public content" in decrypted

    def test_encrypts_all_elements(self):
        """Test that all elements are encrypted including already-encrypted ones."""
        from lockhtml.crypto import encrypt as crypto_encrypt

        enc1 = crypto_encrypt("Already encrypted", password="password")

        html = f"""
        <lockhtml-encrypt data-encrypted="{enc1}"></lockhtml-encrypt>
        <lockhtml-encrypt>New content</lockhtml-encrypt>
        """

        result = lock_html(html, "password")

        # Both should be encrypted (composable encryption)
        assert result.count("data-encrypted=") == 2
        assert "New content" not in result
        # The first one should be re-encrypted (different ciphertext)
        assert f'data-encrypted="{enc1}"' not in result


class TestTemplateCustomization:
    """Tests for template customization."""

    def test_custom_colors(self):
        """Test custom colors are applied."""
        html = "<lockhtml-encrypt>Secret</lockhtml-encrypt>"
        config = LockhtmlConfig(
            template=TemplateConfig(color_primary="#ff0000", color_secondary="#00ff00")
        )

        result = lock_html(html, "password", config)

        assert "#ff0000" in result
        assert "#00ff00" in result

    def test_custom_text(self):
        """Test custom text is applied."""
        html = "<lockhtml-encrypt>Secret</lockhtml-encrypt>"
        config = LockhtmlConfig(
            template=TemplateConfig(
                title="Custom Title",
                button_text="Custom Button",
                error_text="Custom Error",
                placeholder="Custom Placeholder",
            )
        )

        result = lock_html(html, "password", config)

        assert "Custom Title" in result
        assert "Custom Button" in result
        assert "Custom Error" in result
        assert "Custom Placeholder" in result

    def test_custom_css(self):
        """Test custom CSS replaces default styles."""
        html = "<lockhtml-encrypt>Secret</lockhtml-encrypt>"
        custom_css = ".my-custom-class { color: purple; }"

        result = lock_html(html, "password", custom_css=custom_css)

        # Custom CSS should be included
        assert ".my-custom-class" in result
        assert "color: purple" in result
        # Default CSS should NOT be included
        assert ".lockhtml-container" not in result

    def test_custom_css_from_config(self):
        """Test custom CSS from config."""
        html = "<lockhtml-encrypt>Secret</lockhtml-encrypt>"
        config = LockhtmlConfig(custom_css=".config-class { font-size: 20px; }")

        result = lock_html(html, "password", config)

        assert ".config-class" in result
        assert "font-size: 20px" in result

    def test_custom_css_cli_overrides_config(self):
        """Test CLI custom CSS overrides config custom CSS."""
        html = "<lockhtml-encrypt>Secret</lockhtml-encrypt>"
        config = LockhtmlConfig(custom_css=".config-class { color: red; }")
        cli_css = ".cli-class { color: blue; }"

        result = lock_html(html, "password", config, custom_css=cli_css)

        # CLI CSS should be used
        assert ".cli-class" in result
        assert "color: blue" in result
        # Config CSS should NOT be used
        assert ".config-class" not in result


class TestContentHashIntegrity:
    """Tests for content hash storage and verification."""

    def test_hash_stored_in_encrypted_element(self):
        """Test that content hash is stored during encryption."""
        html = "<lockhtml-encrypt>Secret content</lockhtml-encrypt>"
        expected_hash = content_hash("Secret content")

        result = lock_html(html, "password")

        assert f'data-content-hash="{expected_hash}"' in result

    def test_hash_removed_after_decryption(self):
        """Test that content hash is removed during decryption."""
        html = "<lockhtml-encrypt>Secret content</lockhtml-encrypt>"

        encrypted = lock_html(html, "password")
        assert "data-content-hash=" in encrypted

        decrypted = unlock_html(encrypted, "password")
        assert "data-content-hash=" not in decrypted

    def test_hash_preserved_through_roundtrip(self):
        """Test content matches after encrypt/decrypt roundtrip."""
        original_content = "<p>Complex <strong>HTML</strong> content</p>"
        html = f"<lockhtml-encrypt>{original_content}</lockhtml-encrypt>"
        original_hash = content_hash(original_content)

        encrypted = lock_html(html, "password")

        # Verify hash is stored
        assert f'data-content-hash="{original_hash}"' in encrypted

        decrypted = unlock_html(encrypted, "password")

        # Verify content is restored
        assert original_content in decrypted

    def test_hash_with_unicode_content(self):
        """Test hash works with unicode content."""
        content = "日本語コンテンツ 🔐 αβγδ"
        html = f"<lockhtml-encrypt>{content}</lockhtml-encrypt>"
        expected_hash = content_hash(content)

        result = lock_html(html, "パスワード")

        assert f'data-content-hash="{expected_hash}"' in result

    def test_hash_with_empty_content(self):
        """Test hash works with empty content."""
        html = "<lockhtml-encrypt></lockhtml-encrypt>"
        expected_hash = content_hash("")

        result = lock_html(html, "password")

        assert f'data-content-hash="{expected_hash}"' in result

    def test_multiple_elements_have_correct_hashes(self):
        """Test multiple elements each get their own correct hash."""
        html = """
        <lockhtml-encrypt>First content</lockhtml-encrypt>
        <lockhtml-encrypt>Second content</lockhtml-encrypt>
        """
        hash1 = content_hash("First content")
        hash2 = content_hash("Second content")

        result = lock_html(html, "password")

        assert f'data-content-hash="{hash1}"' in result
        assert f'data-content-hash="{hash2}"' in result


class TestComposableEncryption:
    """Tests for composable/nested encryption (closure property)."""

    def test_encrypt_already_encrypted_element(self):
        """Test encrypting an already-encrypted element creates nested encryption."""
        html = "<lockhtml-encrypt>Secret</lockhtml-encrypt>"

        # First encryption
        encrypted1 = lock_html(html, "password1")
        assert "data-encrypted=" in encrypted1

        # Second encryption (re-encrypt)
        encrypted2 = lock_html(encrypted1, "password2")

        # Should have new encryption (not skipped)
        soup1 = BeautifulSoup(encrypted1, "html.parser")
        soup2 = BeautifulSoup(encrypted2, "html.parser")

        data1 = soup1.find("lockhtml-encrypt")["data-encrypted"]
        data2 = soup2.find("lockhtml-encrypt")["data-encrypted"]

        # Content should be different (re-encrypted with new password)
        assert data1 != data2

    def test_nested_encryption_via_wrapping(self):
        """Test nested encryption by wrapping encrypted element in new wrapper."""
        html = """<!DOCTYPE html>
<html><head><title>Test</title></head><body>
<lockhtml-encrypt>Secret</lockhtml-encrypt>
</body></html>"""

        # First encrypt with inner password
        encrypted1 = lock_html(html, "inner")
        assert "data-encrypted=" in encrypted1
        assert "Secret" not in encrypted1

        # Wrap the encrypted element in a new lockhtml-encrypt
        wrapped = mark_elements(encrypted1, ["lockhtml-encrypt"])

        # Encrypt outer wrapper with different password
        encrypted2 = lock_html(wrapped, "outer")

        # Should have 2 encrypted elements (outer wrapping inner)
        soup = BeautifulSoup(encrypted2, "html.parser")
        encrypted_elements = soup.find_all("lockhtml-encrypt")
        outer = encrypted_elements[0]
        assert outer.has_attr("data-encrypted")

        # Decrypt outer layer
        decrypted1 = unlock_html(encrypted2, "outer")
        # Should still have inner encryption
        assert "data-encrypted=" in decrypted1
        assert "Secret" not in decrypted1

        # Decrypt inner layer
        decrypted2 = unlock_html(decrypted1, "inner")
        assert "Secret" in decrypted2

    def test_reencrypt_replaces_ciphertext(self):
        """Test re-encrypting the same element replaces (not nests) the ciphertext."""
        html = "<lockhtml-encrypt>Secret</lockhtml-encrypt>"

        encrypted1 = lock_html(html, "password1")
        encrypted2 = lock_html(encrypted1, "password2")

        # Only one encrypted element (replaced, not nested)
        soup = BeautifulSoup(encrypted2, "html.parser")
        elements = soup.find_all("lockhtml-encrypt")
        assert len(elements) == 1

        # The ciphertext should be different from the first encryption
        soup1 = BeautifulSoup(encrypted1, "html.parser")
        data1 = soup1.find("lockhtml-encrypt")["data-encrypted"]
        data2 = elements[0]["data-encrypted"]
        assert data1 != data2

    def test_wrap_existing_lockhtml_element(self):
        """Test wrapping an existing lockhtml-encrypt element for nested encryption."""
        html = '<lockhtml-encrypt data-encrypted="xyz"></lockhtml-encrypt>'

        result = mark_elements(html, ["lockhtml-encrypt"])

        # Should be wrapped in another lockhtml-encrypt
        assert result.count("<lockhtml-encrypt") == 2

    def test_multi_password_workflow(self):
        """Test encrypting different elements with different passwords."""
        html = """<html><body>
            <div id="admin">Admin content</div>
            <div id="member">Member content</div>
        </body></html>"""

        # First pass: encrypt admin section
        wrapped1 = mark_elements(html, ["#admin"])
        encrypted1 = lock_html(wrapped1, "admin-password")

        # Second pass: encrypt member section with different password
        wrapped2 = mark_elements(encrypted1, ["#member"])
        encrypted2 = lock_html(wrapped2, "member-password")

        # Both sections should be encrypted
        assert encrypted2.count("data-encrypted=") == 2
        assert "Admin content" not in encrypted2
        assert "Member content" not in encrypted2


class TestPerElementTitle:
    """Tests for per-element title attribute."""

    def test_title_attribute_preserved(self):
        """Test title attribute is preserved during encryption."""
        html = '<lockhtml-encrypt title="Admin Panel">Secret</lockhtml-encrypt>'

        result = lock_html(html, "password")

        assert 'data-title="Admin Panel"' in result

    def test_title_in_wrapped_element(self):
        """Test title added during wrapping."""
        html = '<div id="secret">Content</div>'

        result = mark_elements(html, ["#secret"], title="Secret Section")

        assert 'title="Secret Section"' in result

    def test_title_preserved_through_roundtrip(self):
        """Test title survives encrypt/decrypt cycle."""
        html = '<lockhtml-encrypt title="My Title">Secret</lockhtml-encrypt>'

        encrypted = lock_html(html, "password")
        assert 'data-title="My Title"' in encrypted

        decrypted = unlock_html(encrypted, "password")
        assert 'title="My Title"' in decrypted

    def test_title_appears_in_js_runtime(self):
        """Test JS runtime uses per-element title."""
        html = '<lockhtml-encrypt title="Custom Title">Secret</lockhtml-encrypt>'

        result = lock_html(html, "password")

        # JS should read data-title attribute
        assert "this.getAttribute('data-title')" in result


class TestMarkBody:
    """Tests for mark_body function."""

    def test_wraps_body_content(self):
        """Test basic HTML with body content gets wrapped in lockhtml-encrypt."""
        html = "<html><head><title>Test</title></head><body><p>Hello</p></body></html>"

        result = mark_body(html)

        soup = BeautifulSoup(result, "html.parser")
        wrapper = soup.find("lockhtml-encrypt")
        assert wrapper is not None
        assert "Hello" in str(wrapper)

    def test_preserves_head(self):
        """Test head section is NOT wrapped."""
        html = (
            "<html><head><title>My Title</title></head>"
            "<body><p>Body content</p></body></html>"
        )

        result = mark_body(html)

        soup = BeautifulSoup(result, "html.parser")
        head = soup.find("head")
        assert head is not None
        # Head should not be inside lockhtml-encrypt
        assert head.find_parent("lockhtml-encrypt") is None
        assert "My Title" in str(head)

    def test_single_wrapper(self):
        """Test only one lockhtml-encrypt element is created."""
        html = "<html><head></head><body><p>One</p><p>Two</p><p>Three</p></body></html>"

        result = mark_body(html)

        assert result.count("<lockhtml-encrypt>") == 1

    def test_no_body_returns_unchanged(self):
        """Test HTML without body tag returns unchanged."""
        html = "<html><head><title>Test</title></head></html>"

        result = mark_body(html)

        assert "<lockhtml-encrypt>" not in result

    def test_empty_body_returns_unchanged(self):
        """Test HTML with empty body returns unchanged."""
        html = "<html><head></head><body></body></html>"

        result = mark_body(html)

        assert "<lockhtml-encrypt>" not in result

    def test_whitespace_only_body_returns_unchanged(self):
        """Test body with only whitespace returns unchanged."""
        html = "<html><head></head><body>   \n\t  </body></html>"

        result = mark_body(html)

        assert "<lockhtml-encrypt>" not in result

    def test_hint_attribute(self):
        """Test hint parameter adds attribute to wrapper."""
        html = "<html><head></head><body><p>Content</p></body></html>"

        result = mark_body(html, hint="My hint")

        assert 'hint="My hint"' in result

    def test_title_attribute(self):
        """Test title parameter adds attribute to wrapper."""
        html = "<html><head></head><body><p>Content</p></body></html>"

        result = mark_body(html, title="My title")

        assert 'title="My title"' in result

    def test_remember_attribute(self):
        """Test remember parameter adds attribute to wrapper."""
        html = "<html><head></head><body><p>Content</p></body></html>"

        result = mark_body(html, remember="local")

        assert 'remember="local"' in result

    def test_all_attributes(self):
        """Test all three attributes together."""
        html = "<html><head></head><body><p>Content</p></body></html>"

        result = mark_body(html, hint="The hint", title="The title", remember="session")

        assert 'hint="The hint"' in result
        assert 'title="The title"' in result
        assert 'remember="session"' in result


class TestMultiUserEncryptDecrypt:
    """Tests for multi-user encryption and decryption."""

    def test_encrypt_with_users_sets_data_mode(self):
        """Test lock_html with users param sets data-mode='user' attribute."""
        html = "<lockhtml-encrypt>Secret</lockhtml-encrypt>"

        result = lock_html(html, users={"alice": "pw-a", "bob": "pw-b"})

        assert 'data-mode="user"' in result

    def test_decrypt_with_username(self):
        """Test encrypt with users, decrypt with username param works."""
        html = "<lockhtml-encrypt>Secret for users</lockhtml-encrypt>"

        encrypted = lock_html(html, users={"alice": "pw-a"})
        decrypted = unlock_html(encrypted, "pw-a", username="alice")

        assert "Secret for users" in decrypted

    def test_roundtrip_multiuser(self):
        """Test full encrypt/decrypt roundtrip with users."""
        html = """<!DOCTYPE html>
<html>
<head><title>Multi-user Test</title></head>
<body>
<lockhtml-encrypt>Multi-user secret content</lockhtml-encrypt>
</body>
</html>"""

        encrypted = lock_html(html, users={"alice": "pw-a", "bob": "pw-b"})

        # Both users should be able to decrypt
        decrypted_alice = unlock_html(encrypted, "pw-a", username="alice")
        assert "Multi-user secret content" in decrypted_alice

        decrypted_bob = unlock_html(encrypted, "pw-b", username="bob")
        assert "Multi-user secret content" in decrypted_bob

    def test_multiuser_js_runtime_has_username_field(self):
        """Test encrypted HTML JS contains usernamePlaceholder."""
        html = """<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<lockhtml-encrypt>Secret</lockhtml-encrypt>
</body>
</html>"""

        result = lock_html(html, users={"alice": "pw-a"})

        assert "usernamePlaceholder" in result

    def test_data_mode_removed_on_decrypt(self):
        """Test data-mode attribute is removed after decryption."""
        html = "<lockhtml-encrypt>Secret</lockhtml-encrypt>"

        encrypted = lock_html(html, users={"alice": "pw-a"})
        assert 'data-mode="user"' in encrypted

        decrypted = unlock_html(encrypted, "pw-a", username="alice")
        assert "data-mode" not in decrypted


class TestSyncHtmlKeys:
    """Tests for sync_html_keys function."""

    def test_sync_adds_user(self):
        """Test encrypt with users, sync to add bob, verify bob can decrypt."""
        from lockhtml.crypto import decrypt as crypto_decrypt

        html = "<lockhtml-encrypt>Sync secret</lockhtml-encrypt>"

        # Encrypt with alice only
        encrypted = lock_html(html, users={"alice": "pw-a"})

        # Sync to add bob
        result = sync_html_keys(
            encrypted,
            old_users={"alice": "pw-a"},
            new_users={"alice": "pw-a", "bob": "pw-b"},
        )

        # Verify bob can decrypt the element's data-encrypted attribute
        soup = BeautifulSoup(result, "html.parser")
        elem = soup.find("lockhtml-encrypt")
        encrypted_data = elem["data-encrypted"]
        content, _meta = crypto_decrypt(encrypted_data, "pw-b", username="bob")
        assert content == "Sync secret"

    def test_sync_removes_user(self):
        """Test sync to remove bob, verify bob cannot decrypt."""
        from lockhtml.crypto import decrypt as crypto_decrypt

        html = "<lockhtml-encrypt>Remove user secret</lockhtml-encrypt>"

        # Encrypt with alice and bob
        encrypted = lock_html(html, users={"alice": "pw-a", "bob": "pw-b"})

        # Sync to remove bob
        result = sync_html_keys(
            encrypted,
            old_users={"alice": "pw-a"},
            new_users={"alice": "pw-a"},
        )

        # Verify alice can still decrypt
        soup = BeautifulSoup(result, "html.parser")
        elem = soup.find("lockhtml-encrypt")
        encrypted_data = elem["data-encrypted"]
        content, _meta = crypto_decrypt(encrypted_data, "pw-a", username="alice")
        assert content == "Remove user secret"

        # Verify bob cannot decrypt
        with pytest.raises(LockhtmlError):
            crypto_decrypt(encrypted_data, "pw-b", username="bob")

    def test_sync_rekey(self):
        """Test sync with rekey=True changes data-encrypted."""
        from lockhtml.crypto import decrypt as crypto_decrypt

        html = "<lockhtml-encrypt>Rekey secret</lockhtml-encrypt>"

        # Encrypt with alice
        encrypted = lock_html(html, users={"alice": "pw-a"})

        # Capture original data-encrypted value
        soup_orig = BeautifulSoup(encrypted, "html.parser")
        original_data = soup_orig.find("lockhtml-encrypt")["data-encrypted"]

        # Sync with rekey
        result = sync_html_keys(
            encrypted,
            old_users={"alice": "pw-a"},
            new_users={"alice": "pw-a"},
            rekey=True,
        )

        # Verify data-encrypted value changed (new CEK)
        soup_new = BeautifulSoup(result, "html.parser")
        new_data = soup_new.find("lockhtml-encrypt")["data-encrypted"]
        assert new_data != original_data

        # Verify alice can still decrypt
        content, _meta = crypto_decrypt(new_data, "pw-a", username="alice")
        assert content == "Rekey secret"

    def test_sync_sets_data_mode(self):
        """Test sync to multi-user sets data-mode='user'."""
        html = "<lockhtml-encrypt>Mode secret</lockhtml-encrypt>"

        # Encrypt with single password
        encrypted = lock_html(html, password="single-pw")

        # Sync to multi-user
        result = sync_html_keys(
            encrypted,
            old_password="single-pw",
            new_users={"alice": "pw-a", "bob": "pw-b"},
        )

        assert 'data-mode="user"' in result

    def test_sync_no_encrypted_elements_returns_unchanged(self):
        """Test HTML without encrypted elements returns unchanged."""
        html = "<html><body>Normal content</body></html>"

        result = sync_html_keys(
            html,
            old_password="pw",
            new_password="new-pw",
        )

        assert result == html


class TestAutoMetadata:
    """Tests for auto-populated metadata during encryption."""

    def test_meta_auto_populated(self):
        """Test lock_html auto-populates meta with encrypted_at and version."""
        from lockhtml.crypto import decrypt as crypto_decrypt

        html = "<lockhtml-encrypt>Meta test</lockhtml-encrypt>"

        result = lock_html(html, "password")

        # Extract encrypted data and decrypt to inspect meta
        soup = BeautifulSoup(result, "html.parser")
        elem = soup.find("lockhtml-encrypt")
        encrypted_data = elem["data-encrypted"]
        content, meta = crypto_decrypt(encrypted_data, "password")

        assert content == "Meta test"
        assert meta is not None
        assert "encrypted_at" in meta
        assert "version" in meta

    def test_content_hash_unaffected_by_meta(self):
        """Test content hash is computed on inner HTML, not on meta."""
        html = "<lockhtml-encrypt>Hash test content</lockhtml-encrypt>"
        expected_hash = content_hash("Hash test content")

        result = lock_html(html, "password")

        # The content hash should match the inner HTML hash, not be affected by meta
        assert f'data-content-hash="{expected_hash}"' in result


class TestBackwardCompat:
    """Tests for backward compatibility of old function name aliases."""

    def test_encrypt_html_alias_works(self):
        """Test that the old encrypt_html alias still works."""
        from lockhtml.parser import encrypt_html

        html = "<lockhtml-encrypt>Backward compat test</lockhtml-encrypt>"

        result = encrypt_html(html, "password")

        assert "data-encrypted=" in result
        assert "Backward compat test" not in result

    def test_decrypt_html_alias_works(self):
        """Test that the old decrypt_html alias still works."""
        from lockhtml.parser import decrypt_html, encrypt_html

        html = "<lockhtml-encrypt>Alias roundtrip</lockhtml-encrypt>"

        encrypted = encrypt_html(html, "password")
        decrypted = decrypt_html(encrypted, "password")

        assert "Alias roundtrip" in decrypted

    def test_wrap_elements_alias_works(self):
        """Test that the old wrap_elements_for_encryption alias still works."""
        from lockhtml.parser import wrap_elements_for_encryption

        html = '<html><body><div id="secret">Secret</div></body></html>'

        result = wrap_elements_for_encryption(html, ["#secret"])

        assert "<lockhtml-encrypt>" in result

    def test_wrap_body_alias_works(self):
        """Test that the old wrap_body_for_encryption alias still works."""
        from lockhtml.parser import wrap_body_for_encryption

        html = "<html><head></head><body><p>Content</p></body></html>"

        result = wrap_body_for_encryption(html)

        assert "<lockhtml-encrypt>" in result
