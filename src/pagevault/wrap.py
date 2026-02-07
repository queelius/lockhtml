"""Universal encrypted payload generation for pagevault.

Wraps arbitrary files and directories into self-contained encrypted HTML
that can be decrypted and rendered in the browser.
"""

import base64
import mimetypes
import zipfile
from io import BytesIO
from pathlib import Path

from .config import PagevaultConfig
from .crypto import PagevaultError, content_hash, encrypt

# MIME type detection
MIME_OVERRIDES = {
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
}

# Rendering categories
IMAGE_MIMES = {"image/png", "image/jpeg", "image/gif", "image/svg+xml", "image/webp"}
PDF_MIMES = {"application/pdf"}
MARKDOWN_MIMES = {"text/markdown"}
HTML_MIMES = {"text/html"}
TEXT_MIMES = {
    "text/plain",
    "text/css",
    "text/javascript",
    "application/json",
    "application/xml",
    "text/xml",
    "text/csv",
}


def detect_mime(path: Path) -> str:
    """Detect MIME type of a file.

    Args:
        path: Path to the file.

    Returns:
        MIME type string.
    """
    suffix = path.suffix.lower()
    if suffix in MIME_OVERRIDES:
        return MIME_OVERRIDES[suffix]

    mime, _ = mimetypes.guess_type(str(path))
    return mime or "application/octet-stream"


def wrap_file(
    file_path: Path,
    password: str | None = None,
    config: PagevaultConfig | None = None,
    output_path: Path | None = None,
    users: dict[str, str] | None = None,
) -> Path:
    """Wrap a single file into a self-contained encrypted HTML.

    Args:
        file_path: Path to the file to wrap.
        password: Encryption password.
        config: Optional configuration.
        output_path: Output HTML path. Defaults to <filename>.html.
        users: Dict of {username: password} for multi-user.

    Returns:
        Path to the generated HTML file.

    Raises:
        PagevaultError: If file cannot be read or encryption fails.
    """
    file_path = Path(file_path)
    if not file_path.is_file():
        raise PagevaultError(f"File not found: {file_path}")

    # Read file bytes
    try:
        file_bytes = file_path.read_bytes()
    except OSError as e:
        raise PagevaultError(f"Cannot read file {file_path}: {e}") from e

    # Detect MIME type
    mime = detect_mime(file_path)

    # Base64-encode file content
    b64_data = base64.b64encode(file_bytes).decode("ascii")

    # Build metadata
    meta = {
        "type": "file",
        "filename": file_path.name,
        "mime": mime,
        "size": len(file_bytes),
    }

    # Get salt from config
    salt = config.salt if config else None

    # Encrypt: the plaintext is the base64-encoded file data
    encrypted_payload = encrypt(
        b64_data,
        password=password,
        salt=salt,
        users=users,
        meta=meta,
    )

    # Compute content hash for integrity
    hash_value = content_hash(b64_data)

    # Determine output path
    if output_path is None:
        output_path = file_path.with_suffix(".html")

    # Generate HTML
    html = _generate_wrap_html(
        encrypted_payload=encrypted_payload,
        content_hash=hash_value,
        wrap_type="file",
        filename=file_path.name,
        title=f"Protected: {file_path.name}",
        config=config,
        users=users,
        include_marked=(mime in MARKDOWN_MIMES),
    )

    # Write output
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_path.write_text(html, encoding="utf-8")
    except OSError as e:
        raise PagevaultError(f"Cannot write output {output_path}: {e}") from e

    return output_path


def wrap_site(
    dir_path: Path,
    password: str | None = None,
    config: PagevaultConfig | None = None,
    output_path: Path | None = None,
    users: dict[str, str] | None = None,
    entry: str = "index.html",
) -> Path:
    """Wrap a directory into a self-contained encrypted HTML.

    Args:
        dir_path: Path to the directory to wrap.
        password: Encryption password.
        config: Optional configuration.
        output_path: Output HTML path. Defaults to <dirname>.html.
        users: Dict of {username: password} for multi-user.
        entry: Entry point HTML file within the directory.

    Returns:
        Path to the generated HTML file.

    Raises:
        PagevaultError: If directory cannot be read or encryption fails.
    """
    dir_path = Path(dir_path)
    if not dir_path.is_dir():
        raise PagevaultError(f"Directory not found: {dir_path}")

    # Zip the directory
    zip_buffer = BytesIO()
    file_list = []

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(dir_path.rglob("*")):
            if file_path.is_file():
                rel = file_path.relative_to(dir_path)
                rel_str = str(rel).replace("\\", "/")  # Normalize to forward slashes
                file_list.append(rel_str)
                zf.write(file_path, rel_str)

    if not file_list:
        raise PagevaultError(f"Directory is empty: {dir_path}")

    # Verify entry point exists
    if entry not in file_list:
        raise PagevaultError(
            f"Entry point '{entry}' not found in directory. "
            f"Available files: {', '.join(file_list[:10])}"
        )

    # Base64-encode the zip
    zip_bytes = zip_buffer.getvalue()
    b64_data = base64.b64encode(zip_bytes).decode("ascii")

    # Build metadata
    meta = {
        "type": "site",
        "entry": entry,
        "files": file_list,
    }

    # Get salt from config
    salt = config.salt if config else None

    # Encrypt
    encrypted_payload = encrypt(
        b64_data,
        password=password,
        salt=salt,
        users=users,
        meta=meta,
    )

    # Compute content hash
    hash_value = content_hash(b64_data)

    # Determine output path
    if output_path is None:
        output_path = dir_path.parent / f"{dir_path.name}.html"

    # Generate HTML
    html = _generate_wrap_html(
        encrypted_payload=encrypted_payload,
        content_hash=hash_value,
        wrap_type="site",
        filename=dir_path.name,
        title=f"Protected: {dir_path.name}",
        entry=entry,
        config=config,
        users=users,
        include_jszip=True,
    )

    # Write output
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_path.write_text(html, encoding="utf-8")
    except OSError as e:
        raise PagevaultError(f"Cannot write output {output_path}: {e}") from e

    return output_path


def _generate_wrap_html(
    encrypted_payload: str,
    content_hash: str,
    wrap_type: str,
    filename: str,
    title: str,
    entry: str | None = None,
    config: PagevaultConfig | None = None,
    users: dict[str, str] | None = None,
    include_jszip: bool = False,
    include_marked: bool = False,
) -> str:
    """Generate self-contained HTML with encrypted payload.

    Args:
        encrypted_payload: Base64 encrypted data.
        content_hash: SHA-256 content hash.
        wrap_type: "file" or "site".
        filename: Original filename or directory name.
        title: HTML page title.
        entry: Entry point for site mode.
        config: Optional configuration.
        users: Multi-user dict (affects data-mode attribute).
        include_jszip: Whether to include JSZip library.

    Returns:
        Complete HTML string.
    """
    from .config import TemplateConfig

    template = config.template if config else TemplateConfig()

    # Build data attributes
    attrs = [
        f'data-encrypted="{encrypted_payload}"',
        f'data-content-hash="{content_hash}"',
        f'data-wrap-type="{wrap_type}"',
        f'data-filename="{_html_escape(filename)}"',
    ]
    if entry:
        attrs.append(f'data-entry="{_html_escape(entry)}"')
    if users:
        attrs.append('data-mode="user"')

    attrs_str = "\n    ".join(attrs)

    # Get CSS and JS
    css = _get_wrap_css(template)
    crypto_js = _get_crypto_js()
    renderer_js = _get_renderer_js()

    jszip_block = ""
    site_js = ""
    if include_jszip:
        jszip_block = f"\n<script data-pagevault-runtime>{_get_jszip_shim()}</script>"
        site_js = _get_site_renderer_js()

    marked_block = ""
    if include_marked:
        marked_block = f"\n<script data-pagevault-runtime>{_get_marked_js()}</script>"

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{_html_escape(title)}</title>
  <style data-pagevault-runtime>{css}</style>
</head>
<body>
  <pagevault
    {attrs_str}>
  </pagevault>{jszip_block}{marked_block}
  <script data-pagevault-runtime>
{crypto_js}

{renderer_js}

{site_js}
  </script>
</body>
</html>"""


def _html_escape(s: str) -> str:
    """Escape a string for HTML attribute values."""
    return (
        s.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _get_marked_js() -> str:
    """Load vendored marked.js for markdown rendering.

    Returns:
        Contents of marked.min.js.
    """
    vendor_path = Path(__file__).parent / "vendor" / "marked.min.js"
    return vendor_path.read_text(encoding="utf-8")


def _get_wrap_css(template) -> str:
    """Generate CSS for the wrap password prompt."""
    return f"""
/* pagevault wrap styles */
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}

pagevault {{
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
}}

pagevault[data-decrypted] {{
  display: block;
  min-height: auto;
}}

.pagevault-container {{
  text-align: center;
  padding: 2rem;
  border: 2px dashed #ccc;
  border-radius: 8px;
  background: #f9f9f9;
  max-width: 400px;
  margin: 2rem auto;
}}

.pagevault-icon {{ font-size: 3rem; margin-bottom: 1rem; }}
.pagevault-title {{ font-size: 1.25rem; font-weight: 600; margin-bottom: 0.5rem; color: #333; }}
.pagevault-hint {{ color: #666; font-size: 0.9rem; margin-bottom: 1rem; }}
.pagevault-filename {{ color: #999; font-size: 0.8rem; margin-bottom: 1rem; font-family: monospace; }}

.pagevault-form {{
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}}

.pagevault-input {{
  padding: 0.75rem 1rem;
  border: 1px solid #ccc;
  border-radius: 4px;
  font-size: 1rem;
  outline: none;
  transition: border-color 0.2s;
}}
.pagevault-input:focus {{ border-color: {template.color_primary}; }}

.pagevault-button {{
  padding: 0.75rem 1rem;
  background: linear-gradient(135deg, {template.color_primary}, {template.color_secondary});
  color: white;
  border: none;
  border-radius: 4px;
  font-size: 1rem;
  cursor: pointer;
  transition: opacity 0.2s;
}}
.pagevault-button:hover {{ opacity: 0.9; }}
.pagevault-button:disabled {{ opacity: 0.5; cursor: not-allowed; }}
.pagevault-error {{ color: #dc3545; font-size: 0.9rem; margin-top: 0.5rem; }}

/* Toolbar */
.pagevault-toolbar {{
  position: sticky;
  top: 0;
  z-index: 100;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.5rem 1rem;
  background: #f8f8f8;
  border-bottom: 1px solid #ddd;
  font-size: 0.85rem;
}}
.toolbar-filename {{
  font-family: 'Consolas', 'Monaco', monospace;
  font-weight: 600;
  color: #333;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}
.toolbar-size {{ color: #888; white-space: nowrap; }}
.toolbar-btn {{
  margin-left: auto;
  padding: 0.3rem 0.75rem;
  background: {template.color_primary};
  color: white;
  text-decoration: none;
  border: none;
  border-radius: 3px;
  font-size: 0.8rem;
  cursor: pointer;
  white-space: nowrap;
}}
.toolbar-btn:hover {{ opacity: 0.85; }}
.toolbar-btn.active {{ background: #555; }}
.toolbar-toggle {{ margin-left: 0; }}

/* Viewer base */
.pagevault-viewer {{ width: 100%; }}
.pagevault-viewer iframe {{ width: 100%; height: calc(100vh - 40px); border: none; }}
.pagevault-viewer pre {{
  margin: 0;
  white-space: pre-wrap;
  word-wrap: break-word;
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 0.9rem;
  line-height: 1.6;
}}

/* Image viewer */
.pagevault-image-viewer {{
  display: flex;
  justify-content: center;
  align-items: flex-start;
  min-height: calc(100vh - 40px);
  background: #f0f0f0;
  padding: 1rem;
  overflow: auto;
}}
.pagevault-image-viewer img {{
  max-width: 100%;
  max-height: calc(100vh - 72px);
  height: auto;
  display: block;
  cursor: zoom-in;
  object-fit: contain;
}}
.pagevault-image-viewer img.zoomed {{
  max-width: none;
  max-height: none;
  cursor: zoom-out;
}}

/* Text viewer with line numbers */
.pagevault-text-viewer {{
  display: flex;
  min-height: calc(100vh - 40px);
  background: #f5f5f5;
}}
.pagevault-text-viewer .line-numbers {{
  padding: 1rem 0.75rem 1rem 1rem;
  text-align: right;
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 0.9rem;
  line-height: 1.6;
  color: #999;
  user-select: none;
  -webkit-user-select: none;
  border-right: 1px solid #ddd;
  background: #eee;
}}
.pagevault-text-viewer pre {{
  flex: 1;
  padding: 1rem;
  overflow-x: auto;
}}

/* Markdown rendered view */
.markdown-body {{
  max-width: 800px;
  margin: 0 auto;
  padding: 2rem;
  line-height: 1.7;
  color: #24292e;
}}
.markdown-body h1, .markdown-body h2, .markdown-body h3,
.markdown-body h4, .markdown-body h5, .markdown-body h6 {{
  margin-top: 1.5em;
  margin-bottom: 0.5em;
  font-weight: 600;
  line-height: 1.25;
}}
.markdown-body h1 {{ font-size: 2em; padding-bottom: 0.3em; border-bottom: 1px solid #eee; }}
.markdown-body h2 {{ font-size: 1.5em; padding-bottom: 0.3em; border-bottom: 1px solid #eee; }}
.markdown-body h3 {{ font-size: 1.25em; }}
.markdown-body a {{ color: {template.color_primary}; text-decoration: none; }}
.markdown-body a:hover {{ text-decoration: underline; }}
.markdown-body table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
.markdown-body th, .markdown-body td {{ border: 1px solid #ddd; padding: 0.5em 0.75em; text-align: left; }}
.markdown-body th {{ background: #f6f8fa; font-weight: 600; }}
.markdown-body code {{
  padding: 0.2em 0.4em;
  background: #f0f0f0;
  border-radius: 3px;
  font-size: 0.85em;
  font-family: 'Consolas', 'Monaco', monospace;
}}
.markdown-body pre {{
  padding: 1em;
  background: #f6f8fa;
  border-radius: 4px;
  overflow-x: auto;
}}
.markdown-body pre code {{ padding: 0; background: none; font-size: 0.9em; }}
.markdown-body blockquote {{
  margin: 1em 0;
  padding: 0.5em 1em;
  border-left: 4px solid #ddd;
  color: #666;
}}
.markdown-body hr {{ border: none; border-top: 1px solid #ddd; margin: 1.5em 0; }}
.markdown-body ul, .markdown-body ol {{ padding-left: 2em; margin: 0.5em 0; }}
.markdown-body li {{ margin: 0.25em 0; }}
.markdown-body img {{ max-width: 100%; height: auto; }}
.markdown-body p {{ margin: 0.75em 0; }}

/* Markdown source toggle */
.markdown-source {{ max-width: 800px; margin: 0 auto; padding: 0; }}
.markdown-source pre {{
  padding: 2rem;
  background: #f5f5f5;
  min-height: calc(100vh - 40px);
}}

/* Download view */
.pagevault-download {{
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 50vh;
  gap: 1rem;
}}
.pagevault-download a {{
  display: inline-block;
  padding: 1rem 2rem;
  background: {template.color_primary};
  color: white;
  text-decoration: none;
  border-radius: 4px;
  font-size: 1.1rem;
}}
.pagevault-download a:hover {{ opacity: 0.9; }}
.pagevault-download .file-info {{ color: #666; font-size: 0.9rem; }}

/* Site viewer */
.pagevault-site-frame {{ width: 100%; height: 100vh; border: none; }}
"""


def _get_crypto_js() -> str:
    """Generate the shared crypto JS for wrap payloads."""
    return """
// pagevault wrap crypto runtime
(function() {
  'use strict';

  async function computeHash(content) {
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = new Uint8Array(hashBuffer).slice(0, 16);
    return Array.from(hashArray, b => b.toString(16).padStart(2, '0')).join('');
  }

  async function deriveKey(secret, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', encoder.encode(secret), 'PBKDF2', false, ['deriveBits', 'deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: 310000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  }

  async function decryptPayload(encryptedBase64, password, username) {
    try {
      const jsonStr = atob(encryptedBase64);
      const data = JSON.parse(jsonStr);
      if (data.v !== 2) throw new Error('Unsupported version: ' + data.v);

      const salt = Uint8Array.from(atob(data.salt), c => c.charCodeAt(0));
      const iv = Uint8Array.from(atob(data.iv), c => c.charCodeAt(0));
      const ct = Uint8Array.from(atob(data.ct), c => c.charCodeAt(0));

      const secret = username ? username + ':' + password : password;
      const wrappingKey = await deriveKey(secret, salt);

      let cek = null;
      for (const keyBlob of data.keys) {
        const blobIv = Uint8Array.from(atob(keyBlob.iv), c => c.charCodeAt(0));
        const blobCt = Uint8Array.from(atob(keyBlob.ct), c => c.charCodeAt(0));
        try {
          cek = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: blobIv }, wrappingKey, blobCt
          );
          break;
        } catch (e) { continue; }
      }
      if (!cek) throw new Error('No matching key found');

      const cekKey = await crypto.subtle.importKey(
        'raw', cek, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
      );
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv }, cekKey, ct
      );
      const inner = JSON.parse(new TextDecoder().decode(decrypted));
      return { content: inner.c, meta: inner.m || null };
    } catch (e) {
      console.error('Decryption failed:', e);
      return null;
    }
  }

  // Expose globally for renderer
  window.__pagevault = { decryptPayload, computeHash };
})();"""


def _get_renderer_js() -> str:
    """Generate the file renderer JS."""
    return """
// pagevault wrap renderer
(function() {
  'use strict';

  const el = document.querySelector('pagevault[data-encrypted]');
  if (!el) return;

  const isUserMode = el.getAttribute('data-mode') === 'user';
  const filename = el.getAttribute('data-filename') || 'file';
  const wrapType = el.getAttribute('data-wrap-type') || 'file';

  // Render password prompt
  el.innerHTML = `
    <div class="pagevault-container">
      <div class="pagevault-icon">🔒</div>
      <div class="pagevault-title">Protected Content</div>
      <div class="pagevault-filename">${escapeHtml(filename)}</div>
      <form class="pagevault-form">
        ${isUserMode ? '<input type="text" class="pagevault-input" placeholder="Username" autocomplete="username">' : ''}
        <input type="password" class="pagevault-input pagevault-password" placeholder="Password" autocomplete="current-password">
        <button type="submit" class="pagevault-button">Decrypt</button>
        <div class="pagevault-error" style="display: none;"></div>
      </form>
    </div>
  `;

  const form = el.querySelector('form');
  const pwdInput = el.querySelector('.pagevault-password');
  const userInput = el.querySelector('input[placeholder="Username"]');
  const errorDiv = el.querySelector('.pagevault-error');
  const button = el.querySelector('button');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = pwdInput.value;
    if (!password) return;
    const username = userInput ? userInput.value : null;

    button.disabled = true;
    button.textContent = 'Decrypting...';

    const encrypted = el.getAttribute('data-encrypted');
    const expectedHash = el.getAttribute('data-content-hash');

    const result = await window.__pagevault.decryptPayload(encrypted, password, username);
    if (!result) {
      errorDiv.textContent = 'Wrong password';
      errorDiv.style.display = 'block';
      button.disabled = false;
      button.textContent = 'Decrypt';
      pwdInput.value = '';
      pwdInput.focus();
      return;
    }

    // Verify hash
    if (expectedHash) {
      const actualHash = await window.__pagevault.computeHash(result.content);
      if (actualHash !== expectedHash) {
        errorDiv.textContent = 'Content integrity check failed';
        errorDiv.style.display = 'block';
        button.disabled = false;
        button.textContent = 'Decrypt';
        return;
      }
    }

    // Decode base64 content to binary
    const binaryStr = atob(result.content);
    const bytes = new Uint8Array(binaryStr.length);
    for (let i = 0; i < binaryStr.length; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }

    const meta = result.meta || {};
    el.setAttribute('data-decrypted', 'true');
    el.removeAttribute('data-encrypted');

    if (wrapType === 'site' && window.__pagevault_renderSite) {
      window.__pagevault_renderSite(el, bytes, meta);
    } else {
      renderFile(el, bytes, meta);
    }
  });

  setTimeout(() => pwdInput.focus(), 100);

  function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }

  function createToolbar(fname, size, downloadUrl) {
    const toolbar = document.createElement('div');
    toolbar.className = 'pagevault-toolbar';
    toolbar.innerHTML =
      '<span class="toolbar-filename">' + escapeHtml(fname) + '</span>' +
      '<span class="toolbar-size">' + formatSize(size) + '</span>' +
      '<a class="toolbar-btn" href="' + downloadUrl + '" download="' + escapeHtml(fname) + '">Download</a>';
    return toolbar;
  }

  function renderImageViewer(viewer, url, fname) {
    viewer.className = 'pagevault-viewer pagevault-image-viewer';
    const img = document.createElement('img');
    img.src = url;
    img.alt = fname;
    img.addEventListener('click', function() { img.classList.toggle('zoomed'); });
    viewer.appendChild(img);
  }

  function renderPdfViewer(viewer, url) {
    viewer.innerHTML = '<iframe src="' + url + '"></iframe>';
  }

  function renderMarkdownViewer(viewer, text, toolbar) {
    var rendered;
    if (typeof marked !== 'undefined' && marked.parse) {
      rendered = marked.parse(text);
    } else {
      rendered = simpleMarkdown(text);
    }

    var body = document.createElement('div');
    body.className = 'markdown-body';
    body.innerHTML = rendered;

    var source = document.createElement('div');
    source.className = 'markdown-source';
    source.style.display = 'none';
    var pre = document.createElement('pre');
    pre.textContent = text;
    source.appendChild(pre);

    viewer.appendChild(body);
    viewer.appendChild(source);

    // Add toggle button to toolbar
    var toggleBtn = document.createElement('button');
    toggleBtn.className = 'toolbar-btn toolbar-toggle';
    toggleBtn.textContent = 'Source';
    toggleBtn.addEventListener('click', function() {
      var showSource = body.style.display !== 'none';
      body.style.display = showSource ? 'none' : '';
      source.style.display = showSource ? '' : 'none';
      toggleBtn.textContent = showSource ? 'Rendered' : 'Source';
      toggleBtn.classList.toggle('active', showSource);
    });
    toolbar.appendChild(toggleBtn);
  }

  function renderTextViewer(viewer, text) {
    viewer.className = 'pagevault-viewer pagevault-text-viewer';
    var lines = text.split('\\n');
    var gutter = document.createElement('div');
    gutter.className = 'line-numbers';
    for (var i = 1; i <= lines.length; i++) {
      var num = document.createElement('div');
      num.textContent = i;
      gutter.appendChild(num);
    }
    var pre = document.createElement('pre');
    pre.textContent = text;
    viewer.appendChild(gutter);
    viewer.appendChild(pre);
  }

  function renderDownloadView(viewer, url, fname, size) {
    viewer.innerHTML =
      '<div class="pagevault-download">' +
        '<div class="pagevault-icon">📄</div>' +
        '<a href="' + url + '" download="' + escapeHtml(fname) + '">Download ' + escapeHtml(fname) + '</a>' +
        '<div class="file-info">' + formatSize(size) + '</div>' +
      '</div>';
  }

  function renderFile(container, bytes, meta) {
    const mime = meta.mime || 'application/octet-stream';
    const fname = meta.filename || 'download';
    const size = meta.size || bytes.length;
    const blob = new Blob([bytes], { type: mime });
    const url = URL.createObjectURL(blob);

    const toolbar = createToolbar(fname, size, url);
    const viewer = document.createElement('div');
    viewer.className = 'pagevault-viewer';

    if (mime.startsWith('image/')) {
      renderImageViewer(viewer, url, fname);
    } else if (mime === 'application/pdf') {
      renderPdfViewer(viewer, url);
    } else if (mime === 'text/html') {
      viewer.innerHTML = '<iframe src="' + url + '"></iframe>';
    } else if (mime === 'text/markdown') {
      const text = new TextDecoder().decode(bytes);
      renderMarkdownViewer(viewer, text, toolbar);
    } else if (mime.startsWith('text/') || mime === 'application/json' || mime === 'application/xml') {
      const text = new TextDecoder().decode(bytes);
      renderTextViewer(viewer, text);
    } else {
      renderDownloadView(viewer, url, fname, size);
    }

    container.innerHTML = '';
    container.appendChild(toolbar);
    container.appendChild(viewer);
  }

  function simpleMarkdown(text) {
    // Minimal markdown renderer — fallback when marked.js is not available
    let html = text
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/^### (.+)$/gm, '<h3>$1</h3>')
      .replace(/^## (.+)$/gm, '<h2>$1</h2>')
      .replace(/^# (.+)$/gm, '<h1>$1</h1>')
      .replace(/\\*\\*(.+?)\\*\\*/g, '<strong>$1</strong>')
      .replace(/\\*(.+?)\\*/g, '<em>$1</em>')
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/^- (.+)$/gm, '<li>$1</li>')
      .replace(/\\n\\n/g, '</p><p>');
    return '<p>' + html + '</p>';
  }
})();"""


def _get_jszip_shim() -> str:
    """Get a minimal JSZip-compatible implementation for site mode.

    This is a shim that uses the browser's built-in DecompressionStream API
    (available in modern browsers) to decompress zip files without a full
    JSZip library.
    """
    return """
// Minimal ZIP reader using native browser APIs
(function() {
  'use strict';

  class ZipReader {
    constructor(buffer) {
      this.buffer = buffer;
      this.view = new DataView(buffer);
      this.entries = [];
      this._parse();
    }

    _parse() {
      // Find end of central directory
      let eocdOffset = -1;
      for (let i = this.buffer.byteLength - 22; i >= 0; i--) {
        if (this.view.getUint32(i, true) === 0x06054b50) {
          eocdOffset = i;
          break;
        }
      }
      if (eocdOffset === -1) throw new Error('Invalid ZIP file');

      const cdOffset = this.view.getUint32(eocdOffset + 16, true);
      const cdCount = this.view.getUint16(eocdOffset + 10, true);

      let offset = cdOffset;
      for (let i = 0; i < cdCount; i++) {
        if (this.view.getUint32(offset, true) !== 0x02014b50) break;

        const compression = this.view.getUint16(offset + 10, true);
        const compSize = this.view.getUint32(offset + 20, true);
        const uncompSize = this.view.getUint32(offset + 24, true);
        const nameLen = this.view.getUint16(offset + 28, true);
        const extraLen = this.view.getUint16(offset + 30, true);
        const commentLen = this.view.getUint16(offset + 32, true);
        const localHeaderOffset = this.view.getUint32(offset + 42, true);

        const nameBytes = new Uint8Array(this.buffer, offset + 46, nameLen);
        const name = new TextDecoder().decode(nameBytes);

        this.entries.push({
          name, compression, compSize, uncompSize, localHeaderOffset
        });

        offset += 46 + nameLen + extraLen + commentLen;
      }
    }

    async getFile(name) {
      const entry = this.entries.find(e => e.name === name);
      if (!entry) return null;

      // Read local file header to find data offset
      const lh = entry.localHeaderOffset;
      const lhNameLen = this.view.getUint16(lh + 26, true);
      const lhExtraLen = this.view.getUint16(lh + 28, true);
      const dataOffset = lh + 30 + lhNameLen + lhExtraLen;

      const compressedData = new Uint8Array(this.buffer, dataOffset, entry.compSize);

      if (entry.compression === 0) {
        // Stored (no compression)
        return compressedData;
      } else if (entry.compression === 8) {
        // Deflate
        const ds = new DecompressionStream('deflate-raw');
        const writer = ds.writable.getWriter();
        const reader = ds.readable.getReader();

        writer.write(compressedData);
        writer.close();

        const chunks = [];
        let totalLen = 0;
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
          totalLen += value.length;
        }

        const result = new Uint8Array(totalLen);
        let off = 0;
        for (const chunk of chunks) {
          result.set(chunk, off);
          off += chunk.length;
        }
        return result;
      }

      throw new Error('Unsupported compression: ' + entry.compression);
    }

    getFileNames() {
      return this.entries.map(e => e.name).filter(n => !n.endsWith('/'));
    }
  }

  window.__pagevault_ZipReader = ZipReader;
})();"""


def _get_site_renderer_js() -> str:
    """Generate the site renderer JS for URL rewriting.

    Uses data URIs instead of blob URLs to avoid cross-origin issues when
    the wrapped HTML is opened from file:// (where blob:null origins are
    opaque and can't be shared between parent and iframe). Internal page
    navigation is handled via postMessage from an injected interceptor script.
    """
    return """
// pagevault site renderer
(function() {
  'use strict';

  function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  window.__pagevault_renderSite = async function(container, zipBytes, meta) {
    const entry = meta.entry || 'index.html';

    try {
      const zip = new window.__pagevault_ZipReader(zipBytes.buffer);
      const fileNames = zip.getFileNames();

      // Load all files and build resource map
      const resources = {};
      const htmlFiles = new Set();

      for (const name of fileNames) {
        const data = await zip.getFile(name);
        if (!data) continue;
        const ext = name.split('.').pop().toLowerCase();
        const mime = getMimeForExt(ext);
        resources[name] = { data: data, mime: mime, uri: null };
        if (mime === 'text/html') htmlFiles.add(name);
      }

      // Lazily convert binary data to data URI (cached)
      function toDataUri(name) {
        var r = resources[name];
        if (!r) return null;
        if (!r.uri) r.uri = 'data:' + r.mime + ';base64,' + uint8ToBase64(r.data);
        return r.uri;
      }

      // Get HTML file content as text
      function getHtml(name) {
        var r = resources[name];
        if (!r) return null;
        return new TextDecoder().decode(r.data);
      }

      // Rewrite resource URLs in HTML to data URIs
      function rewriteUrls(html, fromPage) {
        var attrPattern = /(src|href|srcset|poster|action)=(["'])([^"']+?)\\2/gi;
        html = html.replace(attrPattern, function(match, attr, quote, url) {
          if (url.startsWith('http://') || url.startsWith('https://') ||
              url.startsWith('//') || url.startsWith('data:') ||
              url.startsWith('#') || url.startsWith('javascript:') ||
              url.startsWith('mailto:')) {
            return match;
          }
          var clean = url.split('#')[0].split('?')[0];
          var resolved = resolvePath(fromPage, clean);
          // Leave <a href> to HTML pages alone — nav interceptor handles them
          if (attr.toLowerCase() === 'href' && htmlFiles.has(resolved)) {
            return match;
          }
          var uri = toDataUri(resolved);
          if (uri) return attr + '=' + quote + uri + quote;
          return match;
        });

        // Rewrite CSS url() references
        html = html.replace(/url\\((['"]?)([^)'"]+?)\\1\\)/gi, function(match, quote, url) {
          if (url.startsWith('http://') || url.startsWith('https://') ||
              url.startsWith('data:') || url.startsWith('#')) {
            return match;
          }
          var resolved = resolvePath(fromPage, url);
          var uri = toDataUri(resolved);
          if (uri) return 'url(' + quote + uri + quote + ')';
          return match;
        });

        // Rewrite quoted strings that match known resource paths.
        // Catches dynamic JS references like img.src = imageData.url
        // where the URL is stored in JSON/JS as "media/xxx.png".
        html = html.replace(/(["'])((?:[a-zA-Z0-9_\\-./]+\\/)?[a-zA-Z0-9_\\-.]+\\.[a-zA-Z0-9]{1,10})\\1/g, function(match, quote, val) {
          // Skip data URIs and absolute URLs
          if (val.indexOf('://') !== -1 || val.startsWith('data:')) return match;
          var clean = val.split('#')[0].split('?')[0];
          var resolved = resolvePath(fromPage, clean);
          // Only replace if it's a known non-HTML resource
          if (resources[resolved] && !htmlFiles.has(resolved)) {
            var uri = toDataUri(resolved);
            if (uri) return quote + uri + quote;
          }
          return match;
        });

        return html;
      }

      // Track current page for relative path resolution
      var currentPage = entry;
      var currentBlobUrl = null;

      // Create iframe
      container.innerHTML = '';
      var iframe = document.createElement('iframe');
      iframe.className = 'pagevault-site-frame';
      iframe.sandbox = 'allow-scripts allow-same-origin';
      container.appendChild(iframe);

      function renderPage(pageName) {
        var html = getHtml(pageName);
        if (!html) return false;
        currentPage = pageName;
        html = rewriteUrls(html, pageName);
        html = injectNavScript(html);
        // Use blob URL (not srcdoc) so the iframe has a real URL context
        // where location.hash, history.pushState, etc. work normally.
        // Resources are already inlined as data URIs, so no cross-origin issue.
        if (currentBlobUrl) URL.revokeObjectURL(currentBlobUrl);
        currentBlobUrl = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
        iframe.src = currentBlobUrl;
        return true;
      }

      // Listen for internal link clicks from iframe
      window.addEventListener('message', function(e) {
        if (!e.data || e.data.type !== 'pagevault-nav') return;
        var href = e.data.href;
        var clean = href.split('#')[0].split('?')[0];
        if (!clean) return;
        var target = resolvePath(currentPage, clean);
        if (htmlFiles.has(target)) {
          renderPage(target);
        }
      });

      // Load entry page
      if (!renderPage(entry)) {
        container.innerHTML = '<div class="pagevault-error">Entry point not found: ' + escapeHtml(entry) + '</div>';
      }
    } catch (e) {
      container.innerHTML = '<div class="pagevault-error">Failed to load site: ' + escapeHtml(e.message) + '</div>';
    }
  };

  function uint8ToBase64(data) {
    var binary = '';
    var len = data.length;
    for (var i = 0; i < len; i += 8192) {
      binary += String.fromCharCode.apply(null, data.subarray(i, Math.min(i + 8192, len)));
    }
    return btoa(binary);
  }

  function injectNavScript(html) {
    // Intercept clicks on internal links and forward to parent via postMessage.
    // Split 'script' tags to avoid closing the outer <script> in the wrapper HTML.
    var tag = '<scr' + 'ipt>document.addEventListener("click",function(e){' +
      'var a=e.target.closest("a");if(!a)return;' +
      'var h=a.getAttribute("href");' +
      'if(!h||h.startsWith("http://")||h.startsWith("https://")||' +
      'h.startsWith("//")||h.startsWith("#")||h.startsWith("data:")||' +
      'h.startsWith("javascript:")||h.startsWith("mailto:"))return;' +
      'e.preventDefault();' +
      'window.parent.postMessage({type:"pagevault-nav",href:h},"*");' +
      '});</scr' + 'ipt>';
    var idx = html.lastIndexOf('</body>');
    if (idx !== -1) return html.slice(0, idx) + tag + html.slice(idx);
    return html + tag;
  }

  function resolvePath(fromPage, href) {
    if (!href) return fromPage;
    href = href.replace(/^\\.\\//g, '');
    // Get directory of the referring page
    var parts = fromPage.split('/');
    parts.pop();
    var segments = href.split('/');
    for (var i = 0; i < segments.length; i++) {
      if (segments[i] === '..') parts.pop();
      else if (segments[i] !== '.' && segments[i] !== '') parts.push(segments[i]);
    }
    return parts.length ? parts.join('/') : href;
  }

  function getMimeForExt(ext) {
    var mimes = {
      html: 'text/html', htm: 'text/html',
      css: 'text/css', js: 'text/javascript',
      json: 'application/json', xml: 'application/xml',
      png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg',
      gif: 'image/gif', svg: 'image/svg+xml', webp: 'image/webp',
      ico: 'image/x-icon',
      pdf: 'application/pdf',
      woff: 'font/woff', woff2: 'font/woff2',
      ttf: 'font/ttf', eot: 'application/vnd.ms-fontobject',
      mp4: 'video/mp4', webm: 'video/webm',
      mp3: 'audio/mpeg', ogg: 'audio/ogg',
      txt: 'text/plain', md: 'text/markdown',
    };
    return mimes[ext] || 'application/octet-stream';
  }
})();"""
