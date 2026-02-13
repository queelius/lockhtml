"""Built-in viewer plugins for pagevault.

These viewers are extracted from the original monolithic renderer in wrap.py.
Each implements the uniform viewer signature:
    async function(container, blob, url, meta, toolbar)

Security note: innerHTML usage is intentional in these viewers:
- PDF/HTML viewers use blob: URLs from URL.createObjectURL() (safe, not user-controlled)
- Markdown viewer renders parsed markdown (same trust model as marked.js library)
- Download view constructs HTML from escapeHtml()-sanitized values
"""

from pathlib import Path

from .base import ViewerPlugin

# JS for PdfViewer: renders in a plain iframe via blob: URL.
# No sandbox needed — browsers' built-in PDF renderers don't execute scripts.
_PDF_IFRAME_JS = """async function(container, blob, url, meta, toolbar) {
    var iframe = document.createElement('iframe');
    iframe.src = url;
    container.appendChild(iframe);
}"""

# JS for HtmlViewer: renders in a sandboxed iframe via blob: URL.
# No allow-scripts: file-mode HTML is display-only (use wrap site for apps).
# allow-same-origin is needed so CSS/images in the blob document resolve.
_HTML_IFRAME_JS = """async function(container, blob, url, meta, toolbar) {
    var iframe = document.createElement('iframe');
    iframe.sandbox = 'allow-same-origin';
    iframe.src = url;
    container.appendChild(iframe);
}"""


class ImageViewer(ViewerPlugin):
    """Viewer for image files with click-to-zoom."""

    name = "image"
    mime_types = ["image/*"]
    priority = 0

    def js(self) -> str:
        return """async function(container, blob, url, meta, toolbar) {
    container.className = 'pagevault-viewer pagevault-image-viewer';
    var img = document.createElement('img');
    img.src = url;
    img.alt = meta.filename;
    img.addEventListener('click', function() { img.classList.toggle('zoomed'); });
    container.appendChild(img);
}"""

    def css(self) -> str:
        return """
/* Image viewer */
.pagevault-image-viewer {
  display: flex;
  justify-content: center;
  align-items: flex-start;
  min-height: calc(100vh - 40px);
  background: #f0f0f0;
  padding: 1rem;
  overflow: auto;
}
.pagevault-image-viewer img {
  max-width: 100%;
  max-height: calc(100vh - 72px);
  height: auto;
  display: block;
  cursor: zoom-in;
  object-fit: contain;
}
.pagevault-image-viewer img.zoomed {
  max-width: none;
  max-height: none;
  cursor: zoom-out;
}"""


class PdfViewer(ViewerPlugin):
    """Viewer for PDF files using browser's built-in renderer."""

    name = "pdf"
    mime_types = ["application/pdf"]
    priority = 0

    def js(self) -> str:
        return _PDF_IFRAME_JS

    def css(self) -> str:
        return ""


class HtmlViewer(ViewerPlugin):
    """Viewer for HTML files using sandboxed iframe.

    The iframe has sandbox='allow-same-origin' but no allow-scripts.
    This means the decrypted HTML is rendered as static content —
    embedded scripts will NOT execute. For interactive HTML apps,
    use ``pagevault wrap site`` instead.
    """

    name = "html"
    mime_types = ["text/html"]
    priority = 0

    def js(self) -> str:
        return _HTML_IFRAME_JS

    def css(self) -> str:
        return ""


class TextViewer(ViewerPlugin):
    """Viewer for text files with line numbers."""

    name = "text"
    mime_types = ["text/*", "application/json", "application/xml"]
    priority = 0

    def js(self) -> str:
        return """async function(container, blob, url, meta, toolbar) {
    container.className = 'pagevault-viewer pagevault-text-viewer';
    var text = await blob.text();
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
    container.appendChild(gutter);
    container.appendChild(pre);
}"""

    def css(self) -> str:
        return """
/* Text viewer with line numbers */
.pagevault-text-viewer {
  display: flex;
  min-height: calc(100vh - 40px);
  background: #f5f5f5;
}
.pagevault-text-viewer .line-numbers {
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
}
.pagevault-text-viewer pre {
  flex: 1;
  padding: 1rem;
  overflow-x: auto;
}"""


class MarkdownViewer(ViewerPlugin):
    """Viewer for markdown files with rendered/source toggle.

    Uses vendored marked.js for full rendering, with a simple
    fallback when marked.js is unavailable.
    """

    name = "markdown"
    mime_types = ["text/markdown"]
    priority = 10  # Higher than TextViewer's text/* wildcard

    def js(self) -> str:
        # The rendered markdown HTML is produced by marked.js (a trusted library)
        # or simpleMarkdown (which escapes all HTML entities first). This is the
        # same trust model as the pre-refactor code in wrap.py.
        return """async function(container, blob, url, meta, toolbar) {
    var text = await blob.text();
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

    container.appendChild(body);
    container.appendChild(source);

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

    function simpleMarkdown(text) {
        var html = text
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
}"""

    def css(self) -> str:
        return """
/* Markdown rendered view */
.markdown-body {
  max-width: 800px;
  margin: 0 auto;
  padding: 2rem;
  line-height: 1.7;
  color: #24292e;
}
.markdown-body h1, .markdown-body h2, .markdown-body h3,
.markdown-body h4, .markdown-body h5, .markdown-body h6 {
  margin-top: 1.5em;
  margin-bottom: 0.5em;
  font-weight: 600;
  line-height: 1.25;
}
.markdown-body h1 { font-size: 2em; padding-bottom: 0.3em; border-bottom: 1px solid #eee; }
.markdown-body h2 { font-size: 1.5em; padding-bottom: 0.3em; border-bottom: 1px solid #eee; }
.markdown-body h3 { font-size: 1.25em; }
.markdown-body a { color: var(--pv-color-primary); text-decoration: none; }
.markdown-body a:hover { text-decoration: underline; }
.markdown-body table { border-collapse: collapse; width: 100%; margin: 1em 0; }
.markdown-body th, .markdown-body td { border: 1px solid #ddd; padding: 0.5em 0.75em; text-align: left; }
.markdown-body th { background: #f6f8fa; font-weight: 600; }
.markdown-body code {
  padding: 0.2em 0.4em;
  background: #f0f0f0;
  border-radius: 3px;
  font-size: 0.85em;
  font-family: 'Consolas', 'Monaco', monospace;
}
.markdown-body pre {
  padding: 1em;
  background: #f6f8fa;
  border-radius: 4px;
  overflow-x: auto;
}
.markdown-body pre code { padding: 0; background: none; font-size: 0.9em; }
.markdown-body blockquote {
  margin: 1em 0;
  padding: 0.5em 1em;
  border-left: 4px solid #ddd;
  color: #666;
}
.markdown-body hr { border: none; border-top: 1px solid #ddd; margin: 1.5em 0; }
.markdown-body ul, .markdown-body ol { padding-left: 2em; margin: 0.5em 0; }
.markdown-body li { margin: 0.25em 0; }
.markdown-body img { max-width: 100%; height: auto; }
.markdown-body p { margin: 0.75em 0; }

/* Markdown source toggle */
.markdown-source { max-width: 800px; margin: 0 auto; padding: 0; }
.markdown-source pre {
  padding: 2rem;
  background: #f5f5f5;
  min-height: calc(100vh - 40px);
}"""

    def dependencies(self) -> list[str]:
        vendor_path = Path(__file__).parent.parent / "vendor" / "marked.min.js"
        return [vendor_path.read_text(encoding="utf-8")]
