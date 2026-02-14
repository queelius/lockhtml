"""HTML viewer using sandboxed iframe."""

from pagevault.viewers.base import ViewerPlugin


class HtmlViewer(ViewerPlugin):
    """Viewer for HTML files using sandboxed iframe.

    The iframe has sandbox='allow-same-origin' but no allow-scripts.
    This means the decrypted HTML is rendered as static content —
    embedded scripts will NOT execute. For interactive HTML apps,
    use ``pagevault lock --site`` instead.
    """

    name = "html"
    mime_types = ["text/html"]
    priority = 0

    def js(self) -> str:
        return """async function(container, blob, url, meta, toolbar) {
    var iframe = document.createElement('iframe');
    iframe.sandbox = 'allow-same-origin';
    iframe.src = url;
    container.appendChild(iframe);
}"""

    def css(self) -> str:
        return ""
