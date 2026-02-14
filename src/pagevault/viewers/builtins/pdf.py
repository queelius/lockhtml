"""PDF viewer using the browser's built-in renderer."""

from pagevault.viewers.base import ViewerPlugin


class PdfViewer(ViewerPlugin):
    """Viewer for PDF files using browser's built-in renderer.

    No sandbox needed — browsers' built-in PDF renderers don't execute scripts.
    """

    name = "pdf"
    mime_types = ["application/pdf"]
    priority = 0

    def js(self) -> str:
        return """async function(container, blob, url, meta, toolbar) {
    var iframe = document.createElement('iframe');
    iframe.src = url;
    container.appendChild(iframe);
}"""

    def css(self) -> str:
        return ""
