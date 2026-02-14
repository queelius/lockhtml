"""Video viewer using the browser's built-in HTML5 video player."""

from pagevault.viewers.base import ViewerPlugin


class VideoViewer(ViewerPlugin):
    """Viewer for video files using HTML5 <video> element."""

    name = "video"
    mime_types = ["video/*"]
    priority = 0

    def js(self) -> str:
        return """async function(container, blob, url, meta, toolbar) {
    container.className = 'pagevault-viewer pagevault-video-viewer';
    var video = document.createElement('video');
    video.controls = true;
    video.src = url;
    container.appendChild(video);
}"""

    def css(self) -> str:
        return """
/* Video viewer */
.pagevault-video-viewer {
  display: flex;
  justify-content: center;
  align-items: flex-start;
  min-height: calc(100vh - 40px);
  background: #000;
  padding: 0;
}
.pagevault-video-viewer video {
  max-width: 100%;
  max-height: calc(100vh - 40px);
}"""
