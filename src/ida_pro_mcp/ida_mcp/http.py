import json
import re
from http.server import HTTPServer
from typing import cast
from urllib.parse import urlparse

from .rpc import McpHttpRequestHandler, get_cached_output


class IdaMcpHttpRequestHandler(McpHttpRequestHandler):
    """GUI-local HTTP handler with cached large-output downloads."""

    def do_GET(self):
        path = urlparse(self.path).path
        output_match = re.match(r"^/output/([a-f0-9-]+)\.(\w+)$", path)
        if output_match:
            if not self._check_auth():
                return
            if not self._check_host():
                return
            self._handle_output_download(output_match.group(1), output_match.group(2))
            return

        super().do_GET()

    def _handle_output_download(self, output_id: str, extension: str):
        data = get_cached_output(output_id)
        if data is None:
            self.send_error(404, "Output not found or expired")
            return

        if extension == "json":
            content = json.dumps(data, indent=2)
        elif isinstance(data, dict) and "code" in data:
            content = str(data["code"])
        elif isinstance(data, list) and data and isinstance(data[0], dict):
            content = "\n\n".join(
                str(item.get("code", item.get("asm", item.get("lines", ""))))
                for item in data
            )
        else:
            content = json.dumps(data, indent=2)

        body = content.encode("utf-8")
        self.send_response(200)
        content_type = "application/json" if extension == "json" else "text/plain"
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Content-Disposition", f'attachment; filename="{output_id}.{extension}"'
        )
        self.end_headers()
        self.wfile.write(body)

    @property
    def server_port(self) -> int:
        return cast(HTTPServer, self.server).server_port

    def _check_host(self) -> bool:
        """Reject DNS-rebinding access to cached local-server output."""
        host = self.headers.get("Host")
        port = self.server_port
        if host not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            self.send_error(403, "Invalid Host")
            return False
        return True
