"""
server/ui.py — Purple team web UI for Lilith engagement database.

Serves a CALDERA-style SPA at /ui/ over the existing HTTPS C2 server.
All state is read-only from EngagementDB; no additional persistence.

Endpoints:
  GET  /ui/                         -> HTML SPA
  GET  /ui/api/summary              -> aggregate stats + recent events
  GET  /ui/api/sessions             -> session list
  GET  /ui/api/session/<id>         -> session detail (tasks + results merged)
  GET  /ui/api/credentials          -> all credential findings
  GET  /ui/api/techniques           -> ATT&CK coverage
  GET  /ui/api/events               -> full event log
  GET  /ui/api/export/json          -> full JSON dump
  GET  /ui/api/export/markdown      -> Markdown engagement report
  POST /ui/api/sessions/<id>/label  -> set label/note on session
"""

import json
import re

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


# ── Router ────────────────────────────────────────────────────────────────────

def handle_ui_request(method: str, path: str, body: bytes, db) -> tuple:
    """Route /ui/* -> (status_code, content_type, body_bytes)."""
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

    if method == "POST":
        m = re.fullmatch(r"/ui/api/sessions/([^/]+)/label", path)
        if m:
            return _j(_label_session(db, m.group(1), body))

    return 404, "application/json", b'{"error":"not found"}'


# ── HTML SPA ──────────────────────────────────────────────────────────────────

_UI_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lilith C2 — Operations</title>
<style>
:root{
  --bg:#0d1117;--surf:#161b22;--surf2:#21262d;--border:#30363d;
  --accent:#7c3aed;--accent2:#4c1d95;
  --red:#ef4444;--green:#22c55e;--yellow:#f59e0b;--blue:#38bdf8;
  --text:#f0f6fc;--muted:#8b949e;--code:#c9d1d9;
  --sw:210px;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;line-height:1.5}
#layout{display:flex;height:100vh;overflow:hidden}
#sidebar{width:var(--sw);flex-shrink:0;background:var(--surf);border-right:1px solid var(--border);display:flex;flex-direction:column}
.logo{padding:18px 18px 14px;font-size:15px;font-weight:700;color:var(--text);border-bottom:1px solid var(--border)}
.logo span{color:var(--accent)}
.nav-link{display:flex;align-items:center;gap:10px;padding:10px 18px;color:var(--muted);text-decoration:none;font-size:13px;transition:color .15s,background .15s;border-left:3px solid transparent}
.nav-link:hover{color:var(--text);background:var(--surf2)}
.nav-link.active{color:var(--text);border-left-color:var(--accent);background:rgba(124,58,237,.08)}
.nav-bottom{margin-top:auto;padding:12px 18px;border-top:1px solid var(--border);color:var(--muted);font-size:11px;display:flex;align-items:center;gap:7px}
.dot{font-size:8px}.dot-ok{color:var(--green)}.dot-err{color:var(--red)}.dot-spin{color:var(--yellow)}
#main{flex:1;overflow:auto;padding:24px 28px}
.view{display:none}.view.active{display:block}
.page-header{margin-bottom:22px}
.page-title{font-size:20px;font-weight:600;margin-bottom:2px}
.page-sub{color:var(--muted);font-size:12px}
/* cards */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:22px}
.card{background:var(--surf);border:1px solid var(--border);border-radius:8px;padding:15px 18px}
.card-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
.card-value{font-size:28px;font-weight:700;line-height:1}
.card-sub{font-size:11px;color:var(--muted);margin-top:4px}
.card.red{border-color:rgba(239,68,68,.4);background:rgba(239,68,68,.04)}
.card.accent{border-color:rgba(124,58,237,.4);background:rgba(124,58,237,.05)}
/* panels */
.panels{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:22px}
@media(max-width:860px){.panels{grid-template-columns:1fr}}
.panel{background:var(--surf);border:1px solid var(--border);border-radius:8px;padding:15px 18px;min-height:160px}
.panel-title{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:12px}
/* tables */
.tbl-wrap{overflow-x:auto;border-radius:8px;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse}
th{background:var(--surf2);color:var(--muted);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;padding:8px 12px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top;color:var(--text)}
tr:last-child td{border-bottom:none}
tr.clickable:hover td{background:var(--surf2);cursor:pointer}
tr.selected td{background:rgba(124,58,237,.08)}
/* badges */
.badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.03em;line-height:1.6}
.b-ntlm{background:rgba(239,68,68,.15);color:#f87171}
.b-kerb{background:rgba(245,158,11,.15);color:#fbbf24}
.b-plain{background:rgba(34,197,94,.15);color:#4ade80}
.b-aes{background:rgba(56,189,248,.15);color:#38bdf8}
.b-cred{background:rgba(239,68,68,.12);color:#f87171}
.b-ok{background:rgba(34,197,94,.12);color:#4ade80}
.b-warn{background:rgba(245,158,11,.12);color:#fbbf24}
.b-info{background:rgba(56,189,248,.12);color:#38bdf8}
.b-grey{background:rgba(139,148,158,.1);color:var(--muted)}
/* chips (ATT&CK) */
.chip{display:inline-block;padding:3px 8px;border-radius:4px;font-size:11px;margin:3px;cursor:default;transition:background .1s}
.chip-on{background:rgba(34,197,94,.15);color:#4ade80;border:1px solid rgba(34,197,94,.3)}
.chip-on:hover{background:rgba(34,197,94,.25)}
.chip-off{background:var(--surf2);color:var(--muted);border:1px solid var(--border)}
.chip-cnt{font-size:9px;opacity:.75;margin-left:2px}
/* tactic sections */
.tactic-section{margin-bottom:18px}
.tactic-header{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--accent);margin-bottom:7px;padding-bottom:4px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.tactic-score{font-weight:400;color:var(--muted)}
/* session detail */
#session-detail{background:var(--surf);border:1px solid var(--border);border-radius:8px;padding:18px;margin-top:16px}
.det-header{display:flex;align-items:center;gap:12px;margin-bottom:14px;padding-bottom:12px;border-bottom:1px solid var(--border)}
.det-title{font-size:15px;font-weight:600;flex:1}
.label-form{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
.label-form input{flex:1;min-width:110px;padding:5px 10px;background:var(--surf2);border:1px solid var(--border);border-radius:5px;color:var(--text);font-size:12px;outline:none}
.label-form input:focus{border-color:var(--accent)}
/* buttons */
.btn{display:inline-block;padding:6px 14px;border-radius:5px;border:1px solid var(--border);background:var(--surf2);color:var(--text);font-size:12px;cursor:pointer;text-decoration:none;transition:border-color .15s,color .15s}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn-primary{background:var(--accent);border-color:var(--accent);color:#fff}
.btn-primary:hover{background:var(--accent2);border-color:var(--accent2);color:#fff}
.btn-sm{padding:3px 10px;font-size:11px}
/* task items */
.task-item{padding:10px 12px;border-radius:6px;margin-bottom:8px;background:var(--surf2);border-left:3px solid var(--border)}
.task-item.t-cred{border-left-color:var(--red)}
.task-item.t-pend{border-left-color:var(--yellow)}
.task-item.t-done{border-left-color:var(--green)}
.task-cmd{font-family:'Cascadia Code','Consolas',monospace;font-size:12px;color:var(--code);margin-bottom:5px;word-break:break-all}
.task-meta{display:flex;gap:8px;flex-wrap:wrap;align-items:center;font-size:11px;color:var(--muted)}
.task-out{margin-top:8px;background:var(--bg);border-radius:4px;padding:8px;font-family:monospace;font-size:11px;color:var(--muted);white-space:pre-wrap;max-height:180px;overflow-y:auto;border:1px solid var(--border)}
/* events */
.ev-item{padding:6px 0;border-bottom:1px solid var(--border);display:flex;gap:10px;align-items:flex-start}
.ev-item:last-child{border-bottom:none}
.ev-time{color:var(--muted);font-size:11px;white-space:nowrap;min-width:50px}
.ev-type{font-size:10px;font-weight:700;text-transform:uppercase;color:var(--accent);min-width:90px}
.ev-detail{font-size:12px;color:var(--text);word-break:break-all}
/* empty state */
.empty{text-align:center;padding:40px;color:var(--muted)}
.empty-icon{font-size:28px;margin-bottom:8px}
/* export row */
.hrow{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:20px}
.hrow .page-title{margin:0}
.hrow .page-sub{margin:0}
.hrow-titles{flex:1}
.btn-row{display:flex;gap:8px;flex-wrap:wrap}
/* report */
#report-content{max-width:880px}
.r-section{margin-bottom:28px}
.r-h1{font-size:22px;font-weight:700;margin-bottom:4px}
.r-h2{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid var(--border)}
.r-meta{display:flex;gap:24px;margin-bottom:22px;color:var(--muted);font-size:12px;flex-wrap:wrap}
/* scrollbar */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
@keyframes spin{to{transform:rotate(360deg)}}
.spin{display:inline-block;animation:spin .8s linear infinite}
/* print */
@media print{
  #sidebar,.btn,.btn-row,button{display:none!important}
  #main{padding:0}
  #view-report{display:block!important}
  body,html{background:#fff;color:#000;height:auto}
  #layout{display:block;height:auto}
  .card,.panel,.tbl-wrap{break-inside:avoid}
  .card{background:#f7f7f7;border-color:#ccc}
  th{background:#eee}
  td,th{border-color:#ccc}
  .chip-on{background:#d1fae5;color:#065f46;border-color:#6ee7b7}
  .chip-off{background:#f3f4f6;color:#9ca3af;border-color:#e5e7eb}
  .tactic-header{color:#7c3aed}
}
</style>
</head>
<body>
<div id="layout">

<!-- Sidebar -->
<nav id="sidebar">
  <div class="logo">⚡ <span>Lilith</span> C2</div>
  <a href="#" class="nav-link active" data-view="dashboard">◈ Dashboard</a>
  <a href="#" class="nav-link" data-view="sessions">⬡ Sessions</a>
  <a href="#" class="nav-link" data-view="credentials">◎ Credentials</a>
  <a href="#" class="nav-link" data-view="attack">▧ ATT&amp;CK</a>
  <a href="#" class="nav-link" data-view="report">◫ Report</a>
  <div class="nav-bottom">
    <span id="status-dot" class="dot dot-spin">●</span>
    <span id="last-refresh">connecting…</span>
  </div>
</nav>

<!-- Main -->
<main id="main">

<!-- Dashboard -->
<div id="view-dashboard" class="view active">
  <div class="page-header">
    <div class="page-title">Operations Dashboard</div>
    <div class="page-sub">Live engagement overview · auto-refresh every 5s</div>
  </div>
  <div class="cards">
    <div class="card"><div class="card-label">Sessions</div><div class="card-value" id="d-sess">0</div></div>
    <div class="card"><div class="card-label">Tasks</div><div class="card-value" id="d-tasks">0</div></div>
    <div class="card red"><div class="card-label">Credentials</div><div class="card-value" id="d-creds">0</div></div>
    <div class="card accent">
      <div class="card-label">ATT&amp;CK Covered</div>
      <div class="card-value" id="d-techs">0</div>
      <div class="card-sub" id="d-techs-sub"></div>
    </div>
    <div class="card"><div class="card-label">Events</div><div class="card-value" id="d-evts">0</div></div>
  </div>
  <div class="panels">
    <div class="panel">
      <div class="panel-title">Top Techniques</div>
      <div id="dash-techs"><div class="empty"><div class="empty-icon">◈</div>No data yet</div></div>
    </div>
    <div class="panel">
      <div class="panel-title">Recent Events</div>
      <div id="dash-evts"><div class="empty"><div class="empty-icon">◈</div>No events yet</div></div>
    </div>
  </div>
</div>

<!-- Sessions -->
<div id="view-sessions" class="view">
  <div class="page-header">
    <div class="page-title">Agent Sessions</div>
    <div class="page-sub">Click a row to inspect tasks and results</div>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr>
        <th>Host</th><th>Session ID</th><th>Registered</th><th>Last Seen</th>
        <th>Label</th><th>Tasks</th><th>Creds</th>
      </tr></thead>
      <tbody id="sess-tbody"><tr><td colspan="7" class="empty">Loading…</td></tr></tbody>
    </table>
  </div>
  <div id="session-detail" style="display:none"></div>
</div>

<!-- Credentials -->
<div id="view-credentials" class="view">
  <div class="page-header">
    <div class="page-title">Credential Findings</div>
    <div class="page-sub">All results containing credential material captured by C2</div>
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr>
        <th>Time</th><th>Session</th><th>Command</th><th>Types</th><th>Preview</th>
      </tr></thead>
      <tbody id="creds-tbody"><tr><td colspan="5" class="empty">Loading…</td></tr></tbody>
    </table>
  </div>
</div>

<!-- ATT&CK -->
<div id="view-attack" class="view">
  <div class="page-header">
    <div class="page-title">MITRE ATT&amp;CK Coverage</div>
    <div class="page-sub">Techniques observed during engagement · green = covered</div>
  </div>
  <div id="attack-heatmap"><div class="empty">Loading…</div></div>
</div>

<!-- Report -->
<div id="view-report" class="view">
  <div class="hrow">
    <div class="hrow-titles">
      <div class="page-title">Engagement Report</div>
      <div class="page-sub">Printable summary for client / purple team delivery</div>
    </div>
    <div class="btn-row">
      <button class="btn btn-primary btn-sm" onclick="window.print()">🖨 Print / PDF</button>
      <a class="btn btn-sm" href="/ui/api/export/json" download="engagement.json">⬇ JSON</a>
      <a class="btn btn-sm" href="/ui/api/export/markdown" download="engagement.md">⬇ Markdown</a>
    </div>
  </div>
  <div id="report-content"><div class="empty">Loading…</div></div>
</div>

</main>
</div>
<script>
'use strict';

// ── Utils ──────────────────────────────────────────────────────────────────────
function esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function fmtDt(s) {
  if (!s) return '—';
  try {
    const d = new Date(s.includes('T') ? s : s.replace(' ','T')+'Z');
    if (isNaN(d)) return s;
    return d.toLocaleString(undefined,{month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false});
  } catch(e) { return s; }
}
function shortId(id) { return id ? '…'+id.slice(-8) : '—'; }

function credBadges(hints) {
  if (!hints || !hints.length) return '';
  const seen = new Set();
  const out  = [];
  for (const h of hints) {
    const lh = h.toLowerCase();
    let tag, cls;
    if (lh.includes('ntlm'))        { tag='NTLM';  cls='b-ntlm'; }
    else if (lh.includes('kerberoast')){ tag='KERB'; cls='b-kerb'; }
    else if (lh.includes('asrep'))  { tag='ASREP'; cls='b-kerb'; }
    else if (lh.includes('plaintext')){ tag='PLAIN'; cls='b-plain'; }
    else if (lh.includes('aes-key')){ tag='AES';   cls='b-aes'; }
    else                            { tag='CRED';  cls='b-cred'; }
    if (!seen.has(tag)) { seen.add(tag); out.push('<span class="badge '+cls+'">'+tag+'</span>'); }
  }
  return out.join(' ');
}

// ── State ──────────────────────────────────────────────────────────────────────
const S = { view:'dashboard', selSess:null };

// ── API ────────────────────────────────────────────────────────────────────────
async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(r.status+' '+r.statusText);
  return r.json();
}

// ── Navigation ─────────────────────────────────────────────────────────────────
function navigate(view) {
  S.view = view;
  document.querySelectorAll('.nav-link').forEach(a => a.classList.toggle('active', a.dataset.view===view));
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id==='view-'+view));
  refresh();
}

// ── Render: Dashboard ──────────────────────────────────────────────────────────
function renderDashboard(d) {
  document.getElementById('d-sess').textContent  = d.session_count;
  document.getElementById('d-tasks').textContent = d.task_count;
  document.getElementById('d-creds').textContent = d.cred_count;
  document.getElementById('d-evts').textContent  = d.event_count;
  const pct = d.total_technique_count
    ? Math.round(100*d.covered_technique_count/d.total_technique_count) : 0;
  document.getElementById('d-techs').textContent     = d.covered_technique_count;
  document.getElementById('d-techs-sub').textContent = pct+'% of '+d.total_technique_count;

  const tt = document.getElementById('dash-techs');
  if (!d.top_techniques || !d.top_techniques.length) {
    tt.innerHTML = '<div class="empty"><div class="empty-icon">◈</div>No techniques recorded</div>';
  } else {
    tt.innerHTML = d.top_techniques.map(t =>
      '<div style="display:flex;align-items:center;gap:8px;margin-bottom:9px">'
      + '<span class="chip chip-on" style="font-size:11px">'+esc(t.tid)+'</span>'
      + '<span style="flex:1;font-size:12px">'+esc(t.name)+'</span>'
      + '<span style="color:var(--muted);font-size:11px">×'+t.count+'</span>'
      + '</div>'
    ).join('');
  }

  const ev = document.getElementById('dash-evts');
  if (!d.recent_events || !d.recent_events.length) {
    ev.innerHTML = '<div class="empty"><div class="empty-icon">◈</div>No events yet</div>';
  } else {
    ev.innerHTML = d.recent_events.map(e =>
      '<div class="ev-item">'
      + '<span class="ev-time">'+esc((e.at||'').slice(11,16))+'</span>'
      + '<span class="ev-type">'+esc(e.type||'')+'</span>'
      + '<span class="ev-detail">'+esc((e.detail||'').slice(0,72))+'</span>'
      + '</div>'
    ).join('');
  }
}

// ── Render: Sessions ───────────────────────────────────────────────────────────
function renderSessions(data) {
  const tbody = document.getElementById('sess-tbody');
  if (!data.length) {
    tbody.innerHTML = '<tr><td colspan="7"><div class="empty"><div class="empty-icon">⬡</div>No sessions registered</div></td></tr>';
    return;
  }
  tbody.innerHTML = data.map(s =>
    '<tr class="clickable'+(S.selSess===s.id?' selected':'')+'" data-id="'+esc(s.id)+'">'
    + '<td><b>'+esc(s.host||'—')+'</b></td>'
    + '<td style="font-family:monospace;font-size:11px;color:var(--muted)">'+esc(shortId(s.id))+'</td>'
    + '<td style="white-space:nowrap">'+esc(fmtDt(s.registered_at))+'</td>'
    + '<td style="white-space:nowrap">'+esc(fmtDt(s.last_seen))+'</td>'
    + '<td>'+(s.label?'<span class="badge b-info">'+esc(s.label)+'</span>':'<span style="color:var(--muted)">—</span>')+'</td>'
    + '<td>'+((s.task_count)||0)+'</td>'
    + '<td>'+((s.cred_tasks||0)>0?'<span class="badge b-cred">CRED</span>':'<span class="badge b-grey">—</span>')+'</td>'
    + '</tr>'
  ).join('');
  tbody.querySelectorAll('tr.clickable').forEach(tr => {
    tr.addEventListener('click', () => openSession(tr.dataset.id));
  });
}

// ── Session Detail ─────────────────────────────────────────────────────────────
async function openSession(id) {
  S.selSess = id;
  document.querySelectorAll('#sess-tbody tr').forEach(tr =>
    tr.classList.toggle('selected', tr.dataset.id===id));
  const det = document.getElementById('session-detail');
  det.style.display = 'block';
  det.innerHTML = '<div style="padding:24px;text-align:center;color:var(--muted)"><span class="spin">○</span> Loading…</div>';
  try {
    const d = await api('/ui/api/session/'+encodeURIComponent(id));
    renderSessionDetail(d, det);
  } catch(e) {
    det.innerHTML = '<div class="empty">Error: '+esc(String(e))+'</div>';
  }
}

function renderSessionDetail(d, el) {
  const s     = d.session || {};
  const tasks = d.tasks   || [];
  const evts  = d.events  || [];

  let h = '<div class="det-header">'
    + '<div class="det-title">'+esc(s.host||'?')
    + '  <span style="font-family:monospace;font-size:11px;color:var(--muted)">'+esc(s.id||'')+'</span></div>'
    + '<button class="btn btn-sm" onclick="document.getElementById(\'session-detail\').style.display=\'none\';S.selSess=null;">× Close</button>'
    + '</div>'
    + '<div class="label-form">'
    + '<input id="det-label" placeholder="Label (e.g. DC01)" value="'+esc(s.label||'')+'">'
    + '<input id="det-note" placeholder="Operator note…" value="'+esc(s.note||'')+'" style="flex:2">'
    + '<button class="btn btn-primary btn-sm" onclick="saveLabel(\''+esc(s.id)+'\')">Save</button>'
    + '</div>';

  if (!tasks.length) {
    h += '<div class="empty"><div class="empty-icon">◈</div>No tasks dispatched yet</div>';
  } else {
    h += '<div class="panel-title" style="margin-bottom:10px">Task Timeline ('+tasks.length+')</div>';
    h += tasks.map(t => {
      const done  = t.output != null;
      const hcred = t.has_creds;
      let cls = 'task-item ' + (hcred ? 't-cred' : done ? 't-done' : 't-pend');
      let inner = '<div class="task-cmd">'+esc(t.command||'')+'</div>'
        + '<div class="task-meta">';
      if (t.technique_id) {
        inner += '<span class="badge b-info">'+esc(t.technique_id)+'</span>'
               + '<span>'+esc(t.technique_desc||'')+'</span>';
      }
      inner += '<span style="margin-left:auto;color:var(--muted)">'+esc(fmtDt(t.dispatched_at))+'</span>';
      if (!done)   inner += '<span class="badge b-warn">pending</span>';
      else if (hcred) inner += '<span class="badge b-cred">CREDS</span>';
      else         inner += '<span class="badge b-ok">done</span>';
      inner += '</div>';
      if (t.cred_hints && t.cred_hints.length) {
        inner += '<div style="margin-top:6px;font-size:11px;color:var(--muted)">'
          + t.cred_hints.slice(0,4).map(h2 => esc(h2.slice(0,100))).join('<br>')
          + '</div>';
      }
      if (done && !t.is_binary && t.output) {
        inner += '<div class="task-out">'+esc(t.output.slice(0,600))+(t.output.length>600?'\n…':'')+'</div>';
      } else if (t.is_binary) {
        inner += '<div class="task-out">[binary data]</div>';
      }
      return '<div class="'+cls+'">'+inner+'</div>';
    }).join('');
  }

  if (evts.length) {
    h += '<div class="panel-title" style="margin:16px 0 8px">Session Events ('+evts.length+')</div>';
    h += evts.slice(-20).reverse().map(e =>
      '<div class="ev-item">'
      + '<span class="ev-time">'+esc((e.at||'').slice(11,16))+'</span>'
      + '<span class="ev-type">'+esc(e.type||'')+'</span>'
      + '<span class="ev-detail">'+esc(e.detail||'')+'</span>'
      + '</div>'
    ).join('');
  }

  el.innerHTML = h;
}

async function saveLabel(id) {
  const label = (document.getElementById('det-label')||{}).value||'';
  const note  = (document.getElementById('det-note') ||{}).value||'';
  try {
    await fetch('/ui/api/sessions/'+encodeURIComponent(id)+'/label',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({label:label.trim(),note:note.trim()})
    });
    api('/ui/api/sessions').then(renderSessions);
  } catch(e) { console.error(e); }
}

// ── Render: Credentials ────────────────────────────────────────────────────────
function renderCredentials(data) {
  const tbody = document.getElementById('creds-tbody');
  if (!data.length) {
    tbody.innerHTML = '<tr><td colspan="5"><div class="empty"><div class="empty-icon">◎</div>No credentials captured yet</div></td></tr>';
    return;
  }
  tbody.innerHTML = data.map(r => {
    const prev = (r.output||'').replace(/\\n/g,' ').slice(0,100);
    return '<tr>'
      + '<td style="white-space:nowrap;font-size:11px">'+esc(fmtDt(r.received_at))+'</td>'
      + '<td style="font-family:monospace;font-size:11px;color:var(--muted)">'+esc(shortId(r.session_id))+'</td>'
      + '<td style="font-family:monospace;font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(r.command||'')+'</td>'
      + '<td>'+credBadges(r.cred_hints)+'</td>'
      + '<td style="color:var(--muted);font-size:11px;font-family:monospace;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(prev)+'</td>'
      + '</tr>';
  }).join('');
}

// ── Render: ATT&CK ────────────────────────────────────────────────────────────
function renderAttack(data) {
  const covered = data.covered||{};
  const allTech = data.all_techniques||{};
  const tactics = data.tactic_order||[];
  const byTac   = {};
  for (const [tid,m] of Object.entries(allTech)) {
    const tac = m.tactic||'Other';
    if (!byTac[tac]) byTac[tac] = [];
    byTac[tac].push({tid,...m});
  }
  const el = document.getElementById('attack-heatmap');
  el.innerHTML = tactics.map(tac => {
    const techs = byTac[tac]||[];
    if (!techs.length) return '';
    const cov = techs.filter(t => covered[t.tid]).length;
    const chips = techs.map(t => {
      const cnt = covered[t.tid] ? covered[t.tid].length : 0;
      const cls = cnt ? 'chip chip-on' : 'chip chip-off';
      const tt  = cnt ? ' title="'+cnt+' session(s)"' : '';
      return '<span class="'+cls+'"'+tt+'>'+esc(t.tid)+' '+esc(t.name)
        +(cnt?'<span class="chip-cnt">×'+cnt+'</span>':'')+'</span>';
    }).join('');
    return '<div class="tactic-section">'
      + '<div class="tactic-header"><span>'+esc(tac)+'</span>'
      + '<span class="tactic-score">'+cov+'/'+techs.length+'</span></div>'
      + '<div>'+chips+'</div>'
      + '</div>';
  }).join('');
}

// ── Render: Report ─────────────────────────────────────────────────────────────
function renderReport(summary, sessions, creds, techniques) {
  const now = new Date().toLocaleDateString(undefined,{year:'numeric',month:'long',day:'numeric'});
  const covered = (techniques||{}).covered||{};
  const allTech = (techniques||{}).all_techniques||{};
  const tactics = (techniques||{}).tactic_order||[];
  const byTac   = {};
  for (const [tid,m] of Object.entries(allTech)) {
    const tac = m.tactic||'Other';
    if (!byTac[tac]) byTac[tac] = [];
    byTac[tac].push({tid,...m});
  }

  let h = '<div class="r-section">'
    + '<div class="r-h1">Engagement Report</div>'
    + '<div class="r-meta">'
    + '<span>Generated: '+esc(now)+'</span>'
    + '<span>Sessions: '+(summary?summary.session_count:'?')+'</span>'
    + '<span>Tasks: '+(summary?summary.task_count:'?')+'</span>'
    + '<span>Credentials: '+(summary?summary.cred_count:'?')+'</span>'
    + '<span>ATT&amp;CK techniques: '+(summary?summary.covered_technique_count:'?')+' / '+(summary?summary.total_technique_count:'?')+'</span>'
    + '</div></div>';

  // Sessions table
  h += '<div class="r-section"><div class="r-h2">Session Inventory</div>'
    + '<div class="tbl-wrap"><table><thead><tr>'
    + '<th>Host</th><th>Session ID</th><th>Registered</th><th>Last Seen</th><th>Label</th><th>Tasks</th><th>Creds</th>'
    + '</tr></thead><tbody>'
    + (sessions||[]).map(s =>
      '<tr><td>'+esc(s.host||'?')+'</td>'
      + '<td style="font-family:monospace;font-size:11px">'+esc(s.id||'')+'</td>'
      + '<td>'+esc(fmtDt(s.registered_at))+'</td>'
      + '<td>'+esc(fmtDt(s.last_seen))+'</td>'
      + '<td>'+esc(s.label||'')+'</td>'
      + '<td>'+(s.task_count||0)+'</td>'
      + '<td>'+((s.cred_tasks||0)>0?'YES':'—')+'</td></tr>'
    ).join('')
    + '</tbody></table></div></div>';

  // Credentials
  if (creds && creds.length) {
    h += '<div class="r-section"><div class="r-h2">Credential Findings ('+creds.length+')</div>'
      + '<div class="tbl-wrap"><table><thead><tr>'
      + '<th>Time</th><th>Session</th><th>Command</th><th>Types</th>'
      + '</tr></thead><tbody>'
      + creds.map(r => {
        const types = [...new Set((r.cred_hints||[]).map(hint => {
          const lh = hint.toLowerCase();
          if (lh.includes('ntlm')) return 'NTLM Hash';
          if (lh.includes('kerberoast')) return 'Kerberoast';
          if (lh.includes('asrep')) return 'AS-REP Roast';
          if (lh.includes('plaintext')) return 'Plaintext';
          if (lh.includes('aes-key')) return 'AES Key';
          return 'Credential';
        }))].join(', ');
        return '<tr>'
          + '<td>'+esc(fmtDt(r.received_at))+'</td>'
          + '<td style="font-family:monospace;font-size:11px">'+esc(shortId(r.session_id))+'</td>'
          + '<td style="font-family:monospace;font-size:11px">'+esc(r.command||'')+'</td>'
          + '<td>'+esc(types)+'</td></tr>';
      }).join('')
      + '</tbody></table></div></div>';
  }

  // ATT&CK coverage
  const covTotal = Object.keys(covered).length;
  const allTotal = Object.keys(allTech).length;
  h += '<div class="r-section"><div class="r-h2">ATT&amp;CK Coverage ('+covTotal+'/'+allTotal+' techniques)</div>'
    + tactics.map(tac => {
      const techs = byTac[tac]||[];
      if (!techs.length) return '';
      return '<div style="margin-bottom:14px">'
        + '<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--accent);margin-bottom:6px">'+esc(tac)+'</div>'
        + techs.map(t => {
          const cnt = covered[t.tid] ? covered[t.tid].length : 0;
          const cls = cnt ? 'chip chip-on' : 'chip chip-off';
          return '<span class="'+cls+'">'+esc(t.tid)+' '+esc(t.name)+(cnt?' ×'+cnt:'')+'</span>';
        }).join('')
        + '</div>';
    }).join('')
    + '</div>';

  document.getElementById('report-content').innerHTML = h;
}

// ── Refresh ────────────────────────────────────────────────────────────────────
async function refresh() {
  const dot = document.getElementById('status-dot');
  const ref = document.getElementById('last-refresh');
  dot.className = 'dot dot-spin';
  try {
    const v = S.view;
    if (v === 'dashboard') {
      renderDashboard(await api('/ui/api/summary'));
    } else if (v === 'sessions') {
      renderSessions(await api('/ui/api/sessions'));
    } else if (v === 'credentials') {
      renderCredentials(await api('/ui/api/credentials'));
    } else if (v === 'attack') {
      renderAttack(await api('/ui/api/techniques'));
    } else if (v === 'report') {
      const [sum,sess,cred,tech] = await Promise.all([
        api('/ui/api/summary'), api('/ui/api/sessions'),
        api('/ui/api/credentials'), api('/ui/api/techniques'),
      ]);
      renderReport(sum, sess, cred, tech);
    }
    dot.className = 'dot dot-ok';
    ref.textContent = new Date().toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
  } catch(e) {
    dot.className = 'dot dot-err';
    ref.textContent = 'error';
    console.error('UI refresh failed:', e);
  }
}

// ── Init ───────────────────────────────────────────────────────────────────────
document.querySelectorAll('.nav-link').forEach(a =>
  a.addEventListener('click', e => { e.preventDefault(); navigate(a.dataset.view); })
);
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""
