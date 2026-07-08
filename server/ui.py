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
<title>LILITH // C2</title>
<style>
:root {
  --bg:     #060606;
  --surf:   #0d0d0d;
  --surf2:  #121212;
  --surf3:  #181818;
  --border: #1e1e1e;
  --bord2:  #272727;
  --red:    #c81e1e;
  --red2:   #ef4444;
  --red3:   rgba(200,30,30,.15);
  --red4:   rgba(200,30,30,.07);
  --text:   #cccccc;
  --muted:  #3d3d3d;
  --muted2: #6a6a6a;
  --green:  #15803d;
  --yellow: #a16207;
  --mono:   'Cascadia Code','Consolas','JetBrains Mono',monospace;
  --sw:     228px;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:var(--bg);color:var(--text);
  font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;line-height:1.5}
body::after{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:9999;
  background:repeating-linear-gradient(
    0deg,transparent 0,transparent 3px,
    rgba(0,0,0,.09) 3px,rgba(0,0,0,.09) 4px)}
#layout{display:flex;height:100vh;overflow:hidden}

/* ── Sidebar ── */
#sidebar{
  width:var(--sw);flex-shrink:0;background:var(--surf);
  border-right:1px solid #1c0000;display:flex;flex-direction:column;
  box-shadow:3px 0 18px rgba(0,0,0,.5)}
.logo{
  padding:22px 18px 18px;border-bottom:1px solid #1c0000;
  display:flex;align-items:center;gap:12px}
.logo-sigil{
  flex-shrink:0;
  filter:drop-shadow(0 0 6px rgba(200,30,30,.75))
         drop-shadow(0 0 14px rgba(200,30,30,.35))}
.logo-name{
  font-size:19px;font-weight:900;letter-spacing:4px;
  color:var(--text);line-height:1}
.logo-name em{color:var(--red2);font-style:normal}
.logo-sub{
  font-size:8px;letter-spacing:5px;color:var(--muted2);
  margin-top:3px;text-transform:uppercase}
.nav-sec{flex:1;overflow-y:auto;padding:8px 0 12px}
.nav-lbl{
  font-size:9px;letter-spacing:3px;color:var(--muted);
  text-transform:uppercase;padding:12px 18px 4px;font-weight:700}
.nav-link{
  display:flex;align-items:center;gap:10px;padding:10px 18px;
  color:var(--muted2);text-decoration:none;font-size:11px;
  letter-spacing:1.2px;text-transform:uppercase;font-weight:500;
  border-left:3px solid transparent;transition:all .12s;
  cursor:pointer;user-select:none}
.nav-link:hover{
  color:var(--text);background:var(--red4);
  border-left-color:rgba(200,30,30,.3)}
.nav-link.active{
  color:var(--red2);background:var(--red3);
  border-left-color:var(--red);
  text-shadow:0 0 12px rgba(239,68,68,.4)}
.nav-ico{font-size:12px;width:16px;text-align:center;flex-shrink:0;opacity:.8}
.nav-bot{
  padding:12px 18px;border-top:1px solid #1c0000;
  display:flex;align-items:center;gap:8px}
.sdot{
  width:7px;height:7px;border-radius:50%;
  background:var(--muted);flex-shrink:0;transition:background .3s}
.sdot.ok{background:var(--red);box-shadow:0 0 8px var(--red),0 0 16px rgba(200,30,30,.4)}
.sdot.err{background:#2a2a2a}
.sdot.spin{background:var(--red2);animation:blink .9s ease infinite}
@keyframes blink{0%,100%{opacity:.15}50%{opacity:1}}
#last-refresh{
  font-size:10px;letter-spacing:1px;color:var(--muted2);
  text-transform:uppercase;font-family:var(--mono)}

/* ── Main area ── */
#main{flex:1;overflow:auto;padding:26px 30px;background:var(--bg)}
.view{display:none!important}
.view.active{display:block!important}
.page-hdr{
  margin-bottom:22px;padding-bottom:14px;
  border-bottom:1px solid var(--border)}
.page-title{
  font-size:17px;font-weight:800;letter-spacing:2px;
  text-transform:uppercase;color:var(--text)}
.page-title .sl{color:var(--red);margin-right:5px;font-weight:400}
.page-sub{
  font-size:10px;color:var(--muted2);
  letter-spacing:2px;margin-top:4px;text-transform:uppercase}

/* ── Stat cards ── */
.cards{
  display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
  gap:10px;margin-bottom:22px}
.card{
  background:var(--surf);border:1px solid var(--border);
  border-top:2px solid var(--bord2);border-radius:3px;
  padding:14px 16px;position:relative;overflow:hidden}
.card::before{
  content:'';position:absolute;top:0;left:0;right:0;
  height:2px;background:transparent;transition:background .3s}
.card.danger{border-top-color:var(--red)}
.card.danger .cv{
  color:var(--red2);
  text-shadow:0 0 20px rgba(239,68,68,.55)}
.card.accent{border-top-color:#7f1d1d}
.clbl{
  font-size:9px;color:var(--muted2);text-transform:uppercase;
  letter-spacing:2px;margin-bottom:9px;font-weight:700}
.cv{
  font-size:30px;font-weight:700;line-height:1;
  font-family:var(--mono);color:var(--text)}
.csub{font-size:10px;color:var(--muted2);margin-top:5px;letter-spacing:.5px}

/* ── Panels ── */
.panels{
  display:grid;grid-template-columns:1fr 1fr;
  gap:12px;margin-bottom:22px}
@media(max-width:860px){.panels{grid-template-columns:1fr}}
.panel{
  background:var(--surf);border:1px solid var(--border);
  border-radius:3px;padding:14px 16px;min-height:150px}
.ptitle{
  font-size:9px;font-weight:700;color:var(--muted2);
  text-transform:uppercase;letter-spacing:3px;
  margin-bottom:12px;padding-bottom:8px;
  border-bottom:1px solid var(--border);
  display:flex;justify-content:space-between;align-items:center}

/* ── Tables ── */
.tbl-wrap{
  overflow-x:auto;border-radius:3px;
  border:1px solid var(--border)}
table{width:100%;border-collapse:collapse}
th{
  background:var(--surf2);color:var(--muted2);font-size:9px;
  font-weight:700;text-transform:uppercase;letter-spacing:2px;
  padding:8px 12px;text-align:left;
  border-bottom:1px solid var(--border);white-space:nowrap}
td{
  padding:9px 12px;border-bottom:1px solid var(--border);
  vertical-align:top;font-size:12px;color:var(--text)}
tr:last-child td{border-bottom:none}
tr.clickable:hover td{background:var(--surf2);cursor:pointer}
tr.selected td{background:rgba(200,30,30,.06)}
tr.selected td:first-child{border-left:3px solid var(--red)}

/* ── Badges ── */
.badge{
  display:inline-block;padding:1px 7px;border-radius:2px;
  font-size:9px;font-weight:700;letter-spacing:1px;
  line-height:1.9;text-transform:uppercase;border:1px solid}
.b-ntlm{background:rgba(200,30,30,.16);color:#f87171;border-color:rgba(200,30,30,.4)}
.b-kerb{background:rgba(180,83,9,.16);color:#fbbf24;border-color:rgba(180,83,9,.4)}
.b-plain{background:rgba(21,128,61,.14);color:#4ade80;border-color:rgba(21,128,61,.4)}
.b-aes{background:rgba(37,99,235,.14);color:#93c5fd;border-color:rgba(37,99,235,.4)}
.b-cred{background:rgba(200,30,30,.16);color:#f87171;border-color:rgba(200,30,30,.4)}
.b-ok{background:rgba(21,128,61,.12);color:#4ade80;border-color:rgba(21,128,61,.35)}
.b-warn{background:rgba(180,83,9,.12);color:#fbbf24;border-color:rgba(180,83,9,.35)}
.b-info{background:rgba(37,99,235,.12);color:#93c5fd;border-color:rgba(37,99,235,.35)}
.b-grey{background:rgba(255,255,255,.04);color:var(--muted2);border-color:var(--bord2)}

/* ── ATT&CK chips ── */
.chip{
  display:inline-block;padding:3px 8px;border-radius:2px;
  font-size:10px;margin:2px;cursor:default;transition:all .1s;
  font-family:var(--mono);border:1px solid}
.chip-on{
  background:rgba(200,30,30,.16);color:var(--red2);
  border-color:rgba(200,30,30,.45);
  text-shadow:0 0 8px rgba(239,68,68,.3)}
.chip-on:hover{background:rgba(200,30,30,.26)}
.chip-off{background:var(--surf2);color:var(--muted2);border-color:var(--border)}
.chip-cnt{font-size:9px;opacity:.65;margin-left:3px}
.tactic-sec{margin-bottom:18px}
.tactic-hdr{
  font-size:9px;font-weight:700;text-transform:uppercase;
  letter-spacing:3px;color:var(--red);margin-bottom:8px;padding:5px 0;
  border-bottom:1px solid var(--border);
  display:flex;justify-content:space-between;align-items:center}
.tactic-score{color:var(--muted2);font-weight:400;letter-spacing:1px}

/* ── Session detail ── */
#session-detail{
  background:var(--surf);border:1px solid var(--border);
  border-radius:3px;border-top:2px solid var(--red);
  padding:18px;margin-top:14px}
.det-hdr{
  display:flex;align-items:center;gap:12px;margin-bottom:14px;
  padding-bottom:12px;border-bottom:1px solid var(--border)}
.det-title{
  font-size:12px;font-weight:700;flex:1;font-family:var(--mono);
  letter-spacing:.5px;text-transform:uppercase;color:var(--text)}
.label-form{
  display:flex;gap:8px;align-items:center;
  flex-wrap:wrap;margin-bottom:14px}
.label-form input{
  flex:1;min-width:110px;padding:6px 10px;
  background:var(--surf2);border:1px solid var(--bord2);
  border-radius:3px;color:var(--text);font-size:12px;outline:none}
.label-form input:focus{border-color:var(--red)}

/* ── Buttons ── */
.btn{
  display:inline-block;padding:6px 14px;border-radius:3px;
  border:1px solid var(--bord2);background:transparent;
  color:var(--muted2);font-size:10px;cursor:pointer;text-decoration:none;
  transition:all .12s;text-transform:uppercase;letter-spacing:1px;font-weight:600}
.btn:hover{border-color:var(--red);color:var(--red2);background:var(--red4)}
.btn-primary{
  background:var(--red3);border-color:var(--red);color:var(--red2)}
.btn-primary:hover{
  background:rgba(200,30,30,.22);
  box-shadow:0 0 12px rgba(200,30,30,.2)}
.btn-sm{padding:3px 10px;font-size:10px}
.hrow{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:22px}
.hrow .page-title{margin:0}.hrow-titles{flex:1}
.btn-row{display:flex;gap:8px;flex-wrap:wrap}

/* ── Tasks ── */
.task-item{
  padding:10px 12px;border-radius:3px;margin-bottom:8px;
  background:var(--surf2);border-left:3px solid var(--bord2)}
.task-item.t-cred{border-left-color:var(--red)}
.task-item.t-pend{border-left-color:#a16207}
.task-item.t-done{border-left-color:#15803d}
.task-cmd{
  font-family:var(--mono);font-size:11px;color:var(--text);
  margin-bottom:5px;word-break:break-all}
.task-meta{
  display:flex;gap:8px;flex-wrap:wrap;
  align-items:center;font-size:10px;color:var(--muted2)}
.task-out{
  margin-top:8px;background:var(--bg);border-radius:3px;
  padding:8px;font-family:var(--mono);font-size:11px;color:var(--muted2);
  white-space:pre-wrap;max-height:180px;overflow-y:auto;
  border:1px solid var(--border)}

/* ── Events ── */
.ev-item{
  padding:6px 0;border-bottom:1px solid var(--border);
  display:flex;gap:10px;align-items:flex-start}
.ev-item:last-child{border-bottom:none}
.ev-time{
  color:var(--muted2);font-size:10px;white-space:nowrap;
  min-width:40px;font-family:var(--mono)}
.ev-type{
  font-size:9px;font-weight:700;text-transform:uppercase;
  color:var(--red);min-width:80px;letter-spacing:1px}
.ev-detail{font-size:11px;color:var(--muted2);word-break:break-all}

/* ── Misc ── */
.empty{
  text-align:center;padding:36px;color:var(--muted2);
  letter-spacing:1px;font-size:11px;text-transform:uppercase}
.empty-icon{font-size:22px;margin-bottom:8px;opacity:.2}
.r-section{margin-bottom:26px}
.r-h1{
  font-size:19px;font-weight:900;margin-bottom:4px;
  letter-spacing:3px;text-transform:uppercase}
.r-h1 em{color:var(--red);font-style:normal}
.r-h2{
  font-size:9px;font-weight:700;color:var(--muted2);
  text-transform:uppercase;letter-spacing:3px;
  margin-bottom:12px;padding-bottom:6px;
  border-bottom:1px solid var(--border)}
.r-meta{
  display:flex;gap:20px;margin-bottom:20px;
  color:var(--muted2);font-size:11px;flex-wrap:wrap;letter-spacing:.5px}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--bord2);border-radius:2px}
@keyframes spin{to{transform:rotate(360deg)}}
.spin{display:inline-block;animation:spin .8s linear infinite}
@media print{
  #sidebar,.btn,.btn-row,button{display:none!important}
  #main{padding:0}
  #view-report{display:block!important}
  body,html{background:#fff;color:#000;height:auto}
  #layout{display:block;height:auto}
  .card,.panel,.tbl-wrap{break-inside:avoid}
  .card{background:#f5f5f5;border-color:#ddd}
  th{background:#eee;color:#333}
}
</style>
</head>
<body>
<div id="layout">

<nav id="sidebar">
  <div class="logo">
    <svg class="logo-sigil" viewBox="0 0 34 34" width="30" height="30" fill="none"
         xmlns="http://www.w3.org/2000/svg">
      <defs>
        <filter id="rglow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="1.5" result="blur"/>
          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>
      <polygon points="17,2 32,30 2,30"
               stroke="#c81e1e" stroke-width="1.8"
               fill="rgba(200,30,30,.08)" filter="url(#rglow)"/>
      <line x1="17" y1="15" x2="17" y2="28"
            stroke="#c81e1e" stroke-width="1.5" opacity=".75"/>
      <circle cx="17" cy="13" r="2.8" fill="#c81e1e"/>
    </svg>
    <div>
      <div class="logo-name"><em>L</em>ILITH</div>
      <div class="logo-sub">Operations Center</div>
    </div>
  </div>

  <div class="nav-sec">
    <div class="nav-lbl">Navigation</div>
    <a class="nav-link active" data-view="dashboard">
      <span class="nav-ico">&#9654;</span>Dashboard
    </a>
    <a class="nav-link" data-view="sessions">
      <span class="nav-ico">&#9711;</span>Sessions
    </a>
    <a class="nav-link" data-view="credentials">
      <span class="nav-ico">&#9671;</span>Credentials
    </a>
    <a class="nav-link" data-view="attack">
      <span class="nav-ico">&#10010;</span>ATT&amp;CK
    </a>
    <a class="nav-link" data-view="report">
      <span class="nav-ico">&#9672;</span>Report
    </a>
  </div>

  <div class="nav-bot">
    <div class="sdot spin" id="sdot"></div>
    <span id="last-refresh">connecting&hellip;</span>
  </div>
</nav>

<main id="main">

<!-- dashboard -->
<div id="view-dashboard" class="view active">
  <div class="page-hdr">
    <div class="page-title">
      <span class="sl">//</span>Operations Dashboard
    </div>
    <div class="page-sub">Live engagement telemetry &nbsp;&middot;&nbsp; Auto-refresh 5s</div>
  </div>
  <div class="cards">
    <div class="card">
      <div class="clbl">Sessions</div>
      <div class="cv" id="d-sess">0</div>
      <div class="csub">Active agents</div>
    </div>
    <div class="card">
      <div class="clbl">Tasks</div>
      <div class="cv" id="d-tasks">0</div>
      <div class="csub">Dispatched</div>
    </div>
    <div class="card danger">
      <div class="clbl">Credentials</div>
      <div class="cv" id="d-creds">0</div>
      <div class="csub">Captured</div>
    </div>
    <div class="card accent">
      <div class="clbl">ATT&amp;CK</div>
      <div class="cv" id="d-techs">0</div>
      <div class="csub" id="d-techs-sub">Covered</div>
    </div>
    <div class="card">
      <div class="clbl">Events</div>
      <div class="cv" id="d-evts">0</div>
      <div class="csub">Total logged</div>
    </div>
  </div>
  <div class="panels">
    <div class="panel">
      <div class="ptitle"><span>Top Techniques</span></div>
      <div id="dash-techs">
        <div class="empty"><div class="empty-icon">&#9672;</div>No data yet</div>
      </div>
    </div>
    <div class="panel">
      <div class="ptitle"><span>Recent Events</span></div>
      <div id="dash-evts">
        <div class="empty"><div class="empty-icon">&#9672;</div>No events yet</div>
      </div>
    </div>
  </div>
</div>

<!-- sessions -->
<div id="view-sessions" class="view">
  <div class="page-hdr">
    <div class="page-title"><span class="sl">//</span>Agent Sessions</div>
    <div class="page-sub">Click a row to inspect tasks and results</div>
  </div>
  <div class="tbl-wrap"><table>
    <thead><tr>
      <th>Host</th><th>Session ID</th><th>Registered</th>
      <th>Last Seen</th><th>Label</th><th>Tasks</th><th>Creds</th>
    </tr></thead>
    <tbody id="sess-tbody">
      <tr><td colspan="7"><div class="empty">Loading&hellip;</div></td></tr>
    </tbody>
  </table></div>
  <div id="session-detail" style="display:none"></div>
</div>

<!-- credentials -->
<div id="view-credentials" class="view">
  <div class="page-hdr">
    <div class="page-title"><span class="sl">//</span>Credential Findings</div>
    <div class="page-sub">All results containing credential material</div>
  </div>
  <div class="tbl-wrap"><table>
    <thead><tr>
      <th>Time</th><th>Session</th><th>Command</th><th>Types</th><th>Preview</th>
    </tr></thead>
    <tbody id="creds-tbody">
      <tr><td colspan="5"><div class="empty">Loading&hellip;</div></td></tr>
    </tbody>
  </table></div>
</div>

<!-- attack -->
<div id="view-attack" class="view">
  <div class="page-hdr">
    <div class="page-title"><span class="sl">//</span>MITRE ATT&amp;CK Coverage</div>
    <div class="page-sub">Techniques observed &nbsp;&middot;&nbsp; Red = covered</div>
  </div>
  <div id="attack-heatmap">
    <div class="empty">Loading&hellip;</div>
  </div>
</div>

<!-- report -->
<div id="view-report" class="view">
  <div class="hrow">
    <div class="hrow-titles">
      <div class="page-title"><span class="sl">//</span>Engagement Report</div>
      <div class="page-sub">Printable summary for client / purple team</div>
    </div>
    <div class="btn-row">
      <button class="btn btn-primary btn-sm" onclick="window.print()">Print / PDF</button>
      <a class="btn btn-sm" href="/ui/api/export/json" download="engagement.json">&#8595; JSON</a>
      <a class="btn btn-sm" href="/ui/api/export/markdown" download="engagement.md">&#8595; Markdown</a>
    </div>
  </div>
  <div id="report-content">
    <div class="empty">Loading&hellip;</div>
  </div>
</div>

</main>
</div>
<script>
'use strict';

function esc(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtDt(s) {
  if (!s) return '—';
  try {
    const d = new Date(s.includes('T') ? s : s.replace(' ', 'T') + 'Z');
    if (isNaN(d)) return s;
    return d.toLocaleString(undefined, {
      month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', hour12: false
    });
  } catch(e) { return s; }
}

function shortId(id) { return id ? '…' + id.slice(-8) : '—'; }

function credBadges(hints) {
  if (!hints || !hints.length) return '';
  const seen = new Set(), out = [];
  for (const h of hints) {
    const lh = h.toLowerCase();
    let tag, cls;
    if      (lh.includes('ntlm'))       { tag = 'NTLM';  cls = 'b-ntlm'; }
    else if (lh.includes('kerberoast')) { tag = 'KERB';  cls = 'b-kerb'; }
    else if (lh.includes('asrep'))      { tag = 'ASREP'; cls = 'b-kerb'; }
    else if (lh.includes('plaintext'))  { tag = 'PLAIN'; cls = 'b-plain'; }
    else if (lh.includes('aes-key'))    { tag = 'AES';   cls = 'b-aes'; }
    else                                { tag = 'CRED';  cls = 'b-cred'; }
    if (!seen.has(tag)) {
      seen.add(tag);
      out.push('<span class="badge ' + cls + '">' + tag + '</span>');
    }
  }
  return out.join(' ');
}

const S = { view: 'dashboard', selSess: null };

async function api(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

function navigate(view) {
  if (!view) return;
  S.view = view;
  document.querySelectorAll('.nav-link').forEach(function(a) {
    a.classList.toggle('active', a.dataset.view === view);
  });
  document.querySelectorAll('.view').forEach(function(v) {
    v.classList.toggle('active', v.id === 'view-' + view);
  });
  refresh();
}

/* ── Dashboard ── */
function renderDashboard(d) {
  document.getElementById('d-sess').textContent  = d.session_count;
  document.getElementById('d-tasks').textContent = d.task_count;
  document.getElementById('d-creds').textContent = d.cred_count;
  document.getElementById('d-evts').textContent  = d.event_count;
  const pct = d.total_technique_count
    ? Math.round(100 * d.covered_technique_count / d.total_technique_count) : 0;
  document.getElementById('d-techs').textContent    = d.covered_technique_count;
  document.getElementById('d-techs-sub').textContent = pct + '% of ' + d.total_technique_count;

  const tt = document.getElementById('dash-techs');
  if (!d.top_techniques || !d.top_techniques.length) {
    tt.innerHTML = '<div class="empty"><div class="empty-icon">&#9672;</div>No techniques recorded</div>';
  } else {
    tt.innerHTML = d.top_techniques.map(function(t) {
      return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:9px">'
        + '<span class="chip chip-on" style="font-size:10px">' + esc(t.tid) + '</span>'
        + '<span style="flex:1;font-size:12px">' + esc(t.name) + '</span>'
        + '<span style="color:var(--muted2);font-size:10px;font-family:var(--mono)">\xd7' + t.count + '</span>'
        + '</div>';
    }).join('');
  }

  const ev = document.getElementById('dash-evts');
  if (!d.recent_events || !d.recent_events.length) {
    ev.innerHTML = '<div class="empty"><div class="empty-icon">&#9672;</div>No events yet</div>';
  } else {
    ev.innerHTML = d.recent_events.map(function(e) {
      return '<div class="ev-item">'
        + '<span class="ev-time">' + esc((e.at || '').slice(11, 16)) + '</span>'
        + '<span class="ev-type">'  + esc(e.type   || '') + '</span>'
        + '<span class="ev-detail">' + esc((e.detail || '').slice(0, 72)) + '</span>'
        + '</div>';
    }).join('');
  }
}

/* ── Sessions ── */
function renderSessions(data) {
  const tbody = document.getElementById('sess-tbody');
  if (!data.length) {
    tbody.innerHTML = '<tr><td colspan="7"><div class="empty">'
      + '<div class="empty-icon">&#9711;</div>No sessions registered</div></td></tr>';
    return;
  }
  tbody.innerHTML = data.map(function(s) {
    const sel = S.selSess === s.id ? ' selected' : '';
    return '<tr class="clickable' + sel + '" data-id="' + esc(s.id) + '">'
      + '<td><b>' + esc(s.host || '—') + '</b></td>'
      + '<td style="font-family:var(--mono);font-size:11px;color:var(--muted2)">'
        + esc(shortId(s.id)) + '</td>'
      + '<td style="white-space:nowrap;font-size:11px">' + esc(fmtDt(s.registered_at)) + '</td>'
      + '<td style="white-space:nowrap;font-size:11px">' + esc(fmtDt(s.last_seen)) + '</td>'
      + '<td>' + (s.label
        ? '<span class="badge b-info">' + esc(s.label) + '</span>'
        : '<span style="color:var(--muted2)">—</span>') + '</td>'
      + '<td style="font-family:var(--mono)">' + (s.task_count || 0) + '</td>'
      + '<td>' + ((s.cred_tasks || 0) > 0
        ? '<span class="badge b-cred">CRED</span>'
        : '<span class="badge b-grey">—</span>') + '</td>'
      + '</tr>';
  }).join('');
  tbody.querySelectorAll('tr.clickable').forEach(function(tr) {
    tr.addEventListener('click', function() { openSession(tr.dataset.id); });
  });
}

async function openSession(id) {
  S.selSess = id;
  document.querySelectorAll('#sess-tbody tr').forEach(function(tr) {
    tr.classList.toggle('selected', tr.dataset.id === id);
  });
  const det = document.getElementById('session-detail');
  det.style.display = 'block';
  det.innerHTML = '<div style="padding:24px;text-align:center;color:var(--muted2)">'
    + '<span class="spin">&#9675;</span> Loading&hellip;</div>';
  try {
    const d = await api('/ui/api/session/' + encodeURIComponent(id));
    renderSessionDetail(d, det);
  } catch(e) {
    det.innerHTML = '<div class="empty">Error: ' + esc(String(e)) + '</div>';
  }
}

function renderSessionDetail(d, el) {
  const s = d.session || {}, tasks = d.tasks || [], evts = d.events || [];
  let h = '<div class="det-hdr">'
    + '<div class="det-title">' + esc(s.host || '?')
    + ' <span style="color:var(--muted2);font-size:10px">' + esc(s.id || '') + '</span></div>'
    + '<button class="btn btn-sm" onclick="'
    + "document.getElementById('session-detail').style.display='none';S.selSess=null;"
    + '">✕ Close</button>'
    + '</div>'
    + '<div class="label-form">'
    + '<input id="det-label" placeholder="Label (e.g. DC01)" value="' + esc(s.label || '') + '">'
    + '<input id="det-note"  placeholder="Operator note…"   value="' + esc(s.note  || '') + '" style="flex:2">'
    + '<button class="btn btn-primary btn-sm" onclick="saveLabel(\'' + esc(s.id) + '\')">Save</button>'
    + '</div>';

  if (!tasks.length) {
    h += '<div class="empty"><div class="empty-icon">&#9672;</div>No tasks dispatched yet</div>';
  } else {
    h += '<div style="font-size:9px;font-weight:700;color:var(--muted2);'
      + 'text-transform:uppercase;letter-spacing:3px;margin-bottom:10px">'
      + 'Task Timeline (' + tasks.length + ')</div>';
    h += tasks.map(function(t) {
      const done  = t.output != null;
      const hcred = t.has_creds;
      const cls   = 'task-item ' + (hcred ? 't-cred' : done ? 't-done' : 't-pend');
      let inner = '<div class="task-cmd">' + esc(t.command || '') + '</div>'
        + '<div class="task-meta">';
      if (t.technique_id) {
        inner += '<span class="badge b-info">' + esc(t.technique_id) + '</span>'
               + '<span>' + esc(t.technique_desc || '') + '</span>';
      }
      inner += '<span style="margin-left:auto">' + esc(fmtDt(t.dispatched_at)) + '</span>';
      if (!done)       inner += '<span class="badge b-warn">pending</span>';
      else if (hcred)  inner += '<span class="badge b-cred">CREDS</span>';
      else             inner += '<span class="badge b-ok">done</span>';
      inner += '</div>';
      if (t.cred_hints && t.cred_hints.length) {
        inner += '<div style="margin-top:6px;font-size:11px;color:var(--muted2)">'
          + t.cred_hints.slice(0, 4).map(function(h2) {
              return esc(h2.slice(0, 100));
            }).join('<br>') + '</div>';
      }
      if (done && !t.is_binary && t.output) {
        inner += '<div class="task-out">'
          + esc(t.output.slice(0, 600))
          + (t.output.length > 600 ? '\n…' : '') + '</div>';
      } else if (t.is_binary) {
        inner += '<div class="task-out">[binary data]</div>';
      }
      return '<div class="' + cls + '">' + inner + '</div>';
    }).join('');
  }

  if (evts.length) {
    h += '<div style="font-size:9px;font-weight:700;color:var(--muted2);'
      + 'text-transform:uppercase;letter-spacing:3px;margin:16px 0 8px">'
      + 'Session Events (' + evts.length + ')</div>';
    h += evts.slice(-20).reverse().map(function(e) {
      return '<div class="ev-item">'
        + '<span class="ev-time">'   + esc((e.at     || '').slice(11, 16)) + '</span>'
        + '<span class="ev-type">'   + esc(e.type    || '') + '</span>'
        + '<span class="ev-detail">' + esc(e.detail  || '') + '</span>'
        + '</div>';
    }).join('');
  }
  el.innerHTML = h;
}

async function saveLabel(id) {
  const label = (document.getElementById('det-label') || {}).value || '';
  const note  = (document.getElementById('det-note')  || {}).value || '';
  try {
    await fetch('/ui/api/sessions/' + encodeURIComponent(id) + '/label', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label: label.trim(), note: note.trim() })
    });
    api('/ui/api/sessions').then(renderSessions);
  } catch(e) { console.error(e); }
}

/* ── Credentials ── */
function renderCredentials(data) {
  const tbody = document.getElementById('creds-tbody');
  if (!data.length) {
    tbody.innerHTML = '<tr><td colspan="5"><div class="empty">'
      + '<div class="empty-icon">&#9671;</div>No credentials captured yet</div></td></tr>';
    return;
  }
  tbody.innerHTML = data.map(function(r) {
    const prev = (r.output || '').replace(/\n/g, ' ').slice(0, 100);
    return '<tr>'
      + '<td style="white-space:nowrap;font-size:11px">' + esc(fmtDt(r.received_at)) + '</td>'
      + '<td style="font-family:var(--mono);font-size:11px;color:var(--muted2)">'
        + esc(shortId(r.session_id)) + '</td>'
      + '<td style="font-family:var(--mono);font-size:11px;max-width:180px;'
        + 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'
        + esc(r.command || '') + '</td>'
      + '<td>' + credBadges(r.cred_hints) + '</td>'
      + '<td style="color:var(--muted2);font-size:11px;font-family:var(--mono);'
        + 'max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'
        + esc(prev) + '</td>'
      + '</tr>';
  }).join('');
}

/* ── ATT&CK ── */
function renderAttack(data) {
  const covered  = data.covered        || {};
  const allTech  = data.all_techniques || {};
  const tactics  = data.tactic_order   || [];
  const byTac    = {};
  for (const tid in allTech) {
    const m   = allTech[tid];
    const tac = m.tactic || 'Other';
    if (!byTac[tac]) byTac[tac] = [];
    byTac[tac].push(Object.assign({ tid: tid }, m));
  }
  document.getElementById('attack-heatmap').innerHTML = tactics.map(function(tac) {
    const techs = byTac[tac] || [];
    if (!techs.length) return '';
    const cov = techs.filter(function(t) { return covered[t.tid]; }).length;
    return '<div class="tactic-sec">'
      + '<div class="tactic-hdr"><span>' + esc(tac) + '</span>'
      + '<span class="tactic-score">' + cov + ' / ' + techs.length + '</span></div>'
      + '<div>' + techs.map(function(t) {
          const cnt = covered[t.tid] ? covered[t.tid].length : 0;
          return '<span class="chip ' + (cnt ? 'chip-on' : 'chip-off') + '"'
            + (cnt ? ' title="' + cnt + ' session(s)"' : '') + '>'
            + esc(t.tid) + ' ' + esc(t.name)
            + (cnt ? '<span class="chip-cnt">\xd7' + cnt + '</span>' : '')
            + '</span>';
        }).join('') + '</div></div>';
  }).join('');
}

/* ── Report ── */
function renderReport(summary, sessions, creds, techniques) {
  const now      = new Date().toLocaleDateString(undefined,
    { year: 'numeric', month: 'long', day: 'numeric' });
  const covered  = (techniques || {}).covered        || {};
  const allTech  = (techniques || {}).all_techniques || {};
  const tactics  = (techniques || {}).tactic_order   || [];
  const byTac    = {};
  for (const tid in allTech) {
    const m   = allTech[tid];
    const tac = m.tactic || 'Other';
    if (!byTac[tac]) byTac[tac] = [];
    byTac[tac].push(Object.assign({ tid: tid }, m));
  }

  let h = '<div class="r-section"><div class="r-h1"><em>L</em>ILITH — Engagement Report</div>'
    + '<div class="r-meta">'
    + '<span>Generated: ' + esc(now) + '</span>'
    + '<span>Sessions: '   + (summary ? summary.session_count : '?') + '</span>'
    + '<span>Tasks: '      + (summary ? summary.task_count    : '?') + '</span>'
    + '<span>Credentials: '+ (summary ? summary.cred_count    : '?') + '</span>'
    + '<span>ATT&amp;CK: ' + (summary ? summary.covered_technique_count : '?')
    + ' / '                + (summary ? summary.total_technique_count   : '?') + '</span>'
    + '</div></div>';

  h += '<div class="r-section"><div class="r-h2">Session Inventory</div>'
    + '<div class="tbl-wrap"><table><thead><tr>'
    + '<th>Host</th><th>Session ID</th><th>Registered</th>'
    + '<th>Last Seen</th><th>Label</th><th>Tasks</th><th>Creds</th>'
    + '</tr></thead><tbody>'
    + (sessions || []).map(function(s) {
        return '<tr>'
          + '<td>' + esc(s.host || '?') + '</td>'
          + '<td style="font-family:var(--mono);font-size:11px">' + esc(s.id || '') + '</td>'
          + '<td>' + esc(fmtDt(s.registered_at)) + '</td>'
          + '<td>' + esc(fmtDt(s.last_seen)) + '</td>'
          + '<td>' + esc(s.label || '') + '</td>'
          + '<td>' + (s.task_count || 0) + '</td>'
          + '<td>' + ((s.cred_tasks || 0) > 0 ? 'YES' : '—') + '</td>'
          + '</tr>';
      }).join('')
    + '</tbody></table></div></div>';

  if (creds && creds.length) {
    h += '<div class="r-section"><div class="r-h2">Credential Findings (' + creds.length + ')</div>'
      + '<div class="tbl-wrap"><table><thead><tr>'
      + '<th>Time</th><th>Session</th><th>Command</th><th>Types</th>'
      + '</tr></thead><tbody>'
      + creds.map(function(r) {
          const types = [];
          const seen  = new Set();
          (r.cred_hints || []).forEach(function(h2) {
            const lh = h2.toLowerCase();
            let tp;
            if      (lh.includes('ntlm'))       tp = 'NTLM Hash';
            else if (lh.includes('kerberoast')) tp = 'Kerberoast';
            else if (lh.includes('asrep'))      tp = 'AS-REP';
            else if (lh.includes('plaintext'))  tp = 'Plaintext';
            else if (lh.includes('aes-key'))    tp = 'AES Key';
            else                                tp = 'Credential';
            if (!seen.has(tp)) { seen.add(tp); types.push(tp); }
          });
          return '<tr>'
            + '<td>' + esc(fmtDt(r.received_at)) + '</td>'
            + '<td style="font-family:var(--mono);font-size:11px">' + esc(shortId(r.session_id)) + '</td>'
            + '<td style="font-family:var(--mono);font-size:11px">' + esc(r.command || '') + '</td>'
            + '<td>' + esc(types.join(', ')) + '</td>'
            + '</tr>';
        }).join('')
      + '</tbody></table></div></div>';
  }

  const covTotal  = Object.keys(covered).length;
  const allTotal  = Object.keys(allTech).length;
  h += '<div class="r-section"><div class="r-h2">ATT&amp;CK Coverage ('
    + covTotal + '/' + allTotal + ')</div>'
    + tactics.map(function(tac) {
        const techs = byTac[tac] || [];
        if (!techs.length) return '';
        return '<div style="margin-bottom:14px">'
          + '<div style="font-size:9px;font-weight:700;text-transform:uppercase;'
          + 'letter-spacing:3px;color:var(--red);margin-bottom:6px">' + esc(tac) + '</div>'
          + techs.map(function(t) {
              const cnt = covered[t.tid] ? covered[t.tid].length : 0;
              return '<span class="chip ' + (cnt ? 'chip-on' : 'chip-off') + '">'
                + esc(t.tid) + ' ' + esc(t.name)
                + (cnt ? ' \xd7' + cnt : '') + '</span>';
            }).join('')
          + '</div>';
      }).join('')
    + '</div>';

  document.getElementById('report-content').innerHTML = h;
}

/* ── Refresh ── */
async function refresh() {
  const dot = document.getElementById('sdot');
  const ref = document.getElementById('last-refresh');
  dot.className = 'sdot spin';
  try {
    const v = S.view;
    if      (v === 'dashboard')   renderDashboard(await api('/ui/api/summary'));
    else if (v === 'sessions')    renderSessions(await api('/ui/api/sessions'));
    else if (v === 'credentials') renderCredentials(await api('/ui/api/credentials'));
    else if (v === 'attack')      renderAttack(await api('/ui/api/techniques'));
    else if (v === 'report') {
      const results = await Promise.all([
        api('/ui/api/summary'),
        api('/ui/api/sessions'),
        api('/ui/api/credentials'),
        api('/ui/api/techniques'),
      ]);
      renderReport(results[0], results[1], results[2], results[3]);
    }
    dot.className = 'sdot ok';
    ref.textContent = new Date().toLocaleTimeString(undefined, {
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
    });
  } catch(e) {
    dot.className = 'sdot err';
    ref.textContent = 'error';
  }
}

/* ── Init: attach nav handlers ── */
document.querySelectorAll('.nav-link').forEach(function(a) {
  a.addEventListener('click', function(e) {
    e.preventDefault();
    navigate(a.dataset.view);
  });
});
refresh();
setInterval(refresh, 5000);
</script>
</body></html>"""
