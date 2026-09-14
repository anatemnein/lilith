"""
Engagement database — persistent SQLite log of all C2 activity.

Every session registration, task dispatch, result, file transfer, and
screenshot is recorded automatically when 'lilith serve' is running.
The database persists on disk across server restarts so the full
engagement timeline is preserved for purple team review.

Schema:
  sessions  — agent check-ins (host, time, operator label)
  tasks     — commands dispatched (command, time, ATT&CK technique)
  results   — output received (output, time, credential hints)
  events    — everything else (file served, upload, download, screenshot, callback)
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from datetime import datetime
from typing import Any


# ── MITRE ATT&CK command→technique mapping ────────────────────────────────────

_ATTACK_MAP: list[tuple[str, str, str]] = [
    # built-in agent commands
    ("screenshot",          "T1113",     "Collection — Screen Capture"),
    ("download",            "T1041",     "Exfiltration — Exfiltration Over C2 Channel"),
    ("upload",              "T1105",     "Command and Control — Ingress Tool Transfer"),
    ("migrate",             "T1055",     "Defense Evasion — Process Injection"),
    ("wnfinject",           "T1055.015", "Defense Evasion — Process Injection (ListPlanting)"),
    ("fiberexec",           "T1055",     "Defense Evasion — Process Injection (Fiber)"),
    ("comhijack",           "T1546.015", "Persistence — COM Hijacking"),
    ("byovdrun",            "T1068",     "Privilege Escalation — BYOVD Kernel Exploit"),
    ("!persist wmi",        "T1546.003", "Persistence — WMI Event Subscription"),
    ("!persist run",        "T1547.001", "Persistence — Registry Run Key"),
    ("!persist schtask",    "T1053.005", "Persistence — Scheduled Task"),
    # discovery
    ("whoami",              "T1033",     "Discovery — System Owner/User Discovery"),
    ("net user",            "T1087.002", "Discovery — Domain Account Discovery"),
    ("net group",           "T1069.002", "Discovery — Domain Groups Discovery"),
    ("net localgroup",      "T1069.001", "Discovery — Local Groups Discovery"),
    ("ipconfig",            "T1016",     "Discovery — System Network Configuration"),
    ("systeminfo",          "T1082",     "Discovery — System Information Discovery"),
    ("tasklist",            "T1057",     "Discovery — Process Discovery"),
    ("netstat",             "T1049",     "Discovery — System Network Connections"),
    ("net use",             "T1021",     "Lateral Movement — Remote Services"),
    ("dir ",                "T1083",     "Discovery — File and Directory Discovery"),
    ("ls ",                 "T1083",     "Discovery — File and Directory Discovery"),
    ("reg query",           "T1012",     "Discovery — Query Registry"),
    ("arp",                 "T1018",     "Discovery — Remote System Discovery"),
    ("nltest",              "T1482",     "Discovery — Domain Trust Discovery"),
    # credential access
    ("mimikatz",            "T1003",     "Credential Access — OS Credential Dumping"),
    ("rubeus kerberoast",   "T1558.003", "Credential Access — Kerberoasting"),
    ("rubeus asreproast",   "T1558.004", "Credential Access — AS-REP Roasting"),
    ("rubeus asktgt",       "T1558.001", "Credential Access — Golden Ticket / TGT Request"),
    ("rubeus s4u",          "T1558.003", "Lateral Movement — Kerberos S4U Delegation Abuse"),
    ("rubeus ptt",          "T1550.003", "Defense Evasion — Pass the Ticket"),
    ("rubeus diamond",      "T1558.001", "Credential Access — Diamond Ticket"),
    ("rubeus silver",       "T1558.002", "Credential Access — Silver Ticket"),
    ("rubeus triage",       "T1558",     "Discovery — Kerberos Ticket Enumeration"),
    ("rubeus",              "T1558",     "Credential Access — Steal/Forge Kerberos Tickets"),
    ("whisker add",         "T1649",     "Credential Access — Shadow Credentials (Write)"),
    ("whisker",             "T1649",     "Credential Access — Shadow Credentials"),
    ("certify request",     "T1649",     "Credential Access — ADCS Certificate Request"),
    ("certify find",        "T1649",     "Discovery — ADCS Vulnerable Template Enumeration"),
    ("certify",             "T1649",     "Credential Access — Steal Authentication Certificates"),
    ("sharpdpapi",          "T1555",     "Credential Access — Credentials from Password Stores"),
    ("sharpchr",            "T1555.003", "Credential Access — Chrome Saved Credentials"),
    # privilege escalation
    ("sharpup",             "T1068",     "Privilege Escalation — Exploitation for PE"),
    ("godpotato",           "T1134.001", "Privilege Escalation — SeImpersonate Token Abuse"),
    ("printspoofer",        "T1134.001", "Privilege Escalation — SeImpersonate Token Abuse"),
    ("juicypotato",         "T1134.001", "Privilege Escalation — SeImpersonate Token Abuse"),
    ("roguepotato",         "T1134.001", "Privilege Escalation — SeImpersonate Token Abuse"),
    ("roguepla",            "T1068",     "Privilege Escalation — WD Race Condition LPE"),
    ("falconflank",         "T1068",     "Privilege Escalation — CrowdStrike Falcon LPE"),
    ("shieldbreak",         "T1068",     "Privilege Escalation — Windows Defender 0day LPE"),
    ("krbrelayup",          "T1558.003", "Privilege Escalation — Kerberos Relay + Shadow Creds"),
    ("runascs",             "T1134.002", "Defense Evasion — Create Process with Token"),
    # AD enumeration / lateral movement
    ("sharphound",          "T1087.002", "Discovery — BloodHound AD Collection"),
    ("adsearch",            "T1087.002", "Discovery — LDAP Account Discovery"),
    ("snaffler",            "T1039",     "Collection — File Share Credential Hunting"),
    ("sharpmapexec",        "T1021.002", "Lateral Movement — Mass SMB/WMI Execution"),
    ("sharpview",           "T1069.002", "Discovery — Domain Group / ACL Enumeration"),
    ("adcsrelay",           "T1557.001", "Credential Access — ADCS HTTP Relay (ESC8)"),
    ("nltest /dclist",      "T1018",     "Discovery — DC Enumeration"),
    ("nltest /domain_trust","T1482",     "Discovery — Domain Trust Discovery"),
    ("net group \"domain admins\"", "T1069.002", "Discovery — Domain Admin Group Enumeration"),
    ("net group \"enterprise admins\"", "T1069.002", "Discovery — Enterprise Admins Enumeration"),
    ("lsadump::dcsync",     "T1003.006", "Credential Access — DCSync"),
    ("lsadump::sam",        "T1003.002", "Credential Access — SAM Dump"),
    ("sekurlsa::logon",     "T1003.001", "Credential Access — LSASS Memory Dump"),
    ("sekurlsa::wdigest",   "T1003.001", "Credential Access — WDigest Credentials"),
    ("kerberos::ptt",       "T1550.003", "Defense Evasion — Pass the Ticket"),
    ("kerberos::golden",    "T1558.001", "Credential Access — Golden Ticket"),
    ("kerberos::silver",    "T1558.002", "Credential Access — Silver Ticket"),
    ("mimikatz",            "T1003",     "Credential Access — OS Credential Dumping"),
    # recon / collection
    ("seatbelt",            "T1082",     "Discovery — System Information Discovery"),
    ("sqlrecon",            "T1505.001", "Discovery/Execution — MSSQL Recon/RCE"),
    ("winpeas",             "T1082",     "Discovery — System Information Discovery"),
    # lateral movement / tunneling
    ("chisel",              "T1090.003", "C2 — Multi-hop Proxy"),
    ("ligolo",              "T1090",     "C2 — Proxy (Layer 3 Tunnel)"),
    # generic
    ("powershell",          "T1059.001", "Execution — PowerShell"),
    ("cmd /c",              "T1059.003", "Execution — Windows Command Shell"),
    ("pid ",                "T1057",     "Discovery — Process Discovery"),
]


def map_attack(command: str) -> tuple[str, str]:
    """Return (technique_id, description) for command, or ('', '') if unknown."""
    cmd_l = command.lower().strip()
    for prefix, tid, desc in sorted(_ATTACK_MAP, key=lambda x: -len(x[0])):
        if cmd_l.startswith(prefix.lower()):
            return tid, desc
    return "", ""


# ── Credential detection ──────────────────────────────────────────────────────

_CRED_RE: list[tuple[re.Pattern, str]] = [
    # Kerberos hashes (Rubeus / Impacket output)
    (re.compile(r'\$krb5tgs\$\d+\$[^\s]{20,}'),                        "kerberoast"),
    (re.compile(r'\$krb5asrep\$\d+\$[^\s]{20,}'),                      "asrep-roast"),
    # NTLM hashes
    (re.compile(r'[0-9a-f]{32}:[0-9a-f]{32}', re.I),                   "ntlm-hash"),
    (re.compile(r'NTLM\s*[=:]\s*[0-9a-f]{32}', re.I),                  "ntlm-hash"),
    (re.compile(r'\bHash\s+NTLM:\s*[0-9a-f]{32}', re.I),               "ntlm-hash"),
    # Cleartext passwords (Mimikatz sekurlsa/lsadump, secretsdump)
    (re.compile(r'Password\s*:\s*(?!\(null\))\S{3,}', re.I),            "plaintext"),
    (re.compile(r'cleartext\s+password\s*[=:\s]\s*\S+', re.I),          "plaintext"),
    (re.compile(r'::[^:]+:[^:]+:[0-9a-f]{32}:[0-9a-f]{32}:::'),         "secretsdump"),
    # Kerberos keys
    (re.compile(r'aes(?:128|256)-cts-hmac[^\s]{10,}', re.I),            "aes-key"),
    (re.compile(r'\brc4_hmac\s*:\s*[0-9a-f]{32}', re.I),               "rc4-key"),
    # Certificates / ADCS
    (re.compile(r'-----BEGIN CERTIFICATE-----'),                         "certificate"),
    (re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),                     "private-key"),
    # Shadow credentials (Whisker output)
    (re.compile(r'Certificate Password:\s*\S+', re.I),                  "shadow-cred"),
    # LAPS
    (re.compile(r'ms-Mcs-AdmPwd\s*[=:]\s*\S{6,}', re.I),               "laps"),
    (re.compile(r'AdmPwd\s*[=:]\s*\S{6,}', re.I),                      "laps"),
    # Rubeus base64 tickets (doI prefix = Kerberos TGT/TGS ASN.1)
    (re.compile(r'doIFuj[A-Za-z0-9+/]{60,}={0,2}'),                    "kerberos-ticket"),
]


def detect_creds(output: str) -> tuple[bool, list[str]]:
    hints = []
    for pat, label in _CRED_RE:
        for m in pat.finditer(output):
            snippet = m.group(0)[:120].strip()
            hints.append(f"[{label}] {snippet}")
    return bool(hints), hints


# ── Database ──────────────────────────────────────────────────────────────────

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    host            TEXT,
    registered_at   TEXT,
    last_seen       TEXT,
    label           TEXT,
    note            TEXT
);

CREATE TABLE IF NOT EXISTS tasks (
    id              TEXT PRIMARY KEY,
    session_id      TEXT,
    command         TEXT,
    dispatched_at   TEXT,
    technique_id    TEXT,
    technique_desc  TEXT
);

CREATE TABLE IF NOT EXISTS results (
    task_id         TEXT PRIMARY KEY,
    session_id      TEXT,
    output          TEXT,
    received_at     TEXT,
    is_binary       INTEGER DEFAULT 0,
    has_creds       INTEGER DEFAULT 0,
    cred_hints      TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    at              TEXT,
    session_id      TEXT,
    type            TEXT,
    detail          TEXT,
    extra           TEXT
);
"""


class EngagementDB:
    def __init__(self, db_path: str) -> None:
        self._path = db_path
        self._lock = threading.Lock()
        self._init()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._path, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    def _init(self) -> None:
        with self._lock, self._conn() as c:
            c.executescript(_SCHEMA)
            for col, default in [("c2_key", "0"), ("sysinfo", "NULL")]:
                try:
                    c.execute(f"ALTER TABLE sessions ADD COLUMN {col} {'INTEGER' if col=='c2_key' else 'TEXT'} DEFAULT {default}")
                except Exception:
                    pass

    def _now(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── writers ───────────────────────────────────────────────────────────────

    def log_session(self, session_id: str, host: str) -> None:
        now = self._now()
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT OR IGNORE INTO sessions(id,host,registered_at,last_seen) VALUES(?,?,?,?)",
                (session_id, host, now, now),
            )

    def update_sysinfo(self, session_id: str, data: dict) -> None:
        import json as _json
        with self._lock, self._conn() as c:
            existing = c.execute("SELECT sysinfo FROM sessions WHERE id=?", (session_id,)).fetchone()
            merged = {}
            if existing and existing[0]:
                try:
                    merged = _json.loads(existing[0])
                except Exception:
                    pass
            merged.update({k: v for k, v in data.items() if v})
            c.execute("UPDATE sessions SET sysinfo=? WHERE id=?", (_json.dumps(merged), session_id))

    def set_c2_key(self, session_id: str, key: int) -> None:
        with self._lock, self._conn() as c:
            c.execute("UPDATE sessions SET c2_key=? WHERE id=?", (key, session_id))

    def get_live_sessions(self) -> list[dict]:
        """Return sessions that have a c2_key set (i.e. were live C2 sessions)."""
        with self._lock, self._conn() as c:
            rows = c.execute(
                "SELECT id, host, c2_key, last_seen FROM sessions WHERE c2_key > 0"
            ).fetchall()
        return [dict(r) for r in rows]

    def touch_session(self, session_id: str) -> None:
        with self._lock, self._conn() as c:
            c.execute("UPDATE sessions SET last_seen=? WHERE id=?",
                      (self._now(), session_id))

    def tag_session(self, session_id: str, label: str, note: str | None = None) -> bool:
        with self._lock, self._conn() as c:
            row = c.execute("SELECT id FROM sessions WHERE id=?", (session_id,)).fetchone()
            if not row:
                return False
            c.execute("UPDATE sessions SET label=?,note=? WHERE id=?",
                      (label, note, session_id))
        return True

    def delete_session(self, session_id: str) -> None:
        with self._lock, self._conn() as c:
            c.execute("DELETE FROM sessions WHERE id=?", (session_id,))
            c.execute("DELETE FROM tasks WHERE session_id=?", (session_id,))
            c.execute("DELETE FROM results WHERE session_id=?", (session_id,))
            c.execute("DELETE FROM events WHERE session_id=?", (session_id,))

    def log_task(self, task_id: str, session_id: str, command: str) -> None:
        tid, desc = map_attack(command)
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT OR IGNORE INTO tasks(id,session_id,command,dispatched_at,technique_id,technique_desc)"
                " VALUES(?,?,?,?,?,?)",
                (task_id, session_id, command, self._now(), tid, desc),
            )

    def log_result(self, task_id: str, session_id: str, output: str,
                   is_binary: bool = False) -> None:
        has_creds, hints = detect_creds(output) if not is_binary else (False, [])
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO results(task_id,session_id,output,received_at,is_binary,has_creds,cred_hints)"
                " VALUES(?,?,?,?,?,?,?)",
                (task_id, session_id, output, self._now(),
                 1 if is_binary else 0,
                 1 if has_creds else 0,
                 json.dumps(hints) if hints else None),
            )

    def log_event(self, type_: str, detail: str,
                  session_id: str | None = None,
                  extra: dict | None = None) -> None:
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT INTO events(at,session_id,type,detail,extra) VALUES(?,?,?,?,?)",
                (self._now(), session_id, type_, detail,
                 json.dumps(extra) if extra else None),
            )

    def add_note(self, task_id: str, note: str) -> bool:
        """Append an operator note to a task result (stored in extra field)."""
        with self._lock, self._conn() as c:
            row = c.execute("SELECT task_id FROM results WHERE task_id=?",
                            (task_id,)).fetchone()
            if not row:
                return False
            c.execute(
                "INSERT INTO events(at,type,detail,extra) VALUES(?,?,?,?)",
                (self._now(), "note", f"Note on task {task_id}", json.dumps({"note": note})),
            )
        return True

    # ── readers ───────────────────────────────────────────────────────────────

    def get_sessions(self) -> list[dict]:
        import json as _json
        with self._conn() as c:
            rows = c.execute("""
                SELECT s.*,
                       COUNT(t.id) AS task_count,
                       SUM(CASE WHEN r.has_creds=1 THEN 1 ELSE 0 END) AS cred_tasks
                FROM sessions s
                LEFT JOIN tasks t ON t.session_id=s.id
                LEFT JOIN results r ON r.session_id=s.id
                GROUP BY s.id
                ORDER BY s.registered_at
            """).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            si_raw = d.get("sysinfo")  # keep sysinfo in dict for _api_session
            try:
                si = _json.loads(si_raw) if si_raw else {}
            except Exception:
                si = {}
            d["sysinfo_user"]      = si.get("username", "")
            d["sysinfo_integrity"] = si.get("integrity", "")
            result.append(d)
        return result

    def get_tasks(self, session_id: str | None = None) -> list[dict]:
        with self._conn() as c:
            if session_id:
                rows = c.execute(
                    "SELECT t.*, r.received_at, r.has_creds, r.cred_hints, r.is_binary"
                    " FROM tasks t LEFT JOIN results r ON r.task_id=t.id"
                    " WHERE t.session_id=? ORDER BY t.dispatched_at",
                    (session_id,),
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT t.*, r.received_at, r.has_creds, r.cred_hints, r.is_binary"
                    " FROM tasks t LEFT JOIN results r ON r.task_id=t.id"
                    " ORDER BY t.dispatched_at"
                ).fetchall()
        return [dict(r) for r in rows]

    def get_results_for_session(self, session_id: str) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT r.*, t.command, t.technique_id, t.technique_desc"
                " FROM results r LEFT JOIN tasks t ON t.id=r.task_id"
                " WHERE r.session_id=? ORDER BY r.received_at",
                (session_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_events(self, session_id: str | None = None) -> list[dict]:
        with self._conn() as c:
            if session_id:
                rows = c.execute(
                    "SELECT * FROM events WHERE session_id=? ORDER BY at",
                    (session_id,),
                ).fetchall()
            else:
                rows = c.execute("SELECT * FROM events ORDER BY at").fetchall()
        return [dict(r) for r in rows]

    def get_cred_results(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute(
                "SELECT r.*, t.command FROM results r LEFT JOIN tasks t ON t.id=r.task_id"
                " WHERE r.has_creds=1 ORDER BY r.received_at"
            ).fetchall()
        return [dict(r) for r in rows]

    # ── export ────────────────────────────────────────────────────────────────

    def export_json(self) -> dict:
        sessions = self.get_sessions()
        tasks    = self.get_tasks()
        events   = self.get_events()
        creds    = self.get_cred_results()

        # Inline full output into tasks for the JSON dump
        with self._conn() as c:
            results_raw = {
                r["task_id"]: dict(r)
                for r in c.execute("SELECT * FROM results").fetchall()
            }

        for t in tasks:
            res = results_raw.get(t["id"])
            if res:
                t["output"]    = res["output"]
                t["is_binary"] = res["is_binary"]
                t["has_creds"] = res["has_creds"]
                t["cred_hints"] = json.loads(res["cred_hints"]) if res["cred_hints"] else []

        techniques: dict[str, list[str]] = {}
        for t in tasks:
            tid = t.get("technique_id") or ""
            if tid:
                techniques.setdefault(tid, [])
                if t["command"] not in techniques[tid]:
                    techniques[tid].append(t["command"])

        return {
            "generated":  datetime.now().isoformat(),
            "summary": {
                "sessions":    len(sessions),
                "hosts":       len({s["host"] for s in sessions}),
                "tasks":       len(tasks),
                "results":     len(results_raw),
                "cred_tasks":  len(creds),
                "techniques":  len(techniques),
                "events":      len(events),
            },
            "sessions":   sessions,
            "tasks":      tasks,
            "events":     events,
            "techniques": [
                {"id": tid, "commands": cmds}
                for tid, cmds in sorted(techniques.items())
            ],
            "credentials": [
                {
                    "session_id": r["session_id"],
                    "task_id":    r["task_id"],
                    "command":    r["command"],
                    "received_at": r["received_at"],
                    "hints":      json.loads(r["cred_hints"]) if r["cred_hints"] else [],
                    "output":     r["output"][:2000] if r["output"] else "",
                }
                for r in creds
            ],
        }

    def export_markdown(self) -> str:
        data = self.export_json()
        s    = data["summary"]
        now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines: list[str] = []

        lines += [
            "# Lilith Engagement Report",
            f"**Generated:** {now}",
            "",
            "---",
            "",
            "## Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Sessions | {s['sessions']} |",
            f"| Unique hosts | {s['hosts']} |",
            f"| Tasks dispatched | {s['tasks']} |",
            f"| Results received | {s['results']} |",
            f"| Credential captures | {s['cred_tasks']} |",
            f"| ATT&CK techniques observed | {s['techniques']} |",
            "",
            "---",
            "",
            "## Sessions",
            "",
            "| Session ID | Host | Registered | Last Seen | Label | Tasks |",
            "|------------|------|------------|-----------|-------|-------|",
        ]
        for sess in data["sessions"]:
            label = sess.get("label") or "—"
            lines.append(
                f"| `{sess['id']}` | {sess['host']} | {sess['registered_at']} |"
                f" {sess['last_seen']} | {label} | {sess.get('task_count', 0)} |"
            )

        lines += ["", "---", "", "## Task Timeline", ""]

        # Group tasks by session
        by_session: dict[str, list[dict]] = {}
        for t in data["tasks"]:
            by_session.setdefault(t["session_id"], []).append(t)

        for sess in data["sessions"]:
            sid   = sess["id"]
            label = sess.get("label") or sess["host"]
            lines += [
                f"### Session `{sid}` — {label}",
                "",
                "| Time | Task ID | Command | ATT&CK | Creds |",
                "|------|---------|---------|--------|-------|",
            ]
            for t in by_session.get(sid, []):
                attack = f"{t['technique_id']} — {t['technique_desc']}" if t.get("technique_id") else "—"
                cred   = "⚠ YES" if t.get("has_creds") else "—"
                time_  = (t.get("dispatched_at") or "")[-8:]  # HH:MM:SS
                tid_s  = f"`{t['id']}`"
                cmd_s  = t["command"].replace("|", "\\|")[:80]
                lines.append(f"| {time_} | {tid_s} | `{cmd_s}` | {attack} | {cred} |")

            # Show non-binary outputs
            lines.append("")
            for t in by_session.get(sid, []):
                out = t.get("output")
                if out and not t.get("is_binary"):
                    preview = out.strip()[:1200]
                    lines += [
                        f"<details><summary>Task <code>{t['id']}</code>: <code>{t['command'][:60]}</code></summary>",
                        "",
                        "```",
                        preview,
                        "```",
                        "",
                        "</details>",
                        "",
                    ]

        lines += ["", "---", "", "## Credential Captures", ""]
        if data["credentials"]:
            for cred in data["credentials"]:
                lines += [
                    f"**Session:** `{cred['session_id']}` | **Time:** {cred['received_at']} | **Command:** `{cred['command']}`",
                    "",
                ]
                for hint in cred["hints"]:
                    lines.append(f"- {hint}")
                lines += [
                    "",
                    "<details><summary>Full output</summary>",
                    "",
                    "```",
                    (cred["output"] or "")[:2000],
                    "```",
                    "",
                    "</details>",
                    "",
                ]
        else:
            lines.append("*No credentials captured.*")

        lines += ["", "---", "", "## ATT&CK Technique Coverage", ""]

        # Map technique_id → (desc, [commands])
        tech_map: dict[str, tuple[str, list[str]]] = {}
        for t in data["tasks"]:
            tid = t.get("technique_id") or ""
            if not tid:
                continue
            desc = t.get("technique_desc") or ""
            cmd  = t["command"][:60]
            if tid not in tech_map:
                tech_map[tid] = (desc, [])
            if cmd not in tech_map[tid][1]:
                tech_map[tid][1].append(cmd)

        if tech_map:
            lines += [
                "| Technique | Description | Commands |",
                "|-----------|-------------|----------|",
            ]
            for tid, (desc, cmds) in sorted(tech_map.items()):
                cmds_s = ", ".join(f"`{c}`" for c in cmds[:5])
                lines.append(f"| [{tid}](https://attack.mitre.org/techniques/{tid.replace('.','/')}) | {desc} | {cmds_s} |")
        else:
            lines.append("*No techniques mapped yet.*")

        lines += ["", "---", "", "## Event Log", ""]
        if data["events"]:
            lines += [
                "| Time | Session | Type | Detail |",
                "|------|---------|------|--------|",
            ]
            for ev in data["events"]:
                time_   = (ev.get("at") or "")[-8:]
                sess_s  = f"`{ev['session_id']}`" if ev.get("session_id") else "—"
                detail  = (ev.get("detail") or "")[:80].replace("|", "\\|")
                lines.append(f"| {time_} | {sess_s} | {ev['type']} | {detail} |")
        else:
            lines.append("*No additional events recorded.*")

        lines += ["", "---", "", "*Report generated by Lilith.*", ""]
        return "\n".join(lines)
