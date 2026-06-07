import yaml
import os

DEFAULTS = {
    "lhost": "10.10.14.1",
    "lport": 4444,
    "http_port": 8443,
    "framework": "sliver",
    "proto": "mtls",
    "type": "beacon",
    "injection_profile": "RuntimeBroker.exe",
    "tools": {},
    # ── stealth / evasion ──────────────────────────────────────────────────────
    # SNI sent in TLS ClientHello — spoofs the hostname visible in network capture
    "sni_host": "assets.msn.com",
    # Prefix added to all served file paths (server strips it on lookup)
    "url_prefix": "/cdn/static/v3",
    # Prefix for callback POST endpoint
    "callback_path": "/api/diagnostics/v1/telemetry",
    # Jitter range (ms) injected between stages to break timing correlation
    "jitter_min_ms": 1500,
    "jitter_max_ms": 6000,
    # User-Agent baked into the C runner (Edge 124 on Win10)
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
}

_CONFIG_NAMES = ("engagement.yaml", "engagement.yml")


def load_config(path=None):
    cfg = dict(DEFAULTS)
    if path is None:
        for name in _CONFIG_NAMES:
            if os.path.exists(name):
                path = name
                break
    if path and os.path.exists(path):
        with open(path) as f:
            user = yaml.safe_load(f) or {}
        cfg.update({k: v for k, v in user.items() if v is not None})
        print(f"[*] Loaded: {path}")
    else:
        print("[!] No engagement.yaml found — using defaults. Run 'lilith init' to create one.")
    return cfg


def create_default_config(path="engagement.yaml"):
    if os.path.exists(path):
        print(f"[!] {path} already exists — not overwriting")
        return False
    example = os.path.join(os.path.dirname(__file__), "..", "engagement.yaml.example")
    if os.path.exists(example):
        import shutil
        shutil.copy(example, path)
    else:
        with open(path, "w") as f:
            f.write("lhost: 10.10.14.1\nhttp_port: 8443\ntools: {}\n")
    print(f"[+] Created: {path} — edit LHOST and tools before building")
    return True
