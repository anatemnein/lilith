import subprocess
import os


# Subject that looks like a Microsoft CDN cert — passes casual certificate inspection
_SUBJECT = (
    "/C=US/ST=Washington/L=Redmond"
    "/O=Microsoft Corporation"
    "/OU=MSN Services"
    "/CN=*.msn.com"
)

# SAN must match CN for browsers / WinHTTP strict validation
_SAN = "DNS:*.msn.com,DNS:msn.com,DNS:assets.msn.com"

# 397 days = browser-standard max validity for CA-issued certs; anything longer is suspicious
_DAYS = 397


def generate_self_signed(cert_path: str, key_path: str, cn: str = "*.msn.com") -> bool:
    subject = (
        f"/C=US/ST=Washington/L=Redmond"
        f"/O=Microsoft Corporation/OU=MSN Services/CN={cn}"
    )
    san = f"DNS:{cn},DNS:{cn.lstrip('*.')}"
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_path,
        "-out",    cert_path,
        "-days",   str(_DAYS),
        "-nodes",
        "-subj",   subject,
        "-addext", f"subjectAltName={san}",
        "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
        "-addext", "extendedKeyUsage=serverAuth",
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "subjectKeyIdentifier=hash",
        "-addext", "authorityKeyIdentifier=keyid:always",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] openssl failed: {result.stderr.strip()}")
        return False
    return True


def ensure_certs(workspace_dir: str, lhost: str) -> tuple[str, str] | tuple[None, None]:
    cert = os.path.join(workspace_dir, "server.crt")
    key  = os.path.join(workspace_dir, "server.key")
    if not os.path.exists(cert) or not os.path.exists(key):
        print("[*] Generating TLS certificate...")
        if not generate_self_signed(cert, key):
            return None, None
        print(f"[+] Cert: {cert}  (CN=*.msn.com, {_DAYS}d)")
    return cert, key
