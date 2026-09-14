# Graph Report - /home/quiet/tools/lilith  (2026-06-25)

## Corpus Check
- Large corpus: 37 files · ~989,705 words. Semantic extraction will be expensive (many Claude tokens). Consider running on a subfolder.

## Summary
- 897 nodes · 1920 edges · 60 communities
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS · INFERRED: 7 edges (avg confidence: 0.84)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Windows API Types|Windows API Types]]
- [[_COMMUNITY_ADS Stager Builder|ADS Stager Builder]]
- [[_COMMUNITY_Defender Threat State|Defender Threat State]]
- [[_COMMUNITY_C2 HTTPS Server|C2 HTTPS Server]]
- [[_COMMUNITY_BYOVD Driver Kit|BYOVD Driver Kit]]
- [[_COMMUNITY_Poly Runner Builder|Poly Runner Builder]]
- [[_COMMUNITY_Engagement DB Core|Engagement DB Core]]
- [[_COMMUNITY_RoguePlanet File Structs|RoguePlanet File Structs]]
- [[_COMMUNITY_Encoder Config|Encoder Config]]
- [[_COMMUNITY_Shellcode Encoder|Shellcode Encoder]]
- [[_COMMUNITY_RoguePlanet LPE Core|RoguePlanet LPE Core]]
- [[_COMMUNITY_Workspace Management|Workspace Management]]
- [[_COMMUNITY_WASM Dropper Builder|WASM Dropper Builder]]
- [[_COMMUNITY_Defender Scan API|Defender Scan API]]
- [[_COMMUNITY_LOLBin Stager Builder|LOLBin Stager Builder]]
- [[_COMMUNITY_PE Patcher Backdoor|PE Patcher Backdoor]]
- [[_COMMUNITY_C Runner Evasion Docs|C Runner Evasion Docs]]
- [[_COMMUNITY_BLE HID Payload|BLE HID Payload]]
- [[_COMMUNITY_HTML Smuggle Inject|HTML Smuggle Inject]]
- [[_COMMUNITY_Capability Docs Index|Capability Docs Index]]
- [[_COMMUNITY_ISO Smuggle Builder|ISO Smuggle Builder]]
- [[_COMMUNITY_Defender Callback API|Defender Callback API]]
- [[_COMMUNITY_Defender FastPath API|Defender FastPath API]]
- [[_COMMUNITY_Defender Clean API|Defender Clean API]]
- [[_COMMUNITY_Cortex XDR Parser|Cortex XDR Parser]]
- [[_COMMUNITY_Defender Behavior Info|Defender Behavior Info]]
- [[_COMMUNITY_Defender Status API|Defender Status API]]
- [[_COMMUNITY_Defender Malware Toast|Defender Malware Toast]]
- [[_COMMUNITY_Defender SigUpdate API|Defender SigUpdate API]]
- [[_COMMUNITY_RoguePlanet Race Exploit|RoguePlanet Race Exploit]]
- [[_COMMUNITY_BYOVD Compile Flow|BYOVD Compile Flow]]
- [[_COMMUNITY_NIS Private Data|NIS Private Data]]
- [[_COMMUNITY_Persistence Mechanisms Docs|Persistence Mechanisms Docs]]
- [[_COMMUNITY_WPAD Proxy Poisoning|WPAD Proxy Poisoning]]
- [[_COMMUNITY_Defender Resource Stats|Defender Resource Stats]]
- [[_COMMUNITY_NTLM Trigger Builder|NTLM Trigger Builder]]
- [[_COMMUNITY_File Basic Information|File Basic Information]]
- [[_COMMUNITY_Pre-check Scan Data|Pre-check Scan Data]]
- [[_COMMUNITY_Defender Config Data|Defender Config Data]]
- [[_COMMUNITY_NIS Network Threat Info|NIS Network Threat Info]]
- [[_COMMUNITY_PE Stub x64 Loader|PE Stub x64 Loader]]
- [[_COMMUNITY_Android APK Builder|Android APK Builder]]
- [[_COMMUNITY_Defender End-of-Life Data|Defender End-of-Life Data]]
- [[_COMMUNITY_Network Delivery Docs|Network Delivery Docs]]
- [[_COMMUNITY_Defense Evasion Docs|Defense Evasion Docs]]
- [[_COMMUNITY_VSS Shadow Volume|VSS Shadow Volume]]
- [[_COMMUNITY_File Disposition Info|File Disposition Info]]
- [[_COMMUNITY_AMSI ETW Bypass Docs|AMSI ETW Bypass Docs]]
- [[_COMMUNITY_Defender Expiration API|Defender Expiration API]]
- [[_COMMUNITY_Defender Component Status|Defender Component Status]]
- [[_COMMUNITY_Defender Threat Stats|Defender Threat Stats]]
- [[_COMMUNITY_Defender Callback Info|Defender Callback Info]]
- [[_COMMUNITY_USB HID Devices Docs|USB HID Devices Docs]]
- [[_COMMUNITY_File Rename Information|File Rename Information]]
- [[_COMMUNITY_Object Directory Info|Object Directory Info]]
- [[_COMMUNITY_Defender Health Data|Defender Health Data]]

## God Nodes (most connected - your core abstractions)
1. `tagMPTHREAT_INFO` - 59 edges
2. `POLY_AGENT()` - 34 edges
3. `_rv()` - 25 edges
4. `cmd_build()` - 25 edges
5. `_lt_church_phase()` - 22 edges
6. `generate_stager()` - 21 edges
7. `EngagementDB` - 21 edges
8. `Workspace` - 21 edges
9. `lt_run()` - 21 edges
10. `Polymorphic C Runner (MinGW cross-compiled)` - 20 edges

## Surprising Connections (you probably didn't know these)
- `cmd_engage()` --calls--> `EngagementDB`  [EXTRACTED]
  lilith.py → core/engage.py
- `RoguePlanet (Windows Defender race condition LPE, listed in tool catalog)` --references--> `RoguePlanet Windows Defender Vulnerability Exploit`  [EXTRACTED]
  README.md → RoguePlanet/README.md
- `cmd_build()` --calls--> `build_ads_stager()`  [EXTRACTED]
  lilith.py → builders/ads_stage.py
- `cmd_build()` --calls--> `build_android_payload()`  [EXTRACTED]
  lilith.py → builders/android.py
- `cmd_build()` --calls--> `build_android_ble_payload()`  [EXTRACTED]
  lilith.py → builders/blehid.py

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Core EDR Evasion Triad: Indirect Syscalls + ntdll Unhooking + Module Stomping** — lilith_readme_indirect_syscalls, lilith_readme_ntdll_unhooking, lilith_readme_module_stomping [EXTRACTED 1.00]
- **Injection Technique Menu: APC + WNF + Thread Hijack + Fiber + Transacted Hollowing + COM Hijack** — lilith_readme_apc_injection, lilith_readme_wnf_injection, lilith_readme_thread_hijack, lilith_readme_fiber_execution, lilith_readme_transacted_hollowing, lilith_readme_com_hijacking [EXTRACTED 1.00]
- **Physical Delivery Device Family: Rubber Ducky + Pico + DigiSpark (USB) + M5StickC Plus2 + Bruce (BLE)** — lilith_readme_rubber_ducky, lilith_readme_pico_hid, lilith_readme_digispark, lilith_readme_m5stick, lilith_readme_bruce_firmware [EXTRACTED 1.00]
- **LPE Tool Suite within Escalation Chain: GodPotato + RoguePlanet + Mimikatz** — lilith_readme_godpotato, lilith_readme_rogueplanet_tool, lilith_readme_mimikatz, lilith_readme_escalation_chain [EXTRACTED 1.00]
- **RoguePlanet Core: Race Condition + MpCleanCallbackFunction + Shadow Copy + SYSTEM Shell** — rogueplanet_readme_race_condition, rogueplanet_rogueplanet_mpcleancallback, rogueplanet_rogueplanet_shadow_copy, rogueplanet_readme_system_shell [INFERRED 0.85]

## Communities (60 total, 0 thin omitted)

### Community 0 - "Windows API Types"
Cohesion: 0.06
Nodes (129): ACCESS_MASK, BOOLEAN, DWORD, HANDLE, LONGLONG, LPCSTR, LPWSTR, _LT_SSPI (+121 more)

### Community 1 - "ADS Stager Builder"
Cohesion: 0.08
Nodes (72): build_ads_stager(), _build_load_ps1(), _build_plant_ps1(), Lilith — NTFS Alternate Data Stream (ADS) staging.  Generates two PowerShell art, Build an ADS staging pair for enc_filename.      Returns (plant_path, load_path), _amsi_from_bytes(), _amsi_reflection_fallback(), _build_chain_ps1() (+64 more)

### Community 2 - "Defender Threat State"
Cohesion: 0.04
Nodes (49): MPDETECTION_ORIGIN, MPDETECTION_STATE, MPEXECUTION_STATUS, MPRESOLVED_REASON, MPTHREAT_CATEGORY, MPTHREAT_DETECTION, MPTHREAT_SEVERITY, MPTHREAT_STATUS (+41 more)

### Community 3 - "C2 HTTPS Server"
Cohesion: 0.09
Nodes (23): cmd_serve(), ensure_certs(), generate_self_signed(), _c2_encode_task(), _c2_get_result(), _c2_kill_session(), _c2_new_session(), _c2_pop_task() (+15 more)

### Community 4 - "BYOVD Driver Kit"
Cohesion: 0.19
Nodes (35): BOOL, bvd_cb_t, HMODULE, LPCWSTR, bv_enable_load_driver(), bv_init_ustr(), bv_register_driver(), bv_report() (+27 more)

### Community 5 - "Poly Runner Builder"
Cohesion: 0.11
Nodes (29): _add_junk_globals(), _apply_poly(), _build_poly_map(), build_runner(), build_runner_sc(), build_runner_sc_c2(), _donut_shellcode(), _find_donut() (+21 more)

### Community 6 - "Engagement DB Core"
Cohesion: 0.17
Nodes (7): Connection, detect_creds(), EngagementDB, map_attack(), Engagement database — persistent SQLite log of all C2 activity.  Every session r, Append an operator note to a task result (stored in extra field)., Return (technique_id, description) for command, or ('', '') if unknown.

### Community 7 - "RoguePlanet File Structs"
Cohesion: 0.08
Nodes (24): _Field_size_, _FILE_PROCESS_IDS_USING_FILE_INFORMATION, NumberOfProcessIdsInList, ProcessIdList, _REPARSE_DATA_BUFFER, DUMMYUNIONNAME, ReparseDataLength, ReparseTag (+16 more)

### Community 8 - "Encoder Config"
Cohesion: 0.15
Nodes (19): find_tool(), find_tool_icase(), list_tools(), Case-insensitive catalog lookup, returns catalog key or None., create_default_config(), load_config(), _banner(), _build_persist_cmd() (+11 more)

### Community 9 - "Shellcode Encoder"
Cohesion: 0.14
Nodes (18): encode_tool(), encode_tool_clr(), _find_donut(), is_dotnet_assembly(), _pot(), Return True if the PE has a CLR directory entry (.NET managed assembly)., Pack a .NET assembly as a two-layer XOR .enc without donut.     The runner loads, Encode a tool for in-memory execution.     .NET assemblies (CLR header present): (+10 more)

### Community 10 - "RoguePlanet LPE Core"
Cohesion: 0.15
Nodes (20): LPCTSTR, CreateJunction(), GetWDInstallDir(), GetWERDir(), IsRunningAsLocalSystem(), LaunchConsoleInSessionId(), main(), MountISO() (+12 more)

### Community 11 - "Workspace Management"
Cohesion: 0.17
Nodes (6): Return a persistent random .enc filename for tool_key, creating one if needed., Return the random .enc filename for tool_key, or None if not yet encoded., Return a persistent random .ps1 filename for tool_key's stager., Store build-time metadata for a tool (e.g. clr path flag, baked args)., Return build-time metadata for a tool, or empty dict if none., Workspace

### Community 12 - "WASM Dropper Builder"
Cohesion: 0.29
Nodes (18): _build_loader_html(), build_wasm_dropper(), build_wasm_module(), _code_section(), _data_section(), _export_section(), _function_section(), _import_section() (+10 more)

### Community 13 - "Defender Scan API"
Cohesion: 0.12
Nodes (19): GUID, MPRESOURCE_STATS, MPSCAN_TYPE, MPSOURCE, MPTHREAT_STATS, tagMPSCAN_DATA, ResourceInfo, ResourceStats (+11 more)

### Community 14 - "LOLBin Stager Builder"
Cohesion: 0.21
Nodes (16): _build_hta(), build_lolbin_stagers(), build_msbuild(), _build_msbuild_xml(), build_mshta(), build_regsvr32(), _build_sct(), _random_guid() (+8 more)

### Community 15 - "PE Patcher Backdoor"
Cohesion: 0.18
Nodes (16): _align_up(), backdoor_pe(), backdoor_pe_from_stager(), _compile_stub(), _donut_ps1(), _patch_and_add_section(), _pe_to_flat(), _rand_sec_name() (+8 more)

### Community 16 - "C Runner Evasion Docs"
Cohesion: 0.13
Nodes (16): Early Bird APC Injection via NtQueueApcThread (no NtCreateThreadEx event), Polymorphic C Runner (MinGW cross-compiled), COM Server Hijacking via HKCU InprocServer32 (auto-cleanup), Domain Fronting Support via front_host Config, donut Shellcode Encoder (pip install donut-shellcode), Fiber-based Self-Execution (ConvertThreadToFiber + CreateFiber + SwitchToFiber), Module Stomping into Signed DLL .text (18 candidates: wintrust/cryptnet/etc), PE Backdoor Patcher (ShimEntry OEP redirect) (+8 more)

### Community 17 - "BLE HID Payload"
Cohesion: 0.19
Nodes (14): _ble_m5stick(), _bruce(), _bruce_android(), build_android_ble_payload(), build_ble_payload(), _chunked_prints(), _esc_c(), _m5stick_android() (+6 more)

### Community 18 - "HTML Smuggle Inject"
Cohesion: 0.18
Nodes (11): load_inject_js(), Return the inject.js content from a previous build_smuggle_payload call, or None, cmd_network(), _dnsmasq_conf(), _hostapd_conf(), _make_handler(), Lilith — Evil twin + captive portal  Sets up a rogue WiFi AP that forces the tar, run_captive_portal() (+3 more)

### Community 19 - "Capability Docs Index"
Cohesion: 0.15
Nodes (14): BLE HID Wireless Physical-Access Delivery (M5StickC Plus2 / Bruce), Bruce Firmware (M5StickC Plus2 BadBLE DuckyScript runner), Cortex XDR Agent Settings Parser (exclusions + uninstall hash), Engagement Database (SQLite, auto ATT&CK mapping, export), SeImpersonate to SYSTEM Escalation Chain (potato family + RoguePlanet), Lilith AV/AMSI Bypass Framework, GodPotato (SeImpersonate → SYSTEM, Win10/11/2019/2022), Fake IIS HTTPS Server (IIS/Schannel mimicry) (+6 more)

### Community 20 - "ISO Smuggle Builder"
Cohesion: 0.22
Nodes (12): build_smuggle_payload(), _iso_bytes(), _iso_download_js(), _lnk_bytes(), Lilith — HTML Smuggling → ISO → LNK delivery  Browser loads lure page → JS assem, Standalone JS snippet that triggers an ISO blob download.     Used directly by t, Generate a self-contained HTML smuggling page embedding an ISO with a LNK stager, MS-SHLLINK StringData: CountCharacters (LE uint16) + UTF-16LE data. (+4 more)

### Community 21 - "Defender Callback API"
Cohesion: 0.15
Nodes (13): HRESULT, MPCALLBACK_TYPE, MPNOTIFY, tagMPCALLBACK_DATA, Data, hResult, Notify, TimeStamp (+5 more)

### Community 22 - "Defender FastPath API"
Cohesion: 0.15
Nodes (13): MP_FASTPATH_TYPE, MP_PERSISTENCE_LIMIT_TYPE, MP_REMOVAL_REASON, MP_SIGNATURE_TYPE, tagMPFASTPATH_DATA, CompilationTimestamp, FastPathSignatureType, FastPathSignatureVersion (+5 more)

### Community 23 - "Defender Clean API"
Cohesion: 0.18
Nodes (12): MPTHREAT_ACTION, MPTHREAT_ID, tagMPCLEAN_DATA, dwStatus, ResourceInfo, ThreatAction, ThreatID, tagMPTHREAT_DATA (+4 more)

### Community 24 - "Cortex XDR Parser"
Cohesion: 0.24
Nodes (10): _ldb_records(), parse_and_report(), _parse_ldb_dir(), Cortex XDR config extractor.  Parses LevelDB .ldb files from Cybereason/Palo Alt, Parse a Cortex XDR agent_settings.db directory and print tactical report., Yield (key, value) byte pairs from a LevelDB SSTable (.ldb) file.     Only handl, Return raw config dict if the .db dir contains a SQLite file., _try_sqlite() (+2 more)

### Community 25 - "Defender Behavior Info"
Cohesion: 0.18
Nodes (11): MP_HASH_TYPE, tagMPTHREAT_INFOEX_BEHAVIOR, ASDeltaSignatureVersion, AVDeltaSignatureVersion, EngineVersion, FidelityValue, HashType, HashValue (+3 more)

### Community 26 - "Defender Status API"
Cohesion: 0.18
Nodes (11): MPCOMPONENT_STATUS, MPSCAN_RESULT, MPTHREAT_STATS_DATA, tagMPSTATUS_INFO, Component, LastFullScan, LastQuickScan, ProductExpirationTime (+3 more)

### Community 27 - "Defender Malware Toast"
Cohesion: 0.22
Nodes (9): MP_MIDL_STRING, MPRESOURCE_CLASS, tagMPMALWARETOAST_DATA, dwThreatId, pszThreatName, tagMPRESOURCE_INFO, Class, Path (+1 more)

### Community 28 - "Defender SigUpdate API"
Cohesion: 0.22
Nodes (9): MP_UPDATE_STAGE, MPSIGUPDATE_TYPE, tagMPSIGUPDATE_DATA, dwCurrentUpdateIndex, dwPercentComplete, dwTotalUpdates, eType, Path (+1 more)

### Community 29 - "RoguePlanet Race Exploit"
Cohesion: 0.33
Nodes (9): ISO Mount Technique (standard-user capability on Win10/11, absent on Server), Windows Defender Race Condition (non-deterministic; 100% on some machines), RoguePlanet Windows Defender Vulnerability Exploit, SYSTEM Shell Spawn (exploit success outcome via nt authority\system), PoC limited to Win10/11 because standard users cannot mount ISO on Windows Server, Windows Defender Vulnerability (Win10/11/Server, tested June 2026 patch), MpCleanCallbackFunction (Windows Defender internal callback, called repeatedly during exploit), RoguePlanet Exploit Demo Screenshot (conhost.exe Administrator, Win10 10.0.26200.8655, SYSTEM shell confirmed) (+1 more)

### Community 30 - "BYOVD Compile Flow"
Cohesion: 0.32
Nodes (7): build_byovd(), build_byovd_sc(), _compile_byovd(), Lilith — BYOVD Kit Builder  Two build modes:    build_byovd(output_exe)     → Re, Compile byovd in SILENT mode, wrap in donut shellcode, pack with two-layer XOR., Core compile step.  silent=True adds -DLT_BYOVD_SILENT (stdout instead of Messag, Compile byovd_template.c into a standalone GUI PE (MessageBoxW output).     For

### Community 31 - "NIS Private Data"
Cohesion: 0.25
Nodes (8): BYTE, tagMPNIS_PRIVATE_DATA, cbDataSize, dwNotificationType, pbData, tagMPRESERVED_DATA, cbReservedData, pbReservedData

### Community 32 - "Persistence Mechanisms Docs"
Cohesion: 0.29
Nodes (8): C2 Agent Mode (HTTPS polling interactive C2), HKCU Run Key Persistence, Scheduled Task Persistence (HighestAvailable, user logon), WER Namespace Scheduled Task Persistence (ONSTART, SYSTEM), WMI CommandLine Event Consumer Persistence (Win32_ProcessStartTrace), Persistence Mechanisms (Run/schtask/WMI/WER), SslStream chosen to avoid WinHTTP COM activation IOC present in CrowdStrike/MDE/Cortex XDR rulesets, SslStream TLS Transport (standard .NET TCP/TLS, no COM activation)

### Community 33 - "WPAD Proxy Poisoning"
Cohesion: 0.36
Nodes (6): _inject_script(), _make_pac_handler(), _make_proxy_handler(), Lilith — WPAD poisoning + injecting HTTP proxy  Serves a malicious PAC script th, HTTP proxy handler that injects inject_js into every HTML response., run_wpad()

### Community 34 - "Defender Resource Stats"
Cohesion: 0.25
Nodes (8): tagMPRESOURCE_STATS, FileBytesCount, FileCount, PPMProgress, ProcessCount, RegKeyCount, Reserved, UINT64

### Community 35 - "NTLM Trigger Builder"
Cohesion: 0.43
Nodes (6): build_ntlm_triggers(), Lilith — NTLM trigger file generator  Drop these files on any share/folder the t, Generate NTLM trigger files that auto-authenticate to lhost when browsed., _scf_file(), _search_connector(), _url_file()

### Community 36 - "File Basic Information"
Cohesion: 0.29
Nodes (7): LARGE_INTEGER, _FILE_BASIC_INFORMATION, ChangeTime, CreationTime, FileAttributes, LastAccessTime, LastWriteTime

### Community 37 - "Pre-check Scan Data"
Cohesion: 0.29
Nodes (7): PMPRESOURCE_INFO, tagMPCLEAN_PRECHECK_DATA, BlockedResourceInfo, BlockingResourceInfo, tagMPSCAN_RESOURCES, dwResourceCount, pResourceList

### Community 38 - "Defender Config Data"
Cohesion: 0.29
Nodes (7): tagMPCONFIGURATION_DATA, ConfigurationName, CurrentDataSize, DataType, pCurrentData, pPreviousData, PreviousDataSize

### Community 39 - "NIS Network Threat Info"
Cohesion: 0.29
Nodes (7): tagMPTHREAT_INFOEX_NIS, DestinationIP, dwDestinationport, dwSourceport, Link, Protocol, SourceIP

### Community 40 - "PE Stub x64 Loader"
Cohesion: 0.57
Nodes (6): _getproc(), _imgbase(), _k32base(), _peb(), _seq(), ShimEntry()

### Community 41 - "Android APK Builder"
Cohesion: 0.47
Nodes (5): _apk_lure_html(), build_android_payload(), Lilith — Android payload delivery (server-side)  Two modes:    chrome / apk  —, Generate Android delivery files served by 'lilith serve'.      mode='chrome'  →, _termux_stager_sh()

### Community 42 - "Defender End-of-Life Data"
Cohesion: 0.33
Nodes (6): FILETIME, tagMPENDOFLIFE_DATA, fAdminControlled, fEndOfLifeImpendingOrPast, ftPlatformExpiry, ftSignatureExpiry

### Community 43 - "Network Delivery Docs"
Cohesion: 0.33
Nodes (6): Rogue WiFi Captive Portal Delivery, Network Delivery Methods (captive portal / WPAD / WebDAV LNK), WebAssembly Browser Dropper (PE inside WASM data section, no MZ magic), WebDAV LNK Delivery via search-ms URI, WPAD PAC Poisoning HTTP Injection Proxy, XOR Obfuscation and Static ML Hardening (random section names/symbols/key/TimeDateStamp)

### Community 44 - "Defense Evasion Docs"
Cohesion: 0.33
Nodes (6): Indirect Syscalls via syscall;ret gadget (Hell's Gate / Halo's Gate SSN), LOLBin Stagers (PowerShell-free delivery), MSBuild Inline C# Shellcode Runner (fileless CodeTaskFactory), mshta HTA/VBScript LOLBin Stager, ntdll Unhooking via SEC_IMAGE_NO_EXECUTE mapping from disk, regsvr32 COM Scriptlet (Squiblydoo) Stager

### Community 45 - "VSS Shadow Volume"
Cohesion: 0.47
Nodes (6): DestroyVSSNamesList(), LLShadowVolumeNames, name, next, RetrieveCurrentVSSList(), ShadowCopyFinderThread()

### Community 46 - "File Disposition Info"
Cohesion: 0.20
Nodes (6): _FILE_DISPOSITION_INFORMATION_EX, Flags, tagMPSTATUS_DATAEX_UNUSED, dwNone, tagMPTHREAT_STATS_DATA, dwThreatCount

### Community 47 - "AMSI ETW Bypass Docs"
Cohesion: 0.40
Nodes (5): AMSI Bypass (AmsiOpenSession → E_INVALIDARG, precompiled DLL loaded from memory), BYOVD Kernel Kit (RTCore64/gdrv/WinRing0x64), ETW Patching (EtwEventWrite/EtwEventWriteFull/etc → XOR RAX,RAX/RET), Invisible Unicode Obfuscation (ZWSP/ZWJ/VS/PUA in .NET type-name strings), PowerShell Stager (10-line fileless loader)

### Community 48 - "Defender Expiration API"
Cohesion: 0.40
Nodes (5): MP_EXPIRE_REASON, MP_EXPIRE_STATE_REPORT, tagMPEXPIRATION_DATA, Reason, State

### Community 49 - "Defender Component Status"
Cohesion: 0.40
Nodes (5): MPCOMPONENT_ID, tagMPSTATUS_DATA, ComponentID, ComponentStatus, fEnable

### Community 50 - "Defender Threat Stats"
Cohesion: 0.40
Nodes (5): tagMPTHREAT_STATS, Reserved, SuspiciousThreatCount, ThreatCount, UINT

### Community 51 - "Defender Callback Info"
Cohesion: 0.50
Nodes (4): __int64, tagMPCALLBACK_INFO, CallbackHandler, v4

### Community 52 - "USB HID Devices Docs"
Cohesion: 0.50
Nodes (4): DigiSpark ATtiny85 HID Keystroke Device, Raspberry Pi Pico (CircuitPython HID) Keystroke Device, Rubber Ducky v1/v2 HID Keystroke Device, USB HID Physical-Access Delivery

### Community 53 - "File Rename Information"
Cohesion: 0.50
Nodes (4): _FILE_RENAME_INFORMATION, FileName, FileNameLength, RootDirectory

### Community 54 - "Object Directory Info"
Cohesion: 0.50
Nodes (4): _OBJECT_DIRECTORY_INFORMATION, Name, TypeName, UNICODE_STRING

### Community 55 - "Defender Health Data"
Cohesion: 0.67
Nodes (3): tagMPHEALTH_DATA, dwNotificationFlag, dwNotificationType

## Knowledge Gaps
- **206 isolated node(s):** `Object`, `UniqueProcessId`, `HandleValue`, `GrantedAccess`, `CreatorBackTraceIndex` (+201 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `tagMPTHREAT_INFO` connect `Defender Threat State` to `Windows API Types`, `BYOVD Driver Kit`, `Pre-check Scan Data`, `RoguePlanet LPE Core`, `Defender Scan API`, `Defender Callback API`, `Defender Clean API`, `Defender Malware Toast`?**
  _High betweenness centrality (0.057) - this node is a cross-community bridge._
- **Why does `EngagementDB` connect `Engagement DB Core` to `Encoder Config`, `C2 HTTPS Server`?**
  _High betweenness centrality (0.021) - this node is a cross-community bridge._
- **Why does `Workspace` connect `Workspace Management` to `Encoder Config`, `Shellcode Encoder`?**
  _High betweenness centrality (0.016) - this node is a cross-community bridge._
- **What connects `Object`, `UniqueProcessId`, `HandleValue` to the rest of the system?**
  _315 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Windows API Types` be split into smaller, more focused modules?**
  _Cohesion score 0.057545507927187316 - nodes in this community are weakly interconnected._
- **Should `ADS Stager Builder` be split into smaller, more focused modules?**
  _Cohesion score 0.07783783783783783 - nodes in this community are weakly interconnected._
- **Should `Defender Threat State` be split into smaller, more focused modules?**
  _Cohesion score 0.04081632653061224 - nodes in this community are weakly interconnected._