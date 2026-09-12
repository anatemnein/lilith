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
"""


def consult_stream(question: str, context: dict, stream_id: str, publish) -> None:
    """Stream tokens to all SSE clients via publish(event). Runs in a background thread."""
    prompt  = _build_prompt(question, context)
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if api_key:
        _stream_claude(prompt, api_key, stream_id, publish)
    else:
        _stream_ollama(prompt, stream_id, publish)


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


def _stream_ollama(prompt: str, stream_id: str, publish) -> None:
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


def _stream_claude(prompt: str, api_key: str, stream_id: str, publish) -> None:
    model = os.environ.get("ASTAROTH_MODEL", "claude-sonnet-5")
    body  = json.dumps({
        "model":      model,
        "max_tokens": 1500,
        "stream":     True,
        "system":     _SYSTEM,
        "messages":   [{"role": "user", "content": prompt}],
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
