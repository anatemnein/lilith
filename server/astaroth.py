"""
server/astaroth.py — Astaroth red team AI consultant.

Backend for the Lilith web UI chat panel. Sends engagement context +
operator question to a configured AI (Claude API or local Ollama).

Config via environment variables:
  ANTHROPIC_API_KEY    → uses Claude (preferred)
  ASTAROTH_MODEL       → Claude model ID (default: claude-sonnet-5)
  ASTAROTH_OLLAMA_URL  → Ollama base URL (default: http://localhost:11434)
  ASTAROTH_OLLAMA_MODEL→ Ollama model (default: llama3.2)
"""

import json
import os
import urllib.request

_SYSTEM = """\
You are Astaroth — an offensive security AI embedded in the Lilith C2 framework.
Your role: analyze engagement data and suggest the shortest, most practical attack paths
toward the operator's objective, based solely on what is already known and available.

Guidelines:
- Recommend the shortest path first, then alternatives
- Reference tools already in Lilith's Arsenal by name when applicable
- Map suggestions to specific ATT&CK techniques (include T-IDs)
- Be tactical and concise — the operator is mid-engagement
- Prefer low-noise paths: in-memory execution, LOLBins, existing sessions
- If credentials are available, prioritize pass-the-hash / pass-the-ticket
- Flag OpSec concerns explicitly
- Never suggest capabilities not already confirmed available
"""


def consult(question: str, context: dict) -> str:
    prompt = _build_prompt(question, context)
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if api_key:
        return _call_claude(prompt, api_key)
    return _call_ollama(prompt)


def _build_prompt(question: str, ctx: dict) -> str:
    lines = ["## Current Engagement State\n"]

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
            out = (o.get("output") or "").strip()[:1000]
            if cmd:
                snippet = f"```\nC2> {cmd}\n{out}\n```" if out else f"```\nC2> {cmd}\n(no output)\n```"
                lines.append(snippet)

    lines.append(f"\n## Operator Question\n{question}")
    return "\n".join(lines)


def _call_claude(prompt: str, api_key: str) -> str:
    model = os.environ.get("ASTAROTH_MODEL", "claude-sonnet-5")
    body  = json.dumps({
        "model":      model,
        "max_tokens": 1500,
        "system":     _SYSTEM,
        "messages":   [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "x-api-key":          api_key,
            "anthropic-version":  "2023-06-01",
            "content-type":       "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            return json.loads(r.read())["content"][0]["text"]
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        return f"[Astaroth — Claude API error {e.code}: {detail}]"
    except Exception as e:
        return f"[Astaroth — error: {e}]"


def _call_ollama(prompt: str) -> str:
    base  = os.environ.get("ASTAROTH_OLLAMA_URL",   "http://localhost:11434")
    model = os.environ.get("ASTAROTH_OLLAMA_MODEL",  "llama3.2")
    full_prompt = _SYSTEM + "\n\n" + prompt
    body = json.dumps({"model": model, "prompt": full_prompt, "stream": False}).encode()
    req  = urllib.request.Request(
        f"{base}/api/generate",
        data=body,
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read()).get("response", "[no response]")
    except Exception as e:
        return (
            f"[Astaroth — no backend available]\n\n"
            f"Set ANTHROPIC_API_KEY for Claude, or run Ollama locally.\n"
            f"Error: {e}"
        )
