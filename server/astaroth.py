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
            out = (o.get("output") or "").strip()[:1000]
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
