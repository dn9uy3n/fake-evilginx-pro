#!/usr/bin/env python3
# test_jsobf_decode.py — prove ultra obfuscation round-trips: decode the
# string-array payload embedded in a proxied page back to plaintext.
# Usage: python3 test_jsobf_decode.py <page.html> [marker]
import base64
import re
import sys

html = open(sys.argv[1]).read()
marker = sys.argv[2] if len(sys.argv) > 2 else None

m = re.search(r"var (_0x[0-9a-z]+)=\[(.*?)\];var (_0x[0-9a-z]+)=function\(i\)\{i=\(i\+(\d+)\)%(\d+);", html)
if not m:
    print("NO-ULTRA-FOUND")
    sys.exit(2)

arrname, arrsrc, _, rot, n = m.groups()
chunks = re.findall(r'"([^"]*)"', arrsrc)
rot, n = int(rot), int(n)
if len(chunks) != n:
    print("chunk count mismatch:", len(chunks), n)
    sys.exit(2)

b64 = ""
for i in range(n):
    c = chunks[(i + rot) % n]
    b64 += c[::-1]
payload = base64.b64decode(b64 + "=" * (-len(b64) % 4)).decode("utf-8", "replace")

print("decoded payload bytes:", len(payload))
if marker:
    print("marker %r present:" % marker, marker in payload)
print("payload head:", payload[:70].replace("\n", " "))
