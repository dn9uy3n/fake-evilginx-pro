#!/usr/bin/env python3
# ja3.py — JA3 md5 từ pipe tshark -T fields (7 section phân tách '|')
# thứ tự field: version|ciphersuite|extension.type|supported_group|ec_point_format|server_name|alpn
import sys
import hashlib

GREASE = {int(f"{h:02x}0a", 16) for h in range(0x0A, 0xFF, 0x10)}


def ints(s):
    out = []
    for tok in (s or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        v = int(tok, 16) if tok.lower().startswith("0x") else int(tok)
        if v in GREASE:
            continue
        out.append(str(v))
    return out


for line in sys.stdin:
    parts = (line.rstrip("\n").split("|") + [""] * 7)[:7]
    ver_s, ciph, exts, groups, ecpf, sni, alpn = parts
    if not ciph:
        continue
    if "." in ver_s:
        a, b = ver_s.split(".")
        ver = str(int(a) * 256 + int(b))
    else:
        ver = str(int(ver_s, 0)) if ver_s else "771"
    ja3s = ",".join([
        ver,
        "-".join(ints(ciph)),
        "-".join(ints(exts)),
        "-".join(ints(groups)),
        "-".join(ints(ecpf)),
    ])
    print(f"SNI={sni or '-'} ALPN={alpn or '-'}")
    print(f"  ja3_string={ja3s}")
    print(f"  JA3_MD5={hashlib.md5(ja3s.encode()).hexdigest()}")
