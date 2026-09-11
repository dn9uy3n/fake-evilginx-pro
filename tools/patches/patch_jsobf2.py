#!/usr/bin/env python3
# patch_jsobf2.py — obfuscate at the /s/*.js serve handler (the real choke point)
import sys

path = "core/http_proxy.go"
old = ('\t\t\t\t\t\t\tscript, err := pl.GetScriptInjectById(js_id, js_params)\n'
       '\t\t\t\t\t\t\tif err == nil {\n'
       '\t\t\t\t\t\t\t\td_body += script + "\\n\\n"\n')
new = ('\t\t\t\t\t\t\tscript, err := pl.GetScriptInjectById(js_id, js_params)\n'
       '\t\t\t\t\t\t\tif err == nil {\n'
       '\t\t\t\t\t\t\t\tscript = ObfuscateJS(script, p.jsobf)\n'
       '\t\t\t\t\t\t\t\td_body += script + "\\n\\n"\n')
src = open(path, "r", encoding="utf-8").read()
n = src.count(old)
if n != 1:
    sys.exit("[abort] pattern found %dx" % n)
open(path, "w", encoding="utf-8").write(src.replace(old, new))
print("[patch] serve-handler obfuscation OK")
