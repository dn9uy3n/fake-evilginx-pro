# Changelog — fake-evilginx-pro (dòng evilginx2-extended)

Fork từ [evilginx2 CE 3.3.0](https://github.com/kgretzky/evilginx2) (commit upstream
`4c0988a`). Mọi tính năng mở rộng được viết clean-room (không tham chiếu binary
thương mại) và verify end-to-end trên lab 2 node (Kali + Ubuntu).

## v0.10 (2026-09-08)
- **Phishlet hot-reload**: `phishlets reload` (console), `POST /phishlets/reload`
  (API), auto-watch thư mục qua fsnotify có sẵn (`-no-watch` tắt) — thêm/sửa/xóa
  YAML không cần restart node (verified live: drop/touch/rm -> watch +N ~N -N).
- **Config mutex**: khóa toàn bộ mutator (deadlock-safe qua savePhishletsNL) —
  vá race console-vs-API mà recon phát hiện.
- **JA4 cho Botguard**: `core/ja4.go` (spec FoxIO, parse từ ClientHello đã peek)
  + unit-test với vector ClientHello THẬT (chromium/curl/go từ captures lab);
  `-bg-ja4 <prefixes>` allowlist (+50 điểm khi ngoài list); eviction các map
  botguard (trước đây grow unbounded). Live: curl giả UA đầy đủ vẫn decoy
  (score=110), chromium pass.
- **Writer-API lure**: `GET /lures` (list), `GET/PUT/DELETE /lures/{id}` (edit
  đầy đủ field + validation như terminal), id là index (delete renumber);
  egctl thêm `lures-list/lure-edit/lure-del/hostname/reload-phishlets`.
- **API hostname**: `POST /phishlets/{name}/hostname` — lỗ hổng fleet được
  phát hiện khi verify (console one-shot không visible cho server process).

## v0.10.1 (2026-09-08)
- **Detonator-aware Botguard** (Microsoft Safe Links / Defender classification):
  referer patterns (`*.protection.outlook.com`, safelinks, smartscreen) + optional
  client CIDR ranges (`-bg-det-cidrs`); flagged sessions pinned to decoy,
  telemetry refused, `/status` exposes `detonators` counter.
  Verified: safelinks-referer request -> `DETONATOR classified` + decoy;
  counter = 1. Chromium thật vẫn pass (không referer safelinks).

## v0.9.1 (2026-09-08)
- **#5 evilpuppet-lite (code ships)**: sidecar `puppet/` (chromedp) — headless
  login qua proxy, cookie extraction, push mTLS về API; endpoint mới
  `POST /pp/cookies` merge cookies vào session sống + mark botguard-verified.
  E2e pending: chromium DNS quirk với tên chỉ có trong /etc/hosts (hướng fix:
  dnsmasq zone nội bộ). Xem `docs/EVILPUPPET.md`.
- Tools mới: `deploy_offline.sh` (#13 offline — SSH deploy + systemd),
  `make_dns_zone.py` (#7 offline — dnsmasq zone).

## v0.9 (2026-09-08)
- **#6 authoring kit**: `make_phishlet.py` (generator + lint) + redirector
  templates (`interstitial`, `download`) trong `src/redirectors/`.
- **#5 UNBLOCKED**: headless Chromium chạy được trên node Ubuntu (thoát blocker
  VM Kali); thiết kế sidecar hoàn chỉnh.
- **Egress audit cuối** (full flags): server-only **0 packets** — 292 packets
  đo được 100% do Chromium snap phone-home (browser mô phỏng, không phải
  framework).
- Phát hiện giới hạn CE: **không phishlet hot-reload** — thêm phishlet phải
  restart node (khác Pro).

## v0.8 (2026-09-08)
- **#9 v2 ultra obfuscator**: string-array (chunk đảo ngược + rotation accessor
  + join loop → atob+eval) — cấu trúc khác mỗi response.
- **#10 v2 query rewrite**: `query_map` (đổi tên param victim→origin) + `drop`
  (xóa param) — hai chiều; outbound Location map ngược cả query.

## v0.7 (2026-09-08)
- **#4 Botguard v2 (JS telemetry)**: probe JS ultra-obfuscated tự inject;
  endpoint `/t/<HMAC-SHA256(lureKey, sid)>`; grace gating (`-bg-grace`); sau
  grace, session chưa verified bị decoy khi chạm credentials; `-bg-ua=false`
  tắt riêng lớp UA (cho headless runtime). Verify bằng Chromium 152 thật.

## v0.6 (2026-09-08)
- **#1 fleet**: REST API write-actions — `GET /phishlets`, `POST
  /phishlets/{name}/enable|disable`, `POST /lures`, `GET /lures/{id}/url` (AES),
  `DELETE /sessions/{id}`; `BuildLureUrl` dùng chung terminal + API; client
  `egctl.py` điều khiển đa server từ PC cá nhân.
- **#12 v2**: webhook payload thêm `rid` top-level (campaign tracking qua AES
  lure params).
- **#3 offline**: `mint_internal_cert.sh` — internal CA; verify chuỗi hợp lệ +
  zero egress khi chạy không `-developer`, `autocert off`.

## v0.5 (2026-09-08)
- **#12 webhook**: `-webhook URL` — POST JSON một lần/session khi auth-complete:
  event/phishlet/session/username/password/**password_sha256**/custom/params/
  cookie_tokens/remote_addr/useragent.

## v0.4 (2026-09-08)
- **#9 JS obfuscation v1**: `-jsobf off/low/medium/high/ultra`; choke point
  `/s/<sid>/<jsid>.js`; 3 fetch cùng URL = 3 hash khác nhau.

## v0.3 (2026-09-08)
- **#14 SQLite**: thay toàn bộ buntDB bằng modernc.org/sqlite (pure-Go, WAL);
  exported API không đổi; persistence qua restart.

## v0.2 (2026-09-08)
- **#10 rewrite_urls v1**: path rewrite hai chiều — victim không thấy path
  thật của origin.

## v0.1 (2026-09-08)
- **#11 AES-256-GCM lure params**: thay RC4-key-trong-URL của CE bằng key
  server-side persist (`general.lure_secret`); fallback RC4 cho URL cũ.
- **#2 REST API mTLS**: listener riêng, client cert tự sinh, stealth base
  path random persist (`/status`, `/sessions`, `/sessions/{id}`).
- **#8 multi-domain**: bỏ suffix-lock `SetSiteHostname`; cookie tracking theo
  domain phishlet (`GetPhishletCookieDomain`).
- **#4 Botguard v1**: ClientHello GREASE parse (peekConn trước vhost SNI) +
  UA blocklist + header heuristics → trang decoy.

## Base
- upstream evilginx2 CE 3.3.0 (`4c0988a`) — GPL-3.0, Kuba Gretzky.
