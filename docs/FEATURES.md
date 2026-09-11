# FEATURES.md — fake-evilginx-pro vs Evilginx Pro (parity matrix)

**Base:** evilginx2 CE 3.3.0 (GPL-3.0) + các extension clean-room trong `src/`.
**Quy tắc tham chiếu:** mô tả tính năng công khai của BreakDev + code CE. Binary Pro
leaked trong workspace KHÔNG được dùng làm nguồn decompile/trích xuất.
**Môi trường đích:** mạng nội bộ kín, zero internet egress (xem OFFLINE_OPS_GUIDE.md).

## Trạng thái fork

- **Repo:** `~/evilginx2-src`, branch `extended`: `v0.1` (`8ab9a36`) → `v0.2`
  (`d6e37f4`, #10) → `v0.3` (`86f811c`, #14) → `v0.4` (`b154b89`, #9) →
  `v0.5` (`3df6cd7`, #12)
- **Binary:** `~/evilginx2-lab/evilginx2` md5 `e7383a09eceadd2275c76b5a56f638e5`
- File thêm: `core/lurecrypto.go` (#11), `core/apid.go` (#2), `core/botguard.go` (#4),
  `core/rewrite.go` (#10), `core/jsobf.go` (#9), `core/webhook.go` (#12),
  `database/database_sqlite.go` (#14)
- File sửa: `core/config.go`, `core/terminal.go`, `core/http_proxy.go`, `main.go`,
  `database/database.go`
- Patch tooling (tái lập từ clone sạch, chạy theo thứ tự trong `~/evilginx2-src`):
  `lab/patch_aes_params.py` → `lab/patch_api.py` → `lab/patch_multidomain.py` →
  `lab/patch_botguard.py` (assert-exact-then-replace) + `lab/lurecrypto.go`,
  `lab/apid.go`, `lab/botguard.go` copy vào `core/` → `go build -mod=vendor`

## Ma trận 14 tính năng

| # | Tính năng Pro | Trạng thái | Chi tiết / bằng chứng |
|---|---------------|-----------|----------------------|
| 1 | Client-Server (điều khiển nhiều server từ 1 client) | 🟡 PARTIAL | API (#2) cho remote read sessions/status; fleet-daemon đầy đủ: pending |
| 2 | Evilginx API (HTTPS + client cert + stealth) | ✅ DONE | `-api <port>`; mTLS RequireAndVerifyClientCert; stealth path random persist (`~/.evilginx/api/`); đo được: /status ok, /sessions JSON đủ, no-cert → `tlsv13 alert certificate required`, sai path → 404 |
| 3 | Wildcard TLS (tránh CT logs) | 🟢 OFFLINE-ALT | Mục đích (không lộ hostname lên CT) đạt bằng cert nội bộ: `-developer` self-signed hoặc cert internal CA vào `~/.evilginx/crt/sites/<host>/`; wildcard qua DNS provider API: N/A offline |
| 4 | Botguard (JA4 + JS telemetry, decoy content) | ✅ DONE (v1 server-side) | `-botguard`; ClientHello GREASE parse (peekConn trước vhost SNI) + UA blocklist + header heuristics (Accept-Language/Sec-Fetch/Upgrade-Insecure) → decoy page. Đo được: curl UA → block; fake-UA → score=100; full browser headers → score=60 (chỉ GREASE); Chromium thật gửi GREASE (đo tshark LAB5) sẽ pass — headless VM không render được nên positive-browser-path xác nhận qua pcap measurement + log từng component |
| 5 | Evilpuppet (Chromium telemetry nền) | 🟡 UNBLOCKED-DEFERRED | Headless Chromium đã chạy tốt trên node Ubuntu (thoát blocker VM Kali); thiết kế clean-room sidecar chromedp: `EVILPUPPET_DESIGN.md`; triển khai khi campaign cần chống telemetry-based detection |
| 6 | Cộng đồng phishlet DB | 🟢 OFFLINE-ALT | Không tải được khi offline; quy trình viết phishlet nội bộ đã chuẩn hoá (lab.yaml + example.yaml) |
| 7 | Quản lý DNS provider ngoài (CF/Route53/Gandi) | ⛔ N/A OFFLINE | Môi trường kín dùng hosts/DNS nội bộ — tính năng mất nghĩa |
| 8 | Multi-domain (mỗi phishlet 1 domain) | ✅ DONE | Bỏ suffix-lock `SetSiteHostname`; `GetLureUrl` đã dùng per-phishlet domain sẵn; cookie tracking theo `GetPhishletCookieDomain`. Đo được: lab (labphish.test) + lab2 (labphish2.test) cùng enabled, victim flow trên domain 2 đủ 200/302/200, cookie jar `.labphish2.test`, capture tokens đầy đủ |
| 9 | JS Obfuscation (off→ultra) | ✅ DONE (v2) | v1 high/ultra + **v2 ultra string-array**: b64 chia chunk đảo ngược trong mảng random + accessor rotation + join loop → atob+eval. Đo: 3 fetch = 3 hash; ultra probe exec trong Chromium 152 thật (round-trip marker qua decoder) |
| 10 | rewrite_urls (qua mặt Safe Browsing) | ✅ DONE (v2 path+query) | `rewrite_urls: [{from, to, query_map, drop}]`. Đo inbound: origin nhận `GET /login?email=x%40y.z` (u→email, src dropped); outbound: victim thấy `Location: /secure-verify?done=1&u=labuser`. Creds+tokens captured qua fake path |
| 11 | Custom URL Parameter Encryption (AES-256) | ✅ DONE | AES-256-GCM, key server-side persist (`lure_secret`), nonce‖ct b64url; đo được: URL chỉ có blob, legacy RC4 decode fail, server decrypt đúng `victim=`, `camp=` vào session.Params |
| 12 | Gophish tích hợp sâu | ✅ DONE (webhook) | `-webhook <URL nội bộ>`: POST JSON mỗi khi auth hoàn tất — event/phishlet/session/username/password/**password_sha256**/custom/params/cookie_tokens/remote_addr/useragent. Đo được: receiver nhận đủ, sha256 khớp `sha256("labpass123")`, cookies=true; push server-side (victim không gọi ra ngoài). CE integration cơ bản (admin_url/api_key/rid) giữ nguyên |
| 13 | Automated Server Deployment | ⛔ N/A OFFLINE | Deploy tự động cần SSH tới VPS internet-facing |
| 14 | SQLite storage | ✅ DONE | buntDB → `modernc.org/sqlite` (pure-Go, WAL, single-writer); API exported giữ nguyên (console + REST không đổi); đo được: `file data.db` = SQLite 3.x, sessions sống qua restart |

## KPI (v0.8-extended)

- DONE: 10 (#2 #4 #8 #9 #10 #11 #12 #14 + #1 fleet write-API + #12 rid) ·
  OFFLINE-ALT-DONE: 1 (#3 internal CA) · OFFLINE-ALT: 1 (#6) ·
  DEFERRED: 1 (#5 Evilpuppet — unblocked: headless Chromium chạy trên Ubuntu node) ·
  N/A-OFFLINE: 2 (#7 #13)
- **Fleet 2 node đang chạy thật:** srv-kali 172.24.228.169:8443 + srv-ubuntu
  192.168.80.68:9443 (egctl.py điều khiển từ Windows; certs lab/api-certs-*/)

## Verify nhanh (mỗi khi build lại)

```bash
# lure params AES
printf 'lures get-url 0 k=v\nexit\n' | ./evilginx2 -p <phishlets> -developer
# API mTLS
curl --cacert ~/.evilginx/api/ca.crt --cert ~/.evilginx/api/client.crt \
     --key ~/.evilginx/api/client.key "https://127.0.0.1:<port>/api-<path>/sessions"
```
