# tools/

Toàn bộ toolchain vận hành của fake-evilginx-pro. Chạy bằng Python 3 (stdlib)
hoặc bash; không cần cài thêm gì.

| Tool | Chức năng | Ví dụ |
|------|-----------|-------|
| `egctl.py` | **Client fleet** — điều khiển mọi server từ PC cá nhân qua API mTLS | `python3 egctl.py servers.json status` |
| `make_phishlet.py` | Sinh phishlet YAML + lint (authoring kit) | `python3 make_phishlet.py --name m1 --phish-domain lab.test --orig-host portal.lab.test --cookie SESS` |
| `mint_internal_cert.sh` | Internal CA + cert cho hostname (thay ACME, zero egress) | `./mint_internal_cert.sh www.lab.test lab.test` |
| `deploy_offline.sh` | Auto-deploy fork lên host nội bộ qua SSH + systemd | `./deploy_offline.sh 192.168.1.50 ubuntu pass /tmp/src.tar.gz` |
| `make_dns_zone.py` | Sinh dnsmasq zone cho phish domain (DNS nội bộ đa máy) | `python3 make_dns_zone.py --domain lab.test --ip 192.168.1.10` |
| `ja3.py` | JA3 md5 calculator từ pipe tshark (audit TLS fingerprint) | xem `docs/BLUE_TEAM_IOC.md` |

## lab/ — môi trường lab tự dựng

| File | Chức năng |
|------|-----------|
| `testsite.py` | Origin mô phỏng: HTTPS login (127.0.0.2:443), cert tự sinh, log request |
| `webhook_rx.py` | Receiver :9090 ghi JSON creds từ `-webhook` vào `webhook_rx.log` |
| `verify_bg2.py` | Verifier Botguard v2 (probe decode + gating flow) |
| `test_jsobf_decode.py` | Decode payload ultra string-array (chứng minh round-trip) |

Lưu ý: `testsite.py`/`webhook_rx.py` tự定位 BASE theo `$HOME/evilginx2-lab` —
đổi bằng biến môi trường hoặc sửa hằng nếu đặt chỗ khác.

## patches/ — bảo trì rebase lên upstream mới

Bộ patch scripts (assert-exact-then-replace) đã dùng để tạo fork từ evilginx2
CE 3.3.0, kèm file .go gốc của từng extension. Khi upstream phát hành bản mới:

1. Clone upstream mới, vào thư mục repo.
2. Copy các file .go vào đúng vị trí (`core/`, `database/`).
3. Chạy các patch theo thứ tự số (w1→w5), mỗi script sẽ abort nếu anchor lệch.
4. `go mod tidy && go mod vendor && go build -mod=vendor`.

Thứ tự khuyến nghị: `patch_aes_params` → `patch_api` → `patch_multidomain` →
`patch_botguard` → `patch_botguard2` → `patch_bg3` → `patch_rewrite` →
`patch_jsobf` → `patch_jsobf2` → `patch_webhook` → `patch_wave1` →
`patch_wave3` → `patch_wave5`.
