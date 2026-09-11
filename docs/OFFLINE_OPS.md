# OFFLINE_OPS_GUIDE.md — Chạy evilginx trong môi trường nội bộ kín (zero internet egress)

**Ngày:** 2026-09-08 · **Trạng thái:** đã verify thực nghiệm trên Kali lab
**Phạm vi:** evilginx2 CE 3.3.0 (đo trực tiếp) + nguyên tắc containment áp dụng được
cho mọi tool trong chiến dịch, kể cả Evilginx Pro **đã có license hợp lệ**.

## 1. Bản đồ điểm chạm mạng của evilginx2 CE (audit source + đo)

| # | Điểm chạm | Khi nào phát sinh | Trạng thái offline |
|---|-----------|-------------------|--------------------|
| N1 | Let's Encrypt ACME (`acme-v02.api.letsencrypt.org`) | **CHỈ khi** autocert on và chạy không có `-developer` | TẮT bằng `-developer` hoặc `config autocert off` |
| N2 | Resolve + fetch origin (HTTPS:443) | Mỗi request victim | Trỏ origin về host nội bộ (/etc/hosts hoặc DNS nội bộ) |
| N3 | DNS server :53 | Khi có client query | Authoritative-only, **không forward** ra internet (grep `nameserver.go` — không có code recursion) |
| N4 | External IP | `config ipv4 external` — set tay | Không gọi service nào (grep: không có ipify/icanhazip…) |
| N5 | GoPhish client | Chỉ khi cấu hình admin_url/api_key | Không cấu hình = không chạy |
| N6 | Update/telemetry | — | Không tồn tại trong CE (grep `main.go`) |
| N7 | **unauth_url mặc định = YouTube** | Victim không hợp lệ bị redirect | ⚠️ **egress phía victim** — bắt buộc `config unauth_url` sang URL nội bộ |
| N8 | Session data | — | Lưu local (`~/.evilginx/data.db`), không upload |

## 2. Kết quả đo (Kali, tcpdump dst-based filter)

**Phase A — posture offline (`-developer`, hosts-file DNS, origin nội bộ), full flow
startup → lure → POST creds → portal → sessions:**

```
egress packets (dst ngoài mọi private range): 0
flow: lure:200 post:302 portal:200 — capture vẫn hoạt động hoàn chỉnh
```

**Phase B — `autocert on`, chạy không `-developer`:**

```
evilginx2 log: HTTP 400 từ https://acme-v02.api.letsencrypt.org/acme/new-order
(= ACME round-trip internet thật, dù chỉ 1 phishlet enabled)
```

→ `autocert` là **duy nhất một** cấu hình mặc định đẩy tool ra internet.

> Ghi chú phương pháp (đắt giá): (1) filter egress phải theo **dst** —
> `not net 172.16/12` loại cả packet có *src* thuộc 172.x và che mất egress thật;
> (2) `kill -9` tcpdump làm mất packet chưa flush — dùng `-U` (packet-buffered) và
> `kill -INT`; (3) khi không bắt được packet, log của chính app (HTTP 400 từ LE)
> vẫn là bằng chứng round-trip.

## 3. Checklist cấu hình offline cho CE

1. Chạy với `-developer` (cert tự ký mọi hostname) **hoặc** `config autocert off` +
   cert thật đặt vào `~/.evilginx/crt/sites/<hostname>/` (`fullchain.pem`+`privkey.pem`).
2. `/etc/hosts` (hoặc DNS nội bộ): hostname phish → IP evilginx, hostname origin → IP nội bộ.
3. Phishlet trỏ `proxy_hosts.domain` về origin nội bộ (tham khảo `lab.yaml` trong lab).
4. `config ipv4 external <IP nội bộ>`, `config ipv4 bind <IP nội bộ>`.
5. `config unauth_url https://<trang nội bộ>/` — **không để mặc định YouTube** (N7).
6. Lure `redirect_url` trỏ nội bộ. Không cấu hình GoPhish (N5) hoặc trỏ GoPhish nội bộ.
7. Kiểm chứng trước chiến dịch: chạy lại tcpdump dst-filter (mục 2) với đúng posture,
   yêu cầu kết quả 0 packet.

## 4. Network containment (vòng ngoài, áp cho MỌI tool — gồm Pro đã license)

Defense-in-depth: kể cả app "hứa" không gọi ra ngoài, vẫn khoan vùng mạng:

```bash
# netns không default route (kho eCommerce nhất)
sudo ip netns add rt-internal
sudo ip link add veth0 type veth peer name veth1 netns rt-internal
sudo ip addr add 10.66.0.1/24 dev veth0 && sudo ip link set veth0 up
sudo ip netns exec rt-internal ip link set lo up
sudo ip netns exec rt-internal ip addr add 10.66.0.2/24 dev veth1
sudo ip netns exec rt-internal ip link set veth1 up
# chỉ route tới dải nội bộ — không default route ⇒ không thể ra internet
sudo ip netns exec rt-internal ip route add 172.24.0.0/16 via 10.66.0.1
sudo ip netns exec rt-internal /home/kali/evilginx2-lab/evilginx2 -p ... -developer

# nftables chặn egress cho user riêng (cách khác)
nft add table inet rt-egress
nft add chain inet rt-egress out "{ type filter output priority 0; }"
nft add rule inet rt-egress out oif "lo" accept
nft add rule inet rt-egress out ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept
nft add rule inet rt-egress out ip daddr != { private ranges } drop
```

Audit template trước mỗi chiến dịch (đo, đừng tin lời hứa):

```bash
sudo tcpdump -i any -U -w egress.pcap "not dst net 127.0.0.0/8 and not dst net 10/8 \
  and not dst net 172.16/12 and not dst net 192.168/16 and not dst net 169.254/16 and not ip6"
# chạy tool + full workflow → kỳ vọng 0 packet
```

## 5. Victim-side egress (dễ quên trong môi trường kín)

- Trang login được proxy phải render được mà **không** tải asset từ CDN ngoài
  (font/js/icon) — nếu origin nội bộ thì tự thỏa; nếu demo với trang có asset ngoài,
  victim browser sẽ leak DNS/HTTP ra ngoài. Audit bằng DevTools/ HAR trên lure nội bộ.
- `unauth_url`, `redirect_url`, og_* lure fields: tất cả trỏ nội bộ.
- Cert cho hostname nội bộ: internal CA (import vào browser lab) hoặc self-signed
  (browser sẽ warning — chấp nhận được trong demo nội bộ có kiểm soát).

## 6. Về Evilginx Pro (license hợp lệ)

- Đường đúng cho môi trường kín: **hỏi BreakDev support** về offline activation /
  danh sách endpoint bắt buộc để allowlist. Vendor bán cho red teamer — đây là use-case
  chính đáng họ xử lý trực tiếp.
- Nếu binary lỗi khi chạy với license hợp lệ: gửi bug report (strace + log + mô tả).
- Không patch/vá cơ chế license trong binary — ngoài phạm vi hỗ trợ.
