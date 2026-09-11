# EVILPUPPET_DESIGN.md — thiết kế Evilpuppet-lite cho evilginx2-extended (#5)

**Trạng thái:** UNBLOCKED (headless Chromium chạy tốt trên node Ubuntu; Kali VM vẫn treo) ·
**Triển khai:** deferred — cần 1 đợt làm việc riêng sau Wave 4.

## Mục tiêu (theo mô tả công khai của Pro)

Browser thật chạy nền trên server tạo ra **browser telemetry hợp lệ** để session
phishing có dấu vân vân máy-học giống victim thật — qua mặt các hệ thống phát hiện
dựa trên telemetry (device fingerprint, handler ordering, client hints...).

## Kiến trúc clean-room (không tham chiếu binary Pro)

```
[evilginx2-extended]  <--HTTP nội bộ-->  [puppet sidecar: chromedp]
        |                                        |
        |                          điều khiển Chromium thật (headless)
        v
   origin thật (nhận traffic + telemetry của chromium)
```

1. **Sidecar** `puppet/` (Go + chromedp): nhận tác vụ qua HTTP nội bộ
   `POST /visit {url, session_token, wait_ms}` — chạy Chromium truy cập trang
   login thật **trong khi victim cũng đang được proxy** — telemetry (TLS JA3 của
   Chromium, HTTP/2 SETTINGS, handler ordering, client hints) đi thẳng tới origin
   gắn với cùng session.
2. **Liên kết session**: evilginx2 gắn `session_token` vào URL victim (đã có cơ chế
   AES params #11); sidecar dùng cùng token → origin thấy 2 "người dùng" cùng
   session: victim (qua proxy) + puppet (browser thật).
3. **Cookie pre-warm**: puppet đăng nhập TRƯỚC bằng tài khoản bot của org (nếu
   chiến dịch cho phép) hoặc chỉ warm-up trang tĩnh; cookie hợp lệ được export về
   evilginx2 qua endpoint nội bộ `POST /pp/cookies` (mTLS như API).
4. **Lưu ý an toàn**: puppet chỉ chạy với origin = mục tiêu đã được ủy quyền trong
   kế hoạch campaign; mọi request puppet đi qua cùng containment zero-egress.

## Tại sao defer

- Cần chromedp + sub-deps (network install `go get` trên node có internet — Ubuntu
  node hiện đã có internet ổn định sau fix DNS).
- Kỹ thuật đã có sẵn: headless Chromium hoạt động trên Ubuntu (verify LAB15),
  fleet API có thể host endpoint /pp/, jsobf có thể obfuscate cả trang trung gian.
- Ước lượng: 1 đợt làm việc (sidecar + endpoint + verify e2e bằng cả curl lẫn
  chromium).

## Khi nào làm

Ngay sau khi campaign xác nhận cần chống lại hệ thống phát hiện dựa trên telemetry
(Sentinel/Abnormal-class). Nếu mục tiêu chỉ có email-gateway + MFA thông thường →
không cần #5.
