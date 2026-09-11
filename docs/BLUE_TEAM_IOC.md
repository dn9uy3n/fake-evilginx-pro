# Blue-Team IOC Checklist — Reverse-Proxy Phishing (evilginx2)

**Nguồn:** quan sát trực tiếp từ lab evilginx2 CE 3.3.0 trên Kali (xem
`LAB_EVILGINX2_SETUP.md`, evidence `.reports/evilginx2-lab/`) + đọc mã nguồn
(`~/evilginx2-src/core/`). Áp dụng được cho cả evilginx2 OSS và các framework
cùng lớp (Evilginx Pro, EvilProxy, EvilNoVNC…).

Cơ chế cần phát hiện: kẻ tấn công vận hành reverse proxy trỏ tới trang login thật,
giữ phiên sống qua proxy, capture password **và** session cookie → vượt MFA SMS/TOTP.
Victim không bao giờ nói chuyện trực tiếp với origin thật.

---

## A. Trước tấn công — domain & certificate

| # | Kiểm soát | Chi tiết |
|---|-----------|----------|
| A1 | CT-log monitoring theo brand keyword | Stream cert mới (crt.sh / CertStream), alert khi SAN/CN chứa tên brand, sản phẩm, SSO domain của mình. evilginx2 thật dùng Let's Encrypt per-hostname (`*.attacker-domain`) — cert mới xuất hiện ngay trước chiến dịch. |
| A2 | Lookalike domain sweep | `dnstwist` theo định kỳ trên domain chính (homoglyph, TLD thay thế, thêm `-login`/`-sso`/`-auth`). |
| A3 | Registrar/whois monitoring | Domain đăng ký < 30 ngày + MX trỏ về dịch vụ email dùng thử (mutations của brand). |

## B. Khi detonate link đáng ngờ (mail gateway / sandbox)

| # | Dấu hiệu (từ lab) | Logic phát hiện |
|---|--------------------|-----------------|
| B1 | Chuỗi 302 khi landing | Lure URL → ngay lập tức `302` sang path login proxied (lab: `/npKorgAP` → 302 `/login`). Proxy hợp pháp hiếm khi redirect 302 cứng ngay request đầu. |
| B2 | Cookie tracking lạ set lúc landed | evilginx2 set cookie tên **8 ký tự ngẫu nhiên** (quan sát: `bdaf-1cf9`, source: `GenRandomString(8)`), value **64 hex**, `Domain=<base-domain>`, `Path=/`, không có trên origin thật. Pattern: `^[0-9a-z]{4}-[0-9a-z]{4}$` + giá trị `^[0-9a-f]{64}$`. |
| B3 | Chỉ có HTTP/1.1 | evilginx2 listener khai báo `NextProtos: ["http/1.1", acme-tls/1]` (http_proxy.go:1549) — **không h2**. Origin thật (Google/Microsoft…) luôn h2. Sandbox so sánh protocol trang phishing vs trang thật. |
| B4 | TLS cert bất thường | Lab dev-mode: self-signed/CA lạ → browser warning. Chiến dịch thật: LE hợp lệ nhưng cho domain chưa-từng-thấy (gắn với A1). |
| B5 | HTML khác snapshot origin | `sub_filters` đổi text/title (lab: "LAB ORIGIN" → "PRODUCTION CLONE"), `auto_filter` rewrite mọi URL origin → phish domain. So khớp fuzzy-hash (tlsh/ssdeep) trang login với bản chính thức. |
| B6 | JS injected bắt MFA | `js_inject` trong phishlet chèn `<script>` không tồn tại trên origin — thường chờ OTP/2FA code. DOM-diff hoặc CSP report-uri sẽ thấy script nguồn lạ. |

## C. Trên origin / CDN / WAF (nhìn từ phía bị giả mạo)

| # | Dấu hiệu | Logic phát hiện |
|---|----------|-----------------|
| C1 | **TLS fingerprint ≠ UA** (IOC mạnh nhất từ lab — đo thật, xem ghi chú) | evilginx2 fetch origin bằng Go `http.Transport` — UA được pass-through từ victim (lab thấy `curl/8.20.0` đi nguyên) nhưng TLS stack là của server-side library, không của Chrome/Firefox. Match "UA trình duyệt + TLS fingerprint phi-trình-duyệt" = reverse proxy / scripted client gần như chắc chắn. |

**C1 — số đo thật trong lab (tshark 4.6.6, loopback, có kiểm soát thời gian — sửa lại LAB4):**

```
evilginx2 upstream (Go http.Transport qua goproxy)  JA3_MD5 = 6fcb7aa10768c08e39459bf9b7478ab4
  → 14 cipher suites (c02b,c02f,c02c,c030,cca9,cca8,c009,c013,c00a,c014,c012,1301,1302,1303)
  → KHÔNG ALPN (Go tắt auto-h2 khi Transport có TLSClientConfig → upstream chỉ HTTP/1.1)
  → KHÔNG GREASE
curl 8.20 (OpenSSL 3.5, cùng máy)                   JA3_MD5 = c654189f0cbcfb638bb74b824e790138
  → 87 suites, ALPN h2,http/1.1, KHÔNG GREASE
Chromium 148 (headless)                              JA3 đổi MỖI kết nối (f4d594a0…, b827f8a6…)
  → CÓ GREASE (vd cipher đầu 0x3a3a) + extension order bị randomize theo thiết kế
```

Hai bài học đo được (một cái là tự sửa lỗi attribution ở LAB4: hash 87-suite c654 lúc
đầu gán nhầm cho evilginx2 — thực ra là curl):

1. **Browser JA3 là non-deterministic** (Chrome randomize extension order) → match
   JA3-hash "của trình duyệt" vô nghĩa từ cả hai phía. Chỉ có **family rule** dùng được.
2. **No-GREASE rule (bền vững nhất):** Chromium luôn gửi GREASE (0x?a?a trong
   ciphers/groups); Go, curl, Python không bao giờ gửi. UA khai báo trình duyệt +
   ClientHello không GREASE = client server-side giả danh trình duyệt = reverse proxy.
3. **No-ALPN/h1-only subtype (evilginx2 cụ thể):** upstream fetch của evilginx2 không
   có extension ALPN → luôn nói HTTP/1.1 với origin trong khi mọi trình duyệt hiện đại
   đề nghị h2. Origin/CDN log: "login page fetch bằng HTTP/1.1 + UA trình duyệt" là
   dấu hiệu proxy. (Framework khác có thể khác — đo trước khi áp.)
4. **UA pass-through:** UA của victim được forward nguyên vẹn qua proxy (lab: curl UA
   tới tận origin) — vì vậy UA từ origin KHÔNG phải bằng chứng; TLS layer mới đáng tin.
| C2 | Path lure ngẫu nhiên | Trước khi vào `/login`, luôn đi qua path ngẫu nhiên kiểu `[A-Za-z]{8}` (lab: `/npKorgAP`) — Pattern scan access log. |
| C3 | Cùng session, hai vị trí | Session cookie bị capture → attacker dùng song song với victim: geo-impossible-travel, UA đổi giữa các request, ASN hosting/datacenter xen giữa user-home. |
| C4 | Referrer lạ vào trang login | Lượt vào trang login từ domain không phải hệ sinh thái chính thức, tỷ lệ nhỏ nhưng đều (target chọn lọc). |

## D. Endpoint & người dùng

| # | Dấu hiệu | Ghi chú |
|---|----------|---------|
| D1 | Password manager không autofill | Autocomplete ghép domain — trên lookalike domain không điền được. Cấy thói quen "không autofill = soi URL". |
| D2 | Warning chứng chỉ | Với lab/dev hoặc cert kém — không đáng tin ở chiến dịch thật (họ dùng LE hợp lệ). |
| D3 | Extension/agent kiểm tra URL vs page-brand | Phòng thủ kiến trúc: page mới render → so URL host với danh sách SSO domain đã đăng ký của org. |

## E. Khuyến nghị kiến trúc (chặn tận gốc lớp tấn công này)

1. **FIDO2 / WebAuthn / passkeys** cho mọi hệ thống quan trọng — origin-binding khiến
   session cookie + password capture vô dụng (proxy không có private key).
2. CT-log alert (A1) + phản ứng: nộp AbuseReport tới CA/registrar/hosting trong giờ đầu.
3. Session hardening phía origin: bind session theo device fingerprint + re-auth với
   WebAuthn khi thấy C3; short-TTL cho session nhạy cảm.
4. Replica-page tarpit: origin phản hồi JS probe (fetch resource chỉ browser thật mới
   chạy) — proxy Go không thực thi JS → phát hiện B-class trước khi victim gõ password.

## Mẫu truy vấn nhanh

```text
# Proxy/IDS (B2): cookie tracking evilginx2-style
http.cookie ~ /^[0-9a-z]{4}-[0-9a-z]{4}=[0-9a-f]{64}/ AND http.response.headers["Set-Cookie"] contains "Path=/"

# Origin WAF (C1): UA trình duyệt + TLS fingerprint Go
tls.ja3_hash IN (known_go_http_client_hashes) AND user_agent ~ "(Chrome|Firefox|Edg)/"

# Access log origin (C2)
http.request.url.path ~ "^/[A-Za-z]{8}$" AND referer NOT IN (official_domains)
```

## Ranh giới

Checklist này lập từ lab **tự dựng, chỉ nhắm test site của mình** (`portal.labsvc.test`,
tài khoản `labuser` tự tạo). Không hàm chứa quan sát nào trên hệ thống của bên thứ ba.
