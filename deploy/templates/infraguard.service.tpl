[Unit]
Description=InfraGuard redirector fronting evilginx2 (%i)
After=network-online.target evilginx2.service
Wants=network-online.target evilginx2.service
# LƯU Ý: dùng Wants= (KHÔNG Requires=) — Requires sẽ kéo InfraGuard chết theo
# mỗi lần restart/stop evilginx2 (stop propagation)

[Service]
Type=simple
User=ubuntu
WorkingDirectory=${IG_HOME}
EnvironmentFile=${IG_HOME}/.env
ExecStart=${IG_HOME}/.venv/bin/infraguard run -c ${IG_HOME}/config/config.yaml
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
