#!/bin/sh
# mint_internal_cert.sh — internal CA + server cert for offline evilginx2-extended.
# Pro-feature #3 offline alternative: no public ACME, no CT logs, no egress.
# Usage: ./mint_internal_cert.sh <hostname> [extra SAN ...]
#   e.g. ./mint_internal_cert.sh www.labphish.test labphish.test
set -e

HOST="$1"
[ -z "$HOST" ] && { echo "usage: $0 <hostname> [extra SAN ...]"; exit 1; }
shift || true

CA_DIR="$HOME/.evilginx/internal-ca"
SITE_DIR="$HOME/.evilginx/crt/sites/$HOST"
mkdir -p "$CA_DIR" "$SITE_DIR"

# 1) internal CA (once)
if [ ! -f "$CA_DIR/ca.key" ]; then
    openssl genrsa -out "$CA_DIR/ca.key" 4096 2>/dev/null
    openssl req -x509 -new -key "$CA_DIR/ca.key" -days 3650 -nodes \
        -subj "/CN=evilginx2-extended Internal CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$CA_DIR/ca.crt"
    chmod 600 "$CA_DIR/ca.key"
    echo "[ca] created $CA_DIR/ca.crt"
else
    echo "[ca] reusing existing CA"
fi

# 2) server cert signed by internal CA
openssl genrsa -out "$SITE_DIR/privkey.pem" 2048 2>/dev/null
SAN="DNS:$HOST"
for extra in "$@"; do SAN="$SAN,DNS:$extra"; done
openssl req -new -key "$SITE_DIR/privkey.pem" \
    -subj "/CN=$HOST" -out /tmp/internal.csr
cat > /tmp/internal.ext <<EOF
subjectAltName=$SAN
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
basicConstraints=CA:FALSE
EOF
openssl x509 -req -in /tmp/internal.csr -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" \
    -CAcreateserial -days 825 -extfile /tmp/internal.ext \
    -out "$SITE_DIR/fullchain.pem" 2>/dev/null
cat "$CA_DIR/ca.crt" >> "$SITE_DIR/fullchain.pem"
rm -f /tmp/internal.csr /tmp/internal.ext
chmod 600 "$SITE_DIR/privkey.pem"

echo "[cert] $SITE_DIR/fullchain.pem (+privkey.pem)"
echo
echo "Next steps:"
echo "  1. evilginx2 console: config autocert off   (avoid Let's Encrypt egress)"
echo "  2. restart evilginx2 WITHOUT -developer -> unmanaged certs are loaded from crt/sites/"
echo "  3. import the CA into lab victim browsers:  $CA_DIR/ca.crt"
echo "  4. curl verify: curl --cacert $CA_DIR/ca.crt https://$HOST/"
