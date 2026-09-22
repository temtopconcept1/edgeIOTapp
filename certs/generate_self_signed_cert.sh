#!/bin/bash
# certs/generate_self_signed_cert.sh
#
# Generates a self-signed TLS certificate + private key for LOCAL
# development/demonstration of HTTPS only. Browsers will show a
# "not secure" warning for a self-signed certificate — this is expected
# and is why real deployments use a certificate from a trusted CA
# (or an internal CA for private networks).
#
# Usage:
#   bash certs/generate_self_signed_cert.sh
#
# Then run the app with HTTPS:
#   python app.py --https
# (see app.py / README.md for how the --https flag is wired to these files)

set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

openssl req -x509 -newkey rsa:2048 \
  -keyout "$DIR/key.pem" \
  -out "$DIR/cert.pem" \
  -days 365 -nodes \
  -subj "/C=NG/ST=Lagos/L=Lagos/O=SSEMS-Prototype/CN=localhost"

echo "Generated $DIR/cert.pem and $DIR/key.pem (self-signed, 365 days)."
