#!/bin/sh
set -eu
umask 077

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cert_dir="$repo_dir/build/webtransport-cert"
mkdir -p "$cert_dir"

if [ -e "$cert_dir/server.key" ] || [ -e "$cert_dir/server.crt" ]; then
    echo "Certificate files already exist in $cert_dir" >&2
    echo "Move them aside before generating a replacement." >&2
    exit 1
fi

cert_tmp=$(mktemp -d "$cert_dir/.generate.XXXXXX")
trap 'rm -rf "$cert_tmp"' EXIT HUP INT TERM
cat > "$cert_tmp/openssl.cnf" <<'EOF'
[req]
distinguished_name = subject
x509_extensions = extensions
prompt = no
[subject]
CN = localhost
[extensions]
subjectAltName = DNS:localhost,IP:127.0.0.1,IP:::1
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
EOF

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -nodes -sha256 -days 13 -config "$cert_tmp/openssl.cnf" \
    -keyout "$cert_tmp/server.key" -out "$cert_tmp/server.crt"
openssl x509 -in "$cert_tmp/server.crt" -outform DER \
    -out "$cert_tmp/server.der"
openssl x509 -in "$cert_tmp/server.crt" -noout -fingerprint -sha256 \
    > "$cert_tmp/fingerprint.txt"

mv "$cert_tmp/server.key" "$cert_tmp/server.crt" \
    "$cert_tmp/server.der" "$cert_tmp/fingerprint.txt" "$cert_dir/"
cat "$cert_dir/fingerprint.txt"
echo "Certificate and private key: $cert_dir"
