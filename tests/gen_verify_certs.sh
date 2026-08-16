#!/bin/sh
# gen_verify_certs.sh — regenerate the S-B4 'starttls-verify' test PKI.
# Run from the repo root (writes into tests/). Requires openssl.
# Committed outputs: tests/verify-ca.pem, tests/verify-relay.pem + .key,
# tests/verify-wrongca.pem. The CA private key (verify-ca.key) is a throwaway
# generation byproduct, NOT committed — re-running produces new certs; the
# committed PEMs are the stable test inputs (3650-day validity).
set -eu
cd "$(dirname "$0")"
openssl req -x509 -newkey rsa:2048 -keyout verify-ca.key -out verify-ca.pem \
  -days 3650 -nodes -subj '/CN=visage-test-CA'
openssl req -newkey rsa:2048 -keyout verify-relay.key -out verify-relay.csr \
  -nodes -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
openssl x509 -req -in verify-relay.csr -CA verify-ca.pem -CAkey verify-ca.key \
  -CAcreateserial -out verify-relay.pem -days 3650 -copy_extensions copy
openssl req -x509 -newkey rsa:2048 -keyout verify-wrongca.key -out verify-wrongca.pem \
  -days 3650 -nodes -subj '/CN=unrelated-CA'
rm -f verify-relay.csr verify-ca.srl
rm -f verify-ca.key verify-wrongca.key
echo 'generated verify-ca.pem verify-relay.pem verify-relay.key verify-wrongca.pem'
