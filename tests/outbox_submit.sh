#!/usr/bin/env bash
# outbox_submit.sh — loopback integration test for the outbox daemon.
#
# Exercises the full submission contract WITHOUT touching real DNS/MX:
#   - fake authoritative DNS (tests/outbox_dns.py) answers MX/A for deliver.test
#   - fake recording MX (tests/outbox_fakemx.py) on 127.0.0.1:12525
#   - outbox delivers DIRECT to that MX via --deliver-port 12525
#
# Positive: STARTTLS + AUTH PLAIN -> 235; AUTH LOGIN -> 235; implicit-TLS AUTH
# -> 235; MAIL/RCPT/DATA -> 250 with delivery attempted; the delivered message
# carries a DKIM-Signature d=jaye.ch s=visage that verifies against the
# generated public key.
#
# Negative: AUTH over plaintext :587 -> 530; unauthenticated MAIL -> 530;
# From:-domain != envelope MAIL FROM domain -> 554 (and no delivery).
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CCFLAGS="-std=c11 -O2 -g -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -I vendor/dhall-c/src -I vendor/datalog-dafsa/src -I vendor/datalog-dafsa/vendor"
MBFLAGS='-I vendor/mbedtls/include -I src -DMBEDTLS_CONFIG_FILE="mbedtls_visage_config.h"'
MB="vendor/mbedtls/build/*.o"

DNS_PORT=15300
FAKEMX_PORT=12525
IMPLICIT_PORT=10465
STARTTLS_PORT=10587

T="$(mktemp -d /tmp/outbox_test.XXXXXX)"
trap 'kill ${DNS_PID:-} ${FAKEMX_PID:-} ${OUTBOX_PID:-} 2>/dev/null; rm -rf "$T"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok   $*"; }

# ---- build (idempotent) ------------------------------------------------
echo "building outbox.com / outbox_check.com / dkim verifier..."
cc $CCFLAGS $MBFLAGS -pthread -o outbox.com \
    src/outbox_main.c src/outbox_submit.c src/outbox_deliver.c src/outbox_auth.c \
    src/smtp_out.c src/mail.c src/auth_results.c src/dkim.c src/smtp_in_tls.c \
    src/data/cacert_pem.c $MB || fail "outbox.com build"
cc $CCFLAGS $MBFLAGS -pthread -o outbox_check.com \
    src/outbox_check.c src/outbox_auth.c src/outbox_submit.c src/outbox_deliver.c \
    src/smtp_out.c src/mail.c src/auth_results.c src/dkim.c src/smtp_in_tls.c \
    src/data/cacert_pem.c $MB || fail "outbox_check.com build"
cc $CCFLAGS $MBFLAGS -o "$T/dkim_verify" tests/outbox_dkim_verify.c src/dkim.c $MB \
    || fail "dkim verifier build"

# ---- unit checks --------------------------------------------------------
./outbox_check.com || fail "outbox_check.com unit tests"

# ---- fixtures -----------------------------------------------------------
openssl genrsa -out "$T/dkim.key" 2048 2>/dev/null || fail "genrsa"
openssl rsa -in "$T/dkim.key" -pubout -out "$T/dkim.pub" 2>/dev/null || fail "pubout"
openssl req -x509 -newkey rsa:2048 -keyout "$T/tls.key" -out "$T/tls.crt" \
    -days 1 -nodes -subj "/CN=localhost" 2>/dev/null || fail "tls cert"
printf 'null:secret\n' > "$T/passwd"; chmod 600 "$T/passwd"
mkdir -p "$T/mx"

# ---- fake DNS + fake MX -------------------------------------------------
python3 tests/outbox_dns.py 127.0.0.1 "$DNS_PORT" \
    deliver.test MX "10 mx.deliver.test" \
    mx.deliver.test A 127.0.0.1 >"$T/dns.log" 2>&1 &
DNS_PID=$!
python3 tests/outbox_fakemx.py 127.0.0.1 "$FAKEMX_PORT" "$T/mx" \
    --cert "$T/tls.crt" --key "$T/tls.key" >"$T/fakemx.log" 2>&1 &
FAKEMX_PID=$!

# ---- outbox daemon ------------------------------------------------------
./outbox.com \
    --implicit-addr 127.0.0.1 --implicit-port "$IMPLICIT_PORT" \
    --starttls-addr 127.0.0.1 --starttls-port "$STARTTLS_PORT" \
    --cert "$T/tls.crt" --key "$T/tls.key" \
    --passwd "$T/passwd" \
    --dkim "jaye.ch=$T/dkim.key" \
    --dns-server "127.0.0.1:$DNS_PORT" \
    --deliver-port "$FAKEMX_PORT" \
    --hostname outbox.test --spool "$T/spool" \
    >"$T/outbox.log" 2>&1 &
OUTBOX_PID=$!

# wait for both listeners
for port in "$STARTTLS_PORT" "$IMPLICIT_PORT"; do
    ok=0
    for _ in $(seq 1 100); do
        if (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null; then ok=1; exec 3>&- 3<&-; break; fi
        sleep 0.1
    done
    [ "$ok" = 1 ] || fail "outbox did not listen on :$port"
done
sleep 0.3   # let DNS/MX settle

CLIENT="python3 tests/outbox_client.py 127.0.0.1"

# ---- negative: AUTH over plaintext :587 -> 530 --------------------------
out=$($CLIENT "$STARTTLS_PORT" plaintext-auth null secret)
echo "$out" | grep -q '^530 ' || fail "plaintext AUTH should be 530, got: $out"
pass "AUTH over plaintext :587 rejected 530"

# ---- positive: STARTTLS + AUTH PLAIN -> 235 -----------------------------
out=$($CLIENT "$STARTTLS_PORT" starttls-auth null secret)
echo "$out" | grep -q '^235 ' || fail "STARTTLS AUTH PLAIN should be 235, got: $out"
pass "STARTTLS + AUTH PLAIN -> 235"

# ---- positive: AUTH LOGIN -> 235 ----------------------------------------
out=$($CLIENT "$STARTTLS_PORT" auth-login null secret)
echo "$out" | grep -q '^235 ' || fail "AUTH LOGIN should be 235, got: $out"
pass "AUTH LOGIN -> 235"

# ---- positive: implicit-TLS AUTH -> 235 ---------------------------------
out=$($CLIENT "$IMPLICIT_PORT" implicit-auth null secret)
echo "$out" | grep -q '^235 ' || fail "implicit-TLS AUTH should be 235, got: $out"
pass "implicit-TLS AUTH PLAIN -> 235"

# ---- negative: unauthenticated MAIL -> 530 ------------------------------
out=$($CLIENT "$IMPLICIT_PORT" unauthed-rcpt me@jaye.ch any@deliver.test)
echo "$out" | grep -q '^530 ' || fail "unauthenticated MAIL should be 530, got: $out"
pass "unauthenticated MAIL rejected 530"

# ---- negative: MAIL FROM domain not in allowed set -> 554 ---------------
out=$($CLIENT "$STARTTLS_PORT" bad-mailfrom null secret me@evil.com)
echo "$out" | grep -q '^554 ' || fail "bad MAIL FROM domain should be 554, got: $out"
pass "MAIL FROM domain not allowed rejected 554"

# ---- positive: submit + delivery + DKIM ---------------------------------
out=$($CLIENT "$STARTTLS_PORT" submit null secret me@jaye.ch any@deliver.test)
echo "$out" | grep -q '^250 ' || fail "submit should be 250, got: $out"
pass "MAIL/RCPT/DATA -> 250, delivery attempted"

sleep 0.5   # let the fake MX finish recording
[ -f "$T/mx/msg-1.eml" ] || fail "no delivered message recorded"
pass "fake MX recorded the delivered message"

grep -qi '^DKIM-Signature:.*d=jaye.ch.*s=visage' "$T/mx/msg-1.eml" \
    || fail "delivered message missing DKIM-Signature d=jaye.ch s=visage"
pass "DKIM-Signature present with d=jaye.ch s=visage"

verdict=$("$T/dkim_verify" "$T/mx/msg-1.eml" "$T/dkim.pub")
echo "$verdict" | grep -q '^VERIFIED' || fail "DKIM verify failed: $verdict"
pass "DKIM-Signature verifies against the generated public key"

# opportunistic STARTTLS should have been used by the delivery client
grep -q 'STARTTLS' "$T/mx/dialogue-1.txt" || fail "delivery did not offer STARTTLS"
pass "outbox delivery used opportunistic STARTTLS"

# ---- negative: From-domain mismatch -> 554, no delivery ------------------
before=$(ls "$T/mx"/msg-*.eml 2>/dev/null | wc -l)
out=$($CLIENT "$STARTTLS_PORT" from-mismatch null secret me@jaye.ch any@deliver.test)
echo "$out" | grep -q '^554 ' || fail "From-mismatch should be 554, got: $out"
pass "From-domain mismatch rejected 554"
after=$(ls "$T/mx"/msg-*.eml 2>/dev/null | wc -l)
[ "$before" = "$after" ] || fail "From-mismatch message was delivered"
pass "From-mismatch message was NOT delivered"

# ---- positive: large (>1.5MB) message over STARTTLS -> 250 ---------------
# Regression for the TLS DATA stall: mbedTLS buffers decrypted record bytes
# that poll() cannot see, so a large body whose ".\r\n" terminator lands past
# the first recv chunk used to strand the tail and never send the 250.
# 1600000 bytes is >1.5MB and lands the terminator deep in the final 16 KiB
# TLS record, so it deterministically stalls on the unfixed daemon.
out=$($CLIENT "$STARTTLS_PORT" submit-large null secret me@jaye.ch \
      any@deliver.test 1600000)
echo "$out" | grep -q '^250 ' || fail "large submit should be 250, got: $out"
pass "large (>1.5MB) STARTTLS DATA -> 250"

echo
echo "ALL OUTBOX INTEGRATION CHECKS PASSED"
