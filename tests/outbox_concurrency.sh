#!/usr/bin/env bash
# outbox_concurrency.sh — prove the outbox poll loop never blocks on delivery.
#
# Two loopback scenarios, both against the real outbox.com binary:
#
#   A. Hung-MX: a fake MX that accepts the delivery connection and then never
#      responds.  outbox's delivery worker gets stuck waiting for the 220
#      greeting, yet a second submission must still be accepted + ack'd 250
#      while the first delivery is in flight.
#
#   B. Reverse-alias reply round-trip: the exact production deadlock.  outbox
#      delivers reply+<token>@jaye.ch to a fake ingress MX (outbox_relaymx.py),
#      which — playing visage's reverse-route — connects BACK to outbox over
#      SMTP (the reply_relay hop) before acking the first leg.  With delivery
#      off the poll thread this completes instead of deadlocking.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CCFLAGS="-std=c11 -O2 -g -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -I vendor/dhall-c/src -I vendor/datalog-dafsa/src -I vendor/datalog-dafsa/vendor"
MBFLAGS='-I vendor/mbedtls/include -I src -DMBEDTLS_CONFIG_FILE="mbedtls_visage_config.h"'
MB="vendor/mbedtls/build/*.o"

T="$(mktemp -d /tmp/outbox_conc.XXXXXX)"
PIDS=""
trap 'for p in $PIDS; do kill "$p" 2>/dev/null; done; sleep 0.5; for p in $PIDS; do kill -9 "$p" 2>/dev/null; done; rm -rf "$T"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok   $*"; }

track() { PIDS="$PIDS $1"; }

wait_file() {  # wait_file PATH TIMEOUT_SEC
    local f="$1" n="$2" i
    for i in $(seq 1 "$n"); do
        [ -e "$f" ] && return 0
        sleep 0.2
    done
    return 1
}

# ---- build (idempotent) ------------------------------------------------
echo "building outbox.com ..."
cc $CCFLAGS $MBFLAGS -pthread -o outbox.com \
    src/outbox_main.c src/outbox_submit.c src/outbox_deliver.c src/outbox_auth.c \
    src/smtp_out.c src/mail.c src/auth_results.c src/dkim.c src/smtp_in_tls.c \
    src/data/cacert_pem.c $MB || fail "outbox.com build"

# ---- shared fixtures ---------------------------------------------------
openssl genrsa -out "$T/dkim.key" 2048 2>/dev/null || fail "genrsa"
openssl req -x509 -newkey rsa:2048 -keyout "$T/tls.key" -out "$T/tls.crt" \
    -days 1 -nodes -subj "/CN=localhost" 2>/dev/null || fail "tls cert"
printf 'null:secret\n' > "$T/passwd"; chmod 600 "$T/passwd"

CLIENT="python3 tests/outbox_client.py 127.0.0.1"

start_outbox() {  # start_outbox NAME IMPLICIT STARTTLS DELIVER DNS [extra...]
    local name="$1" implicit="$2" starttls="$3" deliver="$4" dns="$5"
    shift 5
    ./outbox.com \
        --implicit-addr 127.0.0.1 --implicit-port "$implicit" \
        --starttls-addr 127.0.0.1 --starttls-port "$starttls" \
        --cert "$T/tls.crt" --key "$T/tls.key" \
        --passwd "$T/passwd" \
        --dkim "jaye.ch=$T/dkim.key" \
        --dns-server "127.0.0.1:$dns" \
        --deliver-port "$deliver" \
        --hostname outbox.test --spool "$T/$name/spool" \
        "$@" >"$T/$name/outbox.log" 2>&1 &
    track $!
    echo $! > "$T/$name/outbox.pid"
}

wait_listeners() {  # wait_listeners STARTTLS IMPLICIT
    local port
    for port in "$1" "$2"; do
        local ok=0
        for _ in $(seq 1 100); do
            if (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null; then ok=1; exec 3>&- 3<&-; break; fi
            sleep 0.1
        done
        [ "$ok" = 1 ] || fail "outbox did not listen on :$port"
    done
}

# ========================================================================
# A. Hung MX must not block new submissions
# ========================================================================
DNS_A=15310
HANG_PORT=12535
IMPLICIT_A=10475
STARTTLS_A=10597

mkdir -p "$T/hang" "$T/hang/spool"
python3 tests/outbox_dns.py 127.0.0.1 "$DNS_A" \
    hang.test MX "10 mx.hang.test" \
    mx.hang.test A 127.0.0.1 >"$T/hang/dns.log" 2>&1 &
track $!
python3 tests/outbox_hangmx.py 127.0.0.1 "$HANG_PORT" "$T/hang" \
    >"$T/hang/hangmx.log" 2>&1 &
track $!
start_outbox hang "$IMPLICIT_A" "$STARTTLS_A" "$HANG_PORT" "$DNS_A" \
    --cmd-timeout 5 --data-timeout 5 --max-attempts 1
wait_listeners "$STARTTLS_A" "$IMPLICIT_A"

# First submission: ack'd immediately; its delivery then hangs on the MX.
out=$(timeout 15 $CLIENT "$STARTTLS_A" submit null secret me@jaye.ch any@hang.test)
echo "$out" | grep -q '^250 ' || fail "hung-MX: first submission should be 250, got: $out"
pass "hung-MX: first submission ack'd 250 promptly"

wait_file "$T/hang/accepted-1" 25 || fail "hung-MX: delivery never reached the MX"
pass "hung-MX: delivery worker is (blocked) inside the first delivery"

# Second submission while the first delivery is still stuck: must be serviced.
out=$(timeout 15 $CLIENT "$STARTTLS_A" submit null secret me@jaye.ch any@hang.test)
echo "$out" | grep -q '^250 ' || fail "hung-MX: second submission should be 250, got: $out"
pass "hung-MX: second submission ack'd 250 while first delivery is in flight"

# The hung MX should have accepted exactly one connection (msg2 is still
# queued behind the stuck msg1 delivery — the listener, not the worker,
# serviced it).
nacc=$(ls "$T"/hang/accepted-* 2>/dev/null | wc -l)
[ "$nacc" = "1" ] || fail "hung-MX: expected 1 accepted delivery conn, got $nacc"
pass "hung-MX: listener serviced submission #2 without touching the stuck worker"

kill "$(cat "$T/hang/outbox.pid")" 2>/dev/null   # clean stop (drains fast once MX is gone)

# ========================================================================
# B. Reverse-alias reply round-trip (the production deadlock)
# ========================================================================
DNS_B=15320
RELAY_PORT=12545
IMPLICIT_B=10485
STARTTLS_B=10607

mkdir -p "$T/relay" "$T/relay/spool"
python3 tests/outbox_dns.py 127.0.0.1 "$DNS_B" \
    jaye.ch MX "10 mx.jaye.ch" \
    mx.jaye.ch A 127.0.0.1 \
    sender.test MX "10 mx.sender.test" \
    mx.sender.test A 127.0.0.1 >"$T/relay/dns.log" 2>&1 &
track $!
python3 tests/outbox_relaymx.py 127.0.0.1 "$RELAY_PORT" "$T/relay" \
    127.0.0.1 "$STARTTLS_B" null secret noreply@jaye.ch orig@sender.test \
    >"$T/relay/relaymx.log" 2>&1 &
track $!
start_outbox relay "$IMPLICIT_B" "$STARTTLS_B" "$RELAY_PORT" "$DNS_B"
wait_listeners "$STARTTLS_B" "$IMPLICIT_B"

out=$(timeout 20 $CLIENT "$STARTTLS_B" submit null secret me@jaye.ch reply+token123@jaye.ch)
echo "$out" | grep -q '^250 ' || fail "relay: reply submission should be 250, got: $out"
pass "relay: reply+token submission ack'd 250"

wait_file "$T/relay/reply-relay-done" 50 \
    || fail "relay: reverse-route (reply_relay callback) did not complete"
pass "relay: reverse-route completed (visage-style reply_relay hop ack'd)"

wait_file "$T/relay/msg-1.eml" 50 \
    || fail "relay: reply_relay message was not delivered back"
pass "relay: reply_relay message delivered and recorded (round-trip complete)"

echo
echo "ALL OUTBOX CONCURRENCY CHECKS PASSED"
