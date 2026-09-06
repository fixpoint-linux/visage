#!/usr/bin/env bash
# outbox_internal.sh — prove configurable internal-domain delivery routing.
#
# With --internal-relay-* configured, a recipient in the served domains (the
# internal set) must be delivered to the configured internal relay (the visage
# MX — an implicit-TLS stub here) — NOT resolved via the public MX.  A
# recipient in an external domain must keep direct-MX delivery.  With no
# internal relay configured, behavior must be exactly as before (served-domain
# recipients resolve their public MX).
#
# Phase 1 (configured): the fake DNS deliberately has NO MX/A for jaye.ch, so
#   the internal leg can only succeed by routing to the relay (any MX lookup
#   would come back empty and fail).  The external leg (deliver.test) resolves
#   its MX to the fake MX and is delivered there.
# Phase 2 (unconfigured): same submission to reply+token@jaye.ch resolves the
#   served domain's MX (now present in DNS) and is delivered to the fake MX.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CCFLAGS="-std=c11 -O2 -g -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -I vendor/dhall-c/src -I vendor/datalog-dafsa/src -I vendor/datalog-dafsa/vendor"
MBFLAGS='-I vendor/mbedtls/include -I src -DMBEDTLS_CONFIG_FILE="mbedtls_visage_config.h"'
MB="vendor/mbedtls/build/*.o"

T="$(mktemp -d /tmp/outbox_internal.XXXXXX)"
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
./outbox_check.com || fail "outbox_check.com unit tests"

# ---- shared fixtures ---------------------------------------------------
openssl genrsa -out "$T/dkim.key" 2048 2>/dev/null || fail "genrsa"
openssl rsa -in "$T/dkim.key" -pubout -out "$T/dkim.pub" 2>/dev/null || fail "pubout"
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

stop_outbox() {  # stop_outbox NAME  (SIGTERM -> drain + clean join)
    kill "$(cat "$T/$1/outbox.pid")" 2>/dev/null
    for _ in $(seq 1 50); do
        kill -0 "$(cat "$T/$1/outbox.pid")" 2>/dev/null || return 0
        sleep 0.1
    done
}

# ========================================================================
# Phase 1: internal relay CONFIGURED
# ========================================================================
DNS_CFG=15350
RELAY_PORT=12575        # internal relay (implicit TLS stub)
FAKEMX_PORT=12565       # public fake MX for the external leg
IMPLICIT_1=10505
STARTTLS_1=10627

mkdir -p "$T/relay" "$T/mx" "$T/relay/spool"
# DNS: external domain only — jaye.ch deliberately has NO MX/A, so the internal
# leg succeeds only if it skips MX resolution and goes straight to the relay.
python3 tests/outbox_dns.py 127.0.0.1 "$DNS_CFG" \
    deliver.test MX "10 mx.deliver.test" \
    mx.deliver.test A 127.0.0.1 >"$T/dns-cfg.log" 2>&1 &
track $!
# internal relay stub: implicit TLS on connect, records msg-N.eml.
python3 tests/outbox_fakemx.py 127.0.0.1 "$RELAY_PORT" "$T/relay" \
    --cert "$T/tls.crt" --key "$T/tls.key" --implicit >"$T/relay.log" 2>&1 &
track $!
# public fake MX for the external leg (advertises STARTTLS).
python3 tests/outbox_fakemx.py 127.0.0.1 "$FAKEMX_PORT" "$T/mx" \
    --cert "$T/tls.crt" --key "$T/tls.key" >"$T/mx.log" 2>&1 &
track $!

start_outbox relay "$IMPLICIT_1" "$STARTTLS_1" "$FAKEMX_PORT" "$DNS_CFG" \
    --internal-relay-host 127.0.0.1 \
    --internal-relay-port "$RELAY_PORT" \
    --internal-relay-tls implicit
wait_listeners "$STARTTLS_1" "$IMPLICIT_1"
sleep 0.3

# ---- served-domain recipient -> internal relay (NOT MX) ----------------
out=$(timeout 20 $CLIENT "$STARTTLS_1" submit null secret me@jaye.ch reply+token123@jaye.ch)
echo "$out" | grep -q '^250 ' || fail "internal: reply+token@jaye.ch submission should be 250, got: $out"
pass "internal: served-domain submission ack'd 250"

wait_file "$T/relay/msg-1.eml" 50 || fail "internal: served-domain message never reached the internal relay"
pass "internal: served-domain message delivered to the internal relay (implicit TLS)"

[ "$(ls "$T"/mx/msg-*.eml 2>/dev/null | wc -l)" = "0" ] \
    || fail "internal: served-domain message leaked to the public MX"
pass "internal: served-domain message did NOT reach the public MX"

grep -qi '^DKIM-Signature:.*d=jaye.ch.*s=visage' "$T/relay/msg-1.eml" \
    || fail "internal: relayed message missing DKIM-Signature d=jaye.ch s=visage"
verdict=$("$T/dkim_verify" "$T/relay/msg-1.eml" "$T/dkim.pub")
echo "$verdict" | grep -q '^VERIFIED' || fail "internal: DKIM verify failed: $verdict"
pass "internal: DKIM-sign-then-deliver ordering preserved (signature verifies)"

grep -q '<implicit TLS established>' "$T/relay/dialogue-1.txt" \
    || fail "internal: relay did not establish implicit TLS"
pass "internal: relay leg used implicit TLS (no STARTTLS command)"

# ---- external-domain recipient -> public MX ----------------------------
out=$(timeout 20 $CLIENT "$STARTTLS_1" submit null secret me@jaye.ch any@deliver.test)
echo "$out" | grep -q '^250 ' || fail "internal: any@deliver.test submission should be 250, got: $out"
pass "internal: external-domain submission ack'd 250"

wait_file "$T/mx/msg-1.eml" 50 || fail "internal: external-domain message never reached the public MX"
pass "internal: external-domain message delivered to the public MX"

[ "$(ls "$T"/relay/msg-*.eml 2>/dev/null | wc -l)" = "1" ] \
    || fail "internal: external-domain message leaked to the internal relay"
pass "internal: external-domain message did NOT reach the internal relay"

grep -q 'STARTTLS' "$T/mx/dialogue-1.txt" || fail "internal: external delivery did not offer STARTTLS"
pass "internal: external delivery still uses opportunistic STARTTLS"

stop_outbox relay

# ========================================================================
# Phase 2: NO internal relay configured (unchanged default)
# ========================================================================
DNS_DEF=15360
FAKEMX2_PORT=12585
IMPLICIT_2=10515
STARTTLS_2=10637

mkdir -p "$T/mx2" "$T/mx2/spool" "$T/plain" "$T/plain/spool"
# DNS now DOES answer jaye.ch's MX, so direct-MX delivery resolves it.
python3 tests/outbox_dns.py 127.0.0.1 "$DNS_DEF" \
    jaye.ch MX "10 mx.jaye.ch" \
    mx.jaye.ch A 127.0.0.1 \
    deliver.test MX "10 mx.deliver.test" \
    mx.deliver.test A 127.0.0.1 >"$T/dns-def.log" 2>&1 &
track $!
python3 tests/outbox_fakemx.py 127.0.0.1 "$FAKEMX2_PORT" "$T/mx2" \
    --cert "$T/tls.crt" --key "$T/tls.key" >"$T/mx2.log" 2>&1 &
track $!

start_outbox plain "$IMPLICIT_2" "$STARTTLS_2" "$FAKEMX2_PORT" "$DNS_DEF"
wait_listeners "$STARTTLS_2" "$IMPLICIT_2"
sleep 0.3

out=$(timeout 20 $CLIENT "$STARTTLS_2" submit null secret me@jaye.ch reply+token456@jaye.ch)
echo "$out" | grep -q '^250 ' || fail "default: reply+token@jaye.ch submission should be 250, got: $out"
pass "default: served-domain submission ack'd 250"

wait_file "$T/mx2/msg-1.eml" 50 || fail "default: served-domain message never reached the (fake) MX"
pass "default: with no internal relay, served-domain message resolves its public MX"

echo
echo "ALL OUTBOX INTERNAL-ROUTING CHECKS PASSED"
