#!/usr/bin/env bash
# run.sh — host e2e integration driver for visage (S8).
#
# Mirrors config.example.dhall and drives the full SimpleLogin-style scenario
# against a live `visage daemon`:
#
#   (a) build all binaries
#   (b) config-check config.example.dhall            -> exit 0
#   (c) start relay_fake (recording SMTP server) on  $RELAY_PORT
#   (d) start visage daemon -c <generated config>     (fresh storage)
#   (e) smtptest sender@foo.org -> jane@example.com   -> forward path ok
#   (f) assert relay_fake recorded the forwarded message:
#         Received header present, From/Reply-To are the reverse alias, and
#         the body matches msg1.eml
#   (g) reply round-trip: extract the reverse-alias, send a reply to it, and
#         assert relay_fake recorded a second message whose From=alias and
#         whose recorded envelope RCPT TO = original sender
#   (h) GET /health on 8080 -> 200 {"ok":true}
#   (i) cleanup
#
# REQUIRES live sockets (the rattan sandbox blocks socket()); run on the HOST
# via `make e2e`.
#
# Ports and paths are parametrized via env: SMTP_PORT (default 2525),
# RELAY_PORT (default 2526), HTTP_PORT (default 8080).
set -euo pipefail

SMTP_PORT="${SMTP_PORT:-2525}"
RELAY_PORT="${RELAY_PORT:-2526}"
HTTP_PORT="${HTTP_PORT:-8080}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d /tmp/visage-e2e.XXXXXX)"
DBDIR="$WORK/db"
SPOOLDIR="$WORK/spool"
RELAY_DIR="$WORK/relay"
CONF="$WORK/config.dhall"
mkdir -p "$WORK" "$RELAY_DIR" "$DBDIR" "$SPOOLDIR"
cp "$ROOT/tests/msg1.eml" "$WORK/msg1.eml"

DAEMON_PID=""
RELAY_PID=""

PASSES=0
FAILS=0

pass() { PASSES=$((PASSES + 1)); echo "PASS  $*"; }
fail() { FAILS=$((FAILS + 1)); echo "FAIL  $*"; }

cleanup() {
    set +e
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
    [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
    wait "$RELAY_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# Build a config.dhall from the example with parametrized ports + fresh storage.
# The example's storage.path/spool are relative (./var/...); we make them
# absolute so the daemon always runs against the throwaway tmp dir.
build_config() {
    sed \
        -e "s|port = 2525|port = $SMTP_PORT|" \
        -e "s|port = 2526|port = $RELAY_PORT|" \
        -e "s|port = 8080|port = $HTTP_PORT|" \
        -e "s|path = \"./var/db\"|path = \"$DBDIR\"|" \
        -e "s|spool = \"./var/spool\"|spool = \"$SPOOLDIR\"|" \
        "$ROOT/config.example.dhall" > "$CONF"
}

# Wait up to ~15s for a file to exist and be non-empty.
wait_for_file() {
    local f="$1" n=0
    while [ $n -lt 150 ]; do
        [ -s "$f" ] && return 0
        n=$((n + 1)); sleep 0.1
    done
    return 1
}

# Do an HTTP GET via bash's /dev/tcp and print the raw response (no newlines).
# Returns nonzero if the connection could not be made.
http_get() {
    local port="$1" path="$2"
    local out="$WORK/.http-$port"
    if timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port && { printf 'GET $path HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n' >&3; cat <&3; }" >"$out" 2>/dev/null; then
        tr -d '\r\n' <"$out"
        return 0
    fi
    return 1
}

# True if $1 contains $2.
contains() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }

# True if an HTTP response has status 200 and the given body substring.
http_ok() {
    local resp="$1" body="$2"
    contains "$resp" "200 OK" && contains "$resp" "$body"
}

# Extract the message body (lines after the first blank header/body separator),
# with leading and trailing blank lines trimmed (the SMTP DATA terminator
# CRLF.CRLF can add a trailing blank line; that is a wire artifact, not content).
body_of() {
    awk 'BEGIN{s=0} /^\r?$/{if(!s){s=1;next}} s==1{print}' "$1" \
        | sed -e '/^[[:space:]]*$/d' | sed -e :a -e '/^\n*$/{$d;N;ba}'
}

# ---------------------------------------------------------------------------
echo "== visage e2e (ports smtp=$SMTP_PORT relay=$RELAY_PORT http=$HTTP_PORT)"
echo "== workdir: $WORK"

# (a) build all -------------------------------------------------------------
(cd "$ROOT" && make visage.com config_check.com tests/smtptest.com tests/relay_fake.com >/dev/null)
echo "build ok"

# (b) config-check ----------------------------------------------------------
build_config
if "$ROOT/visage.com" config-check -c "$CONF" >/dev/null 2>&1; then
    pass "config-check on generated config"
else
    fail "config-check on generated config"
fi
if "$ROOT/config_check.com" "$CONF" >/dev/null 2>&1; then
    pass "config_check.com parses generated config"
else
    fail "config_check.com parses generated config"
fi

# (c) relay_fake ------------------------------------------------------------
"$ROOT/tests/relay_fake.com" "$RELAY_PORT" "$RELAY_DIR" >"$WORK/relay.log" 2>&1 &
RELAY_PID=$!
sleep 0.3
if kill -0 "$RELAY_PID" 2>/dev/null; then
    pass "relay_fake listening on $RELAY_PORT"
else
    fail "relay_fake failed to start (see $WORK/relay.log)"
fi

# (d) daemon ----------------------------------------------------------------
"$ROOT/visage.com" daemon -c "$CONF" >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
echo "waiting for daemon health on :$HTTP_PORT"
HEALTHY=0
for i in $(seq 1 100); do
    RESP="$(http_get "$HTTP_PORT" /health || true)"
    if http_ok "$RESP" '"ok":true'; then
        HEALTHY=1; break
    fi
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo "daemon died:"; cat "$WORK/daemon.log"; break
    fi
    sleep 0.1
done
if [ "$HEALTHY" = 1 ]; then
    pass "daemon up: GET /health -> 200 {\"ok\":true}"
else
    fail "daemon health check timed out"
fi

# (e) forward path ----------------------------------------------------------
if "$ROOT/tests/smtptest.com" 127.0.0.1 "$SMTP_PORT" \
        sender@foo.org jane@example.com "$WORK/msg1.eml" >"$WORK/fwd.log" 2>&1; then
    pass "smtptest forward (sender@foo.org -> jane@example.com)"
else
    fail "smtptest forward failed (see $WORK/fwd.log)"
fi

# (f) assert first recorded message -----------------------------------------
FW="$RELAY_DIR/msg-1.eml"
if wait_for_file "$FW"; then
    pass "relay_fake recorded a forwarded message ($FW)"
    if grep -q '^Received:' "$FW"; then
        pass "forwarded message has a Received header"
    else
        fail "forwarded message missing Received header"
    fi
    if grep -q 'reply+[0-9a-f]\{32\}@example.com' "$FW"; then
        pass "forwarded From/Reply-To use a reverse alias (reply+<token>@example.com)"
    else
        fail "forwarded From/Reply-To are NOT a reverse alias"
    fi
    if diff -u <(body_of "$WORK/msg1.eml") <(body_of "$FW") >"$WORK/body.diff" 2>&1; then
        pass "forwarded body matches msg1.eml"
    else
        fail "forwarded body differs from msg1.eml (see $WORK/body.diff)"
    fi
    # envelope assertion for the forward leg
    if grep -q 'MAIL FROM:<jane@example.com>' "$RELAY_DIR/dialogue-1.txt" \
       && grep -q 'RCPT TO:<jane@realmail.example>' "$RELAY_DIR/dialogue-1.txt"; then
        pass "forward envelope MAIL FROM=alias, RCPT TO=destination"
    else
        fail "forward envelope mismatch (see $RELAY_DIR/dialogue-1.txt)"
    fi
else
    fail "relay_fake did not record a forwarded message"
fi

# (g) reply round-trip ------------------------------------------------------
REVERSE="$(grep -o 'reply+[0-9a-f]\{32\}@example.com' "$FW" | head -n1 || true)"
if [ -n "$REVERSE" ]; then
    pass "extracted reverse-alias $REVERSE"
    if "$ROOT/tests/smtptest.com" 127.0.0.1 "$SMTP_PORT" \
            realbox@realmail.example "$REVERSE" "$WORK/msg1.eml" >"$WORK/rep.log" 2>&1; then
        pass "smtptest reply (realbox@realmail.example -> $REVERSE)"
    else
        fail "smtptest reply failed (see $WORK/rep.log)"
    fi
    RW="$RELAY_DIR/msg-2.eml"
    if wait_for_file "$RW"; then
        pass "relay_fake recorded the reply-round-trip message ($RW)"
        if grep -q '^From:.*jane@example.com' "$RW"; then
            pass "reply message From = alias (jane@example.com)"
        else
            fail "reply message From is not the alias"
        fi
        if grep -q '^To:.*sender@foo.org' "$RW"; then
            pass "reply message To = original sender (sender@foo.org)"
        else
            fail "reply message To is not the original sender"
        fi
        if grep -q 'MAIL FROM:<jane@example.com>' "$RELAY_DIR/dialogue-2.txt" \
           && grep -q 'RCPT TO:<sender@foo.org>' "$RELAY_DIR/dialogue-2.txt"; then
            pass "reply envelope MAIL FROM=alias, RCPT TO=sender"
        else
            fail "reply envelope mismatch (see $RELAY_DIR/dialogue-2.txt)"
        fi
    else
        fail "relay_fake did not record the reply-round-trip message"
    fi
else
    fail "could not extract reverse-alias from $FW"
fi

# (h) explicit health check --------------------------------------------------
RESP="$(http_get "$HTTP_PORT" /health || true)"
if http_ok "$RESP" '"ok":true'; then
    pass "GET /health -> 200 {\"ok\":true}"
else
    fail "GET /health returned unexpected response: $RESP"
fi

# ---------------------------------------------------------------------------
echo
echo "== visage e2e: $PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
