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
# Run from the project root so the TLS relay's relative cert/key paths
# ("tests/visage-test-*.pem") resolve deterministically regardless of how the
# harness is invoked.
cd "$ROOT"
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

# --- TLS e2e scenarios (S-B3) -----------------------------------------------
# gen_config emits a full config.dhall with the given SMTP/relay/HTTP ports, the
# relay TLS mode and auth.enabled, and throwaway absolute storage dirs.
#   gen_config <outfile> <smtp_port> <relay_port> <relay_tls> <auth_enabled>
#              <http_port> <db> <spool> [<relay_host>] [<relay_tls_ca>]
#              [<dkim_domain>] [<dkim_selector>] [<dkim_key>]
# <relay_host> defaults to 127.0.0.1; <relay_tls_ca> defaults to "" (the embedded
# Mozilla bundle); <dkim_domain>/<dkim_selector>/<dkim_key> are optional — when
# <dkim_domain> is empty the dkim list is empty (signing disabled), otherwise a
# single { domain, selector, private_key } signing config is emitted.
gen_config() {
    local out="$1" smtp="$2" rport="$3" rtls="$4" authen="$5" hport="$6" db="$7" spool="$8"
    local rhost="${9:-127.0.0.1}" rca="${10:-}"
    local ddomain="${11:-}" dsel="${12:-sel1}" dkey="${13:-}"
    local dkim_list
    if [ -n "$ddomain" ]; then
        dkim_list="dkim = [ { domain = \"$ddomain\", selector = \"$dsel\", private_key = \"$dkey\" } ]"
    else
        dkim_list="dkim = [] : List { domain : Text, selector : Text, private_key : Text }"
    fi
    cat > "$out" <<DHALL
let Auth = { enabled : Bool, username : Text, password : Text }
in  let Config =
      { hostname : Text
      , domains : List Text
      , listen : { address : Text, port : Natural }
      , limits : { message : Natural, line : Natural, rcpts : Natural
                 , cmd_timeout : Natural, data_timeout : Natural }
      , relay : { host : Text, port : Natural, auth : Auth, retries : Natural
                , tls : Text, tls_ca : Text, max_attempts : Natural }
      , storage : { path : Text, spool : Text }
      , reply : { prefix : Text, separator : Text }
      , catch_all : Text
      , aliases : List { alias : Text, destinations : List Text }
      , http : { address : Text, port : Natural }
      , admin : { token : Text }
      , dkim : List { domain : Text, selector : Text, private_key : Text }
      }
in  { hostname = "mx.example.com"
   , domains = [ "example.com" ]
   , listen = { address = "127.0.0.1", port = $smtp }
   , limits = { message = 26214400, line = 1000, rcpts = 100
              , cmd_timeout = 300, data_timeout = 600 }
   , relay = { host = "$rhost", port = $rport
             , auth = { enabled = $authen, username = "u", password = "p" }
             , retries = 3, tls = "$rtls", tls_ca = "$rca", max_attempts = 100 }
   , storage = { path = "$db", spool = "$spool" }
   , reply = { prefix = "reply", separator = "+" }
   , catch_all = ""
   , aliases = [ { alias = "jane@example.com", destinations = [ "jane@realmail.example" ] }
               , { alias = "shopping@example.com", destinations = [ "jane@realmail.example", "bob@realmail.example" ] }
               ]
   , http = { address = "127.0.0.1", port = $hport }
   , admin = { token = "change-me" }
   , $dkim_list
   } : Config
DHALL
}

# wait_health <http_port> <daemon_pid> <logfile>; returns 0 when GET /health
# returns 200 {"ok":true} within ~10s.
wait_health() {
    local port="$1" dpid="$2" logf="$3"
    local i RESP
    for i in $(seq 1 100); do
        RESP="$(http_get "$port" /health || true)"
        if http_ok "$RESP" '"ok":true'; then return 0; fi
        if ! kill -0 "$dpid" 2>/dev/null; then
            echo "daemon died (see $logf):"; cat "$logf"
            return 1
        fi
        sleep 0.1
    done
    return 1
}

# Scenario: relay.tls='starttls' + a TLS relay_fake.  The daemon must upgrade
# the connection with STARTTLS and forward the message over the encrypted
# channel.  Because relay_fake --tls only records traffic it can READ (mbedTLS
# reads fail on plaintext bytes if the client never upgrades), a non-empty,
# readable msg-<n>.eml + dialogue-<n>.txt is itself proof TLS was used.
tls_forward_scenario() {
    echo
    echo "== scenario: TLS forward (relay.tls=starttls, relay_fake --tls)"
    local d="$WORK/tls" db="$WORK/tls/db" spool="$WORK/tls/spool" relay="$WORK/tls/relay"
    local conf="$WORK/tls/config.dhall" rpid="" dpid=""
    local SMTP=2535 RELAY=2536 HTTP=8090
    mkdir -p "$d" "$relay" "$db" "$spool"
    gen_config "$conf" "$SMTP" "$RELAY" starttls False "$HTTP" "$db" "$spool"

    # Start the TLS relay.  Cert/key paths are relative to ROOT (we cd'd there).
    "$ROOT/tests/relay_fake.com" --tls "$RELAY" "$relay" >"$d/relay.log" 2>&1 &
    rpid=$!
    sleep 0.3
    if ! kill -0 "$rpid" 2>/dev/null; then
        fail "TLS: relay_fake --tls failed to start (see $d/relay.log)"
        return
    fi
    "$ROOT/visage.com" daemon -c "$conf" >"$d/daemon.log" 2>&1 &
    dpid=$!
    if wait_health "$HTTP" "$dpid" "$d/daemon.log"; then
        pass "TLS: daemon up (GET /health ok)"
    else
        fail "TLS: daemon failed to become healthy"
        [ -n "$rpid" ] && kill "$rpid" 2>/dev/null
        return
    fi

    if "$ROOT/tests/smtptest.com" 127.0.0.1 "$SMTP" sender@foo.org jane@example.com "$WORK/msg1.eml" >"$d/fwd.log" 2>&1; then
        pass "TLS: smtptest forward accepted"
    else
        fail "TLS: smtptest forward failed (see $d/fwd.log)"
    fi

    local FW="$relay/msg-1.eml" DL="$relay/dialogue-1.txt"
    if wait_for_file "$FW"; then
        pass "TLS: relay_fake --tls recorded the decrypted forwarded message"
        if grep -q '^Received:' "$FW"; then
            pass "TLS: forwarded message has a Received header"
        else
            fail "TLS: forwarded message missing Received header"
        fi
        if grep -q 'reply+[0-9a-f]\{32\}@example.com' "$FW"; then
            pass "TLS: forwarded From/Reply-To use a reverse alias"
        else
            fail "TLS: forwarded From/Reply-To are NOT a reverse alias"
        fi
        if diff -u <(body_of "$WORK/msg1.eml") <(body_of "$FW") >"$d/body.diff" 2>&1; then
            pass "TLS: forwarded body matches msg1.eml"
        else
            fail "TLS: forwarded body differs from msg1.eml (see $d/body.diff)"
        fi
        # The relay_fake only records decrypted traffic: a readable MAIL line +
        # the STARTTLS-upgrade reply prove the daemon actually used TLS.  (Had it
        # not upgraded, mbedTLS reads would fail on the plaintext MAIL and no
        # readable dialogue/body would exist.)
        if wait_for_file "$DL" && grep -q 'Ready to start TLS' "$DL" \
           && grep -q 'MAIL FROM:<jane@example.com>' "$DL"; then
            pass "TLS: dialogue shows STARTTLS upgrade + decrypted MAIL exchange"
        else
            fail "TLS: dialogue does not prove TLS was used (see $DL)"
        fi
    else
        fail "TLS: relay_fake --tls did not record a decrypted forwarded message"
    fi

    [ -n "$dpid" ] && kill "$dpid" 2>/dev/null
    [ -n "$rpid" ] && kill "$rpid" 2>/dev/null
    wait "$dpid" 2>/dev/null || true
    wait "$rpid" 2>/dev/null || true
}

# Scenario: D2 hard rule.  relay.tls='starttls' + relay.auth.enabled=true, but
# the relay is a PLAINTEXT relay_fake that advertises no STARTTLS.  The daemon
# must REFUSE the forward (never send AUTH PLAIN credentials in the clear): the
# recorded plaintext dialogue must contain no 'AUTH' and the message must NOT be
# forwarded (no msg file).
d2_negative_scenario() {
    echo
    echo "== scenario: D2 negative (tls=starttls + auth.enabled, plaintext relay)"
    local d="$WORK/d2" db="$WORK/d2/db" spool="$WORK/d2/spool" relay="$WORK/d2/relay"
    local conf="$WORK/d2/config.dhall" rpid="" dpid=""
    local SMTP=2537 RELAY=2538 HTTP=8091
    mkdir -p "$d" "$relay" "$db" "$spool"
    gen_config "$conf" "$SMTP" "$RELAY" starttls True "$HTTP" "$db" "$spool"

    # PLAINTEXT relay_fake: single-line EHLO reply, no STARTTLS advertised.
    "$ROOT/tests/relay_fake.com" "$RELAY" "$relay" >"$d/relay.log" 2>&1 &
    rpid=$!
    sleep 0.3
    if ! kill -0 "$rpid" 2>/dev/null; then
        fail "D2: plaintext relay_fake failed to start (see $d/relay.log)"
        return
    fi
    "$ROOT/visage.com" daemon -c "$conf" >"$d/daemon.log" 2>&1 &
    dpid=$!
    if wait_health "$HTTP" "$dpid" "$d/daemon.log"; then
        pass "D2: daemon up"
    else
        fail "D2: daemon failed to become healthy"
        [ -n "$rpid" ] && kill "$rpid" 2>/dev/null
        return
    fi

    # Send a message: the daemon accepts it (queued), then the outbound forward
    # attempt must be refused by the D2 rule before any AUTH/MAIL goes out.
    if "$ROOT/tests/smtptest.com" 127.0.0.1 "$SMTP" sender@foo.org jane@example.com "$WORK/msg1.eml" >"$d/fwd.log" 2>&1; then
        pass "D2: smtptest forward accepted (queued)"
    else
        fail "D2: smtptest forward failed (see $d/fwd.log)"
    fi

    local DL="$relay/dialogue-1.txt"
    if wait_for_file "$DL"; then
        pass "D2: daemon connected to the plaintext relay (forward attempted)"
        if grep -qi 'AUTH' "$DL"; then
            fail "D2: FAIL — AUTH sent over plaintext (see $DL)"
        else
            pass "D2: no AUTH command in the plaintext dialogue"
        fi
        if [ -s "$relay/msg-1.eml" ]; then
            fail "D2: FAIL — message was forwarded over plaintext despite no STARTTLS"
        else
            pass "D2: message was NOT forwarded to the plaintext relay"
        fi
    else
        fail "D2: daemon did not attempt to reach the relay"
    fi

    [ -n "$dpid" ] && kill "$dpid" 2>/dev/null
    [ -n "$rpid" ] && kill "$rpid" 2>/dev/null
    wait "$dpid" 2>/dev/null || true
    wait "$rpid" 2>/dev/null || true
}

# --- starttls-verify e2e scenarios (S-B4) ----------------------------------
# These prove the daemon's mandatory-TLS + CA/hostname verification path
# against the committed S-B4 test PKI (tests/verify-ca.pem + the CA-signed leaf
# tests/verify-relay.pem/.key with SAN DNS:localhost + IP:127.0.0.1).  The relay
# hostname is 'localhost' so the daemon must (1) build a verified TLS chain
# against the configured CA and (2) pass the SAN/CN hostname check for the name
# it actually dials.

# Scenario: relay.tls='starttls-verify' + relay.tls_ca=<test CA>, relay_fake
# serving the CA-signed leaf.  The daemon must complete a VERIFY_REQUIRED
# handshake (chain + hostname ok) and forward the message over the encrypted
# channel: a non-empty, readable msg-<n>.eml + a dialogue showing the STARTTLS
# upgrade and the decrypted MAIL exchange.
verify_forward_scenario() {
    echo
    echo "== scenario: starttls-verify forward (tls=starttls-verify, tls_ca=test CA, leaf relay)"
    local d="$WORK/verify" db="$WORK/verify/db" spool="$WORK/verify/spool" relay="$WORK/verify/relay"
    local conf="$WORK/verify/config.dhall" rpid="" dpid=""
    local SMTP=2546 RELAY=2547 HTTP=8094
    mkdir -p "$d" "$relay" "$db" "$spool"
    # Relay host is 'localhost' so the daemon verifies the SAN DNS:localhost.
    gen_config "$conf" "$SMTP" "$RELAY" starttls-verify False "$HTTP" "$db" "$spool" \
        localhost "$ROOT/tests/verify-ca.pem"

    # Serve the CA-signed leaf (verify-relay.pem/.key) instead of the default
    # S-B3 self-signed test cert, so the chain + hostname verify against the CA.
    "$ROOT/tests/relay_fake.com" --tls --cert "$ROOT/tests/verify-relay.pem" \
        --key "$ROOT/tests/verify-relay.key" "$RELAY" "$relay" >"$d/relay.log" 2>&1 &
    rpid=$!
    sleep 0.3
    if ! kill -0 "$rpid" 2>/dev/null; then
        fail "VERIFY: relay_fake --tls (CA leaf) failed to start (see $d/relay.log)"
        return
    fi
    "$ROOT/visage.com" daemon -c "$conf" >"$d/daemon.log" 2>&1 &
    dpid=$!
    if wait_health "$HTTP" "$dpid" "$d/daemon.log"; then
        pass "VERIFY: daemon up (GET /health ok)"
    else
        fail "VERIFY: daemon failed to become healthy"
        [ -n "$rpid" ] && kill "$rpid" 2>/dev/null
        return
    fi

    if "$ROOT/tests/smtptest.com" 127.0.0.1 "$SMTP" sender@foo.org jane@example.com "$WORK/msg1.eml" >"$d/fwd.log" 2>&1; then
        pass "VERIFY: smtptest forward accepted"
    else
        fail "VERIFY: smtptest forward failed (see $d/fwd.log)"
    fi

    local FW="$relay/msg-1.eml" DL="$relay/dialogue-1.txt"
    if wait_for_file "$FW"; then
        pass "VERIFY: relay_fake recorded the decrypted forwarded message (chain+hostname verified)"
        if grep -q '^Received:' "$FW"; then
            pass "VERIFY: forwarded message has a Received header"
        else
            fail "VERIFY: forwarded message missing Received header"
        fi
        if grep -q 'reply+[0-9a-f]\{32\}@example.com' "$FW"; then
            pass "VERIFY: forwarded From/Reply-To use a reverse alias"
        else
            fail "VERIFY: forwarded From/Reply-To are NOT a reverse alias"
        fi
        if diff -u <(body_of "$WORK/msg1.eml") <(body_of "$FW") >"$d/body.diff" 2>&1; then
            pass "VERIFY: forwarded body matches msg1.eml"
        else
            fail "VERIFY: forwarded body differs from msg1.eml (see $d/body.diff)"
        fi
        # A readable MAIL line after the STARTTLS-upgrade reply proves the
        # daemon actually upgraded AND completed the verified handshake.
        if wait_for_file "$DL" && grep -q 'Ready to start TLS' "$DL" \
           && grep -q 'MAIL FROM:<jane@example.com>' "$DL"; then
            pass "VERIFY: dialogue shows STARTTLS upgrade + decrypted MAIL exchange"
        else
            fail "VERIFY: dialogue does not prove verified TLS was used (see $DL)"
        fi
    else
        fail "VERIFY: relay_fake did not record a decrypted forwarded message"
    fi

    [ -n "$dpid" ] && kill "$dpid" 2>/dev/null
    [ -n "$rpid" ] && kill "$rpid" 2>/dev/null
    wait "$dpid" 2>/dev/null || true
    wait "$rpid" 2>/dev/null || true
}

# Scenario: relay.tls='starttls-verify' + relay.tls_ca=<UNRELATED CA> (wrongca),
# relay_fake still serving the CA-signed leaf.  The daemon connects, upgrades to
# TLS, but the leaf does not chain to the configured CA -> verification fails
# (NOT_TRUSTED) -> the daemon PERMFAILs with NO plaintext fallback and NO retry:
# the message must NOT be forwarded and the dialogue must have no MAIL command.
# relay_fake creates an empty msg-<n>.eml at connect, so use the -s (non-empty)
# check for "not forwarded", exactly like the D2-negative precedent.
verify_negative_scenario() {
    echo
    echo "== scenario: starttls-verify negative (tls=starttls-verify, tls_ca=unrelated CA)"
    local d="$WORK/verifyneg" db="$WORK/verifyneg/db" spool="$WORK/verifyneg/spool" relay="$WORK/verifyneg/relay"
    local conf="$WORK/verifyneg/config.dhall" rpid="" dpid=""
    local SMTP=2549 RELAY=2550 HTTP=8095
    mkdir -p "$d" "$relay" "$db" "$spool"
    gen_config "$conf" "$SMTP" "$RELAY" starttls-verify False "$HTTP" "$db" "$spool" \
        localhost "$ROOT/tests/verify-wrongca.pem"

    "$ROOT/tests/relay_fake.com" --tls --cert "$ROOT/tests/verify-relay.pem" \
        --key "$ROOT/tests/verify-relay.key" "$RELAY" "$relay" >"$d/relay.log" 2>&1 &
    rpid=$!
    sleep 0.3
    if ! kill -0 "$rpid" 2>/dev/null; then
        fail "VERIFY-NEG: relay_fake --tls failed to start (see $d/relay.log)"
        return
    fi
    "$ROOT/visage.com" daemon -c "$conf" >"$d/daemon.log" 2>&1 &
    dpid=$!
    if wait_health "$HTTP" "$dpid" "$d/daemon.log"; then
        pass "VERIFY-NEG: daemon up"
    else
        fail "VERIFY-NEG: daemon failed to become healthy"
        [ -n "$rpid" ] && kill "$rpid" 2>/dev/null
        return
    fi

    if "$ROOT/tests/smtptest.com" 127.0.0.1 "$SMTP" sender@foo.org jane@example.com "$WORK/msg1.eml" >"$d/fwd.log" 2>&1; then
        pass "VERIFY-NEG: smtptest forward accepted (queued)"
    else
        fail "VERIFY-NEG: smtptest forward failed (see $d/fwd.log)"
    fi

    local DL="$relay/dialogue-1.txt" FW="$relay/msg-1.eml"
    # Wait for the daemon to have reached the relay (dialogue non-empty) so we
    # know the forward attempt ran, then assert the negative outcomes.
    if wait_for_file "$DL"; then
        pass "VERIFY-NEG: daemon connected to the relay (forward attempted)"
        # It must have gotten as far as advertising/starting TLS...
        if grep -q 'Ready to start TLS' "$DL"; then
            pass "VERIFY-NEG: dialogue shows the STARTTLS upgrade was attempted"
        else
            fail "VERIFY-NEG: dialogue does not show a STARTTLS attempt (see $DL)"
        fi
        # ...but verification against the wrong CA fails, so no MAIL ever goes out.
        if grep -q 'MAIL FROM:' "$DL"; then
            fail "VERIFY-NEG: FAIL — MAIL sent over a failed-verification channel (see $DL)"
        else
            pass "VERIFY-NEG: no MAIL FROM in the dialogue (verification failed before MAIL)"
        fi
        if [ -s "$FW" ]; then
            fail "VERIFY-NEG: FAIL — message forwarded despite failed verification"
        else
            pass "VERIFY-NEG: message NOT forwarded (untrusted cert -> permfail, no plaintext fallback)"
        fi
    else
        fail "VERIFY-NEG: daemon did not attempt to reach the relay"
    fi

    [ -n "$dpid" ] && kill "$dpid" 2>/dev/null
    [ -n "$rpid" ] && kill "$rpid" 2>/dev/null
    wait "$dpid" 2>/dev/null || true
    wait "$rpid" 2>/dev/null || true
}
# --- durable-queue e2e scenarios (S-A3) -----------------------------------
# These prove at-least-once DURABLE delivery via the spool-file lifecycle (the
# observable proxy for queued->delivered).  The daemon spools the sanitized
# outbound body to <spool>/<msgid>.<k>.out.eml at enqueue time and unlinks it
# once the relay accepts the message (status 'delivered'); the raw inbound
# <msgid>.eml is never removed.  There is no CLI that exposes queue status, so
# "queued" == .out.eml present, "delivered" == .out.eml gone.
#
# Print the path of the newest durable outbound spool file, or return nonzero
# if none exists yet.
newest_out_eml() {
    local spool="$1" f
    f="$(ls -t "$spool"/*.out.eml 2>/dev/null | head -n1 || true)"
    if [ -n "$f" ] && [ -s "$f" ]; then
        printf '%s\n' "$f"
        return 0
    fi
    return 1
}

# Scenario: OUTAGE -> RE-DRIVE (same daemon, no restart).  The relay port is
# initially DOWN (nothing listening): the daemon must durably accept + spool the
# message (250), keep it queued while the relay is unreachable, then re-drive
# and deliver it once relay_fake comes up — at-least-once without a restart.
outage_redrive_scenario() {
    echo
    echo "== scenario: outage -> re-drive (same daemon, no restart)"
    local d="$WORK/outage" db="$WORK/outage/db" spool="$WORK/outage/spool"
    local relay="$WORK/outage/relay" conf="$WORK/outage/config.dhall"
    local dpid="" rpid="" i
    local SMTP=2540 RELAY=2541 HTTP=8092
    mkdir -p "$d" "$relay" "$db" "$spool"
    gen_config "$conf" "$SMTP" "$RELAY" none False "$HTTP" "$db" "$spool"

    # Relay port is intentionally DOWN: do NOT start relay_fake yet.
    "$ROOT/visage.com" daemon -c "$conf" >"$d/daemon.log" 2>&1 &
    dpid=$!
    if wait_health "$HTTP" "$dpid" "$d/daemon.log"; then
        pass "OUTAGE: daemon up (relay port $RELAY down)"
    else
        fail "OUTAGE: daemon failed to become healthy"
        return
    fi

    if "$ROOT/tests/smtptest.com" 127.0.0.1 "$SMTP" sender@foo.org jane@example.com \
            "$WORK/msg1.eml" >"$d/fwd.log" 2>&1; then
        pass "OUTAGE: smtptest forward accepted (250; durably queued)"
    else
        fail "OUTAGE: smtptest forward failed (see $d/fwd.log)"
        [ -n "$dpid" ] && kill "$dpid" 2>/dev/null
        return
    fi

    local OUT=""
    if OUT="$(newest_out_eml "$spool")"; then
        pass "OUTAGE: message spooled to $(basename "$OUT") (queued)"
    else
        fail "OUTAGE: no outbound spool file appeared in $spool"
        [ -n "$dpid" ] && kill "$dpid" 2>/dev/null
        return
    fi
    # Relay is still down: nothing must have been delivered yet.
    if [ -e "$relay/msg-1.eml" ]; then
        fail "OUTAGE: FAIL — message delivered while relay was down"
    else
        pass "OUTAGE: not delivered while relay is down (stays queued)"
    fi

    # Bring the (plaintext) relay up on the previously-down port.
    "$ROOT/tests/relay_fake.com" "$RELAY" "$relay" >"$d/relay.log" 2>&1 &
    rpid=$!
    sleep 0.3
    if kill -0 "$rpid" 2>/dev/null; then
        pass "OUTAGE: relay_fake now listening on $RELAY"
        # Re-drive tick cap is 30s, so allow ~45s for delivery.
        for i in $(seq 1 450); do
            [ -s "$relay/msg-1.eml" ] && [ ! -e "$OUT" ] && break
            sleep 0.1
        done
        if [ -s "$relay/msg-1.eml" ]; then
            pass "OUTAGE: relay_fake recorded the forwarded message (re-driven)"
            if [ ! -e "$OUT" ]; then
                pass "OUTAGE: queue reached delivered (spool removed)"
            else
                fail "OUTAGE: relay got the message but spool file still present"
            fi
        else
            fail "OUTAGE: relay_fake did not record the message within the re-drive window"
        fi
    else
        fail "OUTAGE: relay_fake failed to start (see $d/relay.log)"
    fi

    [ -n "$dpid" ] && kill "$dpid" 2>/dev/null
    [ -n "$rpid" ] && kill "$rpid" 2>/dev/null
    wait "$dpid" 2>/dev/null || true
    wait "$rpid" 2>/dev/null || true
}

# Scenario: RESTART persistence (crash recovery).  With the relay down the daemon
# durably queues the message; killing the daemon while it is queued must NOT lose
# it.  On restart with the SAME storage dir, the leftover 'queued' row is drained
# at boot (reset_delivering + queue_redrive) and the message delivered —
# crash-survivable at-least-once.
restart_persistence_scenario() {
    echo
    echo "== scenario: restart persistence (crash while queued)"
    local d="$WORK/restart" db="$WORK/restart/db" spool="$WORK/restart/spool"
    local relay="$WORK/restart/relay" conf="$WORK/restart/config.dhall"
    local dpid="" rpid="" i
    local SMTP=2543 RELAY=2544 HTTP=8093
    mkdir -p "$d" "$relay" "$db" "$spool"
    gen_config "$conf" "$SMTP" "$RELAY" none False "$HTTP" "$db" "$spool"

    # Relay down initially: queue the message, then kill the daemon.
    "$ROOT/visage.com" daemon -c "$conf" >"$d/daemon1.log" 2>&1 &
    dpid=$!
    if wait_health "$HTTP" "$dpid" "$d/daemon1.log"; then
        pass "RESTART: daemon up (relay down)"
    else
        fail "RESTART: daemon failed to become healthy"
        return
    fi

    if "$ROOT/tests/smtptest.com" 127.0.0.1 "$SMTP" sender@foo.org jane@example.com \
            "$WORK/msg1.eml" >"$d/fwd.log" 2>&1; then
        pass "RESTART: smtptest forward accepted (250; durably queued)"
    else
        fail "RESTART: smtptest forward failed (see $d/fwd.log)"
        [ -n "$dpid" ] && kill "$dpid" 2>/dev/null
        return
    fi

    local OUT=""
    if OUT="$(newest_out_eml "$spool")"; then
        pass "RESTART: message spooled to $(basename "$OUT") (queued)"
    else
        fail "RESTART: no outbound spool file appeared in $spool"
        [ -n "$dpid" ] && kill "$dpid" 2>/dev/null
        return
    fi

    # Kill the daemon while it is still queued (relay unreachable).
    kill "$dpid" 2>/dev/null
    wait "$dpid" 2>/dev/null || true
    dpid=""
    pass "RESTART: daemon killed (SIGTERM) while message queued"
    if [ -e "$OUT" ]; then
        pass "RESTART: queued spool body survived the daemon death"
    else
        fail "RESTART: queued spool body was lost on daemon death"
    fi

    # Relay comes up; daemon restarts with the SAME storage -> drains at boot.
    "$ROOT/tests/relay_fake.com" "$RELAY" "$relay" >"$d/relay.log" 2>&1 &
    rpid=$!
    sleep 0.3
    if ! kill -0 "$rpid" 2>/dev/null; then
        fail "RESTART: relay_fake failed to start (see $d/relay.log)"
    fi
    "$ROOT/visage.com" daemon -c "$conf" >"$d/daemon2.log" 2>&1 &
    dpid=$!
    if wait_health "$HTTP" "$dpid" "$d/daemon2.log"; then
        pass "RESTART: daemon restarted (same storage)"
    else
        fail "RESTART: restarted daemon failed to become healthy"
        [ -n "$rpid" ] && kill "$rpid" 2>/dev/null
        [ -n "$dpid" ] && kill "$dpid" 2>/dev/null
        return
    fi

    # Startup drain re-drives the leftover 'queued'; allow the re-drive window.
    for i in $(seq 1 450); do
        [ -s "$relay/msg-1.eml" ] && [ ! -e "$OUT" ] && break
        sleep 0.1
    done
    if [ -s "$relay/msg-1.eml" ]; then
        pass "RESTART: relay_fake recorded the message after restart"
        if [ ! -e "$OUT" ]; then
            pass "RESTART: queue reached delivered (spool removed)"
        else
            fail "RESTART: relay got the message but spool file still present"
        fi
    else
        fail "RESTART: relay_fake did not record the message after restart"
    fi

    [ -n "$dpid" ] && kill "$dpid" 2>/dev/null
    [ -n "$rpid" ] && kill "$rpid" 2>/dev/null
    wait "$dpid" 2>/dev/null || true
    wait "$rpid" 2>/dev/null || true
}

# Scenario: DKIM signing (R9).  A config with dkim=[{domain=example.com,
# selector=sel1, private_key=tests/dkim-test-key.pem}] + a plaintext relay_fake.
# The daemon must DKIM-sign the sanitized forward copy (a=rsa-sha256,
# c=relaxed/relaxed) before enqueue: the recorded msg-1.eml must carry a
# well-formed DKIM-Signature (^DKIM-Signature: with v=1, a=rsa-sha256,
# d=example.com, s=sel1, b=).  Full signature validity is the dkim_check unit's
# job; here we assert presence + well-formedness.  The existing forward body
# match still holds (DKIM adds a header only).
dkim_forward_scenario() {
    echo
    echo "== scenario: DKIM forward (dkim=[{example.com,sel1}], plaintext relay)"
    local d="$WORK/dkim" db="$WORK/dkim/db" spool="$WORK/dkim/spool" relay="$WORK/dkim/relay"
    local conf="$WORK/dkim/config.dhall" rpid="" dpid=""
    local SMTP=2551 RELAY=2552 HTTP=8096
    mkdir -p "$d" "$relay" "$db" "$spool"
    gen_config "$conf" "$SMTP" "$RELAY" none False "$HTTP" "$db" "$spool" \
        127.0.0.1 "" example.com sel1 "$ROOT/tests/dkim-test-key.pem"

    "$ROOT/tests/relay_fake.com" "$RELAY" "$relay" >"$d/relay.log" 2>&1 &
    rpid=$!
    sleep 0.3
    if ! kill -0 "$rpid" 2>/dev/null; then
        fail "DKIM: relay_fake failed to start (see $d/relay.log)"
        return
    fi
    "$ROOT/visage.com" daemon -c "$conf" >"$d/daemon.log" 2>&1 &
    dpid=$!
    if wait_health "$HTTP" "$dpid" "$d/daemon.log"; then
        pass "DKIM: daemon up (GET /health ok)"
    else
        fail "DKIM: daemon failed to become healthy"
        [ -n "$rpid" ] && kill "$rpid" 2>/dev/null
        return
    fi

    if "$ROOT/tests/smtptest.com" 127.0.0.1 "$SMTP" sender@foo.org jane@example.com "$WORK/msg1.eml" >"$d/fwd.log" 2>&1; then
        pass "DKIM: smtptest forward accepted"
    else
        fail "DKIM: smtptest forward failed (see $d/fwd.log)"
    fi

    local FW="$relay/msg-1.eml"
    if wait_for_file "$FW"; then
        pass "DKIM: relay_fake recorded the forwarded message"
        if grep -q '^DKIM-Signature:' "$FW"; then
            pass "DKIM: forwarded message has a DKIM-Signature header"
        else
            fail "DKIM: forwarded message missing DKIM-Signature header"
        fi
        # well-formed: v=1, a=rsa-sha256, d=example.com, s=sel1, b= present.
        if grep -q '^DKIM-Signature:.*v=1' "$FW" \
           && grep -q '^DKIM-Signature:.*a=rsa-sha256' "$FW" \
           && grep -q '^DKIM-Signature:.*d=example.com' "$FW" \
           && grep -q '^DKIM-Signature:.*s=sel1' "$FW" \
           && grep -q '^DKIM-Signature:.*b=' "$FW"; then
            pass "DKIM: DKIM-Signature well-formed (v=1,a=rsa-sha256,d=example.com,s=sel1,b=)"
        else
            fail "DKIM: DKIM-Signature not well-formed (see $FW)"
        fi
        if diff -u <(body_of "$WORK/msg1.eml") <(body_of "$FW") >"$d/body.diff" 2>&1; then
            pass "DKIM: forwarded body still matches msg1.eml"
        else
            fail "DKIM: forwarded body differs from msg1.eml (see $d/body.diff)"
        fi
    else
        fail "DKIM: relay_fake did not record a forwarded message"
    fi

    [ -n "$dpid" ] && kill "$dpid" 2>/dev/null
    [ -n "$rpid" ] && kill "$rpid" 2>/dev/null
    wait "$dpid" 2>/dev/null || true
    wait "$rpid" 2>/dev/null || true
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

# (S-B3) TLS forward scenario ------------------------------------------------
tls_forward_scenario

# (S-B3) D2 negative scenario ------------------------------------------------
d2_negative_scenario

# (S-B4) starttls-verify scenarios -------------------------------------------
verify_forward_scenario
verify_negative_scenario

# (S-A3) durable-queue scenarios ---------------------------------------------
outage_redrive_scenario
restart_persistence_scenario

# (R9) DKIM signing scenario ------------------------------------------------
dkim_forward_scenario

# ---------------------------------------------------------------------------
echo
echo "== visage e2e: $PASSES passed, $FAILS failed"
[ "$FAILS" -eq 0 ]
