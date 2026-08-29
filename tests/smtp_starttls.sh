#!/usr/bin/env bash
# smtp_starttls.sh — inbound STARTTLS integration tests for the visage daemon
# (RFC 3207).  REQUIRES live sockets; run on the host via `dhake e2e` or
# directly.
#
# Drives two live visage.com instances against real clients:
#   (1) tls = { cert, key }     : EHLO advertises STARTTLS; STARTTLS before
#       EHLO -> 503; pipelined bytes before STARTTLS -> 500; STARTTLS ->
#       220 -> TLS -> re-EHLO does NOT re-advertise; MAIL/RCPT/DATA/QUIT over
#       TLS; relay_fake records the forwarded message; admin /health serves
#       plaintext WHILE a TLS SMTP session is live (loop multiplex proof)
#   (2) resilience              : garbage instead of ClientHello drops the
#       connection without killing the daemon
#   (3) no tls value            : no STARTTLS advert, STARTTLS -> 502,
#       plaintext delivery unchanged (regression; empty tls paths are the
#       documented disabled default and must keep working)
#   (4) fail-closed             : tls with only cert -> config error (nonzero
#       exit); garbage cert file -> daemon exits nonzero (bad cert/key must
#       never silently downgrade to plaintext)
# plus an openssl s_client -starttls smtp interop smoke when available.
#
# Ports/paths are parametrized via env: SMTP_TLS_PORT_BASE (default 14530).
set -euo pipefail

cd "$(dirname "$0")/.."

PORT_BASE="${SMTP_TLS_PORT_BASE:-14530}"
SMTP_T=$((PORT_BASE));      HTTP_T=$((PORT_BASE + 1));  RELAY_T=$((PORT_BASE + 2))
SMTP_N=$((PORT_BASE + 3));  HTTP_N=$((PORT_BASE + 4));  RELAY_N=$((PORT_BASE + 5))
CERT=tests/visage-test-cert.pem
KEY=tests/visage-test-key.pem

TMP="$(mktemp -d /tmp/smtp_starttls_XXXXXX)"
mkdir -p "$TMP/t/db" "$TMP/t/spool" "$TMP/n/db" "$TMP/n/spool" \
         "$TMP/relay_t" "$TMP/relay_n"

DAEMONS=()
FAILS=0

cleanup() {
    for pid in "${DAEMONS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    rm -rf "$TMP"
}
trap cleanup EXIT

pass()  { printf 'ok   %s\n' "$1"; }
fail()  { printf 'FAIL %s\n' "$1"; FAILS=$((FAILS + 1)); }
check() { if [ "$1" = 0 ]; then pass "$2"; else fail "$2"; fi }

wait_port() {   # wait_port PORT LABEL
    local i=0
    until (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; do
        i=$((i + 1))
        if [ "$i" -gt 100 ]; then fail "$2 did not come up"; exit 1; fi
        sleep 0.1
    done
}

gen_config() {   # gen_config OUT SMTP HTTP DB SPOOL RELAY [CERT KEY]
    local out="$1" smtp="$2" http="$3" db="$4" spool="$5" relay="$6"
    local cert="${7:-}" key="${8:-}" tls_rec
    if [ -n "$cert" ]; then
        tls_rec="   , tls = { cert = \"$cert\", key = \"$key\" }"
    else
        # empty paths = TLS disabled (the documented default)
        tls_rec="   , tls = { cert = \"\", key = \"\" }"
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
      , storage : { path : Text, spool : Text, retention_days : Natural }
      , reply : { prefix : Text, separator : Text }
      , catch_all : Text
      , aliases : List { alias : Text, destinations : List Text }
      , http : { address : Text, port : Natural }
      , admin : { token : Text }
      , tls : { cert : Text, key : Text }
      , dkim : List { domain : Text, selector : Text, private_key : Text }
      }
in  { hostname = "mx.example.com"
   , domains = [ "example.com" ]
   , listen = { address = "127.0.0.1", port = $smtp }
   , limits = { message = 26214400, line = 1000, rcpts = 100
              , cmd_timeout = 300, data_timeout = 600 }
   , relay = { host = "127.0.0.1", port = $relay
             , auth = { enabled = False, username = "", password = "" }
             , retries = 3, tls = "none", tls_ca = "", max_attempts = 100 }
   , storage = { path = "$db", spool = "$spool", retention_days = 30 }
   , reply = { prefix = "reply", separator = "+" }
   , catch_all = ""
   , aliases = [ { alias = "jane@example.com", destinations = [ "jane@realmail.example" ] } ]
   , http = { address = "127.0.0.1", port = $http }
   , admin = { token = "change-me" }
   , dkim = [] : List { domain : Text, selector : Text, private_key : Text }
$tls_rec
   } : Config
DHALL
}

start_daemon() {   # start_daemon CONF LOG
    ./visage.com daemon -c "$1" >"$2" 2>&1 &
    DAEMONS+=("$!")
}

# ---- (0) fail-closed at config load: tls with only cert must be rejected ----
gen_config "$TMP/bad-half.conf" "$SMTP_T" "$HTTP_T" "$TMP/t/db" "$TMP/t/spool" \
           "$RELAY_T" "$CERT"
if ./visage.com daemon -c "$TMP/bad-half.conf" >"$TMP/bad-half.log" 2>&1; then
    fail "tls cert without key must exit nonzero"
else
    check 0 "tls cert without key exits nonzero (config pair-check)"
fi

# ---- (1) main TLS daemon (empty tls paths = disabled) + relay_fakes ----
gen_config "$TMP/tls.conf" "$SMTP_T" "$HTTP_T" "$TMP/t/db" "$TMP/t/spool" \
           "$RELAY_T" "$CERT" "$KEY"
gen_config "$TMP/none.conf" "$SMTP_N" "$HTTP_N" "$TMP/n/db" "$TMP/n/spool" \
           "$RELAY_N"

./tests/relay_fake.com "$RELAY_T" "$TMP/relay_t" >"$TMP/relay_t.log" 2>&1 &
DAEMONS+=("$!")
./tests/relay_fake.com "$RELAY_N" "$TMP/relay_n" >"$TMP/relay_n.log" 2>&1 &
DAEMONS+=("$!")
start_daemon "$TMP/tls.conf" "$TMP/tls.log"
start_daemon "$TMP/none.conf" "$TMP/none.log"

wait_port "$SMTP_T" "smtp TLS"
wait_port "$HTTP_T" "http TLS"
wait_port "$RELAY_T" "relay TLS"
wait_port "$SMTP_N" "smtp plain"
wait_port "$RELAY_N" "relay plain"

# ---- (2) STARTTLS happy path + pipelining guard + /health multiplex ----
python3 - "$SMTP_T" "$HTTP_T" "$TMP/relay_t" <<'PYEOF' \
    && pass "smtp: STARTTLS seq/guard/TLS delivery + /health multiplex" \
    || fail "smtp: STARTTLS seq/guard/TLS delivery + /health multiplex"
import glob, http.client, os, socket, ssl, sys, time

smtp_port, http_port, relay_dir = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def read_reply(f):
    """Read one SMTP reply (all lines up to the 'ddd ' final line)."""
    lines = []
    while True:
        ln = f.readline()
        assert ln, "unexpected EOF"
        lines.append(ln)
        if ln[3:4] == b" ":
            return lines

# a) STARTTLS before EHLO is a sequencing error (RFC 3207 4)
s = socket.create_connection(("127.0.0.1", smtp_port), timeout=10)
f = s.makefile("rb")
assert f.readline().startswith(b"220 "), "greeting"
s.sendall(b"STARTTLS\r\n")
assert read_reply(f)[0].startswith(b"503"), "STARTTLS before EHLO"

# b) EHLO advertises STARTTLS
s.sendall(b"EHLO client.test\r\n")
ehlo = read_reply(f)
assert any(b"STARTTLS" in ln for ln in ehlo), ehlo
s.sendall(b"QUIT\r\n")
s.close()

# c) pipelined bytes before STARTTLS are rejected (plaintext-injection guard):
#    EHLO + STARTTLS + EHLO in ONE write -> 250 / 500 / 250
s = socket.create_connection(("127.0.0.1", smtp_port), timeout=10)
f = s.makefile("rb")
assert f.readline().startswith(b"220 ")
s.sendall(b"EHLO p.test\r\nSTARTTLS\r\nEHLO y.test\r\n")
r1 = read_reply(f)
assert r1[0].startswith(b"250"), r1
r2 = read_reply(f)
assert r2[0].startswith(b"500") and b"Pipelined" in r2[0], r2
r3 = read_reply(f)
assert r3[0].startswith(b"250"), r3
s.sendall(b"QUIT\r\n")
s.close()

# d) the real flow: STARTTLS -> TLS -> everything else encrypted
s = socket.create_connection(("127.0.0.1", smtp_port), timeout=10)
f = s.makefile("rb")
assert f.readline().startswith(b"220 ")
s.sendall(b"EHLO client.test\r\n")
assert any(b"STARTTLS" in ln for ln in read_reply(f))
s.sendall(b"STARTTLS\r\n")
r = read_reply(f)
assert r[0].startswith(b"220") and b"Ready" in r[0], r
tls = ctx.wrap_socket(s)
tf = tls.makefile("rwb")

tls.sendall(b"EHLO client.test\r\n")            # RFC 3207: gone post-TLS
ehlo2 = read_reply(tf)
assert not any(b"STARTTLS" in ln for ln in ehlo2), ehlo2

tls.sendall(b"MAIL FROM:<bob@example.org>\r\n")
assert read_reply(tf)[0].startswith(b"250")
tls.sendall(b"RCPT TO:<jane@example.com>\r\n")
assert read_reply(tf)[0].startswith(b"250")
tls.sendall(b"DATA\r\n")
assert read_reply(tf)[0].startswith(b"354")
tls.sendall(b"Subject: smtp-starttls-e2e\r\n\r\nsecret-tls-body\r\n.\r\n")
assert read_reply(tf)[0].startswith(b"250")

# e) the admin HTTP listener serves plaintext WHILE the TLS SMTP session is live
c = http.client.HTTPConnection("127.0.0.1", http_port, timeout=10)
c.request("GET", "/health")
resp = c.getresponse()
assert resp.status == 200, resp.status
c.close()

tls.sendall(b"QUIT\r\n")
assert read_reply(tf)[0].startswith(b"221")
tls.close()

# f) the forwarded message reached relay_fake
deadline = time.time() + 5
while time.time() < deadline and not glob.glob(os.path.join(relay_dir, "msg-*.eml")):
    time.sleep(0.1)
msgs = glob.glob(os.path.join(relay_dir, "msg-*.eml"))
assert msgs, "forwarded message missing at relay_fake"
body = open(msgs[0], "rb").read()
assert b"secret-tls-body" in body, body[:200]
PYEOF

# ---- (3) resilience: garbage after STARTTLS must not wedge the daemon ----
python3 - "$SMTP_T" <<'PYEOF' && pass "resilience: non-TLS garbage drops the conn only" \
                           || fail "resilience: non-TLS garbage drops the conn only"
import socket, sys

port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=10)
f = s.makefile("rb")
f.readline()
s.sendall(b"EHLO g.test\r\n")
while True:
    ln = f.readline()
    if ln[3:4] == b" ":
        break
s.sendall(b"STARTTLS\r\n")
line = f.readline()
assert line.startswith(b"220"), line
s.sendall(b"\x16\x03\x01\x00\x05this is not TLS at all\r\n")
s.settimeout(10)
try:
    while s.recv(4096):
        pass            # drain until the server closes (EOF)
except (ConnectionResetError, socket.timeout):
    pass
# a fresh connection must still be served
s2 = socket.create_connection(("127.0.0.1", port), timeout=10)
line = s2.makefile("rb").readline().decode()
assert line.startswith("220 "), line
s2.close()
PYEOF

# ---- (4) regression: empty tls paths = plaintext behavior unchanged ----
python3 - "$SMTP_N" "$HTTP_N" "$TMP/relay_n" <<'PYEOF' \
    && pass "regression: empty tls paths, plaintext unchanged + delivery works" \
    || fail "regression: empty tls paths, plaintext unchanged + delivery works"
import glob, http.client, os, socket, sys, time

smtp_port, http_port, relay_dir = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
s = socket.create_connection(("127.0.0.1", smtp_port), timeout=10)
f = s.makefile("rb")
assert f.readline().startswith(b"220 ")
s.sendall(b"EHLO client.test\r\n")
lines = []
while True:
    ln = f.readline()
    lines.append(ln)
    if ln[3:4] == b" ":
        break
assert not any(b"STARTTLS" in ln for ln in lines), lines
s.sendall(b"STARTTLS\r\n")
assert f.readline().startswith(b"502"), "STARTTLS must be 502 when TLS is off"
s.sendall(b"MAIL FROM:<sender@foo.org>\r\n")
assert f.readline().startswith(b"250")
s.sendall(b"RCPT TO:<jane@example.com>\r\n")
assert f.readline().startswith(b"250")
s.sendall(b"DATA\r\n")
assert f.readline().startswith(b"354")
s.sendall(b"Subject: smtp-plain-e2e\r\n\r\nplain-body\r\n.\r\n")
assert f.readline().startswith(b"250")
s.sendall(b"QUIT\r\n")

# the admin listener still serves /health on the same loop
c = http.client.HTTPConnection("127.0.0.1", http_port, timeout=10)
c.request("GET", "/health")
assert c.getresponse().status == 200
c.close()

deadline = time.time() + 5
while time.time() < deadline and not glob.glob(os.path.join(relay_dir, "msg-*.eml")):
    time.sleep(0.1)
msgs = glob.glob(os.path.join(relay_dir, "msg-*.eml"))
assert msgs, "plain forwarded message missing at relay_fake"
assert b"plain-body" in open(msgs[0], "rb").read()
PYEOF

# ---- (5) fail-closed at init: a garbage cert must refuse to start ----
GARBAGE="$TMP/garbage-cert.pem"
printf 'not a certificate at all\n' > "$GARBAGE"
gen_config "$TMP/bad-cert.conf" "$SMTP_T" "$HTTP_T" "$TMP/t/db" "$TMP/t/spool" \
           "$RELAY_T" "$GARBAGE" "$KEY"
if ./visage.com daemon -c "$TMP/bad-cert.conf" >"$TMP/bad-cert.log" 2>&1; then
    fail "garbage cert must exit nonzero"
else
    check 0 "garbage cert exits nonzero (fail-closed init)"
fi

# ---- (6) openssl s_client interop smoke (when available) ----
if command -v openssl >/dev/null 2>&1; then
    if { printf 'EHLO x\r\nQUIT\r\n'; sleep 5; } |
         timeout 15 openssl s_client -quiet -no_ign_eof -starttls smtp \
             -connect "127.0.0.1:$SMTP_T" 2>/dev/null | grep -q "221 "; then
        check 0 "openssl s_client -starttls smtp interop"
    else
        check 1 "openssl s_client -starttls smtp interop"
    fi
else
    printf 'skip openssl interop (openssl not found)\n'
fi

printf '\n'
if [ "$FAILS" -gt 0 ]; then
    printf '%d checks failed\n' "$FAILS"
    exit 1
fi
printf 'smtp_starttls: OK\n'
