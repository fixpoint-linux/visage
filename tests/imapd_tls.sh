#!/usr/bin/env bash
# imapd_tls.sh — STARTTLS integration tests for imapd (IMAP RFC 2595 +
# SMTP ingest RFC 3207).  REQUIRES live sockets; run on the host via
# `dhake e2e` or directly.
#
# Drives three live imapd instances against real clients:
#   (1) loopback + --cert/--key : STARTTLS on both listeners, LOGIN ok
#       pre-TLS (RFC 3501 11.1 loopback exemption), STARTTLS -> LOGIN/
#       SELECT/FETCH round-trip over TLS, delivered mail visible
#   (2) 0.0.0.0 + --cert/--key  : LOGINDISABLED advertised, plaintext
#       LOGIN refused with NO [PRIVACYREQUIRED], allowed after STARTTLS
#   (3) no cert/key             : no STARTTLS anywhere, plaintext loopback
#       LOGIN unchanged (regression); --cert without --key exits nonzero
#   (4) resilience              : garbage instead of ClientHello drops the
#       connection without killing the daemon
# plus an openssl s_client interop smoke on both protocols when available.
#
# Ports/paths are parametrized via env: IMAPD_TLS_PORT_BASE (default 14430).
set -euo pipefail

cd "$(dirname "$0")/.."

PORT_BASE="${IMAPD_TLS_PORT_BASE:-14430}"
IMAP_A=$((PORT_BASE));      INGEST_A=$((PORT_BASE + 1))
IMAP_B=$((PORT_BASE + 2));  INGEST_B=$((PORT_BASE + 3))
IMAP_D=$((PORT_BASE + 4));  INGEST_D=$((PORT_BASE + 5))
POP3_A=$((PORT_BASE + 6));  POP3_B=$((PORT_BASE + 7))
POP3_D=$((PORT_BASE + 8))
CERT=tests/visage-test-cert.pem
KEY=tests/visage-test-key.pem

TMP="$(mktemp -d /tmp/imapd_tls_XXXXXX)"
ROOT_A="$TMP/a"; ROOT_B="$TMP/b"; ROOT_D="$TMP/d"
mkdir -p "$ROOT_A" "$ROOT_B" "$ROOT_D"

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

start_daemon() {   # start_daemon ROOT LOG EXTRA_ARGS...
    local root="$1" log="$2"; shift 2
    ./imapd.com --root "$root" "$@" >"$log" 2>&1 &
    DAEMONS+=("$!")
}

# ---- users (each root gets its own passwd file) ----
./imapd.com passwd alice waldorf --root "$ROOT_A" >/dev/null
./imapd.com passwd alice waldorf --root "$ROOT_B" >/dev/null
./imapd.com passwd alice waldorf --root "$ROOT_D" >/dev/null
./imapd.com passwd bob waldorf --root "$ROOT_A" >/dev/null  # IDLE test user
./imapd.com passwd carol waldorf --root "$ROOT_A" >/dev/null  # CONDSTORE test user

# ---- instances ----
start_daemon "$ROOT_A" "$TMP/a.log" \
    --cert "$CERT" --key "$KEY" --hostname imap.test \
    --imap-port "$IMAP_A" --ingest-port "$INGEST_A" --pop3-port "$POP3_A"
start_daemon "$ROOT_B" "$TMP/b.log" \
    --cert "$CERT" --key "$KEY" --hostname imap.test \
    --imap-addr 0.0.0.0 --imap-port "$IMAP_B" --ingest-port "$INGEST_B" \
    --pop3-addr 0.0.0.0 --pop3-port "$POP3_B"
start_daemon "$ROOT_D" "$TMP/d.log" \
    --hostname imap.test \
    --imap-port "$IMAP_D" --ingest-port "$INGEST_D" --pop3-port "$POP3_D"

wait_port "$IMAP_A" "imap A"
wait_port "$INGEST_A" "ingest A"
wait_port "$IMAP_B" "imap B"
wait_port "$IMAP_D" "imap D"

# ---- (0) fail-closed: cert without key must refuse to start ----
if ./imapd.com --root "$TMP/bad" --cert "$CERT" \
        --imap-port "$IMAP_D" --ingest-port "$INGEST_D" --pop3-port "$POP3_D" \
        >"$TMP/bad.log" 2>&1; then
    fail "cert without key must exit nonzero"
else
    check 0 "cert without key exits nonzero (fail-closed)"
fi

# ---- (1) IMAP STARTTLS happy path on loopback ----
python3 - "$IMAP_A" <<'PYEOF' && pass "imap: STARTTLS + capability + LOGIN + SELECT" \
                           || fail "imap: STARTTLS + capability + LOGIN + SELECT"
import socket, ssl, sys

port = int(sys.argv[1])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# a) pre-TLS: loopback bind keeps plaintext LOGIN; STARTTLS after an
#    authenticated session is a sequencing violation (RFC 2595)
s = socket.create_connection(("127.0.0.1", port), timeout=10)
f = s.makefile("rb")
greeting = f.readline().decode()
assert "STARTTLS" in greeting and "AUTH=PLAIN" in greeting, greeting
assert "LOGINDISABLED" not in greeting, greeting
s.sendall(b"a1 LOGIN alice waldorf\r\n")
line = f.readline().decode()
assert "a1 OK" in line, line
s.sendall(b"a2 STARTTLS\r\n")
line = f.readline().decode()
assert "a2 BAD" in line, line          # authenticated => too late
s.sendall(b"a3 LOGOUT\r\n")
s.close()

# b) the real flow: STARTTLS first, then everything over TLS
s = socket.create_connection(("127.0.0.1", port), timeout=10)
f = s.makefile("rb")
assert f.readline().startswith(b"* OK")
s.sendall(b"b1 STARTTLS\r\n")
line = f.readline().decode()
assert "b1 OK" in line, line
tls = ctx.wrap_socket(s)
tf = tls.makefile("rwb")

tls.sendall(b"b2 CAPABILITY\r\n")
cap = b""
while True:
    ln = tf.readline()
    cap += ln
    if ln.startswith(b"b2 "):
        break
assert b"STARTTLS" not in cap, cap          # RFC 2595: never re-advertised
assert b"AUTH=PLAIN" in cap, cap

tls.sendall(b"b3 LOGIN alice waldorf\r\n")
login = b""
while True:
    ln = tf.readline()
    login += ln
    if ln.startswith(b"b3 "):
        break
assert b"b3 OK" in login, login
tls.sendall(b"b4 SELECT INBOX\r\n")
sel = b""
while True:
    ln = tf.readline()
    sel += ln
    if ln.startswith(b"b4 "):
        break
assert b"b4 OK" in sel, sel
tls.sendall(b"b5 LOGOUT\r\n")
PYEOF

# ---- (1b) RFC 2177 IDLE: SELECT then IDLE, deliver a new message, expect an
# unsolicited EXISTS from the idling session, then DONE completes the tag.
# Uses its own user (bob) so it cannot perturb alice's INBOX counts. ----
python3 - "$IMAP_A" "$ROOT_A" <<'PYEOF' && pass "imap: RFC 2177 IDLE push (EXISTS) + DONE" \
                           || fail "imap: RFC 2177 IDLE push (EXISTS) + DONE"
import os, socket, sys, time, uuid

port, root = int(sys.argv[1]), sys.argv[2]
s = socket.create_connection(("127.0.0.1", port), timeout=10)
f = s.makefile("rb")
assert f.readline().startswith(b"* OK")
s.sendall(b"c1 LOGIN bob waldorf\r\n")
assert f.readline().startswith(b"c1 OK")
s.sendall(b"c2 SELECT INBOX\r\n")
sel = b""
while True:
    ln = f.readline()
    sel += ln
    if ln.startswith(b"c2 "):
        break
assert b"c2 OK" in sel, sel

# enter IDLE
s.sendall(b"c3 IDLE\r\n")
line = f.readline().decode()
assert line.startswith("+"), line

# a new message lands in the mailbox while we idle
newdir = os.path.join(root, "bob", "Inbox", "new")
os.makedirs(newdir, exist_ok=True)
msg = b"From: bob@example.net\r\nSubject: idle push\r\n\r\nhello\r\n"
open(os.path.join(newdir, uuid.uuid4().hex), "wb").write(msg)

# the server should push an unsolicited EXISTS within the scan cadence
seen = b""
deadline = time.time() + 5
while time.time() < deadline and b"EXISTS" not in seen:
    seen += f.readline()
assert b"EXISTS" in seen, seen

# DONE completes the IDLE; the tagged OK may trail more unsolicited lines
# (the poll loop can emit further EXISTS/RECENT between the first push and
# our DONE arriving), so read until the tagged reply.
s.sendall(b"DONE\r\n")
done = b""
while True:
    ln = f.readline()
    done += ln
    if ln.startswith(b"c3 "):
        break
assert b"\r\nc3 OK IDLE completed\r\n" in done, done
s.sendall(b"c4 LOGOUT\r\n")
PYEOF

# ---- (1c) CONDSTORE + UIDPLUS: HIGHESTMODSEQ on SELECT, MODSEQ fetch item,
# CHANGEDSINCE filters unchanged messages, and UIDPLUS is advertised. ----
python3 - "$IMAP_A" "$ROOT_A" <<'PYEOF' && pass "imap: CONDSTORE (MODSEQ/CHANGEDSINCE) + UIDPLUS" \
                           || fail "imap: CONDSTORE (MODSEQ/CHANGEDSINCE) + UIDPLUS"
import os, socket, sys, uuid

port, root = int(sys.argv[1]), sys.argv[2]
# seed one message into carol's INBOX so the fetch has a row
newdir = os.path.join(root, "carol", "Inbox", "new")
os.makedirs(newdir, exist_ok=True)
open(os.path.join(newdir, uuid.uuid4().hex), "wb").write(
    b"From: a@example.com\r\nSubject: condstore\r\n\r\nhi\r\n")

s = socket.create_connection(("127.0.0.1", port), timeout=10)
f = s.makefile("rb")
assert f.readline().startswith(b"* OK")
s.sendall(b"d1 CAPABILITY\r\n")
cap = b""
while True:
    l = f.readline()
    cap += l
    if l.startswith(b"d1 "):
        break
assert b"CONDSTORE" in cap and b"UIDPLUS" in cap, cap
s.sendall(b"d2 LOGIN carol waldorf\r\n")
assert f.readline().startswith(b"d2 OK")
# FairEmail sends ENABLE CONDSTORE after LOGIN; must get * ENABLED CONDSTORE
s.sendall(b"e0 ENABLE CONDSTORE\r\n")
en = b""
while True:
    l = f.readline()
    en += l
    if l.startswith(b"e0 "):
        break
assert b"* ENABLED CONDSTORE" in en and b"e0 OK" in en, en
s.sendall(b"d3 SELECT INBOX\r\n")
sel = b""
hm = None
while True:
    l = f.readline()
    sel += l
    if b"HIGHESTMODSEQ" in l:
        hm = l
    if l.startswith(b"d3 "):
        break
assert b"d3 OK" in sel, sel
assert hm is not None, sel

# MODSEQ fetch item returns a modseq per message
s.sendall(b"d4 FETCH 1:1 (UID FLAGS MODSEQ)\r\n")
ms = b""
while True:
    l = f.readline()
    ms += l
    if l.startswith(b"d4 "):
        break
assert b"MODSEQ (" in ms, ms
assert b"d4 OK" in ms, ms

# CHANGEDSINCE a huge modseq filters out all messages (nothing changed since)
s.sendall(b"d5 FETCH 1:* (FLAGS) (CHANGEDSINCE 18446744073709551615)\r\n")
cd = b""
while True:
    l = f.readline()
    cd += l
    if l.startswith(b"d5 "):
        break
assert b"d5 OK" in cd and b"* 1 FETCH" not in cd, cd  # no messages returned
s.sendall(b"d6 LOGOUT\r\n")
PYEOF

# ---- (2) RFC 3501 11.1 gating on a non-loopback bind ----
python3 - "$IMAP_B" <<'PYEOF' && pass "imap: non-loopback gates cleartext LOGIN until STARTTLS" \
                           || fail "imap: non-loopback gates cleartext LOGIN until STARTTLS"
import socket, ssl, sys

port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=10)
f = s.makefile("rb")
greeting = f.readline().decode()
assert "STARTTLS" in greeting and "LOGINDISABLED" in greeting, greeting
assert "AUTH=PLAIN" not in greeting, greeting

s.sendall(b"c1 LOGIN alice waldorf\r\n")
line = f.readline().decode()
assert "c1 NO" in line and "PRIVACYREQUIRED" in line, line

s.sendall(b"c2 STARTTLS\r\n")
line = f.readline().decode()
assert "c2 OK" in line, line
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
tls = ctx.wrap_socket(s)
tf = tls.makefile("rwb")

tls.sendall(b"c3 CAPABILITY\r\n")
cap = b""
while True:
    ln = tf.readline()
    cap += ln
    if ln.startswith(b"c3 "):
        break
assert b"AUTH=PLAIN" in cap and b"STARTTLS" not in cap and \
       b"LOGINDISABLED" not in cap, cap

tls.sendall(b"c4 LOGIN alice waldorf\r\n")
line = tf.readline().decode()
assert "c4 OK" in line, line
tls.sendall(b"c5 LOGOUT\r\n")
PYEOF

# ---- (3) SMTP ingest STARTTLS + delivery + (4) IMAP FETCH round-trip ----
python3 - "$INGEST_A" "$IMAP_A" "$ROOT_A" <<'PYEOF' \
    && pass "ingest: EHLO/STARTTLS/TLS delivery + IMAP FETCH over TLS" \
    || fail "ingest: EHLO/STARTTLS/TLS delivery + IMAP FETCH over TLS"
import glob, os, socket, ssl, sys, time

ingest_port, imap_port, root = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

s = socket.create_connection(("127.0.0.1", ingest_port), timeout=10)
f = s.makefile("rb")
assert f.readline().startswith(b"220 ")          # greeting

# STARTTLS before EHLO is a sequencing error
s.sendall(b"STARTTLS\r\n")
assert f.readline().startswith(b"503")

s.sendall(b"EHLO client.test\r\n")
ehlo = b""
while True:
    ln = f.readline()
    ehlo += ln
    if ln.startswith(b"250 "):
        break
assert b"STARTTLS" in ehlo, ehlo

s.sendall(b"STARTTLS\r\n")
assert f.readline().startswith(b"220")
tls = ctx.wrap_socket(s)
tf = tls.makefile("rwb")

tls.sendall(b"EHLO client.test\r\n")                # RFC 3207: gone post-TLS
ehlo2 = b""
while True:
    ln = tf.readline()
    ehlo2 += ln
    if ln.startswith(b"250 "):
        break
assert b"STARTTLS" not in ehlo2, ehlo2

tls.sendall(b"MAIL FROM:<bob@example.org>\r\n")
assert tf.readline().startswith(b"250")
tls.sendall(b"RCPT TO:<alice@example.com>\r\n")
assert tf.readline().startswith(b"250")
tls.sendall(b"DATA\r\n")
assert tf.readline().startswith(b"354")
tls.sendall(b"Subject: imapd-tls-e2e\r\n\r\nsecret-tls-body\r\n.\r\n")
line = tf.readline()
assert line.startswith(b"250"), line
tls.sendall(b"QUIT\r\n")

# the message must land in alice's maildir
deadline = time.time() + 5
newdir = os.path.join(root, "alice", "Inbox", "new")
while time.time() < deadline and not glob.glob(os.path.join(newdir, "*")):
    time.sleep(0.1)
files = glob.glob(os.path.join(newdir, "*"))
assert files, "delivery missing"
body = open(files[0], "rb").read()
assert b"secret-tls-body" in body, body[:200]

# ... and be FETCHable over a fresh STARTTLS IMAP session
s2 = socket.create_connection(("127.0.0.1", imap_port), timeout=10)
f2 = s2.makefile("rb")
assert f2.readline().startswith(b"* OK")
s2.sendall(b"d1 STARTTLS\r\n")
line = f2.readline().decode()
assert "d1 OK" in line, line
tls2 = ctx.wrap_socket(s2)

def tagged(sock, cmd, tag):                      # read until the tag replies
    sock.sendall(("%s %s\r\n" % (tag, cmd)).encode())
    buf = b""
    head = ("%s " % tag).encode()
    mid = ("\r\n%s " % tag).encode()
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
        if buf.startswith(head) or mid in buf:
            return buf
    return buf

sel = tagged(tls2, "LOGIN alice waldorf", "d2")
assert b"d2 OK" in sel, sel
sel = tagged(tls2, "SELECT INBOX", "d3")
assert b"d3 OK" in sel and b"1 EXISTS" in sel, sel
fetch = tagged(tls2, "FETCH 1 (BODY[])", "d4")
assert b"secret-tls-body" in fetch, fetch[:300]
tagged(tls2, "CREATE OldFolder", "d6")
rn = tagged(tls2, "RENAME OldFolder Renamed", "d7")
assert b"d7 OK" in rn, rn
lst = tagged(tls2, "LIST \"\" \"*\"", "d8")
assert b"Renamed" in lst and b"OldFolder" not in lst, lst
tagged(tls2, "LOGOUT", "d5")
PYEOF

# ---- (4) regression: no cert = today's plaintext behavior ----
python3 - "$IMAP_D" "$INGEST_D" <<'PYEOF' && pass "regression: no cert, plaintext loopback unchanged" \
                           || fail "regression: no cert, plaintext loopback unchanged"
import socket, sys

imap_port, ingest_port = int(sys.argv[1]), int(sys.argv[2])
s = socket.create_connection(("127.0.0.1", imap_port), timeout=10)
f = s.makefile("rb")
greeting = f.readline().decode()
assert "STARTTLS" not in greeting and "AUTH=PLAIN" in greeting, greeting
s.sendall(b"e1 CAPABILITY\r\n")
cap = b""
while True:
    ln = f.readline()
    cap += ln
    if ln.startswith(b"e1 "):
        break
assert b"STARTTLS" not in cap, cap
s.sendall(b"e2 LOGIN alice waldorf\r\n")
assert "e2 OK" in f.readline().decode()
s.sendall(b"e3 LOGOUT\r\n")

s2 = socket.create_connection(("127.0.0.1", ingest_port), timeout=10)
f2 = s2.makefile("rb")
assert f2.readline().startswith(b"220 ")
s2.sendall(b"EHLO client.test\r\n")
ehlo = b""
while True:
    ln = f2.readline()
    ehlo += ln
    if ln.startswith(b"250 "):
        break
assert b"STARTTLS" not in ehlo, ehlo
PYEOF

# ---- (5) resilience: garbage after STARTTLS must not wedge the daemon ----
python3 - "$IMAP_A" <<'PYEOF' && pass "resilience: non-TLS garbage drops the conn only" \
                           || fail "resilience: non-TLS garbage drops the conn only"
import socket, sys

port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=10)
f = s.makefile("rb")
f.readline()
s.sendall(b"f1 STARTTLS\r\n")
line = f.readline().decode()
assert "f1 OK" in line, line
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
assert line.startswith("* OK"), line
s2.close()
PYEOF

# ---- (6) openssl s_client interop smoke (when available) ----
if command -v openssl >/dev/null 2>&1; then
    if { printf 'g1 LOGOUT\r\n'; sleep 1; } |
         timeout 15 openssl s_client -quiet -no_ign_eof -starttls imap \
             -connect "127.0.0.1:$IMAP_A" 2>/dev/null | grep -q "g1 OK"; then
        check 0 "openssl s_client -starttls imap interop"
    else
        check 1 "openssl s_client -starttls imap interop"
    fi
    if { printf 'EHLO x\r\nQUIT\r\n'; sleep 5; } |
         timeout 15 openssl s_client -quiet -no_ign_eof -starttls smtp \
             -connect "127.0.0.1:$INGEST_A" 2>/dev/null | grep -q "221 "; then
        check 0 "openssl s_client -starttls smtp interop"
    else
        check 1 "openssl s_client -starttls smtp interop"
    fi
else
    note "skip openssl interop (openssl not found)"
fi

printf '\n'
if [ "$FAILS" -gt 0 ]; then
    printf '%d checks failed\n' "$FAILS"
    exit 1
fi
printf 'imapd_tls: OK\n'
