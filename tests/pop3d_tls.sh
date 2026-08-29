#!/usr/bin/env bash
# pop3d_tls.sh — POP3 (RFC 1939 + STLS RFC 2595) integration tests for imapd.
# REQUIRES live sockets; run on the host via `dhake e2e` or directly.
#
# Drives two live imapd instances against real POP3 clients:
#   (1) loopback + --cert/--key : plaintext USER/PASS ok (loopback exemption),
#       STAT/LIST/UIDL/RETR/TOP/DELE/RSET/QUIT round-trip, dot-stuffing,
#       DELE+QUIT expunge visible on reconnect
#   (2) 0.0.0.0 + --cert/--key  : cleartext USER/PASS refused, STLS -> TLS
#       session works (RFC 2595 gating)
#
# Ports/paths parametrized via env: POP3D_TLS_PORT_BASE (default 14450).
set -euo pipefail

cd "$(dirname "$0")/.."

PORT_BASE="${POP3D_TLS_PORT_BASE:-14450}"
POP3_A=$((PORT_BASE));      INGEST_A=$((PORT_BASE + 1))
POP3_B=$((PORT_BASE + 2));  INGEST_B=$((PORT_BASE + 3))
IMAP_A=$((PORT_BASE + 4));  IMAP_B=$((PORT_BASE + 5))
CERT=tests/visage-test-cert.pem
KEY=tests/visage-test-key.pem

TMP="$(mktemp -d /tmp/pop3d_tls_XXXXXX)"
ROOT_A="$TMP/a"; ROOT_B="$TMP/b"
mkdir -p "$ROOT_A" "$ROOT_B"

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

./imapd.com passwd alice waldorf --root "$ROOT_A" >/dev/null
./imapd.com passwd alice waldorf --root "$ROOT_B" >/dev/null

# seed three messages directly into the maildir (one exercising dot-stuffing)
for root in "$ROOT_A" "$ROOT_B"; do
    mkdir -p "$root/alice/Inbox/new" "$root/alice/Inbox/cur" "$root/alice/Inbox/tmp"
    printf 'Subject: one\r\n\r\nfirst body\r\n' \
        > "$root/alice/Inbox/new/1111111111.M1P1.test"
    printf 'Subject: two\r\nFrom: a@b\r\n\r\nsecond\r\nbody\r\n' \
        > "$root/alice/Inbox/new/2222222222.M2P2.test"
    printf '.leading\r\nSubject: dot\r\n\r\n.dot body\r\n' \
        > "$root/alice/Inbox/new/3333333333.M3P3.test"
done

start_daemon "$ROOT_A" "$TMP/a.log" \
    --cert "$CERT" --key "$KEY" --hostname pop3.test \
    --imap-port "$IMAP_A" --pop3-port "$POP3_A" --ingest-port "$INGEST_A"
start_daemon "$ROOT_B" "$TMP/b.log" \
    --cert "$CERT" --key "$KEY" --hostname pop3.test \
    --imap-addr 0.0.0.0 --imap-port "$IMAP_B" --pop3-addr 0.0.0.0 \
    --pop3-port "$POP3_B" --ingest-port "$INGEST_B"

wait_port "$POP3_A" "pop3 A"
wait_port "$POP3_B" "pop3 B"

# ---- (1) loopback plaintext POP3 full session ----
python3 - "$POP3_A" <<'PYEOF' && pass "pop3: USER/PASS/STAT/LIST/UIDL/RETR/TOP/DELE/RSET/QUIT" \
                           || fail "pop3: USER/PASS/STAT/LIST/UIDL/RETR/TOP/DELE/RSET/QUIT"
import socket, sys

port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=10)
f = s.makefile("rb")

def send(cmd):
    s.sendall((cmd + "\r\n").encode())
    return f.readline().decode().strip()

greet = f.readline().decode()
assert greet.startswith("+OK"), greet
assert send("NOOP") == "+OK"
assert send("USER alice") == "+OK"
assert send("PASS waldorf").startswith("+OK")

st = send("STAT")
assert st.startswith("+OK 3 "), st

# LIST (multiline)
s.sendall(b"LIST\r\n")
assert f.readline().decode().startswith("+OK 3"), "LIST header"
items = []
while True:
    ln = f.readline().decode().strip()
    if ln == ".":
        break
    items.append(ln)
assert len(items) == 3, items

# UIDL (multiline)
s.sendall(b"UIDL\r\n")
assert f.readline().decode().startswith("+OK"), "UIDL header"
uids = []
while True:
    ln = f.readline().decode().strip()
    if ln == ".":
        break
    uids.append(ln)
assert len(uids) == 3, uids
expected = {"1111111111.M1P1.test", "2222222222.M2P2.test",
            "3333333333.M3P3.test"}
assert {u.split()[1] for u in uids} == expected, uids

# RETR all three and verify content + dot-stuffing (order-independent)
def retr(num):
    s.sendall(("RETR %d\r\n" % num).encode())
    assert f.readline().decode().startswith("+OK"), "RETR %d header" % num
    body = b""
    while True:
        ln = f.readline()
        if ln == b".\r\n":
            break
        body += ln
    return body

bodies = {i + 1: retr(i + 1) for i in range(3)}
joined = b"".join(bodies.values())
assert b"first body" in joined and b"Subject: one" in joined, joined
assert b"Subject: two" in joined, joined
# dot-stuffing: the ".leading" header line and ".dot body" must be doubled
assert b"..leading" in joined and b"..dot body" in joined, joined
assert b"\r\n.leading\r\n" not in joined, joined     # unstuffed would be a bug

# TOP <msg> 1 on the two-body-line message returns header + exactly 1 body line
two_num = next(n for n, b in bodies.items() if b"Subject: two" in b)
s.sendall(("TOP %d 1\r\n" % two_num).encode())
assert f.readline().decode().startswith("+OK"), "TOP header"
top = b""
while True:
    ln = f.readline()
    if ln == b".\r\n":
        break
    top += ln
assert b"Subject: two" in top and b"second" in top and b"body" not in top, top

# DELE / RSET / double-DELE
assert send("DELE 2") == "+OK message deleted"
assert send("DELE 2").startswith("-ERR")
assert send("RSET") == "+OK"
assert send("DELE 2") == "+OK message deleted"
assert send("DELE 3") == "+OK message deleted"
assert send("STAT").startswith("+OK 1 "), "STAT after DELEs"
assert send("QUIT") == "+OK bye"
s.close()

# reconnect: messages 2 and 3 expunged, only 1 remains
s = socket.create_connection(("127.0.0.1", port), timeout=10)
f = s.makefile("rb")
f.readline()
send("USER alice")
send("PASS waldorf")
st = send("STAT")
assert st.startswith("+OK 1 "), st
send("QUIT")
s.close()
PYEOF

# ---- (2) RFC 2595 gating on a non-loopback bind + STLS round-trip ----
python3 - "$POP3_B" <<'PYEOF' && pass "pop3: non-loopback gates cleartext USER/PASS until STLS" \
                           || fail "pop3: non-loopback gates cleartext USER/PASS until STLS"
import socket, ssl, sys

port = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", port), timeout=10)
f = s.makefile("rb")
assert f.readline().decode().startswith("+OK")

s.sendall(b"USER alice\r\n")
line = f.readline().decode()
assert "-ERR" in line and "STLS" in line, line
s.sendall(b"PASS waldorf\r\n")
assert "-ERR" in f.readline().decode()

s.sendall(b"STLS\r\n")
line = f.readline().decode()
assert line.startswith("+OK Begin TLS negotiation"), line

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
tls = ctx.wrap_socket(s)
tf = tls.makefile("rwb")

def tsend(cmd):
    tls.sendall((cmd + "\r\n").encode())
    return tf.readline().decode().strip()

assert tsend("USER alice") == "+OK"
assert tsend("PASS waldorf").startswith("+OK")
assert tsend("STAT").startswith("+OK 3 "), tsend("STAT")
assert tsend("QUIT") == "+OK bye"
PYEOF

printf '\n'
if [ "$FAILS" -gt 0 ]; then
    printf '%d checks failed\n' "$FAILS"
    exit 1
fi
printf 'pop3d_tls: OK\n'
