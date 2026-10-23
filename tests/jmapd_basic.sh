#!/usr/bin/env bash
# jmapd_basic.sh — live HTTP tests for jmapd (M1: session document, Mailbox/get,
# Identity/get, auth, lockout, keep-alive, the request caps, and that
# authentication is per REQUEST rather than per connection).
#
# REQUIRES live sockets; run on the host via `dhake e2e` or directly.  Three
# throwaway daemons against one throwaway maildir root:
#   A  main instance      session document, Mailbox/get, Identity/get, the
#                         method-call loop, keep-alive, 404/405/501
#   B  lockout instance   a separate per-IP failure table, so the lockout test
#                         cannot poison A's connections
#   C  small-cap instance --max-request 4096, for the 413
#   E  proxy-fronted instance --public-url https://jmap.example.test, for the
#      advertised-base override (the Caddy arrangement: plaintext listener,
#      https URLs in the session document)
#
# The passwd file is written directly (same format `imapd passwd` writes) so
# this script depends only on jmapd.com, not on imapd.com.
#
# Ports/paths are parametrized via env: JMAPD_PORT_BASE (default 18081).
set -euo pipefail

cd "$(dirname "$0")/.."

PORT_BASE="${JMAPD_PORT_BASE:-18081}"
PORT_A="$PORT_BASE"
PORT_B=$((PORT_BASE + 1))
PORT_C=$((PORT_BASE + 2))
PORT_D=$((PORT_BASE + 3))
PORT_E=$((PORT_BASE + 4))
CERT=tests/visage-test-cert.pem
KEY=tests/visage-test-key.pem

if [ ! -x ./jmapd.com ]; then
    echo "FAIL jmapd.com is not built (run: dhake jmapd.com)" >&2
    exit 1
fi

TMP="$(mktemp -d /tmp/jmapd_basic_XXXXXX)"
ROOT="$TMP/root"
mkdir -p "$ROOT"
printf 'alice:waldorf\n' > "$ROOT/imapd.passwd"
chmod 600 "$ROOT/imapd.passwd"

# ---- seed alice's INBOX: 3 messages, 2 unseen (new/ + cur/ without \Seen) ----
mkdir -p "$ROOT/alice/Inbox/tmp" "$ROOT/alice/Inbox/new" "$ROOT/alice/Inbox/cur"
seed_msg() {   # seed_msg SUBJECT
    printf 'From: sender@example.com\r\nTo: alice@127.0.0.1\r\nSubject: %s\r\nMessage-ID: <%s@example.com>\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\n\r\nbody of %s\r\n' \
        "$1" "$1" "$1"
}
seed_msg one   > "$ROOT/alice/Inbox/new/1700000000.M1P1.seed"
seed_msg two   > "$ROOT/alice/Inbox/cur/1700000001.M2P2.seed"
seed_msg three > "$ROOT/alice/Inbox/cur/1700000002.M3P3.seed:2,S"

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

start_daemon() {   # start_daemon LOG EXTRA_ARGS...
    local log="$1"; shift
    ./jmapd.com --root "$ROOT" --addr 127.0.0.1 "$@" \
        >"$log" 2>&1 &
    DAEMONS+=("$!")
}

start_daemon "$TMP/a.log" --port "$PORT_A"
start_daemon "$TMP/b.log" --port "$PORT_B"
start_daemon "$TMP/c.log" --port "$PORT_C" --max-request 4096
start_daemon "$TMP/d.log" --port "$PORT_D" --cert "$CERT" --key "$KEY"
start_daemon "$TMP/e.log" --port "$PORT_E" --public-url https://jmap.example.test

wait_port "$PORT_A" "jmapd A"
wait_port "$PORT_B" "jmapd B"
wait_port "$PORT_C" "jmapd C"
wait_port "$PORT_D" "jmapd D"
wait_port "$PORT_E" "jmapd E"

AUTH="alice:waldorf"
BASE_A="http://127.0.0.1:$PORT_A"

# ---- (1) the session document, Mailbox/get and Identity/get, over one
#         connection-reusing client (python urllib keeps no connection, but the
#         assertions are about the document, not the socket) ----
python3 - "$PORT_A" <<'PYEOF' && pass "session document + Mailbox/get + Identity/get" \
                           || fail "session document + Mailbox/get + Identity/get"
import base64, json, sys, urllib.request

port = int(sys.argv[1])
base = f"http://localhost:{port}"
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"
SUB = "urn:ietf:params:jmap:submission"


def call(path, payload=None):
    req = urllib.request.Request(base + path, data=payload)
    req.add_header("Authorization", auth)
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, json.loads(r.read())


# --- session ---
st, sess = call("/.well-known/jmap")
assert st == 200, st
for key in ("apiUrl", "uploadUrl", "downloadUrl", "eventSourceUrl"):
    u = sess[key]
    assert "://" in u, (key, u)
    # the session_url was http on loopback, so every advertised URL must be
    # absolute, http, and on the loopback host: a mismatch here is exactly the
    # silent TLS downgrade the mail-hub client refuses.
    assert u.startswith(f"http://localhost:{port}/"), (key, u)
    assert not u.startswith("https://"), (key, u)
assert sess["apiUrl"] == f"{base}/api", sess["apiUrl"]
assert "{accountId}" in sess["downloadUrl"] and "{blobId}" in sess["downloadUrl"]
assert sess["primaryAccounts"][MAIL] == "alice", sess["primaryAccounts"]
assert sess["username"] == "alice"
for cap in (CORE, MAIL, SUB):
    assert cap in sess["capabilities"], cap
assert MAIL in sess["accounts"]["alice"]["accountCapabilities"]
assert "state" in sess

# the same resource is reachable at /jmap/session
st2, sess2 = call("/jmap/session")
assert st2 == 200 and sess2["apiUrl"] == sess["apiUrl"]

# --- Mailbox/get (two calls in one request: the loop and the callId echo) ---
body = json.dumps({"using": [CORE, MAIL, SUB], "methodCalls": [
    ["Mailbox/get", {"accountId": "alice"}, "a"],
    ["Identity/get", {"accountId": "alice"}, "b"],
]}).encode()
st, resp = call("/api", body)
assert st == 200, st
mr = resp["methodResponses"]
assert len(mr) == 2, mr
assert mr[0][0] == "Mailbox/get" and mr[0][2] == "a", mr[0]
assert mr[1][0] == "Identity/get" and mr[1][2] == "b", mr[1]

res = mr[0][1]
assert res["accountId"] == "alice"
assert res["state"] == "m0", res["state"]
by_name = {m["name"]: m for m in res["list"]}
inbox = by_name["Inbox"]
assert inbox["role"] == "inbox", inbox
# 3 seeded messages, one carrying ":2,S"
assert inbox["totalEmails"] == 3, inbox["totalEmails"]
assert inbox["unreadEmails"] == 2, inbox["unreadEmails"]
for role, name in (("sent", "Sent"), ("drafts", "Drafts"), ("trash", "Trash"),
                   ("junk", "Junk"), ("archive", "Archive")):
    assert name in by_name, name
    assert by_name[name]["role"] == role, (name, by_name[name]["role"])
    assert by_name[name]["totalEmails"] == 0, by_name[name]
assert all(m["id"].startswith("m") for m in res["list"])
assert res["notFound"] == []
ids = {m["name"]: m["id"] for m in res["list"]}
assert len(set(ids.values())) == len(ids), "mailbox ids must be unique"

# --- Mailbox/get with an ids filter: one hit, one notFound ---
body = json.dumps({"using": [CORE, MAIL], "methodCalls": [
    ["Mailbox/get", {"accountId": "alice", "ids": [ids["Inbox"], "mAAAA"]}, "c"],
]}).encode()
st, resp = call("/api", body)
res = resp["methodResponses"][0][1]
assert [m["name"] for m in res["list"]] == ["Inbox"], res["list"]
assert res["notFound"] == ["mAAAA"], res["notFound"]

# --- Identity/get ---
ident = mr[1][1]
assert ident["accountId"] == "alice"
assert len(ident["list"]) == 1, ident
idn = ident["list"][0]
assert idn["email"] == "alice@localhost", idn
assert idn["id"].startswith("i"), idn["id"]
PYEOF

# ---- (2) authentication: 401 on a wrong password, with the challenge header ----
code=$(curl -s -o "$TMP/bad.json" -D "$TMP/bad.hdr" -w '%{http_code}' \
    -u alice:wrong "$BASE_A/.well-known/jmap")
if [ "$code" = 401 ] && grep -qi '^www-authenticate: basic' "$TMP/bad.hdr" &&
   grep -q '"unauthorized"' "$TMP/bad.json"; then
    pass "wrong password: 401 + Basic challenge"
else
    fail "wrong password: 401 + Basic challenge (got $code)"
fi

code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE_A/.well-known/jmap")
check "$([ "$code" = 401 ] && echo 0 || echo 1)" "no credentials: 401"

# Bearer auth uses the passwd password as the token
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer waldorf' \
    "$BASE_A/.well-known/jmap")
check "$([ "$code" = 200 ] && echo 0 || echo 1)" "Bearer token authenticates"

# ---- (3) routing: 404 unknown path, 405 wrong method, 501 unimplemented ----
code=$(curl -s -o /dev/null -w '%{http_code}' -u "$AUTH" "$BASE_A/nope")
check "$([ "$code" = 404 ] && echo 0 || echo 1)" "unknown path: 404"

code=$(curl -s -o /dev/null -w '%{http_code}' -u "$AUTH" -d '{}' "$BASE_A/.well-known/jmap")
check "$([ "$code" = 405 ] && echo 0 || echo 1)" "POST on the session route: 405"

code=$(curl -s -o /dev/null -w '%{http_code}' -u "$AUTH" "$BASE_A/api")
check "$([ "$code" = 405 ] && echo 0 || echo 1)" "GET /api: 405"

code=$(curl -s -o /dev/null -w '%{http_code}' -u "$AUTH" "$BASE_A/download/x/y/z")
check "$([ "$code" = 404 ] && echo 0 || echo 1)" \
    "download with an unparseable blob id: 404 before any open"

code=$(curl -s -o /dev/null -w '%{http_code}' -u "$AUTH" "$BASE_A/event/")
check "$([ "$code" = 501 ] && echo 0 || echo 1)" "EventSource (v1 cut): 501"

# ---- (4) request-level errors: notJSON / unknownCapability / unknownMethod ----
api_code() {   # api_code BODY -> prints "STATUS TYPE"
    local body="$1"
    curl -s -o "$TMP/api.json" -w '%{http_code}' -u "$AUTH" \
        -H 'Content-Type: application/json' -d "$body" "$BASE_A/api" >"$TMP/code"
    printf '%s %s' "$(cat "$TMP/code")" \
        "$(sed -n 's/.*"type":"\([a-zA-Z]*\)".*/\1/p' "$TMP/api.json")"
}
out=$(api_code 'not json at all')
check "$([ "$out" = "400 notJSON" ] && echo 0 || echo 1)" "invalid JSON body: 400 notJSON"

out=$(api_code '{"using":["urn:ietf:params:jmap:nope"],"methodCalls":[]}')
check "$([ "$out" = "400 unknownCapability" ] && echo 0 || echo 1)" \
    "unadvertised capability: 400 unknownCapability"

# M3 added Email/changes (it answers cannotCalculateChanges), so the
# unknownMethod probe names a method v1 does not implement at all.
out=$(api_code '{"using":["urn:ietf:params:jmap:core"],"methodCalls":[["Mailbox/set",{},"x"]]}')
check "$([ "$out" = "400 unknownMethod" ] && echo 0 || echo 1)" \
    "method not implemented: 400 unknownMethod"

# ---- (5) keep-alive: two requests on ONE connection, then a pipelined tail ----
python3 - "$PORT_A" <<'PYEOF' && pass "keep-alive: two requests on one connection" \
                           || fail "keep-alive: two requests on one connection"
import base64, socket, sys

port = int(sys.argv[1])
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
s = socket.create_connection(("127.0.0.1", port), timeout=10)


def request(path):
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nAuthorization: {auth}\r\n\r\n".encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        assert chunk, "server closed early"
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    assert lines[0].startswith(b"HTTP/1.1 200"), lines[0]
    clen = 0
    for line in lines[1:]:
        if line.lower().startswith(b"content-length:"):
            clen = int(line.split(b":", 1)[1])
    while len(rest) < clen:
        rest += s.recv(4096)
    return lines, rest[:clen]


h1, b1 = request("/.well-known/jmap")
assert any(b"keep-alive" in l.lower() for l in h1), h1
h2, b2 = request("/.well-known/jmap")
assert b"apiUrl" in b2
assert b"apiUrl" in b1
s.close()

# a pipelined second request in the SAME write is refused (400), not answered
# as part of the first: tail bytes must never leak into the next request.
s = socket.create_connection(("127.0.0.1", port), timeout=10)
s.sendall((f"GET /.well-known/jmap HTTP/1.1\r\nHost: x\r\nAuthorization: {auth}\r\n\r\n"
           f"GET /.well-known/jmap HTTP/1.1\r\nHost: x\r\nAuthorization: {auth}\r\n\r\n").encode())
head = b""
while b"\r\n" not in head:
    head += s.recv(4096)
assert head.startswith(b"HTTP/1.1 400"), head[:64]
s.close()
PYEOF

# ---- (5b) authentication is PER REQUEST, not per connection ----
# A keep-alive connection is not a principal: behind the TLS-terminating proxy
# (deploy/Caddyfile.jmap) Caddy pools upstream connections, so the next
# request on a reused connection can come from a different, unauthenticated
# client.  Each block below authenticates once on a connection and then sends
# a request with NO credentials on the SAME connection; it must be 401.  A
# connection-cached principal answers 200 with the session document (measured
# on the deployed daemon before this fix).
python3 - "$PORT_A" <<'PYEOF' && pass "auth is per request, not per connection (session, POST /api, download)" \
                           || fail "auth is per request, not per connection (session, POST /api, download)"
import base64, json, socket, sys

port = int(sys.argv[1])
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
API = '{"using":["urn:ietf:params:jmap:core"],"methodCalls":[]}'


def connect():
    return socket.create_connection(("127.0.0.1", port), timeout=10)


def send(s, method, path, authorization=None, body=None):
    head = f"{method} {path} HTTP/1.1\r\nHost: x\r\n"
    if authorization:
        head += f"Authorization: {authorization}\r\n"
    if body is not None:
        head += ("Content-Type: application/json\r\n"
                 f"Content-Length: {len(body)}\r\n")
    head += "\r\n"
    s.sendall(head.encode() + (body.encode() if body else b""))


def response(s):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        assert chunk, "server closed before the response head"
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1])
    clen = 0
    for line in lines[1:]:
        if line.lower().startswith(b"content-length:"):
            clen = int(line.split(b":", 1)[1])
    while len(rest) < clen:
        chunk = s.recv(4096)
        assert chunk, "server closed mid-body"
        rest += chunk
    return status, [l.lower() for l in lines[1:]], rest[:clen]


# (a) GET session: authenticated, then the SAME connection with no credential.
s = connect()
send(s, "GET", "/.well-known/jmap", auth)
st, _, body = response(s)
assert st == 200 and b"apiUrl" in body, (st, body[:80])
send(s, "GET", "/.well-known/jmap")
st, hdr, body = response(s)
assert st == 401, ("no-credential session GET on an authenticated connection",
                   st, body[:120])
assert b"apiUrl" not in body, body[:200]      # not one byte of the document
assert any(l.startswith(b"connection: close") for l in hdr), hdr
# a 401 closes the connection, so the next request cannot inherit anything
assert s.recv(4096) == b"", "expected the connection to close after a 401"
s.close()

# (b) POST /api: authenticated, then no credential on the same connection.
s = connect()
send(s, "POST", "/api", auth, API)
st, _, body = response(s)
assert st == 200 and b"methodResponses" in body, (st, body[:120])
send(s, "POST", "/api", None, API)
st, _, body = response(s)
assert st == 401, ("no-credential POST /api on an authenticated connection",
                   st, body[:120])
assert b"methodResponses" not in body, body[:200]
s.close()

# (c) the download route: this is where a borrowed principal is most direct
#     (bytes of a message part), so the assertion is about the bytes, not just
#     a status.  A real blob id is fetched first; the authenticated download
#     keeps the connection alive, and the SAME connection then asks for the
#     same blob with no credential.
s = connect()
send(s, "POST", "/api", auth, json.dumps({
    "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
    "methodCalls": [
        ["Email/query", {"accountId": "alice"}, "q"],
        ["Email/get", {"accountId": "alice",
                       "#ids": {"resultOf": "q", "name": "Email/query",
                                "path": "/ids"},
                       "properties": ["id", "textBody"]}, "g"],
    ]}))
st, _, body = response(s)
assert st == 200, (st, body[:120])
blob = json.loads(body)["methodResponses"][1][1]["list"][0]["textBody"][0]["blobId"]
s.close()
assert blob.startswith("g"), blob

s = connect()
send(s, "GET", f"/download/alice/{blob}/body.txt", auth)
st, _, first = response(s)
assert st == 200 and first, (st, first[:80])
send(s, "GET", f"/download/alice/{blob}/body.txt")
st, _, body = response(s)
assert st == 401, ("no-credential download on an authenticated connection",
                   st, body[:120])
assert body != first, "the message part's bytes must not be served"
s.close()

# (d) the fix must not degrade into one-shot credentials: an authenticated
#     connection keeps serving, and a fresh connection still refuses.
s = connect()
for _ in range(3):
    send(s, "GET", "/.well-known/jmap", auth)
    st, _, body = response(s)
    assert st == 200 and b"apiUrl" in body, (st,)
s.close()
s = connect()
send(s, "GET", "/.well-known/jmap")
st, _, _ = response(s)
assert st == 401, ("no credential on a fresh connection", st)
s.close()
PYEOF

# ---- (6) the request cap: an over-cap POST is 413, not a buffered 8 KiB ----
head -c 8192 /dev/zero | tr '\0' 'x' > "$TMP/big.txt"
code=$(curl -s -o /dev/null -w '%{http_code}' -u "$AUTH" \
    -H 'Content-Type: application/json' --data-binary "@$TMP/big.txt" \
    "http://127.0.0.1:$PORT_C/api")
check "$([ "$code" = 413 ] && echo 0 || echo 1)" "over-cap request: 413"

# ---- (7) per-IP lockout (own daemon: its failure table is independent) ----
locked=1
for _ in 1 2 3 4 5; do
    curl -s -o /dev/null -u alice:wrong "http://127.0.0.1:$PORT_B/.well-known/jmap" || true
done
code=$(curl -s -o /dev/null -w '%{http_code}' -u alice:waldorf \
    "http://127.0.0.1:$PORT_B/.well-known/jmap")
if [ "$code" = 401 ]; then locked=0; fi
check "$locked" "lockout: the correct password is refused after 5 failures"
if grep -q 'jmapd auth-blocked' "$TMP/b.log"; then
    pass "lockout: the blocked attempt is logged"
else
    fail "lockout: the blocked attempt is logged"
fi

# ---- (8) HTTPS from the FIRST BYTE: no STARTTLS, no plaintext phase ----
python3 - "$PORT_D" <<'PYEOF' && pass "TLS: https from the first byte, plaintext refused" \
                           || fail "TLS: https from the first byte, plaintext refused"
import base64, json, socket, ssl, sys

port = int(sys.argv[1])
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# a plaintext HTTP request on the TLS listener must not be answered in clear
s = socket.create_connection(("127.0.0.1", port), timeout=10)
s.sendall(b"GET /.well-known/jmap HTTP/1.1\r\nHost: x\r\n\r\n")
try:
    reply = s.recv(4096)
except OSError:
    reply = b""
s.close()
assert not reply.startswith(b"HTTP/"), reply[:40]

# the real request: TLS from the first byte, and the document says https
raw = socket.create_connection(("127.0.0.1", port), timeout=10)
tls = ctx.wrap_socket(raw)
tls.sendall((f"GET /.well-known/jmap HTTP/1.1\r\nHost: x\r\n"
             f"Authorization: {auth}\r\n\r\n").encode())
buf = b""
while b"\r\n\r\n" not in buf:
    chunk = tls.recv(4096)
    assert chunk, "server closed early"
    buf += chunk
head, rest = buf.split(b"\r\n\r\n", 1)
assert head.startswith(b"HTTP/1.1 200"), head[:40]
clen = 0
for line in head.split(b"\r\n")[1:]:
    if line.lower().startswith(b"content-length:"):
        clen = int(line.split(b":", 1)[1])
while len(rest) < clen:
    rest += tls.recv(4096)
sess = json.loads(rest[:clen])
assert sess["apiUrl"] == f"https://localhost:{port}/api", sess["apiUrl"]
for key in ("uploadUrl", "downloadUrl", "eventSourceUrl"):
    assert sess[key].startswith("https://"), (key, sess[key])
tls.close()
PYEOF

# ---- (9) --public-url: the session document advertises the proxy's base ----
python3 - "$PORT_E" <<'PYEOF' && pass "--public-url: the advertised base is the override" \
                           || fail "--public-url: the advertised base is the override"
import base64, json, sys, urllib.request

port = int(sys.argv[1])
base = f"http://127.0.0.1:{port}"
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
req = urllib.request.Request(base + "/.well-known/jmap")
req.add_header("Authorization", auth)
with urllib.request.urlopen(req, timeout=10) as r:
    assert r.status == 200, r.status
    sess = json.loads(r.read())

# The listener is plaintext on 127.0.0.1:<port>, but the client is told what
# it can actually reach: the https base the proxy publishes.  A document that
# advertises the listener instead is exactly the silent downgrade the client
# refuses.
assert sess["apiUrl"] == "https://jmap.example.test/api", sess["apiUrl"]
assert sess["uploadUrl"] == "https://jmap.example.test/upload/{accountId}/", sess["uploadUrl"]
assert sess["eventSourceUrl"] == "https://jmap.example.test/event/", sess["eventSourceUrl"]
assert sess["downloadUrl"] == ("https://jmap.example.test/download/"
                               "{accountId}/{blobId}/{name}?accept={type}"), sess["downloadUrl"]
# the download template must still be a template: the client substitutes these
for ph in ("{accountId}", "{blobId}", "{name}"):
    assert ph in sess["downloadUrl"], (ph, sess["downloadUrl"])
for key in ("apiUrl", "uploadUrl", "downloadUrl", "eventSourceUrl"):
    u = sess[key]
    assert "127.0.0.1" not in u and f":{port}" not in u, (key, u)
    assert not u.startswith("http://"), (key, u)
PYEOF

# the same override must refuse a plaintext base URL on a network bind: the
# client would be told to send the password in clear
if ./jmapd.com --root "$ROOT" --addr 0.0.0.0 --cert "$CERT" --key "$KEY" \
        --public-url http://jmap.example.test --port "$PORT_C" \
        >"$TMP/pubrefuse.log" 2>&1; then
    fail "http public-url on a non-loopback bind must exit nonzero"
elif grep -q -- '--public-url' "$TMP/pubrefuse.log"; then
    pass "http public-url on a non-loopback bind is refused, naming the flag"
else
    fail "http public-url refusal does not name --public-url"
fi

# ---- (10) a non-loopback bind without TLS must refuse to start ----
if ./jmapd.com --root "$ROOT" --addr 0.0.0.0 --port "$PORT_C" \
        >"$TMP/refuse.log" 2>&1; then
    fail "non-loopback bind without TLS must exit nonzero"
else
    pass "non-loopback bind without TLS exits nonzero (fail-closed)"
fi

echo
if [ "$FAILS" = 0 ]; then
    echo "jmapd_basic: all checks passed"
    exit 0
fi
echo "jmapd_basic: $FAILS check(s) failed"
exit 1
