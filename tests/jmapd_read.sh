#!/usr/bin/env bash
# jmapd_read.sh — live tests for jmapd's M2 read path: the MIME walker behind
# Email/get, Email/query, the #ids back-reference and the blob download.
#
# The maildir is seeded by dropping files straight into the layout (new/, cur/
# with ":2,S" flags, .Sent) — no imapd involved, so this script depends only on
# jmapd.com.  The assertions that matter most are the ones that would catch a
# SILENT-WRONG implementation:
#
#   * bodyValues for text/plain, text/html and the attachment are DISTINCT and
#     each equals its own decoded body (a walker that served the wrong part
#     would return the other one's bytes);
#   * the download bytes equal the base64-DECODED part and are NOT the raw
#     file slice (a download that forgot to decode is the classic bug);
#   * query ordering/total are exact, and position/limit page exactly;
#   * #ids resolves inside one request (the shape the mail-hub client sends);
#   * a property the server does not have is absent from the response;
#   * traversal blob ids are 404 before any open(2);
#   * a 12 MiB part is served truncated-and-flagged, not OOM.
#
# Ports are parametrized via env: JMAPD_PORT_BASE (default 18091).
set -euo pipefail

cd "$(dirname "$0")/.."

PORT_BASE="${JMAPD_PORT_BASE:-18091}"
PORT_A="$PORT_BASE"

if [ ! -x ./jmapd.com ]; then
    echo "FAIL jmapd.com is not built (run: dhake jmapd.com)" >&2
    exit 1
fi

TMP="$(mktemp -d /tmp/jmapd_read_XXXXXX)"
ROOT="$TMP/root"
mkdir -p "$ROOT"
printf 'alice:waldorf\n' > "$ROOT/imapd.passwd"
chmod 600 "$ROOT/imapd.passwd"

mkdir -p "$ROOT/alice/Inbox/tmp" "$ROOT/alice/Inbox/new" "$ROOT/alice/Inbox/cur"
mkdir -p "$ROOT/alice/.Sent/tmp" "$ROOT/alice/.Sent/new" "$ROOT/alice/.Sent/cur"
mkdir -p "$ROOT/alice/.Drafts/tmp" "$ROOT/alice/.Drafts/new" "$ROOT/alice/.Drafts/cur"

# ---- A: multipart/mixed -> multipart/alternative + a base64 pdf attachment ---
cat > "$ROOT/alice/Inbox/cur/1700000100.A.host:2,S" <<'MSGEOF'
From: Alice <alice@example.com>
To: Bob <bob@example.com>
Cc: carol@example.com, Dave <dave@example.com>
Subject: Café report
Message-ID: <a1@example.com>
Date: Mon, 1 Jan 2024 00:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="OUTER"

preamble text
--OUTER
Content-Type: multipart/alternative; boundary="INNER"

--INNER
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

Caf=C3=A9 line one
second line
--INNER
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: base64

PGh0bWw+PGJvZHk+Q2Fmw6k8L2JvZHk+PC9odG1sPg==
--INNER--
--OUTER
Content-Type: application/pdf; name="report.pdf"
Content-Disposition: attachment; filename="report.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQK
--OUTER--
MSGEOF

# ---- B: a plain message in new/ (unseen, no \Seen flag) ----
printf 'From: bob@example.com\r\nTo: alice@example.com\r\nSubject: plain one\r\nMessage-ID: <b1@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nplain body line\r\n' \
    > "$ROOT/alice/Inbox/new/1700000200.B.host"

# ---- C: quoted-printable text, older than A ----
printf 'From: carol@example.com\r\nTo: alice@example.com\r\nSubject: qp one\r\nMessage-ID: <c1@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nqp=20body=20line\r\n' \
    > "$ROOT/alice/Inbox/cur/1700000050.C.host:2,S"

# ---- D: one message in Sent ----
printf 'From: alice@example.com\r\nTo: zoe@example.com\r\nSubject: sent one\r\nMessage-ID: <d1@example.com>\r\nContent-Type: text/plain\r\n\r\nsent body\r\n' \
    > "$ROOT/alice/.Sent/cur/1700000300.D.host:2,S"

# ---- E: a 12 MiB text part (the bounded-response path) ----
{
    printf 'From: big@example.com\r\nTo: alice@example.com\r\nSubject: big one\r\nMessage-ID: <e1@example.com>\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n'
    head -c 12582912 /dev/zero | tr '\0' 'a'
    printf '\r\n'
} > "$ROOT/alice/Inbox/cur/1700000400.E.host:2,S"

# ---- F: 8-bit bytes that are NOT UTF-8, in the Subject and in the body ----
# An ISO-8859-1 header and a raw 8-bit body, both of which jmapd copies through
# verbatim (charset conversion is out of scope).  Seeded in its OWN mailbox so
# the Inbox assertions above keep their exact counts.
mkdir -p "$ROOT/alice/.Odd/tmp" "$ROOT/alice/.Odd/new" "$ROOT/alice/.Odd/cur"
printf 'From: bob@example.com\r\nTo: alice@example.com\r\nSubject: bad \xae byte\r\nMessage-ID: <f1@example.com>\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nbody \xae and \xff here\r\n' \
    > "$ROOT/alice/.Odd/cur/1700000500.F.host:2,S"

# ---- G/H: two SMALL bodies, for the "a reduced limit that cut nothing" case
# (rendered under a tiny --get-body-budget by the daemon in section 5b)
mkdir -p "$ROOT/alice/.Mid/tmp" "$ROOT/alice/.Mid/new" "$ROOT/alice/.Mid/cur"
{
    printf 'From: mid@example.com\r\nTo: alice@example.com\r\nSubject: mid one\r\nMessage-ID: <g1@example.com>\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n'
    head -c 300 /dev/zero | tr '\0' 'm'
    printf '\r\n'
} > "$ROOT/alice/.Mid/cur/1700000600.G.host:2,S"
printf 'From: mid@example.com\r\nTo: alice@example.com\r\nSubject: mid two\r\nMessage-ID: <h1@example.com>\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\ntiny body\r\n' \
    > "$ROOT/alice/.Mid/cur/1700000601.H.host:2,S"

# fixed mtimes so receivedAt ordering is deterministic (maildir INTERNALDATE)
touch -d @1700000100 "$ROOT/alice/Inbox/cur/1700000100.A.host:2,S"
touch -d @1700000200 "$ROOT/alice/Inbox/new/1700000200.B.host"
touch -d @1700000050 "$ROOT/alice/Inbox/cur/1700000050.C.host:2,S"
touch -d @1700000300 "$ROOT/alice/.Sent/cur/1700000300.D.host:2,S"
touch -d @1700000400 "$ROOT/alice/Inbox/cur/1700000400.E.host:2,S"
touch -d @1700000500 "$ROOT/alice/.Odd/cur/1700000500.F.host:2,S"
touch -d @1700000600 "$ROOT/alice/.Mid/cur/1700000600.G.host:2,S"
touch -d @1700000601 "$ROOT/alice/.Mid/cur/1700000601.H.host:2,S"

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

wait_port() {
    local i=0
    until (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; do
        i=$((i + 1))
        if [ "$i" -gt 100 ]; then fail "$2 did not come up"; exit 1; fi
        sleep 0.1
    done
}

./jmapd.com --root "$ROOT" --addr 127.0.0.1 --port "$PORT_A" \
    --hostname localhost >"$TMP/a.log" 2>&1 &
DAEMONS+=("$!")
wait_port "$PORT_A" "jmapd"

AUTH="alice:waldorf"
BASE="http://127.0.0.1:$PORT_A"

# ======================================================================
# (1) query + get + back-reference + download, all over live sockets
# ======================================================================
python3 - "$PORT_A" <<'PYEOF' && pass "read path: query, get, bodyValues, download, back-references" \
                           || fail "read path: query, get, bodyValues, download, back-references"
import base64, json, sys, urllib.error, urllib.request

port = int(sys.argv[1])
base = f"http://127.0.0.1:{port}"
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"
SUB = "urn:ietf:params:jmap:submission"


def call(payload, path="/api"):
    req = urllib.request.Request(base + path, data=json.dumps(payload).encode())
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.status, json.loads(r.read())


def http_get(path, expect=200, headers=True):
    req = urllib.request.Request(base + path)
    req.add_header("Authorization", auth)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


# --- the mailbox id for Inbox ---
st, resp = call({"using": [CORE, MAIL], "methodCalls": [
    ["Mailbox/get", {"accountId": "alice"}, "m0"]]})
inbox = [m for m in resp["methodResponses"][0][1]["list"] if m["name"] == "Inbox"][0]
inbox_id = inbox["id"]

# --- Email/query: ordering, total, paging ---
PROPS = ["id", "threadId", "receivedAt", "from", "to", "cc", "subject",
         "preview", "keywords", "hasAttachment", "size", "mailboxIds",
         "textBody", "htmlBody", "attachments", "messageId"]

st, resp = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice",
                     "filter": {"inMailbox": inbox_id},
                     "sort": [{"property": "receivedAt", "isAscending": False}],
                     "position": 0, "limit": 10}, "q0"]]})
q = resp["methodResponses"][0][1]
assert q["total"] == 4, q          # A, B, C, E (not D, which is in Sent)
assert q["position"] == 0, q
assert len(q["ids"]) == 4, q
assert q["canCalculateChanges"] is False, q
assert q["queryState"].startswith("e"), q

# desc: E (1700000400) > B (1700000200) > A (1700000100) > C (1700000050)
desc_ids = q["ids"]

st, resp = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice",
                     "filter": {"inMailbox": inbox_id},
                     "sort": [{"property": "receivedAt", "isAscending": True}],
                     "position": 0, "limit": 10}, "q0"]]})
asc_ids = resp["methodResponses"][0][1]["ids"]
assert asc_ids == list(reversed(desc_ids)), (asc_ids, desc_ids)

# paging: position 1 limit 2 == desc_ids[1:3]
st, resp = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice",
                     "filter": {"inMailbox": inbox_id},
                     "sort": [{"property": "receivedAt", "isAscending": False}],
                     "position": 1, "limit": 2}, "q0"]]})
page = resp["methodResponses"][0][1]
assert page["ids"] == desc_ids[1:3], page
assert page["total"] == 4, page

# filters
for filt, want in (({"inMailbox": inbox_id, "from": "carol"}, 1),
                   ({"inMailbox": inbox_id, "subject": "plain one"}, 1),
                   ({"inMailbox": inbox_id, "text": "second line"}, 1),
                   ({"inMailbox": inbox_id, "text": "nobody-nowhere"}, 0)):
    st, resp = call({"using": [CORE, MAIL], "methodCalls": [
        ["Email/query", {"filter": filt}, "q0"]]})
    got = resp["methodResponses"][0][1]["total"]
    assert got == want, (filt, got, want)

# --- KEYWORD filters: "which messages in THIS mailbox are unread" ---
# B is the only message in new/ (no \Seen flag), so Inbox is 4 messages of
# which exactly 1 is unread.  This is the bulk-action question ("mark all
# read"), and it must be answered without paging the mailbox.
st, resp = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice",
                     "filter": {"inMailbox": inbox_id, "notKeyword": "$seen"},
                     "sort": [{"property": "receivedAt", "isAscending": False}],
                     "limit": 50}, "q0"]]})
unread = resp["methodResponses"][0][1]
assert "type" not in unread, unread
assert unread["total"] == 1, unread
assert len(unread["ids"]) == 1, unread

st, resp = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice",
                     "filter": {"inMailbox": inbox_id, "keyword": "$seen"},
                     "limit": 50}, "q0"]]})
seen = resp["methodResponses"][0][1]
assert "type" not in seen, seen
assert seen["total"] == 3, seen
assert len(seen["ids"]) == 3, seen
# the two answers PARTITION the mailbox: no id is in both, none is missing
assert set(unread["ids"]).isdisjoint(seen["ids"]), (unread, seen)
assert set(unread["ids"]) | set(seen["ids"]) == set(desc_ids), (unread, seen,
                                                                desc_ids)

# an unknown keyword is a DESCRIBED refusal, never an empty result set
for bad in ({"inMailbox": inbox_id, "keyword": "$forwarded"},
            {"inMailbox": inbox_id, "notKeyword": "$no-such-keyword"},
            {"inMailbox": inbox_id, "keyword": True}):
    st, resp = call({"using": [CORE, MAIL], "methodCalls": [
        ["Email/query", {"filter": bad}, "q0"]]})
    res = resp["methodResponses"][0][1]
    assert res.get("type") == "unsupportedFilter", (bad, res)
    assert res.get("description"), (bad, res)
    assert "ids" not in res and "total" not in res, (bad, res)

# an unsupported sort is a method error, not a silently different order
st, resp = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"sort": [{"property": "subject"}]}, "q0"]]})
assert resp["methodResponses"][0][1].get("type") == "unsupportedSort", resp

# --- Email/get with the #ids BACK-REFERENCE, in ONE request (client shape) ---
st, resp = call({"using": [CORE, MAIL, SUB], "methodCalls": [
    ["Email/query", {"accountId": "alice",
                     "filter": {"inMailbox": inbox_id},
                     "sort": [{"property": "receivedAt", "isAscending": False}],
                     "position": 0, "limit": 3}, "q0"],
    ["Email/get", {"accountId": "alice",
                   "#ids": {"resultOf": "q0", "name": "Email/query",
                            "path": "/ids"},
                   "properties": PROPS,
                   "fetchTextBodyValues": True, "fetchHTMLBodyValues": True,
                   "maxBodyValueBytes": 1048576}, "g0"]]})
assert len(resp["methodResponses"]) == 2, resp
gres = resp["methodResponses"][1][1]
assert "type" not in gres, gres
assert len(gres["list"]) == 3, gres
by_id = {e["id"]: e for e in gres["list"]}
assert set(by_id) == set(desc_ids[:3]), (set(by_id), desc_ids[:3])

# --- the fixture message: every property the client reads ---
fixture = by_id[desc_ids[2]]          # A is third-newest (E, B, A, C)
assert fixture["subject"] == "Café report", fixture["subject"]
assert fixture["preview"] == "Café line one", fixture["preview"]
assert fixture["receivedAt"].endswith("Z") and len(fixture["receivedAt"]) == 20
assert fixture["receivedAt"][4] == "-" and fixture["receivedAt"][10] == "T", fixture
assert fixture["from"][0]["email"] == "alice@example.com", fixture["from"]
assert fixture["from"][0]["name"] == "Alice", fixture["from"]
assert [a["email"] for a in fixture["cc"]] == ["carol@example.com", "dave@example.com"], fixture["cc"]
assert fixture["keywords"].get("$seen") is True, fixture["keywords"]
assert "$flagged" not in fixture["keywords"], fixture["keywords"]
assert fixture["hasAttachment"] is True, fixture
assert fixture["mailboxIds"] == {inbox_id: True}, fixture["mailboxIds"]
assert fixture["messageId"] == ["<a1@example.com>"], fixture["messageId"]
assert fixture["threadId"].startswith("t"), fixture

# textBody / htmlBody / attachments are three DIFFERENT parts
tb = fixture["textBody"]
hb = fixture["htmlBody"]
att = fixture["attachments"]
assert len(tb) == 1 and len(hb) == 1 and len(att) == 1, (tb, hb, att)
assert tb[0]["partId"] == "1.1" and hb[0]["partId"] == "1.2", (tb, hb)
assert att[0]["name"] == "report.pdf" and att[0]["type"] == "application/pdf", att
assert tb[0]["type"] == "text/plain" and hb[0]["type"] == "text/html", (tb, hb)
assert tb[0]["charset"] == "utf-8", tb

# bodyValues: DISTINCT and correctly decoded
bv = fixture["bodyValues"]
assert set(bv) >= {"1.1", "1.2"}, bv
text = bv["1.1"]["value"]
html = bv["1.2"]["value"]
assert text == "Café line one\nsecond line", repr(text)
assert html == "<html><body>Café</body></html>", repr(html)
assert text != html, (text, html)
assert bv["1.1"]["isTruncated"] is False and bv["1.1"]["isEncodingProblem"] is False, bv
# the attachment's bytes are NOT in bodyValues (it is not a body part)
assert "2" not in bv, bv

# quoted-printable message decodes too (fetched on its own: the batch above
# only asked for the first three ids)
st, resp = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/get", {"ids": [desc_ids[3]], "properties": ["id", "textBody"],
                   "fetchTextBodyValues": True}, "g0"]]})
qp = resp["methodResponses"][0][1]["list"][0]
# a single-part body runs to EOF, so its trailing CRLF is part of the body
assert qp["textBody"][0]["partId"] == "1", qp["textBody"]
assert qp["bodyValues"][qp["textBody"][0]["partId"]]["value"] == "qp body line\r\n", qp

# --- a SINGLE-PART message: part "1", never "" -------------------------
# The client caches body rows BY partId and its datalog engine refuses to
# intern the empty string, so an empty partId makes its whole cache write fail
# and the mailbox cannot be listed.  RFC 8621 4.1.1 numbers the part "1".
st, resp = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/get", {"ids": [desc_ids[1]], "properties":
                   ["id", "textBody", "htmlBody", "bodyStructure", "attachments"],
                   "fetchTextBodyValues": True, "fetchHTMLBodyValues": True},
     "g0"]]})
one = resp["methodResponses"][0][1]["list"][0]
assert one["textBody"][0]["partId"] == "1", one["textBody"]
assert one["bodyStructure"]["partId"] == "1", one["bodyStructure"]
assert one["bodyValues"] == {"1": one["bodyValues"]["1"]}, one["bodyValues"]
assert "" not in one["bodyValues"], one["bodyValues"]
assert one["bodyValues"]["1"]["value"] == "plain body line\r\n", one["bodyValues"]
assert one["htmlBody"] == [] and one["attachments"] == [], one
# the blobId minted from part "1" downloads the whole message's body: the
# resolver must accept the id the response just named
st, body, hdrs = http_get(f"/download/alice/{one['textBody'][0]['blobId']}/one.txt")
assert st == 200 and body == b"plain body line\r\n", (st, body)
assert hdrs.get("Content-Type", "").startswith("text/plain"), hdrs

# --- download: the DECODED bytes of the attachment part ---
blob = att[0]["blobId"]
assert blob.startswith("g"), blob
st, body, hdrs = http_get(f"/download/alice/{blob}/report.pdf")
assert st == 200, st
assert body == b"%PDF-1.4\n", body
assert body != b"JVBERi0xLjQK", body      # the RAW base64 text must not be served
assert hdrs.get("Content-Type", "").startswith("application/pdf"), hdrs
assert "attachment" in hdrs.get("Content-Disposition", ""), hdrs
assert hdrs.get("X-Content-Type-Options") == "nosniff", hdrs
assert int(hdrs.get("Content-Length", "-1")) == len(body), hdrs

# the text body part downloads as its decoded text as well
st, body, hdrs = http_get(f"/download/alice/{tb[0]['blobId']}/body.txt")
assert st == 200 and body == "Café line one\nsecond line".encode(), (st, body)
assert hdrs.get("Content-Type", "").startswith("text/plain"), hdrs

# --- the 12 MiB part: a bounded, flagged response rather than OOM ---
big = by_id[desc_ids[0]]
bigpart = big["textBody"][0]["partId"]
assert bigpart == "1", big["textBody"]        # single-part message: part "1"
assert big["size"] > 12582912, big["size"]
assert big["bodyValues"][bigpart]["isTruncated"] is True, "the 12 MiB body must be truncated"
assert len(big["bodyValues"][bigpart]["value"].encode()) == 1048576, "maxBodyValueBytes is exact"
# and the download streams all of it, with an exact Content-Length
# the part is 12 MiB of 'a' plus the message's trailing CRLF (a single-part
# body runs to EOF), and the streamed length is exact
st, body, hdrs = http_get(f"/download/alice/{big['textBody'][0]['blobId']}/big.txt")
assert st == 200 and len(body) == 12582914, (st, len(body))
assert int(hdrs["Content-Length"]) == 12582914, hdrs

# --- a property the server does not have is ABSENT (RFC-legal omission) ---
st, resp = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/get", {"ids": [fixture["id"]],
                   "properties": ["id", "preview", "notAProperty"]}, "g0"]]})
e = resp["methodResponses"][0][1]["list"][0]
assert set(e) == {"id", "preview"}, e

# --- unknown email id -> notFound, not an error ---
st, resp = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/get", {"ids": ["eMTcwMDAwMDAwMC5a", "bogus!"],
                   "properties": ["id"]}, "g0"]]})
gres = resp["methodResponses"][0][1]
assert gres["list"] == [], gres
assert sorted(gres["notFound"]) == ["bogus!", "eMTcwMDAwMDAwMC5a"], gres

# --- traversal / malformed blob ids are 404 BEFORE any open ---
email_id = fixture["id"]
b64 = lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")
evil = [
    "/download/alice/g..%2Fetc%2Fpasswd/x",                 # encoded traversal
    "/download/alice/g" + b64("../../etc/passwd") + ".MA/x",  # traversal payload
    "/download/alice/g" + b64(email_id) + ".MA/x",            # b64url(part "0")? no: MA is "0"
    "/download/alice/g" + b64(email_id) + "." + b64("1..2") + "/x",
    "/download/alice/g" + b64(email_id) + "." + b64("1.9") + "/x",
    "/download/alice/notbase64!.x/name",
    "/download/alice/g" + b64(email_id) + "/x",               # no separator
    "/download/bob/g" + b64(email_id) + "." + b64("2") + "/x",  # wrong account
]
for path in evil:
    st, body, _ = http_get(path)
    assert st == 404, (path, st, body[:80])
print("evil ids rejected:", len(evil))
PYEOF

# ======================================================================
# (2) the download requires authentication
# ======================================================================
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/download/alice/gAAA.MA/x")
check "$([ "$code" = 401 ] && echo 0 || echo 1)" "download without credentials: 401"

# ======================================================================
# (3) the blob pump keeps the connection usable (keep-alive after a body)
# ======================================================================
python3 - "$PORT_A" <<'PYEOF' && pass "download: keep-alive connection serves a second request" \
                           || fail "download: keep-alive connection serves a second request"
import base64, json, socket, sys

port = int(sys.argv[1])
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
s = socket.create_connection(("127.0.0.1", port), timeout=30)


def read_response(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        assert chunk, "closed early"
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    clen = 0
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            clen = int(line.split(b":", 1)[1])
    while len(rest) < clen:
        chunk = sock.recv(65536)
        assert chunk, "closed early in body"
        rest += chunk
    return head, rest[:clen], rest[clen:]


# find the fixture's attachment blob id first
req = (f"POST /api HTTP/1.1\r\nHost: x\r\nAuthorization: {auth}\r\n"
       f"Content-Length: ").encode()
body = json.dumps({"using": ["urn:ietf:params:jmap:mail"], "methodCalls": [
    ["Email/query", {"filter": {}, "sort": [{"property": "receivedAt",
                                            "isAscending": False}],
                     "limit": 10}, "q0"],
    ["Email/get", {"#ids": {"resultOf": "q0", "name": "Email/query",
                            "path": "/ids"},
                   "properties": ["id", "attachments"]}, "g0"]]}).encode()
s.sendall(req + str(len(body)).encode() + b"\r\n\r\n" + body)
head, payload, tail = read_response(s)
assert head.startswith(b"HTTP/1.1 200"), head[:60]
resp = json.loads(payload)
blob = None
for e in resp["methodResponses"][1][1]["list"]:
    if e["attachments"]:
        blob = e["attachments"][0]["blobId"]
assert blob, resp

# GET the blob, then a second request on the SAME connection
s.sendall((f"GET /download/alice/{blob}/report.pdf HTTP/1.1\r\nHost: x\r\n"
           f"Authorization: {auth}\r\n\r\n").encode())
head, body2, tail = read_response(s)
assert head.startswith(b"HTTP/1.1 200"), head[:60]
assert body2 == b"%PDF-1.4\n", body2
s.sendall((f"GET /.well-known/jmap HTTP/1.1\r\nHost: x\r\n"
           f"Authorization: {auth}\r\n\r\n").encode())
head, body3, _ = read_response(s)
assert head.startswith(b"HTTP/1.1 200"), head[:60]
assert b"apiUrl" in body3, body3[:80]
s.close()
PYEOF

# ======================================================================
# (4) every emitted string is valid UTF-8, and a stale sinceState is REFUSED
# ======================================================================
# MEASURED (live): a 100-message page over the real Inbox was 1,740,593 bytes
# and NOT valid UTF-8 (0xAE at offset 206223).  A conforming client refuses the
# WHOLE response, so one 8-bit byte in one body froze the mailbox list.  The
# instrument below is that client's: decode the body as UTF-8, then parse it.
#
# And /changes: the store keeps no per-object change log, so the honest answer
# is the RFC 8620 5.2 method error.  An EMPTY diff is what makes a client
# conclude "nothing changed" and never refresh, so an empty list is refused
# here — with one journal line saying which state was refused and why.
python3 - "$PORT_A" <<'PYEOF' && pass "utf8: every emitted string is valid UTF-8, with U+FFFD for 8-bit bytes" \
                           || fail "utf8: every emitted string is valid UTF-8, with U+FFFD for 8-bit bytes"
import base64, json, sys, urllib.request

port = int(sys.argv[1])
base = f"http://127.0.0.1:{port}"
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"


def raw_call(payload):
    req = urllib.request.Request(base + "/api", data=json.dumps(payload).encode())
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def call(payload):
    raw = raw_call(payload)
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise AssertionError(f"the response is not valid UTF-8: {e}")
    return json.loads(raw)


# --- the 8-bit message, found through its own mailbox ---
mbs = call({"using": [CORE, MAIL], "methodCalls": [["Mailbox/get", {}, "m0"]]})
odd = [m for m in mbs["methodResponses"][0][1]["list"] if m["name"] == "Odd"][0]
q = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"filter": {"inMailbox": odd["id"]}}, "q0"]]})
ids = q["methodResponses"][0][1]["ids"]
assert len(ids) == 1, q

raw = raw_call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/get", {"ids": ids, "properties": ["id", "subject", "textBody"],
                   "fetchTextBodyValues": True}, "g0"]]})
try:
    text = raw.decode("utf-8")
except UnicodeDecodeError as e:
    raise AssertionError(f"Email/get over an 8-bit message is not valid UTF-8 "
                         f"({e}) — a client refuses the whole page")
assert b"\xae" not in raw and b"\xff" not in raw, "a raw 8-bit byte survived"
e = json.loads(text)["methodResponses"][0][1]["list"][0]
assert e["subject"] == "bad \ufffd byte", repr(e["subject"])
bv = e["bodyValues"][e["textBody"][0]["partId"]]["value"]
assert bv == "body \ufffd and \ufffd here\r\n", repr(bv)
print("utf8: subject and body carry U+FFFD")
PYEOF

check "$([ "$(grep -c 'utf8-replaced' "$TMP/a.log")" = 1 ] && echo 0 || echo 1)" \
    "utf8: ONE counted journal line for the response that needed it"
check "$(grep -q 'utf8-replaced .*count=3' "$TMP/a.log" && echo 0 || echo 1)" \
    "utf8: the line names how many substitutions were made"

python3 - "$PORT_A" <<'PYEOF' && pass "changes: a sinceState that cannot be diffed is REFUSED, not answered empty" \
                           || fail "changes: a sinceState that cannot be diffed is REFUSED, not answered empty"
import base64, json, sys, urllib.request

port = int(sys.argv[1])
base = f"http://127.0.0.1:{port}"
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"

for method, arg in (("Email/changes", "sinceState"),
                    ("Mailbox/changes", "sinceState"),
                    ("Thread/changes", "sinceState"),
                    ("Email/queryChanges", "sinceQueryState")):
    payload = {"using": [CORE, MAIL], "methodCalls": [
        [method, {"accountId": "alice", arg: "e10"}, "c0"]]}
    req = urllib.request.Request(base + "/api", data=json.dumps(payload).encode())
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=60) as r:
        assert r.status == 200, (method, r.status)
        res = json.loads(r.read())["methodResponses"][0][1]
    assert res.get("type") == "cannotCalculateChanges", (method, res)
    # an empty diff is the answer that makes a client believe nothing changed
    assert "created" not in res and "updated" not in res, (method, res)
print("changes: four methods refused, no empty diff")
PYEOF

check "$(grep -q 'changes-refused .*method=Email/changes sinceState=e10' "$TMP/a.log" \
        && echo 0 || echo 1)" \
    "changes: the refusal is in the journal, naming the method and the state"

# /queryChanges carries its state in sinceQueryState (RFC 8620 5.6); the line
# must name what the client actually sent, not a key it never uses.
check "$(grep -q 'changes-refused .*method=Email/queryChanges sinceQueryState=e10' "$TMP/a.log" \
        && echo 0 || echo 1)" \
    "changes: the queryChanges refusal names sinceQueryState=e10"
check "$(grep -q 'method=Email/queryChanges sinceState=' "$TMP/a.log" && echo 1 || echo 0)" \
    "changes: no queryChanges line reads the sinceState key"

# ======================================================================
# (5) a bounded-work refusal is ANSWERED and JOURNALED, never a short page
# ======================================================================
# Three claims of commit 227c28f had no covering assertion: the paging-window
# refusal, the unreadable-mailbox refusal, and the HTTP response cap.  Each is
# one probe against the live daemon.
python3 - "$PORT_A" <<'PYEOF' && pass "window: position+limit past the window is a described serverLimit" \
                           || fail "window: position+limit past the window is a described serverLimit"
import base64, json, sys, urllib.request

port = int(sys.argv[1])
base = f"http://127.0.0.1:{port}"
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"


def call(payload):
    req = urllib.request.Request(base + "/api", data=json.dumps(payload).encode())
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.status, json.loads(r.read())


st, resp = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice", "position": 32768, "limit": 256},
     "q0"]]})
assert st == 200, st
res = resp["methodResponses"][0][1]
assert res.get("type") == "serverLimit", res
assert "window" in (res.get("description") or ""), res
assert "ids" not in res, ("a refused page must not also carry ids", res)
PYEOF

check "$(grep -q 'query-over-window .*position+limit=33024' "$TMP/a.log" \
        && echo 0 || echo 1)" \
    "window: the refusal is in the journal with the window it refused"

python3 - "$PORT_A" <<'PYEOF' && pass "response cap: a reply past 16 MiB is a described 500, not a truncated body" \
                           || fail "response cap: a reply past 16 MiB is a described 500, not a truncated body"
import base64, json, sys, urllib.error, urllib.request

port = int(sys.argv[1])
base = f"http://127.0.0.1:{port}"
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"


def call(payload):
    req = urllib.request.Request(base + "/api", data=json.dumps(payload).encode())
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


# the fixture's 12 MiB message: one Email/get call renders up to
# JMAPD_MAX_BODY_VALUE (4 MiB) of it, and the body budget is PER CALL, so five
# calls in one request build a reply past the 16 MiB cap.
st, raw = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice", "limit": 10}, "q0"],
    ["Email/get", {"#ids": {"resultOf": "q0", "name": "Email/query",
                            "path": "/ids"},
                   "properties": ["id", "size"]}, "g0"]]})
listing = json.loads(raw)["methodResponses"][1][1]["list"]
big = max(listing, key=lambda e: e["size"])
assert big["size"] > 12 * 1024 * 1024, big
big = big["id"]

calls = [["Email/get", {"accountId": "alice", "ids": [big],
                        "properties": ["id", "textBody"],
                        "fetchTextBodyValues": True}, f"g{i}"] for i in range(5)]
st, raw = call({"using": [CORE, MAIL], "methodCalls": calls})
assert st == 500, (st, raw[:200])
err = json.loads(raw)
assert err.get("type") == "serverLimit", err
assert "limit" in (err.get("description") or ""), err
PYEOF

check "$(grep -q 'response-over-limit' "$TMP/a.log" && echo 0 || echo 1)" \
    "response cap: the journal names the response that was too big"

# --- the get-truncated count is the RESPONSE's, not the budget's -----------
# A reduced limit with a body that FITS under it cuts nothing, so the journal
# must not claim an object was truncated when no bodyValue says isTruncated.
PORT_D="$((PORT_BASE + 3))"
./jmapd.com --root "$ROOT" --addr 127.0.0.1 --port "$PORT_D" \
    --hostname localhost --get-body-budget 2000 >"$TMP/d.log" 2>&1 &
DAEMONS+=("$!")
wait_port "$PORT_D" "jmapd (small body budget)"

python3 - "$PORT_D" <<'PYEOF' && pass "get-truncated: the count is the response's — a limit that cut nothing logs nothing" \
                           || fail "get-truncated: the count is the response's — a limit that cut nothing logs nothing"
import base64, json, sys, urllib.request

port = int(sys.argv[1])
base = f"http://127.0.0.1:{port}"
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"


def call(payload):
    req = urllib.request.Request(base + "/api", data=json.dumps(payload).encode())
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


mbs = call({"using": [CORE, MAIL], "methodCalls": [
    ["Mailbox/get", {"accountId": "alice"}, "m0"]]})
mid = [m["id"] for m in mbs["methodResponses"][0][1]["list"] if m["name"] == "Mid"][0]
ids = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice", "filter": {"inMailbox": mid},
                     "sort": [{"property": "receivedAt", "isAscending": True}]},
     "q0"]]})["methodResponses"][0][1]["ids"]
assert len(ids) == 2, ids

# 300-byte body first: it leaves ~1.5 KiB of the 2 KiB budget, so the second
# (18-byte) body is rendered under a REDUCED limit that still fits it whole
res = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/get", {"accountId": "alice", "ids": ids,
                   "properties": ["id", "textBody"],
                   "fetchTextBodyValues": True}, "g0"]]})["methodResponses"][0][1]
assert "type" not in res, res
cuts = [v for e in res["list"] for v in e["bodyValues"].values() if v["isTruncated"]]
assert not cuts, ("no body in this page was cut", cuts)
PYEOF

check "$([ -f "$TMP/d.log" ] && ! grep -q 'get-truncated' "$TMP/d.log" && echo 0 || echo 1)" \
    "get-truncated: no line was written for a page nothing was cut from"

# ======================================================================
# (6) Email/get REFUSES a message it cannot read (it used to answer 200 with
#     textBody:[] and bodyValues:{} — a body silently empty, no flag, no line)
# ======================================================================
# Last but one, because it makes one of the fixture's messages unreadable.
ODD_FILE="$ROOT/alice/.Odd/cur/1700000500.F.host:2,S"
PAIR="$(python3 - "$PORT_A" <<'PYEOF'
import base64, json, sys, urllib.request

port = int(sys.argv[1])
base = f"http://127.0.0.1:{port}"
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"


def call(payload):
    req = urllib.request.Request(base + "/api", data=json.dumps(payload).encode())
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


mbs = call({"using": [CORE, MAIL], "methodCalls": [
    ["Mailbox/get", {"accountId": "alice"}, "m0"]]})
by_name = {m["name"]: m["id"] for m in mbs["methodResponses"][0][1]["list"]}
# a readable message FIRST, so the refusal has to roll back a page already
# built: the unreadable one is the second id in the request
ok_q = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice", "filter": {"inMailbox": by_name["Inbox"]},
                     "limit": 1}, "q0"]]})
bad_q = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice", "filter": {"inMailbox": by_name["Odd"]}},
     "q0"]]})
print(ok_q["methodResponses"][0][1]["ids"][0],
      bad_q["methodResponses"][0][1]["ids"][0])
PYEOF
)" || PAIR=""

if [ -n "$PAIR" ] && [ -f "$ODD_FILE" ]; then
    chmod 000 "$ODD_FILE"
    python3 - "$PORT_A" $PAIR <<'PYEOF' && pass "get: an unreadable message is a described serverFail, never an empty body" \
                                  || fail "get: an unreadable message is a described serverFail, never an empty body"
import base64, json, sys, urllib.request

port = int(sys.argv[1])
good, bad = sys.argv[2], sys.argv[3]
base = f"http://127.0.0.1:{port}"
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"

req = urllib.request.Request(base + "/api", data=json.dumps({
    "using": [CORE, MAIL],
    "methodCalls": [["Email/get", {"accountId": "alice", "ids": [good, bad],
                                   "properties": ["id", "subject", "textBody"],
                                   "fetchTextBodyValues": True}, "g0"]]}).encode())
req.add_header("Authorization", auth)
req.add_header("Content-Type", "application/json")
with urllib.request.urlopen(req, timeout=60) as r:
    assert r.status == 200, r.status          # a method error, not a transport one
    res = json.loads(r.read())["methodResponses"][0][1]
assert res.get("type") == "serverFail", res
assert res.get("description"), res
assert "could not be read" in res["description"], res
# the refused call is the WHOLE result: no half-built page, no object whose
# bodyValues are empty because nobody read the file
assert "list" not in res, ("a refused get must not also carry a page", res)
assert "bodyValues" not in json.dumps(res), res
PYEOF
    chmod 644 "$ODD_FILE"
else
    fail "get: an unreadable message is a described serverFail, never an empty body (no fixture)"
fi

check "$(grep -q 'get-unreadable-message' "$TMP/a.log" && echo 0 || echo 1)" \
    "get: the refused read is in the journal"

# ======================================================================
# (7) a MAILBOX that cannot be opened is refused, not searched-and-skipped
# ======================================================================
# Last: hiding the directory hides it from every later assertion.
if [ -d "$ROOT/alice/.Odd" ]; then
    chmod 000 "$ROOT/alice/.Odd"
    python3 - "$PORT_A" <<'PYEOF' && pass "query: an unreadable mailbox is a described serverFail, not an empty list" \
                               || fail "query: an unreadable mailbox is a described serverFail, not an empty list"
import base64, json, sys, urllib.request

port = int(sys.argv[1])
base = f"http://127.0.0.1:{port}"
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"

req = urllib.request.Request(base + "/api", data=json.dumps({
    "using": [CORE, MAIL],
    "methodCalls": [["Email/query", {"accountId": "alice"}, "q0"]]}).encode())
req.add_header("Authorization", auth)
req.add_header("Content-Type", "application/json")
with urllib.request.urlopen(req, timeout=60) as r:
    assert r.status == 200, r.status
    res = json.loads(r.read())["methodResponses"][0][1]
assert res.get("type") == "serverFail", res
assert "could not be read" in (res.get("description") or ""), res
assert "ids" not in res, ("a refused query must not also carry ids", res)
PYEOF
    chmod 755 "$ROOT/alice/.Odd"
else
    fail "query: an unreadable mailbox is a described serverFail, not an empty list (no fixture)"
fi

check "$(grep -q 'query-unreadable-mailbox' "$TMP/a.log" && echo 0 || echo 1)" \
    "query: the unreadable mailbox is in the journal"

# ======================================================================
# (8) a session document is COUNTED like any other: the utf8 counter is
#     process-global, and a --hostname with an ill-formed byte used to be
#     substituted into the session doc with no journal line at all
# ======================================================================
PORT_C="$((PORT_BASE + 2))"
./jmapd.com --root "$ROOT" --addr 127.0.0.1 --port "$PORT_C" \
    --hostname "$(printf 'bad\xaehost')" >"$TMP/c.log" 2>&1 &
DAEMONS+=("$!")
wait_port "$PORT_C" "jmapd (8-bit hostname)"

python3 - "$PORT_C" <<'PYEOF' && pass "session: an ill-formed hostname is U+FFFD, and the substitution is counted" \
                           || fail "session: an ill-formed hostname is U+FFFD, and the substitution is counted"
import base64, json, sys, urllib.request

port = int(sys.argv[1])
base = f"http://127.0.0.1:{port}"
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"


def get(path):
    req = urllib.request.Request(base + path)
    req.add_header("Authorization", auth)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.status, r.read()


st, raw = get("/.well-known/jmap")
assert st == 200, st
text = raw.decode("utf-8")          # raises if the document is not valid UTF-8
assert "\ufffd" in text, text[:200]

# a following /api response must not inherit the session's count
req = urllib.request.Request(base + "/api", data=json.dumps({
    "using": [CORE, MAIL],
    "methodCalls": [["Mailbox/get", {"accountId": "alice"}, "m0"]]}).encode())
req.add_header("Authorization", auth)
req.add_header("Content-Type", "application/json")
with urllib.request.urlopen(req, timeout=60) as r:
    assert r.status == 200, r.status
    assert json.loads(r.read())["methodResponses"][0][0] == "Mailbox/get"
PYEOF

check "$([ "$(grep -c 'utf8-replaced' "$TMP/c.log")" = 1 ] && echo 0 || echo 1)" \
    "session: exactly ONE counted line — the session's, not a leaked count"

echo
if [ "$FAILS" = 0 ]; then
    echo "jmapd_read: all checks passed"
    exit 0
fi
echo "jmapd_read: $FAILS check(s) failed"
exit 1
