#!/usr/bin/env bash
# jmapd_scale.sh — the synthetic 30k-message scale gate.
#
# WHY THIS EXISTS: the live deploy (Archive = 32,107 messages) broke in three
# ways no small fixture could see, and every one of them was a SILENT or
# MISLEADING answer rather than a slow one:
#
#   * the client's page request (Email/query + Email/get with bodies) answered
#     HTTP 500 "response too large" for the WHOLE request as soon as the newest
#     page held big messages — so a 32k mailbox could not be listed at all;
#   * an Email/query whose `text` scan ran out of budget answered a bare
#     {"type":"serverFail"} with no description and no journal line, which the
#     client can only render as "no results";
#   * a message the query could not read was counted as "no match", shrinking
#     the result set without saying so.
#
# The fix is bounded work with an honest answer, and these assertions are the
# ones that FAIL on the old behaviour:
#
#   * a 30k archive is queryable: exact `total`, exact paging near the END, and
#     a full page of bodies served TRUNCATED (isTruncated) instead of 500;
#   * a global text search over the same archive FINDS the term (30,000 hits),
#     and an absent term is a genuine 0 — an empty list is never the
#     representation of "we could not ask";
#   * with the scan budget forced tiny, the same search answers a typed
#     `serverLimit` WITH a description and leaves a `query-over-budget` line in
#     the journal;
#   * an unreadable message is a described `serverFail`, not a shorter list.
#
# The archive is 30,000 messages (~40 MiB): 29,950 small ones plus the 50
# NEWEST at ~400 KiB, because the failure needs the first page to be big.
#
# Ports are parametrized via env: JMAPD_PORT_BASE (default 18101).
set -euo pipefail

cd "$(dirname "$0")/.."

PORT_BASE="${JMAPD_PORT_BASE:-18101}"
PORT_A="$PORT_BASE"
PORT_B=$((PORT_BASE + 1))

if [ ! -x ./jmapd.com ]; then
    echo "FAIL jmapd.com is not built (run: dhake jmapd.com)" >&2
    exit 1
fi

TMP="$(mktemp -d /tmp/jmapd_scale_XXXXXX)"
ROOT="$TMP/root"
mkdir -p "$ROOT"
printf 'alice:waldorf\n' > "$ROOT/imapd.passwd"
chmod 600 "$ROOT/imapd.passwd"

DAEMONS=()
cleanup() {
    for pid in "${DAEMONS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    rm -rf "$TMP"
}
trap cleanup EXIT

pass()  { printf 'ok   %s\n' "$1"; }
fail()  { printf 'FAIL %s\n' "$1"; FAILS=$((FAILS + 1)); }
check() { if [ "$1" = 0 ]; then pass "$2"; else fail "$2"; fi }
FAILS=0

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
    ./jmapd.com --root "$ROOT" --addr 127.0.0.1 "$@" >"$log" 2>&1 &
    DAEMONS+=("$!")
}

# ---- seed the 30k archive -------------------------------------------------
NMSG=30000
NBIG=50
BIGBYTES=409600
echo "seeding $NMSG messages in .Archive ($NBIG of ${BIGBYTES} B) ..."
python3 - "$ROOT" "$NMSG" "$NBIG" "$BIGBYTES" <<'PYEOF' || { fail "seed the archive"; exit 1; }
import os, sys

root, nmsg, nbig, bigbytes = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
arch = os.path.join(root, "alice", ".Archive")
for sub in ("tmp", "new", "cur"):
    os.makedirs(os.path.join(arch, sub), exist_ok=True)

SMALL = ("the quick brown fox jumps over the lazy dog " * 16)[:700]
# A body big enough that 50 of them exceed the server's 16 MiB response cap:
# this is what made the live page request fail as a whole.
BIG = "<html><body><p>" + ("lorem ipsum dolor sit amet " * (bigbytes // 27))[:bigbytes] + "</p></body></html>"

for n in range(nmsg):
    big = n >= nmsg - nbig              # the NEWEST messages are the big ones
    body = BIG if big else SMALL
    ctype = "text/html" if big else "text/plain"
    msg = (
        "From: sender%d@example.com\r\nTo: alice@example.com\r\n"
        "Subject: message %d about needle-visage\r\n"
        "Message-ID: <m%d@example.com>\r\n"
        "Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n"
        "MIME-Version: 1.0\r\nContent-Type: %s; charset=utf-8\r\n\r\n%s\r\n"
        % (n, n, n, ctype, body)
    )
    # 10 of the 30,000 are UNREAD (no ":2,S" in the filename): the keyword
    # query has a non-trivial, exactly known answer to be checked against.
    unread = (n % 3000) == 0
    path = os.path.join(arch, "cur",
                        "%d.M%d.host%s" % (1700000000 + n, n,
                                          "" if unread else ":2,S"))
    with open(path, "w") as f:
        f.write(msg)
    # internal_date is the file mtime, and the query sorts on it: the order has
    # to be explicit, not filesystem-dependent.
    os.utime(path, (1700000000 + n, 1700000000 + n))
PYEOF
check $? "seed a 30,000-message archive (10 of them unread)"

start_daemon "$TMP/a.log" --port "$PORT_A"
start_daemon "$TMP/b.log" --port "$PORT_B" --text-scan-max 1048576
wait_port "$PORT_A" "jmapd A"
wait_port "$PORT_B" "jmapd B"

# ---- (1) a 30k mailbox is queryable, and a big page arrives truncated -----
python3 - "$PORT_A" "$NMSG" <<'PYEOF' && pass "30k archive: exact total, exact paging, big page served truncated" \
                                 || fail "30k archive: exact total, exact paging, big page served truncated"
import base64, json, sys, time, urllib.request

port, nmsg = int(sys.argv[1]), int(sys.argv[2])
base = "http://127.0.0.1:%d" % port
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"
SUB = "urn:ietf:params:jmap:submission"
PROPS = ["id", "threadId", "receivedAt", "from", "to", "cc", "subject",
         "preview", "keywords", "hasAttachment", "size", "mailboxIds",
         "textBody", "htmlBody", "attachments", "messageId"]


def call(payload, timeout=120):
    req = urllib.request.Request(base + "/api", data=json.dumps(payload).encode())
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/json")
    t = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), time.time() - t
    except urllib.error.HTTPError as e:
        return e.code, e.read(), time.time() - t


st, body, _ = call({"using": [CORE, MAIL], "methodCalls": [
    ["Mailbox/get", {"accountId": "alice"}, "m"]]})
assert st == 200, (st, body[:200])
ids = {m["name"]: m["id"] for m in json.loads(body)["methodResponses"][0][1]["list"]}
arch = ids["Archive"]
assert json.loads(body)["methodResponses"][0][1]["list"], body[:200]

# --- the plain query: exact total, bounded time ---
st, body, dt = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice", "filter": {"inMailbox": arch},
                     "sort": [{"property": "receivedAt", "isAscending": False}],
                     "position": 0, "limit": 50}, "q"]]})
res = json.loads(body)["methodResponses"][0][1]
assert st == 200 and "type" not in res, (st, res)
assert res["total"] == nmsg, res["total"]
assert len(res["ids"]) == 50, len(res["ids"])
assert dt < 20, "a 30k query took %.1fs" % dt

# --- paging near the END is exact (a short page here would hide the tail) ---
st, body, dt = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice", "filter": {"inMailbox": arch},
                     "sort": [{"property": "receivedAt", "isAscending": False}],
                     "position": nmsg - 50, "limit": 50}, "q"]]})
tail = json.loads(body)["methodResponses"][0][1]
assert "type" not in tail, tail
assert tail["total"] == nmsg, tail["total"]
assert len(tail["ids"]) == 50, len(tail["ids"])
assert set(tail["ids"]).isdisjoint(res["ids"]), "the tail page repeats the head page"

# --- the CLIENT SHAPE: query + get with bodies in one request ---
# The newest 50 messages are ~400 KiB each, i.e. ~20 MiB of bodies: before the
# body budget this answered 500 {"type":"serverFail","description":"response
# too large"} for the whole request.
st, body, dt = call({"using": [CORE, MAIL, SUB], "methodCalls": [
    ["Email/query", {"accountId": "alice", "filter": {"inMailbox": arch},
                     "sort": [{"property": "receivedAt", "isAscending": False}],
                     "position": 0, "limit": 50}, "q"],
    ["Email/get", {"accountId": "alice",
                   "#ids": {"resultOf": "q", "name": "Email/query",
                            "path": "/ids"},
                   "properties": PROPS, "fetchTextBodyValues": True,
                   "fetchHTMLBodyValues": True,
                   "maxBodyValueBytes": 1048576}, "g"]]})
assert st == 200, (st, body[:200])
gres = json.loads(body)["methodResponses"][1][1]
assert "type" not in gres, gres
assert len(gres["list"]) == 50, len(gres["list"])
assert len(body) < 16 * 1024 * 1024, len(body)
truncated = [e for e in gres["list"]
             if any(v.get("isTruncated") for v in e.get("bodyValues", {}).values())]
assert truncated, "a ~20 MiB page must arrive with isTruncated bodies, not whole"

# --- a GLOBAL text search over the same archive finds the term ---
# (the live bug: this answered an empty list because the scan ran out of budget)
st, body, dt = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice",
                     "filter": {"text": "needle-visage"},
                     "sort": [{"property": "receivedAt", "isAscending": False}],
                     "limit": 5}, "q"]]})
res = json.loads(body)["methodResponses"][0][1]
assert "type" not in res, res
assert res["total"] == nmsg, (res["total"], nmsg)
assert len(res["ids"]) == 5, res

# --- a term that is genuinely absent is a real 0, not a refusal ---
st, body, dt = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice",
                     "filter": {"text": "needle-absent-from-every-message"},
                     "limit": 5}, "q"]]})
res = json.loads(body)["methodResponses"][0][1]
assert "type" not in res, res
assert res["total"] == 0 and res["ids"] == [], res

# --- KEYWORD filters over the 30k archive: exact, and body-free ---
# "which messages in this mailbox are unread" is the bulk-action question.  The
# flags come from the FILENAME, so this must answer 10 exactly and quickly,
# without paging the mailbox and without reading one message body.
NUNREAD = 10
st, body, dt = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice",
                     "filter": {"inMailbox": arch, "notKeyword": "$seen"},
                     "sort": [{"property": "receivedAt", "isAscending": False}],
                     "limit": 100}, "q"]]})
unread = json.loads(body)["methodResponses"][0][1]
assert st == 200 and "type" not in unread, (st, unread)
assert unread["total"] == NUNREAD, unread["total"]
assert len(unread["ids"]) == NUNREAD, len(unread["ids"])
assert dt < 20, "a 30k keyword query took %.1fs" % dt

# the complement is exact too, and the two pages PARTITION the mailbox
st, body, dt = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice",
                     "filter": {"inMailbox": arch, "keyword": "$seen"},
                     "limit": 100}, "q"]]})
seen = json.loads(body)["methodResponses"][0][1]
assert st == 200 and "type" not in seen, (st, seen)
assert seen["total"] == nmsg - NUNREAD, seen["total"]
assert len(seen["ids"]) == 100, len(seen["ids"])
assert set(unread["ids"]).isdisjoint(seen["ids"]), "seen/unseen overlap"

# --- an unknown keyword is a DESCRIBED refusal, never an empty list ---
# ($forwarded has no maildir flag, so this server cannot test it.)
st, body, dt = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice",
                     "filter": {"inMailbox": arch, "keyword": "$forwarded"},
                     "limit": 5}, "q"]]})
res = json.loads(body)["methodResponses"][0][1]
assert res.get("type") == "unsupportedFilter", res
assert res.get("description"), res
assert "ids" not in res and "total" not in res, res
PYEOF

# ---- (2) an over-budget scan is a typed, described, journaled refusal -----
python3 - "$PORT_B" <<'PYEOF' && pass "over-budget text scan: serverLimit + description (never a short list)" \
                           || fail "over-budget text scan: serverLimit + description (never a short list)"
import base64, json, sys, urllib.request

port = int(sys.argv[1])
base = "http://127.0.0.1:%d" % port
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"

req = urllib.request.Request(base + "/api", data=json.dumps({
    "using": [CORE, MAIL],
    "methodCalls": [["Email/query", {"accountId": "alice",
                                     "filter": {"text": "needle-visage"},
                                     "limit": 5}, "q"]]}).encode())
req.add_header("Authorization", auth)
req.add_header("Content-Type", "application/json")
with urllib.request.urlopen(req, timeout=120) as r:
    resp = json.loads(r.read())
res = resp["methodResponses"][0][1]
assert res.get("type") == "serverLimit", res
desc = res.get("description") or ""
assert desc, "the refusal must carry a description"
assert "budget" in desc, desc
PYEOF

# ---- (2b) a keyword query is body-free: the SAME tiny budget answers it -----
# This daemon's scan budget is 1 MiB, so any body read would be refused.  The
# keyword answer must be exact anyway — that is only possible if the flags came
# from the filenames (proving the query reads no message bytes).
python3 - "$PORT_B" <<'PYEOF' && pass "tiny-budget daemon still answers the keyword query exactly (no body reads)" \
                           || fail "tiny-budget daemon still answers the keyword query exactly (no body reads)"
import base64, json, sys, time, urllib.request

port = int(sys.argv[1])
base = "http://127.0.0.1:%d" % port
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"


def call(payload):
    req = urllib.request.Request(base + "/api", data=json.dumps(payload).encode())
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


resp = call({"using": [CORE, MAIL], "methodCalls": [
    ["Mailbox/get", {"accountId": "alice"}, "m"]]})
arch = {m["name"]: m["id"] for m in resp["methodResponses"][0][1]["list"]}["Archive"]

t = time.time()
res = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice",
                     "filter": {"inMailbox": arch, "notKeyword": "$seen"},
                     "limit": 100}, "q"]]})["methodResponses"][0][1]
dt = time.time() - t
assert "type" not in res, res
assert res["total"] == 10, res["total"]
assert len(res["ids"]) == 10, len(res["ids"])
assert dt < 20, "the keyword query took %.1fs" % dt
PYEOF
if grep -q 'query-over-budget' "$TMP/b.log"; then
    pass "over-budget scan leaves a query-over-budget line in the journal"
else
    fail "over-budget scan leaves a query-over-budget line in the journal"
fi

# ---- (3) the truncation is journaled, not silent --------------------------
if grep -q 'get-truncated' "$TMP/a.log"; then
    pass "the truncated page leaves a get-truncated line in the journal"
else
    fail "the truncated page leaves a get-truncated line in the journal"
fi

# ---- (4) an unreadable message is a described refusal, not a short list ---
# Last, because it breaks the fixture it damages: the unreadable file is one of
# the archive's messages, so every filtered query below has to refuse.
VICTIM="$ROOT/alice/.Archive/cur/1700000005.M5.host:2,S"
if [ -f "$VICTIM" ]; then
    chmod 000 "$VICTIM"
    python3 - "$PORT_A" <<'PYEOF' && pass "unreadable message: described serverFail, never a short list" \
                               || fail "unreadable message: described serverFail, never a short list"
import base64, json, sys, urllib.request

port = int(sys.argv[1])
base = "http://127.0.0.1:%d" % port
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"


def call(payload):
    req = urllib.request.Request(base + "/api", data=json.dumps(payload).encode())
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


# a header filter has to read every candidate: the unreadable one must not
# silently become a non-match
resp = call({"using": [CORE, MAIL], "methodCalls": [
    ["Email/query", {"accountId": "alice",
                     "filter": {"subject": "message 5 about needle-visage"},
                     "limit": 5}, "q"]]})
res = resp["methodResponses"][0][1]
assert res.get("type") == "serverFail", res
assert res.get("description"), res
assert "could not be read" in res["description"], res
PYEOF
    chmod 644 "$VICTIM"
else
    fail "unreadable message: described serverFail, never a short list (no victim file)"
fi

if [ "$FAILS" -ne 0 ]; then
    echo
    echo "FAIL $FAILS assertion(s) failed; daemon logs:"
    sed 's/^/  A| /' "$TMP/a.log"
    sed 's/^/  B| /' "$TMP/b.log"
    exit 1
fi
echo
echo "PASS jmapd_scale.sh"
