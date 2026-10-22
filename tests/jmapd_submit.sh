#!/usr/bin/env bash
# jmapd_submit.sh — live tests for jmapd's M4 submission path: EmailSubmission/set
# against a recording SMTP sink on loopback.
#
# What is asserted, and why each one would catch a SILENT-WRONG implementation:
#
#   * the sink RECEIVED the message and it is the right message — the right
#     From, the right Subject, the right body — with the Bcc header removed
#     (RFC 8621 7.5 requires it).  "created" alone proves nothing: a server can
#     answer created and send nothing;
#   * the envelope carried every To/Cc/Bcc recipient, deduplicated, so a
#     blind-copied address is delivered to and a duplicate is not delivered
#     twice;
#   * the submitted Email MOVED to Sent with $seen and WITHOUT $draft — the
#     client's onSuccessUpdateEmail shape, applied as the implicit Email/set
#     RFC 8621 7.5 specifies (it is only a legal patch after the move, because
#     this store keeps one mailbox per message);
#   * the response carries a state change (oldState != newState) and the
#     created object's id/emailId/identityId/sendAt;
#   * a SECOND submission of the same Email is refused (notCreated) and the
#     sink received nothing more: at-most-once is the point of the outbox path;
#   * a sink that is DOWN reports notCreated and leaves the draft in Drafts,
#     un-flagged — an SMTP failure must never be reported as created, and must
#     never leave a draft looking sent;
#   * --outbox-tls none on a NON-loopback relay refuses to start (the
#     credential would cross the network in clear text).
#
# Ports are parametrized via env: JMAPD_PORT_BASE (default 18094).
set -euo pipefail

cd "$(dirname "$0")/.."

PORT_BASE="${JMAPD_PORT_BASE:-18094}"
PORT_A="$PORT_BASE"
SINK_PORT="$((PORT_BASE + 1))"

if [ ! -x ./jmapd.com ]; then
    echo "FAIL jmapd.com is not built (run: dhake jmapd.com)" >&2
    exit 1
fi
if [ ! -f tests/outbox_fakemx.py ]; then
    echo "FAIL tests/outbox_fakemx.py is missing (the recording SMTP sink)" >&2
    exit 1
fi

TMP="$(mktemp -d /tmp/jmapd_submit_XXXXXX)"
ROOT="$TMP/root"
SINK="$TMP/sink"
mkdir -p "$ROOT" "$SINK"
printf 'alice:waldorf\n' > "$ROOT/imapd.passwd"
chmod 600 "$ROOT/imapd.passwd"

mkdir -p "$ROOT/alice/Inbox/tmp" "$ROOT/alice/Inbox/new" "$ROOT/alice/Inbox/cur"
mkdir -p "$ROOT/alice/.Sent/tmp" "$ROOT/alice/.Sent/new" "$ROOT/alice/.Sent/cur"
mkdir -p "$ROOT/alice/.Drafts/tmp" "$ROOT/alice/.Drafts/new" "$ROOT/alice/.Drafts/cur"

# ---- the drafts a client would have composed -------------------------------
printf 'From: alice@example.com\r\nTo: Bob <bob@example.com>\r\nCc: carol@example.com\r\nBcc: dave@example.com\r\nSubject: first submission\r\nMessage-ID: <sub1@example.com>\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nContent-Type: text/plain\r\n\r\nfirst body line\r\nsecond body line\r\n' \
    > "$ROOT/alice/.Drafts/cur/1700000100.SUB1.host:2,D"
printf 'From: alice@example.com\r\nTo: bob@example.com\r\nSubject: patched submission\r\nMessage-ID: <sub2@example.com>\r\nDate: Mon, 1 Jan 2024 01:00:00 +0000\r\nContent-Type: text/plain\r\n\r\npatched body\r\n' \
    > "$ROOT/alice/.Drafts/cur/1700000200.SUB2.host:2,D"
printf 'From: alice@example.com\r\nTo: bob@example.com\r\nSubject: doomed submission\r\nMessage-ID: <sub3@example.com>\r\nDate: Mon, 1 Jan 2024 02:00:00 +0000\r\nContent-Type: text/plain\r\n\r\ndoomed body\r\n' \
    > "$ROOT/alice/.Drafts/cur/1700000300.SUB3.host:2,D"
# an Inbox message, so the onSuccessUpdateEmail-key cases below can send one
# WITHOUT consuming a Draft (the dead-sink section needs exactly one draft left)
printf 'From: alice@example.com\r\nTo: bob@example.com\r\nSubject: unresolvable submission\r\nMessage-ID: <sub4@example.com>\r\nDate: Mon, 1 Jan 2024 03:00:00 +0000\r\nContent-Type: text/plain\r\n\r\nunresolvable body\r\n' \
    > "$ROOT/alice/Inbox/cur/1700000400.SUB4.host:2,S"
touch -d @1700000100 "$ROOT/alice/.Drafts/cur/1700000100.SUB1.host:2,D"
touch -d @1700000200 "$ROOT/alice/.Drafts/cur/1700000200.SUB2.host:2,D"
touch -d @1700000300 "$ROOT/alice/.Drafts/cur/1700000300.SUB3.host:2,D"
touch -d @1700000400 "$ROOT/alice/Inbox/cur/1700000400.SUB4.host:2,S"

PIDS=()
FAILS=0

cleanup() {
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
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
        if [ "$i" -gt 150 ]; then
            echo "FAIL $2 did not come up on port $1" >&2
            echo "--- $2 log ---" >&2
            cat "$3" 2>/dev/null >&2 || true
            exit 1
        fi
        sleep 0.1
    done
}

# ======================================================================
# (1) the happy path, with the client's own onSuccessUpdateEmail shape
# ======================================================================
python3 tests/outbox_fakemx.py 127.0.0.1 "$SINK_PORT" "$SINK" \
    >"$TMP/sink.log" 2>&1 &
PIDS+=("$!")
wait_port "$SINK_PORT" "the recording sink" "$TMP/sink.log"

./jmapd.com --root "$ROOT" --addr 127.0.0.1 --port "$PORT_A" \
    --hostname 127.0.0.1 --identity alice@example.com \
    --outbox-host 127.0.0.1 --outbox-port "$SINK_PORT" --outbox-tls none \
    --submit-wait 10000 >"$TMP/jmapd.log" 2>&1 &
PIDS+=("$!")
wait_port "$PORT_A" "jmapd" "$TMP/jmapd.log"

python3 - "$PORT_A" "$ROOT" "$SINK" <<'PYEOF' && pass "submission: send, envelope, Sent move, state, second-send refusal" \
                           || fail "submission: send, envelope, Sent move, state, second-send refusal"
import base64, glob, json, os, sys, urllib.error, urllib.request

port, root, sink = int(sys.argv[1]), sys.argv[2], sys.argv[3]
base = f"http://127.0.0.1:{port}"
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"
SUB = "urn:ietf:params:jmap:submission"


def call(payload):
    req = urllib.request.Request(base + "/api", data=json.dumps(payload).encode())
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())


def one(name, args, using=(CORE, MAIL, SUB)):
    resp = call({"using": list(using), "methodCalls": [[name, args, "c0"]]})
    return resp["methodResponses"][0][1]


def mailbox_ids():
    res = one("Mailbox/get", {"accountId": "alice"})
    return {m["name"]: m["id"] for m in res["list"]}


def draft_ids():
    """Every Email in Drafts, oldest first."""
    mb = mailbox_ids()
    res = one("Email/query", {"accountId": "alice",
                              "filter": {"inMailbox": mb["Drafts"]},
                              "sort": [{"property": "receivedAt", "isAscending": True}],
                              "limit": 10})
    return res["ids"], mb


def get_email(eid, props):
    res = one("Email/get", {"accountId": "alice", "ids": [eid], "properties": props})
    assert res["list"], res
    return res["list"][0]


def sink_msgs():
    out = []
    for p in sorted(glob.glob(f"{sink}/msg-*.eml")):
        out.append(open(p, "rb").read())
    return out


def sink_rcpts():
    seen = []
    for p in sorted(glob.glob(f"{sink}/dialogue-*.txt")):
        for line in open(p, "r", errors="replace"):
            if line.startswith("C: RCPT TO:"):
                seen.append(line[len("C: RCPT TO:"):].strip().strip("<>"))
    return seen


ids, mb = draft_ids()
assert len(ids) == 3, (ids, "the seeded drafts must all be visible")

# --- Identity/get reports the configured own address ---------------------
ident = one("Identity/get", {"accountId": "alice"})
assert ident["list"], ident
identity = ident["list"][0]
assert identity["email"] == "alice@example.com", identity
identity_id = identity["id"]
assert identity_id.startswith("i"), identity

# --- (a) a plain submission ----------------------------------------------
first = get_email(ids[0], ["id", "subject", "keywords", "mailboxIds"])
assert first["subject"] == "first submission", first
assert first["keywords"].get("$draft") is True, first
assert first["mailboxIds"] == {mb["Drafts"]: True}, first

res = one("EmailSubmission/set", {"accountId": "alice",
                                  "create": {"sub": {"identityId": identity_id,
                                                     "emailId": ids[0]}}})
assert "notCreated" not in res, res
created = res["created"]["sub"]
assert created["id"].startswith("s"), created
assert created["emailId"] == ids[0], created
assert created["identityId"] == identity_id, created
assert created["sendAt"].endswith("Z") and created["sendAt"][4] == "-", created
assert res["oldState"].startswith("s"), res
assert res["newState"] != res["oldState"], res

# --- the SINK got the message, and it is the right message ---------------
msgs = sink_msgs()
assert len(msgs) == 3, (len(msgs), "one transaction per recipient")
for m in msgs:
    text = m.decode("utf-8", "replace")
    assert "Subject: first submission" in text, text[:400]
    assert "From: alice@example.com" in text, text[:400]
    assert "first body line" in text and "second body line" in text, text[:400]
    # RFC 8621 7.5: the Bcc header MUST NOT be delivered
    assert "Bcc:" not in text, ("Bcc header leaked to the relay", text[:600])
rc = sorted(sink_rcpts())
assert rc == ["bob@example.com", "carol@example.com", "dave@example.com"], rc

# --- the Email is in Sent, seen, and no longer a draft -------------------
after = get_email(ids[0], ["id", "keywords", "mailboxIds"])
assert after["id"] == ids[0], after                       # the id survived
assert after["mailboxIds"] == {mb["Sent"]: True}, after
assert after["keywords"].get("$seen") is True, after
assert after["keywords"].get("$draft") is None, after

# --- (b) a second submission of the SAME email is refused ----------------
before = len(sink_msgs())
res = one("EmailSubmission/set", {"accountId": "alice",
                                  "create": {"again": {"identityId": identity_id,
                                                       "emailId": ids[0]}}})
assert "created" not in res, res
err = res["notCreated"]["again"]
assert err["type"] in ("forbidden", "invalidProperties"), err
assert len(sink_msgs()) == before, "a refused submission must send nothing"

# --- (c) the client's own shape: onSuccessUpdateEmail --------------------
# The THREE assertions that used to be here (Sent mailboxIds, $seen set, $draft
# cleared) are all subsumed by sub_move_to_sent: they pass whether the patch is
# applied or silently dropped, so they could not see the #creationId mapping
# bug.  $flagged is the distinguishing keyword — the move never sets it.
res = one("EmailSubmission/set", {
    "accountId": "alice",
    "create": {"sub": {"identityId": identity_id, "emailId": ids[1]}},
    "onSuccessUpdateEmail": {"#sub": {
        "mailboxIds/" + mb["Drafts"]: None,
        "keywords/$draft": None,
        "keywords/$seen": True,
        "keywords/$flagged": True,
    }},
})
assert "notCreated" not in res, res
assert res["created"]["sub"]["emailId"] == ids[1], res
patched = get_email(ids[1], ["id", "keywords", "mailboxIds"])
assert patched["mailboxIds"] == {mb["Sent"]: True}, patched
assert patched["keywords"].get("$seen") is True, patched
assert patched["keywords"].get("$draft") is None, patched
# a keyword the move-to-Sent does NOT set: proves the PATCH was applied
assert patched["keywords"].get("$flagged") is True, patched

# --- (d) an unknown email / identity is invalidProperties ---------------
res = one("EmailSubmission/set", {"accountId": "alice",
                                  "create": {"nope": {"identityId": identity_id,
                                                      "emailId": "eAAAA"}}})
assert res["notCreated"]["nope"]["type"] == "invalidProperties", res
res = one("EmailSubmission/set", {"accountId": "alice",
                                  "create": {"nope": {"identityId": "iZZZ",
                                                      "emailId": ids[2]}}})
assert res["notCreated"]["nope"]["type"] == "invalidProperties", res
assert res["notCreated"]["nope"]["properties"] == ["identityId"], res

# --- (e) an update is cannotUnsend (RFC 8621 7.5) -----------------------
res = one("EmailSubmission/set", {"accountId": "alice",
                                  "update": {created["id"]: {"undoStatus": "canceled"}}})
assert res["notUpdated"][created["id"]]["type"] == "cannotUnsend", res

# --- (f) an UNRESOLVABLE onSuccessUpdateEmail key: still created, patch
# reported as not applied (the submission is the client's, the patch is not) --
inbox_ids = one("Email/query", {"accountId": "alice",
                                "filter": {"inMailbox": mb["Inbox"]},
                                "limit": 10})["ids"]
target = None
for cand in inbox_ids:
    got = one("Email/get", {"accountId": "alice", "ids": [cand],
                            "properties": ["id", "subject"]})["list"]
    if got and got[0]["subject"] == "unresolvable submission":
        target = got[0]["id"]
        break
assert target, ("the seeded Inbox message must be visible", inbox_ids)
res = one("EmailSubmission/set", {
    "accountId": "alice",
    "create": {"sub": {"identityId": identity_id, "emailId": target}},
    "onSuccessUpdateEmail": {"#nosuch": {"keywords/$answered": True}},
})
assert "notCreated" not in res, res
assert res["created"]["sub"]["emailId"] == target, res
unp = get_email(target, ["id", "keywords", "mailboxIds"])
assert unp["mailboxIds"] == {mb["Sent"]: True}, unp
assert unp["keywords"].get("$answered") is None, unp   # NOT applied

print("submission assertions: all passed")
PYEOF

# an unresolvable key must be LOGGED, not silently dropped (a client that sent
# a patch the server did not apply has to be able to find out)
if grep -q "names no submission created here" "$TMP/jmapd.log"; then
    pass "submission: an unresolvable onSuccessUpdateEmail key is logged, not silent"
else
    fail "submission: an unresolvable onSuccessUpdateEmail key is logged, not silent"
fi

# ======================================================================
# (2) a DEAD sink: notCreated, and the draft stays a draft in Drafts
# ======================================================================
kill "${PIDS[0]}" 2>/dev/null || true
wait "${PIDS[0]}" 2>/dev/null || true
PIDS=("${PIDS[@]:1}")

python3 - "$PORT_A" "$ROOT" <<'PYEOF' && pass "submission: a refused relay is notCreated and leaves the draft in Drafts" \
                           || fail "submission: a refused relay is notCreated and leaves the draft in Drafts"
import base64, json, sys, urllib.request

port, root = int(sys.argv[1]), sys.argv[2]
base = f"http://127.0.0.1:{port}"
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"
SUB = "urn:ietf:params:jmap:submission"


def one(name, args):
    body = json.dumps({"using": [CORE, MAIL, SUB],
                       "methodCalls": [[name, args, "c0"]]}).encode()
    req = urllib.request.Request(base + "/api", data=body)
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())["methodResponses"][0][1]


mbs = {m["name"]: m["id"] for m in one("Mailbox/get", {"accountId": "alice"})["list"]}
ids = one("Email/query", {"accountId": "alice",
                          "filter": {"inMailbox": mbs["Drafts"]},
                          "limit": 10})["ids"]
assert len(ids) == 1, (ids, "only the doomed draft is left in Drafts")
identity = one("Identity/get", {"accountId": "alice"})["list"][0]["id"]

res = one("EmailSubmission/set", {"accountId": "alice",
                                  "create": {"sub": {"identityId": identity,
                                                     "emailId": ids[0]}}})
assert "created" not in res, res
err = res["notCreated"]["sub"]
assert err["type"] in ("serverUnavailable", "serverFail"), err
assert err.get("description"), err

# the draft did NOT move, did NOT get $seen, and is still a draft
e = one("Email/get", {"accountId": "alice", "ids": [ids[0]],
                      "properties": ["id", "keywords", "mailboxIds"]})["list"][0]
assert e["mailboxIds"] == {mbs["Drafts"]: True}, e
assert e["keywords"].get("$draft") is True, e
assert e["keywords"].get("$seen") is None, e
print("dead-relay assertions: all passed")
PYEOF

# ======================================================================
# (3) --outbox-tls none on a non-loopback relay refuses to start
# ======================================================================
rc=0
out="$(./jmapd.com --root "$ROOT" --addr 127.0.0.1 --port "$((PORT_BASE + 2))" \
    --outbox-host 10.20.30.40 --outbox-tls none 2>&1)" || rc=$?
check "$([ "$rc" != 0 ] && echo 0 || echo 1)" \
    "startup: --outbox-tls none with a non-loopback relay is refused (exit $rc)"
case "$out" in
    *"clear text"*|*"non-loopback"*) pass "startup: the refusal names the reason" ;;
    *) fail "startup: the refusal names the reason (got: $out)" ;;
esac

# and an unknown TLS mode is a usage error, not a silent fallback
rc=0
out="$(./jmapd.com --root "$ROOT" --addr 127.0.0.1 --port "$((PORT_BASE + 2))" \
    --outbox-tls bogus 2>&1)" || rc=$?
check "$([ "$rc" = 2 ] && echo 0 || echo 1)" \
    "startup: an unknown --outbox-tls value is a usage error (exit $rc)"

# ======================================================================
# (4) a message larger than the send limit is tooLarge, NOT "queue is full"
#     (the queue cap is the real send limit: the whole message must be
#     resident while the worker runs; the read cap is larger, so the old
#     msglen > max_msg branch could never fire)
# ======================================================================
mkdir -p "$ROOT/alice/Inbox/cur"
{
    printf 'From: alice@example.com\r\nTo: bob@example.com\r\nSubject: huge submission\r\nMessage-ID: <sub5@example.com>\r\nDate: Mon, 1 Jan 2024 05:00:00 +0000\r\nContent-Type: text/plain\r\n\r\n'
    head -c 9437184 /dev/zero | tr '\0' 'x'
    printf '\r\n'
} > "$ROOT/alice/Inbox/cur/1700000500.SUB5.host:2,S"
touch -d @1700000500 "$ROOT/alice/Inbox/cur/1700000500.SUB5.host:2,S"

python3 - "$PORT_A" <<'PYEOF' && pass "submission: a message over the 8 MiB send limit is tooLarge, not serverUnavailable" \
                           || fail "submission: a message over the 8 MiB send limit is tooLarge, not serverUnavailable"
import base64, json, sys, urllib.request

port = int(sys.argv[1])
base = f"http://127.0.0.1:{port}"
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"
SUB = "urn:ietf:params:jmap:submission"


def one(name, args):
    body = json.dumps({"using": [CORE, MAIL, SUB],
                       "methodCalls": [[name, args, "c0"]]}).encode()
    req = urllib.request.Request(base + "/api", data=body)
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())["methodResponses"][0][1]


mbs = {m["name"]: m["id"] for m in one("Mailbox/get", {"accountId": "alice"})["list"]}
inbox = one("Email/query", {"accountId": "alice",
                            "filter": {"inMailbox": mbs["Inbox"]},
                            "limit": 10})["ids"]
target = None
for cand in inbox:
    got = one("Email/get", {"accountId": "alice", "ids": [cand],
                            "properties": ["id", "subject", "size"]})["list"]
    if got and got[0]["subject"] == "huge submission":
        target = got[0]
        break
assert target, ("the oversized message must be visible", inbox)
assert target["size"] > 8 * 1024 * 1024, target
identity = one("Identity/get", {"accountId": "alice"})["list"][0]["id"]

res = one("EmailSubmission/set", {"accountId": "alice",
                                  "create": {"big": {"identityId": identity,
                                                     "emailId": target["id"]}}})
assert "created" not in res, res
err = res["notCreated"]["big"]
assert err["type"] == "tooLarge", err
assert err["maxSize"] == 8 * 1024 * 1024, err
print("too-large assertions: all passed")
PYEOF

# ======================================================================
# (5) --submit-wait 0 means ZERO: created at once, the verdict only logged
#     (before the fix `submit_wait ? : 5000` turned a 0 into a 5 s stall)
# ======================================================================
ROOT2="$TMP/root2"
HOLE_PORT="$((PORT_BASE + 4))"
PORT_C="$((PORT_BASE + 3))"
cp -a "$ROOT" "$ROOT2"
printf 'From: alice@example.com\r\nTo: bob@example.com\r\nSubject: nowait submission\r\nMessage-ID: <sub6@example.com>\r\nDate: Mon, 1 Jan 2024 06:00:00 +0000\r\nContent-Type: text/plain\r\n\r\nnowait body\r\n' \
    > "$ROOT2/alice/.Drafts/cur/1700000600.SUB6.host:2,D"
touch -d @1700000600 "$ROOT2/alice/.Drafts/cur/1700000600.SUB6.host:2,D"

# a relay that accepts the connection and never says a word: the worker blocks
# in the dialogue, so the ONLY thing that can end the request early is the wait
python3 -c 'import socket,sys,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((sys.argv[1],int(sys.argv[2]))); s.listen(8)
c,_=s.accept(); time.sleep(3600)' 127.0.0.1 "$HOLE_PORT" >"$TMP/hole.log" 2>&1 &
HOLE_PID=$!
PIDS+=("$HOLE_PID")
wait_port "$HOLE_PORT" "the silent relay" "$TMP/hole.log"

./jmapd.com --root "$ROOT2" --addr 127.0.0.1 --port "$PORT_C" \
    --hostname 127.0.0.1 --identity alice@example.com \
    --outbox-host 127.0.0.1 --outbox-port "$HOLE_PORT" --outbox-tls none \
    --submit-wait 0 >"$TMP/jmapd2.log" 2>&1 &
PIDS+=("$!")
wait_port "$PORT_C" "jmapd (--submit-wait 0)" "$TMP/jmapd2.log"

python3 - "$PORT_C" <<'PYEOF' && pass "submission: --submit-wait 0 answers created without waiting" \
                           || fail "submission: --submit-wait 0 answers created without waiting"
import base64, json, sys, time, urllib.request

port = int(sys.argv[1])
base = f"http://127.0.0.1:{port}"
auth = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"
SUB = "urn:ietf:params:jmap:submission"


def one(name, args):
    body = json.dumps({"using": [CORE, MAIL, SUB],
                       "methodCalls": [[name, args, "c0"]]}).encode()
    req = urllib.request.Request(base + "/api", data=body)
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read())["methodResponses"][0][1]


mbs = {m["name"]: m["id"] for m in one("Mailbox/get", {"accountId": "alice"})["list"]}
ids = one("Email/query", {"accountId": "alice",
                          "filter": {"inMailbox": mbs["Drafts"]},
                          "limit": 10})["ids"]
target = None
for cand in ids:
    got = one("Email/get", {"accountId": "alice", "ids": [cand],
                            "properties": ["id", "subject"]})["list"]
    if got and got[0]["subject"] == "nowait submission":
        target = got[0]["id"]
        break
assert target, ("the nowait draft must be visible", ids)
identity = one("Identity/get", {"accountId": "alice"})["list"][0]["id"]

t0 = time.monotonic()
res = one("EmailSubmission/set", {"accountId": "alice",
                                  "create": {"sub": {"identityId": identity,
                                                     "emailId": target}}})
elapsed = time.monotonic() - t0
assert "notCreated" not in res, res
assert res["created"]["sub"]["emailId"] == target, res
assert elapsed < 2.0, ("--submit-wait 0 stalled the request", elapsed)
# accepted-without-verdict is still FILED (Sent + $seen), delivery unknown
e = one("Email/get", {"accountId": "alice", "ids": [target],
                      "properties": ["id", "keywords", "mailboxIds"]})["list"][0]
assert e["mailboxIds"] == {mbs["Sent"]: True}, e
assert e["keywords"].get("$seen") is True, e
print(f"nowait assertions: all passed ({elapsed:.3f}s)")
PYEOF

if grep -q "accepted-without-verdict" "$TMP/jmapd2.log"; then
    pass "submission: the no-verdict outcome is logged as accepted-without-verdict"
else
    fail "submission: the no-verdict outcome is logged as accepted-without-verdict"
fi

# closing the silent relay makes the worker's verdict land AFTER the response:
# it must be logged as lost, not dropped in silence
kill "$HOLE_PID" 2>/dev/null || true
late=1
for _ in $(seq 1 100); do
    if grep -q "late worker verdict lost" "$TMP/jmapd2.log"; then late=0; break; fi
    sleep 0.1
done
check "$late" "submission: a verdict that lands after the window is logged as late worker verdict lost"

echo
if [ "$FAILS" = 0 ]; then
    echo "jmapd_submit: all checks passed"
    exit 0
fi
echo "jmapd_submit: $FAILS check(s) failed"
echo "--- jmapd log ---"
cat "$TMP/jmapd.log" 2>/dev/null || true
echo "--- sink log ---"
cat "$TMP/sink.log" 2>/dev/null || true
exit 1
