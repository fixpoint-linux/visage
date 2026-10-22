#!/usr/bin/env bash
# jmapd_write.sh — live tests for jmapd's M3 write path: Email/set (update,
# create, destroy), Thread/get, the state sidecar + ifInState, and /changes.
#
# The assertions that matter most are the ones that would catch a SILENT-WRONG
# implementation:
#
#   * an Email id is UNCHANGED by a keywords patch AND by a mailbox MOVE, and
#     the maildir file kept its base name (a rename that changed the base would
#     silently hand the client a new id for the same message);
#   * a stale ifInState is REFUSED (stateMismatch) and the current one is
#     ACCEPTED — a server that ignored ifInState would pass the second half only;
#   * destroy makes the Email stop existing while the neighbouring message
#     survives;
#   * a created draft reads back with the right subject, keywords, mailbox and
#     body (the RFC 5322 builder is not checked by "did it return an id");
#   * two replies group into ONE Thread, and Thread/get agrees with the
#     threadId Email/get reported;
#   * /changes answers cannotCalculateChanges, not an invented diff.
#
# Ports are parametrized via env: JMAPD_PORT_BASE (default 18093).
set -euo pipefail

cd "$(dirname "$0")/.."

PORT_BASE="${JMAPD_PORT_BASE:-18093}"
PORT_A="$PORT_BASE"

if [ ! -x ./jmapd.com ]; then
    echo "FAIL jmapd.com is not built (run: dhake jmapd.com)" >&2
    exit 1
fi

TMP="$(mktemp -d /tmp/jmapd_write_XXXXXX)"
ROOT="$TMP/root"
mkdir -p "$ROOT"
printf 'alice:waldorf\n' > "$ROOT/imapd.passwd"
chmod 600 "$ROOT/imapd.passwd"

mkdir -p "$ROOT/alice/Inbox/tmp" "$ROOT/alice/Inbox/new" "$ROOT/alice/Inbox/cur"
mkdir -p "$ROOT/alice/.Sent/tmp" "$ROOT/alice/.Sent/new" "$ROOT/alice/.Sent/cur"
mkdir -p "$ROOT/alice/.Drafts/tmp" "$ROOT/alice/.Drafts/new" "$ROOT/alice/.Drafts/cur"

# ---- a conversation: the root, a reply to it, and an unrelated message ------
printf 'From: bob@example.com\r\nTo: alice@example.com\r\nSubject: root one\r\nMessage-ID: <root1@example.com>\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nContent-Type: text/plain\r\n\r\nroot body\r\n' \
    > "$ROOT/alice/Inbox/cur/1700000100.ROOT.host:2,S"
printf 'From: alice@example.com\r\nTo: bob@example.com\r\nSubject: re: root one\r\nMessage-ID: <reply1@example.com>\r\nIn-Reply-To: <root1@example.com>\r\nReferences: <root1@example.com>\r\nDate: Mon, 1 Jan 2024 01:00:00 +0000\r\nContent-Type: text/plain\r\n\r\nreply body\r\n' \
    > "$ROOT/alice/Inbox/cur/1700000200.REPLY.host:2,S"
printf 'From: carol@example.com\r\nTo: alice@example.com\r\nSubject: unrelated\r\nMessage-ID: <other1@example.com>\r\nDate: Mon, 1 Jan 2024 02:00:00 +0000\r\nContent-Type: text/plain\r\n\r\nother body\r\n' \
    > "$ROOT/alice/Inbox/cur/1700000300.OTHER.host:2,S"

touch -d @1700000100 "$ROOT/alice/Inbox/cur/1700000100.ROOT.host:2,S"
touch -d @1700000200 "$ROOT/alice/Inbox/cur/1700000200.REPLY.host:2,S"
touch -d @1700000300 "$ROOT/alice/Inbox/cur/1700000300.OTHER.host:2,S"

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

BASE="http://127.0.0.1:$PORT_A"

# ======================================================================
# (1) the write path over live sockets
# ======================================================================
python3 - "$PORT_A" "$ROOT" <<'PYEOF' && pass "write path: flag, move, create, destroy, state, threads" \
                           || fail "write path: flag, move, create, destroy, state, threads"
import base64, json, os, sys, urllib.error, urllib.request

port = int(sys.argv[1])
root = sys.argv[2]
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


def one(name, args, using=(CORE, MAIL)):
    """One method call, returning its result object."""
    resp = call({"using": list(using), "methodCalls": [[name, args, "c0"]]})
    return resp["methodResponses"][0][1]


def mailboxes():
    res = one("Mailbox/get", {"accountId": "alice"})
    return {m["name"]: m for m in res["list"]}


mbs = mailboxes()
inbox, sent, drafts = mbs["Inbox"]["id"], mbs["Sent"]["id"], mbs["Drafts"]["id"]

# --- the seeded conversation: one thread for root+reply -------------------
res = one("Email/query", {"accountId": "alice", "filter": {"inMailbox": inbox},
                          "sort": [{"property": "receivedAt", "isAscending": True}],
                          "limit": 10})
ids = res["ids"]
assert len(ids) == 3, res
state_before = res["queryState"]
assert state_before.startswith("e"), res

res = one("Email/get", {"accountId": "alice", "ids": ids,
                        "properties": ["id", "threadId", "subject", "keywords",
                                       "mailboxIds", "messageId"]})
by_id = {e["id"]: e for e in res["list"]}
root_e, reply_e, other_e = by_id[ids[0]], by_id[ids[1]], by_id[ids[2]]
assert root_e["subject"] == "root one", root_e
assert root_e["threadId"] == reply_e["threadId"], (root_e, reply_e)
assert root_e["threadId"] != other_e["threadId"], (root_e, other_e)

# --- Thread/get agrees with Email/get and groups the pair -----------------
tres = one("Thread/get", {"accountId": "alice", "ids": [root_e["threadId"]]})
assert len(tres["list"]) == 1, tres
assert tres["list"][0]["id"] == root_e["threadId"], tres
assert sorted(tres["list"][0]["emailIds"]) == sorted([root_e["id"], reply_e["id"]]), tres
assert tres["notFound"] == [], tres
tres = one("Thread/get", {"accountId": "alice", "ids": ["tnope"]})
assert tres["notFound"] == ["tnope"] and tres["list"] == [], tres
tres = one("Thread/get", {"accountId": "alice"})
assert len(tres["list"]) == 2, tres

# --- Email/set: flag flip keeps the id AND the maildir base name ----------
res = one("Email/set", {"accountId": "alice", "ifInState": state_before,
                        "update": {root_e["id"]: {"keywords/$flagged": True}}})
assert res.get("type") is None, res
assert root_e["id"] in res["updated"], res   # present in updated, value null
assert "notUpdated" not in res, res
new_state = res["newState"]
assert new_state != state_before, res

res = one("Email/get", {"accountId": "alice", "ids": [root_e["id"]],
                        "properties": ["id", "keywords"]})
e = res["list"][0]
assert e["id"] == root_e["id"], e            # the id MUST NOT change
assert e["keywords"].get("$flagged") is True, e
assert e["keywords"].get("$seen") is True, e
# the file kept its base name (a base rename would change the id silently)
assert os.path.exists(f"{root}/alice/Inbox/cur/1700000100.ROOT.host:2,FS"), \
    sorted(os.listdir(f"{root}/alice/Inbox/cur"))

# --- a STALE ifInState is refused whole, the current one is accepted ------
res = one("Email/set", {"accountId": "alice", "ifInState": state_before,
                        "update": {root_e["id"]: {"keywords/$flagged": False}}})
assert res.get("type") == "stateMismatch", res
res = one("Email/get", {"accountId": "alice", "ids": [root_e["id"]],
                        "properties": ["id", "keywords"]})
assert res["list"][0]["keywords"].get("$flagged") is True, res  # nothing happened

# --- Email/set: a mailbox replace is a MOVE that keeps the id -------------
res = one("Email/set", {"accountId": "alice",
                        "update": {other_e["id"]: {"mailboxIds": {sent: True}}}})
assert "notUpdated" not in res, res
res = one("Email/get", {"accountId": "alice", "ids": [other_e["id"]],
                        "properties": ["id", "mailboxIds"]})
e = res["list"][0]
assert e["id"] == other_e["id"], e
assert e["mailboxIds"] == {sent: True}, e
assert os.path.exists(f"{root}/alice/.Sent/cur/1700000300.OTHER.host:2,S"), \
    sorted(os.listdir(f"{root}/alice/.Sent/cur"))
assert not os.path.exists(f"{root}/alice/Inbox/cur/1700000300.OTHER.host:2,S")

# --- Email/set: create a draft (the client's exact shape) -----------------
res = one("Email/set", {"accountId": "alice", "create": {"draft": {
    "mailboxIds": {drafts: True},
    "keywords": {"$draft": True, "$seen": True},
    "from": [{"email": "alice@example.com"}],
    "to": [{"name": "Bob", "email": "bob@example.com"}],
    "cc": [{"email": "carol@example.com"}],
    "bcc": [{"email": "dave@example.com"}],
    "subject": "draft subject",
    "textBody": [{"partId": "t1", "type": "text/plain"}],
    "htmlBody": [{"partId": "h1", "type": "text/html"}],
    "bodyValues": {"t1": {"value": "draft text\nline two"},
                   "h1": {"value": "<p>draft html</p>"}},
    "inReplyTo": ["<root1@example.com>"],
    "references": ["<root1@example.com>"],
}}})
assert "notCreated" not in res, res
created = res["created"]["draft"]
draft_id = created["id"]
assert draft_id.startswith("e"), created
assert created["threadId"] == root_e["threadId"], created  # a reply in the thread
assert created["size"] > 0, created

# it reads back with the right subject, keywords, mailbox and BODY
res = one("Email/get", {"accountId": "alice", "ids": [draft_id],
                        "properties": ["id", "subject", "keywords", "mailboxIds",
                                       "from", "to", "cc", "bcc", "textBody",
                                       "htmlBody", "messageId", "preview"],
                        "fetchTextBodyValues": True,
                        "fetchHTMLBodyValues": True})
e = res["list"][0]
assert e["subject"] == "draft subject", e
assert e["keywords"].get("$draft") is True and e["keywords"].get("$seen") is True, e
assert e["mailboxIds"] == {drafts: True}, e
assert e["from"][0]["email"] == "alice@example.com", e
assert e["to"][0]["name"] == "Bob" and e["to"][0]["email"] == "bob@example.com", e
assert e["cc"][0]["email"] == "carol@example.com", e
assert e["bcc"][0]["email"] == "dave@example.com", e
tb, hb = e["textBody"], e["htmlBody"]
assert len(tb) == 1 and len(hb) == 1, (tb, hb)
bv = e["bodyValues"]
assert bv[tb[0]["partId"]]["value"] == "draft text\r\nline two", repr(bv)
assert bv[hb[0]["partId"]]["value"] == "<p>draft html</p>", repr(bv)
assert e["preview"].startswith("draft text"), e["preview"]

# --- destroy: the Email stops existing, its neighbour does not ------------
res = one("Email/set", {"accountId": "alice", "destroy": [draft_id]})
assert res["destroyed"] == [draft_id], res
res = one("Email/get", {"accountId": "alice", "ids": [draft_id],
                        "properties": ["id"]})
assert res["notFound"] == [draft_id], res
res = one("Email/get", {"accountId": "alice", "ids": [root_e["id"]],
                        "properties": ["id"]})
assert res["notFound"] == [] and len(res["list"]) == 1, res

# --- /changes answers cannotCalculateChanges ------------------------------
for name in ("Email/changes", "Mailbox/changes", "Thread/changes"):
    res = one(name, {"accountId": "alice", "sinceState": state_before})
    assert res.get("type") == "cannotCalculateChanges", (name, res)
res = one("Email/queryChanges", {"accountId": "alice", "sinceQueryState": state_before,
                                 "filter": {}})
assert res.get("type") == "cannotCalculateChanges", res

# --- the state moved on for a read client (fingerprint, not just our writes)
res = one("Mailbox/get", {"accountId": "alice"})
assert res["state"].startswith("m"), res
assert int(res["state"][1:]) > 0, res
print("write path assertions: all passed")
PYEOF

# ======================================================================
# (2) a delivery by ANOTHER writer bumps the state (two daemons, one tree)
# ======================================================================
state_before=$(curl -s -u alice:waldorf -X POST "$BASE/api" \
    -H 'Content-Type: application/json' \
    -d '{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/query",{"accountId":"alice","limit":1},"c0"]]}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["methodResponses"][0][1]["queryState"])')
printf 'From: ext@example.com\r\nTo: alice@example.com\r\nSubject: delivered by imapd\r\nMessage-ID: <ext1@example.com>\r\n\r\nx\r\n' \
    > "$ROOT/alice/Inbox/new/1700000900.EXT.host"
state_after=$(curl -s -u alice:waldorf -X POST "$BASE/api" \
    -H 'Content-Type: application/json' \
    -d '{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/query",{"accountId":"alice","limit":1},"c0"]]}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["methodResponses"][0][1]["queryState"])')
check "$([ "$state_before" != "$state_after" ] && echo 0 || echo 1)" \
    "state: a message delivered behind jmapd's back moves the state ($state_before -> $state_after)"

# ======================================================================
# (3) Email/set requires authentication (a write route with no credential)
# ======================================================================
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api" \
    -H 'Content-Type: application/json' \
    -d '{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"alice","destroy":["eAAAA"]},"c0"]]}')
check "$([ "$code" = 401 ] && echo 0 || echo 1)" "Email/set without credentials: 401"

echo
if [ "$FAILS" = 0 ]; then
    echo "jmapd_write: all checks passed"
    exit 0
fi
echo "jmapd_write: $FAILS check(s) failed"
exit 1
