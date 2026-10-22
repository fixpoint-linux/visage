#!/usr/bin/env bash
# jmapd_hub.sh — THE ACCEPTANCE TEST for jmapd (M4): the REAL client.
#
# Everything up to here tested jmapd with curl.  This one points the actual
# mail-hub client (/home/jaye/email, Zig + Elm) at jmapd and drives the
# client's OWN HTTP API — so what is proven is not "jmapd answers something",
# but "a JMAP client that only speaks RFC 8620/8621 can read, flag, move and
# send through this server".
#
# The client is NOT modified and NOT stubbed: it is built with `zig build` and
# run as a separate process against jmapd on loopback (the client's
# loopback_dev URL policy: http is accepted only to a loopback host).  If it is
# not built, this script FAILS LOUDLY — a missing client is a finding, not
# something to work around.
#
# What is asserted, in the client's own terms:
#   * GET /api/session            — the client discovered the account from
#                                   jmapd's session document;
#   * GET /api/mailboxes          — Mailbox/get, with roles, through the cache;
#   * GET /api/messages?mailbox=  — Email/query + Email/get (a #resultOf
#                                   back-reference in ONE request);
#   * GET /api/message/<id>       — textBody AND htmlBody both arrive and are
#                                   DECODED (the multipart/alternative fixture
#                                   would otherwise show base64 or one part);
#   * POST /api/message/<id>/flags — Email/set with ifInState, read back;
#   * POST /api/message/<id>/move  — mailboxIds replacement, i.e. a maildir
#                                   move that keeps the Email id;
#   * POST /api/send              — Email/set create (draft) + EmailSubmission/set
#                                   with onSuccessUpdateEmail, and the message
#                                   then appears in the client's Sent list;
#   * POST /api/sync (twice)      — /changes answers cannotCalculateChanges and
#                                   the client full-refreshes instead of failing.
#
# Ports are parametrized via env: JMAPD_PORT_BASE (default 18095).
set -euo pipefail

cd "$(dirname "$0")/.."

PORT_BASE="${JMAPD_PORT_BASE:-18095}"
JMAP_PORT="$PORT_BASE"
SINK_PORT="$((PORT_BASE + 1))"
HUB_PORT="$((PORT_BASE + 2))"

MAIL_HUB_DIR="${MAIL_HUB_DIR:-/home/jaye/email}"
MAIL_HUB="$MAIL_HUB_DIR/zig-out/bin/mail-hub"
MAIL_AUTH="$MAIL_HUB_DIR/zig-out/bin/mail-auth"

echo "== jmapd_hub: building the client ($MAIL_HUB_DIR) =="
if [ ! -d "$MAIL_HUB_DIR" ]; then
    echo "FAIL the mail-hub client checkout is missing: $MAIL_HUB_DIR" >&2
    exit 1
fi
if ! ( cd "$MAIL_HUB_DIR" && zig build ); then
    echo "FAIL the mail-hub client does not build (cd $MAIL_HUB_DIR && zig build)" >&2
    echo "FAIL this is a finding about the client, not something jmapd can fix" >&2
    exit 1
fi
if [ ! -x "$MAIL_HUB" ] || [ ! -x "$MAIL_AUTH" ]; then
    echo "FAIL the client built but its binaries are missing:" >&2
    echo "FAIL   $MAIL_HUB" >&2
    echo "FAIL   $MAIL_AUTH" >&2
    exit 1
fi
echo "ok   the client built: $("$MAIL_HUB" --help 2>&1 | head -1)"

if [ ! -x ./jmapd.com ]; then
    echo "FAIL jmapd.com is not built (run: dhake jmapd.com)" >&2
    exit 1
fi

TMP="$(mktemp -d /tmp/jmapd_hub_XXXXXX)"
ROOT="$TMP/root"
SINK="$TMP/sink"
mkdir -p "$ROOT" "$SINK" "$TMP/db"
printf 'alice:waldorf\n' > "$ROOT/imapd.passwd"
chmod 600 "$ROOT/imapd.passwd"

# ---- the seeded maildir: 2 mailboxes, 3 messages ---------------------------
mkdir -p "$ROOT/alice/Inbox/tmp" "$ROOT/alice/Inbox/new" "$ROOT/alice/Inbox/cur"
mkdir -p "$ROOT/alice/.Work/tmp" "$ROOT/alice/.Work/new" "$ROOT/alice/.Work/cur"

# (1) plain, unread
printf 'From: Bob <bob@example.com>\r\nTo: alice@example.com\r\nSubject: plain hello\r\nMessage-ID: <plain1@example.com>\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nplain body one\r\n' \
    > "$ROOT/alice/Inbox/cur/1700000100.PLAIN.host:2,"
# (2) multipart/alternative with a base64 attachment: the part that proves the
#     walker, the decoder and the bodyValues assembly all agree
{
    printf 'From: Carol <carol@example.com>\r\n'
    printf 'To: alice@example.com\r\n'
    printf 'Subject: =?UTF-8?B?bXVsdGlwYXJ0IGhlbGxv?=\r\n'
    printf 'Message-ID: <mp1@example.com>\r\n'
    printf 'Date: Mon, 1 Jan 2024 01:00:00 +0000\r\n'
    printf 'MIME-Version: 1.0\r\n'
    printf 'Content-Type: multipart/mixed; boundary="OUTER"\r\n'
    printf '\r\n'
    printf -- '--OUTER\r\n'
    printf 'Content-Type: multipart/alternative; boundary="INNER"\r\n\r\n'
    printf -- '--INNER\r\n'
    printf 'Content-Type: text/plain; charset=utf-8\r\n\r\n'
    printf 'plain alternative body\r\n'
    printf -- '--INNER\r\n'
    printf 'Content-Type: text/html; charset=utf-8\r\n\r\n'
    printf '<p>html alternative body</p>\r\n'
    printf -- '--INNER--\r\n'
    printf -- '--OUTER\r\n'
    printf 'Content-Type: text/plain; name="note.txt"\r\n'
    printf 'Content-Disposition: attachment; filename="note.txt"\r\n'
    printf 'Content-Transfer-Encoding: base64\r\n\r\n'
    printf 'aGVsbG8gYXR0YWNobWVudAo=\r\n'
    printf -- '--OUTER--\r\n'
} > "$ROOT/alice/Inbox/cur/1700000200.MULTI.host:2,"
# (3) a folded, RFC 2047-encoded header pair
printf 'From: "Dave" <dave@example.com>\r\nTo: alice@example.com,\r\n alice+work@example.com\r\nSubject: =?utf-8?Q?caf=C3=A9_r=C3=A9union?=\r\nMessage-ID: <enc1@example.com>\r\nDate: Mon, 1 Jan 2024 02:00:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nencoded subject body\r\n' \
    > "$ROOT/alice/Inbox/cur/1700000300.ENC.host:2,"
touch -d @1700000100 "$ROOT/alice/Inbox/cur/1700000100.PLAIN.host:2,"
touch -d @1700000200 "$ROOT/alice/Inbox/cur/1700000200.MULTI.host:2,"
touch -d @1700000300 "$ROOT/alice/Inbox/cur/1700000300.ENC.host:2,"

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
        if [ "$i" -gt 200 ]; then
            echo "FAIL $2 did not come up on port $1" >&2
            echo "--- $2 log ---" >&2
            cat "$3" 2>/dev/null >&2 || true
            exit 1
        fi
        sleep 0.1
    done
}

dump_logs() {
    echo "--- jmapd log ---"
    cat "$TMP/jmapd.log" 2>/dev/null || true
    echo "--- mail-hub log ---"
    cat "$TMP/hub.log" 2>/dev/null || true
    echo "--- sink log ---"
    cat "$TMP/sink.log" 2>/dev/null || true
}

# ======================================================================
# the three daemons: a recording SMTP sink, jmapd, and the real client
# ======================================================================
python3 tests/outbox_fakemx.py 127.0.0.1 "$SINK_PORT" "$SINK" \
    >"$TMP/sink.log" 2>&1 &
PIDS+=("$!")
wait_port "$SINK_PORT" "the recording sink" "$TMP/sink.log"

./jmapd.com --root "$ROOT" --addr 127.0.0.1 --port "$JMAP_PORT" \
    --hostname 127.0.0.1 --identity alice@example.com \
    --outbox-host 127.0.0.1 --outbox-port "$SINK_PORT" --outbox-tls none \
    --submit-wait 15000 >"$TMP/jmapd.log" 2>&1 &
PIDS+=("$!")
wait_port "$JMAP_PORT" "jmapd" "$TMP/jmapd.log"

# a device token for the client's own API (printed once, captured here)
TOKEN="$("$MAIL_AUTH" --tokens "$TMP/tokens.json" add e2e 2>"$TMP/auth.log")"
chmod 600 "$TMP/tokens.json" 2>/dev/null || true
if [ -z "$TOKEN" ]; then
    echo "FAIL mail-auth did not mint a token" >&2
    cat "$TMP/auth.log" >&2 || true
    exit 1
fi

cat > "$TMP/hub.json" <<JSON
{"bind":"127.0.0.1","port":$HUB_PORT,
 "session_url":"http://127.0.0.1:$JMAP_PORT/.well-known/jmap",
 "auth":"basic","username":"alice","password":"waldorf",
 "tokens":"$TMP/tokens.json","sessions":"$TMP/sessions.json","db":"$TMP/db"}
JSON
chmod 600 "$TMP/hub.json"

"$MAIL_HUB" --config "$TMP/hub.json" >"$TMP/hub.log" 2>&1 &
PIDS+=("$!")
wait_port "$HUB_PORT" "mail-hub" "$TMP/hub.log"

# ======================================================================
# the acceptance run: the client's own API, end to end
# ======================================================================
rc=0
python3 - "$HUB_PORT" "$TOKEN" "$SINK" <<'PYEOF' || rc=$?
import glob, json, sys, urllib.error, urllib.request

port, token, sink = int(sys.argv[1]), sys.argv[2], sys.argv[3]
base = f"http://127.0.0.1:{port}"


def api(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def get(path):
    st, body = api("GET", path)
    assert st == 200, (path, st, body)
    return body


def post(path, body=None):
    st, b = api("POST", path, body)
    assert st == 200 or st == 202, (path, st, b)
    return b


fails = []


def check(cond, what, detail=None):
    if cond:
        print(f"ok   {what}")
    else:
        fails.append(what)
        print(f"FAIL {what}" + (f" — {detail}" if detail is not None else ""))


# --- the session: the client discovered jmapd's account -------------------
sess = get("/api/session")
check(sess.get("accountId") == "alice", "hub: /api/session names the account", sess)
check("mail" in json.dumps(sess.get("mailCapabilities", {})),
      "hub: the mail capabilities came from jmapd's session document", sess)

# --- mailboxes: Mailbox/get through the client's cache -------------------
mbs = get("/api/mailboxes")["mailboxes"]
by_role = {m.get("role"): m for m in mbs if m.get("role")}
check(len(mbs) >= 4, "hub: /api/mailboxes lists the account's mailboxes",
      [m["name"] for m in mbs])
check("inbox" in by_role and "sent" in by_role and "drafts" in by_role,
      "hub: Inbox/Sent/Drafts carry their roles", sorted(by_role))
inbox = by_role["inbox"]["id"]
sent = by_role["sent"]["id"]
work = next((m["id"] for m in mbs if m["name"] == "Work"), None)
check(work is not None, "hub: the second seeded mailbox is visible",
      [m["name"] for m in mbs])

# --- the message list: Email/query + Email/get in ONE request ------------
msgs = get(f"/api/messages?mailbox={inbox}&refresh=1")["messages"]
check(len(msgs) == 3, "hub: /api/messages?mailbox=Inbox returns the 3 seeded messages",
      [(m.get("subject"), m.get("id")) for m in msgs])
subjects = sorted(m["subject"] for m in msgs)
check(subjects == sorted(["plain hello", "multipart hello", "café réunion"]),
      "hub: subjects arrive (RFC 2047 decoded, folded headers unfolded)", subjects)

multi = next(m for m in msgs if m["subject"] == "multipart hello")
check(multi["hasAttachment"] is True,
      "hub: the multipart/alternative message reports its attachment", multi)

# --- the reading pane: BOTH bodies, decoded ------------------------------
detail = get(f"/api/message/{multi['id']}")
texts = [b["value"] for b in detail["textBody"]]
htmls = [b["value"] for b in detail["htmlBody"]]
check(any("plain alternative body" in t for t in texts),
      "hub: textBody arrives decoded", texts)
check(any("html alternative body" in h for h in htmls),
      "hub: htmlBody arrives decoded", htmls)
check(any(a["name"] == "note.txt" for a in detail["attachments"]),
      "hub: the attachment is named", detail["attachments"])

plain = next(m for m in msgs if m["subject"] == "plain hello")

# --- flags: Email/set with ifInState, read back --------------------------
res = post(f"/api/message/{plain['id']}/flags", {"seen": True})
check(res.get("ok") is True, "hub: POST /api/message/<id>/flags reports ok", res)
check(res.get("keywords", {}).get("$seen") is True,
      "hub: the flag write reports $seen", res)
after = get(f"/api/message/{plain['id']}")
check(after["keywords"].get("$seen") is True,
      "hub: $seen reads back through the client's cache", after["keywords"])

# --- move: mailboxIds replacement is a maildir MOVE ----------------------
res = post(f"/api/message/{plain['id']}/move", {"mailboxId": work})
check(res.get("ok") is True, "hub: POST /api/message/<id>/move reports ok", res)
in_work = get(f"/api/messages?mailbox={work}&refresh=1")["messages"]
check(any(m["id"] == plain["id"] for m in in_work),
      "hub: the moved message is in the target mailbox", [m["id"] for m in in_work])
# the client's own /api/message row carries the mailbox list; the id must be
# the SAME one it had in Inbox (a maildir move renames the file, not its base)
detail = get(f"/api/message/{plain['id']}")
check(detail["id"] == plain["id"] and detail["mailboxIds"] == [work],
      "hub: the moved message kept its Email id and its new mailbox",
      (detail["id"], detail["mailboxIds"]))

# --- send: draft + submission + onSuccessUpdateEmail ---------------------
res = post("/api/send", {"to": [{"name": "Bob", "email": "bob@example.com"}],
                         "subject": "sent through jmapd",
                         "text": "the hub wrote this body\n"})
check(res.get("ok") is True, "hub: POST /api/send reports ok", res)
check(isinstance(res.get("submissionId"), str) and res["submissionId"].startswith("s"),
      "hub: the send reports an EmailSubmission id", res)
check(res.get("emailId", "").startswith("e"),
      "hub: the send reports the Email id", res)

sent_list = get(f"/api/messages?mailbox={sent}&refresh=1")["messages"]
check(any(m["id"] == res.get("emailId") for m in sent_list),
      "hub: the sent message appears in the client's Sent list",
      [m["id"] for m in sent_list])
sent_row = next((m for m in sent_list if m["id"] == res.get("emailId")), None)
if sent_row:
    check(sent_row["keywords"].get("$seen") is True and
          sent_row["keywords"].get("$draft") is None,
          "hub: the sent message is seen and no longer a draft", sent_row["keywords"])
    check(sent_row["subject"] == "sent through jmapd",
          "hub: the sent message reads back with its subject", sent_row["subject"])

# the sink really got it (the client's "ok" alone would not prove a send)
got = [open(p, "rb").read().decode("utf-8", "replace")
       for p in sorted(glob.glob(f"{sink}/msg-*.eml"))]
check(any("Subject: sent through jmapd" in m and
          "the hub wrote this body" in m for m in got),
      "hub: the relay received the client's message", len(got))

# --- sync twice: /changes -> cannotCalculateChanges -> full refresh ------
first = post("/api/sync")
check("full" in first, "hub: POST /api/sync answers", first)
second = post("/api/sync")
check("full" in second, "hub: a second /api/sync answers too", second)
mbs2 = get("/api/mailboxes")["mailboxes"]
check(len(mbs2) >= 4, "hub: the mailbox list survives the sync", len(mbs2))

print()
if fails:
    print(f"hub assertions: {len(fails)} FAILED")
    sys.exit(1)
print("hub assertions: all passed")
PYEOF
check "$rc" "hub: the client's own API works end to end against jmapd"

echo
if [ "$FAILS" = 0 ]; then
    echo "jmapd_hub: all checks passed"
    exit 0
fi
echo "jmapd_hub: $FAILS check(s) failed"
dump_logs
exit 1
